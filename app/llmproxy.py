"""Per-request LLM gate (plan v2 #2b, 2026-10-13): a thin HTTP proxy on 127.0.0.1 between llm-local and llama-server.

Before, a whole tgread or llm-local run held the LLM gate. A part of a chunked 7-day summary held it for 10-12 min, so on
13.10 a live `vault gmail get` got no answer within 230 s. Now every model request takes the gate on its own:

- Each LLM subprocess runs inside LLMGate.lease(): env LLM_LOCAL_PORT = this proxy, LLM_LOCAL_TICKET = a random ticket
  that llm-local sends as the header X-LLM-Ticket. The lease holds the class (live / bulk / background), whether the
  work is private (vault data) or the caller's own text, the async job and the caller.
- Gated: every request except GET /health, GET /props and POST /tokenize, /detokenize (no slot, no KV cache). Those
  still need a valid ticket; only GET /health (llm-ctl's check) doesn't.
- Fail closed: no or unknown ticket -> 403; the gate timed out -> 503; the lease's caller left before its first request
  ran -> 499; the KV flush failed -> 503; llama-server unreachable -> 502. llm-local turns each into an error. Nothing is
  ever retried with less filtering.
- The answer is relayed byte for byte (status line, headers and body as llama-server sent them), so the output is the
  same as without the proxy.
- The flush rule holds per request (LLMGate.use: private work, then caller text -> the KV cache is replaced first).
- Preemption: a running bulk/background request that the gate asks to stop (a live request waited preempt_after s) is
  aborted upstream (llama-server cancels a task whose connection closed) and sent again after the live work, with its
  place in the queue; llm-local sees one answer. At most LLMGate.MAX_PREEMPTS times per request.
- llm-local gone (stopped, timed out): its queued request is dropped, a running one aborted upstream.
No text is ever logged; the counters are numbers.
"""
import http.server
import json
import select
import socket
import socketserver
import threading
import time

import vaultlib as V

UNGATED = {('GET', '/health'), ('GET', '/props'), ('POST', '/tokenize'), ('POST', '/detokenize')}
NO_TICKET = {('GET', '/health')}
MAX_BODY = 64 << 20


class Preempted(Exception):
    pass


class Unreachable(Exception):
    pass


def sock_alive(sock):
    """False once the peer closed (EOF/reset). llm-local sends nothing after its request, so readable = closed."""
    try:
        r, _, _ = select.select([sock], [], [], 0)
        return not r or bool(sock.recv(1, socket.MSG_PEEK))
    except (OSError, ValueError):
        return False


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class LLMProxy:
    def __init__(self, gate, upstream_port, port=8180, host='127.0.0.1'):
        self.gate, self.upstream, self.host, self.port = gate, int(upstream_port), host, int(port)
        self.httpd = None
        self.counts = {'requests': 0, 'gated': 0, 'preempted': 0, 'refused': 0, 'gone': 0}
        self._lock = threading.Lock()

    def count(self, k):
        with self._lock:
            self.counts[k] = self.counts.get(k, 0) + 1

    def start(self):
        handler = type('Handler', (_Handler,), {'proxy': self})
        self.httpd = _Server((self.host, self.port), handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, name='llm-proxy', daemon=True).start()
        return self

    def stop(self):
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()

    def relay(self, method, path, body, client, abort=None):
        """One request to llama-server -> its raw answer (bytes). abort() true: stop it now (Preempted). The client
        (llm-local) closing its connection stops it too (V.ClientGone). Either way the upstream connection is closed,
        which makes llama-server cancel the task."""
        try:
            up = socket.create_connection(('127.0.0.1', self.upstream), timeout=60)
        except OSError as e:
            raise Unreachable(type(e).__name__)
        try:
            up.sendall((f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.upstream}\r\n'
                        f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                        f'Connection: close\r\n\r\n').encode('ascii') + body)
            buf, watch = [], [up, client]
            while True:
                if abort is not None and abort():
                    raise Preempted()
                r, _, _ = select.select(watch, [], [], 0.2)
                if client in r:
                    if not sock_alive(client):
                        raise V.ClientGone('llm-local went away; its request was stopped')
                    watch = [up]                       # unexpected bytes from the client: stop watching it
                if up in r:
                    chunk = up.recv(1 << 16)
                    if not chunk:
                        break
                    buf.append(chunk)
            if not buf:
                raise Unreachable('empty answer')
            return b''.join(buf)
        except (ConnectionError, socket.timeout) as e:
            raise Unreachable(type(e).__name__)
        finally:
            try:
                up.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            up.close()

    def gated(self, lz, method, path, body, client):
        """A model request under the gate, with its lease's class and privacy; re-run after a preemption."""
        self.count('gated')

        def alive():
            if not sock_alive(client):
                return False
            if lz['alive'] is None or lz['started']:   # once its work ran, a lease runs to the end
                return True
            return lz['alive']()
        seq, n = None, 0
        while True:
            with self.gate.use(lz['private'], what=lz['what'], timeout=lz['timeout'], cls=lz['cls'], alive=alive,
                               job=lz['job'], lease=lz['id'], seq=seq, preempts=n,
                               preemptible=lz['cls'] != 'live' and n < self.gate.MAX_PREEMPTS) as e:
                lz['started'] = True
                seq = e['seq']
                stop = e['preempt']
                try:
                    return self.relay(method, path, body, client, abort=stop.is_set if stop is not None else None)
                except Preempted:
                    e['preempted'] = True
                    self.count('preempted')
            n += 1


class _Handler(http.server.BaseHTTPRequestHandler):
    proxy = None
    protocol_version = 'HTTP/1.0'

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.one('GET')

    def do_POST(self):
        self.one('POST')

    def err(self, code, msg):
        data = json.dumps({'error': {'code': code, 'message': msg, 'type': 'vault_llm_gate'}}).encode()
        try:
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass

    def one(self, method):
        px = self.proxy
        px.count('requests')
        self.close_connection = True
        path = self.path.split('?', 1)[0]
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            return self.err(413, 'bad or too large request')
        body = self.rfile.read(n) if n else b''
        lz = None
        if (method, path) not in NO_TICKET:
            lz = px.gate.ticket(self.headers.get('X-LLM-Ticket'))
            if lz is None:
                px.count('refused')
                return self.err(403, 'no valid LLM ticket: the vault gives one to each LLM job (fail closed)')
        try:
            if (method, path) in UNGATED:
                raw = px.relay(method, self.path, body, self.connection)
            else:
                raw = px.gated(lz, method, self.path, body, self.connection)
        except V.ClientGone:
            px.count('gone')
            if sock_alive(self.connection):            # the lease's caller left: tell llm-local, it stops
                self.err(499, 'the caller went away before this LLM job ran')
            return
        except V.VaultError as e:                      # LLMBusy (gate timeout), LLMUnavailable (KV flush failed)
            return self.err(503, str(e)[:300])
        except Unreachable:
            return self.err(502, 'the local LLM server is not reachable')
        try:
            self.wfile.write(raw)
        except OSError:
            pass
