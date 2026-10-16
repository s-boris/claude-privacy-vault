#!/usr/bin/python3 -I
"""Unit tests for the privacy vault (claude-vault): secret store, audit log, Telegram notifier, raw-release state
machine, LLM gate, policy layer, tgread argv building (against tgread's real parser), login job (2FA never on disk),
HTTP API (auth, routing, limits), paperless (fake server: metadata only, anonymized content, whitelisted raw fields,
audit without values; metadata writes: update + matching rules, allowlisted write paths, no delete; the
~/bin/paperless + ~/bin/vault clients when they exist, i.e. not in the image), Firefly (pseudonyms), llm-run allowlist, startup refusals and a subprocess smoke test of the
raw-release flow in test mode.

Runs in the image (/opt/vault/tests/test_vault.py) and in the repo (~/opt/claude-vault/tests). No network: every
peer (Telegram, paperless, Firefly, llm-local) is a local fake. Fixture rule (brain commits are scanned by
secretscan): never write a complete token literally; build such values at runtime."""
import base64
import contextlib
import datetime as dt
import hashlib
import http.server
import html
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'app'))


def vend(name, fallback):
    p = ROOT / 'vendor' / name
    return str(p) if p.exists() else fallback


TGREAD = vend('tgread', '/home/node/opt/claude-vault/vendor/tgread')
SECRETSCAN = vend('secretscan.py', '/home/node/bin/secretscan.py')
BILLS = vend('bills', '/home/node/bin/bills')
PY = os.environ.get('VAULT_TEST_PY') or next(p for p in ('/opt/vault/venv/bin/python3', '/home/node/opt/tgread-venv/bin/python3') if os.path.exists(p))
TMP = Path(tempfile.mkdtemp(prefix='vault-tests-'))
os.environ.pop('http_proxy', None)
os.environ.pop('HTTP_PROXY', None)
os.environ['BILLS_NOW'] = '2026-10-10 12:00'
os.environ['BILLS_STATE_DIR'] = str(TMP / 'bills-state')

import sources as S  # noqa: E402
import vaultd as D  # noqa: E402
import metrics as MX  # noqa: E402
import vaultlib as V  # noqa: E402
import watch as W  # noqa: E402
import jobs as J  # noqa: E402

D.log = lambda msg: None                     # quiet in-process servers (the subprocess test reads its own log)
TOKEN = 'vt-' + 'a1B2' * 12
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()
BOT_ID = 7012345678
BOT_TOKEN = f'{BOT_ID}:' + 'AAH' + 'q' * 32
CHAT_ID = '123456789'
PL_TOKEN = 'pl' + '0123456789abcdef' * 2 + 'zz'
FF_TOKEN = 'ff' + 'Z9y8' * 10
IBAN = 'CH93' + '0076' + '2011' + '6238' + '5295' + '7'
PHONE = '+41 79 ' + '123 45 67'

STUB_LLM = r'''#!/usr/bin/python3 -I
import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
text = sys.stdin.read()
with open(os.path.join(d, 'llm-calls.jsonl'), 'a') as f:
    f.write(json.dumps({'args': args, 'chars': len(text), 'text': text[:200],
                        'cache': os.environ.get('LLM_LOCAL_CACHE_DIR')}) + '\n')
mode = open(os.path.join(d, 'llm-mode')).read().strip() if os.path.exists(os.path.join(d, 'llm-mode')) else 'ok'
if mode == 'fail':
    print('llm-local: local LLM unavailable: test', file=sys.stderr)
    sys.exit(3)
if mode == 'slow':
    import time
    time.sleep(3)
if '--json' in args:
    print(open(os.path.join(d, 'llm-json')).read().strip())
    sys.exit(0)
if '--anonymize' in args:
    out = text.replace('Herzschmerz', '[private: health]')
    if '--paraphrase' in args:                     # policy v4: a recognisable "paraphrase"
        out = out.replace('Treffpunkt', 'Meeting point')
    sys.stdout.write(out if mode == 'plain' else 'ANON ' + out)
    sys.exit(0)
sys.stdout.write('ECHO ' + ' '.join(args) + ' | ' + text)
'''

FAKE_TGREAD = r'''#!/usr/bin/python3 -I
import os, sys, time
a = sys.argv[1:]
if a[:1] != ['login-qr']:
    print('fake tgread: only login-qr', file=sys.stderr); sys.exit(2)
out = a[a.index('--out') + 1]
os.makedirs(os.path.dirname(out), exist_ok=True)
open(out, 'wb').write(b'\x89PNG\r\n\x1a\nFAKEQR')
print(f'QR_READY path={out} expires_in=30s', flush=True)
time.sleep(0.3)
print('PASSWORD_NEEDED hint=none', flush=True)
for attempt in range(3):
    pw = sys.stdin.readline().rstrip('\n')
    if pw == 'right-horse-battery':
        os.remove(out)
        print('LOGIN_OK user_id=1 name=Test', flush=True)
        sys.exit(0)
    print(f'PASSWORD_INVALID attempts_left={2 - attempt}', flush=True)
sys.exit(1)
'''


def write_exec(path, text):
    path.write_text(text)
    path.chmod(0o700)
    return path


STUB_DIR = TMP / 'stub'
STUB_DIR.mkdir()
STUB_PATH = write_exec(STUB_DIR / 'llm-local', STUB_LLM)
FAKE_TG_PATH = write_exec(TMP / 'fake-tgread', FAKE_TGREAD)


def llm_calls():
    p = STUB_DIR / 'llm-calls.jsonl'
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def llm_mode(m):
    (STUB_DIR / 'llm-mode').write_text(m)


def make_pdf(lines):
    """A minimal valid one-page PDF with a text layer (Helvetica), xref offsets computed."""
    esc = [ln.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)') for ln in lines]
    stream = 'BT /F1 11 Tf 14 TL 50 790 Td ' + ' '.join(f'({t}) Tj T*' for t in esc) + ' ET'
    objs = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R '
            '/Resources << /Font << /F1 5 0 R >> >> >>',
            f'<< /Length {len(stream)} >>\nstream\n{stream}\nendstream',
            '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>']
    out, offs = bytearray(b'%PDF-1.4\n'), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f'{i} 0 obj\n{o}\nendobj\n'.encode('latin-1')
    x = len(out)
    out += f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode()
    for o in offs:
        out += f'{o:010d} 00000 n \n'.encode()
    out += f'trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n'.encode()
    return bytes(out)


# ============================================================================================ fake peers

class FakeServer:
    """A tiny HTTP server on 127.0.0.1; handle(method, path, headers, body) -> (status, headers, bytes)."""

    def __init__(self, handle):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                outer.requests.append((method, self.path, dict(self.headers), body))
                st, hd, data = handle(method, self.path, self.headers, body)
                self.send_response(st)
                for k, v in hd.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._do('GET')

            def do_POST(self):
                self._do('POST')

            def do_PATCH(self):
                self._do('PATCH')

            def do_PUT(self):
                self._do('PUT')

            def do_DELETE(self):
                self._do('DELETE')

        self.requests = []
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.srv.server_address[1]}'
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def jresp(obj, status=200):
    return status, {'Content-Type': 'application/json'}, json.dumps(obj).encode()


class FakeTelegram(FakeServer):
    """The Bot API as the vault uses it: sendMessage, and for the approval bot getUpdates (served from
    self.updates by offset, like Telegram), answerCallbackQuery, editMessageText; for the pinned status
    pinChatMessage + getChat (self.pinned = (id, date) or None; ids in self.deleted are gone: edit/pin -> 400;
    self.edit_error = (status, description) makes the next edits fail). conflict=True: 409 on getUpdates."""

    def __init__(self):
        self.reset()
        super().__init__(self.handle)

    def reset(self):
        self.fail = self.conflict = False
        self.sent, self.calls, self.updates, self.uid = [], [], [], 1000
        self.pinned, self.deleted, self.edit_error = None, set(), None

    def handle(self, method, path, headers, body):
        m = re.fullmatch(r'/bot([^/]+)/(\w+)', path)
        if not m or m.group(1) != BOT_TOKEN:
            return jresp({'ok': False, 'description': 'Unauthorized'}, 401)
        if self.fail:
            return jresp({'ok': False, 'description': 'Bad Request: chat not found'}, 400)
        meth, p = m.group(2), dict(urllib.parse.parse_qsl(body.decode()))
        self.calls.append((meth, p))
        if meth == 'sendMessage':
            self.sent.append(p)
            return jresp({'ok': True, 'result': {'message_id': 100 + len(self.sent), 'date': 1_800_000_000 + len(self.sent)}})
        if meth == 'editMessageText' and int(p.get('message_id') or 0) in self.deleted:
            return jresp({'ok': False, 'error_code': 400, 'description': 'Bad Request: message to edit not found'}, 400)
        if meth == 'editMessageText' and self.edit_error:
            return jresp({'ok': False, 'error_code': self.edit_error[0], 'description': self.edit_error[1]},
                         self.edit_error[0])
        if meth == 'pinChatMessage':
            mid = int(p.get('message_id') or 0)
            if mid in self.deleted or not 100 < mid <= 100 + len(self.sent):
                return jresp({'ok': False, 'error_code': 400, 'description': 'Bad Request: message to pin not found'}, 400)
            self.pinned = (mid, 1_800_000_000 + mid - 100)
            return jresp({'ok': True, 'result': True})
        if meth == 'getChat':
            res = {'id': int(p['chat_id']), 'type': 'private', 'first_name': 'Owner'}
            if self.pinned:
                res['pinned_message'] = {'message_id': self.pinned[0], 'date': self.pinned[1], 'text': 'PINNED TEXT'}
            return jresp({'ok': True, 'result': res})
        if meth == 'getUpdates':
            if self.conflict:
                return jresp({'ok': False, 'error_code': 409,
                              'description': 'Conflict: terminated by other getUpdates request'}, 409)
            self.updates = [u for u in self.updates if u['update_id'] >= int(p.get('offset') or 0)]
            return jresp({'ok': True, 'result': self.updates})
        if meth in ('answerCallbackQuery', 'editMessageText'):
            return jresp({'ok': True, 'result': True})
        return jresp({'ok': False, 'description': 'method not faked'}, 404)

    def press(self, data, message_id, chat=CHAT_ID, frm=None):
        """A tap on an inline button (a callback_query update)."""
        self.uid += 1
        self.updates.append({'update_id': self.uid, 'callback_query': {
            'id': f'cq{self.uid}', 'from': {'id': int(frm or chat), 'is_bot': False}, 'data': data,
            'message': {'message_id': message_id, 'chat': {'id': int(chat), 'type': 'private'}}}})

    def method_calls(self, name):
        return [p for m, p in self.calls if m == name]

    def last_code(self):
        return re.search(r'Code: (\d{6})', self.sent[-1]['text']).group(1)


import urllib.parse  # noqa: E402

DOC7_CONTENT = ('Krankenkasse Muster AG, Bahnhofstrasse 1, 8001 Zuerich\nRechnung Nr. R-2026-0042\n'
                f'Policen-Nr. 12.345.678\nKunden-Nr. 98765\nRechnungsdatum 01.10.2026\nZahlbar bis 31.10.2026\n'
                f'Telefon {PHONE}\nDer Patient hatte Herzschmerz nach dem Termin.\nTotal CHF 123.45\nIBAN {IBAN}\n')
DOC7_PDF = make_pdf(['Krankenkasse Muster AG', 'Bahnhofstrasse 1, 8001 Zuerich', 'Rechnung Nr. R-2026-0042',
                     'Rechnungsdatum 01.10.2026', 'Zahlbar bis 31.10.2026', 'Rechnungsbetrag CHF 123.45',
                     f'IBAN {IBAN}', 'Policen-Nr. 12.345.678'])

SCAN_PDF = make_pdf([])          # a page without any text: what a scanner produces before OCR
DOC9_OCR = ('Garage Beispiel AG\nRechnung vom 20.09.2026\nZahlbar innert 30 Tagen\nTotal CHF 456.70\n'
            f'IBAN {IBAN}\n')


class FakePaperless(FakeServer):
    def __init__(self):
        self.docs = {
            7: {'id': 7, 'title': f'Rechnung Krankenkasse (Rueckruf {PHONE})', 'created': '2026-10-01T00:00:00+02:00',
                'added': '2026-10-02T09:00:00+02:00', 'modified': '2026-10-02T09:00:00+02:00', 'correspondent': 1,
                'document_type': 2, 'tags': [3], 'content': DOC7_CONTENT, 'original_file_name': 'rechnung.pdf',
                'page_count': 1, 'notes': []},
            8: {'id': 8, 'title': 'Lohnabrechnung Mai', 'created': '2024-05-31T00:00:00+02:00',
                'added': '2026-10-01T09:00:00+02:00', 'modified': '2026-10-01T09:00:00+02:00', 'correspondent': None,
                'document_type': None, 'tags': [], 'content': 'Lohn Mai 2024', 'original_file_name': 'lohn.pdf',
                'page_count': 1, 'notes': []},
            9: {'id': 9, 'title': 'Scan Rechnung Garage', 'created': '2026-09-20T00:00:00+02:00',
                'added': '2026-09-21T09:00:00+02:00', 'modified': '2026-09-21T09:00:00+02:00', 'correspondent': None,
                'document_type': None, 'tags': [], 'content': DOC9_OCR, 'original_file_name': 'scan.pdf',
                'page_count': 1, 'notes': []}}
        rule = {'match': '', 'matching_algorithm': 1, 'is_insensitive': True}          # paperless' defaults
        self.tax = {'correspondents': {1: dict(rule, id=1, name='Krankenkasse Muster AG', document_count=1)},
                    'document_types': {2: dict(rule, id=2, name='Rechnung', document_count=1)},
                    'tags': {3: dict(rule, id=3, name='gesundheit', document_count=1, is_inbox_tag=False),
                             4: dict(rule, id=4, name='steuern', document_count=0, is_inbox_tag=False)}}
        self.next_id = 50
        super().__init__(self.handle)

    def tax_handle(self, method, kind, oid, body):
        objs = self.tax[kind]
        if oid is None and method == 'POST':
            d = json.loads(body)
            if any(o['name'].lower() == d.get('name', '').lower() for o in objs.values()):
                return jresp({'name': ['This field must be unique.']}, 400)
            self.next_id += 1
            o = {'id': self.next_id, 'match': '', 'matching_algorithm': 1, 'is_insensitive': True, 'document_count': 0}
            if kind == 'tags':
                o['is_inbox_tag'] = False
            o.update(d)
            objs[o['id']] = o
            return jresp(o, 201)
        o = objs.get(oid)
        if o is None:
            return jresp({'detail': 'Not found.'}, 404)
        if method == 'GET':
            return jresp(o)
        if method == 'PATCH':
            o.update(json.loads(body))
            return jresp(o)
        return jresp({'detail': f'Method "{method}" not allowed.'}, 405)

    def handle(self, method, path, headers, body):
        if headers.get('Authorization') != f'Token {PL_TOKEN}':
            return jresp({'detail': 'Invalid token.'}, 401)
        v = re.search(r'version=(\d+)', headers.get('Accept') or '')
        if v and int(v.group(1)) < 9:                                    # like paperless 3.3 (API 9..10)
            return jresp({'detail': 'Invalid version in "Accept" header.'}, 406)
        u = urllib.parse.urlsplit(path)
        q = dict(urllib.parse.parse_qsl(u.query))
        m = re.fullmatch(r'/api/(tags|correspondents|document_types)/(?:(\d+)/)?', u.path)
        if m and not (m.group(2) is None and method == 'GET'):
            return self.tax_handle(method, m.group(1), m.group(2) and int(m.group(2)), body)
        if m:
            lst = [self.tax[m.group(1)][k] for k in sorted(self.tax[m.group(1)])]
            if m.group(1) != 'tags':
                return jresp({'count': len(lst), 'next': None, 'results': lst})
            if q.get('page') == '2':                                     # tags: 2 pages; 'next' names a public host
                return jresp({'count': len(lst), 'next': None, 'results': lst[1:]})
            return jresp({'count': len(lst), 'next': 'https://paperless.example.invalid/api/tags/?page=2&page_size=100',
                          'results': lst[:1]})
        if u.path == '/api/documents/' and method == 'GET':
            docs = sorted(self.docs.values(), key=lambda d: d['added'], reverse=True)
            if 'query' in q:
                docs = [d for d in docs if q['query'].lower() in (d['title'] + d['content']).lower()]
                docs = [dict(d, __search_hit__={'highlights': 'RAW-HIGHLIGHT ' + d['content'][:40]}) for d in docs]
            return jresp({'count': len(docs), 'next': None, 'results': docs[:int(q.get('page_size', 25))]})
        m = re.fullmatch(r'/api/documents/(\d+)/', u.path)
        if m:
            d = self.docs.get(int(m.group(1)))
            if d and method == 'PATCH':
                d.update(json.loads(body), modified='2026-10-12T10:00:00+02:00')
            elif d and method != 'GET':
                return jresp({'detail': f'Method "{method}" not allowed.'}, 405)
            return jresp(d) if d else jresp({'detail': 'Not found.'}, 404)
        m = re.fullmatch(r'/api/documents/(\d+)/download/', u.path)
        if m:
            return 200, {'Content-Type': 'application/pdf',
                         'Content-Disposition': 'attachment; filename="rechnung.pdf"'}, \
                SCAN_PDF if m.group(1) == '9' else DOC7_PDF
        if u.path == '/api/documents/post_document/' and method == 'POST':
            return jresp('task-0001')
        if u.path == '/api/tasks/':
            return jresp([{'task_id': q.get('task_id'), 'status': 'SUCCESS', 'related_document': '42'}])
        return jresp({'detail': 'no route'}, 404)


class FakeFirefly(FakeServer):
    def __init__(self):
        super().__init__(self.handle)

    def handle(self, method, path, headers, body):
        if headers.get('Authorization') != f'Bearer {FF_TOKEN}':
            return jresp({'message': 'Unauthenticated.'}, 401)
        u = urllib.parse.urlsplit(path)
        if u.path == '/api/v1/about':
            return jresp({'data': {'version': '6.4.0'}})
        if u.path == '/api/v1/insight/expense/category':
            return jresp([{'name': 'Groceries', 'difference_float': -420.5, 'currency_code': 'CHF'}])
        if u.path == '/api/v1/insight/income/category':
            return jresp([{'name': 'Salary', 'difference_float': 7000, 'currency_code': 'CHF'}])
        if u.path == '/api/v1/insight/expense/expense':
            return jresp([{'name': 'Migros Exampletown', 'difference_float': -300.0, 'currency_code': 'CHF'},
                          {'name': 'Bar Zur Traube', 'difference_float': -80.0, 'currency_code': 'CHF'}])
        return jresp({'message': 'no route'}, 404)


TELEGRAM = FakeTelegram()
PAPERLESS = FakePaperless()
PAPERLESS_W = FakePaperless()        # own state: the metadata-write tests change its documents and rules
FIREFLY = FakeFirefly()
CLI_DIR = Path(os.environ.get('VAULT_CLI_DIR', '/home/node/bin'))     # ~/bin/vault + ~/bin/paperless (not in the image)


def make_env(name, **extra):
    env = {'VAULT_DATA': str(TMP / name), 'VAULT_APP': str(ROOT), 'VAULT_PYTHON': PY, 'VAULT_TGREAD': TGREAD,
           'VAULT_LLM_LOCAL': str(STUB_PATH), 'VAULT_SECRETSCAN': SECRETSCAN, 'VAULT_BILLS': BILLS,
           'VAULT_LLM_CTL': str(ROOT / 'app' / 'llm-ctl'), 'VAULT_TOKEN_SHA256': TOKEN_SHA, 'VAULT_NO_LLAMA': '1',
           'VAULT_NO_SYNC': '1', 'VAULT_TELEGRAM_API': TELEGRAM.url, 'LLM_LOCAL_PORT': '1'}
    env.update(extra)
    return env


def make_cfg(name, **extra):
    cfg = V.Config(make_env(name, **extra))
    for d in (cfg.data, cfg.home, cfg.secrets, cfg.state, cfg.cache, cfg.tmp, cfg.inbox, cfg.logs):
        V.ensure_dir(d)
    os.environ['HOME'] = str(cfg.home)           # like vaultd.main(): secretscan reads the vault's own secrets
    return cfg


def all_files_text(root):
    out = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            try:
                out.append(Path(dp, f).read_bytes().decode('utf-8', 'replace'))
            except OSError:
                pass
    return '\n'.join(out)


class Clock:
    def __init__(self, t=1_791_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


# ============================================================================================ core

class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(f'secrets-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)

    def test_validation_set_once_and_private(self):
        with self.assertRaises(V.VaultError) as cm:
            self.store.set('telegram', {'bot_token': 'nope', 'chat_id': CHAT_ID})
        self.assertNotIn('nope', str(cm.exception))              # values are never echoed
        with self.assertRaises(V.VaultError):
            self.store.set('telegram', {'bot_token': BOT_TOKEN})   # missing key
        with self.assertRaises(V.VaultError):
            self.store.set('paperless', {'url': 'http://x:8000/api/../evil', 'token': PL_TOKEN})
        with self.assertRaises(V.VaultError):
            self.store.set('nonsense', {})
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': int(CHAT_ID)})
        p = self.store.path('telegram')
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(self.store.get('telegram')['chat_id'], CHAT_ID)
        with self.assertRaises(V.VaultError) as cm:
            self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.assertEqual(cm.exception.code, 'already_set')
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': '987654321'}, replace_ok=True)
        self.assertEqual(self.store.names(), {'telegram': True, 'paperless': False, 'firefly': False,
                                              'homeassistant': False, 'gmail': False})
        self.store.set('paperless', {'url': 'http://198.51.100.5:8000/', 'token': PL_TOKEN})
        self.assertEqual(self.store.get('paperless')['url'], 'http://198.51.100.5:8000')
        with self.assertRaises(V.NotConfigured):
            self.store.get('firefly')

    def test_hmac_key_stable(self):
        k = self.store.hmac_key()
        self.assertEqual(len(k), 32)
        self.assertEqual(k, V.SecretStore(self.cfg).hmac_key())


class AuditTests(unittest.TestCase):
    def test_log_read_clean_rotate(self):
        cfg = make_cfg('audit')
        clock = Clock()
        a = V.Audit(cfg.audit_path, clock=clock)
        a.log('raw_request', reason='line1\nline2\x00‮', query='q' * 1000, n=3, ok=True)
        self.assertEqual(stat.S_IMODE(cfg.audit_path.stat().st_mode), 0o600)
        clock.t += 10 * 86400
        a.log('later')
        recs = a.read(days=7)
        self.assertEqual([r['event'] for r in recs], ['later'])
        recs = a.read(days=30)
        self.assertEqual(recs[0]['reason'], 'line1 line2')
        self.assertLessEqual(len(recs[0]['query']), 300)
        a.MAX_BYTES = 10
        a.log('rotated')
        self.assertTrue(cfg.audit_path.with_name('audit.log.1').exists())
        self.assertEqual([r['event'] for r in a.read(days=30)], ['raw_request', 'later', 'rotated'])


class NotifierTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(f'notify-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        TELEGRAM.fail = False

    def test_send_only_sendmessage_protected(self):
        n = V.Notifier(self.store, TELEGRAM.url)
        before = len(TELEGRAM.sent)
        self.assertTrue(n.send('hello owner'))
        p = TELEGRAM.sent[-1]
        self.assertEqual(len(TELEGRAM.sent), before + 1)
        self.assertEqual((p['chat_id'], p['text'], p['protect_content']), (CHAT_ID, 'hello owner', 'true'))
        for bad in ('forwardMessage', 'copyMessage', 'setWebhook', 'sendDocument', 'unpinChatMessage',
                    'deleteMessage', 'getChatHistory'):
            with self.assertRaises(V.NotifyError):
                n._call(bad, {})
        self.assertEqual(V.Notifier.METHODS, ('sendMessage', 'getUpdates', 'answerCallbackQuery', 'editMessageText',
                                              'getFile', 'pinChatMessage', 'getChat'))   # getFile: finance intake;
        # pinChatMessage + getChat (the owner's chat only): the pinned status message (app/board.py)
        self.assertEqual(n.bot_id(), BOT_ID)

    def test_errors_never_contain_the_token(self):
        TELEGRAM.fail = True
        n = V.Notifier(self.store, TELEGRAM.url)
        with self.assertRaises(V.NotifyError) as cm:
            n.send('x')
        self.assertIn('chat not found', str(cm.exception))
        self.assertNotIn(BOT_TOKEN, str(cm.exception))
        n2 = V.Notifier(self.store, 'http://127.0.0.1:1')
        with self.assertRaises(V.NotifyError) as cm:
            n2.send('x')
        self.assertNotIn(BOT_TOKEN, str(cm.exception))

    def test_test_mode_logs_only(self):
        logged = []
        n = V.Notifier(V.SecretStore(make_cfg('notify-empty')), TELEGRAM.url, test_mode=True, log=logged.append)
        before = len(TELEGRAM.sent)
        n.send('Code: 123456')
        self.assertEqual(len(TELEGRAM.sent), before)
        self.assertIn('TEST MODE', logged[0])


class FakeNotifier:
    def __init__(self, fail=False):
        self.msgs, self.buttons, self.fail = [], [], fail

    def send(self, text, buttons=None):
        if self.fail:
            raise V.NotifyError('Telegram sendMessage failed: test')
        self.msgs.append(text)
        self.buttons.append(buttons)
        return 100 + len(self.msgs)

    def code(self):
        return re.search(r'Code: (\d{6})', self.msgs[-1]).group(1)


class RawRequestTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(f'raw-{self._testMethodName}')
        self.audit = V.Audit(self.cfg.audit_path)
        self.n = FakeNotifier()
        self.clock = Clock()
        self.raw = V.RawRequests(self.n, self.audit, b'k' * 32, clock=self.clock)

    def test_release_once(self):
        r = self.raw.create('tg', "search 'Lugano'", 'owner asked for the exact quote', 'RAW TEXT')
        self.assertEqual((r['valid_seconds'], r['approval'], r['attempts_allowed']), (900, 'code', 3))
        msg = self.n.msgs[-1]
        self.assertTrue(msg.startswith("🔐 Claude asks for raw text\nWhy: owner asked for the exact quote\n"
                                       "What: tg · search 'Lugano' · ~8 bytes\n\n🔑 Code: "), msg)
        self.assertIn('(valid 15 min)', msg)
        self.assertIsNone(self.n.buttons[-1])                           # fallback mode: no buttons
        code = self.n.code()
        self.assertEqual(self.raw.release(r['request_id'], code), 'RAW TEXT')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'], code)
        self.assertEqual(cm.exception.code, 'request_released')
        log = self.cfg.audit_path.read_text()
        self.assertNotIn(code, log)
        self.assertNotIn('RAW TEXT', log)
        self.assertEqual([e['event'] for e in self.audit.read()], ['raw_request', 'raw_released'])

    def test_three_wrong_codes_kill(self):
        r = self.raw.create('paperless', 'paperless #7', 'need the exact wording', ('a.pdf', b'%PDF'), kind='file')
        code = self.n.code()
        wrong = f'{(int(code) + 1) % 1_000_000:06d}'
        for left in (2, 1):
            with self.assertRaises(V.VaultError) as cm:
                self.raw.release(r['request_id'], wrong)
            self.assertEqual((cm.exception.code, cm.exception.extra['attempts_left']), ('wrong_code', left))
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'], 'abc')                     # malformed counts too
        self.assertEqual(cm.exception.code, 'request_dead')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'], code)                      # even the right code: dead
        self.assertEqual(cm.exception.code, 'request_dead')
        self.assertIsNone(self.raw.reqs[r['request_id']]['payload'])

    def test_expiry_limits_and_failures(self):
        r = self.raw.create('test', 'test', 'checking the flow', 'x')
        self.clock.t += 901
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'], self.n.code())
        self.assertEqual(cm.exception.code, 'request_expired')
        for i in range(3):
            self.raw.create('test', 'test', f'reason {i}', 'x')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.create('test', 'test', 'one too many', 'x')
        self.assertEqual(cm.exception.code, 'too_many_pending')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.create('test', 'test', '  ', 'x')
        self.assertEqual(cm.exception.code, 'reason_required')
        self.clock.t += 3601                                             # the 3 pending expire; a new hour
        for i in range(16):                                              # 4 so far today + 16 = 20 (10 an hour)
            if i == 8:
                self.clock.t += 3601
            rr = self.raw.create('test', 'test', f'reason {i}', 'x')
            self.raw.release(rr['request_id'], self.n.code())
        with self.assertRaises(V.VaultError) as cm:
            self.raw.create('test', 'test', 'limit', 'x')
        self.assertEqual(cm.exception.code, 'daily_limit')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release('nope', '123456')
        self.assertEqual(cm.exception.code, 'unknown_request')

    def test_notify_failure_stores_nothing(self):
        raw = V.RawRequests(FakeNotifier(fail=True), self.audit, b'k' * 32, clock=self.clock)
        with self.assertRaises(V.VaultError) as cm:
            raw.create('test', 'test', 'checking', 'x')
        self.assertEqual(cm.exception.code, 'notify_failed')
        self.assertEqual(raw.reqs, {})
        self.assertEqual(raw.pending(), [])

    def test_kind_mismatch_costs_no_attempt(self):
        r = self.raw.create('secret-rotate', 'paperless', 'token rotated', None, kind='secret', meta={'name': 'paperless'})
        self.assertIn('replace a vault secret\nWhy: token rotated\nSecret: paperless', self.n.msgs[-1])
        code = self.n.code()
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'], code, expect_kind=('text', 'file'))
        self.assertEqual(cm.exception.code, 'wrong_request')
        with self.assertRaises(V.VaultError):
            self.raw.release(r['request_id'], code, expect_kind='secret', expect_meta={'name': 'firefly'})
        self.assertEqual(self.raw.reqs[r['request_id']]['attempts'], 0)
        self.assertIsNone(self.raw.release(r['request_id'], code, expect_kind='secret',
                                           expect_meta={'name': 'paperless'}))

    def test_scrub_codes_masks_only_live_codes(self):
        r = self.raw.create('test', 'test', 'checking', 'x')
        code = self.n.code()
        text = f'old 654321, live {code}, spaced {code[:3]} {code[3:]}, longer 9{code}9'
        out = self.raw.scrub_codes(text)
        self.assertNotIn(code, out.replace(f'9{code}9', ''))
        self.assertIn('654321', out)
        self.assertEqual(out.count('[code]'), 2)
        self.raw.release(r['request_id'], code)
        self.assertEqual(self.raw.scrub_codes(f'now {code}'), f'now {code}')


class GateTests(unittest.TestCase):
    def test_flush_before_external_after_private(self):
        flushes = []
        g = V.LLMGate(flush=lambda: flushes.append(1))
        with g.use(private=False):
            pass
        self.assertEqual(flushes, [])
        with g.use(private=True, what='tgread search'):
            self.assertEqual(g.busy[0], 'tgread search')
        self.assertTrue(g.dirty)
        with g.use(private=True):
            pass
        self.assertEqual(flushes, [])
        with g.use(private=False):
            pass
        self.assertEqual(flushes, [1])
        with g.use(private=False):
            pass
        self.assertEqual(flushes, [1])

    def test_flush_failure_and_busy(self):
        def boom():
            raise RuntimeError('down')
        g = V.LLMGate(flush=boom)
        with g.use(private=True):
            pass
        with self.assertRaises(V.LLMUnavailable):
            with g.use(private=False):
                pass
        self.assertTrue(g.dirty)                                         # still dirty: the next one retries
        g2 = V.LLMGate()
        with g2.use(private=True, what='long job'):
            with self.assertRaises(V.LLMBusy) as cm:
                with g2.use(private=True, timeout=0.2):
                    pass
            self.assertIn('long job', str(cm.exception))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(f'policy-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)
        self.store.set('paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})
        self.gate = V.LLMGate()
        self.policy = V.Policy(self.cfg, self.gate)
        llm_mode('ok')

    def test_regex_net(self):
        out = self.policy.regex_net(f'call {PHONE}, iban {IBAN}, token {PL_TOKEN}, Examplestrasse 5, 1234 Exampletown, '
                                    f'bot {BOT_TOKEN}')
        for raw in (PHONE, IBAN, PL_TOKEN, BOT_TOKEN):
            self.assertNotIn(raw, out)
        self.assertIn('Examplestrasse 5', out)                              # policy v2 keeps addresses
        self.policy.nets.append(lambda t: t.replace('Exampletown', 'N.'))
        self.assertIn('N.', self.policy.regex_net('in Exampletown'))

    def test_anonymize_and_no_fallback(self):
        n0 = len(llm_calls())
        out = self.policy.anonymize(f'Hi {PHONE}. Er hat Herzschmerz.', owner_name='Nico')
        self.assertTrue(out.startswith('ANON '))
        self.assertIn('[private: health]', out)
        self.assertNotIn(PHONE, out)
        call = llm_calls()[n0]
        self.assertEqual(call['args'], ['--anonymize', '--owner-name', 'Nico'])
        self.assertNotIn(PHONE, call['text'])                            # regex net ran before the LLM too
        self.assertTrue(self.gate.dirty)
        llm_mode('fail')
        with self.assertRaises(V.LLMUnavailable) as cm:
            self.policy.anonymize('Er hat Herzschmerz.')
        self.assertIn('exit 3', str(cm.exception))
        llm_mode('ok')
        self.policy.anonymize('Lohn 9500', owner_name='Nico', keep_own_money=True)   # admin documents only
        self.assertEqual(llm_calls()[-1]['args'], ['--anonymize', '--owner-name', 'Nico', '--keep-own-money'])

    def test_policy_version(self):
        # His own money/business details are redacted too (v3, v3.1), then message text leaves as
        # checked paraphrases (v4); the version is part of the paperless cache key, so older content is never served
        self.assertEqual(V.POLICY_VERSION, 'llm-local-v4.1+regex-2026-10-13')
        self.assertIn('"llm-local-v4.1+regex-2026-10-13"', Path(ROOT / 'vendor' / 'llm-local').read_text())
        self.assertIn('POLICY_VERSION}', Path(ROOT / 'app' / 'sources.py').read_text())

    def test_anonymization_cache_private_jobs_only(self):
        # plan v2 #3: llm-local's cache (detections as positions, verdicts, sealed summaries/paraphrases) for the
        # vault's private jobs; never for a plain prompt such as triage or llm-run (Claude's own text)
        self.policy.anonymize('Treffpunkt 07:30', paraphrase=True)
        self.assertEqual(llm_calls()[-1]['cache'], str(self.cfg.llm_cache))
        self.policy.run_llm(['--json', '--system', 'triage'], 'x')
        self.assertIsNone(llm_calls()[-1]['cache'])
        self.assertNotIn('LLM_LOCAL_CACHE_DIR', self.cfg.tool_env())
        self.assertEqual(self.cfg.llm_cache, self.cfg.state / 'llm-cache')
        self.assertFalse(self.policy.clear_cache())
        (self.cfg.llm_cache / 'detect' / 'ab').mkdir(parents=True)
        (self.cfg.llm_cache / 'key').write_bytes(b'k' * 32)
        self.assertTrue(self.policy.clear_cache())
        self.assertFalse(self.cfg.llm_cache.exists())
        with self.assertRaises(V.VaultError):                         # llm-run can't point llm-local at it either
            D.llm_argv(['--anonymize', '--cache-dir', str(self.cfg.llm_cache)])

    def test_policy_v4_paraphrase_only_for_messages(self):
        # Policy v4: message text is summarized and paraphrased without changing any meaning, numbers or facts.
        # Telegram/Gmail/event text: --paraphrase (the check and fallback live in llm-local, tests/llm-local). Paperless
        # content and the media extractors keep the anonymized wording.
        llm_mode('plain')
        try:
            out = self.policy.anonymize('Treffpunkt 07:30, er hat Herzschmerz', owner_name='Nico', paraphrase=True)
            self.assertEqual(llm_calls()[-1]['args'], ['--anonymize', '--owner-name', 'Nico', '--paraphrase'])
            self.assertEqual(out, 'Meeting point 07:30, er hat [private: health]')
            out = self.policy.anonymize("Treffpunkt, Lohn CHF 9'500", keep_own_money=True)     # paperless
            self.assertEqual((out, llm_calls()[-1]['args']), ("Treffpunkt, Lohn CHF 9'500",
                                                              ['--anonymize', '--keep-own-money']))
            self.assertEqual(D.llm_argv(['--anonymize', '--paraphrase']), ['--anonymize', '--paraphrase'])
            for src in ('sources.py', 'media.py'):                        # paperless content, media names/facts
                self.assertNotIn('paraphrase=', Path(ROOT / 'app' / src).read_text(), src)
        finally:
            llm_mode('ok')

    def test_policy_v31_mail_amounts(self):
        # Regression: receipts in `vault gmail search` showed "$108.34". Mail is his own money: --all-amounts, and
        # the money net runs again in code, so even an LLM that keeps a figure (this stub) can't leak it
        llm_mode('plain')
        try:
            receipts = "Total $108.34 | USD 12.00 | CHF 1'234.50 | € 9,99 | Total: 45.00 | am 21.10. um 10.30 Uhr"
            out = self.policy.anonymize(receipts, owner_name='Nico', all_amounts=True)
            self.assertEqual(llm_calls()[-1]['args'], ['--anonymize', '--owner-name', 'Nico', '--all-amounts'])
            self.assertEqual(out, 'Total [amount] | [amount] | [amount] | [amount] | Total: [amount] | am 21.10. um 10.30 Uhr')
            self.assertEqual(self.policy.anonymize('Total $108.34'), 'Total $108.34')      # chats: a lone small amount stays
            self.assertEqual(self.policy.anonymize("Lohn CHF 9'500", keep_own_money=True), "Lohn CHF 9'500")  # paperless exempt
            self.assertNotIn('--all-amounts', llm_calls()[-1]['args'])
            with self.assertRaises(V.VaultError):
                self.policy.anonymize('x', keep_own_money=True, all_amounts=True)
            self.assertEqual(self.policy.money_net('Paid $108.34, Treffpunkt 19.00'), 'Paid [amount], Treffpunkt 19.00')
            self.assertEqual(D.llm_argv(['--anonymize', '--all-amounts']), ['--anonymize', '--all-amounts'])
        finally:
            llm_mode('ok')


# ============================================================================================ tgread

def load_tgread():
    os.environ.setdefault('TGREAD_HOME', str(TMP / 'tgread-parser-home'))
    return V.load_module('tgread_parser_check', TGREAD)


class TgArgvTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T = load_tgread()
        cls.parser = cls.T.build_parser()

    def parse(self, cmd, params, raw=False):
        return self.parser.parse_args(S.build_tg_argv(cmd, params, raw=raw))

    def test_injection_never_enables_raw(self):
        a = self.parse('search', {'query': '--raw', 'chat': '--raw', 'from': '-n 5 --raw', 'n': 5})
        self.assertFalse(a.raw)
        self.assertEqual((a.query, a.chat, a.sender, a.n), ('--raw', '--raw', '-n 5 --raw', 5))
        a = self.parse('recent', {'chat': '--raw', 'hours': 2.5})
        self.assertFalse(a.raw)
        self.assertEqual(a.hours, 2.5)
        a = self.parse('exclude', {'action': 'add', 'chats': ['--raw', '-1001234']})
        self.assertEqual((a.action, a.chats), ('add', ['--raw', '-1001234']))
        a = self.parse('search', {'query': 'x'}, raw=True)                  # only the raw-release path
        self.assertTrue(a.raw)
        with self.assertRaises(V.VaultError):
            S.build_tg_argv('summarize', {}, raw=True)

    def test_validation(self):
        bad = [('search', {'query': 'x', 'raw': True}), ('search', {}), ('search', {'query': 'a\nb'}),
               ('search', {'query': 'x', 'n': '5'}), ('search', {'query': 'x', 'n': 0}),
               ('search', {'query': 'x', 'n': True}), ('search', {'query': 'x' * 501}),
               ('recent', {'hours': -1}), ('chats', {'type': 'evil'}), ('exclude', {'action': 'drop'}),
               ('sync', {'chats': ['--raw']}), ('download', {'chat': 'x', 'msg': 1}), ('login-qr', {}),
               ('set-credentials', {}), ('search', {'query': 'x', 'full': 'yes'})]
        for cmd, params in bad:
            with self.assertRaises(V.VaultError, msg=(cmd, params)):
                S.build_tg_argv(cmd, params)
        a = self.parse('chats', {'pseudonyms': False, 'all': True, 'type': 'group'})
        self.assertEqual((a.pseudonyms, a.all, a.type), (False, True, 'group'))
        a = self.parse('sync', {'chats': ['-1001', '@x'], 'max_seconds': 60, 'since': '7d'})
        self.assertEqual((a.chats, a.max_seconds, a.since), (['-1001', '@x'], 60, '7d'))
        a = self.parse('purge', {'chat': '--yes'})
        self.assertEqual((a.chat, a.yes), ('--yes', False))
        a = self.parse('alias', {'action': 'set', 'args': ['-1001234', 'dive group'], 'tag': 'tauchen'})
        self.assertEqual((a.action, a.args, a.tag), ('set', ['-1001234', 'dive group'], 'tauchen'))
        a = self.parse('find-chat', {'query': '--yes', 'n': 5})
        self.assertEqual((a.query, a.n), ('--yes', 5))
        for cmd in S.TG_SPECS:                                           # every spec parses with tgread's parser
            req = {p.name: (p.choices[0] if p.kind == 'choice' else 'x')
                   for p in S.TG_SPECS[cmd]['params'] if p.required}
            self.parse(cmd, req)


class TgRunTests(unittest.TestCase):
    """The real vendored tgread (venv python) in a fresh vault home."""

    def setUp(self):
        self.cfg = make_cfg(f'tg-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)
        self.audit = V.Audit(self.cfg.audit_path)
        self.n = V.Notifier(self.store, TELEGRAM.url)
        self.policy = V.Policy(self.cfg, V.LLMGate())
        self.tg = S.TG(self.cfg, self.policy, self.policy.gate, self.audit, self.n)

    def test_not_logged_in_and_config(self):
        r = self.tg.run('search', {'query': 'Lugano'})                    # the local archive: empty, no login needed
        self.assertEqual((r['exit_code'], r['stdout'].count('0 hit(s)')), (0, 1), r)
        cfg = json.loads(self.tg.config_path.read_text())                # ensured before any LLM-backed command
        self.assertEqual((cfg['local_llm_cmd'], cfg['llm_fallback'], cfg['use_local_llm']), (str(STUB_PATH), False, True))
        self.assertEqual((cfg['local_llm_anonymize_args'], cfg['local_llm_summary_args']),     # policy v4
                         (['--anonymize', '--paraphrase'], ['--summary', '--paraphrase']))
        r = self.tg.run('status', {})
        self.assertEqual(r['exit_code'], 0, r)
        self.assertIn('session: missing', r['stdout'])
        self.assertIn('sync: by the vault every 15 min', r['stdout'])
        self.assertNotIn('cron:', r['stdout'])
        self.assertNotIn('local LLM: unavailable', r['stdout'])
        cfg.update(llm_fallback=True, local_llm_cmd='/bin/cat', local_llm_anonymize_args=['--anonymize'])
        self.tg.config_path.write_text(json.dumps(cfg))                  # changed behind the vault's back...
        self.tg.run('search', {'query': 'x'})                            # ...restored before the next search
        cfg = json.loads(self.tg.config_path.read_text())
        self.assertEqual((cfg['local_llm_cmd'], cfg['llm_fallback'], cfg['local_llm_anonymize_args']),
                         (str(STUB_PATH), False, ['--anonymize', '--paraphrase']))
        self.assertFalse(self.tg.ensure_config())                         # idempotent
        self.assertEqual([e['event'] for e in self.audit.read()], ['tg_search', 'tg_search'])

    def test_anonymization_cache_env_and_cleared_on_purge(self):
        # plan v2 #3: tgread's llm-local runs use the cache (env), finish when the caller left (the retry is then
        # instant), and tg purge / exclude add / wipe clear all of it
        self.assertEqual(self.tg.env()['LLM_LOCAL_CACHE_DIR'], str(self.cfg.llm_cache))
        self.assertFalse(self.tg.stop_on_gone('recent', {}))
        self.assertEqual(self.tg.run('search', {'query': 'x'})['exit_code'], 0)   # the real tgread writes its config
        real = self.tg._exec
        self.tg._exec = lambda argv, timeout, **kw: (0, '', '')
        try:
            for cmd, params, cleared in (('search', {'query': 'x'}, False), ('exclude', {'action': 'list'}, False),
                                         ('purge', {'chat': 'Grouptrip', 'yes': True}, True),
                                         ('exclude', {'action': 'add', 'chats': ['Grouptrip']}, True),
                                         ('wipe', {'data': True}, True)):
                self.cfg.llm_cache.mkdir(parents=True, exist_ok=True)
                (self.cfg.llm_cache / 'key').write_bytes(b'k' * 32)
                self.tg.run(cmd, params)
                self.assertEqual(not self.cfg.llm_cache.exists(), cleared, cmd)
        finally:
            self.tg._exec = real
        self.assertEqual([e['reason'] for e in self.audit.read() if e['event'] == 'llm_cache_cleared'],
                         ['tg purge', 'tg exclude', 'tg wipe'])

    def test_bot_chat_always_excluded(self):
        with self.assertRaises(V.VaultError) as cm:
            self.tg.run('sync', {})
        self.assertEqual(cm.exception.code, 'bot_not_excluded')
        with self.assertRaises(V.VaultError):
            self.tg.run('search', {'query': 'x', 'sync': True})
        self.assertIsNone(self.tg.sync_once())
        self.assertIn('skipped', self.tg.sync_state['last']['error'])
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.assertEqual(self.tg.forced_excludes(), [777000, BOT_ID])
        self.assertEqual(self.tg.env()['TGREAD_FORCE_EXCLUDE'], f'777000,{BOT_ID}')
        with self.assertRaises(V.VaultError) as cm:
            self.tg.run('exclude', {'action': 'rm', 'chats': [str(BOT_ID)]})
        self.assertEqual(cm.exception.code, 'protected_chat')
        r = self.tg.run('exclude', {'action': 'list'})
        self.assertEqual(r['exit_code'], 0, r)
        self.assertIn(str(BOT_ID), r['stdout'])
        self.assertIn('777000', r['stdout'])
        r = self.tg.run('sync', {'max_seconds': 10})                     # allowed now; fails: not logged in
        self.assertEqual(r['exit_code'], 3, r)

    def test_credentials_validation(self):
        with self.assertRaises(V.VaultError):
            self.tg.set_credentials('12x', 'f' * 32)
        with self.assertRaises(V.VaultError):
            self.tg.set_credentials('123456', 'nothex')
        r = self.tg.set_credentials(123456, 'ab' * 16)
        self.assertEqual(r['exit_code'], 0, r)
        self.assertTrue(self.tg.creds_path.is_file())
        self.assertEqual(stat.S_IMODE(self.tg.creds_path.stat().st_mode), 0o600)
        self.assertNotIn('ab' * 16, r['stdout'] + r['stderr'])
        self.assertNotIn('ab' * 16, self.cfg.audit_path.read_text())
        self.tg.session_path.write_bytes(b'x')
        with self.assertRaises(V.VaultError) as cm:
            self.tg.set_credentials(123456, 'ab' * 16)
        self.assertEqual(cm.exception.code, 'session_exists')


class LoginJobTests(unittest.TestCase):
    def test_qr_then_2fa_never_on_disk(self):
        policy = V.Policy(make_cfg('login-policy'), V.LLMGate())     # the regex net needs the real tgread
        cfg = make_cfg('login', VAULT_TGREAD=str(FAKE_TG_PATH), VAULT_PYTHON=sys.executable)
        job = S.LoginJob(cfg, policy, cfg.tool_env)
        done = []
        job.on_success = lambda: done.append(1)
        with self.assertRaises(V.VaultError):
            job.password('x')                                            # nothing waiting yet
        snap = job.start(timeout=60)
        self.assertEqual(snap['state'], 'QR_READY', snap)
        self.assertEqual(base64.b64decode(snap['qr_png_b64'])[:4], b'\x89PNG')
        self.assertEqual(snap['expires_in'], 30)
        for _ in range(50):
            if job.snapshot()['state'] == 'PASSWORD_NEEDED':
                break
            time.sleep(0.1)
        job.password('wrong-one')
        for _ in range(50):
            if job.snapshot()['state'] == 'PASSWORD_INVALID':
                break
            time.sleep(0.1)
        self.assertEqual(job.snapshot()['state'], 'PASSWORD_INVALID')
        job.password('right-horse-battery')
        for _ in range(50):
            if done:
                break
            time.sleep(0.1)
        snap = job.snapshot()
        self.assertEqual((snap['state'], snap['exit_code'], done), ('LOGIN_OK', 0, [1]), snap)
        self.assertNotIn('qr_png_b64', snap)
        blob = all_files_text(cfg.data)
        self.assertNotIn('right-horse-battery', blob)
        self.assertNotIn('wrong-one', blob)
        with self.assertRaises(V.VaultError):
            job.password('a\nb')


# ============================================================================================ HTTP API

class ApiBase(unittest.TestCase):
    name = 'api'
    extra_env = {}

    @classmethod
    def setUpClass(cls):
        cls.cfg = make_cfg(cls.name, **cls.extra_env)
        cls.app = D.App(cls.cfg)
        cls.srv = D.Server(('127.0.0.1', 0), D.Handler)
        cls.url = f'http://127.0.0.1:{cls.srv.server_address[1]}'
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        D.APP = self.app
        os.environ['HOME'] = str(self.cfg.home)
        TELEGRAM.fail = False
        llm_mode('ok')

    def call(self, method, path, body=None, token=TOKEN, raw_body=None):
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={'Authorization': f'Bearer {token}'} if token else {})
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def raw_flow(self, source, query, reason='owner asked for it'):
        st, r = self.call('POST', '/raw/request', {'source': source, 'query': query, 'reason': reason})
        self.assertEqual(st, 200, r)
        st, out = self.call('POST', '/raw/release', {'request_id': r['request_id'], 'code': TELEGRAM.last_code()})
        self.assertEqual(st, 200, out)
        return out


def legacy_text(cls):
    """Privacy plan A (chunk 4, 14.10): TEXT_DEFAULT is False, so routes answer with hits/digests/cards unless the
    owner approves a text release. These older tests cover the text pipeline itself (anonymize, paraphrase, watch,
    jobs over text routes), which still runs after his approval: they run with the old default."""
    su, td = cls.setUp, cls.tearDown

    def setUp(self):
        self._text_default = D.TEXT_DEFAULT
        D.TEXT_DEFAULT = True
        su(self)

    def tearDown(self):
        try:
            td(self)
        finally:
            D.TEXT_DEFAULT = self._text_default
    cls.setUp, cls.tearDown = setUp, tearDown
    return cls


@legacy_text
class ApiCoreTests(ApiBase):
    name = 'api-core'

    def test_auth_and_routing(self):
        req = urllib.request.Request(self.url + '/health')
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as r:
            self.assertEqual(json.loads(r.read()), {'ok': True})
        for tok in (None, 'wrong', TOKEN + 'x'):
            st, r = self.call('GET', '/status', token=tok)
            self.assertEqual((st, r['code']), (401, 'unauthorized'))
        st, r = self.call('GET', '/status')
        self.assertEqual(st, 200, r)
        self.assertEqual(r['secrets'], {'telegram': False, 'paperless': False, 'firefly': False, 'homeassistant': False, 'gmail': False})
        self.assertFalse(r['tg']['bot_chat_excluded'])
        self.assertEqual(self.call('GET', '/nope')[0], 404)
        self.assertEqual(self.call('POST', '/tg/download', {'chat': 'x', 'msg': 1})[0], 404)
        self.assertEqual(self.call('POST', '/status', raw_body=b'not json')[0], 400)
        self.assertEqual(self.call('POST', '/tg/search', raw_body=b'[1]')[0], 400)
        self.assertEqual(self.call('POST', '/raw/request', raw_body=b'x' * ((1 << 20) + 1))[0], 413)
        self.assertEqual(self.call('DELETE', '/status')[0], 405)
        st, r = self.call('POST', '/tg/search', {'query': 'x', 'raw': True})
        self.assertEqual((st, r['code']), (400, 'unknown_param'))
        st, r = self.call('GET', '/')
        self.assertIn('POST /raw/request', r['endpoints'])
        self.assertIn('auth_failed', [e['event'] for e in self.call('GET', '/audit?days=1')[1]['events']])


class ApiMetricsTests(ApiBase):
    """plan v2 #8: GET /metrics and the /status line; numbers only, never a query or payload."""
    name = 'api-metrics'

    def test_metrics_api_numbers_only(self):
        self.call('POST', '/raw/request', {'source': 'tg', 'query': {'cmd': 'search', 'query': 'Geheimnis-xyz'},
                                           'reason': 'Herzschmerz-abc'})
        self.call('GET', '/nope/' + 'x' * 30)
        st, s = self.call('GET', '/status')
        self.assertEqual(st, 200, s)
        self.assertIn('calls', s['metrics'])
        self.assertEqual(s['llm']['waiting'], 0)
        st, m = self.call('GET', '/metrics?days=1')
        self.assertEqual(st, 200, m)
        routes = [r['route'] for r in m['routes']]
        self.assertIn('POST /raw/request', routes)
        self.assertIn('other', routes)                                  # unknown paths never become a key
        self.assertEqual(self.call('GET', '/metrics?days=x')[0], 400)
        self.app.metrics.flush()
        blob = (self.cfg.state / 'metrics.json').read_text()
        for word in ('Geheimnis', 'Herzschmerz', 'xxxxx'):
            self.assertNotIn(word, blob)

    def test_queued_request_dropped_when_client_leaves(self):
        # plan v2 #2: a caller that gave up while queued (the 188 s wait on 13.10) costs no LLM time
        go, started = threading.Event(), threading.Event()

        def hold():
            with self.app.gate.use(private=True, what='tgread summarize', cls='bulk'):
                started.set()
                go.wait(15)
        th = threading.Thread(target=hold, daemon=True)
        th.start()
        self.assertTrue(started.wait(5))
        n0 = len(llm_calls())
        body = json.dumps({'args': ['--max-tokens', '5'], 'text': 'Dropped-question-xyz'}).encode()
        port = int(self.url.rsplit(':', 1)[1])
        sk = socket.create_connection(('127.0.0.1', port), timeout=5)
        sk.sendall(b'POST /llm/run HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ' + TOKEN.encode()
                   + b'\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode()
                   + b'\r\n\r\n' + body)
        for _ in range(100):
            if self.app.gate.waiting:
                break
            time.sleep(0.05)
        q = self.app.gate.queue_view()
        self.assertEqual(([x['class'] for x in q['queue']], q['running']['what']), (['live'], 'tgread summarize'))
        sk.close()
        for _ in range(100):                                            # dropped within ~1 s, before it ran
            if not self.app.gate.waiting:
                break
            time.sleep(0.05)
        self.assertEqual(self.app.gate.waiting, 0)
        go.set()
        th.join(5)
        time.sleep(0.3)
        self.assertEqual([c for c in llm_calls()[n0:] if 'Dropped-question' in c['text']], [])
        self.assertGreaterEqual(self.app.metrics.summary(1)['llm']['dropped'], 1)


class SchedulerTests(unittest.TestCase):
    """plan v2 #2: the LLM gate as a priority queue (live > bulk > background, FIFO within, background promoted after
    10 min), dropping queued jobs whose caller left, stopping running ones, the flush rule, the queue view."""

    def setUp(self):
        self.now = [1000.0]
        self.flushes = []
        self.m = MX.Metrics(Path(tempfile.mkdtemp(dir=TMP)) / 'm.json')
        self.gate = V.LLMGate(flush=lambda: self.flushes.append(1), metrics=self.m, clock=lambda: self.now[0])

    def hold(self):
        """A running job that holds the gate until the returned event is set."""
        go, started = threading.Event(), threading.Event()

        def run():
            with self.gate.use(private=True, what='tgread recent', cls='live'):
                started.set()
                go.wait(10)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.assertTrue(started.wait(5))
        return go, t

    def enqueue(self, order, name, cls, private=True, alive=None, errors=None):
        n = self.gate.waiting

        def run():
            try:
                with self.gate.use(private=private, what=f'job {name}', cls=cls, alive=alive, timeout=20):
                    order.append(name)
            except V.VaultError as e:
                (errors if errors is not None else []).append((name, e.code))
        t = threading.Thread(target=run, daemon=True)
        t.start()
        for _ in range(200):
            if self.gate.waiting > n:
                break
            time.sleep(0.01)
        return t

    def test_priority_fifo_and_promotion(self):
        go, holder = self.hold()
        order = []
        ts = [self.enqueue(order, n, c) for n, c in (('bg1', 'background'), ('bulk1', 'bulk'), ('live1', 'live'),
                                                      ('live2', 'live'), ('bulk2', 'bulk'), ('bg2', 'background'))]
        view = self.gate.queue_view()
        self.assertEqual([q['class'] for q in view['queue']], ['live', 'live', 'bulk', 'bulk', 'background',
                                                               'background'])
        self.assertEqual(view['running']['what'], 'tgread recent')
        self.assertEqual(set(view['queue'][0]), {'class', 'what', 'waited_s'})
        go.set()
        for t in ts + [holder]:
            t.join(10)
        self.assertEqual(order, ['live1', 'live2', 'bulk1', 'bulk2', 'bg1', 'bg2'])
        go, holder = self.hold()                          # promotion: a background job waiting 10 min joins bulk
        order = []
        ts = [self.enqueue(order, 'bg', 'background')]
        self.now[0] += 601
        ts += [self.enqueue(order, 'bulk', 'bulk'), self.enqueue(order, 'live', 'live')]
        go.set()
        for t in ts + [holder]:
            t.join(10)
        self.assertEqual(order, ['live', 'bg', 'bulk'])
        llm = self.m.summary(1)['llm']
        self.assertEqual((llm['jobs'], llm['queue_max'] >= 6), (11, True))

    def test_caller_gone_while_queued_never_runs(self):
        go, holder = self.hold()
        order, errors, alive = [], [], [True]
        t = self.enqueue(order, 'gone', 'live', alive=lambda: alive[0], errors=errors)
        alive[0] = False
        t.join(5)
        go.set()
        holder.join(5)
        self.assertEqual((order, errors), ([], [('gone', 'client_gone')]))
        self.assertEqual(self.gate.waiting, 0)
        self.assertEqual(self.m.summary(1)['llm']['dropped'], 1)

    def test_running_process_stopped_when_caller_gone(self):
        alive = [True]
        threading.Timer(0.5, lambda: alive.__setitem__(0, False)).start()
        t0 = time.time()
        with self.assertRaises(V.ClientGone):
            V.run_proc(['/bin/sleep', '30'], alive=lambda: alive[0], poll=0.2)
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(V.run_proc(['/bin/echo', 'ok'], alive=lambda: True)[:2], (0, 'ok\n'))

    def test_flush_once_busy_timeout(self):
        with self.gate.use(private=True, what='tgread recent'):
            pass
        with self.gate.use(private=False, what='llm-run (caller text)'):
            pass
        with self.gate.use(private=False, what='llm-run (caller text)'):
            pass
        self.assertEqual(len(self.flushes), 1)
        with self.gate.use(private=False, what='llm-run (caller text)'):
            pass
        with self.gate.use(private=True, what='gmail search', cls='live'):
            pass
        with self.gate.use(private=False, what='llm-run (caller text)'):
            pass
        self.assertEqual(len(self.flushes), 2)                         # once per private -> external switch
        go, holder = self.hold()
        with self.assertRaises(V.LLMBusy):
            with self.gate.use(private=True, what='x', timeout=0.3):
                pass
        go.set()
        holder.join(5)
        self.assertEqual(self.gate.waiting, 0)
        self.assertEqual(S.tg_class('summarize', {}), 'bulk')
        self.assertEqual((S.tg_class('recent', {'full': True}), S.tg_class('recent', {'n': 'x'})), ('bulk', 'live'))


class MetricsTests(unittest.TestCase):
    """plan v2 #8: hourly totals, percentiles, restart, llm-local's numbers, the slow-queue alert, retention."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))
        self.now = [1792000800.0]
        self.alerts = []
        self.m = MX.Metrics(self.dir / 'metrics.json', clock=lambda: self.now[0],
                            alert=lambda kind, *a, **k: self.alerts.append(kind),
                            stats_file=self.dir / 'llm-stats.jsonl')

    def test_sums_percentiles_restart_and_llm_numbers(self):
        for _ in range(90):
            self.m.call('POST /tg/recent', 200, 1.0)
        for _ in range(10):
            self.m.call('POST /tg/recent', 200, 100.0)
        self.m.call('POST /tg/recent', 503, 5, code='llm_busy')
        self.m.call('POST /tg/recent', 200, 2, gone=True)
        r = self.m.summary(1)['routes'][0]
        self.assertEqual((r['route'], r['calls'], r['errors'], r['timeouts'], r['gone']),
                         ('POST /tg/recent', 102, 1, 1, 1))
        self.assertEqual((r['p50_s'], r['p95_s'], r['max_s']), (1, 100.0, 100.0))
        self.m.llm_wait('bulk', 30)
        self.m.llm_job(60)
        (self.dir / 'llm-stats.jsonl').write_text(json.dumps(
            {'calls': 2, 'prompt_tokens': 300, 'cached_tokens': 700, 'gen_tokens': 50, 'prompt_s': 3.0,
             'gen_s': 5.0, 'cache': {'detect': [3, 1]}}) + '\nnot json\n')
        self.m.tick()
        self.assertFalse((self.dir / 'llm-stats.jsonl').exists())
        self.assertEqual(stat.S_IMODE((self.dir / 'metrics.json').stat().st_mode), 0o600)
        m2 = MX.Metrics(self.dir / 'metrics.json', clock=lambda: self.now[0])          # after a restart
        s2 = m2.summary(1)
        self.assertEqual(s2['routes'], self.m.summary(1)['routes'])
        llm = s2['llm']
        self.assertEqual((llm['prompt_tokens_reused'], llm['reused_share'], llm['prompt_tps'], llm['gen_tps']),
                         (700, 0.7, 100.0, 10.0))
        self.assertEqual((llm['wait']['bulk']['p95_s'], llm['jobs']), (30, 1))
        self.assertEqual(s2['cache']['detect'], {'hits': 3, 'misses': 1, 'hit_rate': 0.75})
        self.assertIn('24 h: 102 calls, 1 errors, 1 callers left early', m2.status_line())
        self.assertIn('cache hits 75%', m2.status_line())

    def test_alert_threshold_and_retention(self):
        self.m.llm_wait('bulk', 1000)                                      # this hour's p95 wait: over 15 min
        self.assertFalse(self.m.check_alert())                             # the hour isn't over yet
        self.now[0] += 3600
        self.assertTrue(self.m.check_alert())
        self.assertFalse(self.m.check_alert())                             # once per hour
        self.assertEqual(self.alerts, ['llm-wait'])
        self.m.llm_wait('live', 10)
        self.now[0] += 3600
        self.assertFalse(self.m.check_alert())                             # a fast hour: quiet
        for _ in range(MX.KEEP_HOURS + 50):
            self.now[0] += 3600
            self.m.call('GET /status', 200, 0.01)
        self.m.flush()
        self.assertEqual(len(self.m.hours), MX.KEEP_HOURS)
        self.assertEqual(MX.route_key('POST', '/secrets/gmail:work'), 'POST /secrets/*')
        self.assertEqual(MX.route_key('GET', '/jobs/abc123/x'), 'GET /jobs/*')

    def test_gate_records_classes_queue_and_busy_time(self):
        gate = V.LLMGate(metrics=self.m)
        with gate.use(private=True, what='tgread summarize'):
            pass
        with gate.use(private=True, what='gmail triage (3)'):
            pass
        with gate.use(private=False, what='llm-run', cls='live'):
            pass
        llm = self.m.summary(1)['llm']
        self.assertEqual((llm['jobs'], sorted(llm['wait']), llm['queue_max']), (3, ['background', 'bulk', 'live'], 1))
        self.assertEqual(gate.waiting, 0)


class ApiSecretTests(ApiBase):
    name = 'api-secrets'

    def test_secrets_write_only_and_rotation(self):
        st, r = self.call('POST', '/secrets/telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.assertEqual(st, 200, r)
        st, r = self.call('GET', '/secrets')
        self.assertEqual(r['secrets']['telegram'], True)
        self.assertNotIn(BOT_TOKEN, json.dumps(self.call('GET', '/status')[1]))
        self.assertTrue(self.call('GET', '/status')[1]['tg']['bot_chat_excluded'])
        st, r = self.call('POST', '/secrets/paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})
        self.assertEqual((st, r['check']), (200, 'paperless reachable, token accepted'))
        st, r = self.call('POST', '/secrets/paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})
        self.assertEqual((st, r['code']), (409, 'already_set'))
        st, r = self.call('POST', '/raw/request', {'source': 'secret-rotate', 'query': {'name': 'firefly'},
                                                   'reason': 'rotate'})
        self.assertEqual((st, r['code']), (409, 'not_set'))
        st, r = self.call('POST', '/raw/request', {'source': 'secret-rotate', 'query': {'name': 'paperless'},
                                                   'reason': 'new paperless token'})
        self.assertEqual(st, 200, r)
        code = TELEGRAM.last_code()
        st, out = self.call('POST', '/raw/release', {'request_id': r['request_id'], 'code': code})
        self.assertEqual((st, out['code']), (409, 'wrong_request'))          # secret codes never release data
        st, out = self.call('POST', '/secrets/paperless', {'url': PAPERLESS.url, 'token': 'short',
                                                           'request_id': r['request_id'], 'code': code})
        self.assertEqual(st, 400)                                        # invalid value: code not consumed
        st, out = self.call('POST', '/secrets/paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN,
                                                           'request_id': r['request_id'], 'code': code})
        self.assertEqual((st, out['replaced']), (200, True), out)
        audit = self.cfg.audit_path.read_text()
        for raw in (BOT_TOKEN, PL_TOKEN, code):
            self.assertNotIn(raw, audit)



class ApiFinanceRulesTests(ApiBase):
    """The Firefly sync rules: write-only like a secret, replacing needs his code."""
    name = 'api-finance-rules'

    @unittest.skipUnless((ROOT / 'vendor' / 'firefly_sync').is_dir(), 'Firefly importer not in this tree')
    def test_rules_write_only_and_replace_with_code(self):
        self.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        ex = json.loads((ROOT / 'vendor' / 'firefly_sync' / 'firefly_rules.example.json').read_text())
        st, r = self.call('GET', '/finance/rules')
        self.assertEqual((st, r['set']), (200, False))
        st, r = self.call('POST', '/raw/request', {'source': 'finance-rules', 'query': {}, 'reason': 'new rules'})
        self.assertEqual((st, r['code']), (409, 'not_set'))
        st, r = self.call('POST', '/finance/rules', {'rules': ex})
        self.assertEqual((st, r['replaced'], r['sections']['PAYEES']), (200, False, len(ex['PAYEES'])), r)
        st, got = self.call('GET', '/finance/rules')
        self.assertEqual((got['set'], got['valid'], got['sha256']), (True, True, r['sha256']))
        st, r = self.call('POST', '/finance/rules', {'rules': ex})
        self.assertEqual((st, r['code']), (409, 'already_set'))
        st, r = self.call('POST', '/raw/request', {'source': 'finance-rules', 'query': {}, 'reason': 'owner: new trip'})
        self.assertEqual(st, 200, r)
        self.assertTrue(TELEGRAM.sent[-1]['text'].startswith('🔐 Claude asks to replace your Firefly sync rules'))
        code = TELEGRAM.last_code()
        bad = dict(ex, PAYEES=[['(broken[', 'X']])
        st, out = self.call('POST', '/finance/rules', {'rules': bad, 'request_id': r['request_id'], 'code': code})
        self.assertEqual((st, out['code']), (400, 'bad_rules'))         # invalid: his code is not used up
        ex['TRIPS'].append(['New Trip 2027', ['2027-01-01', '2027-01-05'], [], 'newtown'])
        st, out = self.call('POST', '/finance/rules', {'rules': ex, 'request_id': r['request_id'], 'code': code})
        self.assertEqual((st, out['replaced'], out['sections']['TRIPS']), (200, True, len(ex['TRIPS'])), out)
        st, out = self.call('POST', '/finance/rules', {'rules': ex, 'request_id': r['request_id'], 'code': code})
        self.assertEqual(st, 410)                                        # his code works once
        audit = self.cfg.audit_path.read_text()
        for raw in ('CH93 0076 2011 6238 5295 7', 'Jane Doe', 'Example Grocer', 'newtown', code):
            self.assertNotIn(raw, audit)


class ApiNoFinanceTests(ApiBase):
    """Plan D2: without app/finance.py (the public vault) the bank intake is a NullFinance: nothing runs, the bot
    ignores bank exports and their buttons, the board sees it idle, /finance/* and its raw request answer 404."""
    name = 'api-nofinance'

    @classmethod
    def setUpClass(cls):
        saved, D.F = D.F, None
        try:
            super().setUpClass()
        finally:
            D.F = saved

    def test_null_finance(self):
        fin = self.app.finance
        self.assertIsInstance(fin, D.NullFinance)
        self.assertFalse(fin.busy)
        t0 = time.time()
        self.assertIsNone(fin.run(threading.Event()))
        self.assertLess(time.time() - t0, 1)
        self.assertEqual(fin.status(), {'installed': False, 'status': 'not installed'})
        self.assertIsNone(fin.on_message({'chat': {'id': 1}, 'document': {'file_name': 'export.csv'}}))
        self.assertIsNone(fin.on_callback({'data': 'f:import:1'}))
        for method, path, body in (('GET', '/finance/status', None), ('GET', '/finance/rules', None),
                                   ('POST', '/finance/rules', {'rules': {}}), ('POST', '/finance/check', {})):
            st, r = self.call(method, path, body)
            self.assertEqual((st, r.get('code')), (404, 'not_found'), (path, r))
        st, r = self.call('POST', '/raw/request', {'source': 'finance-rules', 'query': {}, 'reason': 'new rules'})
        self.assertEqual(st, 404, r)


class SiteValuesTests(unittest.TestCase):
    """S9: this deployment's own values live in config (app/site_values.py, private-only; the server's .env for
    docker-compose.yml). Missing or malformed -> the neutral defaults, never a looser filter."""

    def test_tgread_device_name(self):
        saved = V.SITE
        try:
            V.SITE = None
            c = V.Config({'VAULT_DATA': str(TMP / 'site-none')})
            self.assertEqual(c.tg_device, '')
            self.assertNotIn('TGREAD_DEVICE_MODEL', c.tool_env())
            V.SITE = type('Site', (), {'TG_DEVICE_MODEL': ' Test Reader '})
            c = V.Config({'VAULT_DATA': str(TMP / 'site-set')})
            self.assertEqual(c.tool_env()['TGREAD_DEVICE_MODEL'], 'Test Reader')
        finally:
            V.SITE = saved
        code = ('import importlib.util as U, sys; s = U.spec_from_file_location("t", sys.argv[1], '
                'loader=__import__("importlib.machinery").machinery.SourceFileLoader("t", sys.argv[1])); '
                'm = U.module_from_spec(s); s.loader.exec_module(m); print(m.DEVICE_MODEL)')
        env = {k: v for k, v in os.environ.items() if k != 'TGREAD_DEVICE_MODEL'}
        for extra, want in (({}, 'Homesrv Reader'), ({'TGREAD_DEVICE_MODEL': '  '}, 'Homesrv Reader'),
                            ({'TGREAD_DEVICE_MODEL': 'Test Reader'}, 'Test Reader')):
            out = subprocess.run([PY, '-I', '-c', code, TGREAD], env={**env, **extra}, capture_output=True, text=True,
                                 timeout=60)
            self.assertEqual((out.returncode, out.stdout.strip()), (0, want), out.stderr[-500:])

    def test_topic_seeds(self):
        import topics as TP
        base = TP.DEFAULT_SEEDS
        self.assertEqual(TP._site_seeds(base, None), base)
        bad = type('Site', (), {'TOPIC_SEEDS': {'travel': 'a string', 'party': [], 'sport': [1], 'food': [' '],
                                                'nope': ['x']}})
        self.assertEqual(TP._site_seeds(base, bad), base)
        self.assertEqual(TP._site_seeds(base, type('Site', (), {'TOPIC_SEEDS': ['x']})), base)
        got = TP._site_seeds(base, type('Site', (), {'TOPIC_SEEDS': {'travel': ('Flug nach X gebucht',)}}))
        self.assertEqual(got['travel'], ['Flug nach X gebucht'])
        self.assertEqual({t: v for t, v in got.items() if t != 'travel'},
                         {t: v for t, v in base.items() if t != 'travel'})
        self.assertEqual(set(TP.SEEDS), set(base))
        self.assertTrue(all(len(v) >= 6 for v in TP.SEEDS.values()))

    @unittest.skipUnless((ROOT / 'docker-compose.yml').is_file() and (ROOT / '.env.example').is_file(),
                         'compose files not here (image)')
    def test_compose_values_from_env(self):
        comp = (ROOT / 'docker-compose.yml').read_text()
        ex = (ROOT / '.env.example').read_text()
        names = set(re.findall(r'\$\{(\w+)', comp))
        self.assertGreaterEqual(names, {'VAULT_MODELS_DIR', 'VAULT_CPUS', 'VAULT_CPUSET', 'VAULT_MEM_LIMIT',
                                        'VAULT_DEPLOY_DIR'})
        for n in names:
            self.assertRegex(ex, rf'(?m)^(# )?{n}=', n)
        self.assertNotRegex(comp, r'(?m)^\s*- /mnt/')                       # no host path of this server
        # this server's values (VAULT_HA_DEVICE: unset or blank -> HA picks safely) come from its .env, the vault's
        # settings from vault.env
        self.assertIn('env_file: [vault.env, .env]', comp)
        self.assertRegex(ex, r'(?m)^VAULT_HA_DEVICE=')
        self.assertNotIn('VAULT_HA_DEVICE', (ROOT / 'vault.env').read_text())


class ApiRawTests(ApiBase):
    name = 'api-raw'

    def test_raw_test_flow_and_alerts(self):
        self.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'Vault test — ignore, no action needed'})
        self.assertEqual(st, 200, r)
        self.assertNotIn('test_mode', r)                                  # a real vault: the code went to Telegram
        msg = TELEGRAM.sent[-1]['text']
        self.assertTrue(msg.startswith('🔐 Claude asks for raw text\nWhy: Vault test — ignore, no action needed\n'
                                       'What: test · no data · ~19 bytes\n\n🔑 Code: '), msg)
        self.assertEqual(r['approval'], 'code')                          # this bot isn't polled (test: never started)
        st, p = self.call('GET', '/raw/pending')
        self.assertEqual(p['requests'][-1]['state'], 'pending')
        self.assertNotIn(TELEGRAM.last_code(), json.dumps(p))
        st, out = self.call('POST', '/raw/release', {'request_id': r['request_id'], 'code': TELEGRAM.last_code()})
        self.assertEqual((st, out), (200, {'status': 'released', 'kind': 'text', 'text': 'raw-release test OK'}))
        st, r = self.call('POST', '/raw/request', {'source': 'nope', 'reason': 'x y z'})
        self.assertEqual(st, 400)
        TELEGRAM.fail = True
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'owner unreachable'})
        self.assertEqual((st, r['code']), (502, 'notify_failed'))
        TELEGRAM.fail = False
        self.app.alert('demo', 'Demo alert', f'call {PHONE}')
        self.app.alert('demo', 'Demo alert', 'deduplicated')
        st, a = self.call('GET', '/alerts')
        self.assertEqual(len(a['alerts']), 1)
        self.assertNotIn(PHONE, a['alerts'][0]['text'])
        st, r = self.call('POST', '/alerts/ack', {'names': [a['alerts'][0]['name'], '../audit.log']})
        self.assertEqual(r['acknowledged'], 1)
        self.assertTrue(self.cfg.audit_path.exists())


class ApiConsoleTests(ApiBase):
    """vault-console: the owner at the Unraid terminal types the 2FA password or a secret into the vault."""
    name = 'api-console'

    def console(self, method, path, body=None, key=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={'X-Vault-Console': self.app.console_key if key is None else key,
                                              'Content-Type': 'application/json'})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b'{}')

    def test_console_key_routes_and_loopback(self):
        kf = self.cfg.state / 'console.key'
        self.assertEqual(kf.read_text().strip(), self.app.console_key)
        self.assertEqual(kf.stat().st_mode & 0o777, 0o600)
        st, r = self.console('GET', '/secrets')
        self.assertEqual(st, 200, r)
        for method, path, body in (('POST', '/paperless/get', {'id': 7}), ('GET', '/audit', None),
                                   ('POST', '/raw/release', {'request_id': 'x', 'code': '1'}),
                                   ('POST', '/tg/search', {'query': 'x'}), ('POST', '/llm/run', {'text': 'x'})):
            self.assertEqual(self.console(method, path, body)[0], 401, path)      # outside CONSOLE_ROUTES
        self.assertEqual(self.console('GET', '/secrets', key='0' * 64)[0], 401)
        self.assertEqual(self.console('GET', '/secrets', key='')[0], 401)
        with self.assertRaises(V.VaultError) as cm:                              # only from inside the container
            self.app.console_auth(self.app.console_key, 'GET', '/secrets', '203.0.113.2')
        self.assertEqual(cm.exception.status, 401)
        st, r = self.console('POST', '/tg/2fa', {'password': 'x'})
        self.assertEqual((st, r['code']), (409, 'not_waiting'))                   # no login waiting
        self.assertIn('console_refused', [e['event'] for e in self.app.audit.read()])

    def test_console_replaces_a_secret_without_code_api_cannot(self):
        st, r = self.call('POST', '/secrets/firefly', {'url': 'http://127.0.0.1:18081', 'token': PL_TOKEN})
        self.assertEqual(st, 200, r)
        st, r = self.call('POST', '/secrets/firefly', {'url': 'http://127.0.0.1:18082', 'token': PL_TOKEN})
        self.assertEqual((st, r['code']), (409, 'already_set'))                   # the API needs the owner's code
        st, r = self.console('POST', '/secrets/firefly', {'url': 'http://127.0.0.1:18082', 'token': PL_TOKEN})
        self.assertEqual((st, r['replaced']), (200, True), r)
        self.assertEqual(self.app.store.get('firefly')['url'], 'http://127.0.0.1:18082')
        rec = [e for e in self.app.audit.read() if e['event'] == 'secret_set'][-1]
        self.assertEqual((rec['via'], rec['replaced']), ('console', True))
        self.assertNotIn(PL_TOKEN, self.cfg.audit_path.read_text())

    def test_console_cli(self):
        cfg = V.Config(make_env(self.name, VAULT_PORT=str(self.srv.server_address[1])))
        out = []
        asked = []

        def ask(prompt):
            asked.append(('plain', prompt))
            return CHAT_ID

        def ask_secret(prompt):
            asked.append(('hidden', prompt))
            return BOT_TOKEN

        rc = D.console_main(['secret', 'telegram'], ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out[-1], 'secret telegram: stored')
        self.assertEqual(asked, [('hidden', "Token of a NEW bot from @BotFather used ONLY by the vault, never Claude's "
                                            'chat bot (like 123456789:AA...) (not shown): '),
                                 ('plain', 'Your Telegram chat id (a number; Claude can tell you): ')])
        self.assertEqual(self.app.store.get('telegram'), {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        rc = D.console_main(['2fa'], ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)
        self.assertEqual(rc, 1)
        self.assertIn('no Telegram login is waiting', out[-1])
        self.assertEqual(D.console_main(['bogus'], out=out.append, cfg=cfg), 2)
        self.assertIn('vault-console tg-credentials', out[-1])
        self.assertFalse(any(BOT_TOKEN in str(x) for x in out))

    def test_console_secret_prompts(self):
        """Every secret field has a readable prompt; exactly the tokens are typed without echo."""
        for name, spec in V.SECRET_SPECS.items():
            for key in spec:
                self.assertIn((name, key), D.CONSOLE_FIELDS)
                prompt, hidden = D.console_field(name, key)
                self.assertEqual(hidden, key.endswith(('token', 'password')), (name, key))
                self.assertEqual(prompt.endswith(' (not shown): '), hidden, prompt)
                self.assertNotIn(f'{name} {key}', prompt)                       # labels, not raw key names
        self.assertEqual(D.console_field('x', 'api_hash'), ('x api_hash (not shown): ', True))   # safe fallback

    def test_console_tg_credentials(self):
        cfg = V.Config(make_env(self.name, VAULT_PORT=str(self.srv.server_address[1])))
        tg = self.app.tg
        api_hash, api_hash2 = 'ab' * 16, 'cd' * 16
        answers = {}
        asked, out = [], []

        def ask(prompt):
            asked.append(('plain', prompt))
            return answers['confirm'] if prompt.startswith('Replace') else answers['id']

        def ask_secret(prompt):
            asked.append(('hidden', prompt))
            return answers['hash']

        def run(**a):
            answers.clear()
            answers.update(a)
            asked.clear()
            return D.console_main(['tg-credentials'], ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)

        id_prompt = ('plain', 'Telegram api_id (a number, from my.telegram.org > API development tools): ')
        hash_prompt = ('hidden', 'Telegram api_hash (32 characters, not shown): ')
        self.assertEqual(self.call('GET', '/tg/credentials'), (200, {'credentials': False, 'logged_in': False}))
        self.assertEqual(self.console('GET', '/tg/credentials')[0], 200)
        # bad api_id: refused before the hash is even asked
        self.assertEqual(run(id='12x', hash=api_hash), 1)
        self.assertEqual(asked, [id_prompt])
        self.assertIn('api_id must be a number', out[-1])
        # bad hash: refused in the console, nothing reaches tgread
        self.assertEqual(run(id='1234567', hash='nothex'), 1)
        self.assertEqual(asked, [id_prompt, hash_prompt])
        self.assertIn('api_hash 32 hex characters', out[-1])
        self.assertFalse(tg.creds_path.exists())
        # first time: stored, no confirm question
        self.assertEqual(run(id='1234567', hash=f' {api_hash}\n'), 0, out)
        self.assertEqual(asked, [id_prompt, hash_prompt])
        self.assertEqual(out[-1], 'telegram credentials: stored')
        self.assertEqual(json.loads(tg.creds_path.read_text()), {'api_id': 1234567, 'api_hash': api_hash})
        self.assertEqual(stat.S_IMODE(tg.creds_path.stat().st_mode), 0o600)
        rec = [e for e in self.app.audit.read() if e['event'] == 'tg_credentials_set'][-1]
        self.assertEqual((rec['ok'], rec['replaced'], rec['via']), (True, False, 'console'))
        # already set: says so; anything but y/yes keeps them, without asking for values
        for no in ('', 'n', 'no', 'x'):
            self.assertEqual(run(id='7654321', hash=api_hash2, confirm=no), 1)
            self.assertEqual(asked, [('plain', 'Replace them? [y/N] ')])
            self.assertEqual(out[-2:], ['telegram credentials: already set', 'telegram credentials: unchanged'])
        self.assertEqual(json.loads(tg.creds_path.read_text())['api_hash'], api_hash)
        # y: replaced
        self.assertEqual(run(id='7654321', hash=api_hash2, confirm=' Y '), 0, out)
        self.assertEqual(asked, [('plain', 'Replace them? [y/N] '), id_prompt, hash_prompt])
        self.assertEqual(out[-1], 'telegram credentials: stored')
        self.assertEqual(json.loads(tg.creds_path.read_text()), {'api_id': 7654321, 'api_hash': api_hash2})
        rec = [e for e in self.app.audit.read() if e['event'] == 'tg_credentials_set'][-1]
        self.assertEqual((rec['replaced'], rec['via']), (True, 'console'))
        # logged in: refused up front, nothing asked
        tg.session_path.write_bytes(b'x')
        try:
            self.assertEqual(run(id='1234567', hash=api_hash), 1)
            self.assertEqual(asked, [])
            self.assertIn('already logged in', out[-1])
        finally:
            tg.session_path.unlink()
        # Ctrl-D at a prompt: cancelled, nothing changed
        self.assertEqual(D.console_main(['tg-credentials'], ask=lambda p: (_ for _ in ()).throw(EOFError()),
                                        ask_secret=ask_secret, out=out.append, cfg=cfg), 1)
        self.assertEqual(out[-1], 'vault-console: cancelled')
        # the values never show up in what he sees or in the audit log
        for v in (api_hash, api_hash2):
            self.assertFalse(any(v in str(x) for x in out))
            self.assertNotIn(v, self.cfg.audit_path.read_text())
        tg.creds_path.unlink()


@legacy_text
class ApiLiveViewTests(ApiBase):
    """Live view for the owner: one stderr line per API call + `vault-console watch [--full]` (console key only).
    No secret ever shows up in either: 2FA passwords, api_hash, secret bodies, raw-release codes, the QR."""
    name = 'api-live'

    def setUp(self):
        super().setUp()
        self.lines = []
        D.log = self.lines.append

    def tearDown(self):
        D.log = lambda msg: None

    def console(self, method, path, body=None, key=None):
        return ApiConsoleTests.console(self, method, path, body, key)

    def line_for(self, method, path):
        hits = [ln for ln in self.lines if f' {method} {path} ' in ln]
        self.assertTrue(hits, (method, path, self.lines))
        return hits[-1]

    def all_events(self, full=True):
        st, r = self.console('GET', '/console/events?after=0' + ('&full=1' if full else ''))
        self.assertEqual(st, 200, r)
        return r['events']

    def watch_output(self, full=True):
        out = []
        rc = D.console_watch(lambda m, p, b=None: self.console(m, p, b)[1], full=full, out=out.append, max_polls=1)
        self.assertEqual(rc, 0)
        return out

    def test_one_line_per_call(self):
        if not self.app.store.is_set('telegram'):
            self.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.call('GET', '/status')
        self.assertRegex(self.line_for('GET', '/status'), r'^127\.0\.0\.1 api GET /status -> 200 \d+(\.\d)? K?B \d+ms$')
        self.call('POST', '/tg/search', {'query': 'dentist Lena', 'chat': 'Lena', 'since': '2026-10-01', 'n': 5})
        self.assertRegex(self.line_for('POST', '/tg/search'), r' api POST /tg/search query="dentist Lena" '
                         r'chat="Lena" since="2026-10-01" n=5 -> 200 \(exit 2\) \d+ B \d+ms$')    # no such chat
        st, r = self.call('POST', '/llm/run', {'args': ['--anonymize'], 'text': 'Herzschmerz again. Call [phone] or '
                                               '[EMAIL], see [private: family] and [link: x.ch]'})
        self.assertEqual(st, 200, r)
        ln = self.line_for('POST', '/llm/run')
        self.assertIn('args=["--anonymize"] text=(82 chars) -> 200 ', ln)
        self.assertTrue(ln.endswith('| redacted: 2 private (family 1, health 1), 3 masked (email 1, link 1, phone 1)'),
                        ln)
        self.assertNotIn('Herzschmerz', ln)
        self.call('POST', '/tg/search', {'query': 'x', 'raw': True})
        self.assertIn('query="x" raw=(hidden) -> 400 unknown_param ', self.line_for('POST', '/tg/search'))
        self.call('GET', '/status', token='wrong')
        self.assertIn(' GET /status -> 401 unauthorized ', self.lines[-1])
        out = self.raw_flow('test', None)
        self.assertEqual(out['text'], 'raw-release test OK')
        ln = self.line_for('POST', '/raw/release')
        self.assertRegex(ln, r'request_id="[0-9a-f]+" code=\(hidden\) -> 200 .*\| RAW text released')
        self.call('GET', '/health')
        self.assertFalse([ln for ln in self.lines if '/health' in ln])
        self.assertEqual(len(self.lines), 7, self.lines)                  # exactly one line per call

    def test_secrets_never_in_lines_or_watch(self):
        api_hash, wrong_2fa, right_2fa = 'ef' * 16, 'Wr0ng-' + 'horse-2fa', 'right-horse-battery'
        self.app.store.path('telegram').unlink(missing_ok=True)          # set through the API below
        self.assertEqual(self.call('POST', '/secrets/telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})[0], 200)
        self.assertIn('POST /secrets/telegram bot_token=(hidden) chat_id=(hidden) -> 200',
                      self.line_for('POST', '/secrets/telegram'))
        self.assertEqual(self.call('POST', '/secrets/paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})[0], 200)
        st, r = self.call('POST', '/tg/credentials', {'api_id': '1234567', 'api_hash': api_hash})
        self.assertEqual((st, r['exit_code']), (200, 0), r)
        self.assertIn('api_id=(hidden) api_hash=(hidden) -> 200', self.line_for('POST', '/tg/credentials'))
        # a QR login with 2FA (fake tgread): the QR and both passwords stay out of the live view
        fake = make_cfg('api-live-login', VAULT_TGREAD=str(FAKE_TG_PATH), VAULT_PYTHON=sys.executable)
        real_login, self.app.tg.login = self.app.tg.login, S.LoginJob(fake, self.app.policy, fake.tool_env)
        try:
            st, r = self.call('POST', '/tg/login-qr', {'timeout': 60})
            self.assertEqual((st, r['state']), (200, 'QR_READY'), r)
            qr = r['qr_png_b64']

            def wait_state(want):
                for _ in range(50):
                    s = self.call('GET', '/tg/login')[1]['state']
                    if s == want:
                        return
                    time.sleep(0.1)
                self.fail(f'login state {s}, wanted {want}')
            wait_state('PASSWORD_NEEDED')
            self.assertEqual(self.call('POST', '/tg/2fa', {'password': wrong_2fa})[0], 200)
            wait_state('PASSWORD_INVALID')
            self.assertEqual(self.call('POST', '/tg/2fa', {'password': right_2fa})[0], 200)
            wait_state('LOGIN_OK')
        finally:
            self.app.tg.login = real_login
        self.assertIn('POST /tg/2fa password=(hidden) -> 200', self.line_for('POST', '/tg/2fa'))
        # raw-release codes: a used one is never logged, a live one is scrubbed from echoed output
        self.raw_flow('test', None)
        code1 = TELEGRAM.last_code()
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'second code stays pending'})
        self.assertEqual(st, 200, r)
        code2 = TELEGRAM.last_code()
        st, r = self.call('POST', '/llm/run', {'text': f'echo {code2[:3]} {code2[3:]} / {PL_TOKEN} / {api_hash} / '
                                                       f'{BOT_TOKEN}'})
        self.assertIn(PL_TOKEN, r['stdout'])                              # the caller got its own text back...
        events = self.all_events()
        body = [e for e in events if ' POST /llm/run ' in e['line']][-1]['body']
        self.assertIn('echo [code] / [secret] / [secret] / [secret]', body)  # ...the live view scrubs it
        self.assertTrue(any('"qr_png_b64": "(' in e['body'] for e in events))
        blob = '\n'.join(self.lines + [e['line'] + '\n' + e['body'] for e in events]
                         + self.watch_output(full=True) + self.watch_output(full=False))
        for secret in (BOT_TOKEN, PL_TOKEN, api_hash, wrong_2fa, right_2fa, qr, qr[:40], self.app.console_key):
            self.assertNotIn(secret, blob)
        for code in (code1, code2):
            self.assertIsNone(re.search(rf'(?<!\d){code[:3]}[ -]?{code[3:]}(?!\d)', blob), code)

    def test_watch_console_only_long_poll_and_truncation(self):
        st, r = self.call('GET', '/console/events?last=5')                # the API token never reaches it
        self.assertEqual((st, r['code']), (404, 'not_found'))
        self.assertIn(' api GET /console/events last="5" -> 404 not_found ', self.lines[-1])
        self.assertEqual(self.console('GET', '/console/events', key='0' * 64)[0], 401)
        n = len(self.lines)
        st, r = self.console('GET', '/console/events?last=1')
        self.assertEqual(st, 200, r)
        self.assertEqual(len(self.lines), n)                              # the watch itself is not logged
        self.assertIn('console_watch', [e['event'] for e in self.app.audit.read()])
        seq = r['seq']
        threading.Timer(0.3, lambda: self.call('GET', '/status')).start()
        t0 = time.time()
        st, r = self.console('GET', f'/console/events?after={seq}&wait=5')
        self.assertLess(time.time() - t0, 4)
        self.assertEqual([e['seq'] for e in r['events']], [seq + 1])
        self.assertRegex(r['events'][0]['line'], r'^\d\d:\d\d:\d\d 127\.0\.0\.1 api GET /status -> 200 ')
        self.assertNotIn('body', r['events'][0])                           # bodies only with full=1
        st, r = self.console('GET', f'/console/events?after={seq + 1}&wait=0.2')
        self.assertEqual(r['events'], [])
        # --full: body as received, terminal escapes dropped, cut at 4 KB with a note
        self.call('POST', '/llm/run', {'text': 'line one\nbell\x07 esc\x1b[2J ' + 'x' * 10000})
        ev = self.all_events()[-1]
        self.assertLessEqual(len(ev['body']), V.LiveTap.BODY_MAX)
        self.assertRegex(ev['body_note'], r'^\[truncated: the first 8192 of 10\d\d\d characters shown\]$')
        self.assertIn('--- stdout ---\nECHO  | line one\nbell esc[2J xxx', ev['body'])
        out = self.watch_output(full=True)
        self.assertTrue(out[0].startswith('vault-console watch: every API call to the vault, live: REQUEST, RAW'))
        blk = [ln for ln in out if "\nREQUEST\n    LLM run on Claude's own text text=(" in ln][-1]
        self.assertIn('\n\nRESPONSE · what Claude got\n    {\n', blk)
        self.assertIn('\n    --- stdout ---\n    ECHO  | line one\n', blk)
        self.assertRegex(blk, r'\n    …\(\d+ more chars\)\n\n→ 200 · ')    # each part cut at 8 KB
        self.assertNotIn('RAW · what went in', blk)                        # Claude's own text: no source
        self.assertFalse(any('\x1b' in x or '\x07' in x for x in out))
        self.assertFalse(any(ln.startswith('    ') for ln in self.watch_output(full=False)))
        # the CLI: watch is a console command; Ctrl-C ends it cleanly
        cfg = V.Config(make_env(self.name, VAULT_PORT=str(self.srv.server_address[1])))
        said = []

        def ctrl_c(msg):
            said.append(msg)
            if len(said) == 3:
                raise KeyboardInterrupt
        self.assertEqual(D.console_main(['watch', '--full'], out=ctrl_c, cfg=cfg), 0)
        self.assertEqual(said[-1], 'vault-console: watch stopped')
        said.clear()
        self.assertEqual(D.console_main(['watch', '--bogus'], out=said.append, cfg=cfg), 2)
        self.assertIn('vault-console watch [--full]', said[-1])

    def test_render_and_redaction_helpers(self):
        txt = V.render_body({'state': 'QR_READY', 'qr_png_b64': 'QUJD' * 50, 'stdout': 'a\nb', 'n': 1})
        self.assertNotIn('QUJD', txt)
        self.assertTrue(txt.endswith('"n": 1\n}\n--- stdout ---\na\nb'), txt)
        priv, masked = V.tap_redactions({'stdout': '[private: Health] [PHONE] [phone] [card number] [URL:x.ch] '
                                                   '[NAME] [Person A] [key]', 'qr_png_b64': '[phone]'})
        self.assertEqual((priv, masked), ({'health': 1}, {'phone': 2, 'card': 1, 'link': 1, 'name': 1}))
        p = V.tap_params({'query': 'a "b"\nc', 'password': 'pw', 'token': 't', 'code': '123456', 'text': 'abc',
                          'content_b64': 'QUJD', 'query2': 'x', 'n': 3, 'chats': ['A', 'B'],
                          'q2': {'id': 7, 'secret': 'z'}})
        self.assertEqual(p, 'query="a \\"b\\" c" password=(hidden) token=(hidden) code=(hidden) text=(3 chars) '
                            'content_b64=(4 base64 chars) query2=(hidden) n=3 chats=["A","B"] q2=(hidden)')
        self.assertEqual(V.tap_params({'chat_id': '1', 'url': 'u'}, secret=True), 'chat_id=(hidden) url=(hidden)')
        tap = V.LiveTap()
        tap.MAX_BYTES = 30_000
        for i in range(20):
            tap.add(tap.event('1.2.3.4', 'api', 'POST', '/llm/run', {}, {}, 200, {'stdout': 'y' * 9000}, 9000, 1))
        self.assertLessEqual(tap.bytes, 30_000)
        r = tap.since(after=0)
        self.assertEqual((r['seq'], r['skipped'], len(r['events'])), (20, 20 - len(r['events']), len(r['events'])))


@legacy_text
class ApiLlmTgTests(ApiBase):
    name = 'api-llm-tg'

    def test_llm_run_allowlist_and_flush(self):
        flushes = []
        self.app.gate.flush = lambda: flushes.append(1)
        st, r = self.call('POST', '/llm/run', {'args': ['--no-start'], 'text': 'x'})
        self.assertEqual(st, 400)
        st, r = self.call('POST', '/llm/run', {'args': ['--system', 'line1\nline2', '--max-tokens', '50', '--json=1'],
                                               'text': 'x'})
        self.assertEqual(st, 400)                                        # --json takes no value
        with self.app.gate.use(private=True):
            pass
        st, r = self.call('POST', '/llm/run', {'args': ['--system', '-tricky\nline2', '--max-tokens', '50', '--temp=0'],
                                               'text': 'hello'})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['exit_code'], 0)
        self.assertEqual(r['stdout'], 'ECHO --system=-tricky\nline2 --max-tokens=50 --temp=0 | hello')
        self.assertEqual(flushes, [1])
        self.assertIsNone(llm_calls()[-1]['cache'])                      # Claude's own text: never the cache (#3)
        st, r = self.call('POST', '/llm/run', {'args': ['--anonymize', '--cache-dir', '/data/state/llm-cache'],
                                               'text': 'hello'})
        self.assertEqual(st, 400)
        llm_mode('fail')
        st, r = self.call('POST', '/llm/run', {'args': [], 'text': 'x'})
        self.assertEqual((st, r['exit_code']), (200, 3))
        llm_mode('ok')

    def test_tg_endpoints(self):
        st, r = self.call('POST', '/tg/search', {'query': 'Lugano', 'n': 5})
        self.assertEqual((st, r['exit_code']), (200, 0), r)
        st, r = self.call('POST', '/tg/status', {})
        self.assertIn('session: missing', r['stdout'])
        st, r = self.call('POST', '/tg/credentials', {'api_id': '12', 'api_hash': 'x'})
        self.assertEqual(st, 400)
        st, r = self.call('GET', '/tg/login')
        self.assertEqual(r['state'], 'idle')
        st, r = self.call('POST', '/tg/2fa', {'password': 'x'})
        self.assertEqual((st, r['code']), (409, 'not_waiting'))
        st, r = self.call('POST', '/tg/login-qr', {'timeout': 5})
        self.assertEqual(st, 400)


class ApiPaperlessTests(ApiBase):
    name = 'api-paperless'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app.store.set('paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})
        cls.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        (STUB_DIR / 'llm-json').write_text(json.dumps({'sender_name': 'Krankenkasse Muster AG',
                                                       'sender_address': 'Bahnhofstrasse 1, 8001 Zuerich'}))

    def test_search_recent_meta_are_metadata_only(self):
        st, r = self.call('POST', '/paperless/search', {'q': 'Krankenkasse', 'n': 5})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['count'], 1)
        d = r['results'][0]
        self.assertEqual(set(d), {'id', 'created', 'added', 'title', 'correspondent', 'document_type', 'tags', 'url'})
        blob = json.dumps(r)
        for raw in ('RAW-HIGHLIGHT', 'Herzschmerz', IBAN, PHONE):
            self.assertNotIn(raw, blob)
        self.assertIn('[PHONE]', d['title'])
        self.assertEqual((d['correspondent'], d['document_type'], d['tags']), ('Krankenkasse Muster AG', 'Rechnung',
                                                                               ['gesundheit']))
        st, r = self.call('POST', '/paperless/recent', {'n': 2})
        self.assertEqual([x['id'] for x in r['results']], [7, 8])
        self.assertNotIn('Herzschmerz', json.dumps(r))
        st, r = self.call('GET', '/paperless/meta')
        self.assertEqual([t['name'] for t in r['tags']], ['gesundheit', 'steuern'])   # page 2 fetched from OUR base
        events = [e['event'] for e in self.app.audit.read()]
        for ev in ('paperless_search', 'paperless_recent', 'paperless_meta'):
            self.assertIn(ev, events)

    def test_get_is_a_card_without_content(self):
        n0 = len(llm_calls())
        st, r = self.call('POST', '/paperless/get', {'id': 7, 'chars': 5000})     # chars: older clients, ignored
        self.assertEqual(st, 200, r)
        self.assertNotIn('content', r)                                   # plan B: never content
        self.assertNotIn('original_file_name', r)
        self.assertEqual(set(r) - {'_warnings'}, {'id', 'created', 'added', 'title', 'correspondent', 'document_type',
                                                  'tags', 'url', 'page_count', 'amount', 'currency', 'due_date'})
        self.assertEqual((r['amount'], r['currency'], r['due_date'], r['page_count']), ('123.45', 'CHF', '2026-10-31', 1))
        blob = json.dumps(r)
        for raw in ('Herzschmerz', PHONE, IBAN, 'rechnung.pdf'):
            self.assertNotIn(raw, blob)
        self.assertEqual(len(llm_calls()), n0)                           # no local model for a card
        rec = [e for e in self.app.audit.read() if e['event'] == 'paperless_get'][-1]
        self.assertEqual((rec['doc_id'], rec['card']), (7, True))
        st, r = self.call('POST', '/paperless/get', {'id': 7, 'content': True})
        self.assertEqual((st, r['code']), (400, 'content_needs_approval'))
        self.assertEqual(self.call('POST', '/paperless/get', {'id': 999})[0], 404)
        self.assertEqual(self.call('POST', '/paperless/get', {'id': 'x'})[0], 400)
        self.assertEqual(self.call('POST', '/paperless/get', {'id': 7, 'chars': 200_000})[0], 400)

    def test_anon_content_only_as_raw_source(self):
        n0 = len(llm_calls())
        out = self.raw_flow('paperless-anon', {'id': 7, 'chars': 5000}, reason='owner wants the gist of the letter')
        self.assertEqual(out['kind'], 'text')
        self.assertTrue(out['text'].startswith('# paperless #7: '), out['text'][:80])
        self.assertIn('ANON ', out['text'])
        self.assertIn('[private: health]', out['text'])
        for raw in ('Herzschmerz', PHONE, IBAN):
            self.assertNotIn(raw, out['text'])
        self.assertEqual(len(llm_calls()), n0 + 1)
        self.assertIn('--keep-own-money', llm_calls()[-1]['args'])          # his admin documents keep his figures
        self.assertIn('paperless #7', TELEGRAM.sent[-1]['text'])
        out2 = self.raw_flow('paperless-anon', {'id': 7, 'chars': 5000})
        self.assertEqual((out2['text'], len(llm_calls())), (out['text'], n0 + 1))      # cached
        llm_mode('fail')
        st, r = self.call('POST', '/raw/request', {'source': 'paperless-anon', 'query': {'id': 7, 'chars': 4000},
                                                   'reason': 'gist'})
        self.assertEqual((st, r['code']), (503, 'llm_unavailable'))      # no fallback to raw text
        llm_mode('ok')

    def test_fields_tier1_free_tier2_withheld(self):
        st, r = self.call('POST', '/paperless/fields', {'id': 7, 'fields': ['amount', 'evil']})
        self.assertEqual((st, r['code']), (400, 'bad_field'))
        want = ['amount', 'currency', 'due_date', 'iban', 'invoice_date', 'policy_number', 'customer_number',
                'invoice_number', 'correspondent', 'document_date', 'sender_name', 'sender_address', 'dates']
        n0 = len(llm_calls())
        st, r = self.call('POST', '/paperless/fields', {'id': 7, 'fields': want})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['amount'], r['currency'], r['due_date'], r['invoice_date']),
                         ('123.45', 'CHF', '2026-10-31', '2026-10-01'))
        self.assertEqual((r['correspondent'], r['document_date']), ('Krankenkasse Muster AG', '2026-10-01'))
        tier2 = ['iban', 'policy_number', 'customer_number', 'invoice_number', 'sender_name', 'sender_address', 'dates']
        self.assertEqual(r['_withheld'], tier2)
        self.assertTrue(all(r[k] is None for k in tier2))                # soft: null, never an error
        self.assertIs(r['has_payment_ref'], True)                        # iban withheld -> the bool is added
        self.assertIn('--reason', r['_withheld_hint'])
        self.assertEqual(len(llm_calls()), n0)                           # sender fields withheld: no model run
        blob = json.dumps(r)
        for raw in (IBAN, '12.345.678', '98765', 'R-2026-0042', 'Bahnhofstrasse'):
            self.assertNotIn(raw, blob)
        st, r = self.call('POST', '/paperless/fields', {'id': 8, 'fields': ['period_years', 'title']})
        self.assertEqual((r['period_years'], r.get('_withheld')), ([], None))
        st, r = self.call('POST', '/paperless/fields', {'id': 7})        # default set: tier 1 only
        self.assertNotIn('_withheld', r)
        self.assertEqual(set(r) - {'_confidence', '_warnings'}, set(S.DEFAULT_FIELDS))
        rec = [e for e in self.app.audit.read() if e['event'] == 'paperless_fields'][-3]
        self.assertEqual((rec['withheld'], rec['tier2']), (tier2, False))

    def test_fields_tier2_with_the_owners_ok(self):
        want = ['amount', 'currency', 'due_date', 'iban', 'invoice_date', 'policy_number', 'customer_number',
                'invoice_number', 'correspondent', 'document_date', 'sender_name', 'sender_address', 'dates']
        out = self.raw_flow('paperless-fields', {'id': 7, 'fields': want}, reason='Kündigung needs the policy number')
        self.assertEqual(out['kind'], 'text')
        self.assertIn('paperless #7, fields', TELEGRAM.sent[-1]['text'])
        r = json.loads(out['text'])
        self.assertEqual(r['amount'], '123.45')
        self.assertEqual(r['iban'], IBAN)
        self.assertEqual(r['policy_number'], '12.345.678')
        self.assertEqual(r['customer_number'], '98765')
        self.assertEqual(r['invoice_number'], 'R-2026-0042')
        self.assertEqual((r['sender_name'], r['sender_address']), ('Krankenkasse Muster AG',
                                                                     'Bahnhofstrasse 1, 8001 Zuerich'))
        self.assertIn('2026-10-31', r['dates'])
        self.assertEqual(set(r) - set(want), {'_confidence', '_warnings'})
        rec = [e for e in self.app.audit.read() if e['event'] == 'paperless_fields'][-1]
        self.assertEqual((rec['fields'], rec['tier2']), (want, True))
        audit = self.cfg.audit_path.read_text()
        for raw in (IBAN, '123.45', '12.345.678'):
            self.assertNotIn(raw, audit)
        st, r = self.call('POST', '/raw/request', {'source': 'paperless-fields', 'query': {'id': 7, 'fields': ['x']},
                                                   'reason': 'need it'})
        self.assertEqual((st, r['code']), (400, 'bad_field'))
        (STUB_DIR / 'llm-json').write_text(json.dumps({'sender_name': 'Invented GmbH', 'sender_address': 'Nowhere 9'}))
        r = json.loads(self.raw_flow('paperless-fields', {'id': 7, 'fields': ['sender_name', 'sender_address']})['text'])
        self.assertEqual((r['sender_name'], r['sender_address']), (None, None))   # not verbatim in the text: dropped
        self.assertTrue(any('dropped' in w for w in r['_warnings']))
        (STUB_DIR / 'llm-json').write_text(json.dumps({'sender_name': 'Krankenkasse Muster AG',
                                                       'sender_address': 'Bahnhofstrasse 1, 8001 Zuerich'}))

    def test_fields_of_a_scan_come_from_paperless_ocr(self):
        st, r = self.call('POST', '/paperless/fields', {'id': 9, 'fields': ['amount', 'currency', 'iban',
                                                                              'invoice_date', 'due_date']})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['amount'], r['currency'], r['iban'], r['invoice_date'], r['has_payment_ref']),
                         ('456.70', 'CHF', None, '2026-09-20', True))
        self.assertEqual(r['_withheld'], ['iban'])
        self.assertEqual((r['due_date'], r['_confidence'].get('due_date')), ('2026-10-20', 'low'))
        self.assertTrue(any("paperless' OCR text" in w for w in r['_warnings']), r['_warnings'])
        self.assertFalse(any('page images' in w for w in r['_warnings']), r['_warnings'])

    def test_suggest_picks_existing_names_only(self):
        (STUB_DIR / 'llm-json').write_text(json.dumps({'document_type': 'rechnung', 'correspondent': 'Evil Corp',
                                                       'tags': ['steuern', 'made-up', 'gesundheit']}))
        try:
            st, r = self.call('POST', '/paperless/suggest', {'id': 8})
            self.assertEqual(st, 200, r)
            self.assertEqual(r['suggested'], {'document_type': 'Rechnung', 'correspondent': None,
                                              'tags': ['steuern', 'gesundheit']})
            self.assertEqual(r['current'], {'document_type': None, 'correspondent': None, 'tags': []})
            self.assertEqual(r['changes'], {'document_type': 'Rechnung', 'tags_add': ['steuern', 'gesundheit']})
            self.assertTrue(any('not an existing name' in w for w in r['_warnings']))
            sent = llm_calls()[-1]
            self.assertIn('Lohn Mai 2024', sent['text'])                   # the model read it inside the vault
            self.assertNotIn('Lohn Mai 2024', json.dumps(r))
            st, r = self.call('POST', '/paperless/suggest', {'id': 7})
            self.assertEqual(r['changes'], {'tags_add': ['steuern']})       # already Rechnung / gesundheit
            self.assertNotIn('Herzschmerz', json.dumps(r))
            self.assertIn('paperless_suggest', [e['event'] for e in self.app.audit.read()])
        finally:
            (STUB_DIR / 'llm-json').write_text(json.dumps({'sender_name': 'Krankenkasse Muster AG',
                                                           'sender_address': 'Bahnhofstrasse 1, 8001 Zuerich'}))

    def test_rule_test_ids_and_current_values_only(self):
        st, r = self.call('POST', '/paperless/rule-test', {'kind': 'correspondent', 'match': 'krankenkasse',
                                                           'matching_algorithm': 'any', 'name': 'Krankenkasse Muster AG'})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['checked'], 3)
        self.assertEqual(r['matches'], [{'id': 7, 'current': 'Krankenkasse Muster AG', 'would_change': False}])
        st, r = self.call('POST', '/paperless/rule-test', {'kind': 'tag', 'match': r'Lohn\s+Mai', 'matching_algorithm': 4})
        self.assertEqual([(m['id'], m['current']) for m in r['matches']], [(8, [])])
        st, r = self.call('POST', '/paperless/rule-test', {'kind': 'type', 'match': 'LOHN', 'matching_algorithm': 'literal',
                                                           'is_insensitive': False})
        self.assertEqual(r['count'], 0)
        st, r = self.call('POST', '/paperless/rule-test', {'kind': 'type', 'match': 'Krankenkase Muster',
                                                           'matching_algorithm': 'fuzzy'})
        self.assertEqual([m['id'] for m in r['matches']], [7])
        self.assertNotIn('Herzschmerz', json.dumps(r))
        self.assertNotIn('title', json.dumps(r))
        for bad in ({'kind': 'tag', 'match': 'x', 'matching_algorithm': 6}, {'kind': 'tag', 'match': '(',
                    'matching_algorithm': 4}, {'kind': 'x', 'match': 'a', 'matching_algorithm': 1},
                    {'kind': 'tag', 'match': '', 'matching_algorithm': 1}, {'kind': 'tag', 'match': 'a',
                    'matching_algorithm': 1, 'evil': 1}):
            self.assertEqual(self.call('POST', '/paperless/rule-test', bad)[0], 400, bad)
        self.assertIn('paperless_rule_test', [e['event'] for e in self.app.audit.read()])

    def test_intake_event_in_the_feed_without_text(self):
        self.app.events.add([{'source': 'paperless', 'ts': 1_791_000_000, 'chat_key': 'intake', 'chat': 'paperless',
                              'chat_type': 'document', 'label': 'filed', 'actionable': 1, 'ref': 'paperless:42',
                              'doc': json.dumps({'doc_id': 42, 'type': 'Rechnung', 'correspondent': 'X AG',
                                                 'bill_likely': True})}])
        st, r = self.call('GET', '/events?since=0&source=paperless')
        self.assertEqual(st, 200, r)
        e = r['events'][-1]
        self.assertEqual((e['source'], e['label'], e['actionable'], e['doc']['doc_id'], e['doc']['bill_likely']),
                         ('paperless', 'filed', True, 42, True))
        self.assertNotIn('text', e)
        st, r = self.call('GET', '/intake/status')
        self.assertEqual((st, r['intake'], r['limit_per_hour']), (200, 'on', 30))

    def test_raw_text_and_file_need_the_code(self):
        out = self.raw_flow('paperless', {'id': 7}, reason='owner wants the exact letter')
        self.assertEqual(out['kind'], 'text')
        self.assertIn('Herzschmerz', out['text'])
        self.assertIn(IBAN, out['text'])
        self.assertIn('paperless #7: Rechnung Krankenkasse', TELEGRAM.sent[-1]['text'])
        out = self.raw_flow('paperless-file', {'id': 7}, reason='owner wants the PDF')
        self.assertEqual((out['kind'], out['filename']), ('file', 'rechnung.pdf'))
        self.assertEqual(base64.b64decode(out['content_b64']), DOC7_PDF)
        self.assertTrue(TELEGRAM.sent[-1]['text'].startswith('🔐 Claude asks for an original file\nWhy: owner wants the PDF'))

    def test_upload_and_task(self):
        st, r = self.call('POST', '/paperless/upload', {'filename': 'scan.pdf', 'title': 'Brief',
                                                        'content_b64': base64.b64encode(DOC7_PDF).decode(),
                                                        'correspondent': 'Krankenkasse Muster AG', 'tags': ['gesundheit']})
        self.assertEqual((st, r['document_id']), (200, 42), r)
        req = [x for x in PAPERLESS.requests if x[1] == '/api/documents/post_document/'][-1]
        self.assertIn(b'name="correspondent"\r\n\r\n1', req[3])
        st, r = self.call('POST', '/paperless/upload', {'filename': '../x.pdf', 'content_b64': 'AA=='})
        self.assertEqual(st, 400)
        st, r = self.call('POST', '/paperless/upload', {'filename': 'x.pdf', 'content_b64': 'AA==',
                                                        'correspondent': 'Unknown AG'})
        self.assertEqual((st, r['code']), (400, 'unknown_name'))


class ApiPaperlessWriteTests(ApiBase):
    """V1 POST /paperless/update and V2 POST /paperless/taxonomy (2026-10-12): metadata writes only, no content in
    or out, no delete, audit without values. Uses its own fake paperless (PAPERLESS_W)."""
    name = 'api-paperless-write'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app.store.set('paperless', {'url': PAPERLESS_W.url, 'token': PL_TOKEN})

    def writes(self, since):
        return [(m, p, json.loads(b) if b else None) for m, p, h, b in PAPERLESS_W.requests[since:] if m != 'GET']

    def assertNoDeletes(self):
        self.assertEqual([r[:2] for r in PAPERLESS_W.requests if r[0] in ('DELETE', 'PUT')], [])

    def test_only_allowlisted_writes_reach_paperless(self):
        n0 = len(PAPERLESS_W.requests)
        for method, path in (('DELETE', '/api/documents/7/'), ('PUT', '/api/documents/7/'),
                             ('POST', '/api/documents/bulk_edit/'), ('POST', '/api/documents/7/notes/'),
                             ('PATCH', '/api/documents/7/notes/'), ('PATCH', '/api/users/1/'),
                             ('POST', '/api/workflows/'),
                             ('PATCH', PAPERLESS_W.url + '/api/documents/7/'), ('POST', '/api/tags/?x=1'),
                             ('DELETE', '/api/tags/3/'), ('PATCH', '/api/documents/'), ('POST', '/api/documents/7/')):
            with self.assertRaises(V.VaultError, msg=(method, path)) as cm:
                self.app.paperless.req(method, path, {})
            self.assertEqual(cm.exception.code, 'write_refused')
        self.assertEqual(PAPERLESS_W.requests[n0:], [])

    def test_taxonomy_create_update_and_meta(self):
        n0 = len(PAPERLESS_W.requests)
        rx = r'\b(Rechnung|Faktura|Invoice)\b|Empfangsschein|Zahlteil'
        st, r = self.call('POST', '/paperless/taxonomy', {'kind': 'document_type', 'name': 'rechnung', 'match': rx,
                                                          'matching_algorithm': 4, 'is_insensitive': True})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['kind'], r['id'], r['name'], r['action'], r['changed'], r['algorithm'], r['match']),
                         ('document_types', 2, 'Rechnung', 'updated', ['match', 'matching_algorithm'], 'regex', rx))
        self.assertEqual(self.writes(n0), [('PATCH', '/api/document_types/2/', {'match': rx, 'matching_algorithm': 4})])
        st, r = self.call('POST', '/paperless/taxonomy', {'kind': 'type', 'name': 'Rechnung', 'match': rx,
                                                          'matching_algorithm': 'regex'})
        self.assertEqual((st, r['action'], r['changed']), (200, 'unchanged', []))       # idempotent: no write
        self.assertEqual(len(self.writes(n0)), 1)
        st, r = self.call('POST', '/paperless/taxonomy', {'kind': 'tag', 'name': 'Inbox', 'is_inbox_tag': True})
        self.assertEqual((st, r['code']), (400, 'unknown_name'))                        # new names need create
        self.assertEqual(len(self.writes(n0)), 1)
        st, r = self.call('POST', '/paperless/taxonomy', {'kind': 'tags', 'name': 'Inbox', 'is_inbox_tag': True,
                                                          'create': True})
        self.assertEqual((st, r['action'], r['is_inbox_tag'], r['name']), (200, 'created', True, 'Inbox'), r)
        self.assertEqual(self.writes(n0)[-1], ('POST', '/api/tags/', {'is_inbox_tag': True, 'name': 'Inbox'}))
        st, r = self.call('POST', '/paperless/taxonomy', {'kind': 'correspondent', 'name': 'Krankenkasse Muster AG',
                                                          'matching_algorithm': 6})
        self.assertEqual((st, r['algorithm'], r['changed']), (200, 'auto', ['matching_algorithm']))
        st, r = self.call('GET', '/paperless/meta')
        rech = next(o for o in r['document_types'] if o['name'] == 'Rechnung')
        self.assertEqual((rech['algorithm'], rech['matching_algorithm'], rech['match'], rech['is_insensitive']),
                         ('regex', 4, rx, True))
        self.assertTrue(next(o for o in r['tags'] if o['name'] == 'Inbox')['is_inbox_tag'])
        self.assertFalse(next(o for o in r['tags'] if o['name'] == 'gesundheit')['is_inbox_tag'])
        self.assertNotIn('is_inbox_tag', r['correspondents'][0])
        ev = [e for e in self.app.audit.read() if e['event'] == 'paperless_taxonomy']
        self.assertEqual([(e['kind'], e['name'], e['action'], e['fields']) for e in ev[-4:]],
                         [('document_types', 'Rechnung', 'updated', ['match', 'matching_algorithm']),
                          ('document_types', 'Rechnung', 'unchanged', []),
                          ('tags', 'Inbox', 'created', ['name', 'is_inbox_tag']),
                          ('correspondents', 'Krankenkasse Muster AG', 'updated', ['matching_algorithm'])])
        self.assertNotIn('Empfangsschein', self.cfg.audit_path.read_text())             # no match strings in the audit
        self.assertNoDeletes()

    def test_taxonomy_refuses_bad_rules(self):
        n0 = len(PAPERLESS_W.requests)
        g = {'kind': 'tag', 'name': 'gesundheit'}
        for body, code in (
                ({'kind': 'workflow', 'name': 'x', 'matching_algorithm': 0}, 'bad_param'),
                ({'kind': 'tag', 'name': '', 'matching_algorithm': 0}, 'bad_param'),
                ({'kind': 'tag', 'name': 'x' * 129, 'matching_algorithm': 0}, 'bad_param'),
                (g, 'bad_param'),                                                         # nothing to set
                (dict(g, matching_algorithm=7), 'bad_param'),
                (dict(g, matching_algorithm=True), 'bad_param'),
                (dict(g, matching_algorithm='magic'), 'bad_param'),
                (dict(g, match='a' * 257, matching_algorithm=4), 'bad_param'),              # length cap
                (dict(g, match='KVG\nVVG', matching_algorithm=4), 'bad_param'),
                (dict(g, match='(KVG', matching_algorithm=4), 'bad_regex'),
                (dict(g, match='KVG|', matching_algorithm=4), 'bad_regex'),                 # would match every document
                (dict(g, match='.*', matching_algorithm=4), 'bad_regex'),
                (dict(g, match='  ', matching_algorithm=1), 'bad_param'),
                (dict(g, matching_algorithm=3), 'bad_param'),                              # literal, but no text stored
                (dict(g, is_insensitive='no'), 'bad_param'),
                ({'kind': 'type', 'name': 'Rechnung', 'is_inbox_tag': True}, 'bad_param'),
                (dict(g, color='#ff0000', matching_algorithm=0), 'unknown_param'),
                (dict(g, owner=2, matching_algorithm=0), 'unknown_param'),
                (dict(g, id=3, matching_algorithm=0), 'unknown_param'),
                (dict(g, set_permissions={}, matching_algorithm=0), 'unknown_param'),
                ({'kind': 'tag', 'name': 'Neu', 'matching_algorithm': 6}, 'unknown_name')):
            st, r = self.call('POST', '/paperless/taxonomy', body)
            self.assertEqual((st, r.get('code')), (400, code), body)
        self.assertEqual(self.writes(n0), [])
        self.assertNoDeletes()

    def test_update_metadata_only_and_audited_by_field_name(self):
        n0 = len(PAPERLESS_W.requests)
        st, r = self.call('POST', '/paperless/update', {'id': 7, 'title': 'Rechnung Garage Oktober',
                                                        'created': '2026-09-30', 'document_type': 'rechnung',
                                                        'correspondent': 'Krankenkasse Muster AG',
                                                        'tags_add': ['Steuern'], 'tags_remove': ['gesundheit']})
        self.assertEqual(st, 200, r)
        self.assertEqual(set(r), {'id', 'created', 'added', 'title', 'correspondent', 'document_type', 'tags', 'url',
                                  'changed'})
        self.assertEqual((r['title'], r['created'], r['document_type'], r['tags']),
                         ('Rechnung Garage Oktober', '2026-09-30', 'Rechnung', ['steuern']))
        self.assertEqual(r['changed'], ['created', 'tags', 'title'])       # type/correspondent were already so
        for raw in ('Herzschmerz', IBAN, PHONE):
            self.assertNotIn(raw, json.dumps(r))
        self.assertEqual(self.writes(n0), [('PATCH', '/api/documents/7/', {'title': 'Rechnung Garage Oktober',
                                                                           'created': '2026-09-30', 'tags': [4]})])
        rec = [e for e in self.app.audit.read() if e['event'] == 'paperless_update'][-1]
        self.assertEqual((rec['doc_id'], rec['fields']), (7, ['created', 'tags', 'title']))
        self.assertNotIn('Garage Oktober', self.cfg.audit_path.read_text())              # field names, never values
        n1 = len(PAPERLESS_W.requests)
        st, r = self.call('POST', '/paperless/update', {'id': '7', 'title': 'Rechnung Garage Oktober',
                                                        'tags_remove': ['gesundheit'], 'tags_add': ['steuern']})
        self.assertEqual((st, r['changed']), (200, []))                                  # already so: nothing written
        self.assertEqual(self.writes(n1), [])
        self.assertNoDeletes()

    def test_update_refuses_content_and_bad_input(self):
        n0 = len(PAPERLESS_W.requests)
        for extra in ({'content': 'x'}, {'notes': ['x']}, {'owner': 1}, {'set_permissions': {}},
                      {'custom_fields': []}, {'archive_serial_number': 5}, {'tags': [1]}, {'delete': True}):
            st, r = self.call('POST', '/paperless/update', dict({'id': 8, 'title': 'x'}, **extra))
            self.assertEqual((st, r['code']), (400, 'unknown_param'), extra)
        for bad in ({'id': 8}, {'id': 8, 'create': True}, {'id': 'x', 'title': 'x'}, {'id': 8, 'title': 'a\nb'},
                    {'id': 8, 'title': 'x' * 129}, {'id': 8, 'created': '2026-13-01'},
                    {'id': 8, 'created': '1.10.2026'}, {'id': 8, 'tags_add': 'steuern'},
                    {'id': 8, 'tags_add': ['x'] * 21}, {'id': 8, 'tags_add': [5]}, {'id': 8, 'document_type': ''},
                    {'id': 8, 'tags_add': ['steuern'], 'tags_remove': ['STEUERN']},
                    {'id': 8, 'title': 'x', 'create': 'yes'}):
            st, r = self.call('POST', '/paperless/update', bad)
            self.assertEqual(st, 400, (bad, r))
        st, r = self.call('POST', '/paperless/update', {'id': 999, 'title': 'x'})
        self.assertEqual((st, r['code']), (404, 'not_found'))
        st, r = self.call('POST', '/paperless/update', {'id': 8, 'tags_add': ['Inbox-X']})
        self.assertEqual((st, r['code']), (400, 'unknown_name'))
        st, r = self.call('POST', '/paperless/update', {'id': 8, 'document_type': 'Lohnabrechnung',
                                                        'tags_remove': ['nope']})
        self.assertEqual((st, r['code']), (400, 'unknown_name'))
        self.assertEqual(self.writes(n0), [])                                            # no refused call wrote
        st, r = self.call('POST', '/paperless/update', {'id': 8, 'document_type': 'Lohnabrechnung',
                                                        'tags_add': ['Inbox-X'], 'create': True})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['document_type'], r['tags'], r['changed']), ('Lohnabrechnung', ['Inbox-X'],
                                                                         ['document_type', 'tags']))
        self.assertEqual([(m, p) for m, p, b in self.writes(n0)],
                         [('POST', '/api/document_types/'), ('POST', '/api/tags/'), ('PATCH', '/api/documents/8/')])
        ev = [(e['kind'], e['action']) for e in self.app.audit.read() if e['event'] == 'paperless_taxonomy']
        self.assertEqual(ev[-2:], [('document_types', 'created'), ('tags', 'created')])
        self.assertNoDeletes()


@unittest.skipUnless((CLI_DIR / 'vault').is_file() and (CLI_DIR / 'paperless').is_file(), 'clients not here (image)')
class CliPaperlessWriteTests(ApiBase):
    """~/bin/paperless set | rule set | rules -> exec ~/bin/vault -> this in-process vault -> its own fake paperless.
    VAULT_MODE is off on purpose: these commands always go through the vault."""
    name = 'cli-paperless-write'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.pl = FakePaperless()
        cls.app.store.set('paperless', {'url': cls.pl.url, 'token': PL_TOKEN})
        cls.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})     # raw requests (--reason)
        home = TMP / 'cli-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        for f in ('vault', 'paperless'):
            (home / 'bin' / f).symlink_to(CLI_DIR / f)
        tok = TMP / 'cli-token'
        tok.write_text(TOKEN + '\n')
        tok.chmod(0o600)
        cls.bin = home / 'bin'
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': cls.url, 'VAULT_TOKEN_FILE': str(tok),
                   'VAULT_MODE': 'off'}

    def cli(self, *args, tool='paperless'):
        p = subprocess.run([str(self.bin / tool), *args], env=self.env, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout, p.stderr

    def test_cli_card_fields_suggest_rule_test(self):
        """privacy plan B (2026-10-14): get = a card; tier-2 fields withheld; --content/--reason = the owner's ✅."""
        rc, out, err = self.cli('get', '7')
        self.assertEqual(rc, 0, err)
        self.assertNotIn('--- content ---', out)
        self.assertIn('amount: CHF 123.45  due: 2026-10-31', out)
        for raw in ('Herzschmerz', IBAN, 'rechnung.pdf'):
            self.assertNotIn(raw, out)
        rc, out, err = self.cli('get', '7', '--content')
        self.assertEqual(rc, 2, out + err)
        rc, out, err = self.cli('get', '7', '--content', '--reason', 'owner wants the gist')
        self.assertEqual(rc, 10, out + err)
        self.assertIn('vault raw release', out)
        rc, out, err = self.cli('fields', '7', '--fields', 'amount,iban')
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertEqual((d['amount'], d['iban'], d['_withheld'], d['has_payment_ref']), ('123.45', None, ['iban'], True))
        self.assertIn('withheld', err)
        rc, out, err = self.cli('fields', '7', '--fields', 'iban', '--reason', 'Kündigung needs it')
        self.assertEqual(rc, 10, out + err)
        rc, out, err = self.cli('rule', 'test', 'correspondent', '--any', 'krankenkasse', '--name', 'Krankenkasse Muster AG')
        self.assertEqual(rc, 0, err)
        self.assertIn('1 of 3 documents match', out)
        self.assertIn('#7  now: Krankenkasse Muster AG  (already so)', out)
        rc, out, err = self.cli('suggest', '8')
        self.assertEqual(rc, 0, err)
        self.assertIn('suggested:', out)
        rc, out, err = self.cli('raw', 'request', '--source', 'paperless-fields', '--id', '7', '--reason', 'need it',
                                tool='vault')
        self.assertEqual(rc, 10, out + err)

    def test_cli_set_rule_set_and_rules(self):
        rc, out, err = self.cli('set', '7', '--title', 'Rechnung Oktober', '--tag', '-gesundheit', '--tag', '+steuern')
        self.assertEqual(rc, 0, err)
        self.assertIn('#7  2026-10-01  Rechnung Oktober', out)
        self.assertIn('changed: tags, title', out)
        self.assertEqual(self.pl.docs[7]['tags'], [4])
        rc, out, err = self.cli('set', '7', '--tag', '-gesundheit')
        self.assertEqual((rc, out.splitlines()[-1]), (0, 'changed: nothing (it was already so)'), err)
        rc, out, err = self.cli('set', '7')
        self.assertEqual(rc, 2)
        self.assertIn('nothing to change', err)
        rc, out, err = self.cli('set', '7', '--tag', '--title')
        self.assertEqual(rc, 2)
        self.assertIn('bad --tag', err)
        rc, out, err = self.cli('set', '7', '--type', 'Police')
        self.assertEqual(rc, 2)
        self.assertIn("no document type named 'Police'", err)
        rx = r'\b(Police|Versicherungspolice|Policennummer)\b'
        rc, out, err = self.cli('rule', 'set', 'type', 'Police', '--regex', rx, '--create')
        self.assertEqual(rc, 0, err)
        self.assertIn(f'type created: Police  [id ', out)
        self.assertIn(f'regex "{rx}" (case-insensitive)', out)
        self.assertEqual(self.pl.requests[-1][:2], ('POST', '/api/document_types/'))
        self.assertEqual(json.loads(self.pl.requests[-1][3]), {'name': 'Police', 'match': rx, 'matching_algorithm': 4,
                                                               'is_insensitive': True})
        rc, out, err = self.cli('rule', 'set', 'tag', 'Inbox', '--inbox', '--create')
        self.assertEqual(rc, 0, err)
        self.assertIn('· inbox tag', out)
        rc, out, err = self.cli('rule', 'set', 'type', 'Police', '--inbox')
        self.assertEqual(rc, 2)
        self.assertIn('only apply to tags', err)
        rc, out, err = self.cli('rule', 'set', 'tag', 'steuern', '--regex', 'Steuer|')
        self.assertEqual(rc, 2)
        self.assertIn('every document', err)
        rc, out, err = self.cli('rule', 'set', 'tag', 'steuern')
        self.assertEqual(rc, 2)
        self.assertIn('nothing to set', err)
        rc, out, err = self.cli('rule', 'set', 'type', 'Police', '--auto')
        self.assertEqual(rc, 0, err)
        self.assertIn("type updated: Police", out)
        self.assertIn("auto (paperless' classifier)", out)
        rc, out, err = self.cli('rule', 'set', 'tag', 'steuern', '--literal', 'Steueramt Examplecity',
                                '--case-sensitive')
        self.assertEqual(rc, 0, err)
        self.assertIn('literal "Steueramt Examplecity" (case-sensitive)', out)
        self.assertEqual(json.loads(self.pl.requests[-1][3]), {'match': 'Steueramt Examplecity',
                                                               'matching_algorithm': 3, 'is_insensitive': False})
        rc, out, err = self.cli('rule', 'set', 'tag', 'Inbox', '--no-inbox', '--none')
        self.assertEqual(rc, 0, err)
        self.assertIn('no automatic matching', out)
        self.assertNotIn('inbox tag', out)
        rc, out, err = self.cli('rule', 'set', 'tag', 'Inbox', '--inbox')
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli('rules', 'type')
        self.assertEqual(rc, 0, err)
        self.assertIn('document types (2):', out)
        self.assertIn('Rechnung  [id 2, 1 docs]  any, no match text (matches nothing)', out)
        rc, out, err = self.cli('rules', '--json')
        d = json.loads(out)
        self.assertEqual(set(d), {'tags', 'document_types', 'correspondents'})
        self.assertTrue(next(t for t in d['tags'] if t['name'] == 'Inbox')['is_inbox_tag'])
        rc, out, err = self.cli('paperless', 'set', '7', '--tag=+Inbox', '--json', tool='vault')
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)['changed'], ['tags'])
        rc, out, err = self.cli('meta')                      # every command goes through the vault (2026-10-14)
        self.assertEqual(rc, 0, err)
        self.assertIn('document types (', out)
        self.assertEqual([r[:2] for r in self.pl.requests if r[0] in ('DELETE', 'PUT')], [])


class ApiFireflyTests(ApiBase):
    name = 'api-firefly'

    def test_firefly(self):
        st, r = self.call('GET', '/firefly/status')
        self.assertEqual(r['configured'], False)
        st, r = self.call('POST', '/firefly/summary', {'start': '2026-09-01', 'end': '2026-09-30'})
        self.assertEqual((st, r['code']), (503, 'not_configured'))
        st, r = self.call('POST', '/secrets/firefly', {'url': FIREFLY.url, 'token': FF_TOKEN})
        self.assertEqual(st, 200, r)
        self.assertIn('6.4.0', r['check'])
        st, r = self.call('POST', '/firefly/summary', {'start': '2026-09-01', 'end': '2026-09-30'})
        self.assertEqual(r['expense'][0], {'category': 'Groceries', 'total': -420.5, 'currency': 'CHF'})
        st, r = self.call('POST', '/firefly/merchants', {'start': '2026-09-01', 'end': '2026-09-30'})
        blob = json.dumps(r)
        self.assertNotIn('Migros', blob)
        self.assertNotIn('Traube', blob)
        names = [m['merchant'] for m in r['merchants']]
        self.assertTrue(all(re.fullmatch(r'Merchant [0-9a-f]{6}', n) for n in names))
        st, r2 = self.call('POST', '/firefly/merchants', {'start': '2026-09-01', 'end': '2026-09-30'})
        self.assertEqual(names, [m['merchant'] for m in r2['merchants']])
        st, r = self.call('POST', '/firefly/summary', {'start': '2026-9-1', 'end': 'x'})
        self.assertEqual(st, 400)


class ApiStaticTests(unittest.TestCase):
    def test_bot_methods_and_who_can_approve(self):
        src = '\n'.join(Path(ROOT / 'app' / f).read_text()
                        for f in ('vaultlib.py', 'vaultd.py', 'sources.py', 'board.py', 'finance.py', 'gmail.py')
                        if (ROOT / 'app' / f).is_file())                # finance.py: private-only (plan D2)
        calls = set(re.findall(r"_call\('(\w+)'", src))
        self.assertEqual(calls, {'sendMessage', 'getUpdates', 'answerCallbackQuery', 'editMessageText', 'getFile',
                                 'pinChatMessage', 'getChat'})
        nl = Path(ROOT / 'app' / 'vaultlib.py').read_text()                # both only on the owner's chat id
        for m in ('pinChatMessage', 'getChat'):
            self.assertRegex(nl, r"_call\('" + m + r"', \{'chat_id': self\.chat_id\(\)")
        self.assertEqual(set(V.Notifier.METHODS), calls)
        for bad in ('forwardMessage', 'copyMessage', 'setWebhook', 'sendDocument'):
            self.assertNotIn(bad, src)
        self.assertEqual(len(re.findall(r'\.get_updates\(', src)), 1)            # only the approval bot polls
        # a decision comes from exactly two places: the bot callback and the console-only route
        import ast
        vias = []
        for f in ('vaultlib.py', 'vaultd.py', 'sources.py'):
            for node in ast.walk(ast.parse(Path(ROOT / 'app' / f).read_text())):
                if isinstance(node, ast.Call) and getattr(node.func, 'attr', None) == 'decide':
                    vias.append([k.value.value for k in node.keywords if k.arg == 'via'])
        self.assertEqual(vias, [['telegram'], ['console']])
        d = Path(ROOT / 'app' / 'vaultd.py').read_text()
        body = d[d.index('    def h_raw_approve'):d.index('    def h_events')]
        self.assertIn("if self.via() != 'console':", body.split('.decide(')[0])
        self.assertIn("'--host', '127.0.0.1'", Path(ROOT / 'app' / 'vaultd.py').read_text())
        self.assertIn("'--cache-ram', '0'", Path(ROOT / 'app' / 'vaultd.py').read_text())

    def test_llm_argv(self):
        self.assertEqual(D.llm_argv(['--anonymize', '--owner-name', 'Nico', '--strict']),
                         ['--anonymize', '--owner-name=Nico', '--strict'])
        self.assertEqual(D.llm_argv(['--keep-own-money', '--owner-name', 'Nico']),
                         ['--keep-own-money', '--owner-name=Nico'])
        for bad in (['--system'], ['--max-tokens', 'x'], ['--max-tokens', '0'], ['--owner-name', 'a\nb'],
                    ['positional'], ['--temp', '3'], ['--anonymize=1'], 'not-a-list'):
            with self.assertRaises(V.VaultError, msg=bad):
                D.llm_argv(bad)


@unittest.skipUnless((CLI_DIR / 'vault').is_file(), 'client not here (image)')
class CliRawEventsTests(ApiBase):
    """~/bin/vault raw request/release (buttons, code), secret rotation, events -> this in-process vault."""
    name = 'cli-raw-events'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})    # a new bot: polled
        home = TMP / 'cli-raw-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        (home / 'bin' / 'vault').symlink_to(CLI_DIR / 'vault')
        tok = TMP / 'cli-raw-token'
        tok.write_text(TOKEN + '\n')
        tok.chmod(0o600)
        cls.bin = home / 'bin'
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': cls.url, 'VAULT_TOKEN_FILE': str(tok)}

    def cli(self, *args, stdin=None):
        p = subprocess.run([str(self.bin / 'vault'), *args], env=self.env, input=stdin, capture_output=True,
                           text=True, timeout=90)
        return p.returncode, p.stdout, p.stderr

    def rid(self, out):
        return re.search(r'request ([0-9a-f]{12})', out).group(1)

    def test_raw_buttons_code_secret_and_events(self):
        TELEGRAM.updates = []
        self.assertEqual(self.app.approval.step(), 0)                   # buttons mode
        rc, out, err = self.cli('raw', 'request', '--source', 'test', '--reason', 'cli check')
        self.assertEqual(rc, 10, err)
        self.assertIn('✅ Allow once / ❌ Deny buttons', out)
        rid = self.rid(out)
        self.assertIn(f'After his tap: vault raw release {rid}', out)
        rc, out, err = self.cli('raw', 'release', rid, '--no-wait')
        self.assertEqual(rc, 10, err)
        self.assertIn("hasn't decided yet", err)
        kb = json.loads(TELEGRAM.sent[-1]['reply_markup'])['inline_keyboard'][0]
        TELEGRAM.press(kb[0]['callback_data'], 100 + len(TELEGRAM.sent))
        threading.Timer(1.5, self.app.approval.step).start()          # his tap arrives while the client waits
        rc, out, err = self.cli('raw', 'release', rid, '--wait', '30')
        self.assertEqual((rc, out), (0, 'raw-release test OK\n'), err)
        self.assertIn('waiting for his tap', err)
        rc, out, err = self.cli('raw', 'release', rid, '--no-wait')
        self.assertEqual(rc, 1)                                         # once only
        self.assertIn('released', err)
        rc, out, err = self.cli('secret', 'rotate', 'telegram', '--reason', 'new bot')
        self.assertEqual(rc, 10, err)
        rid = self.rid(out)
        self.assertIn(f'After his tap: vault secret set telegram --request-id {rid} < new.json', out)
        self.app.raw.decide(rid, True, via='console')
        rc, out, err = self.cli('secret', 'set', 'telegram', '--request-id', rid,
                                stdin=json.dumps({'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID}))
        self.assertEqual((rc, out.strip()), (0, 'secret telegram: replaced'), err)
        self.app.approval.state = 'stopped'                            # fallback: the code
        rc, out, err = self.cli('raw', 'request', '--source', 'test', '--reason', 'cli code check')
        self.assertEqual(rc, 10, err)
        self.assertIn('6-digit code', out)
        rc, out, err = self.cli('raw', 'release', self.rid(out), TELEGRAM.last_code())
        self.assertEqual((rc, out), (0, 'raw-release test OK\n'), err)
        rc, out, err = self.cli('events')
        self.assertEqual(rc, 0, err)
        self.assertRegex(out, r'^next cursor: \d+')
        rc, out, err = self.cli('tg', 'events', '--since', '0', '--json')
        self.assertEqual((rc, json.loads(out)['events']), (0, []), err)
        rc, out, err = self.cli('events', 'mute', '--chat', '-400')
        self.assertEqual((rc, out.strip()), (0, 'telegram chat -400: mute (1 rule(s) in total)'), err)
        rc, out, err = self.cli('events', 'rules')
        self.assertEqual(json.loads(out)[0]['chat'], '-400')
        rc, out, err = self.cli('status')
        self.assertEqual(rc, 0, err)
        self.assertIn('raw approval: fallback code (vault bot: stopped', out)
        self.assertIn('event feed: cursor 0, sources telegram, 1 rule(s)', out)


# ============================================================================================ approval bot (plan C)

BOTAPI = FakeTelegram()              # the approval tests' own Bot API (TELEGRAM keeps its simple history)


class ApprovalTests(unittest.TestCase):
    """The owner approves raw releases with ✅ Allow once / ❌ Deny buttons of the vault's OWN bot."""

    def setUp(self):
        BOTAPI.reset()
        self.tg = BOTAPI
        self.cfg = make_cfg(f'approval-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)
        self.audit = V.Audit(self.cfg.audit_path)
        self.notifier = V.Notifier(self.store, self.tg.url)
        self.alerts, self.clock = [], Clock()
        self.bot = V.ApprovalBot(self.cfg, self.store, self.notifier, self.audit, log=lambda m: None,
                                 alert=lambda *a, **k: self.alerts.append(a), clock=self.clock)
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})   # a NEW bot (set after init)
        self.raw = V.RawRequests(self.notifier, self.audit, b'k' * 32, clock=self.clock, approver=self.bot)
        self.bot.raw = self.raw
        self.assertEqual(self.bot.step(), 0)                         # first long poll: healthy
        self.assertTrue(self.bot.healthy())

    def request(self, payload='RAW TEXT'):
        r = self.raw.create('tg', "search 'Lugano'", 'owner asked for the exact quote', payload)
        kb = json.loads(self.tg.sent[-1]['reply_markup'])['inline_keyboard'][0]
        return r, 100 + len(self.tg.sent), kb

    def answers(self):
        return [p['text'] for p in self.tg.method_calls('answerCallbackQuery')]

    def edits(self):
        return [p['text'] for p in self.tg.method_calls('editMessageText')]

    def test_allow_once_then_release_once(self):
        r, mid, kb = self.request()
        self.assertEqual((r['approval'], r['status'], r['valid_seconds']), ('buttons', 'pending', 900))
        self.assertNotIn('attempts_allowed', r)
        sent = self.tg.sent[-1]
        self.assertEqual(sent['text'], "🔐 Claude asks for raw text\nWhy: owner asked for the exact quote\n"
                                       "What: tg · search 'Lugano' · ~8 bytes\n\n⏱ Valid 15 min\n"
                                       "✅ Allow once: only if you asked for this\n❌ Deny: otherwise\n"
                                       "(or ignore it: it expires by itself)")
        self.assertNotIn('Code:', sent['text'])
        self.assertEqual(([b['text'] for b in kb], sent['protect_content']), (['✅ Allow once', '❌ Deny'], 'true'))
        self.assertTrue(all(V.CALLBACK_RE.fullmatch(b['callback_data']) for b in kb))
        with self.assertRaises(V.RawPending) as cm:                  # not decided yet: the client polls again
            self.raw.release(r['request_id'])
        self.assertEqual((cm.exception.status, cm.exception.extra['status']), (409, 'pending'))
        with self.assertRaises(V.VaultError) as cm:                  # a code means nothing here, and costs nothing
            self.raw.release(r['request_id'], '123456')
        self.assertEqual(cm.exception.code, 'no_code')
        self.assertEqual(self.raw.reqs[r['request_id']]['attempts'], 0)
        self.assertEqual(self.raw.decide(r['request_id'], True, via='api')[0], 'mismatch')    # only bot or console
        self.tg.press(kb[0]['callback_data'], mid)
        self.assertEqual(self.bot.step(), 0)
        self.assertEqual(self.answers(), ['Allowed once ✓'])
        self.assertTrue(self.edits()[-1].startswith(sent['text'] + '\n\n✅ Allowed once · '))
        self.assertNotIn('reply_markup', self.tg.method_calls('editMessageText')[-1])   # buttons gone
        self.assertEqual(self.raw.release(r['request_id']), 'RAW TEXT')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'])
        self.assertEqual(cm.exception.code, 'request_released')
        self.assertEqual([e['event'] for e in self.audit.read()],
                         ['raw_request', 'raw_decision_refused', 'raw_approved', 'raw_released'])
        gu = self.tg.method_calls('getUpdates')[-1]
        self.assertEqual(json.loads(gu['allowed_updates']), ['callback_query', 'message'])   # + finance intake
        self.assertEqual(self.bot.st['offsets'][str(BOT_ID)], self.tg.uid + 1)          # confirmed: not seen again

    def test_waiting_release_returns_on_the_tap(self):
        r, mid, kb = self.request()
        got = []
        t = threading.Thread(target=lambda: got.append(self.raw.release(r['request_id'], wait=10)))
        t.start()
        time.sleep(0.3)
        self.tg.press(kb[0]['callback_data'], mid)
        self.bot.step()
        t.join(5)
        self.assertEqual(got, ['RAW TEXT'])

    def test_wrong_chat_or_sender_is_ignored(self):
        r, mid, kb = self.request()
        n = len(self.tg.calls)
        self.tg.press(kb[0]['callback_data'], mid, chat='987654321')            # another chat
        self.tg.press(kb[0]['callback_data'], mid, frm='987654321')             # someone else in a group with it
        self.bot.step()
        self.assertEqual([m for m, p in self.tg.calls[n:]], ['getUpdates'])    # no answer, no edit
        self.assertEqual(self.raw.reqs[r['request_id']]['state'], 'pending')
        self.assertEqual([e['why'] for e in self.audit.read() if e['event'] == 'raw_callback_refused'],
                         ['wrong_chat', 'wrong_chat'])
        with self.assertRaises(V.RawPending):
            self.raw.release(r['request_id'])

    def test_forged_buttons_change_nothing(self):
        r, mid, kb = self.request()
        rid, nonce = r['request_id'], kb[0]['callback_data'].split(':')[2]
        for data, m in ((f'a:{rid}:' + 'x' * 16, mid),                  # wrong nonce
                        (kb[0]['callback_data'], mid + 5),              # pressed under another message
                        (f'a:{rid}', mid),                              # malformed
                        ('a:' + 'f' * 12 + ':' + nonce, mid)):          # unknown request
            self.tg.press(data, m)
        self.bot.step()
        self.assertEqual(self.answers(), ['This button is not valid', 'This button is not valid', 'Unknown button',
                                          'This request is gone (expired, or the vault restarted)'])
        self.assertEqual((self.raw.reqs[rid]['state'], self.edits()), ('pending', []))
        self.assertEqual([e.get('why') for e in self.audit.read()
                          if e['event'] in ('raw_decision_refused', 'raw_callback_refused')],
                         ['mismatch', 'mismatch', 'bad_data', 'unknown'])

    def test_double_tap_and_deny(self):
        r, mid, kb = self.request()
        self.tg.press(kb[0]['callback_data'], mid)
        self.tg.press(kb[0]['callback_data'], mid)                      # double tap
        self.tg.press(kb[1]['callback_data'], mid)                      # Deny after Allow: too late
        self.bot.step()
        self.assertEqual(self.answers(), ['Allowed once ✓', 'Already approved', 'Already approved'])
        self.assertEqual(self.raw.release(r['request_id']), 'RAW TEXT')
        r2, mid2, kb2 = self.request('SECOND')
        self.tg.press(kb2[1]['callback_data'], mid2)
        self.tg.press(kb2[0]['callback_data'], mid2)                    # Allow after Deny: too late
        self.bot.step()
        self.assertEqual(self.answers()[-2:], ['Denied ✓', 'Already denied'])
        self.assertIn('\n\n❌ Denied · ', self.edits()[-1])
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r2['request_id'])
        self.assertEqual((cm.exception.status, cm.exception.code), (410, 'request_denied'))
        self.assertIsNone(self.raw.reqs[r2['request_id']]['payload'])

    def test_expiry_late_tap_and_unclaimed_approval(self):
        r, mid, kb = self.request()
        self.clock.t += 901
        self.bot.step()                                                 # the message shows it expired
        self.assertIn('\n\n⌛ Expired (not used) · ', self.edits()[-1])
        self.tg.press(kb[0]['callback_data'], mid)                      # a late tap
        self.bot.step()
        self.assertEqual(self.answers()[-1], 'Already expired')
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r['request_id'])
        self.assertEqual(cm.exception.code, 'request_expired')
        r2, mid2, kb2 = self.request()
        self.tg.press(kb2[0]['callback_data'], mid2)
        self.bot.step()
        self.clock.t += 301                                             # allowed, but never picked up
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(r2['request_id'])
        self.assertEqual(cm.exception.code, 'request_expired')

    def test_shared_bot_is_never_polled_and_the_code_still_works(self):
        cfg = make_cfg('approval-shared')
        store = V.SecretStore(cfg)
        store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})    # configured BEFORE: maybe shared
        n, audit = V.Notifier(store, self.tg.url), V.Audit(cfg.audit_path)
        bot = V.ApprovalBot(cfg, store, n, audit, log=lambda m: None)
        n0 = len(self.tg.calls)
        self.assertEqual(bot.step(), 30)
        self.assertEqual((bot.state, bot.healthy(), bot.status()['mode']), ('shared', False, 'code'))
        raw = V.RawRequests(n, audit, b'k' * 32, clock=self.clock, approver=bot)
        r = raw.create('test', 'no data', 'checking the flow', 'x')
        self.assertEqual((r['approval'], r['attempts_allowed']), ('code', 3))
        self.assertNotIn('reply_markup', self.tg.sent[-1])
        self.assertEqual(raw.release(r['request_id'], self.tg.last_code()), 'x')       # the code still works
        r = raw.create('test', 'no data', 'checking the console', 'y')
        self.assertEqual(raw.decide(r['request_id'], True, via='console')[0], 'approved')
        self.assertEqual(raw.release(r['request_id']), 'y')                            # console: no code needed
        bot2 = V.ApprovalBot(cfg, store, n, audit, log=lambda m: None)                  # a restart keeps it shared
        self.assertEqual((bot2.step(), bot2.state), (30, 'shared'))
        self.assertEqual([m for m, p in self.tg.calls[n0:]], ['sendMessage', 'sendMessage'])   # never getUpdates
        self.assertEqual(json.loads((cfg.state / 'approval-bot.json').read_text())['shared_bot_ids'], [BOT_ID])
        self.assertEqual((cfg.state / 'approval-bot.json').stat().st_mode & 0o777, 0o600)

    def test_conflict_marks_the_bot_shared_for_good(self):
        self.tg.conflict = True
        self.assertEqual(self.bot.step(), 30)
        self.assertEqual((self.bot.state, self.alerts[-1][0]), ('conflict', 'approval-bot'))
        self.assertNotIn(BOT_TOKEN, json.dumps(self.alerts) + self.bot.detail)
        self.tg.conflict = False
        n0 = len(self.tg.calls)
        self.assertEqual((self.bot.step(), self.bot.state), (30, 'shared'))
        self.assertEqual(self.tg.calls[n0:], [])
        r = self.raw.create('test', 'no data', 'checking', 'x')
        self.assertEqual(r['approval'], 'code')
        self.assertIn('Code: ', self.tg.sent[-1]['text'])
        self.assertIn('approval_bot_conflict', [e['event'] for e in self.audit.read()])

    def test_rate_limits_and_volume_alert(self):
        vol = []
        raw = V.RawRequests(FakeNotifier(), self.audit, b'k' * 32, clock=self.clock, on_volume=vol.append)
        for i in range(10):
            rr = raw.create('test', 'test', f'reason {i}', 'x')
            raw.decide(rr['request_id'], False, via='console')
            self.clock.t += 1
        self.assertEqual(vol, [7, 8, 9, 10])                            # more than 6 an hour: the owner hears of it
        with self.assertRaises(V.VaultError) as cm:
            raw.create('test', 'test', 'one too many', 'x')
        self.assertEqual((cm.exception.status, cm.exception.code), (429, 'hourly_limit'))
        self.assertIn('raw_rate_limited', [e['event'] for e in self.audit.read()])
        self.clock.t += 3600
        self.assertEqual(raw.create('test', 'test', 'a new hour', 'x')['status'], 'pending')

    def test_secrets_never_logged(self):
        r, mid, kb = self.request('TOPSECRET RAW')
        self.tg.press(kb[0]['callback_data'], mid)
        self.bot.step()
        self.assertEqual(self.raw.release(r['request_id']), 'TOPSECRET RAW')
        nonce = kb[0]['callback_data'].split(':')[2]
        blob = all_files_text(self.cfg.state) + all_files_text(self.cfg.logs) + self.cfg.audit_path.read_text()
        for s in (BOT_TOKEN, nonce, 'TOPSECRET'):
            self.assertNotIn(s, blob)
        self.assertNotIn(nonce, json.dumps(self.raw.pending()))

    def test_daily_summary_only_on_days_with_activity(self):
        def at(day, h, m=0):
            return dt.datetime(2026, 10, day, h, m, tzinfo=V.TZ).timestamp()
        n0 = len(self.tg.sent)
        self.assertIsNone(self.bot.daily_summary(at(11, 20, 5)))       # a quiet day: silence
        self.assertEqual(len(self.tg.sent), n0)
        self.request()
        self.audit.log('auth_failed', count=3)
        self.assertIsNone(self.bot.daily_summary(at(12, 19, 59)))      # not before 20:00
        text = self.bot.daily_summary(at(12, 20, 1))
        self.assertEqual(text, '🔐 Vault, last 24 h\nRaw requests: 1 (tg 1)\n✅ 0 allowed · ❌ 0 denied\n'
                               '⌛ 0 expired · 📦 0 delivered\n⚠️ auth failed: 3')
        self.assertEqual(self.tg.sent[-1]['text'], text)
        self.assertIsNone(self.bot.daily_summary(at(12, 21, 0)))       # once a day
        self.assertIn('daily_summary_sent', [e['event'] for e in self.audit.read()])

    def test_disabled_in_test_mode(self):
        cfg = make_cfg('approval-testmode', VAULT_TEST_MODE='1')
        store = V.SecretStore(cfg)
        bot = V.ApprovalBot(cfg, store, V.Notifier(store, self.tg.url, test_mode=True), V.Audit(cfg.audit_path),
                            log=lambda m: None)
        store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        n0 = len(self.tg.calls)
        self.assertEqual((bot.step(), bot.state, self.tg.calls[n0:]), (300, 'disabled', []))


class ApiApprovalTests(ApiBase):
    name = 'api-approval'

    def setUp(self):
        super().setUp()
        if not self.app.store.is_set('telegram'):       # set after the vault started: a new bot, polled
            self.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})

    def console(self, method, path, body=None, key=None):
        return ApiConsoleTests.console(self, method, path, body, key)

    def test_owner_approves_claude_cannot(self):
        TELEGRAM.updates = []
        self.assertEqual(self.app.approval.step(), 0)                   # a bot set after the first start: polled
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'checking the buttons'})
        self.assertEqual((st, r['approval'], r['status']), (200, 'buttons', 'pending'), r)
        rid = r['request_id']
        for body in ({'request_id': rid, 'decision': 'approve'}, {'request_id': rid}):
            st, e = self.call('POST', '/raw/approve', body)             # Claude's token: no such endpoint
            self.assertEqual((st, e['code']), (404, 'not_found'))
        st, idx = self.call('GET', '/')
        self.assertNotIn('POST /raw/approve', idx['endpoints'])
        st, p = self.call('POST', '/raw/release', {'request_id': rid, 'wait': 0.3})
        self.assertEqual((st, p['status'], p['approval']), (200, 'pending', 'buttons'), p)
        st, p = self.call('POST', '/raw/release', {'request_id': rid, 'code': '123456'})
        self.assertEqual((st, p['code']), (409, 'no_code'))
        st, p = self.call('GET', '/raw/pending')
        self.assertEqual((p['requests'][-1]['approval'], p['requests'][-1]['state']), ('buttons', 'pending'))
        self.assertEqual(self.console('POST', '/raw/approve', {'request_id': rid, 'decision': 'maybe'})[0], 400)
        st, c = self.console('POST', '/raw/approve', {'request_id': rid, 'decision': 'approve'})
        self.assertEqual((st, c), (200, {'outcome': 'approved'}))
        self.assertIn('\n\n✅ Allowed once · ', TELEGRAM.method_calls('editMessageText')[-1]['text'])
        st, out = self.call('POST', '/raw/release', {'request_id': rid})
        self.assertEqual((st, out), (200, {'status': 'released', 'kind': 'text', 'text': 'raw-release test OK'}))
        self.assertEqual([e['via'] for e in self.app.audit.read() if e['event'] == 'raw_approved'], ['console'])
        self.app.approval.state = 'stopped'                            # e.g. the bot can't poll: code fallback
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'checking the fallback'})
        self.assertEqual(r['approval'], 'code')
        st, out = self.call('POST', '/raw/release', {'request_id': r['request_id'], 'code': TELEGRAM.last_code()})
        self.assertEqual((st, out['status']), (200, 'released'))

    def test_console_cli_pending_approve_deny(self):
        cfg = V.Config(make_env(self.name, VAULT_PORT=str(self.srv.server_address[1])))
        self.app.approval.state = 'stopped'
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'console check'})
        rid, out = r['request_id'], []
        self.assertEqual(D.console_main(['pending'], out=out.append, cfg=cfg), 0)
        self.assertIn(rid, out[-1])
        self.assertIn('pending', out[-1])
        self.assertEqual(D.console_main(['approve', rid], ask=lambda p: 'n', out=out.append, cfg=cfg), 1)
        self.assertEqual(out[-1], 'vault-console: nothing changed')
        self.assertEqual(D.console_main(['deny', rid], ask=lambda p: 'y', out=out.append, cfg=cfg), 0)
        self.assertEqual(out[-1], 'vault-console: denied')
        self.assertEqual(D.console_main(['approve', rid], ask=lambda p: 'y', out=out.append, cfg=cfg), 1)
        self.assertIn('no pending request', out[-1])
        st, e = self.call('POST', '/raw/release', {'request_id': rid, 'code': TELEGRAM.last_code()})
        self.assertEqual((st, e['code']), (410, 'request_denied'))


# ============================================================================================ event feed (plan E)

def ev_item(i, text, chat_key='2001', chat='Anna', chat_type='user', sender='Anna', sender_key='2001', quiet=None,
            ts=None):
    """One queued message as tgread live-items hands it over (regex-masked line, real names)."""
    return {'qid': i, 'ts': ts if ts is not None else time.time(), 'chat_key': chat_key, 'chat_id': int(chat_key),
            'chat_type': chat_type, 'chat': chat, 'sender': sender, 'sender_key': sender_key, 'msg_id': 500 + i,
            'text': f'[10.10. 12:00] {sender}: {text} (#{500 + i})', 'quiet': quiet, 'public': False}


def triage_says(*labels):
    (STUB_DIR / 'llm-json').write_text(json.dumps({'results': [
        {'i': n, 'label': lab, 'actionable': lab != 'chatter'} for n, lab in enumerate(labels, 1)]}))


class ApiHaOffTests(ApiBase):
    """HA status feed switch (15.10): VAULT_HA_FEED unset = off -> /ha/now 409 ha_off, no thread, status says off."""
    name = 'api-ha-off'

    def test_off(self):
        st, r = self.call('GET', '/ha/now')
        self.assertEqual((st, r['code']), (409, 'ha_off'))
        st, s = self.call('GET', '/status')
        self.assertEqual((s['ha']['feed'], s['ha']['state']), ('off', 'off'))
        self.assertNotIn('homeassistant', s['events']['sources'])


class ApiHaNowTests(ApiBase):
    """GET /ha/now (phase 2): coarse flags + age, never coordinates; HA rows in /events carry `ha` (invented)."""
    name = 'api-ha-now'
    extra_env = {'VAULT_HA_FEED': '1', 'VAULT_HA_DEVICE': 'owner_phone'}

    def test_not_configured_then_flags(self):
        st, r = self.call('GET', '/ha/now')
        self.assertEqual((st, r['code']), (409, 'not_configured'))
        self.app.store.set('homeassistant', {'url': 'http://127.0.0.1:9', 'token': 'x' * 30, 'person': 'person.owner'})
        sts = [{'entity_id': 'person.owner', 'state': 'not_home', 'attributes': {
                    'device_trackers': ['device_tracker.owner_phone'], 'latitude': 21.5, 'longitude': 11.25}},
               {'entity_id': 'device_tracker.owner_phone', 'state': 'not_home', 'attributes': {
                   'latitude': 21.5, 'longitude': 11.25, 'source_type': 'gps'}},
               {'entity_id': 'zone.home', 'state': '0', 'attributes': {'friendly_name': 'Home', 'latitude': 21.0,
                                                                        'longitude': 11.25, 'radius': 100}},
               {'entity_id': 'binary_sensor.owner_phone_android_auto', 'state': 'off', 'attributes': {}},
               {'entity_id': 'sensor.owner_phone_geocoded_location', 'state': 'Fakestr. 1, 9999 Fakeville',
                'attributes': {'Locality': 'Fakeville', 'Thoroughfare': 'Fakestr.', 'Postal Code': '9999'}}]
        import ha_live as HL
        self.app.ha.feed.set_selection(HL.select(sts, 'person.owner', 'owner_phone'))
        self.app.ha.feed.observe_all(sts)
        st, r = self.call('GET', '/ha/now')
        self.assertEqual(st, 200, r)
        self.assertEqual((r['place']['kind'], r['place']['band'],
                          r['place']['flag'], r['place']['town']), ('away', 'far', 'far', 'Fakeville'))
        self.assertFalse(r['drive']['active'])
        blob = json.dumps(r)
        for bad in ('21.5', '11.25', 'Fakestr', '9999'):
            self.assertNotIn(bad, blob)
        self.assertEqual(r['connection']['feed'], 'on')
        st, s = self.call('GET', '/status')
        self.assertIn('homeassistant', s['events']['sources'])
        # a feed row comes out of /events with its coarse `ha` object
        head = self.call('GET', '/events?since=latest')[1]['next_cursor']
        self.app.ha.feed.observe('binary_sensor.owner_phone_android_auto', {'state': 'on', 'attributes': {}})
        self.app.ha.feed.tick(time.time() + 1)
        st, ev = self.call('GET', f'/events?since={head}&source=homeassistant')
        self.assertEqual(st, 200, ev)
        e = ev['events'][-1]
        self.assertEqual((e['source'], e['label'], e['ha']['state'], e['actionable']), ('homeassistant', 'drive',
                                                                                         'start', True))
        self.assertEqual(ev['live']['homeassistant'], self.app.ha.state)
        self.assertIn('ha_now', [x['event'] for x in self.call('GET', '/audit?days=1')[1]['events']])

    def test_z_cli_ha_now(self):
        """~/bin/vault ha now [--json] -> this in-process vault: coarse lines, no coordinates (invented values)."""
        if not (CLI_DIR / 'vault').exists():
            self.skipTest('no ~/bin/vault client here (inside the image)')
        self.app.store.set('homeassistant', {'url': 'http://127.0.0.1:9', 'token': 'x' * 30, 'person': 'person.owner'},
                           replace_ok=True)
        import ha_live as HL
        sts = [{'entity_id': 'person.owner', 'state': 'home', 'attributes': {
                    'device_trackers': ['device_tracker.owner_phone'], 'latitude': 21.0, 'longitude': 11.25}},
               {'entity_id': 'device_tracker.owner_phone', 'state': 'home', 'attributes': {
                   'latitude': 21.0, 'longitude': 11.25, 'source_type': 'gps'}},
               {'entity_id': 'zone.home', 'state': '1', 'attributes': {'friendly_name': 'Home', 'latitude': 21.0,
                                                                        'longitude': 11.25, 'radius': 100}},
               {'entity_id': 'binary_sensor.owner_phone_android_auto', 'state': 'off', 'attributes': {}},
               {'entity_id': 'sensor.owner_phone_battery_level', 'state': '42', 'attributes': {}},
               {'entity_id': 'sensor.owner_phone_bluetooth_connection', 'state': '1', 'attributes': {
                   'connected_paired_devices': ['AA:BB:CC:DD:EE:09 (Fake Buds Z)']}}]
        self.app.ha.feed.set_selection(HL.select(sts, 'person.owner', 'owner_phone'))
        self.app.ha.feed.observe_all(sts)
        home = TMP / 'cli-ha-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        if not (home / 'bin' / 'vault').exists():
            (home / 'bin' / 'vault').symlink_to(CLI_DIR / 'vault')
        tok = TMP / 'cli-ha-token'
        tok.write_text(TOKEN + '\n')
        tok.chmod(0o600)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': self.url, 'VAULT_TOKEN_FILE': str(tok)}
        p = subprocess.run([str(home / 'bin' / 'vault'), 'ha', 'now'], env=env, capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('place: home [home]', p.stdout)
        self.assertIn('drive: no', p.stdout)
        self.assertIn('bluetooth: headphones', p.stdout)
        self.assertIn('battery: 40%', p.stdout)
        for bad in ('21.0', '11.25', 'Fake Buds', 'AA:BB'):
            self.assertNotIn(bad, p.stdout)
        p = subprocess.run([str(home / 'bin' / 'vault'), 'ha', 'now', '--json'], env=env, capture_output=True,
                           text=True, timeout=60)
        self.assertEqual(json.loads(p.stdout)['place']['flag'], 'home')


class EventFeedTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_cfg(f'events-{self._testMethodName}')
        self.clock = Clock(time.time())
        self.store = V.EventStore(self.cfg.state / 'events.db', clock=self.clock)
        self.rules = V.EventRules(self.cfg.state / 'events-rules.json')
        self.gate = V.LLMGate()
        self.policy = V.Policy(self.cfg, self.gate)
        self.feed = V.EventFeed(self.store, self.rules, self.policy, self.gate, clock=self.clock)
        llm_mode('plain')

    def tearDown(self):
        llm_mode('ok')

    def test_triage_then_anonymize_only_what_surfaces(self):
        now = self.clock()
        triage_says('question_to_owner', 'chatter', 'money')
        n0 = len(llm_calls())
        rows = self.feed.process('telegram', {'owner_name': 'Lukas Meier', 'items': [
            ev_item(1, f'Kommst du am Samstag? Ruf an {PHONE}. Er hat Herzschmerz.', ts=now - 60),
            ev_item(2, 'haha', ts=now - 50),
            ev_item(3, 'Kannst du mir die 45 CHF fürs Konzert schicken?', chat_key='-300', chat='Familie Muster',
                    chat_type='group', sender='Peter', sender_key='2003', ts=now - 40)]})
        calls = llm_calls()[n0:]
        self.assertEqual([c['args'][0] for c in calls], ['--json'])     # privacy plan A: triage only, no paraphrase
        sysp = calls[0]['args'][calls[0]['args'].index('--system') + 1]
        self.assertIn('Lukas', sysp)
        self.assertNotIn('Meier', sysp)
        self.assertNotIn(PHONE, calls[0]['text'])                       # the regex net runs before the LLM
        self.assertEqual([(r['label'], r['actionable'], r['text']) for r in rows],
                         [('question_to_owner', 1, None), ('chatter', 0, None), ('money', 1, None)])
        self.assertEqual(rows[2]['chat'], 'group')                      # a group without an alias
        self.assertEqual(rows[2]['who'], 'Peter')
        self.assertTrue(all(r['urgency'] in V.URGENCY for r in rows))
        got, nxt, more, reset = self.store.since(0)
        self.assertEqual((len(got), nxt, more, reset), (3, 3, False, False))
        self.assertIsNone(got[1]['text'])                               # chatter: counted, no text kept

    def test_split_failure_falls_back_to_one_call_per_item(self):
        llm_mode('ok')                                                  # 'ANON ' prefix breaks the item blocks
        triage_says('request', 'deadline')
        rows = self.feed.process('telegram', {'owner_name': 'Lukas', 'items': [
            ev_item(1, 'Bring bitte den Schlüssel mit'), ev_item(2, 'Anmeldung bis Freitag')]})
        self.assertEqual([r['text'] for r in rows], [None, None])      # privacy plan A: no text, no paraphrase
        self.assertEqual([c['args'][0] for c in llm_calls()[-1:]], ['--json'])
        self.assertEqual([p[:5] for p in self.feed.anonymize(['a', 'b'], 'Lukas')], ['ANON ', 'ANON '])

    def test_bad_triage_output_surfaces_only_direct_chats(self):
        (STUB_DIR / 'llm-json').write_text('not json')
        rows = self.feed.process('telegram', {'owner_name': 'Lukas', 'items': [
            ev_item(1, 'Hoi, wie gehts?'),
            ev_item(2, 'Wer kommt mit?', chat_key='-400', chat='Climbing Crew', chat_type='supergroup')]})
        self.assertEqual([(r['label'], r['actionable'], r['text']) for r in rows],
                         [('unknown', 1, None), ('unknown', 0, None)])
        self.assertEqual(V.parse_triage('{"results": [{"i": 1, "label": "chatter", "actionable": true}, '
                                        '{"i": 2, "label": "money"}, {"i": true, "label": "money"}]}',
                                        [{'chat_type': 'user'}] * 3),
                         [('chatter', False), ('money', True), ('unknown', True)])

    def test_rules_quiet_stale_and_busy(self):
        now = self.clock()
        self.rules.set('telegram', 'mute', chat='-400')
        self.rules.set('telegram', 'priority', sender='2002')          # Bob: always surfaced, even where it's quiet
        self.rules.set('gmail', 'mute', sender='2001')                  # another source: no effect here
        items = [ev_item(1, 'climb tonight?', chat_key='-400', chat='Climbing Crew', chat_type='supergroup'),
                 ev_item(2, 'News', chat_key='-1000000000500', chat='Rhein News', chat_type='channel', quiet='channel'),
                 ev_item(3, 'ok', chat_key='-600', chat='Spam Deals', chat_type='supergroup', sender='Bob',
                         sender_key='2002', quiet='muted'),
                 ev_item(4, 'alt', ts=now - 7 * 3600)]
        items += [ev_item(10 + k, f'msg {k}', chat_key='2005', chat='Eve', sender='Eve', sender_key='2005')
                  for k in range(12)]
        triage_says(*(['chatter'] * 11))                                # Bob + 10 of Eve's 12 (cap per chat hour)
        rows = self.feed.process('telegram', {'owner_name': 'Lukas', 'items': items})
        coll = {(r['chat_key'], r['why']): r['count'] for r in rows if r['label'] == 'collapsed'}
        self.assertEqual(coll, {('-400', 'muted'): 1, ('-1000000000500', 'channel'): 1, ('2001', 'stale'): 1,
                                ('2005', 'busy'): 2})
        bob = [r for r in rows if r['sender_key'] == '2002'][0]
        self.assertEqual((bob['priority'], bob['text'], bob['label']), (1, None, 'chatter'))
        self.assertEqual(sum(1 for r in rows if r['chat_key'] == '2005' and r['label'] == 'chatter'), 10)
        n0 = len(llm_calls())
        rows = self.feed.process('telegram', {'owner_name': 'Lukas', 'items': [
            ev_item(30, 'noch eins', chat_key='2005', chat='Eve', sender='Eve', sender_key='2005')]})
        self.assertEqual([(r['label'], r['why']) for r in rows], [('collapsed', 'busy')])   # the stored hour counts
        self.assertEqual(len(llm_calls()), n0)                          # nothing to triage: no LLM call

    def test_rules_validation(self):
        for bad in (('whatsapp', 'mute', '1', None), ('telegram', 'loud', '1', None), ('telegram', 'mute', '1', '2'),
                    ('telegram', 'mute', None, None), ('telegram', 'mute', 'a\nb', None)):
            with self.assertRaises(V.VaultError, msg=bad):
                self.rules.set(bad[0], bad[1], chat=bad[2], sender=bad[3])
        self.rules.set('telegram', 'mute', chat='-400')
        self.rules.set('telegram', 'mute', chat='-400')
        self.assertEqual(len(self.rules.list()), 1)
        self.assertEqual((self.rules.match('telegram', '-400'), self.rules.match('gmail', '-400')), ('mute', None))
        self.rules.set('telegram', 'priority', sender='2002')
        self.assertEqual(self.rules.match('telegram', '-400', '2002'), 'priority')          # priority wins
        self.rules.set('telegram', 'normal', chat='-400')
        self.assertEqual([r['sender'] for r in self.rules.list()], ['2002'])
        self.assertEqual(self.rules.path.stat().st_mode & 0o777, 0o600)

    def test_llm_failure_stores_nothing(self):
        llm_mode('fail')
        with self.assertRaises(V.LLMUnavailable):
            self.feed.process('telegram', {'owner_name': 'Lukas', 'items': [ev_item(1, 'Kommst du?')]})
        self.assertEqual(self.store.head(), 0)
        with self.assertRaises(V.VaultError):
            self.feed.process('whatsapp', {'items': []})

    def test_store_cursor_more_reset_and_retention(self):
        self.store.add([{'source': 'telegram', 'ts': 1, 'chat_key': 'a', 'label': 'chatter'} for _ in range(5)])
        self.store.add([{'source': 'gmail', 'ts': 2, 'chat_key': 'b', 'label': 'request', 'actionable': 1}])
        rows, nxt, more, reset = self.store.since(0, 2)
        self.assertEqual(([r['cursor'] for r in rows], nxt, more, reset), ([1, 2], 2, True, False))
        rows, nxt, more, reset = self.store.since(nxt, 10, source='gmail')
        self.assertEqual(([r['cursor'] for r in rows], nxt, more), ([6], 6, False))
        rows, nxt, more, reset = self.store.since(2, 10, source='telegram')
        self.assertEqual(([r['cursor'] for r in rows], nxt), ([3, 4, 5], 6))
        rows, nxt, more, reset = self.store.since(99)
        self.assertEqual((len(rows), reset), (6, True))                 # beyond the head (a new store): from 0
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.clock.t += 8 * 86400
        self.store.prune()
        self.assertEqual(self.store.since(6), ([], 6, False, False))    # pruned: not a reset
        self.store.add([{'source': 'telegram', 'ts': 3, 'chat_key': 'a', 'label': 'request'}])
        self.assertEqual([r['cursor'] for r in self.store.since(6)[0]], [7])


class ApiEventsTests(ApiBase):
    name = 'api-events'

    def setUp(self):
        super().setUp()
        llm_mode('plain')
        self.queue = []                                                 # tgread's event-feed queue (faked)
        tg = self.app.tg

        def items(after, n):
            its = [i for i in self.queue if i['qid'] > after][:n]
            last = its[-1]['qid'] if its else after
            return {'source': 'telegram', 'owner_name': 'Lukas Meier', 'items': its, 'last_qid': last,
                    'pending': sum(1 for i in self.queue if i['qid'] > last)}
        tg.logged_in = lambda: True
        tg.live_peek = lambda after: {'pending': sum(1 for i in self.queue if i['qid'] > after),
                                      'last_qid': max([0] + [i['qid'] for i in self.queue])}
        tg.live_items = items

    def tearDown(self):
        llm_mode('ok')
        for k in ('logged_in', 'live_peek', 'live_items'):
            self.app.tg.__dict__.pop(k, None)

    def position(self):
        return json.loads((self.cfg.state / 'events-sources.json').read_text())

    def test_feed_cursor_alias_and_retry(self):
        st, r = self.call('GET', '/events?since=latest')
        self.assertEqual((st, r['events'], r['more']), (200, [], False), r)
        self.assertEqual(r['live'], {'telegram': 'disabled', 'gmail': 'unconfigured',   # VAULT_NO_SYNC here
                                     'homeassistant': 'off'})
        cur = r['next_cursor']
        self.assertFalse(self.app.events_once())                        # nothing queued
        self.queue += [ev_item(1, f'Kommst du morgen? {PHONE}'), ev_item(2, 'lol'),
                       ev_item(3, 'News', chat_key='-1000000000500', chat='Rhein News', chat_type='channel',
                               quiet='channel')]
        triage_says('question_to_owner', 'chatter')
        self.assertFalse(self.app.events_once())
        self.assertEqual(self.position(), {'telegram': 3})
        st, r = self.call('GET', f'/events?since={cur}')
        ev = r['events']
        self.assertEqual([(e['source'], e['label'], e['actionable']) for e in ev],
                         [('telegram', 'question_to_owner', True), ('telegram', 'chatter', False),
                          ('telegram', 'collapsed', False)])
        self.assertNotIn('text', ev[0])                                 # privacy plan A: never text
        self.assertEqual((ev[0]['sender'], ev[0]['chat_key'], ev[0]['ref']), ('Anna', '2001', '501'))
        self.assertNotIn('text', ev[1])
        self.assertEqual((ev[2]['count'], ev[2]['why']), (1, 'channel'))
        self.assertNotIn(PHONE, json.dumps(r))
        self.assertEqual(r['dropped_counts'], {'telegram:channel': 1})
        st, r2 = self.call('GET', f"/events?since={r['next_cursor']}")
        self.assertEqual(r2['events'], [])
        st, r3 = self.call('GET', f'/events?since={cur}&max=1')
        self.assertEqual((len(r3['events']), r3['more'], r3['next_cursor']), (1, True, r3['events'][0]['cursor']))
        st, r4 = self.call('GET', f'/tg/events?since={cur}')
        self.assertEqual([e['cursor'] for e in r4['events']], [e['cursor'] for e in ev])
        st, r5 = self.call('GET', f'/events?since={cur}&source=gmail')
        self.assertEqual(r5['events'], [])
        for bad in ('since=-1', 'since=abc', 'max=0', 'max=501', 'source=whatsapp'):
            st, e = self.call('GET', f'/events?{bad}')
            self.assertEqual((st, e['code']), (400, 'bad_param'), bad)
        self.queue.append(ev_item(4, 'Zahlst du die Miete?'))
        llm_mode('fail')                                                # LLM down: the batch waits, nothing lost
        with self.assertRaises(V.VaultError):
            self.app.events_once()
        self.assertEqual(self.position(), {'telegram': 3})
        llm_mode('plain')
        triage_says('money')
        self.assertFalse(self.app.events_once())
        self.assertEqual(self.position(), {'telegram': 4})
        self.queue[:] = [ev_item(1, 'Treffen wir uns am Montag?')]       # tgread's queue was reset (wipe)
        triage_says('plan_datetime')
        self.app.events_once()
        self.assertEqual(self.position(), {'telegram': 1})
        st, r6 = self.call('GET', f"/events?since={r['next_cursor']}")
        self.assertEqual([e['label'] for e in r6['events']], ['money', 'plan_datetime'])
        st, s = self.call('GET', '/status')
        self.assertEqual((s['events']['head'], s['events']['error']), (r6['next_cursor'], None))

    def test_rules_routes(self):
        st, r = self.call('POST', '/events/rules', {'source': 'telegram', 'chat': '-400', 'mode': 'mute'})
        self.assertEqual((st, r['rules'][0]['mode']), (200, 'mute'), r)
        st, r = self.call('GET', '/events/rules')
        self.assertEqual([(x['source'], x['chat'], x['mode']) for x in r['rules']], [('telegram', '-400', 'mute')])
        st, r = self.call('POST', '/events/rules', {'source': 'gmail', 'sender': 'x@example.org', 'mode': 'priority'})
        self.assertEqual(st, 200, r)
        st, e = self.call('POST', '/events/rules', {'source': 'telegram', 'chat': '1', 'sender': '2', 'mode': 'mute'})
        self.assertEqual((st, e['code']), (400, 'bad_param'))
        st, r = self.call('POST', '/events/rules', {'source': 'telegram', 'chat': '-400', 'mode': 'normal'})
        self.assertEqual([x['source'] for x in r['rules']], ['gmail'])
        self.assertIn('event_rule', [e['event'] for e in self.app.audit.read()])


FAKE_LIVE = r'''#!/usr/bin/python3 -I
import json, os, signal, sys, time
d = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]
with open(os.path.join(d, 'calls.jsonl'), 'a') as f:
    f.write(json.dumps({'argv': a, 'force': os.environ.get('TGREAD_FORCE_EXCLUDE')}) + '\n')
if a[:1] == ['live']:
    signal.signal(signal.SIGTERM, lambda *x: sys.exit(0))
    for line in ('LIVE_READY', 'LIVE_QUEUED', 'SYNC_DONE new=1 edited=0 deleted=0 older=0 errors=0'):
        print(line, flush=True)
    while True:
        time.sleep(0.05)
print(json.dumps({'argv': a}))
'''


class LiveJobTests(unittest.TestCase):
    def test_supervisor_pauses_for_connection_commands(self):
        d = TMP / 'fake-live'
        d.mkdir()
        fake = write_exec(d / 'tgread', FAKE_LIVE)
        cfg = make_cfg('livejob', VAULT_TGREAD=str(fake), VAULT_PYTHON=sys.executable, VAULT_NO_SYNC='0')
        V.ensure_dir(cfg.home / '.config' / 'tgread')
        V.write_private(cfg.home / '.config' / 'tgread' / 'config.json', '{}')
        V.write_private(cfg.secrets / 'tgread.session', 'x')
        store = V.SecretStore(cfg)
        store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        gate = V.LLMGate()
        policy = V.Policy(make_cfg('livejob-policy'), gate)            # the real tgread's masks for the regex net
        tg = S.TG(cfg, policy, gate, V.Audit(cfg.audit_path), V.Notifier(store, TELEGRAM.url),
                  bot_ids=lambda: [BOT_ID, 6000000001])
        self.assertTrue(tg.live.enabled)

        def calls():
            return [json.loads(x) for x in (d / 'calls.jsonl').read_text().splitlines()]

        def until(cond):
            for _ in range(300):
                if cond():
                    return True
                time.sleep(0.05)
            return False
        stop = threading.Event()
        th = threading.Thread(target=tg.live.run, args=(stop,), daemon=True)
        th.start()
        try:
            self.assertTrue(until(lambda: tg.live.running() and tg.live.last_sync))
            self.assertTrue(tg.live.wake.is_set())                      # LIVE_QUEUED wakes the event feed
            snap = tg.live.snapshot()
            self.assertEqual((snap['state'], snap['queued_since_start'], snap['restarts']), ('running', 1, 0))
            self.assertTrue(json.loads(tg.config_path.read_text())['live_events'])
            live = calls()[-1]
            self.assertEqual(live['argv'], ['live', '--sync-minutes', str(cfg.sync_minutes)])
            self.assertEqual(set(live['force'].split(',')), {'777000', str(BOT_ID), '6000000001'})
            self.assertIsNone(tg.sync_once())                           # the listener syncs by itself
            res = tg.run('search', {'query': 'Lugano', 'sync': True})
            self.assertNotIn('--sync', json.loads(res['stdout'])['argv'])          # the archive is live already
            pid = tg.live.proc.pid
            res = tg.run('status', {'check': True})                    # needs the connection: pauses the listener
            self.assertIn('vault live listener: ', res['stdout'])
            self.assertTrue(until(lambda: tg.live.running() and tg.live.proc.pid != pid))
            self.assertEqual([c['argv'][0] for c in calls()], ['live', 'search', 'status', 'live'])
            self.assertEqual(tg.live.restarts, 0)
        finally:
            stop.set()
            tg.live.stop()
            th.join(5)


# ============================================================================================ process level

# ============================================================================================ pinned status board

import board as B  # noqa: E402


def board_snap(**kw):
    s = {'pending': [], 'llm_busy': None, 'llm': 'ok', 'finance_busy': None, 'tg_sync': False, 'gmail_check': False,
         'tg_logged_in': True, 'tg_live': 'running', 'gmail_configured': True, 'gmail_watch': 'idle',
         'gmail_error': False, 'paperless': True, 'firefly': True, 'events_error': False, 'alerts': 0,
         'policy': V.POLICY_VERSION}
    s.update(kw)
    return s


def tap_ev(path, status=200, via='api', private=None, masked=None, exit=None):
    return {'via': via, 'path': path, 'status': status, 'private': private or {}, 'masked': masked or {},
            'exit': exit}


class StatusBoardTests(unittest.TestCase):
    """The pinned status message in the owner's vault-bot chat (app/board.py) against the fake Bot API."""

    def setUp(self):
        BOTAPI.reset()
        self.tg = BOTAPI
        self.cfg = make_cfg(f'board-{self._testMethodName}')
        self.store = V.SecretStore(self.cfg)
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.notifier = V.Notifier(self.store, self.tg.url)
        self.clock = Clock(1_791_000_000.0)
        self.snap = board_snap()
        self.events = V.EventStore(self.cfg.state / 'events.db', clock=self.clock)
        self.logs = []
        self.board = self.make()

    def make(self, **kw):
        return B.StatusBoard(self.cfg, self.notifier, lambda: self.snap, events=self.events,
                             enabled=kw.get('enabled', lambda: (True, '')), log=self.logs.append, clock=self.clock)

    def n(self, meth):
        return len(self.tg.method_calls(meth))

    def text(self):
        return (self.tg.method_calls('editMessageText') or self.tg.method_calls('sendMessage'))[-1]['text']

    def test_create_pin_once_edit_on_change_throttle_refresh(self):
        self.assertEqual(self.board.step(), 'created')
        sent = self.tg.sent[-1]
        self.assertEqual((sent['chat_id'], sent['disable_notification'], sent['protect_content']), (CHAT_ID, 'true', 'true'))
        self.assertTrue(sent['text'].startswith('🟢 Idle\n'), sent['text'])
        pin = self.tg.method_calls('pinChatMessage')
        self.assertEqual([(p['chat_id'], p['message_id'], p['disable_notification']) for p in pin],
                         [(CHAT_ID, '101', 'true')])
        self.assertEqual(self.board.status()['state'], 'pinned')
        self.clock.t += 40
        self.assertEqual(self.board.step(), 'unchanged')                 # nothing changed: no call at all
        self.assertEqual((self.n('sendMessage'), self.n('editMessageText'), self.n('pinChatMessage')), (1, 0, 1))
        self.snap = board_snap(llm_busy=('telegram triage (4)', self.clock.t))
        self.assertEqual(self.board.step(), 'edited')                    # changed, last write 40 s ago
        self.assertTrue(self.text().startswith('🟢 Sorting 4 new Telegram msg(s) since '), self.text())
        self.assertEqual(self.tg.method_calls('editMessageText')[-1]['message_id'], '101')
        self.snap = board_snap(llm_busy=('event anonymize (2)', self.clock.t))
        self.clock.t += 10
        self.assertEqual(self.board.step(), 'throttled')                 # changed again 10 s later: waits
        self.clock.t += 21
        self.assertEqual(self.board.step(), 'edited')
        self.assertIn('Anonymizing 2 item(s)', self.text())
        self.assertEqual(self.n('editMessageText'), 2)
        self.clock.t += 590
        self.assertEqual(self.board.step(), 'unchanged')
        self.clock.t += 20                                               # 10 min since the last edit: clock refresh
        before = self.n('getChat')
        self.assertEqual(self.board.step(), 'edited')
        self.assertEqual(self.n('getChat'), before + 1)                  # and the pin is checked
        self.assertEqual((self.n('sendMessage'), self.n('pinChatMessage')), (1, 1))
        # a restart (new instance, same state file) keeps editing the same message
        self.board._save(force=True)
        b2 = self.make()
        self.snap = board_snap(tg_sync=True)
        self.clock.t += 31
        self.assertEqual(b2.step(), 'edited')
        self.assertEqual((self.n('sendMessage'), self.tg.method_calls('editMessageText')[-1]['message_id']), (1, '101'))
        self.assertIn('Syncing Telegram', self.text())

    def test_status_command_forces_a_refresh_owner_only(self):
        self.board.step()
        self.clock.t += 5
        self.assertFalse(self.board.on_message({'text': '/status', 'from': {'id': 999}, 'chat': {'id': 999}}))
        self.assertFalse(self.board.on_message({'text': '/fsync', 'from': {'id': int(CHAT_ID)},
                                                'chat': {'id': int(CHAT_ID)}}))
        self.assertEqual(self.board.step(), 'unchanged')
        self.assertTrue(self.board.on_message({'text': '/status@VaultBot', 'from': {'id': int(CHAT_ID)},
                                               'chat': {'id': int(CHAT_ID)}}))
        n = self.n('getChat')
        self.assertEqual(self.board.step(), 'edited')                    # forced: no change needed, 5 s after
        self.assertEqual(self.n('getChat'), n + 1)
        # through the approval bot's poll: /status never reaches the finance intake (no help text)
        audit = V.Audit(self.cfg.audit_path)
        bot = V.ApprovalBot(self.cfg, self.store, self.notifier, audit, log=lambda m: None, clock=self.clock)
        bot.st['shared_bot_ids'] = []
        fin = []
        bot.board = self.board
        bot.finance = type('F', (), {'on_message': lambda s, m: fin.append(m)})()
        self.tg.uid += 1
        self.tg.updates.append({'update_id': self.tg.uid, 'message': {
            'message_id': 5, 'text': '/status', 'from': {'id': int(CHAT_ID)}, 'chat': {'id': int(CHAT_ID)}}})
        self.tg.uid += 1
        self.tg.updates.append({'update_id': self.tg.uid, 'message': {
            'message_id': 6, 'text': '/freport', 'from': {'id': int(CHAT_ID)}, 'chat': {'id': int(CHAT_ID)}}})
        self.assertEqual(bot.step(), 0)
        self.assertTrue(self.board.forced)
        self.assertEqual([m['text'] for m in fin], ['/freport'])

    def test_state_not_stuck_off_once_enabled(self):
        self.assertEqual(self.board.step(), 'created')
        on = [False]
        board = self.make(enabled=lambda: (on[0], "only with the vault's own bot (vault bot: starting)"))
        self.assertEqual(board.step(), 'off')                            # the vault bot had not polled yet
        on[0] = True
        self.clock.t += 5
        self.assertEqual(board.step(), 'unchanged')
        self.assertEqual((board.status()['state'], board.status()['detail']), ('pinned', None))

    def test_recreate_after_delete_repin_after_unpin_and_errors(self):
        self.board.step()
        self.clock.t += 300
        self.tg.deleted.add(101)                                         # the owner deleted it
        self.snap = board_snap(tg_sync=True)
        self.assertEqual(self.board.step(), 'created')
        self.assertEqual((self.n('sendMessage'), [p['message_id'] for p in self.tg.method_calls('pinChatMessage')]),
                         (2, ['101', '102']))
        self.assertIn('Syncing Telegram', self.tg.sent[-1]['text'])
        self.assertTrue(any('sending a new one' in m for m in self.logs))
        # unpinned: the next check pins the same message again (no new message)
        self.tg.pinned = None
        self.clock.t += 10
        self.board.force()
        self.assertEqual(self.board.step(), 'edited')
        self.assertEqual([p['message_id'] for p in self.tg.method_calls('pinChatMessage')], ['101', '102', '102'])
        # an older pinned message (ours is newer) means ours was unpinned too
        self.tg.pinned = (50, 1_700_000_000)
        self.clock.t += 10
        self.board.force()
        self.board.step()
        self.assertEqual(self.n('pinChatMessage'), 4)
        # the owner pinned something newer himself: left alone
        self.tg.pinned = (500, 1_900_000_000)
        self.clock.t += 10
        self.board.force()
        self.board.step()
        self.assertEqual(self.n('pinChatMessage'), 4)
        self.assertEqual(self.board.status()['state'], 'unpinned')
        self.assertFalse(self.board.status()['pinned'])
        # "not modified" is fine; 429 backs off for retry_after; network errors never create a new message
        self.tg.edit_error = (400, 'Bad Request: message is not modified: specified new message content and reply markup are exactly the same')
        self.clock.t += 10
        self.board.force()
        self.assertEqual(self.board.step(), 'edited')
        self.tg.edit_error = (429, 'Too Many Requests: retry after 7')
        self.clock.t += 10
        self.board.force()
        self.assertEqual(self.board.step(), 'backoff')
        self.assertEqual(self.board.backoff_until, self.clock.t + 8)
        self.tg.edit_error = None
        self.snap = board_snap()
        self.clock.t += 5
        n = len(self.tg.calls)
        self.assertEqual(self.board.step(), 'backoff')                   # still waiting: no call
        self.assertEqual(len(self.tg.calls), n)
        self.clock.t += 31
        self.assertEqual(self.board.step(), 'edited')
        self.assertEqual(self.n('sendMessage'), 2)
        self.tg.fail = True                                              # chat not found (400) on everything
        self.clock.t += 10
        self.board.force()
        self.assertEqual(self.board.step(), 'backoff')                   # recreate also failed -> backoff
        self.tg.fail = False
        self.assertEqual(self.n('sendMessage'), 2)
        self.clock.t += 61
        self.assertEqual(self.board.step(), 'created')                   # the message was marked gone
        self.assertEqual(self.n('sendMessage'), 3)
        # deleted again right away: no second new message within 2 min
        self.tg.deleted.add(103)
        self.snap = board_snap(tg_sync=True)
        self.clock.t += 31
        self.assertEqual(self.board.step(), 'backoff')
        self.assertEqual(self.n('sendMessage'), 3)
        self.clock.t += 120
        self.assertEqual(self.board.step(), 'created')
        self.assertEqual(self.n('sendMessage'), 4)

    def test_counts_correct_and_no_content(self):
        b = self.board
        for ev in (tap_ev('/tg/search', private={'health': 2}, masked={'phone': 1}),
                   tap_ev('/tg/summarize', private={'dating': 1}),
                   tap_ev('/paperless/get', masked={'iban': 2}),
                   tap_ev('/gmail/search'), tap_ev('/llm/run', exit=3, masked={'phone': 9}),
                   tap_ev('/raw/request', status=409),
                   tap_ev('/events', masked={'email': 1}),                # not a request, but its redactions count
                   tap_ev('/status'), tap_ev('/tg/status'), tap_ev('/raw/release'), tap_ev('/gmail/status'),
                   tap_ev('/tg/search', via='console', private={'x': 5}), tap_ev('/tg/search', status=401)):
            b.note_call(ev)
        for event, rec in (('raw_request', {'source': 'tg'}), ('raw_request', {'source': 'gmail'}),
                           ('raw_approved', {}), ('raw_denied', {}), ('raw_expired', {}), ('raw_released', {}),
                           ('finance_import', {'sent': 23, 'ok': True}), ('auth_failed', {})):
            b.note_audit(event, rec)
        rows = [{'source': 'telegram', 'ts': int(self.clock.t), 'chat_key': '2001', 'chat': 'Anna Secretname',
                 'sender': 'Anna', 'label': 'question', 'actionable': 1, 'text': 'Herzschmerz und IBAN'},
                {'source': 'telegram', 'ts': int(self.clock.t), 'chat_key': '2002', 'chat': 'Gym group',
                 'label': 'chatter', 'actionable': 0},
                {'source': 'telegram', 'ts': int(self.clock.t), 'chat_key': '2003', 'chat': 'News',
                 'label': 'collapsed', 'count': 5, 'why': 'channel'},
                {'source': 'telegram', 'ts': int(self.clock.t), 'chat_key': '2004', 'chat': 'Mum',
                 'label': 'chatter', 'priority': 1, 'text': 'call me'},
                {'source': 'gmail', 'ts': int(self.clock.t), 'chat_key': 'bank.ch', 'chat': 'Bank',
                 'label': 'bill', 'actionable': 1, 'text': 'Rechnung'},
                {'source': 'gmail', 'ts': int(self.clock.t), 'chat_key': 'shop.ch', 'chat': 'Shop',
                 'label': 'collapsed', 'count': 3, 'why': 'newsletter'}]
        self.clock.t -= 86400
        self.events.add([dict(rows[0], chat_key='old')])                 # yesterday: not today's count
        self.clock.t += 86400
        self.events.add(rows)
        self.snap = board_snap(pending=[{'state': 'pending', 'approval': 'buttons', 'kind': 'text', 'source': 'tg',
                                         'expires': self.clock.t + 600}],
                               llm_busy=('paperless doc 7', self.clock.t - 120))
        self.assertEqual(b.step(), 'created')
        text = self.tg.sent[-1]['text']
        lines = text.split('\n')
        self.assertLessEqual(len(lines), 14, text)
        self.assertEqual(lines[0], '🟢 Waiting for your ✅: raw text (tg), 10 min left · Anonymizing a document since '
                         + dt.datetime.fromtimestamp(self.clock.t - 120, V.TZ).strftime('%H:%M'))
        self.assertIn('🤖 Claude: 6 requests (TG 2 · mail 1 · docs 1 · LLM 1 · raw 1)', lines)   # a refused ask too
        self.assertIn('🔐 Raw: 2 asked · ✅ 1 · ❌ 1 · ⌛ 1', lines)
        self.assertIn('🙈 Redacted: 7 (3 private · 4 masked)', lines)
        self.assertIn('💬 Telegram: 8 new → 2 for Claude, 6 chatter', lines)
        self.assertIn('✉️ Mail: 4 new → 1 for Claude, 3 other', lines)
        self.assertIn('🏦 Firefly: 1 import (+23 tx)', lines)
        self.assertIn('TG live ✅ · Gmail ✅ · Paperless ✅', lines)
        self.assertIn('Firefly ✅ · LLM ✅ · Feed ✅', lines)
        self.assertRegex(lines[-1], r'^🕐 \d\d:\d\d · policy v\d+(?:\.\d+)? \(\d\d-\d\d\)$')
        for bad in ('Anna', 'Secretname', 'Herzschmerz', 'IBAN', 'Gym', 'Mum', 'call me', 'Bank', 'Rechnung', 'Shop',
                    'News', 'paperless doc 7', BOT_TOKEN, BOT_TOKEN.split(':')[1], CHAT_ID, 'PINNED TEXT'):
            self.assertNotIn(bad, text)
        self.assertNotIn('PINNED TEXT', all_files_text(self.cfg.state))   # getChat's text is never kept
        # state file: counts only
        st = json.loads((self.cfg.state / 'status-board.json').read_text())
        self.assertEqual(st['counts']['calls'], {'TG': 2, 'docs': 1, 'mail': 1, 'LLM': 1, 'raw': 1})
        self.assertNotIn(BOT_TOKEN, json.dumps(st))
        # health problems colour the dot; alerts are counted
        self.assertTrue(b.render(board_snap(llm='down'))[0].startswith('🔴 Idle'))
        body = b.render(board_snap(gmail_watch='reconnecting', alerts=2))[0]
        self.assertTrue(body.startswith('🟡 Idle'), body)
        self.assertIn('Gmail ⚠️', body)
        self.assertIn('⚠️ 2 open alerts', body)
        body = b.render(board_snap(gmail_configured=False, tg_live='waiting', paperless=False))[0]
        self.assertIn('✉️ Mail: 4 new', body)                            # not set up any more, but mail came today
        self.assertIn('TG live ⏸ · Gmail ➖ · Paperless ➖', body)
        body = b.render(board_snap(finance_busy='import', gmail_check=True, tg_sync=True))[0]
        self.assertTrue(body.startswith('🟢 Firefly import · Syncing Telegram (+1)'), body)
        # midnight Zurich: a new day starts at zero
        self.clock.t += 86400
        body = b.render(board_snap())[0]
        self.assertIn('🤖 Claude: 0 requests', body)
        self.assertIn('🔐 Raw: 0 asked · ✅ 0 · ❌ 0', body)
        self.assertIn('💬 Telegram: 0 new', body)
        self.assertIn('✉️ Mail: not set up', b.render(board_snap(gmail_configured=False))[0])

    def test_off_without_the_vaults_own_bot(self):
        b = self.make(enabled=lambda: (False, 'only with the vault\'s own bot (vault bot: shared)'))
        self.assertEqual(b.step(), 'off')
        self.assertEqual(self.tg.calls, [])
        self.assertEqual(b.status()['state'], 'off')


class ApiBoardTests(ApiBase):
    """The board wired into the app: API calls and raw requests counted, GET /status, off in the wrong setups."""
    name = 'api-board'

    def test_wiring_counts_and_status(self):
        TELEGRAM.reset()
        app = self.app
        self.assertEqual(app.board.step(), 'off')                        # no telegram secret / bot not polling
        self.assertIn('vault bot', app.board.status()['detail'])
        app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        app.approval.state = 'polling'
        st, r = self.call('POST', '/llm/run', {'args': ['--summary'], 'text': 'hello'})
        self.assertEqual(st, 200, r)
        st, r = self.call('POST', '/raw/request', {'source': 'test', 'reason': 'board test'})
        self.assertEqual(st, 200, r)
        self.call('GET', '/status')
        self.call('GET', '/status', token='wrong')
        self.assertEqual(app.board.step(), 'created')
        text = TELEGRAM.sent[-1]['text']
        self.assertTrue(text.startswith('🟢 Waiting for your code: raw text (test), 14 min left'), text)
        self.assertIn('🤖 Claude: 2 requests (LLM 1 · raw 1)', text)
        self.assertIn('🔐 Raw: 1 asked · ✅ 0 · ❌ 0', text)
        self.assertIn('Paperless ➖', text)
        st, s = self.call('GET', '/status')
        self.assertEqual((s['board']['state'], s['board']['message'], s['board']['pinned']), ('pinned', True, True))
        self.assertNotIn('text', s['board'])
        app.cfg.no_status_board = True
        try:
            self.assertEqual(app.board_enabled(), (False, 'test mode / VAULT_NO_STATUS_BOARD=1'))
        finally:
            app.cfg.no_status_board = False
        app.approval.state = 'shared'
        self.assertFalse(app.board_enabled()[0])
        self.assertEqual(app.board.step(), 'off')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ProcessTests(unittest.TestCase):
    def run_vaultd(self, env, wait_for=None, timeout=20):
        p = subprocess.Popen([sys.executable, '-I', str(ROOT / 'app' / 'vaultd.py')], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        return p

    def test_refusals(self):
        env = make_env('proc-refuse', VAULT_TOKEN_SHA256='', PATH='/usr/bin:/bin')
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'app' / 'vaultd.py')], env=env, capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertIn('VAULT_TOKEN_SHA256', p.stderr)
        cfg = make_cfg('proc-testmode')
        V.SecretStore(cfg).set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        env = make_env('proc-testmode', VAULT_TEST_MODE='1', PATH='/usr/bin:/bin')
        p = subprocess.run([sys.executable, '-I', str(ROOT / 'app' / 'vaultd.py')], env=env, capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertIn('TEST_MODE', p.stderr)

    def test_test_mode_raw_flow_code_only_in_log(self):
        port = free_port()
        env = make_env('proc-smoke', VAULT_TEST_MODE='1', VAULT_PORT=str(port), VAULT_LISTEN='127.0.0.1',
                       PATH='/usr/bin:/bin')
        logf = TMP / 'proc-smoke.log'
        with open(logf, 'w') as lf:
            p = subprocess.Popen([sys.executable, '-I', str(ROOT / 'app' / 'vaultd.py')], env=env, stdout=lf,
                                 stderr=subprocess.STDOUT)
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            base = f'http://127.0.0.1:{port}'
            for _ in range(100):
                try:
                    opener.open(base + '/health', timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)

            def call(path, body=None):
                req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                             headers={'Authorization': f'Bearer {TOKEN}'})
                try:
                    with opener.open(req, timeout=30) as r:
                        return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read())
            st, s = call('/status')
            self.assertEqual((st, s['vault']['test_mode']), (200, True))
            st, r = call('/raw/request', {'source': 'test', 'reason': 'subprocess smoke test'})
            self.assertEqual(st, 200, r)
            time.sleep(0.2)
            code = re.findall(r'Code: (\d{6})', logf.read_text())[-1]
            st, r2 = call('/raw/release', {'request_id': r['request_id'], 'code': code})
            self.assertEqual((st, r2['text']), (200, 'raw-release test OK'))
            st, r3 = call('/raw/release', {'request_id': r['request_id'], 'code': code})
            self.assertEqual((st, r3['code']), (410, 'request_released'))
            st, a = call('/audit?days=1')
            self.assertNotIn(code, json.dumps(a))
            self.assertEqual([e['event'] for e in a['events']], ['raw_request', 'raw_released'])
        finally:
            p.terminate()
            p.wait(10)
        self.assertEqual(p.returncode, 0, logf.read_text())
        log = logf.read_text()
        self.assertIn('shutting down', log)
        # one stderr line per API call (docker logs): the code only in test mode's own notifier line, never in them
        calls = [ln for ln in log.splitlines() if ' api ' in ln and ' -> ' in ln]
        self.assertEqual(len(calls), 5, log)
        self.assertRegex(calls[0], r'^\S+ 127\.0\.0\.1 api GET /status -> 200 \d+(\.\d)? K?B \d+ms$')
        self.assertIn('POST /raw/release request_id=', calls[2])
        self.assertIn('code=(hidden) -> 200', calls[2])
        self.assertIn("| RAW text released (owner-approved)", calls[2])
        self.assertIn(' -> 410 request_released ', calls[3])
        self.assertFalse([ln for ln in calls if code in ln])


@legacy_text
class WatchTests(ApiBase):
    """/watch in the vault's own bot: Claude's API calls, live, in the owner's chat. Off by default,
    owner chat only, batched (one silent message per 5 s), scrubbed like the live view, auto-off, never the console."""
    name = 'api-watch'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app.store.set('paperless', {'url': PAPERLESS.url, 'token': PL_TOKEN})

    def setUp(self):
        super().setUp()
        if not self.app.store.is_set('telegram'):
            self.app.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.app._secret_vals = None
        BOTAPI.reset()
        self.clock = Clock(time.time())               # the live view's own clock is the real one
        self.audit = V.Audit(self.cfg.state / f'watch-{self._testMethodName}.jsonl')
        self.logs = []
        self.wb = self.app.watch                       # the app's own (wired to its tap, scrubber and /status)
        self.assertIsInstance(self.wb, W.WatchBot)
        self.wb.notifier, self.wb.audit, self.wb.clock, self.wb.log = (V.Notifier(self.app.store, BOTAPI.url),
                                                                       self.audit, self.clock, self.logs.append)
        self.wb.pending, self.wb.first_ts, self.wb.last_sent, self.wb.routine, self.wb.routine_sent = [], None, 0, {}, 0

    def tearDown(self):
        self.wb.until = None
        self.app.tap.bot_full_until = self.app.tap.console_full_seen = 0.0
        self.app.tap.sweep_raw()

    def msg(self, text, chat=CHAT_ID, frm=None):
        return {'message_id': 9, 'text': text, 'from': {'id': int(frm or chat)}, 'chat': {'id': int(chat)}}

    def tick(self, secs=0):
        self.clock.t += secs
        return self.wb.tick()

    def search(self, q):
        st, r = self.call('POST', '/tg/search', {'query': q, 'chat': 'Lena', 'n': 5})
        self.assertEqual(st, 200, r)

    def texts(self):
        return [m['text'] for m in BOTAPI.sent]

    def test_off_by_default_nothing_sent_while_off(self):
        self.assertFalse(self.wb.on)                                     # off after every start
        self.assertIs(self.app.approval.watch, self.app.watch)
        self.search('dentist')
        self.assertEqual((self.tick(), self.tick(10), self.tick(3600)), (0, 0, 0))
        self.assertEqual(BOTAPI.calls, [])
        if D.F is not None:                                               # the bank intake answers /help
            self.assertIn('/watch on [full] [30m|2h]', D.F.HELP)        # (private-only, plan D2)

    def test_owner_chat_only(self):
        for m in (self.msg('/watch on', chat='555'), self.msg('/watch on', frm='555'),
                  self.msg('/watch on', chat='-100123', frm=CHAT_ID), self.msg('/status'), self.msg('watch on')):
            self.assertFalse(self.wb.on_message(m), m)                  # not his /watch: finance refuses + audits
        self.assertFalse(self.wb.on)
        self.assertEqual(BOTAPI.calls, [])
        # through the approval bot's poll: a stranger's /watch goes on to finance (refused there), his starts it
        bot = V.ApprovalBot(self.cfg, self.app.store, self.wb.notifier, self.audit, log=lambda m: None,
                            clock=self.clock)
        bot.st['shared_bot_ids'] = []
        fin = []
        bot.watch, bot.finance = self.wb, type('F', (), {'on_message': lambda s, m: fin.append(m)})()
        for chat, text in ((555, '/watch on full'), (int(CHAT_ID), '/watch on full 2h')):
            BOTAPI.uid += 1
            BOTAPI.updates.append({'update_id': BOTAPI.uid, 'message': {
                'message_id': 5, 'text': text, 'from': {'id': chat}, 'chat': {'id': chat}}})
        self.assertEqual(bot.step(), 0)
        self.assertEqual([m['text'] for m in fin], ['/watch on full'])
        self.assertTrue(self.wb.on and self.wb.full)
        self.assertEqual(self.wb.until - self.clock.t, 7200)
        on = BOTAPI.sent[-1]
        self.assertEqual((on['chat_id'], on['protect_content']), (CHAT_ID, 'true'))
        self.assertNotIn('disable_notification', on)                     # the answer to his command notifies
        self.assertIn('Watch on (full: with what Claude got) for 120 min', on['text'])

    def test_batching_silent_one_message_per_call(self):
        """One message per call, at once; more than 3 calls within 5 s: the rest go out together, every 5 s."""
        self.wb.on_message(self.msg('/watch on'))
        n0 = len(BOTAPI.sent)
        self.search('a')
        self.search('b')
        self.assertEqual(self.tick(), 2)                                 # one message per call, at once
        self.assertEqual(len(BOTAPI.sent), n0 + 2)
        m = BOTAPI.sent[-1]
        self.assertEqual((m['chat_id'], m['disable_notification'], m['protect_content'], m['parse_mode']),
                         (CHAT_ID, 'true', 'true', 'HTML'))
        self.assertRegex(BOTAPI.sent[-2]['text'], r"^\d\d:\d\d:\d\d 🔎 search Telegram · 'a' · chat Lena · n 5 "
                                                  r"→ ⚠️ exit 2 · \d+\.\d s$")      # one plain line
        self.assertNotIn('Claude got', m['text'])                        # without full: no bodies
        self.search('c')
        self.assertEqual(self.tick(1), 1)                                # the third call within 5 s: still alone
        self.search('d')
        self.search('e')
        self.assertEqual((self.tick(1), self.tick(4)), (0, 0))           # 5 calls within 5 s: d and e wait
        self.assertEqual(self.tick(1), 1)                                # ... and go out together
        t = BOTAPI.sent[-1]['text']
        self.assertEqual((t.count('search Telegram'), "'d'" in t, "'e'" in t, t.count('\n')), (2, True, True, 1), t)
        self.search('f')
        self.assertEqual(self.tick(1), 1)                                # calm again: alone, at once
        self.assertIn("'f'", BOTAPI.sent[-1]['text'])
        # many big bodies (full): what does not fit waits for the next message, 5 s later
        self.wb.on_message(self.msg('/watch on full'))
        for i in range(4):
            self.app.record_call('127.0.0.1', 'api', 'POST', '/tg/summarize', {}, {'chat': f'c{i}'}, 200,
                                 {'stdout': f'summary {i} ' + 'y' * 3000, 'stderr': '', 'exit_code': 0}, 3100, 900)
        n1 = len(BOTAPI.sent)
        self.assertEqual((self.tick(), self.tick(5), self.tick(1), self.tick(3), self.tick(1)), (0, 1, 0, 0, 1))
        self.assertEqual(len(BOTAPI.sent), n1 + 2)
        self.assertTrue(all(len(t) <= 4000 for t in self.texts()))
        self.assertEqual(sum(len(re.findall(r'💬 Telegram digest · chat c\d', t)) for t in self.texts()[-2:]), 4)
        self.assertIn('\n\n━━━━━━━━\n\n', BOTAPI.sent[-1]['text'])

    def test_full_blocks_scrubbed_and_console_never_shown(self):
        self.app.raw.create('secret-rotate', 'telegram', 'rotate', None, kind='secret', meta={'name': 'telegram'})
        code = TELEGRAM.last_code()                                      # a live raw code
        self.wb.on_message(self.msg('/watch on full 30m'))
        body = {'output': f'token {BOT_TOKEN} code {code[:3]} {code[3:]} ' + 'x' * 3000, 'exit_code': 0}
        self.app.record_call('127.0.0.1', 'api', 'POST', '/llm/run', {}, {'text': 'hello'}, 200, body, 3100, 1234)
        self.app.record_call('127.0.0.1', 'console', 'GET', '/secrets', {}, None, 200, {'names': ['x']}, 10, 2)
        self.app.record_call('127.0.0.1', 'api', 'POST', '/raw/request', {}, {'source': 'tg', 'query': 'q',
                             'reason': 'r'}, 200, {'request_id': 'r1', 'status': 'pending'}, 60, 20)
        self.assertEqual(self.tick(), 2)                                 # two calls of Claude's: two messages
        t, t2 = self.texts()[-2:]
        self.assertNotIn(BOT_TOKEN, t)
        self.assertNotIn(code[:3] + ' ' + code[3:], t)
        self.assertIn('token <b>[secret]</b> code <b>[code]</b> ', t)     # placeholders stand out
        self.assertRegex(t, r"^\d\d:\d\d:\d\d 🧠 LLM on Claude's own text → ✅ done · 1\.2 s · nothing hidden\n\n"
                            r"<b>Claude got</b>\n<blockquote expandable>output: token ")   # no Original, no JSON
        self.assertNotIn('<b>Original</b>', t)
        self.assertRegex(t, r'\n…\(\d+ more chars\)</blockquote>$')
        self.assertRegex(t2, r"^\d\d:\d\d:\d\d 🔐 text request · 'q' → waiting for your ✅ · 0\.0 s\n\n"
                             r"<b>Claude got</b>\n<blockquote expandable>request_id: r1\nstatus: pending</blockquote>$")
        self.assertNotIn('secrets', t + t2)                              # the owner's console calls never show
        self.assertLess(len(t), 3900)
        self.assertNotIn(code[:3] + ' ' + code[3:], ' '.join(self.logs))

    def get_doc(self, doc_id, **kw):
        st, r = self.call('POST', '/paperless/suggest', {'id': doc_id, **kw})
        self.assertEqual(st, 200, r)
        return r

    def last_event(self, path):
        return [e for e in self.app.tap.raw_since(0) if e['path'] == path][-1]

    def test_raw_only_while_a_full_watch_runs(self):
        self.get_doc(7)                                                  # no watch: no RAW anywhere
        self.assertIsNone(self.last_event('/paperless/suggest')['raw_in'])
        self.wb.on_message(self.msg('/watch on'))                        # compact watch: still none
        self.get_doc(7)
        self.assertIsNone(self.last_event('/paperless/suggest')['raw_in'])
        self.assertEqual(self.app.tap.raw_kept, 0)
        self.wb.on_message(self.msg('/watch on full'))
        r = self.get_doc(7)
        ev = self.last_event('/paperless/suggest')
        self.assertIn('── Paperless document 7 ──\nKrankenkasse Muster AG', ev['raw_in'])
        self.assertIn('Herzschmerz', ev['raw_in'])                       # RAW: what went in, for the owner only
        self.assertNotIn('Herzschmerz', json.dumps(r))                   # the response stays anonymized
        self.assertEqual(self.app.tap.raw_kept, 1)
        self.assertEqual(self.tick(), 1)
        t = BOTAPI.sent[-1]['text']
        self.assertRegex(t, r'^\d\d:\d\d:\d\d 📄 Paperless suggestions · id 7 → ✅ done · [\d.]+ s · nothing hidden\n\n'
                            r'<b>Original</b>\n<blockquote expandable>'
                            r'Krankenkasse Muster AG[^\n]*\n(.|\n)*</blockquote>\n\n<b>Claude got</b>\n<blockquote expandable>')
        self.assertNotIn('── Paperless document 7 ──', t)                # no internal markers in the bot's view
        self.assertLess(t.index('<b>Original</b>'), t.index('<b>Claude got</b>'))
        self.wb.on_message(self.msg('/watch off'))                       # off: the buffer keeps no RAW text
        self.assertEqual(self.app.tap.raw_kept, 0)
        self.assertTrue(all(e['raw_in'] is None for e in self.app.tap.raw_since(0)))
        # an attached vault-console watch --full captures too, until it stops polling
        ApiLiveViewTests.console(self, 'GET', '/console/events?last=1&full=1')
        self.get_doc(7)
        self.assertIsNotNone(self.last_event('/paperless/suggest')['raw_in'])
        self.app.tap.console_full_seen -= 40                             # the console went away
        self.app.tap.sweep_raw()
        self.assertEqual(self.app.tap.raw_kept, 0)
        self.get_doc(7)
        self.assertIsNone(self.last_event('/paperless/suggest')['raw_in'])

    def test_raw_never_reachable_by_the_api_token(self):
        mark = '+41 78 ' + '555 66 77'                                   # masked by every filter: only RAW has it
        PAPERLESS.docs[77] = dict(PAPERLESS.docs[8], id=77, content=f'Rueckruf {mark} wegen Herzschmerz und Termin')
        lines = []
        D.log = lines.append
        try:
            self.wb.on_message(self.msg('/watch on full'))
            self.get_doc(77)
            self.assertIn(mark, self.last_event('/paperless/suggest')['raw_in'])
            st, r = self.call('GET', '/console/events?last=50&full=1')   # the console's route: not for the token
            self.assertEqual(st, 404, r)
            seen = []
            for method, path in D.App.ROUTES:
                if method != 'GET' or path == '/console/events':
                    continue
                st, r = self.call('GET', path)
                seen.append(path)
                self.assertNotIn(mark, json.dumps(r), path)
            for path, body in (('/tg/events', None), ('/events', None)):
                self.assertNotIn(mark, json.dumps(self.call('GET', path)[1]), path)
            self.assertIn('/status', seen)
            st, r = self.call('GET', '/status')
            self.assertEqual((r['watch']['on'], r['watch']['full'], r['watch']['raw_kept']), (True, True, 1))
            self.assertNotIn(mark, '\n'.join(lines))                     # not in the vault log
            self.assertNotIn(mark, all_files_text(self.cfg.data))        # never on disk (audit, caches, state)
        finally:
            D.log = lambda msg: None
            PAPERLESS.docs.pop(77, None)

    def test_raw_scrubbed_and_console_layout(self):
        self.app.raw.create('secret-rotate', 'telegram', 'rotate', None, kind='secret', meta={'name': 'telegram'})
        code = TELEGRAM.last_code()
        PAPERLESS.docs[78] = dict(PAPERLESS.docs[8], id=78, content=(
            f'bot {BOT_TOKEN}\nlink https://pay.example.ch/x?token=abcDEF123456&id=5\nYour verification code is '
            f'482913\nvault code {code}\n' + 'Zeile mit Inhalt\n' * 900))
        try:
            ApiLiveViewTests.console(self, 'GET', '/console/events?last=1&full=1')
            self.get_doc(78, chars=12000)
            raw = self.last_event('/paperless/suggest')['raw_in']
            for bad in (BOT_TOKEN, 'abcDEF123456', '482913', code):
                self.assertNotIn(bad, raw)
            self.assertIn('bot [secret]', raw)
            self.assertIn('?token=[token]&id=5', raw)
            self.assertIn('verification code is [code]', raw)
            out = []
            rc = D.console_watch(lambda m, p, b=None: ApiLiveViewTests.console(self, m, p, b)[1], full=True,
                                 out=out.append, max_polls=1)
            self.assertEqual(rc, 0)
            block = [o for o in out if 'Paperless suggest id=78' in o]
            self.assertTrue(block, [o[:200] for o in out])
            block = block[-1]
            self.assertRegex(block, r'^━━━━ \d\d:\d\d:\d\d ━━━━\nREQUEST\n    Paperless suggest id=78, chars=12000\n\n'
                                    r'RAW · what went in\n    ── Paperless document 78 ──\n    bot \[secret\]\n')
            raw_part = block.split('RAW · what went in\n')[1].split('\n\nRESPONSE · what Claude got\n')[0]
            raw_part = '\n'.join(ln[4:] for ln in raw_part.split('\n'))
            self.assertTrue(8100 < len(raw_part) < 8192 + 30, len(raw_part))      # the console: 8 KB per part
            self.assertRegex(raw_part, r'\n…\(\d+ more chars\)$')
            # the bot: ~1200 per part
            self.wb.on_message(self.msg('/watch on full'))
            self.get_doc(78)
            self.assertEqual(self.tick(), 1)
            t = BOTAPI.sent[-1]['text']
            part = html.unescape(t.split('<b>Original</b>\n<blockquote expandable>')[1].split('</blockquote>')[0])
            self.assertTrue(1200 <= len(part) < 1260, len(part))
            self.assertRegex(part, r'\n…\(\d+ more chars\)$')
            self.assertIn('?token=[token]&amp;id=5', t)                     # escaped for parse_mode HTML
        finally:
            PAPERLESS.docs.pop(78, None)

    def test_telegram_raw_reread_only_in_a_full_watch(self):
        calls, real = [], self.app.tg._exec
        mark = '+41 78 ' + '555 66 77'

        def fake(argv, timeout, **kw):
            calls.append(list(argv))
            if '--raw' in argv:
                return 0, ('RAW OUTPUT (exact text, unmasked): only for an exact quote the owner explicitly asked '
                           f'for; never forward it.\n[2026-10-12 18:02] Lena Muster in Grouptrip: Treffpunkt Bahnhof '
                           f'07:30, Tel {mark}\n'), ''
            return 0, '[2026-10-12 18:02] Person A in Grouptrip: Treffpunkt Bahnhof 07:30, Tel [PHONE]\n', ''
        self.app.tg._exec = fake
        try:
            self.assertEqual(self.call('POST', '/tg/search', {'query': 'Treffpunkt', 'n': 3})[0], 200)
            self.assertFalse([c for c in calls if '--raw' in c])                # no full watch: no re-read
            self.assertIsNone(self.last_event('/tg/search')['raw_in'])
            self.wb.on_message(self.msg('/watch on full'))
            st, r = self.call('POST', '/tg/search', {'query': 'Treffpunkt', 'n': 3})
            self.assertEqual(st, 200, r)
            self.assertNotIn('Lena Muster', json.dumps(r))
            self.assertNotIn(mark, json.dumps(r))
            self.assertEqual(calls[-1][0], 'search')
            self.assertIn('--raw', calls[-1])
            self.assertNotIn('--raw', calls[-2])
            raw = self.last_event('/tg/search')['raw_in']
            self.assertTrue(raw.startswith('── Telegram search (re-read) ──\n[2026-10-12 18:02] Lena Muster in '
                                           'Grouptrip: Treffpunkt Bahnhof 07:30, Tel '), raw)
            self.assertNotIn('RAW OUTPUT', raw)
            self.call('POST', '/tg/summarize', {'hours': 24, 'chat': 'Grouptrip'})     # its window, one chat
            self.assertEqual((calls[-1][0], '--raw' in calls[-1]), ('recent', True))
            self.assertIn('Grouptrip', ' '.join(calls[-1]))
            self.call('POST', '/tg/summarize', {'hours': 24})                         # all chats
            self.assertEqual((calls[-1][0], '--raw' in calls[-1], '--include-read' in calls[-1]),
                             ('unread-summary-data', True, True))
            self.tick()
            self.assertRegex('\n'.join(self.texts()), r'\n<b>Original</b>\n<blockquote expandable>Lena Muster in Grouptrip · '
                                                       r'12\.10\.(2026)? 18:02: Treffpunkt Bahnhof 07:30, Tel ')
            self.assertNotIn(mark, '\n'.join(self.logs))
            self.assertNotIn(mark, all_files_text(self.cfg.data))
        finally:
            self.app.tg._exec = real

    def test_routine_polls_only_counted(self):
        self.wb.on_message(self.msg('/watch on'))
        n0 = len(BOTAPI.sent)
        for _ in range(3):
            self.assertEqual(self.call('GET', '/status')[0], 200)
        self.assertEqual((self.tick(), self.tick(5), self.tick(60)), (0, 0, 0))   # routine only: no message yet
        self.search('real')
        self.assertEqual(self.tick(), 1)
        t = BOTAPI.sent[-1]['text']
        self.assertTrue(t.endswith('\n\n<i>+ routine polls: status 3</i>'), t)
        self.assertEqual(t.count('status'), 1, t)
        self.call('GET', '/status')
        self.assertEqual(self.tick(599), 0)                              # routine-only: at most every 10 min
        self.assertEqual(self.tick(1), 1)
        self.assertEqual(BOTAPI.sent[-1]['text'], '<i>+ routine polls: status 1</i>')
        self.assertEqual(len(BOTAPI.sent), n0 + 2)

    def test_commands_auto_off_and_audit(self):
        self.wb.on_message(self.msg('/watch'))
        self.assertIn('/watch on [full] [30m|2h]', BOTAPI.sent[-1]['text'])   # usage while off
        self.wb.on_message(self.msg('/watch@VaultBot on'))
        self.assertEqual((self.wb.until - self.clock.t, self.wb.full), (1800, False))   # default 30 min
        self.wb.on_message(self.msg('/watch'))
        self.assertIn('Watch is on for 30 more min', BOTAPI.sent[-1]['text'])
        self.wb.on_message(self.msg('/watch on 99h'))
        self.assertEqual(self.wb.until - self.clock.t, 12 * 3600)        # at most 12 h
        self.search('pending')
        self.wb.on_message(self.msg('/watch off'))                       # what is pending goes out first
        self.assertIn("search Telegram · 'pending'", BOTAPI.sent[-2]['text'])
        self.assertEqual(BOTAPI.sent[-1]['text'], '👁 Watch off.')
        self.assertFalse(self.wb.on)
        # auto-off: the last batch, then "ended"; nothing after that
        self.wb.on_message(self.msg('/watch on 1m'))
        self.search('late')
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.tick(60), 0)
        self.assertFalse(self.wb.on)
        self.assertIn("'late'", BOTAPI.sent[-2]['text'])
        self.assertEqual(BOTAPI.sent[-2]['disable_notification'], 'true')
        self.assertIn('Watch ended (time is up)', BOTAPI.sent[-1]['text'])
        self.assertNotIn('disable_notification', BOTAPI.sent[-1])
        n = len(BOTAPI.sent)
        self.search('after')
        self.assertEqual((self.tick(5), self.tick(30)), (0, 0))
        self.assertEqual(len(BOTAPI.sent), n)
        recs = [json.loads(ln) for ln in self.audit.path.read_text().splitlines()]
        self.assertEqual([(r['event'], r.get('why'), r.get('minutes')) for r in recs],
                         [('watch_on', None, 30), ('watch_on', None, 720), ('watch_off', 'owner', None),
                          ('watch_on', None, 1), ('watch_off', 'timeout', None)])
        self.assertNotIn('pending', self.audit.path.read_text())        # no content in the audit

    def test_forgiving_commands_state_and_buttons(self):
        """Regression: the help text came 4x for '/watch', '/watch full', '/watch: state', '/watch: full'."""
        def state_msg():
            m = BOTAPI.sent[-1]
            kb = json.loads(m['reply_markup'])['inline_keyboard']
            return m['text'], [(b['text'], b['callback_data']) for row in kb for b in row]
        want = [('Watch 30 min', 'w:on:30'), ('Watch full 30 min', 'w:full:30'), ('Full 2 h', 'w:full:120'),
                ('Off', 'w:off')]
        for cmd in ('/watch', '/watch:', '/watch: state', '/watch status', '/watch state:', '/watch bogus 7'):
            self.assertTrue(self.wb.on_message(self.msg(cmd)), cmd)
            self.assertFalse(self.wb.on, cmd)
            text, kb = state_msg()
            self.assertTrue(text.startswith('👁 Watch is off.\n/watch on [full] [30m|2h]'), (cmd, text))
            self.assertEqual(kb, want, cmd)
            self.assertNotIn('disable_notification', BOTAPI.sent[-1])
        self.assertTrue(self.wb.on_message(self.msg('/watch: full')))      # full = on full, default 30 min
        self.assertEqual((self.wb.on, self.wb.full, self.wb.until - self.clock.t), (True, True, 1800))
        self.assertGreater(self.app.tap.bot_full_until, self.clock.t)
        self.wb.on_message(self.msg('/watch full 2h'))
        self.assertEqual((self.wb.full, self.wb.until - self.clock.t), (True, 7200))
        self.wb.on_message(self.msg('/Watch@VaultBot: state'))
        text, kb = state_msg()
        self.assertTrue(text.startswith('👁 Watch is on (full) for 120 more min.'), text)
        self.assertEqual(kb, want)
        self.wb.on_message(self.msg('/watch on: 2h'))
        self.assertEqual((self.wb.full, self.wb.until - self.clock.t), (False, 7200))
        self.wb.on_message(self.msg('/watch off.'))
        self.assertFalse(self.wb.on)
        self.assertEqual(self.app.tap.bot_full_until, 0.0)
        for other in ('/watchdog', '/watch-x on', '/status', 'watch on'):  # not /watch: on to finance
            self.assertFalse(self.wb.on_message(self.msg(other)), other)
        self.assertFalse(self.wb.on_message(self.msg('/watch: full', chat='555')))
        self.assertFalse(self.wb.on)
        # the buttons, through the approval bot's poll: his presses count, a stranger's never
        bot = V.ApprovalBot(self.cfg, self.app.store, self.wb.notifier, self.audit, log=lambda m: None,
                            clock=self.clock)
        bot.st['shared_bot_ids'] = []
        bot.watch, bot.finance = self.wb, None
        self.addCleanup(lambda: (bot.st.pop('offsets', None), bot._save()))   # the poll offset is saved state
        BOTAPI.press('w:full:30', 101, chat='555')
        BOTAPI.press('w:full:30', 101, chat=CHAT_ID, frm='555')
        self.assertEqual(bot.step(), 0)
        self.assertFalse(self.wb.on)
        self.assertEqual(BOTAPI.method_calls('answerCallbackQuery'), [])
        BOTAPI.press('w:full:120', 101)
        bot.step()
        self.assertEqual((self.wb.on, self.wb.full, self.wb.until - self.clock.t), (True, True, 7200))
        self.assertEqual(BOTAPI.method_calls('answerCallbackQuery')[-1]['text'], 'Watch full on for 120 min ✓')
        self.assertIn('Watch on (full: with what Claude got) for 120 min', BOTAPI.sent[-1]['text'])
        BOTAPI.press('w:on:30', 101)
        bot.step()
        self.assertEqual((self.wb.on, self.wb.full, self.app.tap.bot_full_until), (True, False, 0.0))
        BOTAPI.press('w:on:999', 101)                                    # capped like typed durations
        bot.step()
        self.assertEqual(self.wb.until - self.clock.t, 720 * 60)
        BOTAPI.press('w:bogus', 101)
        bot.step()
        self.assertEqual(BOTAPI.method_calls('answerCallbackQuery')[-1]['text'], 'Unknown button')
        BOTAPI.press('w:off', 101)
        bot.step()
        self.assertFalse(self.wb.on)
        self.assertEqual(BOTAPI.method_calls('answerCallbackQuery')[-1]['text'], 'Watch off ✓')
        recs = [json.loads(ln)['event'] for ln in self.audit.path.read_text().splitlines()]
        self.assertEqual(recs.count('raw_callback_refused'), 2)          # the stranger's presses, audited
        self.assertEqual(recs.count('watch_on'), 6)

    def test_readable_lines_no_json_scrubbed_and_progress_edited(self):
        """Readability (JSON-formatted lines were hard to follow): one plain line per call with an
        emoji and a verb, HH:MM:SS, no JSON or dict dumps, formatted after the scrub (a secret value in a parameter
        still comes out as [secret]); compact shows enums, dates and counts, never names or text; LLM busy / job
        progress polls are one line edited in place until another line goes out."""
        self.wb.on_message(self.msg('/watch on'))
        n0 = len(BOTAPI.sent)
        ask = {'source': 'tg', 'query': 'Wochenende', 'since': '30d', 'kind': 'yesno', 'session': True,
               'question': 'Are there plans for this weekend?', 'chat': BOT_TOKEN}
        body = {'source': 'telegram', 'query': 'Wochenende', 'kind': 'yesno', 'question': ask['question'],
                'messages': 20, 'parts': 1, 'dropped': 0, 'today': '2026-10-15',
                'asked': {'label': 'this weekend', 'from': '2026-10-17', 'to': '2026-10-18'},
                'answer': {'answer': 'no', 'date': '2026-10-10', 'timing': 'past', 'relative': 'last weekend',
                           'in_window': False, 'refs': ['#201']},
                'session': {'id': 's-abcdefgh', 'turns_left': 5, 'expires': '2026-10-15T00:20:00+02:00'}}
        self.app.record_call('127.0.0.1', 'api', 'POST', '/answer', {}, ask, 200, body, 700, 14_200)
        self.app.record_call('127.0.0.1', 'api', 'POST', '/answer', {}, {'session': 's-abcdefgh', 'question': 'wo?'},
                             200, {'kind': 'when', 'turn': 2, 'messages': 20, 'dropped': 1,
                                   'answer': {'date': '2026-10-10', 'venue': 'Cannstatter Wasen', 'who': ['Marco']},
                                   'session': {'id': 's-abcdefgh', 'turns_left': 4}}, 300, 9_000)
        self.app.record_call('127.0.0.1', 'api', 'POST', '/raw/request', {}, {'source': 'tg', 'query': 'q',
                             'reason': 'r'}, 200, {'request_id': 'r1', 'status': 'pending'}, 60, 20)
        self.assertEqual(self.tick(), 3)
        a, f, r = self.texts()[-3:]
        self.assertRegex(a, r"^\d\d:\d\d:\d\d 🔎 ask tg · 'Wochenende' · chat \[secret\] · yesno · 30d · new session → "
                            r"✅ answer: no 2026-10-10 \(past\) last weekend ⚠️ not on the asked days · 20 msgs, "
                            r"0 dropped · 14 s$")
        self.assertRegex(f, r"^\d\d:\d\d:\d\d ↪️ follow-up 2/6 · when → ✅ answer: 2026-10-10 · place ✓ · 20 msgs, 1 dropped · "
                            r"9\.0 s$")
        self.assertRegex(r, r"^\d\d:\d\d:\d\d 🔐 text request · 'q' → waiting for your ✅ · 0\.0 s$")
        for t in (a, f, r):
            self.assertNotRegex(t, r'[{}]|"\w+":|\w="')                # no JSON, no dict dumps, no k="v"
            self.assertEqual(t.count('\n'), 0, t)                       # one line per call
            for txt in ('Cannstatter', 'Marco', 'Are there plans', BOT_TOKEN):
                self.assertNotIn(txt, t)                               # compact: no names, text or secrets
        # progress: one line, edited in place
        job = {'id': 'abcd1234', 'op': 'answer', 'state': 'running', 'elapsed_s': 14,
               'progress': {'done': 0, 'total': 2, 'step': 'answer part 1/2'}}
        self.app.record_call('127.0.0.1', 'api', 'GET', '/jobs/abcd1234', {}, None, 200, job, 120, 3)
        self.assertEqual(self.tick(1), 0)
        self.assertRegex(BOTAPI.sent[-1]['text'], r'^\d\d:\d\d:\d\d ⏳ job abcd1234 running · answer part 1/2 · 14 s$')
        sent, e0 = len(BOTAPI.sent), len(BOTAPI.method_calls('editMessageText'))
        self.app.record_call('127.0.0.1', 'api', 'GET', '/status', {}, None, 200,
                             {'vault': {'version': 'x'}, 'llm': {'busy_with': 'answer yesno (tg, part 2/2)',
                              'queue': {'running': {'what': 'answer yesno (tg, part 2/2)', 'class': 'live',
                                                    'elapsed_s': 29, 'eta_s': None}, 'queue': []}}}, 400, 2)
        self.tick(1)
        edits = BOTAPI.method_calls('editMessageText')
        self.assertEqual((len(BOTAPI.sent), len(edits) - e0), (sent, 1))      # edited, not a new message
        self.assertEqual(int(edits[-1]['message_id']), 100 + sent)
        self.assertRegex(edits[-1]['text'], r'^\d\d:\d\d:\d\d 🧠 LLM busy: answer yesno \(tg, part 2/2\) · 29 s$')
        self.app.record_call('127.0.0.1', 'api', 'POST', '/raw/request', {}, {'source': 'tg', 'query': 'q2',
                             'reason': 'r'}, 200, {'request_id': 'r2', 'status': 'pending'}, 60, 20)
        self.assertEqual(self.tick(6), 1)                                # calm again (no 4 calls within 5 s)
        self.app.record_call('127.0.0.1', 'api', 'GET', '/jobs/abcd1234', {}, None, 200, dict(job, elapsed_s=44), 120, 3)
        self.tick(1)
        self.assertEqual(len(BOTAPI.sent), sent + 2)                     # after another line: a new progress line
        self.assertIn('· 44 s', BOTAPI.sent[-1]['text'])
        self.assertEqual(len(BOTAPI.sent) - n0, 6)
        self.assertNotIn(BOT_TOKEN, json.dumps(BOTAPI.calls))
        self.app.record_call('127.0.0.1', 'api', 'GET', '/status', {}, None, 200, {'llm': {'queue': {}}}, 40, 2)
        self.tick(1)
        self.assertEqual(self.wb.routine.get('status'), 1)                  # an idle /status poll stays routine
        # full: Claude got as plain key: value lines, still scrubbed
        self.wb.on_message(self.msg('/watch on full'))
        self.app.record_call('127.0.0.1', 'api', 'POST', '/answer', {}, ask, 200, dict(body, note=f'x {BOT_TOKEN}'),
                             700, 14_200)
        self.tick()
        t = BOTAPI.sent[-1]['text']
        self.assertIn('<b>Claude got</b>\n<blockquote expandable>source: telegram\n', t)
        self.assertIn('answer:\n  answer: no\n  date: 2026-10-10\n', t)
        self.assertIn('note: x <b>[secret]</b>', t)
        self.assertNotRegex(t, r'[{}]|"\w+":')
        self.assertNotIn(BOT_TOKEN, t)

    def test_html_layout_readable_and_escaped(self):
        """Readability: emoji header, bold section titles, expandable quotes, one line per
        message without ### headers, refs or footers, placeholders in bold, the hidden line in italics; all escaped."""
        self.wb.on_message(self.msg('/watch on full'))
        out = ('### Grouptrip <Team> (group, chat -1000000000123)\n'
               '[2026-10-12 18:02] Lena & Co: Treffpunkt <Bahnhof> 07:30, Tel [phone] [private: health] '
               '(#123 reply to #120)  <== match\n'
               '    zweiti Zeile <b>nöd fett</b> (#124)\n'
               '(private passages and identifiers removed by the local LLM; names and addresses kept as written. '
               'Regex masks applied before and after.)')
        raw = {'parts': [('Telegram search (re-read)', '### Grouptrip <Team> (group, chat -1000000000123)\n'
                          '[2026-10-12 18:02] Lena Muster: Treffpunkt <Bahnhof> & mehr 07:30 (#123)')], 'total': 120}
        self.app.record_call('127.0.0.1', 'api', 'POST', '/tg/search', {}, {'query': 'Treff & <x>', 'n': 3}, 200,
                             {'stdout': out, 'stderr': '', 'exit_code': 0}, 900, 35_400, raw_in=raw)
        self.assertEqual(self.tick(), 1)
        m = BOTAPI.sent[-1]
        t = m['text']
        self.assertEqual(m['parse_mode'], 'HTML')
        day = r'12\.10\.(2026)? 18:02'
        self.assertRegex(t, r"^\d\d:\d\d:\d\d 🔎 search Telegram · 'Treff &amp; &lt;x&gt;' · n 3 → ✅ done · 35 s · "
                            r"🙈 hidden: 1 health passage · 1 phone number\n\n"
                            r"<b>Original</b>\n<blockquote expandable>▸ Grouptrip &lt;Team&gt;\n"
                            r"Lena Muster · " + day + r": Treffpunkt &lt;Bahnhof&gt; &amp; mehr 07:30</blockquote>\n\n"
                            r"<b>Claude got</b>\n<blockquote expandable>▸ Grouptrip &lt;Team&gt;\n"
                            r"Lena &amp; Co · " + day + r": Treffpunkt &lt;Bahnhof&gt; 07:30, Tel <b>\[phone\]</b> "
                            r"<b>\[private: health\]</b> / zweiti Zeile &lt;b&gt;nöd fett&lt;/b&gt;</blockquote>$")
        for noise in ('###', '(#123', '#124', '<== match', 'local LLM', 'chat -1000000000123'):
            self.assertNotIn(noise, t)
        tags = re.findall(r'<[^>]*>', t)                                 # only Telegram's tags, balanced
        self.assertTrue(set(tags) <= {'<b>', '</b>', '<i>', '</i>', '<blockquote expandable>', '</blockquote>'}, tags)
        for a, b in (('<b>', '</b>'), ('<i>', '</i>'), ('<blockquote expandable>', '</blockquote>')):
            self.assertEqual(tags.count(a), tags.count(b), a)
        rest = re.sub(r'<(/?)(b|i|blockquote)( expandable)?>', '', t)
        self.assertNotRegex(rest, r'[<>]|&(?!amp;|lt;|gt;)')                # nothing unescaped is left
        self.assertEqual(W.plain(t).count('<Bahnhof>'), 2)                 # the plain-text fallback reads right
        # a part longer than ~1200 characters is cut before escaping (no entity or tag cut in half)
        self.app.record_call('127.0.0.1', 'api', 'POST', '/tg/recent', {}, {'chat': 'x'}, 200,
                             {'stdout': '[2026-10-12 18:02] A: ' + '<&> ' * 900, 'stderr': '', 'exit_code': 0},
                             3700, 1000)
        self.assertEqual(self.tick(1), 1)
        got = BOTAPI.sent[-1]['text'].split('<b>Claude got</b>\n<blockquote expandable>')[1].split('</blockquote>')[0]
        self.assertTrue(1200 <= len(html.unescape(got)) < 1260, len(html.unescape(got)))
        self.assertRegex(got, r'(&lt;|&amp;|&gt;)\n…\(\d+ more chars\)$')          # whole entities only
        # compact: the header, the other parameters, the hidden line
        self.wb.on_message(self.msg('/watch on'))
        self.app.record_call('127.0.0.1', 'api', 'POST', '/gmail/search', {}, {'q': 'Rechnung', 'n': 2}, 200,
                             {'count': 1, 'results': [{'from': 'Shop (shop.ch)', 'date': '2026-10-12T09:00:00+02:00',
                              'subject': 'Ihre Rechnung', 'snippet': 'Total [amount]', 'attachments': []}]}, 300, 2000)
        self.assertEqual(self.tick(1), 1)
        self.assertRegex(BOTAPI.sent[-1]['text'], r"^\d\d:\d\d:\d\d 📧 search Gmail · 'Rechnung' · n 2 → ✅ 1 mail\(s\) · "
                                                  r"2\.0 s · 🙈 hidden: 1 amount$")


# ============================================================================================ async jobs (plan v2 #4)

class JobsTests(unittest.TestCase):
    """app/jobs.py: lifecycle, long polls, expiry, the size cap, coalescing, cancel, refused routes, restarts."""

    def setUp(self):
        self.clock = Clock()
        self.audit = V.Audit(TMP / f'jobs-audit-{self._testMethodName}.jsonl')
        self.gate_ev = threading.Event()
        self.runs = []

    def make(self, run=None, **kw):
        def default(job):
            self.runs.append(job.op)
            if job.params.get('block'):
                self.gate_ev.wait(10)
            return 200, {'exit_code': 0, 'stdout': 'x' * int(job.params.get('size', 10)), 'stderr': ''}
        js = J.Jobs(run or default, self.audit, clock=self.clock, **kw)
        return js

    def wait_state(self, js, jid, state, owner='o'):
        for _ in range(200):
            if js.get(jid, owner)['state'] == state:
                return
            time.sleep(0.02)
        self.fail(f'job never reached {state}')

    def test_lifecycle_long_poll_and_list(self):
        js = self.make()
        t = js.submit('tg.recent', {'chat': 'x', 'block': True}, 'o', ip='203.0.113.2')
        self.assertRegex(t['id'], r'^[0-9a-f]{16}$')
        self.assertIn(t['state'], ('queued', 'running'))
        self.assertFalse(t['coalesced'])
        t0 = time.time()
        v = js.get(t['id'], 'o', wait=0.3)                               # long poll: returns when the wait is over
        self.assertTrue(0.25 <= time.time() - t0 < 2, time.time() - t0)
        self.assertEqual(v['state'], 'running')
        self.assertNotIn('result', v)
        threading.Timer(0.3, self.gate_ev.set).start()
        t0 = time.time()
        v = js.get(t['id'], 'o', wait=10)                                # ... or as soon as the job ends
        self.assertLess(time.time() - t0, 5)
        self.assertEqual((v['state'], v['status'], v['result']['stdout']), ('done', 200, 'x' * 10))
        self.assertEqual(js.list('o')[0]['id'], t['id'])
        self.assertNotIn('result', js.list('o')[0])
        self.assertEqual(js.list('someone else'), [])
        with self.assertRaises(V.VaultError) as e:                       # another token: no such job
            js.get(t['id'], 'p')
        self.assertEqual(e.exception.status, 404)
        ev = [(e['event'], e.get('op')) for e in self.audit.read()]
        self.assertEqual(ev, [('job_submit', 'tg.recent'), ('job_done', 'tg.recent')])
        self.assertNotIn('chat', json.dumps(self.audit.read()))         # ids, op, state, numbers only (G7)

    def test_refused_ops_and_params(self):
        js = self.make()
        for op in ('raw.release', 'raw.request', 'secrets.telegram', 'console.events', 'tg.download', 'tg.purge',
                   'paperless.fields', 'paperless.update', 'media.release', 'gmail.to-paperless', None, 7):
            with self.assertRaises(V.VaultError) as e:
                js.submit(op, {}, 'o')
            self.assertEqual((e.exception.status, e.exception.code), (400, 'bad_op'), op)
        with self.assertRaises(V.VaultError):
            js.submit('tg.search', ['not', 'a', 'dict'], 'o')
        for method, route in J.OPS.values():                             # never a raw, secret, console or write route
            self.assertFalse(route.startswith(J.NEVER), route)
            self.assertEqual(method, 'POST')
        self.assertEqual(self.runs, [])

    def test_coalesce_expiry_and_restart(self):
        js = self.make()
        a = js.submit('tg.summarize', {'hours': 168, 'block': True}, 'o')
        b = js.submit('tg.summarize', {'block': True, 'hours': 168}, 'o')       # same request, other key order
        c = js.submit('tg.summarize', {'hours': 24, 'block': True}, 'o')
        self.assertEqual((b['id'], b['coalesced']), (a['id'], True))
        self.assertNotEqual(c['id'], a['id'])
        self.gate_ev.set()
        self.wait_state(js, a['id'], 'done')
        self.wait_state(js, c['id'], 'done')
        self.clock.t += 60
        self.assertEqual(js.submit('tg.summarize', {'hours': 168, 'block': True}, 'o')['id'], a['id'])  # just ended
        self.clock.t += 61
        d = js.submit('tg.summarize', {'hours': 168, 'block': True}, 'o')                  # older: a new run
        self.assertNotEqual(d['id'], a['id'])
        self.wait_state(js, d['id'], 'done')
        self.clock.t += J.Jobs.TTL + 1                                   # kept 30 min after the end, then gone
        with self.assertRaises(V.VaultError) as e:
            js.get(a['id'], 'o')
        self.assertEqual((e.exception.status, e.exception.code), (404, 'no_such_job'))
        self.assertEqual(self.runs.count('tg.summarize'), 3)
        fresh = self.make()                                              # a restart: memory only, nothing survives
        with self.assertRaises(V.VaultError):
            fresh.get(d['id'], 'o')
        self.assertFalse(any(TMP.glob('**/jobs*.json')))                 # never on disk

    def test_size_cap_and_too_many(self):
        js = self.make()
        js.MAX_BYTES = 3000
        a = js.submit('tg.recent', {'size': 1200}, 'o')
        self.wait_state(js, a['id'], 'done')
        self.clock.t += 1
        b = js.submit('tg.recent', {'size': 1300}, 'o')
        self.wait_state(js, b['id'], 'done')
        self.clock.t += 1
        c = js.submit('tg.recent', {'size': 1400}, 'o')
        self.wait_state(js, c['id'], 'done')
        va = js.get(a['id'], 'o')                                        # the oldest result was dropped
        self.assertEqual((va['state'], va['error']['code']), ('expired', 'result_dropped'))
        self.assertNotIn('result', va)
        self.assertEqual(js.get(c['id'], 'o')['result']['stdout'], 'x' * 1400)
        big = js.submit('tg.recent', {'size': 5000}, 'o')               # one result over the cap: not kept
        self.wait_state(js, big['id'], 'failed')
        self.assertEqual(js.get(big['id'], 'o')['error']['code'], 'too_large')
        js.MAX_ACTIVE = 2
        js.submit('tg.recent', {'block': True, 'n': 1}, 'o')
        js.submit('tg.recent', {'block': True, 'n': 2}, 'o')
        with self.assertRaises(V.VaultError) as e:
            js.submit('tg.recent', {'block': True, 'n': 3}, 'o')
        self.assertEqual((e.exception.status, e.exception.code), (429, 'too_many_jobs'))
        self.gate_ev.set()

    def test_cancel_through_the_gate(self):
        gate = V.LLMGate()
        started = threading.Event()

        def run(job):                                                    # like run_job: the job is the caller
            V.CALLER.alive, V.CALLER.job = job.alive, job.id
            try:
                with gate.use(private=True, what='tgread summarize', cls='bulk'):
                    pass
                return 200, {'ok': True}
            except V.VaultError as e:
                return e.status, {'error': str(e), 'code': e.code}
            finally:
                V.CALLER.alive = V.CALLER.job = None
        js = self.make(run, outlook=gate.outlook)
        hold = threading.Event()

        def busy():
            with gate.use(private=True, what='tgread recent', cls='live'):
                started.set()
                hold.wait(10)
        threading.Thread(target=busy, daemon=True).start()
        started.wait(5)
        t = js.submit('tg.summarize', {'hours': 1}, 'o')
        for _ in range(100):                                             # its LLM step waits behind the running one
            if js.get(t['id'], 'o').get('position') == 1:
                break
            time.sleep(0.02)
        v = js.get(t['id'], 'o')
        self.assertEqual((v['state'], v['position']), ('running', 1))
        self.assertIsInstance(v['eta_s'], int)
        self.assertEqual(js.cancel(t['id'], 'o')['id'], t['id'])
        self.wait_state(js, t['id'], 'cancelled')
        self.assertEqual(js.get(t['id'], 'o')['error']['code'], 'client_gone')
        hold.set()
        self.assertIn('job_cancel', [e['event'] for e in self.audit.read()])


class ChunkedSummaryTests(unittest.TestCase):
    """sources.TG.summarize_chunked: window -> parts (busy chats per day, small ones together) -> one merge."""

    def setUp(self):
        self.cfg = make_cfg(f'chunk-{self._testMethodName}')
        self.policy = V.Policy(self.cfg, V.LLMGate())
        self.tg = S.TG(self.cfg, self.policy, self.policy.gate, V.Audit(self.cfg.audit_path),
                       V.Notifier(V.SecretStore(self.cfg), TELEGRAM.url))
        self.tg.ensure_config = lambda: False
        self.calls, self.fail_part = [], None
        llm_mode('ok')
        now = time.time()
        day = lambda k: (dt.datetime.now(V.TZ) - dt.timedelta(days=k)).date().isoformat()   # noqa: E731
        self.win = {'since': 0, 'until': None, 'span': '', 'sync': 'last sync 2026-10-13 10:00', 'msgs': 0, 'chars': 0,
                    'chats': [
                        {'chat_id': 11, 'msgs': 30, 'chars': 6000, 'first_ts': now - 3600, 'last_ts': now - 60,
                         'days': [{'day': day(0), 'msgs': 30, 'chars': 6000}], 'total': 30, 'unread': 3},
                        {'chat_id': '-1001234567890', 'msgs': 300, 'chars': 30000, 'first_ts': now - 2 * 86400,
                         'last_ts': now - 120, 'days': [{'day': day(2), 'msgs': 100, 'chars': 10000},
                                                        {'day': day(1), 'msgs': 100, 'chars': 10000},
                                                        {'day': day(0), 'msgs': 100, 'chars': 10000}],
                         'total': 300, 'unread': 50},
                        {'chat_id': 33, 'msgs': 2, 'chars': 300, 'first_ts': now - 7200, 'last_ts': now - 3000,
                         'days': [{'day': day(0), 'msgs': 2, 'chars': 300}], 'total': 2, 'unread': 0},
                        {'chat_id': 44, 'msgs': 3, 'chars': 500, 'first_ts': now - 9000, 'last_ts': now - 5000,
                         'days': [{'day': day(0), 'msgs': 3, 'chars': 500}], 'total': 3, 'unread': 1}]}

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            self.calls.append(argv)
            if argv[0] == 'window':
                return 0, json.dumps(self.win), ''
            if argv[0] == 'summarize':
                n = len(self.calls) - 1
                if self.fail_part == n:
                    return 6, '', 'tgread: local LLM unavailable'
                chats = argv[argv.index('--chats') + 1:] if '--chats' in argv else ['?']
                return 0, (f'Summary of {n * 10} message(s) in {len(chats)} chat(s), since 2026-10-11 10:00 '
                           f'(last sync 2026-10-13 10:00):\n\nPART{n} about chats {" ".join(chats)}; call +41 79 '
                           f'123 45 67\n\n(summary by the local LLM from anonymized text; regex masks applied before '
                           f'and after)\n'), ''
            return 2, '', 'unexpected'
        self.tg._exec = fake_exec

    def test_parts_order_progress_partial_and_merge(self):
        rep = []
        r = self.tg.summarize_chunked({'hours': 72, 'per_chat': 60}, report=lambda k, **kw: rep.append((k, kw)))
        self.assertEqual(r['exit_code'], 0, r)
        self.assertEqual(self.calls[0][0], 'window')
        self.assertRegex(' '.join(self.calls[0]), r'--since=@\d+')
        since = int(re.search(r'--since=@(\d+)', ' '.join(self.calls[0]))[1])
        self.assertEqual(since % S.WINDOW_ROUND, 0)                     # rounded: a re-run sends the same text
        parts = [c for c in self.calls if c[0] == 'summarize']
        chats = [c[c.index('--chats') + 1:] for c in parts]
        self.assertEqual(chats, [['11'], ['-1001234567890'], ['-1001234567890'], ['-1001234567890'], ['33', '44']])
        self.assertTrue(all('--no-counts' in c for c in parts))
        busy = parts[1:4]                                                # newest day first, open end; older: --until
        self.assertFalse(any(a.startswith('--until') for a in busy[0]))
        self.assertTrue(all(any(a.startswith('--until=@') for a in c) for c in busy[1:]))
        self.assertTrue(all(c[c.index('--per-chat') + 1] == '0' for c in busy))
        self.assertEqual(parts[0][parts[0].index('--per-chat') + 1], '60')
        steps = [kw['step'] for k, kw in rep if k == 'progress']
        self.assertEqual(steps, ['window'] + [f'part {i}/5' for i in range(1, 6)] + ['merge'])
        partial = [kw['item'] for k, kw in rep if k == 'partial']
        self.assertEqual([p['part'] for p in partial], [1, 2, 3, 4, 5])
        self.assertTrue(all('PART' in p['text'] and '+41 79' not in p['text'] for p in partial))    # filtered
        self.assertNotIn('Summary of', partial[0]['text'])
        merge = llm_calls()[-1]
        self.assertEqual(merge['args'][:3], ['--summary', '--paraphrase', '--system'])
        self.assertEqual(merge['cache'], str(self.cfg.llm_cache))      # a private job: the anonymization cache
        out = r['stdout']
        self.assertRegex(out, r'^Summary of 150 message\(s\) in 4 chat\(s\), last 72 h \(last sync [^)]*; 5 parts '
                              r'merged\):\n')
        self.assertIn('ECHO --summary --paraphrase', out)
        self.assertLess(out.index('PART1'), out.index('PART5'))
        self.assertNotIn('+41 79 123 45 67', out)
        self.assertEqual(r['parts'], 5)

    def test_part_failure_merge_failure_and_small_windows(self):
        self.fail_part = 2
        r = self.tg.summarize_chunked({'hours': 72})
        self.assertEqual(r['exit_code'], 6)
        self.assertIn('part 2/5', r['stderr'])
        self.fail_part, self.calls = None, []
        llm_mode('fail')                                                 # the merge fails: the parts are the answer
        r = self.tg.summarize_chunked({'hours': 72})
        self.assertEqual(r['exit_code'], 0)
        self.assertIn('NOT merged', r['stdout'])
        self.assertIn('merge failed', r['stderr'])
        self.assertEqual(r['stdout'].count('## Part '), 5)
        llm_mode('ok')
        self.win['chats'] = [self.win['chats'][2]]                       # one small chat: one call, no merge
        self.calls = []
        n = len(llm_calls())
        r = self.tg.summarize_chunked({'hours': 24})
        self.assertEqual([c[0] for c in self.calls], ['window', 'summarize'])
        self.assertNotIn('--no-counts', self.calls[1])
        self.assertRegex(r['stdout'], r'^Summary of \d+ message\(s\) in 1 chat\(s\), last 24 h \(last sync')
        self.assertEqual(len(llm_calls()), n)
        self.win['chats'] = []
        r = self.tg.summarize_chunked({'hours': 24})
        self.assertIn('No messages to summarize in the last 24 h', r['stdout'])
        self.calls = []
        self.tg.summarize_chunked({'hours': 24, 'chats': ['33'], 'since': '7d'})   # an explicit window: as asked
        self.assertEqual([c[0] for c in self.calls], ['summarize'])

    def test_plan_parts_packs_quiet_days(self):
        days = ['2026-10-07', '2026-10-08', '2026-10-09', '2026-10-10', '2026-10-11', '2026-10-12', '2026-10-13']
        sizes = [4362, 3880, 3907, 68, 767, 738, 3611]
        c = {'chat_id': '-1001234567890', 'msgs': 70, 'chars': sum(sizes), 'first_ts': 0, 'last_ts': 9, 'unread': 4,
             'days': [{'day': d, 'msgs': 10, 'chars': n} for d, n in zip(days, sizes)]}
        since = int(dt.datetime(2026, 10, 7, 9, 30, tzinfo=V.TZ).timestamp())
        a, b = S.plan_parts({'chats': [c]}, since)                      # 7 days -> 2 parts of whole days
        self.assertEqual((a['label'], b['label']), ('1 chat, 2026-10-09 to 2026-10-13', '1 chat, 2026-10-07 to 2026-10-08'))
        self.assertEqual((a['chars'], b['chars']), (9091, 8242))
        self.assertIsNone(a['until'])                                    # the newest part is open-ended
        self.assertEqual(b['until'], a['since'])                         # contiguous
        self.assertEqual(a['since'], int(dt.datetime(2026, 10, 9, tzinfo=V.TZ).timestamp()))
        self.assertEqual(b['since'], since)                              # the oldest starts with the window
        self.assertEqual((a['unread'], b['unread'], a['per_chat'], a['chats']), (4, 0, 0, [-1001234567890]))

    def test_plan_parts_limits(self):
        chats = [{'chat_id': i, 'msgs': 1, 'chars': 1000, 'first_ts': 0, 'last_ts': 100 - i,
                  'days': [{'day': '2026-10-13', 'msgs': 1, 'chars': 1000}]} for i in range(20)]
        parts = S.plan_parts({'chats': chats}, 0)
        self.assertTrue(all(len(p['chats']) <= S.GROUP_CHATS and p['chars'] <= S.GROUP_CHARS for p in parts))
        self.assertEqual(sum(len(p['chats']) for p in parts), 20)
        self.assertEqual([c for p in parts for c in p['chats']], list(range(20)))   # newest first, all kept


@legacy_text
class ApiJobsTests(ApiBase):
    name = 'api-jobs'

    def wait_job(self, jid, wait=20):
        st, j = self.call('GET', f'/jobs/{jid}?wait={wait}')
        self.assertEqual(st, 200, j)
        return j

    def test_job_runs_the_route_and_the_live_view_shows_it(self):
        st, direct = self.call('POST', '/tg/search', {'query': 'Lugano', 'n': 5})
        self.assertEqual(st, 200, direct)
        st, t = self.call('POST', '/jobs', {'op': 'tg.search', 'params': {'query': 'Lugano', 'n': 5}})
        self.assertEqual(st, 200, t)
        self.assertIn('position', t)
        j = self.wait_job(t['id'])
        self.assertEqual(j['state'], 'done', j)
        self.assertEqual(j['result']['exit_code'], 0)
        self.assertEqual(j['result']['stdout'], direct['stdout'])
        st, lst = self.call('GET', '/jobs')
        self.assertIn(t['id'], [x['id'] for x in lst['jobs']])
        self.assertTrue(all('result' not in x for x in lst['jobs']))
        evs = self.app.tap.raw_since(0)
        sub = [e for e in evs if e['path'] == '/jobs' and e['method'] == 'POST'][-1]
        self.assertEqual((sub['job']['phase'], sub['job']['route']), ('submit', '/tg/search'))
        self.assertIn("Telegram search 'Lugano'", sub['request'])
        done = [e for e in evs if (e.get('job') or {}).get('phase') == 'done'][-1]
        self.assertEqual((done['path'], done['via']), ('/tg/search', 'api'))
        self.assertIn(f"job {t['id'][:8]} done", done['line'])
        poll = [e for e in evs if e['path'] == f"/jobs/{t['id']}"][-1]
        self.assertNotIn('stdout', poll['body'])                         # polls: state only, the answer shows once
        self.assertTrue(W.routine(poll))
        self.assertRegex(W.header(sub), r"^\d\d:\d\d:\d\d 🔎 search Telegram · 'Lugano' · n 5 → ⏳ job \w+")
        self.assertRegex(W.header(done), r"^\d\d:\d\d:\d\d 🔎 search Telegram · 'Lugano' .*→ .* \(job\)")
        self.assertRegex(W.tick_line(poll), r'^⏳ job \w+ ')              # its polls: the progress line
        self.assertNotIn('Claude got', W.entry(sub, full=True))
        self.assertIn('Claude got', W.entry(done, full=True))
        st, s = self.call('GET', '/status')
        self.assertEqual(s['jobs'], {'active': 0})
        events = [e['event'] for e in self.call('GET', '/audit?days=1')[1]['events']]
        self.assertIn('job_submit', events)
        self.assertIn('job_done', events)
        self.assertIn('tg_search', events)                               # audited like the route it ran

    def test_refusals(self):
        for body in ({'op': 'raw.release', 'params': {}}, {'op': 'secrets.telegram'}, {'op': '/raw/release'},
                     {'op': 'tg.search', 'params': [1]}, {}):
            st, r = self.call('POST', '/jobs', body)
            self.assertEqual(st, 400, (body, r))
        st, r = self.call('POST', '/jobs', {'op': 'tg.search', 'params': {'query': 'x', 'raw': True}})
        self.assertEqual(st, 200)                                        # the route's own checks run in the job
        j = self.wait_job(r['id'])
        self.assertEqual((j['state'], j['status'], j['error']['code']), ('failed', 400, 'unknown_param'))
        self.assertEqual(self.call('GET', '/jobs/0123456789abcdef')[0], 404)
        self.assertEqual(self.call('GET', '/jobs/x?wait=abc')[0], 400)
        self.assertEqual(self.call('GET', '/jobs', token='wrong')[0], 401)
        self.assertEqual(self.call('POST', '/jobs/0123456789abcdef/cancel', {})[0], 404)


@unittest.skipUnless((CLI_DIR / 'vault').is_file(), 'client not here (image)')
@legacy_text
class CliJobsTests(ApiBase):
    """~/bin/vault --async + job wait/list/cancel -> this in-process vault: output and exit codes (12 = running)."""
    name = 'cli-jobs'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        home = TMP / 'cli-jobs-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        (home / 'bin' / 'vault').symlink_to(CLI_DIR / 'vault')
        tok = TMP / 'cli-jobs-token'
        tok.write_text(TOKEN + '\n')
        tok.chmod(0o600)
        cls.bin = home / 'bin'
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': cls.url, 'VAULT_TOKEN_FILE': str(tok)}

    def cli(self, *args, stdin=''):
        p = subprocess.run([str(self.bin / 'vault'), *args], env=self.env, input=stdin, capture_output=True,
                           text=True, timeout=90)
        return p.returncode, p.stdout, p.stderr

    def test_async_wait_list_cancel(self):
        rc, out, err = self.cli('tg', 'search', 'Lugano', '--async')
        self.assertEqual(rc, 0, err)
        jid = out.strip()
        self.assertRegex(jid, r'^[0-9a-f]{16}$')
        self.assertIn(f'vault job wait {jid}', err)
        rc, out, err = self.cli('job', 'wait', jid, '--max', '30')
        self.assertEqual(rc, 0, err)
        self.assertIn('0 hit(s)', out)                                   # printed like `vault tg search`
        llm_mode('slow')
        try:
            rc, out, err = self.cli('--async', 'llm-run', '--', '--max-tokens', '5', stdin='hello')
            self.assertEqual(rc, 0, err)
            slow = out.strip()
            rc, out, err = self.cli('job', 'wait', slow, '--max', '1')
            self.assertEqual(rc, 12, err)
            self.assertIn('still running', err)
            rc, out, err = self.cli('job', 'list')
            self.assertIn(slow, out)
            rc, out, err = self.cli('job', 'wait', slow, '--max', '30')
            self.assertEqual((rc, out), (0, 'ECHO --max-tokens=5 | hello'), err)
        finally:
            llm_mode('ok')
        rc, out, err = self.cli('job', 'wait', '0123456789abcdef')
        self.assertEqual(rc, 1)
        self.assertIn('no such job', err)
        rc, out, err = self.cli('job', 'wait', '../raw')
        self.assertEqual(rc, 2)
        rc, out, err = self.cli('--async', 'tg', 'download', '--chat', 'x', '--msg', '1', '--reason', 'r')
        self.assertEqual(rc, 2)
        self.assertIn('--async is not available', err)



# ============================================================================================ per-request LLM gate

import llmproxy as LP  # noqa: E402
import select  # noqa: E402

NOPROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class FakeLlama:
    """llama-server stand-in: a POST sleeps body['sleep'] s while watching its connection (a closed one cancels the
    task, as llama-server does), then answers fixed bytes. Logs ('start'|'end'|'cancel'|'flush', name) in order."""

    def __init__(self):
        self.log, self.lock = [], threading.Lock()
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *a):
                pass

            def answer(self, data):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('X-Fake', 'llama')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.answer(b'{"status": "ok"}')

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])) or b'{}')
                name = body.get('name', '?')
                fake.add(('start', name))
                end = time.time() + float(body.get('sleep', 0))
                while time.time() < end:
                    r, _, _ = select.select([self.connection], [], [], 0.02)
                    if r and not self.connection.recv(1, socket.MSG_PEEK):
                        fake.add(('cancel', name))
                        return
                fake.add(('end', name))
                self.answer(json.dumps({'choices': [{'message': {'content': f'answer {name} ü'},
                                                     'finish_reason': 'stop'}]}, ensure_ascii=False).encode())
        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def add(self, x):
        with self.lock:
            self.log.append(x)

    def starts(self):
        with self.lock:
            return [n for k, n in self.log if k == 'start']


def ask(port, ticket, name, sleep=0.0, path='/v1/chat/completions'):
    """One model request as llm-local sends it -> (status, body bytes, seconds, headers)."""
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=json.dumps({'name': name, 'sleep': sleep}).encode(),
                                 headers={'Content-Type': 'application/json',
                                          **({'X-LLM-Ticket': ticket} if ticket else {})})
    t = time.time()
    try:
        with NOPROXY.open(req, timeout=30) as r:
            return r.status, r.read(), time.time() - t, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.time() - t, dict(e.headers)


class ProxyTests(unittest.TestCase):
    """plan v2 #2b (13.10): each model request takes the gate on its own through the proxy. A live call waits at most
    one request (or preempt_after s, then the bulk request is aborted and re-run); the flush rule holds per request;
    answers are relayed byte for byte; no ticket, no model."""

    def setUp(self):
        self.fake = FakeLlama()
        self.gate = V.LLMGate(flush=lambda: self.fake.add(('flush', '-')),
                              metrics=MX.Metrics(Path(tempfile.mkdtemp(dir=TMP)) / 'm.json'))
        self.gate.preempt_after = 0                    # boundary preemption only, unless a test turns it on
        self.proxy = LP.LLMProxy(self.gate, self.fake.port, port=0).start()
        self.gate.proxy = self.proxy

    def tearDown(self):
        self.proxy.stop()
        self.fake.httpd.shutdown()

    def until(self, cond, t=8.0):
        end = time.time() + t
        while time.time() < end:
            if cond():
                return
            time.sleep(0.01)
        self.fail('timed out waiting')

    def worker(self, private, cls, names, sleep, out, gap=0.0, alive=None):
        """A lease (as tgread or llm-local hold it) whose subprocess sends its requests one after the other."""
        def run():
            with self.gate.lease(private, what=f'{cls} work', cls=cls, alive=alive) as env:
                for n in names:
                    out.append((n,) + ask(self.proxy.port, env['LLM_LOCAL_TICKET'], n, sleep)[:3])
                    time.sleep(gap)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def test_live_waits_at_most_one_request(self):
        bulk, live = [], []
        tb = self.worker(True, 'bulk', [f'b{i}' for i in range(6)], 0.5, bulk, gap=0.01)
        self.until(lambda: 'b1' in self.fake.starts())
        tl = self.worker(True, 'live', ['l1', 'l2', 'l3'], 0.05, live)
        tl.join(10)
        tb.join(20)
        self.assertLessEqual(live[0][3], 0.5 + 0.4)   # behind at most one bulk request, not the 3 s run
        st = self.fake.starts()
        i = st.index('l1')
        self.assertEqual(st[i:i + 3], ['l1', 'l2', 'l3'])           # the live read's requests back to back
        self.assertIn(st[i - 1], ('b1', 'b2'))                      # right after the bulk request that ran
        self.assertEqual([x[0] for x in bulk], [f'b{i}' for i in range(6)])
        self.assertTrue(all(x[1] == 200 for x in bulk + live))
        self.assertNotIn('cancel', [k for k, _ in self.fake.log])   # boundary preemption: nothing aborted
        self.assertEqual(self.gate.waiting, 0)

    def test_preempts_a_long_bulk_request(self):
        self.gate.preempt_after = 0.3
        bulk, live = [], []
        tb = self.worker(True, 'bulk', ['B'], 2.5, bulk)
        self.until(lambda: 'B' in self.fake.starts())
        tl = self.worker(True, 'live', ['L'], 0.05, live)
        tl.join(10)
        tb.join(15)
        self.assertLess(live[0][3], 1.5)               # ~preempt_after + the cancel, not the 2.5 s request
        log = self.fake.log
        self.assertEqual([x for x in log if x[1] == 'B'], [('start', 'B'), ('cancel', 'B'), ('start', 'B'), ('end', 'B')])
        self.assertLess(log.index(('end', 'L')), log.index(('end', 'B')))
        self.assertEqual(len(bulk), 1)                 # the subprocess saw one answer, the full one
        self.assertEqual((bulk[0][1], json.loads(bulk[0][2])['choices'][0]['message']['content']), (200, 'answer B ü'))
        self.assertEqual(self.proxy.counts['preempted'], 1)
        self.assertTrue(self.gate.dirty)

    def test_preempted_at_most_twice(self):
        self.gate.preempt_after = 0.2
        bulk = []
        tb = self.worker(True, 'bulk', ['B'], 1.2, bulk)
        for k in range(3):
            self.until(lambda: self.fake.starts().count('B') == min(k + 1, 3))
            out = []
            self.worker(True, 'live', [f'L{k}'], 0.01, out).join(10)
            self.assertEqual(out[0][1], 200)
        tb.join(15)
        self.assertEqual(self.fake.starts().count('B'), 3)          # two preemptions, then it runs to the end
        self.assertEqual([k for k, n in self.fake.log if n == 'B'].count('cancel'), 2)
        self.assertEqual(bulk[0][1], 200)

    def test_flush_per_request(self):
        def one(private, names):
            with self.gate.lease(private, what='llm-run (caller text)' if not private else 'tgread recent',
                                 cls='live') as env:
                for n in names:
                    self.assertEqual(ask(self.proxy.port, env['LLM_LOCAL_TICKET'], n)[0], 200)
        one(True, ['p1'])
        one(False, ['x1', 'x2'])
        one(True, ['p2'])
        one(False, ['x3'])
        seq = [n if k != 'flush' else 'FLUSH' for k, n in self.fake.log if k in ('start', 'flush')]
        self.assertEqual(seq, ['p1', 'FLUSH', 'x1', 'x2', 'p2', 'FLUSH', 'x3'])

    def test_bytes_unchanged_and_llm_local_output_same(self):
        with self.gate.lease(True, what='tgread search', cls='live') as env:
            via = ask(self.proxy.port, env['LLM_LOCAL_TICKET'], 'same')
            self.assertEqual(V.lease_env(), env)       # what Config.tool_env() adds for a subprocess
            cfg = make_cfg('proxy-env')
            cfg.tool_llm_port = self.proxy.port
            te = cfg.tool_env()
            self.assertEqual((te['LLM_LOCAL_PORT'], te['LLM_LOCAL_TICKET']), (str(self.proxy.port), env['LLM_LOCAL_TICKET']))
        self.assertEqual(V.lease_env(), {})
        self.assertNotIn('LLM_LOCAL_TICKET', cfg.tool_env())        # no lease: no ticket, and the proxy's port
        direct = ask(self.fake.port, None, 'same')
        self.assertEqual((via[0], via[1], via[3].get('X-Fake')), (direct[0], direct[1], direct[3].get('X-Fake')))
        # the real llm-local: the same output through the proxy as straight from (mock) llama-server
        d = Path(tempfile.mkdtemp(dir=TMP))
        (d / 'mode').write_text('ok')
        mock = subprocess.Popen([sys.executable, '-I', str(ROOT / 'tests' / 'llm-local' / 'mock_server.py'), str(d / 'port'),
                                 str(d / 'req.log'), str(d / 'mode')], env={'MOCK_PORT': '0', 'PATH': os.environ['PATH']},
                                stderr=subprocess.DEVNULL)
        try:
            self.until(lambda: (d / 'port').exists() and (d / 'port').read_text().strip())
            mport = int((d / 'port').read_text())
            px = LP.LLMProxy(self.gate, mport, port=0).start()
            src = (ROOT / 'tests' / 'llm-local' / 'fixtures' / 'swiss-para.txt').read_text()
            base = {'PATH': os.environ['PATH'], 'LLM_LOCAL_BACKEND': 'local', 'LLM_LOCAL_CTL': '/bin/false', 'LANG': 'C.UTF-8'}

            def run(env):
                return subprocess.run([sys.executable, '-I', str(ROOT / 'vendor' / 'llm-local'), '--paraphrase'], input=src,
                                      capture_output=True, text=True, env={**base, **env}, timeout=120)
            a = run({'LLM_LOCAL_PORT': str(mport)})
            with self.gate.lease(True, what='tgread search', cls='live') as env:
                b = run({'LLM_LOCAL_PORT': str(px.port), 'LLM_LOCAL_TICKET': env['LLM_LOCAL_TICKET']})
            c = run({'LLM_LOCAL_PORT': str(px.port)})                   # no ticket: refused, nothing out
            px.stop()
        finally:
            mock.kill()
            mock.wait()
        self.assertEqual((a.returncode, b.returncode), (0, 0), b.stderr[-300:])
        self.assertEqual(a.stdout, b.stdout)
        self.assertIn('Mia: ', b.stdout)
        self.assertEqual((c.returncode, c.stdout), (4, ''))
        self.assertIn('HTTP 403', c.stderr)

    def test_fail_closed(self):
        p = self.proxy.port
        self.assertEqual(ask(p, None, 'x')[0], 403)
        self.assertEqual(ask(p, 'f' * 32, 'x')[0], 403)
        with NOPROXY.open(f'http://127.0.0.1:{p}/health', timeout=10) as r:   # GET /health: llm-ctl's check
            self.assertEqual((r.status, json.loads(r.read())), (200, {'status': 'ok'}))
        with self.gate.lease(True, what='tgread search', cls='live') as env:
            t = env['LLM_LOCAL_TICKET']
            hold = []
            th = self.worker(True, 'bulk', ['long'], 1.0, hold)
            self.until(lambda: 'long' in self.fake.starts())
            st, _, secs, _ = ask(p, t, 'tok', path='/tokenize')   # no slot: not gated, no wait
            self.assertEqual(st, 200)
            self.assertLess(secs, 0.5)
            th.join(10)
        self.assertEqual(ask(p, t, 'late')[0], 403)                   # the lease is closed: its ticket is dead
        down = LP.LLMProxy(self.gate, self.fake.port, port=0)
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        dead = s.getsockname()[1]
        s.close()
        down.upstream = dead
        down.start()
        try:
            with self.gate.lease(True, what='x', cls='live') as env:
                self.assertEqual(ask(down.port, env['LLM_LOCAL_TICKET'], 'x')[0], 502)
        finally:
            down.stop()
        with self.assertRaises(V.ClientGone):                       # caller gone before anything ran
            with self.gate.lease(True, what='x', cls='live', alive=lambda: False):
                pass
        flag, hold, out = [True], [], []
        th = self.worker(True, 'bulk', ['busy'], 0.8, hold)
        self.until(lambda: 'busy' in self.fake.starts())
        tl = self.worker(True, 'live', ['q1'], 0.0, out, alive=lambda: flag[0])
        time.sleep(0.2)
        flag[0] = False                                             # its caller leaves while it is queued
        tl.join(10)
        th.join(10)
        self.assertEqual(out[0][1], 499)
        self.assertNotIn('q1', self.fake.starts())
        flag, out = [True], []
        with self.gate.lease(True, what='x', cls='live', alive=lambda: flag[0]) as env:   # once it ran, it finishes
            out.append(ask(p, env['LLM_LOCAL_TICKET'], 'r1')[0])
            flag[0] = False
            out.append(ask(p, env['LLM_LOCAL_TICKET'], 'r2')[0])
        self.assertEqual(out, [200, 200])

    def test_turn_kept_between_requests(self):
        a, b, c = [], [], []
        ta = self.worker(True, 'bulk', ['a1', 'a2', 'a3', 'a4'], 0.2, a, gap=0.05)
        self.until(lambda: 'a1' in self.fake.starts())
        tc = self.worker(True, 'background', ['c1'], 0.05, c)
        tb = self.worker(True, 'bulk', ['b1'], 0.05, b)
        for t in (ta, tb, tc):
            t.join(10)
        self.assertEqual(self.fake.starts(), ['a1', 'a2', 'a3', 'a4', 'b1', 'c1'])

class WeightsVerifyTests(unittest.TestCase):
    """2026-10-14 (Gemma-4 switch): every weight file (model + MTP drafter) is sha256-checked before llama-server may
    load it, a changed file is hashed again, a read-only weights dir is never written, the drafter goes in as -md."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=TMP))
        self.w = self.root / 'weights'
        self.w.mkdir()
        (self.root / 'data' / 'state').mkdir(parents=True)
        sums = {}
        for name, body in (('m.gguf', b'model'), ('d.gguf', b'draft')):
            (self.w / name).write_bytes(body)
            sums[name] = hashlib.sha256(body).hexdigest()
        self.cfg = V.Config({'VAULT_DATA': str(self.root / 'data'), 'VAULT_WEIGHTS': str(self.w)})
        self.saved = D.WEIGHTS, D.MODEL_FILE, D.DRAFT_FILE
        D.WEIGHTS = [(n, s, 'http://127.0.0.1:9/' + n) for n, s in sums.items()]
        D.MODEL_FILE, D.DRAFT_FILE = 'm.gguf', 'd.gguf'

    def tearDown(self):
        D.WEIGHTS, D.MODEL_FILE, D.DRAFT_FILE = self.saved
        os.chmod(self.w, 0o755)

    def llama(self):
        return D.Llama(self.cfg, lambda *a: None)

    def test_both_files_checked_marker_and_argv(self):
        la = self.llama()
        la.verify()
        self.assertTrue(la.verified)
        keys = json.loads((self.cfg.state / 'model-verified.json').read_text())
        self.assertEqual([k['file'] for k in keys], ['m.gguf', 'd.gguf'])
        argv = la.argv()
        self.assertEqual(argv[argv.index('-m') + 1], str(self.w / 'm.gguf'))
        self.assertEqual(argv[argv.index('-md') + 1], str(self.w / 'd.gguf'))
        self.llama().verify()                      # marker hit: no error, nothing hashed again

    def test_drafter_mismatch_refused(self):
        (self.w / 'd.gguf').write_bytes(b'tampered')
        with self.assertRaisesRegex(RuntimeError, r'd\.gguf: sha256 mismatch'):
            self.llama().verify()

    def test_changed_file_hashed_again(self):
        self.llama().verify()
        (self.w / 'm.gguf').write_bytes(b'other model')
        with self.assertRaisesRegex(RuntimeError, r'm\.gguf: sha256 mismatch'):
            self.llama().verify()

    def test_old_single_file_marker(self):
        V.write_private(self.cfg.state / 'model-verified.json', json.dumps({'file': 'x.gguf', 'size': 1}))
        self.llama().verify()
        self.assertEqual(len(json.loads((self.cfg.state / 'model-verified.json').read_text())), 2)

    @unittest.skipIf(os.geteuid() == 0, 'root ignores the read-only mode bits')
    def test_missing_file_in_read_only_dir_not_downloaded(self):
        (self.w / 'd.gguf').unlink()
        os.chmod(self.w, 0o555)
        with self.assertRaisesRegex(RuntimeError, r'd\.gguf is missing .*vault admin deploy'):
            self.llama().verify()

    def test_no_drafter(self):
        D.WEIGHTS, D.DRAFT_FILE = D.WEIGHTS[:1], ''
        la = self.llama()
        la.verify()
        self.assertNotIn('-md', la.argv())

    def projector(self, body=b'proj', sha_of=b'proj'):
        self.addCleanup(setattr, D, 'MMPROJ_FILE', D.MMPROJ_FILE)
        self.addCleanup(setattr, D, 'MMPROJ_SHA256', D.MMPROJ_SHA256)
        D.MMPROJ_FILE, D.MMPROJ_SHA256 = 'p.gguf', hashlib.sha256(sha_of).hexdigest()
        if body is not None:
            (self.w / 'p.gguf').write_bytes(body)

    def test_vision_projector_verified_and_loaded(self):            # vault-photos round 4 (16.10)
        self.projector()
        la = self.llama()
        la.verify()
        self.assertEqual((la.vision, la.vision_detail), (True, 'on'))
        argv = la.argv()
        self.assertEqual(argv[argv.index('--mmproj') + 1], str(self.w / 'p.gguf'))
        keys = json.loads((self.cfg.state / 'model-verified.json').read_text())
        self.assertEqual([k['file'] for k in keys], ['m.gguf', 'd.gguf', 'p.gguf'])
        la.state = 'running'
        self.assertTrue(la.vision_ready())
        la.state = 'starting'
        self.assertFalse(la.vision_ready())

    def test_vision_projector_optional_never_fatal(self):
        self.projector(body=b'tampered')                            # sha256 mismatch: the LLM still starts
        la = self.llama()
        la.verify()
        self.assertTrue(la.verified)
        self.assertFalse(la.vision)
        self.assertIn('sha256 mismatch', la.vision_detail)
        self.assertNotIn('--mmproj', la.argv())
        (self.w / 'p.gguf').unlink()                                # missing: never downloaded here
        la = self.llama()
        la.verify()
        self.assertFalse(la.vision)
        self.assertIn('vault admin deploy', la.vision_detail)
        self.assertFalse((self.w / 'p.gguf').exists())
        self.assertFalse(la.vision_ready())

    def test_vision_switched_off(self):
        self.projector()
        self.cfg.vision = False                                     # VAULT_VISION=0
        la = self.llama()
        la.verify()
        self.assertFalse(la.vision)
        self.assertNotIn('--mmproj', la.argv())
        self.assertEqual(len(json.loads((self.cfg.state / 'model-verified.json').read_text())), 2)
        self.assertFalse(V.Config({'VAULT_DATA': str(self.root / 'data'), 'VAULT_VISION': '0'}).vision)
        self.assertTrue(V.Config({'VAULT_DATA': str(self.root / 'data')}).vision)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
