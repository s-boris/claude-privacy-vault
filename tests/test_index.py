"""Semantic index C3 (vault memory plan, 2026-10-15): the chunker (gap, size, overlap), the spread sample, RRF with
the per-chat cap, recall@k/MRR and the C4 gate, sqlite-vec (load + KNN with partition and metadata filters), the
embed server (127.0.0.1, SCHED_IDLE wrapper, sha256 before load, a fake llama-server end to end, the VAULT_EMBED
switch), the bake-off with fakes (numbers and enums only: no chunk or question text in the result, the eval file or
the audit), the routes (/index/status, /index/eval: not a text route, job op index.eval) and the public smoke set.
Invented fixtures only. Run: python3 -I tests/test_index.py (VAULT_VEC_PATH=.../vec0 for the sqlite-vec parts;
VAULT_VEC_REQUIRED=1 in the image makes them mandatory)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402
import contextlib  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import stat  # noqa: E402
import struct  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
import index as IX  # noqa: E402
import jobs as J  # noqa: E402

V, D = TV.V, TV.D
VEC = os.environ.get('VAULT_VEC_PATH', '')
VEC_REQUIRED = os.environ.get('VAULT_VEC_REQUIRED') == '1'
NOW = 1_760_000_000


def vec_ok():
    try:
        return bool(VEC) and IX.vec_version(VEC).startswith('v')
    except Exception:
        if VEC_REQUIRED:
            raise
        return False


HAVE_VEC = vec_ok()
need_vec = unittest.skipUnless(HAVE_VEC or VEC_REQUIRED, 'sqlite-vec not loadable here (VAULT_VEC_PATH)')

FAKE_SERVER = r'''#!/usr/bin/python3 -I
# a fake llama-server --embeddings: /health, /v1/embeddings with hashed bag-of-words vectors (64 dims)
import hashlib, json, math, re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port = int(sys.argv[sys.argv.index('--port') + 1])
def vec(t):
    v = [0.0] * 64
    for w in re.findall(r'\w{4,}', t.lower()):
        v[int(hashlib.md5(w.encode()).hexdigest(), 16) % 64] += 1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def send(self, d):
        b = json.dumps(d).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self.send({'status': 'ok'})
    def do_POST(self):
        d = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if any(len(t) > 1200 for t in d['input']):     # like a slot's context limit: the whole request fails
            self.send_response(500); self.send_header('Content-Length', '0'); self.end_headers(); return
        self.send({'data': [{'index': i, 'embedding': vec(t)} for i, t in enumerate(d['input'])],
                   'usage': {'prompt_tokens': sum(len(t.split()) for t in d['input'])}})
HTTPServer(('127.0.0.1', port), H).serve_forever()
'''

# invented chats: 4 chats, a few topics each (no real data)
TOPICS = [
    ('Mara', 'Grillfescht am Rhy am Samschtig, ich bring Würscht und Brot'),
    ('Tim', 'Zahnarzttermin verschoben auf Dienstag Nachmittag'),
    ('Lea', 'Festivaltickets ausverkauft, Warteliste probieren'),
    ('Nico', 'Heizung kaputt, Monteur kommt morgen früh'),
    ('Ivana', 'rodjendan subota torta donosim'),
    ('Emma', 'concert cancelled refund within fourteen days'),
    ('Ryan', 'plants watering vacation Thailand key under mat'),
    ('Jana', 'Geschenk Mutter Geburtstag Wellness Gutschein'),
]
SECRET_BITS = ('Würscht', 'Zahnarzttermin', 'Festivaltickets', 'Monteur', 'torta', 'refund', 'Thailand',
               'Gutschein', 'Mara', 'Ivana', 'Ryan')


def fixture_rows():
    rows, rid = [], 0
    for c in range(4):
        chat = 9000 + c
        ts = NOW - 400 * 86400 + c * 3600
        for t in range(40):                              # 40 conversations per chat, 3 messages each
            who, text = TOPICS[(t + c) % len(TOPICS)]
            for k in range(3):
                rid += 1
                rows.append({'id': rid, 'chat': chat, 'msg': rid, 'ts': ts + k * 60, 'edit_ts': None, 'out': k == 1,
                             'sid': 100 + c, 'sender': 'me' if k == 1 else who,
                             'kind': 'dm' if c < 2 else 'group', 'text': f'{text} variante{t} teil{k} Zusatz{t * 7 + c}'})
            ts += 4 * 86400
    return rows


def strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class FakeTG:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def index_rows(self, after=0, max_rows=2000):
        self.calls.append(after)
        page = [r for r in self.rows if r['id'] > after][:max_rows]
        return {'after': after, 'last': page[-1]['id'] if page else after, 'rows': page}

    def fts_queries(self, qs, any_=False):
        out = []
        for q in qs:
            words = [w for w in q.split() if w.isalnum()]
            out.append(' AND '.join(f'"{w}"' for w in words) if words else None)
        return out


class FakeGate:
    def __init__(self):
        self.uses = []

    @contextlib.contextmanager
    def lease(self, private, what='', timeout=0, cls=None, alive=None):
        self.uses.append(('lease', what, cls))
        yield

    @contextlib.contextmanager
    def use(self, private, what='', timeout=0, cls=None, **kw):
        self.uses.append(('use', what, cls))
        yield {}


class FakePolicy:
    """The local LLM's eval questions: words of the chunk (so vectors find it), keywords = one distinctive word."""
    def __init__(self):
        self.calls = 0

    def run_llm(self, args, text, timeout=0, **kw):
        self.calls += 1
        assert '--schema' in args and '--json' in args
        words = [w for w in text.replace(':', ' ').split() if len(w) > 4]
        extra = [w for w in words if w.startswith('Zusatz')]
        return json.dumps({'lang': 'gsw' if 'Rhy' in text else 'de', 'query': ' '.join(words[2:8]) + ' ?',
                           'keywords': extra[0] if extra else words[0]})


class FakeAudit:
    def __init__(self):
        self.lines = []

    def log(self, event, **kw):
        self.lines.append(dict(event=event, **kw))


def weights_dir(root, names):
    d = Path(root) / 'models'
    d.mkdir(parents=True, exist_ok=True)
    files = {}
    for n in names:
        p = d / f'{n}.gguf'
        p.write_bytes(f'fake weights {n}'.encode())
        files[n] = (p.name, hashlib.sha256(p.read_bytes()).hexdigest(), f'https://huggingface.co/x/{n}')
    return d, files


def make_cfg(name, **extra):
    tmp = tempfile.mkdtemp(prefix='ix-', dir=str(TV.TMP))
    srv = Path(tmp) / 'fake-llama-server'
    srv.write_text(FAKE_SERVER)
    srv.chmod(0o755)
    wd, files = weights_dir(tmp, IX.MODELS)
    env = {'VAULT_WEIGHTS': str(wd), 'VAULT_LLAMA_BIN': str(srv), 'VAULT_EMBED_PORT': str(free_port() - 1),
           'VAULT_VEC_PATH': VEC or '/nonexistent/vec0'}
    env.update(extra)
    return TV.make_cfg(name, **env), files


# ============================================================================================ pure functions

class ChunkTests(unittest.TestCase):
    def row(self, i, ts, text, chat=1, sender='Ana'):
        return {'id': i, 'chat': chat, 'msg': i, 'ts': ts, 'text': text, 'sender': sender, 'kind': 'dm'}

    def test_gap_size_overlap(self):
        rows = [self.row(1, 0, 'a' * 100), self.row(2, 60, 'b' * 100), self.row(3, 60 + 46 * 60, 'c' * 100)]
        ch = IX.chunk_rows(rows)
        self.assertEqual([c['msgs'] for c in ch], [[1, 2], [3]])     # 45-min gap: new chunk, no overlap
        rows = [self.row(i, i * 60, 'x' * 300) for i in range(1, 8)]
        ch = IX.chunk_rows(rows)
        self.assertTrue(all(c['chars'] <= IX.MAX_CHARS + 320 for c in ch))
        for a, b in zip(ch, ch[1:]):
            self.assertEqual(a['msgs'][-1], b['msgs'][0])          # one message of overlap
        self.assertEqual(sorted({m for c in ch for m in c['msgs']}), list(range(1, 8)))
        self.assertEqual(ch[-1]['msgs'][-1], 7)
        self.assertGreater(len(ch[-1]['msgs']), 1)                  # no chunk made of the overlap alone

    def test_per_chat_text_and_meta(self):
        rows = [self.row(1, 0, 'Hoi zäme', chat=1), self.row(2, 10, 'Hello', chat=2, sender='me'),
                self.row(3, 20, '', chat=1), self.row(4, 30, 'y' * 5000, chat=1)]
        ch = IX.chunk_rows(rows)
        self.assertEqual(sorted(c['chat'] for c in ch), [1, 2])
        c1 = [c for c in ch if c['chat'] == 1][0]
        self.assertEqual(c1['msgs'], [1, 4])                        # the empty message is skipped
        self.assertTrue(c1['text'].startswith('Ana: Hoi zäme\nAna: y'))
        self.assertLessEqual(len(c1['text']), IX.MAX_MSG_CHARS + 30)  # a long message is cut
        self.assertEqual((c1['ts_first'], c1['ts_last'], c1['n']), (0, 30, 2))
        self.assertNotIn('Ana:', c1['kw_text'])                     # the keyword leg sees message text only

    def test_spread_sample(self):
        import random
        chunks = IX.chunk_rows(fixture_rows())
        s = IX.spread_sample(chunks, 8, random.Random(1))
        self.assertEqual(len({c['chat'] for c in s[:4]}), 4)       # the first round: one per chat
        self.assertEqual([c['msgs'] for c in s], [c['msgs'] for c in IX.spread_sample(chunks, 8, random.Random(1))])
        self.assertEqual(len(IX.spread_sample(chunks, 10 ** 6, random.Random(1))), len(chunks))


class MetricTests(unittest.TestCase):
    def test_rrf_cap_scores(self):
        self.assertEqual(IX.rrf([[1, 2, 3], [3, 1]]), [1, 3, 2])
        self.assertEqual(IX.rrf([[1], [2]], ts={1: 5, 2: 9}), [2, 1])   # tie: newest first
        chat_of = {1: 'a', 2: 'a', 3: 'a', 4: 'a', 5: 'b'}
        self.assertEqual(IX.cap_per_chat([1, 2, 3, 4, 5], chat_of), [1, 2, 3, 5])
        s = IX.scores([1, 6, None, 11])
        self.assertEqual(s, {'n': 4, 'r5': 0.25, 'r10': 0.5, 'mrr': round((1 + 1 / 6 + 1 / 11) / 4, 3)})
        self.assertEqual(IX.scores([]), {'n': 0})
        b = IX.breakdown([1, None], [{'lang': 'gsw', 'cross': False}, {'lang': 'de', 'cross': True}])
        self.assertEqual((b['lang']['gsw']['r5'], b['lang']['de']['r5'], b['cross']['cross']['n']), (1.0, 0.0, 1))

    def test_gate(self):
        def bd(r10, lang):
            return {'all': {'r10': r10}, 'lang': {k: {'n': n, 'r10': v} for k, (n, v) in lang.items()}}
        kw = bd(0.40, {'gsw': (50, 0.5), 'en': (10, 0.9)})
        self.assertTrue(IX.gate_check(kw, bd(0.55, {'gsw': (50, 0.6), 'en': (10, 0.5)}))['passed'])  # en: n < 30
        g = IX.gate_check(kw, bd(0.55, {'gsw': (50, 0.45), 'en': (10, 0.9)}))
        self.assertEqual((g['passed'], g['buckets_worse']), (False, ['gsw']))
        self.assertFalse(IX.gate_check(kw, bd(0.45, {'gsw': (50, 0.6)}))['lift_ok'])

    def test_smoke_set(self):
        items = IX.load_smoke()
        self.assertGreaterEqual(len(items), 30)
        for lang in ('gsw', 'de', 'en', 'bcs'):
            self.assertGreaterEqual(sum(1 for x in items if x['lang'] == lang), 6, lang)
        self.assertTrue(all(set(x) == {'lang', 'doc', 'query'} and x['doc'] and x['query'] for x in items))


@need_vec
class VecTests(unittest.TestCase):
    def test_load_and_knn_filters(self):
        self.assertEqual(IX.vec_version(VEC), 'v0.1.9')
        c = IX.vec_connect(VEC)
        c.execute('CREATE VIRTUAL TABLE v USING vec0(chunk_id INTEGER PRIMARY KEY, embedding float[3] '
                  'distance_metric=cosine, source TEXT PARTITION KEY, chat_id INTEGER, ts_last INTEGER)')
        for i, (e, src, chat) in enumerate([([1, 0, 0], 'tg', 1), ([0, 1, 0], 'tg', 2), ([.9, .1, 0], 'tg', 2),
                                            ([1, 0, 0], 'gmail', 3)]):
            c.execute('INSERT INTO v(chunk_id, embedding, source, chat_id, ts_last) VALUES (?, ?, ?, ?, ?)',
                      (i + 1, struct.pack('3f', *e), src, chat, 100 + i))
        q = struct.pack('3f', 1, 0, 0)
        self.assertEqual([r[0] for r in c.execute("SELECT chunk_id FROM v WHERE embedding MATCH ? AND k = 2 AND "
                                                  "source = 'tg' ORDER BY distance", (q,))], [1, 3])
        self.assertEqual([r[0] for r in c.execute('SELECT chunk_id FROM v WHERE embedding MATCH ? AND k = 5 AND '
                                                  'chat_id = 2 ORDER BY distance', (q,))], [3, 2])
        with self.assertRaises(Exception):                       # extension loading is off again
            c.execute("SELECT load_extension('x')")


# ============================================================================================ server

class EmbedProcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.files = make_cfg('ix-proc')

    def test_argv_local_idle_pinned_pooling(self):
        for model, pool in (('embeddinggemma', 'mean'), ('qwen3-0.6b', 'last'), ('bge-m3', 'cls')):
            a = IX.EmbedProc(self.cfg, model, self.files, 18000).argv()
            self.assertEqual(a[1:3], ['-I', '-c'])
            self.assertIn('SCHED_IDLE', a[3])
            self.assertIn('os.nice(19)', a[3])
            self.assertEqual(a[4], self.cfg.llama_bin)
            self.assertEqual(a[a.index('--host') + 1], '127.0.0.1')
            self.assertEqual(a[a.index('--pooling') + 1], pool)
            self.assertIn('--embeddings', a)
            self.assertEqual(a[a.index('-t') + 1], str(IX.EMBED_THREADS))
        with self.assertRaises(V.VaultError):
            IX.EmbedProc(self.cfg, 'gpt-x', self.files, 18000)

    def test_sha_and_missing(self):
        bad = dict(self.files, **{'bge-m3': (self.files['bge-m3'][0], '0' * 64, 'u')})
        with self.assertRaises(RuntimeError) as e:
            IX.EmbedProc(self.cfg, 'bge-m3', bad, free_port()).start()
        self.assertIn('sha256 mismatch', str(e.exception))
        gone = dict(self.files, **{'bge-m3': ('missing.gguf', '0' * 64, 'u')})
        with self.assertRaises(RuntimeError) as e:
            IX.EmbedProc(self.cfg, 'bge-m3', gone, free_port()).start()
        self.assertIn('vault admin deploy', str(e.exception))

    def test_fake_server_end_to_end(self):
        with IX.EmbedProc(self.cfg, 'embeddinggemma', self.files, free_port()) as p:
            self.assertGreaterEqual(p.wait_ready(30), 0)
            vs, toks = p.embed(['Grillfest am Rhein', 'Zahnarzt Dienstag'])
            self.assertEqual((len(vs), len(vs[0])), (2, 64))
            self.assertAlmostEqual(sum(x * x for x in vs[0]), 1.0, places=5)
            self.assertGreater(toks, 0)
            self.assertIn(p.sched(), ('idle', 'other'))           # idle wherever SCHED_IDLE is allowed
            if hasattr(os, 'SCHED_IDLE'):
                self.assertEqual(p.sched(), 'idle')
            hwm, rss = p.mem_kb()
            self.assertGreater(hwm, 0)
            pid = p.proc.pid
        self.assertFalse(os.path.exists(f'/proc/{pid}/status') and p.running())
        marker = json.loads((self.cfg.state / 'embed-verified.json').read_text())
        self.assertIn('embeddinggemma.gguf', [m['file'] for m in marker])
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg.logs / 'embed-server.log').st_mode), 0o600)

    def test_supervisor_switch(self):
        cfg, files = make_cfg('ix-off', VAULT_EMBED='0')
        s = IX.EmbedServer(cfg, files)
        s.run()                                                  # off: returns at once
        self.assertEqual(s.status(), {'on': False, 'model': None, 'state': 'off'})
        cfg, files = make_cfg('ix-bad', VAULT_EMBED='nonesuch')
        s = IX.EmbedServer(cfg, files, log=lambda m: None)
        s.run()
        self.assertEqual(s.status()['state'], 'failed')
        cfg, files = make_cfg('ix-on', VAULT_EMBED='bge-m3')
        s = IX.EmbedServer(cfg, files, log=lambda m: None)
        import threading
        t = threading.Thread(target=s.run, daemon=True)
        t.start()
        for _ in range(200):
            if s.state == 'running':
                break
            time.sleep(0.05)
        st = s.status()
        self.assertEqual((st['on'], st['model'], st['state'], st['port']), (True, 'bge-m3', 'running', cfg.embed_port))
        self.assertGreater(st['rss_mb'], 0)
        s.stop()
        t.join(15)
        self.assertEqual(s.status()['state'], 'stopped')


# ============================================================================================ bake-off

@need_vec
class EvalTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.files = make_cfg('ix-eval')
        self.tg, self.gate, self.pol, self.audit = FakeTG(fixture_rows()), FakeGate(), FakePolicy(), FakeAudit()
        self.ix = IX.Index(self.cfg, self.tg, self.pol, self.gate, self.audit, self.files, log=lambda m: None)

    def test_numbers_only_and_recall(self):
        steps = []
        r = self.ix.eval({'sample': 100, 'queries': 30, 'models': 'embeddinggemma,bge-m3'},
                         report=lambda kind, **kw: steps.append(kw.get('step')))
        self.assertEqual((r['n_chunks'], r['n_queries'], r['queries_failed']), (100, 30, 0))
        self.assertEqual(sorted(r['models']), ['bge-m3', 'embeddinggemma'])
        for m, x in r['models'].items():
            self.assertEqual(set(x) >= {'vector', 'hybrid', 'speed', 'ram', 'smoke', 'gate', 'dims'}, True, x)
            self.assertGreaterEqual(x['vector']['all']['r10'], 0.5)   # the fake vectors find their chunk
            self.assertGreaterEqual(x['hybrid']['all']['r10'], r['keyword']['all']['r10'] - 0.2)
            self.assertEqual(x['ram']['sched'], 'idle' if hasattr(os, 'SCHED_IDLE') else 'other')
            self.assertGreater(x['speed']['tokens'], 0)
            self.assertIsNotNone(x['speed']['query_ms_p95'])
        self.assertGreater(r['keyword']['all']['r10'], 0.5)          # "Zusatz<n>" keywords are distinctive
        self.assertIn(r['recommended'], r['models'])
        self.assertEqual(r['langs']['gsw'] + r['langs']['de'], 30)
        # privacy: no chunk, question or keyword text anywhere: result, eval file, audit, progress steps
        allowed = set(IX.LANGS) | set(IX.MODELS) | {f for f, _, _ in self.files.values()} | {'idle', 'other', 'v0.1.9'}
        file_blob = (self.cfg.state / 'index-eval.json').read_text()
        for blob in (json.dumps(r, ensure_ascii=False), file_blob, json.dumps(self.audit.lines, ensure_ascii=False),
                     json.dumps(steps, ensure_ascii=False)):
            for bad in SECRET_BITS + ('Zusatz', 'variante'):
                self.assertNotIn(bad, blob)
        for s in strings(r):
            self.assertTrue(s in allowed or s.replace('_', '').replace('@', '').isalnum() or s == r['at'], s)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg.state / 'index-eval.json').st_mode), 0o600)
        self.assertEqual([a['event'] for a in self.audit.lines], ['index_eval', 'index_eval'])
        self.assertTrue(all(set(a) <= {'event', 'model', 'n', 'r5', 'r10', 'mrr', 'vector_r10', 'keyword_r10', 'gate'}
                            for a in self.audit.lines))
        # LLM work at background priority; every embedding batch takes the gate
        self.assertEqual({(k, c) for k, w, c in self.gate.uses}, {('lease', 'background'), ('use', 'background')})
        self.assertEqual(self.pol.calls, 30)
        st = self.ix.status()
        self.assertEqual(st['eval']['n_queries'], 30)
        self.assertEqual(st['vec'], {'version': 'v0.1.9'})
        self.assertFalse(st['eval_running'])
        self.assertNotIn('eval_full', st)
        self.assertEqual(self.ix.status(full=True)['eval_full']['n_queries'], 30)

    def test_bad_params_busy_and_llm_failures(self):
        for b in ({'sample': 5}, {'queries': 'x'}, {'models': ['gpt-x']}, {'models': 7}):
            with self.assertRaises(V.VaultError) as e:
                self.ix.eval(b)
            self.assertEqual(e.exception.status, 400, b)
        self.ix._eval_lock.acquire()
        try:
            with self.assertRaises(V.VaultError) as e:
                self.ix.eval({})
            self.assertEqual(e.exception.status, 409)
        finally:
            self.ix._eval_lock.release()
        self.pol.run_llm = lambda *a, **k: '{"lang": "xx", "query": "q", "keywords": "k"}'
        with self.assertRaises(V.VaultError) as e:
            self.ix.eval({'sample': 60, 'queries': 20, 'models': ['bge-m3']})
        self.assertEqual(e.exception.code, 'llm_unavailable')
        self.assertFalse((self.cfg.state / 'index-eval.json').exists())

    def test_vec_missing(self):
        cfg, files = make_cfg('ix-novec', VAULT_VEC_PATH='/nonexistent/vec0')
        ix = IX.Index(cfg, self.tg, self.pol, self.gate, self.audit, files)
        self.assertIn('error', ix.status()['vec'])
        with self.assertRaises(V.VaultError) as e:
            ix.eval({})
        self.assertEqual(e.exception.status, 503)


# ============================================================================================ routes

class RouteTests(TV.ApiBase):
    name = 'api-index'

    def test_routes(self):
        st, r = self.call('GET', '/index/status')
        self.assertEqual(st, 200, r)
        self.assertEqual(r['embed'], {'on': False, 'model': None, 'state': 'off'})
        self.assertEqual(sorted(r['models']), sorted(IX.MODELS))
        self.assertIn('vec', r)
        st, r = self.call('POST', '/index/eval', {'models': ['gpt-x']})
        self.assertEqual(st, 400, r)
        self.assertNotIn('/index/eval', D.TEXT_ROUTES)
        self.assertNotIn('/index/status', D.TEXT_ROUTES)
        self.assertEqual(J.OPS['index.eval'], ('POST', '/index/eval'))
        st, r = self.call('GET', '/status')
        self.assertEqual(r['embed']['state'], 'off')
        st, r = self.call('GET', '/index/status')       # C4: the index part (numbers and enums only)
        self.assertEqual((r['index']['built'], r['index']['maintained'], r['index']['unavailable']),
                         (False, False, 'embed_off'))
        st, r = self.call('POST', '/index/rebuild', {})  # no embed server: nothing to rebuild with
        self.assertEqual((st, r.get('code') or r.get('error')), (409, 'index_off'), r)
        st, r = self.call('POST', '/index/rebuild', {'mode': 'drop'})
        self.assertEqual(st, 400, r)
        self.assertNotIn('/index/rebuild', D.TEXT_ROUTES)
        self.assertIn('retrieval', V.TAP_SAFE_KEYS)
        self.assertIn(self.app.index.on_purge, self.app.tg.purge_hooks)
        self.assertIn(self.app.index.poke, self.app.tg.live.listeners)
        self.assertIs(self.app.answer.index, self.app.index)

    def test_pins(self):
        self.assertEqual(sorted(D.EMBED_FILES), sorted(IX.MODELS))
        for f, sha, url in D.EMBED_FILES.values():
            self.assertRegex(f, r'^[\w.+-]+\.gguf$')
            self.assertRegex(sha, r'^[0-9a-f]{64}$')
            self.assertTrue(url.startswith(('https://huggingface.co/ggml-org/', 'https://huggingface.co/Qwen/')), url)
            self.assertTrue(url.endswith('/' + f))



# ============================================================================================ C4: index.db + hybrid

class FakeTG4(FakeTG):
    """FakeTG + the C4 internals: a chat's tail, the indexable chats, search-style lines, search hits."""
    def __init__(self, rows):
        super().__init__(rows)
        self.gone_chats, self.line_calls = set(), []

    def live_rows(self):
        return [r for r in self.rows if r['chat'] not in self.gone_chats]

    def index_rows(self, after=0, max_rows=2000):
        page = [r for r in sorted(self.live_rows(), key=lambda r: r['id']) if r['id'] > after][:max_rows]
        return {'after': after, 'last': page[-1]['id'] if page else after, 'rows': page}

    def index_rows_chat(self, chat, since_ts, after=0, max_rows=5000):
        page = [r for r in sorted(self.live_rows(), key=lambda r: r['id'])
                if r['chat'] == chat and r['ts'] >= since_ts and r['id'] > after][:max_rows]
        return {'after': after, 'last': page[-1]['id'] if page else after, 'rows': page}

    def index_chats(self):
        return sorted({r['chat'] for r in self.rows} - self.gone_chats)

    def logged_in(self):
        return True

    def line(self, r):
        t = time.strftime('%Y-%m-%d %H:%M', time.localtime(r['ts']))
        return {'chat_id': r['chat'], 'chat': 'x', 'chat_type': 'user', 'msg_id': r['msg'], 'ts': r['ts'],
                'line': f"[{t}] {r['sender']}: {r['text']} (#{r['msg']})"}

    def index_lines(self, pairs):
        self.line_calls.append(list(pairs))
        want = {(c, m) for c, m in pairs}
        return [self.line(r) for r in sorted(self.live_rows(), key=lambda r: r['ts']) if (r['chat'], r['msg']) in want]

    def find_hits(self, query, since=None, n=15, extra=None):
        w = query.lower().split()
        hits = [r for r in self.live_rows() if all(x in r['text'].lower() for x in w)]
        return [self.line(r) for r in sorted(hits, key=lambda r: -r['ts'])][:n]

    def alias_map(self):
        return {}


class IdPolicy(FakePolicy):
    def anonymize(self, text, **kw):
        return text

    @staticmethod
    def regex_net(s, **kw):
        return s

    @staticmethod
    def money_net(s, **kw):
        return s


def chunk_set(rows):
    return sorted((c['chat'], tuple(c['msgs'])) for c in IX.chunk_rows(rows))


def db_set(ix):
    d = ix.db()
    out = []
    for cid, chat in d.c.execute('SELECT id, chat_id FROM chunks'):
        out.append((chat, tuple(m for (m,) in d.c.execute('SELECT msg_id FROM chunk_msgs WHERE chunk_id=? '
                                                          'ORDER BY msg_id', (cid,)))))
    return sorted(out)


@need_vec
class C4IndexTests(unittest.TestCase):
    def setUp(self):
        self.cfg, files = make_cfg('c4-' + self._testMethodName[5:], VAULT_EMBED='embeddinggemma',
                                   VAULT_EMBED_PORT=str(free_port()))      # a port that was free just now
        self.rows = fixture_rows()
        self.tg, self.gate, self.audit = FakeTG4(self.rows), FakeGate(), FakeAudit()
        self.now = [NOW]
        self.ix = IX.Index(self.cfg, self.tg, IdPolicy(), self.gate, self.audit, files, log=lambda m: None,
                           clock=lambda: self.now[0], key=b'k' * 32)
        self.th = threading.Thread(target=self.ix.server.run, daemon=True)
        self.th.start()
        for _ in range(600):                           # a failed start retries after 5 s (EmbedServer backoff)
            if self.ix.server.state == 'running':
                break
            time.sleep(0.05)
        self.assertEqual(self.ix.server.state, 'running', self.ix.server.detail)

    def tearDown(self):
        self.ix.server.stop()
        self.ix.stop_ev.set()
        self.th.join(5)

    def build(self):
        self.assertEqual(self.ix.due(self.now[0]), 'build')
        self.assertEqual(self.ix.unavailable(), 'not_built')
        r = self.ix.step()
        self.assertIsNotNone(r)
        return r

    def test_build_numbers_only_private_file(self):
        r = self.build()
        self.assertEqual(r['chunks'], len(IX.chunk_rows(self.rows)))
        self.assertEqual(db_set(self.ix), chunk_set(self.rows))
        self.assertIsNone(self.ix.unavailable())
        self.assertTrue(self.ix.db_path.exists() and not self.ix.shadow_path.exists())
        self.assertEqual(stat.S_IMODE(self.ix.db_path.stat().st_mode), 0o600)
        self.ix.db().c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        blob = self.ix.db_path.read_bytes()
        for bit in SECRET_BITS:                        # no message text in the index file
            self.assertNotIn(bit.encode(), blob, bit)
        st = self.ix.status()['index']
        self.assertTrue(st['built'] and st['current'] and st['dims'] == 64 and st['chunks'] == r['chunks'])
        for v in strings(st):
            for bit in SECRET_BITS:
                self.assertNotIn(bit, v)
        self.assertTrue(all(u[2] == 'background' for u in self.gate.uses if u[0] == 'use'))
        ev = [e for e in self.audit.lines if e['event'] == 'index_rebuild']
        self.assertTrue(ev and ev[-1]['chunks'] == r['chunks'] and ev[-1]['swapped'])
        self.assertIsNone(self.ix.due(self.now[0]))        # built, current, nothing pending
        self.assertIsNone(self.ix.step())

    def test_c5_topic_helpers(self):
        """C5: a spread sample of DM chunks (ids and msg ids), their vectors, version-tagged topic labels (a new
        version clears them), per-chat counts in a time window; seed texts embedded at background priority."""
        self.build()
        n = self.ix.db().counts()[0]
        pick = self.ix.topic_sample(10, 3, min_chars=1)
        self.assertEqual(len(pick), 10)
        self.assertEqual(set(pick[0]), {'id', 'chat', 'ts_last', 'chars', 'msgs'})
        self.assertTrue(all(c['msgs'] and c['chat'] > 0 for c in pick))
        self.assertGreater(len({c['chat'] for c in pick}), 1)      # spread across chats
        vecs = self.ix.chunk_vectors([c['id'] for c in pick])
        self.assertEqual(set(vecs), {c['id'] for c in pick})
        self.assertTrue(all(len(v) == 64 for v in vecs.values()))
        self.assertEqual(len(self.ix.chunk_vectors(range(1, n + 1))), n)        # the big-set path
        ids = self.ix.topics_pending('t1')
        self.assertEqual(len(ids), n)
        self.assertEqual(self.ix.set_topics({i: 'travel' for i in ids[:5]}, 't1'), 5)
        self.assertEqual(self.ix.set_topics({ids[5]: 'party'}, 'old'), 0)          # a stale version writes nothing
        self.assertEqual(len(self.ix.topics_pending('t1')), n - 5)
        chats = {r[0] for r in self.ix.db().c.execute('SELECT chat_id FROM chunks')}
        counts = self.ix.topic_counts(chats, 0, 't1')
        self.assertEqual(sum(c.get('travel', 0) for c in counts.values()), 5)
        self.assertEqual(self.ix.topic_counts(chats, 0, 't2'), {})
        self.assertEqual(self.ix.topic_counts(chats, 2 ** 40, 't1'), {})
        self.assertEqual(len(self.ix.topics_pending('t2')), n)                  # a new version: all cleared
        v = self.ix.embed_docs(['Flug nach Funchal', 'Rave am Samstag'])
        self.assertEqual([len(x) for x in v], [64, 64])
        self.assertTrue(any(u[1] == 'index (docs)' and u[2] == 'background' for u in self.gate.uses))

    def test_too_long_chunk_is_shortened_not_fatal(self):
        rid = max(r['id'] for r in self.rows)
        self.rows.append({'id': rid + 1, 'chat': 9003, 'msg': rid + 1, 'ts': NOW - 86400, 'edit_ts': None, 'out': 0,
                          'sid': 7, 'sender': 'Zed', 'kind': 'dm', 'text': 'Velotour ' * 170})   # 1530 chars
        r = self.build()
        self.assertEqual(db_set(self.ix), chunk_set(self.rows))
        self.assertEqual((r['chunks'], self.ix.skipped), (len(IX.chunk_rows(self.rows)), 0))

    def test_incremental_reconcile_and_purge(self):
        self.build()
        d = self.ix.db()
        before = dict(d.c.execute('SELECT mac, id FROM chunks'))
        last = max(self.rows, key=lambda r: (r['chat'] == 9000, r['ts']))
        rid = max(r['id'] for r in self.rows)
        self.rows += [dict(last, id=rid + 1, msg=rid + 1, ts=last['ts'] + 120, text='Nachtrag Grill ab sechs'),
                      dict(last, id=rid + 2, msg=rid + 2, chat=9100, ts=last['ts'] + 200, text='neuer Chat Velotour')]
        self.ix.poke()
        self.assertIsNone(self.ix.due(self.now[0] + 5))   # debounced
        self.now[0] += IX.DEBOUNCE_S + 1
        self.assertEqual(self.ix.due(self.now[0]), 'update')
        r = self.ix.step()
        self.assertTrue(r['added'] >= 2 and r['deleted'] >= 1, r)
        self.assertEqual(db_set(self.ix), chunk_set(self.rows))
        after = dict(d.c.execute('SELECT mac, id FROM chunks'))
        self.assertTrue(len(set(before) & set(after)) >= len(before) - 2)   # the rest kept their vectors
        # an edit and a deletion: the nightly reconcile
        i = next(k for k, x in enumerate(self.rows) if x['chat'] == 9001)
        self.rows[i] = dict(self.rows[i], text=self.rows[i]['text'] + ' korrigiert', edit_ts=NOW)
        del self.rows[i + 4]
        self.now[0] += 86400
        self.assertEqual(self.ix.due(self.now[0]), 'reconcile')
        self.ix.step()
        self.assertEqual(db_set(self.ix), chunk_set(self.rows))
        # purge: the chat's chunks go at once, before any reconcile
        self.tg.gone_chats.add(9002)
        n2 = sum(1 for c, _ in db_set(self.ix) if c == 9002)
        self.ix.on_purge('purge', {'chat': 'Lea', 'yes': True})
        self.assertFalse([c for c, _ in db_set(self.ix) if c == 9002])
        ev = [e for e in self.audit.lines if e['event'] == 'index_purge'][-1]
        self.assertEqual((ev['cmd'], ev['chunks_deleted']), ('purge', n2))
        self.ix.on_purge('wipe', {'session': True})       # session only: the index stays
        self.assertTrue(self.ix.db_path.exists())
        self.ix.on_purge('wipe', {'data': True, 'yes': True})
        self.assertFalse(self.ix.db_path.exists())
        self.assertEqual(self.ix.unavailable(), 'not_built')

    def test_purge_fails_closed_and_aborts_a_running_build(self):
        self.build()
        self.tg.index_chats = lambda: (_ for _ in ()).throw(RuntimeError('tgread down'))
        self.ix.on_purge('exclude', {'action': 'add', 'chat': 'x'})
        self.assertFalse(self.ix.db_path.exists())         # can't tell which chat: the whole index goes
        self.tg.index_chats = lambda: sorted({r['chat'] for r in self.rows} - self.tg.gone_chats)
        uses = [0]
        real = self.ix._embed_docs

        def purge_midway(docs, what):
            uses[0] += 1
            if uses[0] == 3:                               # a purge lands while the build embeds
                self.tg.gone_chats.add(9001)
                self.ix.on_purge('purge', {'chat': 'x'})
            return real(docs, what)
        self.ix._embed_docs = purge_midway
        self.assertIsNone(self.ix.step())                  # aborted, nothing swapped in
        self.assertFalse(self.ix.db_path.exists())
        self.assertTrue(self.ix.rebuild_wanted)
        self.ix._embed_docs = real
        self.ix.step()                                     # resumes into the shadow file, then swaps
        self.assertEqual(db_set(self.ix), chunk_set([r for r in self.rows if r['chat'] != 9001]))

    def test_retrieve_hybrid_cap_budget_filters(self):
        self.build()
        hits = self.tg.find_hits('Zahnarzttermin')
        res = self.ix.retrieve('Zahnarzttermin verschoben Dienstag Nachmittag',
                               [(h['chat_id'], h['msg_id']) for h in hits], budget=1500)
        self.assertTrue(res['chunks'] and res['vector_hits'] and res['keyword_hits'])
        self.assertLessEqual(res['chars'], 1500 + max(c['chars'] for c in res['chunks']))
        per = {}
        for c in res['chunks']:
            per[c['chat']] = per.get(c['chat'], 0) + 1
        self.assertTrue(max(per.values()) <= IX.PER_CHAT)
        texts = {(r['chat'], r['msg']): r['text'] for r in self.rows}
        top = res['chunks'][0]
        self.assertTrue(any('Zahnarzttermin' in texts[(top['chat'], m)] for m in top['msgs']))
        one = self.ix.retrieve('Zahnarzttermin verschoben', (), chat=9001, budget=4000, cap=None, recency=True)
        self.assertTrue(one['chunks'] and all(c['chat'] == 9001 for c in one['chunks']))
        late = self.ix.retrieve('Zahnarzttermin', (), since_ts=NOW - 30 * 86400)
        self.assertTrue(all(c['ts_last'] >= NOW - 30 * 86400 for c in late['chunks']))
        for c in res['chunks']:                            # ids and numbers only
            self.assertEqual(set(c), {'id', 'chat', 'ts_first', 'ts_last', 'chars', 'msgs'})
        self.ix.server.stop()
        with self.assertRaises(IX.Unavailable) as e:
            self.ix.retrieve('x')
        self.assertEqual(e.exception.reason, 'embed_down')

    def test_answer_hybrid_fallback_and_session(self):
        import answer as AN
        self.build()
        cfg = type('C', (), {'state': self.cfg.state, 'index_on': True, 'ask_sessions': True})()
        an = AN.Answer(cfg, IdPolicy(), self.gate, FakeAudit(), tg=self.tg, clock=lambda: self.now[0])
        an.index = self.ix
        seen = []
        an.run_json = lambda kind, text, cls, what: seen.append(text) or '{}'
        b = {'source': 'tg', 'query': 'Zahnarzttermin', 'since': '500d', 'kind': 'yesno',
             'question': 'Wurde der Zahnarzttermin verschoben?'}
        r = an.run(dict(b))
        ret = r['retrieval']
        self.assertEqual(ret['mode'], 'hybrid')
        self.assertTrue(ret['chunks'] >= 1 and ret['vector_hits'] >= 1 and 0 < ret['chars'] <= 2600, ret)
        self.assertEqual(r['parts'], 1)
        self.assertIn('Zahnarzttermin', seen[-1])
        for v in strings(ret):
            for bit in SECRET_BITS:
                self.assertNotIn(bit, v)
        r2 = an.run(dict(b, retrieval='keyword'))          # per-call switch
        self.assertEqual(r2['retrieval']['mode'], 'keyword')
        r3 = an.run(dict(b, **{'from': 'Tim'}))            # filters: tgread's keyword search
        self.assertEqual(r3['retrieval'], {'mode': 'keyword', 'keyword_hits': r3['messages'], 'fallback': 'filters'})
        with self.assertRaises(V.VaultError):
            an.run(dict(b, retrieval='magic'))
        cfg.index_on = False                               # VAULT_INDEX off: today's path by default
        self.assertEqual(an.run(dict(b))['retrieval']['mode'], 'keyword')
        cfg.index_on = True
        self.ix.server.stop()                              # embed server down: keyword per call, with the reason
        r4 = an.run(dict(b))
        self.assertEqual((r4['retrieval']['mode'], r4['retrieval']['fallback']), ('keyword', 'embed_down'))

    def test_ranked_chat_window_and_session_followup(self):
        import answer as AN
        self.build()
        cfg = type('C', (), {'state': self.cfg.state, 'index_on': True, 'ask_sessions': True})()
        an = AN.Answer(cfg, IdPolicy(), self.gate, FakeAudit(), tg=self.tg, clock=lambda: self.now[0])
        an.index = self.ix
        an.run_json = lambda kind, text, cls, what: '{}'
        rows = sorted((r for r in self.rows if r['chat'] == 9001), key=lambda r: r['ts'])
        msgs = [{'ts': time.strftime('%Y-%m-%d %H:%M', time.localtime(r['ts'])), 'sender': r['sender'],
                 'text': r['text'], 'ref': f"#{r['msg']}"} for r in rows]
        self.assertGreater(len(AN.FX.chunks(msgs, AN.CHUNK_CHARS)), 1)
        sel, info = an.ranked_chat('hybrid', 'yesno', 'Zahnarzttermin verschoben?', '500d', msgs, '9001')
        self.assertEqual(info['mode'], 'ranked')
        self.assertTrue(0 < len(sel) < len(msgs) and info['window_messages'] == len(msgs))
        self.assertLessEqual(AN.part_size(sel), AN.CHUNK_CHARS)
        self.assertTrue(any('Zahnarzttermin' in m['text'] for m in sel))
        for kind in ('count', 'requests', 'interests'):    # exhaustive kinds read the whole window
            self.assertEqual(an.ranked_chat('hybrid', kind, 'q', '500d', msgs, '9001'), (msgs, {'mode': 'window'}))
        self.assertEqual(an.ranked_chat('keyword', 'yesno', 'q', '500d', msgs, '9001')[0], msgs)
        # a hybrid ask with a session: the follow-up reads exactly the same picked messages
        b = {'source': 'tg', 'query': 'Festivaltickets', 'since': '500d', 'kind': 'yesno',
             'question': 'Gibt es noch Festivaltickets?', 'session': True}
        r = an.run(b, owner='o')
        self.assertEqual(r['retrieval']['mode'], 'hybrid')
        n = len(self.tg.line_calls)
        r2 = an.run({'session': r['session']['id'], 'question': 'und wann?'}, owner='o')
        self.assertEqual(len(self.tg.line_calls), n + 1)
        self.assertEqual(self.tg.line_calls[-1], self.tg.line_calls[n - 1])
        self.assertEqual(r2['messages'], r['messages'])


if __name__ == '__main__':
    unittest.main(verbosity=1)
