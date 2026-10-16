#!/usr/bin/python3 -I
"""Document intake tests (app/intake.py, privacy plan D 2026-10-14): the owner's photos and PDFs sent to the vault bot
go into paperless. Strangers ignored and audited, the type from the bytes (HEIC and fakes refused), tags Inbox +
via-bot, the reply with tier-1 fields, albums merged into one PDF, 30 files per hour, duplicates, the audit (doc id +
sha only), the feed event, /intake/status counts, and the bot routing (CSV/XLSX/ZIP still to finance).
No network: Telegram and paperless are local fakes; synthetic documents only."""
import base64
import hashlib
import http.server
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'app'))
TMP = Path(tempfile.mkdtemp(prefix='vault-intake-tests-'))
for k in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY'):
    os.environ.pop(k, None)

import intake as I  # noqa: E402
import sources as S  # noqa: E402
import vaultlib as V  # noqa: E402

try:
    from PIL import Image
except ImportError:                                      # the image has python3-pil; a bare host may not
    Image = None
needs_pil = unittest.skipUnless(Image, 'no Pillow here')

BOT_ID = 7099887711
BOT_TOKEN = f'{BOT_ID}:' + 'AAF' + 'k' * 32
CHAT_ID = '123456789'
PL_TOKEN = 'pl' + 'fedcba9876543210' * 2 + 'qq'
IBAN = 'CH93' + '0076' + '2011' + '6238' + '5295' + '7'
CAPTION = 'Zahnarzt Rechnung Oktober'


def make_pdf(lines):
    """A minimal valid one-page PDF with a text layer (Helvetica)."""
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


BILL_TEXT = ['Zahnarztpraxis Beispiel AG', 'Rechnung Nr. R-77', 'Rechnungsdatum 01.10.2026', 'Zahlbar bis 31.10.2026',
             'Total CHF 210.50', f'IBAN {IBAN}']
BILL_PDF = make_pdf(BILL_TEXT)
LETTER_PDF = make_pdf(['Gemeinde Beispiel', 'Einladung zur Versammlung'])
HEIC = b'\x00\x00\x00\x18ftypheic' + b'\x00' * 200


def jpeg(color):
    b = io.BytesIO()
    Image.new('RGB', (60, 80), color).save(b, format='JPEG')
    return b.getvalue()


class FakeServer:
    def __init__(self):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                with outer.lock:
                    st, ctype, data = outer.handle(method, self.path, self.headers, body)
                self.send_response(st)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = lambda self: self._do('GET')          # noqa: E731
            do_POST = lambda self: self._do('POST')        # noqa: E731
            do_PATCH = lambda self: self._do('PATCH')      # noqa: E731

        self.lock = threading.Lock()
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.srv.server_address[1]}'
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def jr(obj, st=200):
    return st, 'application/json', json.dumps(obj).encode()


class FakeBot(FakeServer):
    def __init__(self):
        super().__init__()
        self.reset()

    def reset(self):
        self.sent, self.calls, self.files, self.updates = [], [], {}, []

    def handle(self, method, path, headers, body):
        m = re.fullmatch(r'/file/bot([^/]+)/(.+)', path)
        if m:
            self.calls.append(('download', m.group(2)))
            if m.group(1) != BOT_TOKEN or urllib.parse.unquote(m.group(2)) not in self.files:
                return 404, 'text/plain', b'not found'
            return 200, 'application/octet-stream', self.files[urllib.parse.unquote(m.group(2))]
        m = re.fullmatch(r'/bot([^/]+)/(\w+)', path)
        if not m or m.group(1) != BOT_TOKEN:
            return jr({'ok': False, 'description': 'Unauthorized'}, 401)
        meth, p = m.group(2), dict(urllib.parse.parse_qsl(body.decode()))
        self.calls.append((meth, p))
        if meth == 'sendMessage':
            self.sent.append(p)
            return jr({'ok': True, 'result': {'message_id': 500 + len(self.sent)}})
        if meth == 'getFile':
            fid = p['file_id']
            if fid not in self.files:
                return jr({'ok': False, 'description': 'Bad Request: invalid file_id'}, 400)
            return jr({'ok': True, 'result': {'file_id': fid, 'file_path': fid, 'file_size': len(self.files[fid])}})
        if meth == 'getUpdates':
            return jr({'ok': True, 'result': [u for u in self.updates if u['update_id'] >= int(p.get('offset') or 0)]})
        if meth == 'answerCallbackQuery':
            return jr({'ok': True, 'result': True})
        return jr({'ok': False, 'description': 'method not faked'}, 404)

    def _fid(self, data):
        fid = f'files/f{len(self.files)}_{hashlib.sha1(data).hexdigest()[:8]}'
        self.files[fid] = data
        return fid

    def doc(self, name, data, mime=None, chat=CHAT_ID, frm=None, caption=None, group=None):
        m = {'message_id': 10, 'from': {'id': int(frm or chat)}, 'chat': {'id': int(chat), 'type': 'private'},
             'document': {'file_id': self._fid(data), 'file_name': name, 'file_size': len(data)}}
        if mime:
            m['document']['mime_type'] = mime
        if caption:
            m['caption'] = caption
        if group:
            m['media_group_id'] = group
        return m

    def photo(self, data, chat=CHAT_ID, caption=None, group=None):
        fid = self._fid(data)
        m = {'message_id': 11, 'from': {'id': int(chat)}, 'chat': {'id': int(chat), 'type': 'private'},
             'photo': [{'file_id': 'thumb-not-downloaded', 'file_size': 10, 'width': 9},
                       {'file_id': fid, 'file_size': len(data), 'width': 60}]}
        if caption:
            m['caption'] = caption
        if group:
            m['media_group_id'] = group
        return m


class FakePaperless(FakeServer):
    """post_document (multipart recorded), tasks (duplicates fail like paperless), documents/<id>/ + download,
    tags/correspondents/document_types (tags can be created)."""

    def __init__(self):
        super().__init__()
        self.reset()

    def reset(self):
        self.uploads, self.docs, self.by_sha, self.tasks = [], {}, {}, {}
        self.tax = {'tags': {1: {'id': 1, 'name': 'Inbox', 'is_inbox_tag': True}},
                    'correspondents': {5: {'id': 5, 'name': 'Zahnarztpraxis Beispiel AG'}},
                    'document_types': {6: {'id': 6, 'name': 'Rechnung'}}}
        self.next_doc, self.next_tax = 42, 50

    @staticmethod
    def parts(body, headers):
        bnd = re.search(r'boundary=(\S+)', headers.get('Content-Type') or '').group(1).encode()
        out = []
        for chunk in body.split(b'--' + bnd)[1:-1]:
            head, _, data = chunk.partition(b'\r\n\r\n')
            name = re.search(rb'name="([^"]+)"', head).group(1).decode()
            fn = re.search(rb'filename="([^"]+)"', head)
            out.append((name, fn.group(1).decode() if fn else None, data[:-2]))
        return out

    def handle(self, method, path, headers, body):
        if headers.get('Authorization') != f'Token {PL_TOKEN}':
            return jr({'detail': 'Invalid token.'}, 401)
        u = urllib.parse.urlsplit(path)
        q = dict(urllib.parse.parse_qsl(u.query))
        m = re.fullmatch(r'/api/(tags|correspondents|document_types)/', u.path)
        if m and method == 'GET':
            lst = list(self.tax[m.group(1)].values())
            return jr({'count': len(lst), 'next': None, 'results': lst})
        if m and method == 'POST':
            self.next_tax += 1
            o = dict(json.loads(body), id=self.next_tax)
            self.tax[m.group(1)][o['id']] = o
            return jr(o, 201)
        if u.path == '/api/documents/post_document/' and method == 'POST':
            parts = self.parts(body, headers)
            self.uploads.append(parts)
            data = next(d for n, f, d in parts if n == 'document')
            sha = hashlib.sha256(data).hexdigest()
            tid = f'task-{len(self.uploads)}'
            if sha in self.by_sha:
                self.tasks[tid] = {'task_id': tid, 'status': 'FAILURE',
                                   'result': f'Not consuming x: It is a duplicate of y (#{self.by_sha[sha]}).'}
            else:
                did = self.next_doc
                self.next_doc += 1
                self.by_sha[sha] = did
                title = next((d.decode() for n, f, d in parts if n == 'title'), None)
                fn = next(f for n, f, d in parts if n == 'document')
                bill = data == BILL_PDF or data.startswith(b'%PDF') and b'Zahn' not in data and data != LETTER_PDF
                self.docs[did] = {'id': did, 'title': title or fn.rsplit('.', 1)[0], 'created': '2026-10-01T00:00:00',
                                  'added': '2026-10-14T10:00:00', 'modified': '2026-10-14T10:00:00',
                                  'correspondent': 5 if bill else None, 'document_type': 6 if bill else None,
                                  'tags': [int(d) for n, f, d in parts if n == 'tags'],
                                  'content': '\n'.join(BILL_TEXT) if bill else 'Gemeinde Beispiel Einladung',
                                  'original_file_name': fn, 'page_count': 1, 'notes': [], '_file': data}
                self.tasks[tid] = {'task_id': tid, 'status': 'SUCCESS', 'related_document': str(did)}
            return jr(tid)
        if u.path == '/api/tasks/':
            return jr([self.tasks[q['task_id']]])
        m = re.fullmatch(r'/api/documents/(\d+)/(download/)?', u.path)
        if m and method == 'GET':
            d = self.docs.get(int(m.group(1)))
            if not d:
                return jr({'detail': 'Not found.'}, 404)
            if m.group(2):
                return 200, 'application/pdf', d['_file']
            return jr({k: v for k, v in d.items() if k != '_file'})
        return jr({'detail': 'no route'}, 404)


BOT = FakeBot()
PL = FakePaperless()


class Base(unittest.TestCase):
    def setUp(self):
        BOT.reset()
        PL.reset()
        d = TMP / self._testMethodName
        env = {'VAULT_DATA': str(d), 'VAULT_APP': str(ROOT), 'VAULT_TELEGRAM_API': BOT.url, 'VAULT_NO_LLAMA': '1',
               'VAULT_NO_SYNC': '1'}
        self.cfg = V.Config(env)
        for x in (self.cfg.data, self.cfg.home, self.cfg.state, self.cfg.cache, self.cfg.tmp):
            V.ensure_dir(x)
        self.store = V.SecretStore(self.cfg)
        self.store.set('telegram', {'bot_token': BOT_TOKEN, 'chat_id': CHAT_ID})
        self.store.set('paperless', {'url': PL.url, 'token': PL_TOKEN})
        self.notifier = V.Notifier(self.store, BOT.url)
        self.audit = V.Audit(self.cfg.audit_path)
        self.gate = V.LLMGate()
        self.policy = V.Policy(self.cfg, self.gate)
        self.paperless = S.Paperless(self.cfg, self.store, self.policy, self.gate, self.audit)
        self.events = V.EventStore(self.cfg.state / 'events.db')
        self.logs = []
        self.it = I.Intake(self.cfg, self.store, self.notifier, self.audit, self.paperless, events=self.events,
                           log=self.logs.append)

    def send(self, *msgs):
        for m in msgs:
            self.assertTrue(I.wants(m), m)
            self.it.on_message(m)
        self.it.drain()

    def evs(self, name=None):
        ev = self.audit.read(days=1)
        return [e for e in ev if e['event'] == name] if name else [e['event'] for e in ev]

    def tags_of_upload(self, i=-1):
        names = {o['id']: o['name'] for o in PL.tax['tags'].values()}
        return sorted(names[int(d)] for n, f, d in PL.uploads[i] if n == 'tags')


class IntakeTests(Base):
    def test_refuses_other_chats(self):
        self.it.on_message(BOT.doc('x.pdf', BILL_PDF, 'application/pdf', chat='555', frm='555'))
        self.it.on_message(BOT.doc('x.pdf', BILL_PDF, 'application/pdf', chat=CHAT_ID, frm='555'))  # a group member
        self.it.drain()
        self.assertEqual((PL.uploads, BOT.sent), ([], []))
        self.assertFalse([c for c in BOT.calls if c[0] in ('getFile', 'download')])
        self.assertEqual(self.evs().count('intake_refused'), 2)
        self.assertIn('intake_refused', V.ApprovalBot.SECURITY_EVENTS)
        self.assertEqual(self.it.status()['refused'], 2)

    def test_pdf_filed_with_tags_reply_event_and_audit(self):
        self.send(BOT.doc('Rechnung Zahnarzt Okt.pdf', BILL_PDF, 'application/pdf', caption=CAPTION))
        self.assertEqual(len(PL.uploads), 1)
        self.assertEqual(self.tags_of_upload(), ['Inbox', 'via-bot'])          # via-bot created on the way
        parts = {n: (f, d) for n, f, d in PL.uploads[0]}
        self.assertEqual(parts['title'][1].decode(), CAPTION)
        self.assertTrue(parts['document'][0].startswith('via-bot-') and parts['document'][0].endswith('.pdf'))
        reply = BOT.sent[-1]['text']
        self.assertTrue(reply.startswith(f'📄 Filed as #42 "{CAPTION}"\nRechnung · Zahnarztpraxis Beispiel AG\n'
                                         f'💰 CHF 210.50 · due Sat 31.10'), reply)   # short lines
        self.assertEqual(BOT.sent[-1]['protect_content'], 'true')
        self.assertNotIn(IBAN, reply)
        rec = self.evs('intake_filed')[-1]
        self.assertEqual((rec['doc_id'], rec['size'], rec['sha12'], rec['bill_likely']),
                         (42, len(BILL_PDF), hashlib.sha256(BILL_PDF).hexdigest()[:12], True))
        audit = self.cfg.audit_path.read_text()
        for private in (CAPTION, 'Rechnung Zahnarzt', 'Zahnarztpraxis', IBAN, '210.50'):
            self.assertNotIn(private, audit)                           # doc id + sha only
        self.assertNotIn('paperless_upload', self.evs())               # the generic upload line (with title) is off
        rows, _, _, _ = self.events.since(0)
        self.assertEqual(len(rows), 1)
        e = rows[0]
        self.assertEqual((e['source'], e['label'], e['actionable'], e['ref'], e['text']),
                         ('paperless', 'filed', 1, 'paperless:42', None))
        self.assertEqual(json.loads(e['doc']), {'doc_id': 42, 'type': 'Rechnung',
                                                'correspondent': 'Zahnarztpraxis Beispiel AG', 'bill_likely': True})
        st = self.it.status()
        self.assertEqual((st['filed'], st['last_hour'], st['limit_per_hour']), (1, 1, 30))
        self.assertNotIn(CAPTION, json.dumps(st))

    def test_letter_is_not_a_bill(self):
        self.send(BOT.doc('brief.pdf', LETTER_PDF, 'application/pdf'))
        reply = BOT.sent[-1]['text']
        self.assertTrue(reply.startswith('📄 Filed as #42'), reply)
        self.assertNotIn('due', reply)
        self.assertEqual(self.events.since(0)[0][0]['actionable'], 0)

    def test_wrong_types_refused(self):
        self.send(BOT.doc('rechnung.pdf', b'\x7fELF' + b'\x00' * 300, 'application/pdf'))
        self.assertIn('Not filed', BOT.sent[-1]['text'])
        self.assertIn('a program', BOT.sent[-1]['text'])
        self.send(BOT.doc('IMG_0001.HEIC', HEIC, 'image/heic'))
        self.assertIn('HEIC', BOT.sent[-1]['text'])
        self.send(BOT.doc('notes.pdf', b'just some text that is not a pdf at all\n' * 3, 'application/pdf'))
        self.assertIn('Not filed', BOT.sent[-1]['text'])
        self.assertEqual(PL.uploads, [])
        self.assertEqual(self.it.status()['rejected'], 3)
        self.assertEqual(len(self.evs('intake_rejected')), 3)

    def test_too_big_never_downloaded(self):
        m = BOT.doc('big.pdf', BILL_PDF, 'application/pdf')
        m['document']['file_size'] = I.MAX_FILE + 1
        self.send(m)
        self.assertIn('over 20 MB', BOT.sent[-1]['text'])
        self.assertFalse([c for c in BOT.calls if c[0] in ('getFile', 'download')])

    def test_duplicate(self):
        self.send(BOT.doc('a.pdf', BILL_PDF, 'application/pdf'))
        self.send(BOT.doc('b.pdf', BILL_PDF, 'application/pdf'))
        self.assertIn('Already in paperless', BOT.sent[-1]['text'])
        self.assertEqual((self.it.status()['filed'], self.it.status()['duplicates']), (1, 1))

    @needs_pil
    def test_album_of_photos_becomes_one_pdf(self):
        g = 'album-1'
        self.send(BOT.photo(jpeg('white'), group=g, caption='Mietvertrag'), BOT.photo(jpeg('gray'), group=g),
                  BOT.photo(jpeg('black'), group=g))
        self.assertEqual(len(PL.uploads), 1)
        parts = {n: (f, d) for n, f, d in PL.uploads[0]}
        self.assertTrue(parts['document'][0].endswith('.pdf'))
        self.assertTrue(parts['document'][1].startswith(b'%PDF'))
        self.assertEqual(parts['title'][1].decode(), 'Mietvertrag')
        self.assertIn('(3 photos merged into one PDF)', BOT.sent[-1]['text'])
        self.assertEqual(self.evs('intake_filed')[-1]['pages'], 3)
        self.assertNotIn('thumb-not-downloaded', json.dumps(BOT.calls))       # the largest size only

    @needs_pil
    def test_single_photo_and_album_with_a_pdf(self):
        self.send(BOT.photo(jpeg('white')))
        self.assertTrue(PL.uploads[-1][-1][1].endswith('.jpg'))
        g = 'album-2'
        self.send(BOT.photo(jpeg('gray'), group=g), BOT.doc('brief.pdf', LETTER_PDF, 'application/pdf', group=g))
        self.assertEqual([p[-1][1].rsplit('.', 1)[-1] for p in PL.uploads], ['jpg', 'jpg', 'pdf'])

    def test_rate_limit_30_per_hour(self):
        for i in range(I.MAX_PER_HOUR):
            self.it.on_message(BOT.doc(f'{i}.pdf', make_pdf([f'Dokument {i}']), 'application/pdf'))
        self.assertEqual(self.it.q.qsize(), I.MAX_PER_HOUR)
        n = len(BOT.sent)
        self.it.on_message(BOT.doc('31.pdf', BILL_PDF, 'application/pdf'))
        self.it.on_message(BOT.doc('32.pdf', BILL_PDF, 'application/pdf'))
        self.assertEqual(self.it.q.qsize(), I.MAX_PER_HOUR)
        self.assertEqual(len(BOT.sent), n + 1)                               # told once, not per file
        self.assertIn('limit reached', BOT.sent[-1]['text'])
        self.assertEqual(self.it.status()['rate_limited'], 2)
        self.assertEqual(len(self.evs('intake_rate_limited')), 2)


class RoutingTests(Base):
    def test_wants(self):
        self.assertTrue(I.wants(BOT.doc('x.pdf', BILL_PDF)))
        self.assertTrue(I.wants(BOT.doc('scan', b'x', 'image/jpeg')))
        self.assertTrue(I.wants(BOT.photo(b'x')))
        for name, mime in (('export.csv', 'text/csv'), ('statement.xlsx', None), ('raw.zip', 'application/zip')):
            self.assertFalse(I.wants(BOT.doc(name, b'x', mime)), name)
        self.assertFalse(I.wants({'text': '/fsync', 'from': {'id': 1}, 'chat': {'id': 1}}))

    def test_bot_routes_documents_to_intake_and_exports_to_finance(self):
        bot = V.ApprovalBot(self.cfg, self.store, self.notifier, self.audit, log=lambda m: None)
        bot.st['shared_bot_ids'] = []
        got = []
        bot.finance = type('Fin', (), {'on_message': lambda s, m: got.append(('finance', (m.get('document') or {})
                                                                            .get('file_name') or m.get('text')))})()
        bot.intake = type('In', (), {'wants': staticmethod(I.wants),
                                     'on_message': lambda s, m: got.append(('intake', (m.get('document') or {})
                                                                           .get('file_name') or 'photo'))})()
        msgs = [BOT.doc('export.csv', b'a;b', 'text/csv'), BOT.doc('bill.pdf', BILL_PDF, 'application/pdf'),
                BOT.photo(b'x'), BOT.doc('CardBank.xlsx', b'PK', None), BOT.doc('raw.zip', b'PK', 'application/zip'),
                {'text': '/fsync', 'from': {'id': int(CHAT_ID)}, 'chat': {'id': int(CHAT_ID)}}]
        BOT.updates = [{'update_id': i + 1, 'message': m} for i, m in enumerate(msgs)]
        self.assertEqual(bot.step(), 0)
        self.assertEqual(got, [('finance', 'export.csv'), ('intake', 'bill.pdf'), ('intake', 'photo'),
                               ('finance', 'CardBank.xlsx'), ('finance', 'raw.zip'), ('finance', '/fsync')])

    def test_app_wiring_and_status_route(self):
        import vaultd as D
        self.assertIn(('GET', '/intake/status'), D.App.ROUTES)
        self.assertFalse([k for k in D.App.ROUTES if 'intake' in k[1] and k[0] != 'GET'])   # no upload route
        src = (ROOT / 'app' / 'intake.py').read_text()
        self.assertNotIn("audit.log('intake_filed', doc_id=doc_id, title", src)


if __name__ == '__main__':
    unittest.main(verbosity=1)
