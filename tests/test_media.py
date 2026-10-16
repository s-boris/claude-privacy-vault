#!/usr/bin/python3 -I
"""Media requests (plan v2 #1, 2026-09-22): the list is metadata only with privacy-filtered names (excluded chats
refused); a bundle goes through the owner's approval (preview with name, type, size, chat and date only in his
message, never in the API response); Allow once / Facts only / Deny; real types from the bytes (.exe/.zip refused);
bundle, keep and daily-byte limits; expiry, single pickup, sha256; acks and the overdue alert; extraction keeps
flight times and airports and drops the PNR, ticket number, price and invented fields; an LLM failure returns no
text; .ics attendee addresses masked; the client's folder, record file, gc and acks.
Run: python3 -I tests/test_media.py (uses test_vault.py's fakes and stub LLM)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402

import base64  # noqa: E402
import hashlib  # noqa: E402
import importlib.machinery  # noqa: E402
import importlib.util  # noqa: E402
import io  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
import zipfile  # noqa: E402
from pathlib import Path  # noqa: E402

import media as M  # noqa: E402

V, D = TV.V, TV.D

TICKET = ['EXAMPLE AIR   E-TICKET RECEIPT & ITINERARY',
          'Passenger: Alex MUSTER',
          'Booking reference (PNR): ABC12D',
          'Ticket number: 607-2345678901',
          'Flight LH 0074   Zurich (ZRH) - Frankfurt (FRA)   31 Oct 2026   Departure 10:05   Arrival 18:20   Terminal 1',
          'Flight LH 0622   Frankfurt (FRA) - Funchal (FNC)   1 Nov 2026   Departure 02:40   Arrival 07:55',
          'Baggage: 1 PC 23 kg',
          'Fare: CHF 1,234.50   Taxes CHF 312.40   Total CHF 1,546.90']
PDF = TV.make_pdf(TICKET)
LLM_TRAVEL = {'segments': [
    {'carrier': 'Example Air', 'number': 'LH 0074', 'from': 'ZRH', 'to': 'FRA', 'dep_date': '31 Oct 2026', 'dep_time': '10:05',
     'arr_date': '31 Oct 2026', 'arr_time': '18:20', 'terminal': '1', 'gate': 'B12'},
    {'carrier': 'Example Air', 'number': 'LH 0622', 'from': 'FRA', 'to': 'FNC', 'dep_date': '1 Nov 2026',
     'dep_time': '02:40', 'arr_time': '07:55'},
    {'number': 'LH 999', 'dep_time': '11:11'}],
    'baggage': '1 PC 23 kg', 'passengers': ['Alex'], 'pnr': 'ABC12D', 'price': 'CHF 1,234.50'}
ICS = ('BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Tauchgang Example Reef\r\nDTSTART:20261102T053000Z\r\n'
       'DTEND:20261102T090000Z\r\nLOCATION:Example Beach\\, Funchal\r\nATTENDEE;CN=Lisa Muster:mailto:lisa.muster@example.com'
       '\r\nATTENDEE:mailto:peter.keller@example.org\r\nORGANIZER;CN=Dive Center:mailto:info@dive.example\r\n'
       'END:VEVENT\r\nEND:VCALENDAR\r\n').encode()
SECRET_WORDS = ('ABC12D', '607-2345678901', '1,234.50', '312.40', 'B12', 'LH 999')


def zip_bytes(names):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for n in names:
            z.writestr(n, 'x')
    return b.getvalue()


FILES = {11: ('Example Air_eticket.pdf', PDF, 'application/pdf', 'Patrick'),
         12: ('Herzschmerz_Befund.pdf', TV.make_pdf(['Befund']), 'application/pdf', 'You'),
         13: ('setup.pdf', b'MZ\x90\x00' + b'\0' * 200, 'application/pdf', 'Patrick'),
         14: ('photos.zip', zip_bytes(['a.jpg', 'b.jpg']), 'application/zip', 'Patrick'),
         15: (None, b'\xff\xd8\xff\xe0' + b'\0' * 3000, 'image/jpeg', 'Patrick'),
         16: ('dive.ics', ICS, 'text/calendar', 'Patrick'),
         17: ('big.pdf', b'%PDF-1.4\n' + b'0' * 64, 'application/pdf', 'Patrick'),
         18: ('MAX MUSTER-X7K2LM-30OCT-2135-ZRH.pdf', PDF, 'application/pdf', 'Patrick')}


def fake_media_list(chat, msg=None, n=30, since=None, mtype=None):
    if str(chat) == 'Familie':
        raise V.VaultError('tgread media: that chat is excluded from the archive', 404, 'not_found')
    items = [{'msg': k, 'date': f'2026-09-07 18:{k:02d}', 'type': 'photo' if k == 15 else 'document',
              'name': v[0], 'size': len(v[1]) if k != 17 else 60 << 20, 'mime': v[2], 'duration': None, 'from': v[3]}
             for k, v in sorted(FILES.items())]
    items = [i for i in items if (msg is None or i['msg'] == msg) and (mtype is None or i['type'] == mtype)]
    return {'chat': {'id': -301, 'type': 'group', 'label': 'Grouptrip 2026'}, 'items': items[:n]}


def fake_raw_file(chat, msg, max_mb=20):
    name, data = FILES[msg][0], FILES[msg][1]
    return name or f'-301_{msg}.jpg', data


class SniffTests(unittest.TestCase):
    def test_real_type_from_bytes(self):
        ok = {b'%PDF-1.7\n': 'pdf', b'\xff\xd8\xff\xe1': 'jpeg', b'\x89PNG\r\n\x1a\n': 'png', b'OggS\0\2': 'ogg',
              b'\0\0\0\x18ftypisom': 'mp4', b'\0\0\0\x18ftypM4A ': 'm4a', b'BEGIN:VCALENDAR\r\n': 'ics',
              'Hallo Welt'.encode(): 'txt', zip_bytes(['[Content_Types].xml', 'word/document.xml']): 'docx'}
        for data, typ in ok.items():
            self.assertEqual(M.sniff(data), (typ, None), data[:12])
        for data in (b'MZ\x90\x00', b'\x7fELF\2\1', b'#!/bin/sh\nrm -rf /', zip_bytes(['a.txt']), b'Rar!\x1a\x07',
                     b'\x1f\x8b\x08\0', b'<html><script>alert(1)</script>', b'\xd0\xcf\x11\xe0\xa1\xb1',
                     zip_bytes(['[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin'])):
            typ, why = M.sniff(data)
            self.assertIsNone(typ, data[:12])
            self.assertTrue(why)

    def test_clean_name_and_keys(self):
        self.assertEqual(M.clean_name('../../.ssh/id_rsa', 'txt'), 'id_rsa.txt')
        self.assertEqual(M.clean_name('Foto.png', 'jpeg'), 'Foto.png.jpg')
        self.assertEqual(M.parse_key('gmail:work:12@[Gmail]/All Mail#2'), ('gmail', {'ref': 'work:12@[Gmail]/All Mail', 'n': 2}))
        self.assertEqual(M.parse_key('paperless:7:archived'), ('paperless', {'id': 7, 'archived': True}))
        for bad in ('tg:x:1', 'paperless:', 'gmail:main:1', 'file:/etc/passwd'):
            with self.assertRaises(V.VaultError):
                M.parse_key(bad)


class Approver:
    def healthy(self):
        return True


class RawMediaTests(unittest.TestCase):
    """The state machine with the third button (unit level, buttons mode)."""

    def setUp(self):
        self.cfg = TV.make_cfg(f'media-raw-{self._testMethodName}')
        self.audit = V.Audit(self.cfg.audit_path)
        self.n = TV.FakeNotifier()
        self.raw = V.RawRequests(self.n, self.audit, b'k' * 32, approver=Approver())

    def payload(self, size=10):
        return {'keep': 120, 'files': [{'key': 'tg:1:2', 'source': 'tg', 'name': 'x.pdf', 'type': 'pdf', 'size': size,
                                        'sha256': 'ab' * 32, 'data': b'%PDF' + b'0' * (size - 4)}]}

    def test_facts_button_and_single_pickup(self):
        r = self.raw.create('media', 'tg:1:2', 'flight times', self.payload(), kind='media',
                            preview=['📎 x.pdf (PDF, 10 bytes) · Grouptrip 2026 (group)'], facts_ok=True)
        rows = self.n.buttons[-1]
        datas = [b[1] for row in rows for b in row]
        self.assertEqual([d[0] for d in datas], ['a', 'd', 'x'])
        self.assertTrue(V.CALLBACK_RE.fullmatch(datas[2]))
        self.assertIn('Claude asks for 1 file\nWhy: flight times\n📎 x.pdf', self.n.msgs[-1])
        nonce = datas[2].split(':')[2]
        rid = r['request_id']
        self.assertEqual(self.raw.decide(rid, True, 'telegram', nonce=nonce, message_id=999, facts=True)[0], 'mismatch')
        self.assertEqual(self.raw.decide(rid, True, 'telegram', nonce=nonce, message_id=101, facts=True)[0], 'facts')
        out = self.raw.release(rid, expect_kind='media')
        self.assertIsInstance(out, V.FactsOnly)
        with self.assertRaises(V.VaultError) as cm:
            self.raw.release(rid, expect_kind='media')
        self.assertEqual(cm.exception.status, 410)
        self.assertIn('facts_only', self.cfg.audit_path.read_text())

    def test_no_facts_button_unless_offered_and_limits(self):
        r = self.raw.create('media', 'tg:1:2', 'the photo', self.payload(), kind='media', preview=['📎 a'])
        self.assertEqual(len(self.n.buttons[-1]), 1)
        nonce = self.n.buttons[-1][0][0][1].split(':')[2]
        self.assertEqual(self.raw.decide(r['request_id'], True, 'telegram', nonce=nonce, message_id=101,
                                         facts=True)[0], 'mismatch')
        self.raw.MAX_MEDIA_BYTES_DAY = 25
        self.raw.create('media', 'tg:1:3', 'second', self.payload(10), kind='media', preview=['📎 b'])
        with self.assertRaises(V.VaultError) as cm:
            self.raw.create('media', 'tg:1:4', 'third', self.payload(10), kind='media', preview=['📎 c'])
        self.assertEqual(cm.exception.code, 'daily_bytes')


class MediaApiTests(TV.ApiBase):
    name = 'api-media'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.app.store.set('telegram', {'bot_token': TV.BOT_TOKEN, 'chat_id': TV.CHAT_ID})
        cls.app.tg.media_list = fake_media_list
        cls.app.tg.raw_file = fake_raw_file

    def setUp(self):
        super().setUp()
        raw = self.app.raw
        raw.reqs.clear()
        raw.recent, raw.per_day, raw.media_bytes = [], {}, {}
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(LLM_TRAVEL))

    def request(self, keys, **kw):
        return self.call('POST', '/media/request', dict({'keys': keys, 'reason': 'flight times for the calendar'}, **kw))

    def test_list_metadata_only_filtered_names_excluded_refused(self):
        st, r = self.call('POST', '/media/list', {'source': 'tg', 'chat': 'Grouptrip 2026', 'type': 'pdf'})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['where'], 'Grouptrip 2026 (group, chat -301)')
        names = {i['key']: i['name'] for i in r['items']}
        self.assertEqual(names['tg:-301:11'], 'Example Air_eticket.pdf')
        self.assertEqual(names['tg:-301:12'], '[private: health]_Befund.pdf')
        self.assertNotIn('Herzschmerz', json.dumps(r))
        self.assertNotIn('content_b64', json.dumps(r))
        self.assertEqual(names['tg:-301:18'], 'MAX MUSTER-[code]-30OCT-2135-ZRH.pdf')     # model passed it: code masks
        self.assertNotIn('X7K2LM', json.dumps(r))
        st, r = self.call('POST', '/media/list', {'source': 'tg', 'chat': 'Grouptrip 2026', 'grep': 'X7K2'})
        self.assertEqual((st, r['items']), (200, []))                    # --grep cannot probe for codes
        TV.llm_mode('fail')
        st, r = self.call('POST', '/media/list', {'source': 'tg', 'chat': 'Grouptrip 2026', 'grep': 'befund'})
        self.assertEqual((st, [i['name'] for i in r['items']]), (200, ['[name hidden]']))
        st, r = self.call('POST', '/media/list', {'source': 'tg', 'chat': 'Familie'})
        self.assertEqual((st, r['code']), (404, 'not_found'))
        self.assertIn('media_list', self.cfg.audit_path.read_text())

    def test_request_preview_release_sha256_once(self):
        st, r = self.request(['tg:-301:11'])
        self.assertEqual(st, 200, r)
        self.assertNotIn('Example Air', json.dumps(r))                       # no raw names in the API response
        self.assertEqual((r['keep_minutes'], r['files'][0]['type']), (120, 'pdf'))
        msg = TV.TELEGRAM.sent[-1]['text']
        for part in ('Claude asks for 1 file\nWhy: flight times for the calendar', 'Example Air_eticket.pdf (PDF, 1 page',
                     'Grouptrip 2026 (group)', 'Patrick', '7 Sep 2026', "Kept on Claude's side 2 h, then deleted"):
            self.assertIn(part, msg)
        st, out = self.call('POST', '/media/release', {'request_id': r['request_id'], 'code': TV.TELEGRAM.last_code()})
        self.assertEqual((st, out['status']), (200, 'released'), out)
        f = out['files'][0]
        self.assertEqual(base64.b64decode(f['content_b64']), PDF)
        self.assertEqual(f['sha256'], hashlib.sha256(PDF).hexdigest())
        self.assertEqual((f['name'], f['mime']), ('Example Air_eticket.pdf', 'application/pdf'))
        st, again = self.call('POST', '/media/release', {'request_id': r['request_id']})
        self.assertEqual(st, 410)
        audit = self.cfg.audit_path.read_text()
        self.assertIn('media_released', audit)
        self.assertNotIn('Example Air', audit)
        self.assertNotIn(f['content_b64'][:40], audit)
        st, ack = self.call('POST', '/media/ack', {'request_id': r['request_id'], 'event': 'saved',
                                                   'files': [f['sha256']]})
        self.assertEqual(st, 200, ack)
        st, bad = self.call('POST', '/media/ack', {'request_id': r['request_id'], 'event': 'deleted',
                                                   'files': ['00' * 32]})
        self.assertEqual(st, 409)

    def test_refused_types_and_limits(self):
        for key, code in (('tg:-301:13', 'type_refused'), ('tg:-301:14', 'type_refused'), ('tg:-301:17', 'too_large')):
            st, r = self.request([key])
            self.assertEqual(r.get('code'), code, (key, r))
        self.assertEqual(self.request([f'tg:-301:{i}' for i in (11, 12, 15, 16, 11)])[1]['code'], 'bad_param')
        self.assertEqual(self.request(['tg:-301:11'] * 6)[1]['code'], 'bad_param')
        self.assertEqual(self.request(['tg:-301:11'], keep_minutes=121)[1]['code'], 'bad_param')
        st, r = self.request(['tg:-301:11', 'tg:-301:15'], keep_minutes=30)
        self.assertEqual(st, 200, r)
        self.assertFalse(r['facts_offered'])                            # a photo in the bundle: no Facts only
        self.assertIn('2 files', TV.TELEGRAM.sent[-1]['text'])
        rec = self.app.raw.reqs[r['request_id']]
        rec['expires'] = time.time() - 1                                # 15-min expiry
        st, out = self.call('POST', '/media/release', {'request_id': r['request_id'], 'code': '000000'})
        self.assertEqual((st, out['code']), (410, 'request_expired'))

    def test_facts_only_returns_fields_not_files(self):
        self.app.raw.mode = lambda: 'buttons'
        try:
            st, r = self.request(['tg:-301:11'])
        finally:
            del self.app.raw.mode
        self.assertEqual(st, 200, r)
        self.assertTrue(r['facts_offered'])
        self.assertIn('x:' + r['request_id'], json.dumps(TV.TELEGRAM.sent[-1]))
        self.assertEqual(self.app.raw.decide(r['request_id'], True, via='console', facts=True)[0], 'facts')
        st, out = self.call('POST', '/media/release', {'request_id': r['request_id']})
        self.assertEqual((st, out['status']), (200, 'facts'), out)
        blob = json.dumps(out)
        self.assertNotIn('content_b64', blob)
        self.assertEqual([s['number'] for s in out['facts'][0]['segments']], ['LH 0074', 'LH 0622'])

    def test_extract_grounded_no_pnr_ticket_price_invented(self):
        st, r = self.call('POST', '/media/extract', {'key': 'tg:-301:11'})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['kind'], r['structured']), ('travel', 'llm'))
        s1, s2 = r['segments']
        self.assertEqual((s1['number'], s1['from'], s1['to'], s1['dep_date'], s1['dep_time'], s1['arr_time']),
                         ('LH 0074', 'ZRH', 'FRA', '2026-10-31', '10:05', '18:20'))
        self.assertEqual((s2['number'], s2['dep_date'], s2['dep_time']), ('LH 0622', '2026-11-01', '02:40'))
        self.assertEqual(r['passengers'], ['Alex'])
        self.assertGreaterEqual(r['dropped'], 4)                        # gate, LH 999 segment, pnr, price
        blob = json.dumps(r, ensure_ascii=False)
        for w in SECRET_WORDS + ('CHF',):
            self.assertNotIn(w, blob)
        (TV.STUB_DIR / 'llm-json').write_text('not json')               # structured pass fails: code patterns
        st, r = self.call('POST', '/media/extract', {'key': 'tg:-301:11'})
        self.assertEqual(st, 200, r)
        self.assertTrue(r['structured'].startswith('code'))
        self.assertEqual([(s['number'], s.get('dep_time'), s.get('from'), s.get('to')) for s in r['segments']],
                         [('LH 0074', '10:05', 'ZRH', 'FRA'), ('LH 0622', '02:40', 'FRA', 'FNC')])
        for w in SECRET_WORDS:
            self.assertNotIn(w, json.dumps(r))
        self.assertIn('media_extract', self.cfg.audit_path.read_text())

    def test_extract_llm_failure_returns_no_text(self):
        TV.llm_mode('fail')
        st, r = self.call('POST', '/media/extract', {'key': 'tg:-301:11'})
        self.assertEqual(st, 503, r)
        blob = json.dumps(r)
        for w in ('LH 0074', 'ZRH', 'Alex', 'ABC12D'):
            self.assertNotIn(w, blob)
        st, r = self.call('POST', '/media/extract', {'key': 'tg:-301:15'})
        self.assertEqual((st, r['code']), (422, 'unreadable'))         # photos are read now (OCR); this one is broken

    def test_ics_attendee_addresses_masked(self):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps({'events': [
            {'name': 'Tauchgang Example Reef', 'venue': 'Example Beach, Funchal', 'date': '2026-11-02', 'start': '06:30',
             'address': 'lisa.muster@example.com'}]}))
        text = M.ics_text(ICS)
        self.assertIn('Attendees: Lisa Muster, peter.keller@example.org', text)
        self.assertNotIn('lisa.muster@', text)
        st, r = self.call('POST', '/media/extract', {'key': 'tg:-301:16'})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['kind'], 'ics')
        self.assertEqual(r['events'], [{'name': 'Tauchgang Example Reef', 'venue': 'Example Beach, Funchal',
                                        'date': '2026-11-02', 'start': '06:30'}])
        blob = json.dumps(r)
        for w in ('@example', 'divecenter.example', 'peter.keller'):
            self.assertNotIn(w, blob)
        sent = [c for c in TV.llm_calls() if '--anonymize' in c['args']][-1]['text']
        self.assertNotIn('lisa.muster@', sent)


class AckTests(unittest.TestCase):
    def test_overdue_delete_alert_once(self):
        cfg = TV.make_cfg('media-acks')
        clock = TV.Clock()
        alerts = []
        m = M.Media(cfg, None, None, None, None, None, V.Audit(cfg.audit_path), None,
                    alert=lambda *a, **k: alerts.append(a), clock=clock)
        m.acks = {'r1': {'released': clock.t, 'delete_by': clock.t + 7200, 'files': ['aa'], 'saved': None,
                         'deleted': None, 'alerted': False},
                  'r2': {'released': clock.t, 'delete_by': clock.t + 7200, 'files': ['bb'], 'saved': None,
                         'deleted': None, 'alerted': False}}
        m.ack({'request_id': 'r2', 'event': 'deleted', 'files': ['bb']})
        clock.t += 7200 + M.ACK_GRACE - 1
        self.assertEqual(m.check_acks(), [])
        clock.t += 2
        self.assertEqual(m.check_acks(), ['r1'])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(m.check_acks(), [])
        self.assertIn('media_delete_overdue', cfg.audit_path.read_text())
        self.assertEqual(stat.S_IMODE(os.stat(cfg.state / 'media-acks.json').st_mode), 0o600)
        with self.assertRaises(V.VaultError):
            m.ack({'request_id': 'nope', 'event': 'saved'})


CLIENT = TV.CLI_DIR / 'vault'


@unittest.skipUnless(CLIENT.exists(), 'the assistant-side client is not in the image')
class ClientMediaTests(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader('vault_client', str(CLIENT))
        spec = importlib.util.spec_from_loader('vault_client', loader)
        self.m = importlib.util.module_from_spec(spec)
        loader.exec_module(self.m)
        self.tmp = Path(tempfile.mkdtemp(dir=TV.TMP))
        self.m.MEDIA_DIR = str(self.tmp / 'cache' / 'vault' / 'media')
        self.m.MEDIA_STATE = str(self.tmp / 'state' / 'media.json')
        self.calls, self.fail = [], False
        test = self

        class C:
            def call(self, method, path, body=None, timeout=None):
                if test.fail:
                    raise SystemExit(3)
                test.calls.append((path, body))
                return {'ok': True}
        self.c = C()

    def test_save_record_gc_acks(self):
        sha = hashlib.sha256(PDF).hexdigest()
        r = {'request_id': 'abc123abc123', 'keep_minutes': 120, 'files': [
            {'name': '../.Example Air.pdf', 'sha256': sha, 'content_b64': base64.b64encode(PDF).decode()}]}
        paths = self.m.media_save(self.c, r)
        p = Path(paths[0])
        self.assertEqual((p.name, p.read_bytes()), ('Example Air.pdf', PDF))
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(self.m.MEDIA_DIR).stat().st_mode), 0o700)
        self.assertEqual(self.calls[-1], ('/media/ack', {'request_id': 'abc123abc123', 'event': 'saved', 'files': [sha]}))
        rec = json.loads(Path(self.m.MEDIA_STATE).read_text())['abc123abc123']
        self.assertEqual(stat.S_IMODE(os.stat(self.m.MEDIA_STATE).st_mode), 0o600)
        self.assertIsNone(rec['deleted'])
        self.m.media_gc(self.c, quiet=True)
        self.assertTrue(p.exists())
        self.fail = True                                                # vault unreachable: deleted anyway, ack later
        self.m.media_gc(self.c, now=time.time() + 121 * 60, quiet=True)
        self.assertFalse(p.parent.exists())
        self.fail = False
        self.m.media_gc(self.c, now=time.time() + 122 * 60, quiet=True)
        self.assertEqual(self.calls[-1][1]['event'], 'deleted')
        n = len(self.calls)
        self.m.media_gc(self.c, now=time.time() + 123 * 60, quiet=True)
        self.assertEqual(len(self.calls), n)                            # acked once
        bad = dict(r, request_id='def456def456', files=[dict(r['files'][0], sha256='00' * 32)])
        with self.assertRaises(SystemExit):
            self.m.media_save(self.c, bad)


TABLE_TICKET = """E-TICKET RECEIPT AND ITINERARY
   Booking reference: X7K2LM   Date of issue: 07 Sep 2026
   Flight   Departure   Arrival   Class   Baggage
   QR 084   Zurich (ZRH)   Doha (DOH)   Economy   7kg
   Fri, 30 Oct 2026  21:35   Sat, 31 Oct 2026  06:45
   Terminal 1   Aircraft: Boeing 787-9
   QR 412   Doha (DOH)   Funchal (FNC)   Economy   7kg
   Sat, 31 Oct 2026  07:50   Sat, 31 Oct 2026  12:25
   Aircraft: Airbus A320
   Fare: [amount]   Baggage 1 PC 23 kg"""
APP_TICKET = """Outbound · Fri 30 Oct
21:35  Zurich ZRH   Turkish Airlines · TK 1934 · Airbus A321
02:35  Istanbul IST (+1)
06:50  Istanbul IST   Turkish Airlines · TK 0372 · A330
12:25  Funchal FNC
Return · Sat 14 Nov
20:30  Funchal FNC   Turkish Airlines · TK 373 · Airbus A330
01:05  Istanbul IST (+1)"""
REF = M.dt.date(2026, 9, 7)


class TravelFactsTests(unittest.TestCase):
    """Live check 13.10 (an e-ticket gave only "A320"): the model splits carrier and number and writes weekdays,
    tables put the times on the next line, apps put them first; nothing may come out as a wrong day."""

    def check(self, llm, text, ref=REF):
        return M.check_fields('travel', llm, text, M.banned_tokens(text), lambda t: t, ref=ref)

    def test_model_split_carrier_and_weekday_dates(self):
        llm = {'segments': [
            {'carrier': 'QR', 'number': '084', 'from': 'Zurich (ZRH)', 'to': 'Doha (DOH)', 'dep_date': 'Fri, 30 Oct 2026',
             'dep_time': '21:35', 'arr_date': 'Sat, 31 Oct 2026', 'arr_time': '6:45'},
            {'carrier': 'Qatar Airways', 'number': '412', 'dep_date': '31.10.2026', 'dep_time': '07:50'},
            {'number': 'A320', 'dep_date': 'Sat, 31 Oct 2026'},
            {'number': 'QR 999', 'dep_time': '07:50'},
            {'number': 'X7K2LM'}]}
        facts, why = self.check(llm, TABLE_TICKET)
        self.assertEqual([(s['number'], s.get('dep_date'), s.get('dep_time'), s.get('arr_date'), s.get('arr_time'))
                          for s in facts['segments']],
                         [('QR 084', '2026-10-30', '21:35', '2026-10-31', '06:45'),
                          ('QR 412', '2026-10-31', '07:50', None, None)])
        self.assertEqual(facts['segments_from'], 'model')
        self.assertEqual(why['number'], 3)                               # A320, QR 999, the booking reference
        self.assertNotIn('X7K2LM', repr(facts))

    def test_code_patterns_table_and_app_layouts(self):
        facts, _ = self.check({}, TABLE_TICKET)
        self.assertEqual([(s['number'], s.get('dep_date'), s.get('dep_time'), s.get('arr_time'), s.get('from'), s.get('to'))
                          for s in facts['segments']],
                         [('QR 084', '2026-10-30', '21:35', '06:45', 'ZRH', 'DOH'),
                          ('QR 412', '2026-10-31', '07:50', '12:25', 'DOH', 'FNC')])
        self.assertEqual(facts['segments_from'], 'code')
        facts, _ = self.check({}, APP_TICKET)
        self.assertEqual([(s['number'], s.get('dep_date'), s.get('dep_time'), s.get('arr_time')) for s in facts['segments']],
                         [('TK 1934', '2026-10-30', '21:35', '02:35'), ('TK 0372', None, '06:50', '12:25'),
                          ('TK 373', '2026-11-14', '20:30', '01:05')])

    def test_no_wrong_day_and_model_gaps_filled(self):
        llm = {'segments': [
            {'number': 'TK 1934', 'dep_date': 'Fri 30 Oct', 'dep_time': '21:35', 'arr_date': 'Fri 30 Oct', 'arr_time': '02:35'},
            {'number': 'TK 0372', 'dep_date': 'Fri 30 Oct', 'dep_time': '06:50', 'arr_time': '12:25'}]}
        facts, why = self.check(llm, APP_TICKET)
        segs = facts['segments']
        self.assertEqual([s['number'] for s in segs], ['TK 1934', 'TK 0372', 'TK 373'])  # TK 373 from the code
        self.assertEqual(facts['segments_from'], 'model + code')
        self.assertNotIn('arr_date', segs[0])                             # overnight: not "arrives 30 Oct"
        self.assertNotIn('dep_date', segs[1])                             # leaves before the leg before it
        self.assertEqual((why['arr_date'], why['dep_date']), (1, 1))

    def test_file_name_codes_masked_in_code(self):
        cases = {'MAX MUSTER-X7K2LM-30OCT-2135-ZRH.pdf': 'MAX MUSTER-[code]-30OCT-2135-ZRH.pdf',
                 'Invoice-9BF0758D-7752614.pdf': 'Invoice-[code]-[code].pdf',
                 'Receipt-2244-7340.pdf': 'Receipt-2244-7340.pdf',
                 'IMG_20260907_162900.jpg': 'IMG_20260907_162900.jpg',
                 'PXL_20260907_162900123.jpg': 'PXL_20260907_[code].jpg',
                 'ticket_6072345678901.pdf': 'ticket_[code].pdf',
                 'Madeira_Dive_Itinerary_14-29_November_2026.pdf': 'Madeira_Dive_Itinerary_14-29_November_2026.pdf',
                 'EK0391_boarding_pass_Teil2.pdf': 'EK0391_boarding_pass_Teil2.pdf',
                 'video_1080p_v2.mp4': 'video_1080p_v2.mp4', 'Lohnausweis 2025.pdf': 'Lohnausweis 2025.pdf',
                 'ABCDE1.pdf': '[code].pdf', '': ''}
        for name, want in cases.items():
            self.assertEqual(M.mask_name_codes(name), want, name)

    def test_dates_years_and_non_flights(self):
        self.assertEqual(M.find_dates('Fri 30 Oct\n21:35'), [('30 Oct', '--10-30')])
        self.assertEqual(M.find_dates('30 Oct 21:35 and 3. Mai 26'), [('30 Oct', '--10-30'), ('3. Mai 26', '2026-05-03')])
        self.assertEqual(M.parse_date('Fri, 30 Oct', ref=REF), '2026-10-30')
        self.assertEqual(M.parse_date('05 Jan', ref=M.dt.date(2026, 12, 20)), '2027-01-05')
        self.assertEqual(M.parse_date('Sa., 14.11.2026'), '2026-11-14')
        self.assertEqual(M.parse_date('Mar 5, 2026'), '2026-03-05')
        self.assertEqual(M.parse_time('06:45 (+1)'), '06:45')
        self.assertEqual(M.ref_date('2026-09-07 16:17'), REF)
        for line in ('Aircraft: Airbus A320 31 Oct 2026', 'Baggage 1 PC 23 kg 31 Oct 2026', 'Ref LX12AB 31 Oct 2026',
                     'A321neo 07:50'):
            self.assertEqual(M.flight_numbers(line), [], line)
        self.assertEqual([m[0] for m in M.flight_numbers('TK1931 07:50')], ['TK1931'])


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(TV.TMP, ignore_errors=True)
