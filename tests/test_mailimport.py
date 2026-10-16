#!/usr/bin/python3 -I
"""Tests for the Gmail -> paperless backfill (app/mailimport.py) against the fake IMAP server of test_gmail (with
LIST \\All, BODYSTRUCTURE, HEADER.FIELDS and BODY.PEEK[part] added here) and a fake paperless with checksums.
Covers: IMAP answer parsing (literals, RFC 2231/2047 names, attached mails), All Mail detection, the cheap rules,
the scan (only BODY.PEEK and metadata; bytes only for the important categories; the model only for the rest;
subjects dropped after sorting), duplicates (exact by checksum, likely by name + date, repeats), the summary
(counts, years, domains / first names; never a subject, a file name or a surname), the import (types, tags, date,
limit, idempotent re-runs, duplicates at upload, budget), the checksum fallbacks, the API routes.
Fixture rule: never write a complete token or app password literally (they come from test_vault / test_gmail)."""
import base64
import email
import email.policy
import hashlib
import json
import re
import sys
import time
import unittest
import urllib.parse
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_gmail as TG  # noqa: E402  (fake IMAP, mail(), make_accounts)
import test_vault as T  # noqa: E402  (fixtures: stub LLM, fake paperless, ApiBase)
import mailimport as MI  # noqa: E402
import sources as S  # noqa: E402
import vaultlib as V  # noqa: E402

ALL = '[Gmail]/Alle Nachrichten'
DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
DAY = 86400
NOW = time.time()


# ============================================================================================ fakes

def bstruct(part):
    """A BODYSTRUCTURE string for a parsed mail part (Gmail-like; non-ASCII names as RFC 2231 FILENAME*)."""
    if part.is_multipart():
        return '(' + ''.join(bstruct(p) for p in part.iter_parts()) + \
            f' "{part.get_content_subtype().upper()}" ("BOUNDARY" "{part.get_boundary()}") NIL NIL)'
    mt, st = part.get_content_maintype().upper(), part.get_content_subtype().upper()
    params = [(k, v) for k, v in (part.get_params() or [])[1:] if k != 'name']
    ps = '(' + ' '.join(f'"{k.upper()}" "{v}"' for k, v in params) + ')' if params else 'NIL'
    enc = (part.get('Content-Transfer-Encoding') or '7bit').upper()
    payload = part.get_payload()
    size = len(payload.encode()) if isinstance(payload, str) else 0
    disp, fn = part.get_content_disposition(), part.get_filename()
    d = 'NIL'
    if disp:
        if fn and not fn.isascii():
            d = f'("{disp.upper()}" ("FILENAME*" "utf-8\'\'{urllib.parse.quote(fn)}"))'
        else:
            d = f'("{disp.upper()}" ' + (f'("FILENAME" "{fn}")' if fn else 'NIL') + ')'
    if mt == 'TEXT':
        return f'("{mt}" "{st}" {ps} NIL NIL "{enc}" {size} {payload.count(chr(10))} NIL {d} NIL NIL)'
    return f'("{mt}" "{st}" {ps} NIL NIL "{enc}" {size} NIL {d} NIL NIL)'


def part_of(msg, num):
    p = msg
    for i in num.split('.'):
        if p.is_multipart():
            p = list(p.iter_parts())[int(i) - 1]
        elif i != '1':
            return None
    return p


class DocIMAP(TG.FakeIMAP):
    """test_gmail's fake + LIST (All Mail with \\All), X-GM-RAW has:attachment, BODYSTRUCTURE, HEADER.FIELDS and
    BODY.PEEK[part]. A fetch without PEEK would set seen_set (as before)."""

    def __init__(self, all_mail=True):
        super().__init__()
        self.all_mail = all_mail
        if all_mail:
            self.folders[ALL] = []
            self.uidvalidity[ALL] = 9
            self.next_uid[ALL] = 1
        self.part_fetches = []

    def serve(self, h):
        outer, rf = self, h.rfile

        class R:
            def readline(self, *a):
                while True:
                    line = rf.readline(*a)
                    m = re.match(rb'(\S+) LIST ', line)
                    if not (m and outer.all_mail):
                        return line
                    outer.log.append(('LIST', line.decode().strip()))
                    h.wfile.write(b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
                                  b'* LIST (\\HasChildren \\Noselect) "/" "[Gmail]"\r\n'
                                  b'* LIST (\\All \\HasNoChildren) "/" "' + ALL.encode() + b'"\r\n'
                                  + m.group(1) + b' OK LIST completed\r\n')
                    h.wfile.flush()

            def read(self, n):
                return rf.read(n)

            def close(self):
                rf.close()
        h.rfile = R()
        return super().serve(h)

    def search(self, folder, args, lit):
        a = [x.decode() if isinstance(x, bytes) else x for x in args]
        if len(a) >= 2 and a[0].upper() == 'X-GM-RAW' and 'has:attachment' in self.unq(a[1]):
            m = re.search(r'after:(\d{4})/(\d{2})/(\d{2})', self.unq(a[1]))
            lo = time.mktime(time.strptime('-'.join(m.groups()), '%Y-%m-%d')) if m else 0
            return [u for u, ts, r in self.folders[folder]
                    if ts >= lo and TG.G.attachment_parts(TG.G.parse_message(r))]
        return super().search(folder, args, lit)

    def fetch(self, folder, tk, w):
        line = self.log[-1][1]
        up = line.upper()
        if 'BODY[' in up.replace('BODY.PEEK[', 'PEEK['):
            self.seen_set = True
        if 'BODYSTRUCTURE' not in up and not re.search(r'BODY\.PEEK\[(?:\d|HEADER\.FIELDS)', up):
            return super().fetch(folder, tk, w)
        want = set()
        for piece in tk[3].decode().split(','):
            a, _, b = piece.partition(':')
            want |= set(range(int(a), (int(b) if b else int(a)) + 1))
        hm = re.search(r'HEADER\.FIELDS \(([^)]*)\)', up)
        pm = re.search(r'BODY\.PEEK\[([\d.]+)\]', up)
        for seq, (uid, ts, raw) in enumerate(self.folders[folder], 1):
            if uid not in want:
                continue
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            head = f'* {seq} FETCH (UID {uid} INTERNALDATE "{TG.imaplib.Time2Internaldate(ts)[1:-1]}" ' \
                   f'RFC822.SIZE {len(raw)}'
            if 'BODYSTRUCTURE' in up:
                head += f' BODYSTRUCTURE {bstruct(msg)}'
            lits = []
            if hm:
                keep = set(hm.group(1).split())
                hdr = ''.join(f'{k}: {v}\r\n' for k, v in
                              email.message_from_bytes(raw, policy=email.policy.compat32).items()
                              if k.upper() in keep) + '\r\n'
                lits.append((f'BODY[HEADER.FIELDS ({hm.group(1)})]', hdr.encode()))
            if pm:
                self.part_fetches.append((uid, pm.group(1)))
                p = part_of(msg, pm.group(1))
                lits.append((f'BODY[{pm.group(1)}]', (p.get_payload() if p is not None else '').encode()))
            out = head.encode()
            for key, data in lits:
                out += f' {key} {{{len(data)}}}\r\n'.encode() + data
            w(out + b')\r\n')


class PaperlessCS(T.FakePaperless):
    """+ checksum__iexact (or ignored, like an old paperless), /metadata/ original_checksum, uploads that create a
    document (or fail as a duplicate of an existing checksum), tasks."""

    def __init__(self, honor=True):
        self.honor, self.csum, self.uploads, self.tasks = honor, {}, [], {}
        super().__init__()

    def handle(self, method, path, headers, body):
        if headers.get('Authorization') != f'Token {T.PL_TOKEN}':
            return super().handle(method, path, headers, body)
        u = urllib.parse.urlsplit(path)
        q = dict(urllib.parse.parse_qsl(u.query))
        m = re.fullmatch(r'/api/documents/(\d+)/metadata/', u.path)
        if m:
            return T.jresp({'original_checksum': self.csum.get(int(m.group(1)), ''), 'original_size': 1})
        if u.path == '/api/documents/' and method == 'GET' and 'checksum__iexact' in q and self.honor:
            ids = [i for i, c in self.csum.items() if c == q['checksum__iexact'].lower()]
            return T.jresp({'count': len(ids), 'next': None, 'results': [{'id': i} for i in ids]})
        if u.path == '/api/documents/post_document/' and method == 'POST':
            bnd = headers.get('Content-Type').split('boundary=')[1].encode()
            fields, data = {}, b''
            for chunk in body.split(b'--' + bnd)[1:-1]:
                head, _, val = chunk[2:].partition(b'\r\n\r\n')
                name = re.search(rb'name="([^"]+)"', head).group(1).decode()
                if name == 'document':
                    data = val[:-2]
                    fields['filename'] = re.search(rb'filename="([^"]*)"', head).group(1).decode()
                else:
                    fields.setdefault(name, []).append(val[:-2].decode())
            md5 = hashlib.md5(data).hexdigest()
            tid = f'task-{len(self.tasks) + 1:04d}'
            if md5 in self.csum.values():
                self.tasks[tid] = {'task_id': tid, 'status': 'FAILURE',
                                   'result': 'Not consuming x.pdf: It is a duplicate of y (#7)'}
            else:
                self.next_id += 1
                did = self.next_id
                self.csum[did] = md5
                self.docs[did] = {'id': did, 'title': fields.get('title', [''])[0], 'created': '2026-01-01T00:00:00',
                                  'added': '2026-10-16T09:00:00+02:00', 'modified': '2026-10-16T09:00:00+02:00',
                                  'correspondent': None, 'document_type': None, 'tags': [], 'content': '',
                                  'original_file_name': fields['filename'], 'page_count': 1, 'notes': []}
                self.tasks[tid] = {'task_id': tid, 'status': 'SUCCESS', 'related_document': str(did)}
            self.uploads.append(dict(fields, md5=md5))
            return T.jresp(tid)
        if u.path == '/api/tasks/':
            return T.jresp([self.tasks.get(q.get('task_id'), {'status': 'PENDING'})])
        return super().handle(method, path, headers, body)


# ============================================================================================ fixtures

PDF_A = T.make_pdf(['Lohn Oktober'])
PDF_B = T.make_pdf(['Rechnung Telefon'])
PDF_C = T.make_pdf(['Unterlagen Verwaltung'])
PDF_D = T.make_pdf(['Praemie 2026'])
PDF_E = T.make_pdf(['Lohn Mai 2024'])
PDF_F = T.make_pdf(['Bestellung Laptop'])
PDF_G = T.make_pdf(['Info Firma'])
PDF_H = T.make_pdf(['Flyer'])
SUBJECTS = ['Lohnabrechnung Oktober', 'Ihre Rechnung', 'Unterlagen', 'Herbstaktion', 'Ihr Mietvertrag',
            'Police 2026', 'Lohnabrechnung Mai', 'Fwd: Lohn', 'Bestellung 987', 'Foto', 'Info']
NAMES = ['Lohnabrechnung_2026-10', 'Rechnung_123', 'scan0001', 'Flyer_Herbst', 'Mietvertrag', 'Prämienrechnung',
         'Lohnabrechnung Mai', 'Rechnung_987', 'doc_2', 'Keller']


def fill(imap, folder):
    """Eleven mails; one has no document. -> uids in order."""
    m = TG.mail
    spec = [
        (m('Muster Treuhand AG <lohn@muster-treuhand.example>', SUBJECTS[0], 'Hallo',
           attachments=[('Lohnabrechnung_2026-10.pdf', PDF_A, 'application/pdf')]), NOW - 10 * DAY),
        (m('Fernmelde AG <rechnung@fernmelde.example>', SUBJECTS[1], 'Hallo',
           attachments=[('Rechnung_123.pdf', PDF_B, 'application/pdf')]), NOW - 9 * DAY),
        (m('Beispiel Verwaltung <info@beispiel-verwaltung.example>', SUBJECTS[2], 'Hallo',
           attachments=[('scan0001.pdf', PDF_C, 'application/pdf')]), NOW - 8 * DAY),
        (m('Shop News <news@shop-news.example>', SUBJECTS[3], 'Aktion', bulk=True,
           attachments=[('Flyer_Herbst.pdf', PDF_H, 'application/pdf')]), NOW - 7 * DAY),
        (m('Immo AG <info@immo-ag.example>', SUBJECTS[4], 'Hallo',
           attachments=[('Mietvertrag.docx', b'PK\x03\x04 fake docx', DOCX)]), NOW - 6 * DAY),
        (m('Krankenkasse Muster AG <service@kk-muster.example>', SUBJECTS[5], 'Hallo',
           attachments=[('Prämienrechnung_2026.pdf', PDF_D, 'application/pdf')]), NOW - 5 * DAY),
        (m('Muster Treuhand AG <lohn@muster-treuhand.example>', SUBJECTS[6], 'Hallo',
           attachments=[('Lohnabrechnung Mai.pdf', PDF_E, 'application/pdf')]),
         time.mktime(time.strptime('2024-06-02', '%Y-%m-%d'))),
        (m('Anna Keller <anna.keller@gmx.test>', SUBJECTS[7], 'fwd',
           attachments=[('Lohnabrechnung_2026-10.pdf', PDF_A, 'application/pdf')]), NOW - 4 * DAY),
        (m('Shop AG <noreply@shop.example>', SUBJECTS[8], 'Danke',
           attachments=[('Rechnung_987.pdf', PDF_F, 'application/pdf')]), NOW - 3 * DAY),
        (m('Bob <bob@example.org>', SUBJECTS[9], 'Bild', attachments=[('foto.jpg', b'\xff\xd8\xff fake', 'image/jpeg')]),
         NOW - 2 * DAY),
        (m('Firma X <a@firma-x.example>', SUBJECTS[10], 'Hallo', attachments=[('doc_2.pdf', PDF_G, 'application/pdf')]),
         NOW - 1 * DAY),
    ]
    return [imap.add(folder, raw, ts=ts) for raw, ts in spec]


def seed(pl):
    """His archive as the hints learn it: two receipts from Shop AG (a sender learned as 'receipt')."""
    rule = {'match': '', 'matching_algorithm': 1, 'is_insensitive': True}
    pl.tax['correspondents'][30] = dict(rule, id=30, name='Shop AG', document_count=2)
    pl.tax['document_types'][31] = dict(rule, id=31, name='Quittung', document_count=2)
    for i, x in ((40, 'a'), (41, 'b')):
        pl.docs[i] = {'id': i, 'title': f'Beleg {x.upper()}', 'created': '2025-03-01T00:00:00+01:00',
                      'added': '2025-03-02T09:00:00+01:00', 'modified': '2025-03-02T09:00:00+01:00',
                      'correspondent': 30, 'document_type': 31, 'tags': [], 'content': '',
                      'original_file_name': f'beleg-{x}.pdf', 'page_count': 1, 'notes': []}
    return pl


def make_service(name, imap, pl, **env):
    cfg, store, gs, feed, events, rules = TG.make_accounts(name, imap)
    cfg.env.update({'VAULT_MAILIMPORT_LLM_PACE': '0', 'VAULT_MAILIMPORT_IMAP_PACE': '0', **env})
    store.set('gmail', {'address': TG.ADDR, 'app_password': TG.APP_PW})
    store.set('paperless', {'url': pl.url, 'token': T.PL_TOKEN})
    gate = V.LLMGate()
    paperless = S.Paperless(cfg, store, gs.policy, gate, gs.audit)
    return MI.MailImport(cfg, gs, paperless, gs.policy, gate, gs.audit, log=lambda *a: None), cfg


def llm_answers(items):
    (T.STUB_DIR / 'llm-json').write_text(json.dumps({'items': items}))


# ============================================================================================ unit tests

class ParseTests(unittest.TestCase):
    def test_fetch_answer_literals_names_and_attached_mail(self):
        b64 = base64.b64encode('Änderung.pdf'.encode()).decode()
        dat = [(b'1 (UID 42 RFC822.SIZE 5000 INTERNALDATE "16-Oct-2026 10:14:00 +0200" BODYSTRUCTURE (("TEXT" '
                b'"PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 10 1 NIL NIL NIL)("APPLICATION" "PDF" ("NAME" {14}',
                b'Rech"nung).pdf'),
               (b') NIL NIL "BASE64" 400 NIL ("ATTACHMENT" ("FILENAME*" "utf-8\'\'Pr%C3%A4mie.pdf")) NIL)("MESSAGE" '
                b'"RFC822" NIL NIL NIL "7BIT" 300 NIL (("TEXT" "PLAIN" NIL NIL NIL "7BIT" 5 1 NIL NIL NIL)'
                b'("APPLICATION" "PDF" ("NAME" "=?UTF-8?B?' + b64.encode() + b'?=") NIL NIL "BASE64" 200 NIL NIL '
                b'NIL) "MIXED" NIL NIL NIL) 20 NIL NIL NIL) "MIXED" ("BOUNDARY" "b1") NIL NIL) X-GM-MSGID 1234567 '
                b'BODY[HEADER.FIELDS (FROM SUBJECT LIST-ID LIST-UNSUBSCRIBE PRECEDENCE)] {41}',
                b'From: A <a@b.example>\r\nSubject: Hallo\r\n\r\n'), b')',
               b'2 (UID 43 RFC822.SIZE 10 BODYSTRUCTURE ("APPLICATION" "PDF" NIL NIL NIL "BASE64" 8 NIL NIL NIL))']
        recs = [MI.parse_fetch(r) for r in MI.fetch_records(dat)]
        self.assertEqual([MI._i(r['UID']) for r in recs], [42, 43])
        parts = MI.walk_parts(recs[0]['BODYSTRUCTURE'])
        self.assertEqual([(p['part'], p['type'], p['name'], p['kind']) for p in parts],
                         [('1', 'text/plain', '', None), ('2', 'application/pdf', 'Prämie.pdf', 'pdf'),
                          ('3.1', 'text/plain', '', None), ('3.2', 'application/pdf', 'Änderung.pdf', 'pdf')])
        self.assertEqual((parts[1]['size'], parts[1]['encoding']), (400, 'base64'))
        self.assertEqual(MI._s(recs[0]['X-GM-MSGID']), '1234567')
        self.assertTrue(recs[0]['BODY[HEADER.FIELDS (FROM SUBJECT LIST-ID LIST-UNSUBSCRIBE PRECEDENCE)]']
                        .startswith(b'From: A'))
        self.assertEqual(MI.walk_parts(recs[1]['BODYSTRUCTURE'])[0]['part'], '1')     # a single-part mail
        self.assertIsNotNone(MI.internaldate(recs[0]['INTERNALDATE']))

    def test_all_mail_any_language_and_literal(self):
        class Im:
            def __init__(self, dat):
                self.dat = dat

            def list(self):
                return 'OK', self.dat
        self.assertEqual(MI.all_mail_folder(Im([b'(\\HasNoChildren) "/" "INBOX"',
                                                b'(\\All \\HasNoChildren) "/" "[Gmail]/Alle Nachrichten"'])),
                         '[Gmail]/Alle Nachrichten')
        self.assertEqual(MI.all_mail_folder(Im([b'(\\All) "/" "[Gmail]/Tous les &AOk-mails"'])),
                         '[Gmail]/Tous les émails')
        self.assertEqual(MI.all_mail_folder(Im([(b'(\\All) "/" {16}', b'[Gmail]/All Mail')])), '[Gmail]/All Mail')
        self.assertIsNone(MI.all_mail_folder(Im([b'(\\HasNoChildren) "/" "INBOX"'])))

    def test_cheap_rules(self):
        r = MI.classify_rule
        self.assertEqual(r('Lohnabrechnung_2026-10.pdf', 'x', 'firma.ch', 0), ('payslip', 'name'))
        self.assertEqual(r('Steuerrechnung 2025.pdf', '', '', 0), ('tax', 'name'))           # tax before bill
        self.assertEqual(r('Prämienrechnung.pdf', '', '', 0), ('insurance', 'name'))       # umlaut folded
        self.assertEqual(r('Kontoauszug_09.pdf', '', '', 0), ('statement', 'name'))
        self.assertEqual(r('AGB_Versicherung.pdf', '', '', 0), (None, None))                # mixed: the model
        self.assertEqual(r('E-Ticket.pdf', 'Ihre Buchung', '', 0), ('other', 'name'))
        self.assertEqual(r('Rechnung_987.pdf', '', 'shop.example', 0, 'receipt'), ('receipt', 'name'))  # a shop
        self.assertEqual(r('Rechnung_987.pdf', '', 'shop.example', 0), ('bill', 'name'))
        self.assertEqual(r('doc.pdf', 'Ihre Police', '', 0), ('insurance', 'subject'))
        self.assertEqual(r('doc.pdf', 'Hallo', 'kk.example', 0, 'insurance'), ('insurance', 'sender'))   # learned
        self.assertEqual(r('doc.pdf', 'Hallo', 'steueramt.zh.ch', 0), ('tax', 'domain'))
        self.assertEqual(r('doc.pdf', 'Hallo', 'einwohner.stadt-beispiel.ch', 0), ('official', 'domain'))
        self.assertEqual(r('Heizungssteuerung.pdf', 'Anleitung', '', 0), ('other', 'subject'))    # not "Steuer"
        self.assertEqual(r('doc.pdf', 'Hallo', 'kk.example', 1, 'insurance'), ('other', 'bulk'))
        self.assertEqual(r('doc.pdf', 'Hallo', 'firma.ch', 0), (None, None))

    def test_correspondent_and_title(self):
        mi = MI.MailImport.__new__(MI.MailImport)
        corrs = {1: 'Fernmelde (Schweiz) AG', 2: 'Krankenkasse Muster AG', 3: 'Muster Treuhand'}
        row = {'company': 'Fernmelde', 'domain': 'rechnung.fernmelde.example'}
        self.assertEqual(mi.correspondent(row, corrs), 'Fernmelde (Schweiz) AG')
        self.assertEqual(mi.correspondent({'company': 'Muster Treuhand AG', 'domain': 'x.ch'}, corrs),
                         'Muster Treuhand')
        self.assertIsNone(mi.correspondent({'company': None, 'domain': 'gmx.test'}, corrs))
        t = mi.title({'name': 'scan0001.pdf', 'company': 'Fernmelde', 'who': 'fernmelde.example',
                      'domain': 'fernmelde.example'}, 'Rechnung', '2026-10-01')
        self.assertEqual(t, 'Rechnung Fernmelde 2026-10')
        self.assertEqual(mi.title({'name': 'Mietvertrag_2026.pdf', 'company': None, 'who': 'Anna', 'domain': ''},
                                  'Vertrag', '2026-10-01'), 'Mietvertrag 2026')


# ============================================================================================ scan + import

class ScanImportTests(unittest.TestCase):
    def setUp(self):
        T.llm_mode('ok')
        self.imap = DocIMAP()
        self.uids = fill(self.imap, ALL)
        self.pl = seed(PaperlessCS())
        self.pl.csum[7] = hashlib.md5(PDF_D).hexdigest()           # the premium bill is in paperless already
        self.mi, self.cfg = make_service(f'mi-{self._testMethodName}', self.imap, self.pl)
        llm_answers([{'n': 1, 'c': 'contract'}, {'n': 2, 'c': 'banana'}])

    def tearDown(self):
        bad = [n for n in self.imap.names() if n in TG.FORBIDDEN]
        self.assertEqual(bad, [], 'a mailbox-changing IMAP command was sent')
        self.assertFalse(self.imap.seen_set, 'a fetch without BODY.PEEK')

    def scan(self, **b):
        r = self.mi.start_scan(b)
        self.mi.scan(r['plan'])
        return r['plan'], self.mi.summary(r['plan'])

    def test_scan_summary_duplicates_and_privacy(self):
        calls0 = len(T.llm_calls())
        pid, s = self.scan()
        self.assertEqual((s['status'], s['phase']), ('done', 'done'))
        self.assertEqual(s['accounts']['main']['all_mail'], True)
        self.assertEqual(s['totals'], {'mails': 10, 'attachments': 10, 'pdf': 9, 'office': 1})
        c = s['categories']
        self.assertEqual({k: v['attachments'] for k, v in c.items()},
                         {'payslip': 3, 'bill': 1, 'contract': 2, 'other': 1, 'insurance': 1, 'receipt': 1,
                          'unsure': 1})
        self.assertEqual(c['payslip']['duplicates'], {'exact': 0, 'likely': 1, 'repeat': 1})
        self.assertEqual(c['insurance']['duplicates']['exact'], 1)
        self.assertEqual(c['contract']['office_docs'], 1)
        self.assertEqual(c['contract']['sorted_by'], {'llm': 1, 'name': 1})
        self.assertEqual(dict(c['payslip']['top_senders']), {'muster-treuhand.example': 2, 'Anna': 1})
        self.assertEqual(self.mi.learned_hints()[0], {30: 'receipt'})     # Shop AG, from his archive
        self.assertEqual(c['receipt']['sorted_by'], {'name': 1})
        self.assertEqual(c['payslip']['years'], {'2024': 1, time.strftime('%Y'): 2} if time.strftime('%Y') != '2024'
                         else {'2024': 3})
        self.assertEqual(s['duplicates'], {'likely': 1, 'repeat': 1, 'exact': 1})
        self.assertEqual(s['checksum'], {'method': 'filter', 'checked': 8, 'important': 8})
        self.assertEqual(s['document_types']['bill'], {'name': 'Rechnung', 'exists': True})
        self.assertEqual(s['document_types']['payslip'], {'name': 'Lohnabrechnung', 'exists': False})
        self.assertEqual(s['correspondent_matches']['insurance'], 1)
        self.assertEqual(s['estimate']['all_important_min'], 3)       # 4 new PDFs x (15 s pause + 20 s)
        # one model call for the two undecided rows; bytes only for the important categories (not other/unsure)
        self.assertEqual(len(T.llm_calls()) - calls0, 1)
        self.assertEqual(sorted(u for u, _ in self.imap.part_fetches),
                         sorted(self.uids[i] for i in (0, 1, 2, 4, 5, 6, 7, 8)))
        # privacy: no subject, file name or surname in the answer; subjects gone from the plan rows
        blob = json.dumps(s, ensure_ascii=False)
        for x in SUBJECTS + NAMES:
            self.assertNotIn(x, blob)
        self.assertEqual(self.mi.db.q('SELECT COUNT(*) FROM items WHERE subject IS NOT NULL')[0][0], 0)
        self.assertEqual({n for n, _ in self.imap.log} - {'LIST', 'UID SEARCH', 'UID FETCH', 'CAPABILITY', 'LOGIN',
                                                          'EXAMINE', 'LOGOUT', 'NOOP'}, set())

    def test_import_types_limit_idempotent_and_dry(self):
        pid, s = self.scan()
        cats = ['payslip', 'bill', 'contract', 'insurance', 'receipt']
        dry = self.mi.start_run({'plan': pid, 'categories': ','.join(cats), 'dry': True})
        self.assertEqual((dry['to_import'], dry['per_category']),
                         (4, {'payslip': 1, 'bill': 1, 'contract': 1, 'receipt': 1}))
        self.assertEqual(self.pl.uploads, [])
        r = self.mi.start_run({'plan': pid, 'categories': cats, 'limit': 2, 'pause': 2})
        with self.assertRaises(V.VaultError) as e:                    # one at a time
            self.mi.start_run({'plan': pid, 'categories': cats})
        self.assertEqual(e.exception.code, 'busy')
        pauses = []
        self.mi._sleep = pauses.append                                 # (no real pauses in the test)
        self.mi.import_run(r['run'])
        self.assertEqual(self.mi.db.run(r['run'])['status'], 'done')
        self.assertEqual((len(self.pl.uploads), pauses), (2, [2, 2]))  # the throttle after each upload
        up = self.pl.uploads[0]
        self.assertEqual((up['created'], up['filename']),
                         ([time.strftime('%Y-%m-%d', time.localtime(NOW - 10 * DAY))], 'Lohnabrechnung_2026-10.pdf'))
        names = {o['id']: o['name'] for o in self.pl.tax['document_types'].values()}
        tags = {o['id']: o['name'] for o in self.pl.tax['tags'].values()}
        self.assertEqual(names[int(up['document_type'][0])], 'Lohnabrechnung')
        self.assertEqual(sorted(tags[int(t)] for t in up['tags']), ['Inbox', 'mail-import'])
        self.assertEqual(up['title'], ['Lohnabrechnung 2026-10'])
        # resume: the next run imports the rest, a third one nothing (idempotent)
        r2 = self.mi.start_run({'plan': pid, 'categories': cats})
        self.assertEqual(r2['to_import'], 2)
        self.mi.import_run(r2['run'])
        self.assertEqual(len(self.pl.uploads), 4)
        self.assertEqual(self.mi.start_run({'plan': pid, 'categories': cats, 'dry': True})['to_import'], 0)
        st = self.mi.summary(pid)
        self.assertEqual(st['categories']['payslip']['state'], {'imported': 1, 'planned': 2})
        self.assertEqual(st['runs'][0]['counts'], {'imported': 2})
        bills = [u for u in self.pl.uploads if names.get(int((u.get('document_type') or ['0'])[0])) == 'Quittung']
        self.assertEqual(len(bills), 1)                               # the shop's invoice as a receipt
        audit = (self.cfg.audit_path).read_text()
        self.assertIn('mailimport_filed', audit)
        for x in SUBJECTS + NAMES:
            self.assertNotIn(x, audit)

    def test_duplicate_at_upload_budget_and_fallbacks(self):
        pid, s = self.scan(download=False)                            # no bytes in the scan: name + date only
        self.assertEqual(s['checksum']['checked'], 0)
        self.assertEqual(s['categories']['insurance']['duplicates']['exact'], 0)
        self.pl.csum[8] = hashlib.md5(PDF_B).hexdigest()              # the phone bill arrived meanwhile
        self.mi._sleep = lambda s: None
        r = self.mi.start_run({'plan': pid, 'categories': ['bill', 'insurance']})
        self.assertEqual(r['to_import'], 2)
        self.mi.import_run(r['run'])
        self.assertEqual(self.mi.db.run(r['run'])['counts'], {'duplicate': 2})
        self.assertEqual(self.pl.uploads, [])
        # paperless without the checksum filter: per-document /metadata/
        old = PaperlessCS(honor=False)
        old.csum[7] = 'ab' * 16
        mi2, _ = make_service('mi-old', self.imap, old)
        self.assertEqual(mi2.checksum_method(), 'metadata')
        self.assertEqual(mi2.by_checksum('AB' * 16, 'metadata'), 7)
        self.assertEqual(self.mi.checksum_method(), 'filter')
        # the daily budget: a run waits instead of downloading over it
        self.mi.mb_day = 0
        r = self.mi.start_run({'plan': pid, 'categories': ['payslip']})
        waits = []

        def stop_after(s):
            waits.append(s)
            self.mi._cancel.set()
        self.mi._sleep = stop_after
        self.mi.import_run(r['run'])
        self.assertEqual((self.mi.db.run(r['run'])['status'], waits), ('waiting', [600]))
        self.mi._cancel.clear()

    def test_inbox_fallback_since_max_cancel_and_resume(self):
        imap = DocIMAP(all_mail=False)
        fill(imap, 'INBOX')
        mi, _ = make_service('mi-inbox', imap, self.pl)
        r = mi.start_scan({'max': 3, 'llm': False})
        mi.scan(r['plan'])
        s = mi.summary(r['plan'])
        self.assertEqual((s['accounts']['main']['all_mail'], s['totals']['mails']), (False, 2))   # newest 3: 1 image
        self.assertEqual(s['categories']['unsure']['sorted_by'], {'no-llm': 1})
        r = mi.start_scan({'since': time.strftime('%Y-%m-%d', time.localtime(NOW - 1 * DAY))})
        mi._cancel.set()                                              # cancelled at the first step
        mi.scan(r['plan'])
        mi.cancel({'plan': r['plan']})
        mi._cancel.clear()
        self.assertEqual(mi.db.plan(r['plan'])['status'], 'cancelled')
        self.assertTrue(mi.start_scan({'resume': r['plan']})['resumed'])
        mi.scan(r['plan'])
        self.assertEqual(mi.summary(r['plan'])['totals']['mails'], 1)  # Gmail's after: is a date
        with self.assertRaises(V.VaultError):
            mi.start_scan({'since': '16.10.2026'})
        with self.assertRaises(V.VaultError):
            mi.start_run({'plan': r['plan'], 'categories': ['bills']})
        self.assertEqual(mi.drop({'plan': r['plan']})['rows'], 1)


class ApiMailImportTests(T.ApiBase):
    name = 'api-mailimport'

    @classmethod
    def setUpClass(cls):
        cls.imap = DocIMAP()
        fill(cls.imap, ALL)
        cls.pl = seed(PaperlessCS())
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0',
                         'VAULT_MAILIMPORT_LLM_PACE': '0', 'VAULT_MAILIMPORT_IMAP_PACE': '0'}
        super().setUpClass()
        cls.app.store.set('paperless', {'url': cls.pl.url, 'token': T.PL_TOKEN})

    def test_routes(self):
        st, r = self.call('POST', '/secrets/gmail', {'address': TG.ADDR, 'app_password': TG.APP_PW_SHOWN})
        self.assertEqual(st, 200, r)
        st, r = self.call('GET', '/gmail/import')
        self.assertEqual((st, r['plans']), (200, []))
        llm_answers([{'n': 1, 'c': 'contract'}, {'n': 2, 'c': 'other'}])
        st, r = self.call('POST', '/gmail/import/scan', {'accounts': 'all'})
        self.assertEqual(st, 200, r)
        pid = r['plan']
        st, r2 = self.call('POST', '/gmail/import/scan', {})
        self.assertEqual((st, r2.get('code')), (409, 'busy'))
        st, r2 = self.call('POST', '/gmail/import/run', {'plan': pid, 'categories': ['bill']})
        self.assertEqual((st, r2.get('code')), (409, 'not_ready'))
        self.app.mailimport.scan(pid)                                 # (the worker thread runs this in the vault)
        st, s = self.call('GET', f'/gmail/import?plan={pid}')
        self.assertEqual((st, s['status'], s['totals']['attachments']), (200, 'done', 10))
        self.assertNotIn('Lohnabrechnung_2026', json.dumps(s, ensure_ascii=False))
        st, d = self.call('POST', '/gmail/import/run', {'plan': pid, 'categories': 'bill,receipt', 'dry': True})
        self.assertEqual((st, d['to_import'], d['dry']), (200, 2, True))
        st, e = self.call('POST', '/gmail/import/run', {'plan': pid, 'categories': ['everything']})
        self.assertEqual((st, e.get('code')), (400, 'bad_param'))
        st, e = self.call('POST', '/gmail/import/scan', {'folder': 'x'})
        self.assertEqual((st, e.get('code')), (400, 'unknown_param'))
        st, c = self.call('POST', '/gmail/import/cancel', {})
        self.assertEqual((st, c['cancelled']), (200, []))
        st, d = self.call('POST', '/gmail/import/drop', {'plan': pid})
        self.assertEqual((st, d['rows']), (200, 10))



@unittest.skipUnless((T.CLI_DIR / 'vault').is_file(), 'client not here (image)')
class ClientMailImportTests(T.ApiBase):
    """~/bin/vault gmail import … -> this in-process vault (aggregates only on the terminal)."""
    name = 'cli-mailimport'

    @classmethod
    def setUpClass(cls):
        cls.imap = DocIMAP()
        fill(cls.imap, ALL)
        cls.pl = seed(PaperlessCS())
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0',
                         'VAULT_MAILIMPORT_LLM_PACE': '0', 'VAULT_MAILIMPORT_IMAP_PACE': '0'}
        super().setUpClass()
        cls.app.store.set('paperless', {'url': cls.pl.url, 'token': T.PL_TOKEN})
        cls.app.store.set('gmail', {'address': TG.ADDR, 'app_password': TG.APP_PW})
        home = T.TMP / 'cli-mi-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        (home / 'bin' / 'vault').symlink_to(T.CLI_DIR / 'vault')
        tok = T.TMP / 'cli-mi-token'
        tok.write_text(T.TOKEN + '\n')
        tok.chmod(0o600)
        cls.bin = home / 'bin'
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': cls.url, 'VAULT_TOKEN_FILE': str(tok)}

    def cli(self, *args):
        p = T.subprocess.run([str(self.bin / 'vault'), 'gmail', 'import', *args], env=self.env, capture_output=True,
                             text=True, timeout=90)
        return p.returncode, p.stdout, p.stderr

    def test_client(self):
        rc, out, err = self.cli('status')
        self.assertEqual((rc, out.strip()), (0, 'no plan yet: vault gmail import scan'), err)
        llm_answers([{'n': 1, 'c': 'contract'}, {'n': 2, 'c': 'other'}])
        rc, out, err = self.cli('scan', '--max', '50')
        self.assertEqual(rc, 0, err)
        pid = re.search(r'plan (mi[0-9a-f]{6}): queued', out).group(1)
        self.app.mailimport.scan(pid)
        rc, out, err = self.cli('status', pid)
        self.assertEqual(rc, 0, err)
        self.assertIn(f'plan {pid} · done', out)
        self.assertRegex(out, r'payslip +3 +3 +1 +0 +1 +1 +0')
        self.assertIn('types: contract -> Vertrag (new)', out)
        for x in SUBJECTS + NAMES:
            self.assertNotIn(x, out)
        rc, out, err = self.cli('--plan', pid, '--categories', 'bill,receipt', '--dry-run')
        self.assertEqual((rc, out.split(' · ')[0]), (0, 'dry run: 2 documents (bill 1, receipt 1)'), err)
        rc, out, err = self.cli('--plan', pid, '--categories', 'bills')
        self.assertNotEqual(rc, 0)
        self.assertIn('unknown categories bills', out + err)
        rc, out, err = self.cli('cancel')
        self.assertEqual((rc, out.strip()), (0, 'cancelled: nothing was running'), err)
        rc, out, err = self.cli('drop', pid)
        self.assertEqual((rc, out.strip()), (0, f'plan {pid} removed from the vault (10 rows)'), err)


if __name__ == '__main__':
    unittest.main(verbosity=1)
