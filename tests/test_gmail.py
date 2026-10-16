#!/usr/bin/python3 -I
"""Tests for the vault's Gmail source (app/gmail.py) against an in-process fake IMAP server (plain TCP, imaplib
compatible: CAPABILITY, LOGIN, EXAMINE, UID SEARCH incl. CHARSET literals, UID FETCH with BODY.PEEK partials, IDLE).

Two accounts (secret gmail = "main" + gmail:work on the same fake server, one mailbox each): own secrets, state,
positions, folder config, auth block and alerts; REFs and events carry the account label; search over all accounts;
the read-only guarantee for each account.

Covers: the read-only guarantee (the client refuses STORE/COPY/MOVE/EXPUNGE/SELECT/... before sending, and the fake
server never sees one), IDLE (new mail wakes the poll, renewal, reconnect after a dropped connection), the poll ->
event feed path with a stubbed local LLM (triage labels, anonymized text, sender as name + domain, pseudonymous
sender keys, mute/priority by domain or address, positions only moving after the feed stored the batch, UIDVALIDITY
reset, no backlog on the first run), the API routes (status, search incl. a non-ASCII query, get, config,
to-paperless, raw requests), secrets never logged, the events cursor, and the ~/bin clients when they exist.

Reuses test_vault's fixtures (stub llm-local, fake Telegram + paperless). Fixture rule: never write a complete
token or app password literally; build such values at runtime."""
import base64
import contextlib
import email.message
import imaplib
import json
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_vault as T  # noqa: E402  (fixtures: TMP, stub LLM, fake Telegram/paperless, ApiBase)

import board as B  # noqa: E402
import gmail as G  # noqa: E402
import vaultd as D  # noqa: E402
import vaultlib as V  # noqa: E402

ADDR = 'lukas.' + 'meier' + '@gmail.com'
APP_PW = 'abcd' + 'efgh' + 'ijkl' + 'mnop'
ADDR2 = 'l.' + 'meier' + '@firma.ch'                   # the second account ("work")
APP_PW2 = 'qrst' + 'uvwx' + 'yzab' + 'cdef'
APP_PW_SHOWN = ' '.join(APP_PW[i:i + 4] for i in range(0, 16, 4))      # how Google shows it
FORBIDDEN = {'STORE', 'COPY', 'MOVE', 'EXPUNGE', 'APPEND', 'SELECT', 'CLOSE', 'CREATE', 'DELETE', 'RENAME',
             'SUBSCRIBE', 'UNSUBSCRIBE', 'UID STORE', 'UID COPY', 'UID MOVE', 'UID EXPUNGE', 'AUTHENTICATE'}
PDF = T.make_pdf(['Rechnung 2026-77', 'Betrag CHF 45.00'])


# ============================================================================================ fake IMAP server

def mail(sender, subject, body='', html=None, attachments=(), bulk=False, inline_img=False):
    m = email.message.EmailMessage()
    m['From'] = sender
    m['To'] = ADDR
    m['Subject'] = subject
    m['Date'] = 'Tue, 13 Oct 2026 10:00:00 +0200'
    if bulk:
        m['List-Unsubscribe'] = '<https://example.org/unsub?u=1>'
    if body is not None:
        m.set_content(body)
    if html is not None:
        if body is None:
            m.set_content(html, subtype='html')
        else:
            m.add_alternative(html, subtype='html')
    if inline_img:
        m.add_attachment(b'\x89PNG fake', maintype='image', subtype='png', filename='logo.png',
                         disposition='inline', cid='<logo1>')
    for fn, data, ctype in attachments:
        mt, st = ctype.split('/')
        m.add_attachment(data, maintype=mt, subtype=st, filename=fn)
    return bytes(m)


class FakeIMAP:
    """A small IMAP4rev1 server: per folder [(uid, internaldate, raw)], UIDVALIDITY, UIDNEXT. Records every command
    (`log`: 'NAME' or 'UID SUB' + the raw line) and whether a fetch would have set \\Seen."""

    def __init__(self, idle=True, gmail_ext=True, serve=True):
        self.idle_cap, self.gmail_ext = idle, gmail_ext
        self.folders = {'INBOX': [], 'Rechnungen': [], 'Rechnungen/März': []}
        self.uidvalidity = {f: 7 for f in self.folders}
        self.next_uid = {f: 1 for f in self.folders}
        self.log, self.lines = [], []
        self.seen_set = False
        self.idlers = []                               # (folder, write) of connections in IDLE
        self.conns = []
        self.lock = threading.Lock()
        self.password = APP_PW
        self.users = {}                                # further accounts: address -> their mailbox (a FakeIMAP)
        if not serve:
            return
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                with contextlib.suppress(OSError):                 # the client went away (drop tests)
                    outer.serve(self)

        class S(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
        self.srv = S(('127.0.0.1', 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def add(self, folder, raw, ts=None, uid=None):
        with self.lock:
            uid = uid or self.next_uid[folder]
            self.next_uid[folder] = uid + 1
            self.folders[folder].append((uid, ts or time.time(), raw))
            n = len(self.folders[folder])
            for f, w in list(self.idlers):
                if f == folder:
                    try:
                        w(f'* {n} EXISTS\r\n'.encode())
                    except OSError:
                        pass
        return uid

    def add_user(self, addr, password):
        """A second account on this server with its own mailbox (returned: add mail to it with .add)."""
        box = FakeIMAP(self.idle_cap, self.gmail_ext, serve=False)
        box.password = password
        self.users[addr] = box
        return box

    def drop_all(self):
        """Close every client connection (network failure / server restart)."""
        for box in self.users.values():
            box.idlers = []
        with self.lock:
            conns, self.conns, self.idlers = self.conns, [], []
        for c in conns:
            with contextlib.suppress(OSError):
                c.shutdown(socket.SHUT_RDWR)

    def names(self):
        return [n for n, _ in self.log]

    @staticmethod
    def tokens(line):
        return re.findall(rb'"(?:[^"\\]|\\.)*"|\(|\)|[^\s()]+', line)

    @staticmethod
    def unq(t):
        t = t.decode() if isinstance(t, bytes) else t
        return t[1:-1].replace('\\"', '"').replace('\\\\', '\\') if t.startswith('"') else t

    def serve(self, h):
        lock = threading.Lock()

        def w(b):
            with lock:
                h.wfile.write(b)
                h.wfile.flush()
        with self.lock:
            self.conns.append(h.connection)
        w(b'* OK fake IMAP ready\r\n')
        folder, box = None, self                       # box: the logged-in account's mailbox
        while True:
            line = h.rfile.readline()
            if not line:
                return
            line = line.rstrip(b'\r\n')
            lit = None
            m = re.search(rb'\{(\d+)\}$', line)
            if m:
                w(b'+ go ahead\r\n')
                lit = h.rfile.read(int(m.group(1)))
                line = line[:m.start()].rstrip() + b' ' + h.rfile.readline().rstrip(b'\r\n')
            tk = self.tokens(line)
            if len(tk) < 2:
                continue
            tag, cmd = tk[0], tk[1].decode().upper()
            name = cmd + (' ' + tk[2].decode().upper() if cmd == 'UID' and len(tk) > 2 else '')
            self.log.append((name, line.decode('utf-8', 'replace')))
            ok = lambda txt='done': w(tag + b' OK ' + txt.encode() + b'\r\n')  # noqa: E731
            if cmd == 'CAPABILITY':
                caps = 'IMAP4rev1' + (' IDLE' if self.idle_cap else '') + (' X-GM-EXT-1' if self.gmail_ext else '')
                w(f'* CAPABILITY {caps}\r\n'.encode())
                ok()
            elif cmd == 'LOGIN':
                user = self.unq(tk[2])
                b = self if user == ADDR else self.users.get(user)
                if b is not None and self.unq(tk[3]) == b.password:
                    box = b
                    ok('LOGIN completed')
                else:
                    w(tag + b' NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)\r\n')
            elif cmd == 'EXAMINE':
                f = self.unq(tk[2])
                f = {G.imap_utf7(k): k for k in box.folders}.get(f)
                if f is None:
                    w(tag + b' NO [NONEXISTENT] Unknown Mailbox\r\n')
                    continue
                folder = f
                msgs = box.folders[f]
                w(f'* FLAGS (\\Answered \\Flagged \\Seen)\r\n* {len(msgs)} EXISTS\r\n* 0 RECENT\r\n'
                  f'* OK [UIDVALIDITY {box.uidvalidity[f]}] UIDs valid\r\n'
                  f'* OK [UIDNEXT {box.next_uid[f]}] Predicted next UID\r\n'.encode())
                ok('[READ-ONLY] EXAMINE completed')
            elif name == 'UID SEARCH' and folder:
                time.sleep(getattr(box, 'search_delay', 0))   # a slow account (~54 s in a live run)
                ok_ = box.search(folder, tk[3:], lit)
                w(('* SEARCH' + ''.join(f' {u}' for u in ok_) + '\r\n').encode())
                ok()
            elif name == 'UID FETCH' and folder:
                box.fetch(folder, tk, w)
                ok()
            elif cmd == 'NOOP':
                ok()
            elif cmd == 'IDLE' and self.idle_cap and folder:
                w(b'+ idling\r\n')
                ent = (folder, w)
                with box.lock:
                    box.idlers.append(ent)
                done = h.rfile.readline()
                with box.lock:
                    if ent in box.idlers:
                        box.idlers.remove(ent)
                if not done:
                    return
                self.log.append(('DONE', done.decode().strip()))
                ok('IDLE terminated')
            elif cmd == 'LOGOUT':
                w(b'* BYE logging out\r\n')
                ok()
                return
            else:
                w(tag + b' BAD command not supported here\r\n')

    def search(self, folder, args, lit):
        msgs = self.folders[folder]
        args = [a.decode() for a in args]
        if args[:1] == ['CHARSET']:
            args = args[2:]
        if not args:
            return []
        key = args[0].upper()
        if key == 'ALL':
            return [u for u, _, _ in msgs]
        if key == 'UID':
            a, _, b = args[1].partition(':')
            hi = max([u for u, _, _ in msgs] or [0])
            lo, top = int(a), (hi if b == '*' else int(b))
            res = [u for u, _, _ in msgs if lo <= u <= top]
            return res or ([hi] if b == '*' and hi else [])      # RFC 3501: n:* always matches the last message
        if key in ('X-GM-RAW', 'TEXT'):
            q = (lit.decode('utf-8') if lit is not None else self.unq(args[1])).lower()
            hay = {u: ' '.join((G.header(m, 'From'), G.header(m, 'Subject'), G.body_text(m))).lower()
                   for u, m in ((u, G.parse_message(r)) for u, _, r in msgs)}
            return [u for u, _, _ in msgs if q in hay[u]]
        return []

    def fetch(self, folder, tk, w):
        uidset = tk[3].decode()
        items = b' '.join(tk[4:]).decode().upper()
        if re.search(r'BODY\[|RFC822(?![.]SIZE)|BINARY\[', items.replace('BODY.PEEK[', 'PEEK[')):
            self.seen_set = True                       # a real server would set \Seen now
        spans = []                                     # RFC 3501 sequence sets: 5 | 5:9 | 5:* | 3,7,9:12
        for piece in uidset.split(','):
            a, _, b = piece.partition(':')
            spans.append((int(a), (int(b) if b and b != '*' else (10 ** 9 if b == '*' else int(a)))))
        self.fetch_calls = getattr(self, 'fetch_calls', 0) + 1
        for seq, (uid, ts, raw) in enumerate(self.folders[folder], 1):
            if not any(lo <= uid <= hi for lo, hi in spans):
                continue
            parts = [f'UID {uid}']
            if 'INTERNALDATE' in items:
                parts.append(f'INTERNALDATE {imaplib.Time2Internaldate(ts)}')
            if 'RFC822.SIZE' in items:
                parts.append(f'RFC822.SIZE {len(raw)}')
            m = re.search(r'BODY\.PEEK\[\](?:<0\.(\d+)>)?', items)
            if m:
                data = raw[:int(m.group(1))] if m.group(1) else raw
                key = 'BODY[]<0>' if m.group(1) else 'BODY[]'
                w(f'* {seq} FETCH ({" ".join(parts)} {key} {{{len(data)}}}\r\n'.encode() + data + b')\r\n')
            else:
                w(f'* {seq} FETCH ({" ".join(parts)})\r\n'.encode())


# ============================================================================================ helpers

def make_gmail(name, imap, **env):
    cfg = T.make_cfg(name, VAULT_GMAIL_IMAP=f'127.0.0.1:{imap.port}', VAULT_GMAIL_TLS='0', **env)
    store = V.SecretStore(cfg)
    gate = V.LLMGate()
    policy = V.Policy(cfg, gate)
    audit = V.Audit(cfg.audit_path)
    alerts = []
    g = G.Gmail(cfg, store, policy, audit, store.hmac_key(),
                alert=lambda kind, title, body, hours=6: alerts.append((kind, title, body)))
    g.alerts = alerts
    events = V.EventStore(cfg.state / 'events.db')
    rules = V.EventRules(cfg.state / 'events-rules.json')
    feed = V.EventFeed(events, rules, policy, gate)
    return cfg, store, g, feed, events, rules


def make_accounts(name, imap):
    """GmailAccounts (what vaultd uses) on the same fixtures as make_gmail."""
    cfg, store, g, feed, events, rules = make_gmail(name, imap)
    gs = G.GmailAccounts(cfg, store, g.policy, g.audit, store.hmac_key(),
                         alert=lambda kind, title, body, hours=6: g.alerts.append((kind, title, body)))
    gs.alerts = g.alerts
    return cfg, store, gs, feed, events, rules


def wait_for(cond, timeout=10.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return cond()


def gmail_triage_says(*labels):
    (T.STUB_DIR / 'llm-json').write_text(json.dumps({'results': [
        {'i': n, 'label': lab, 'actionable': lab not in ('newsletter', 'other')} for n, lab in enumerate(labels, 1)]}))


BILL = lambda: mail('Galaxus Rechnungen <rechnung@news.galaxus.ch>', 'Ihre Rechnung 2026-77',  # noqa: E731
                    f'Guten Tag Lukas\nBitte bezahlen Sie CHF 45.00 bis 30.10.2026. Fragen: {T.PHONE}.\nIBAN {T.IBAN}',
                    attachments=[('Rechnung-2026-77.pdf', PDF, 'application/pdf')], inline_img=True)
NEWS = lambda: mail('Digitec <news@digitec.ch>', 'Top Deals der Woche', None,  # noqa: E731
                    html='<html><head><style>p{color:red}</style></head><body><p>Nur heute:&nbsp;50% auf alles</p>'
                         '<script>x()</script></body></html>', bulk=True)
PERSON = lambda: mail('Anna Muster <anna.muster@gmx.ch>', 'Samstag?',  # noqa: E731
                      'Hoi Lukas, kommst du am Samstag? Ich habe Herzschmerz. Sag mir bis Freitag Bescheid.')


class ReadOnlyCheck(unittest.TestCase):
    """Every test ends with: the fake server never saw a command that could change mail, and no fetch would have
    set \\Seen."""
    imap = None

    def tearDown(self):
        if self.imap is not None:
            self.assertFalse(set(self.imap.names()) & FORBIDDEN, self.imap.names())
            self.assertFalse(self.imap.seen_set)
            self.assertTrue({n.split()[1] for n in self.imap.names() if n.startswith('UID ')} <= {'SEARCH', 'FETCH'})


# ============================================================================================ unit tests

class ParsingTests(unittest.TestCase):
    def test_body_attachments_sender_and_names(self):
        msg = G.parse_message(BILL())
        self.assertIn('CHF 45.00', G.body_text(msg))
        self.assertEqual(G.attachments_meta(msg), [{'index': 1, 'name': 'Rechnung-2026-77.pdf',
                                                     'type': 'application/pdf', 'size': len(PDF)}])   # no inline logo
        self.assertEqual(G.sender_of(msg), ('Galaxus Rechnungen', 'rechnung@news.galaxus.ch', 'news.galaxus.ch'))
        news = G.parse_message(NEWS())
        self.assertEqual(G.body_text(news), 'Nur heute: 50% auf alles')                   # HTML -> text, no CSS/JS
        stub = G.parse_message(mail('A <a@b.ch>', 's', 'View in browser', html='<p>' + 'Real content. ' * 5 + '</p>'))
        self.assertIn('Real content.', G.body_text(stub))                                 # a plain stub: HTML wins
        both = G.parse_message(mail('A <a@b.ch>', 's', 'Plain text body that is long enough to win.',
                                    html='<p>HTML version</p>'))
        self.assertEqual(G.body_text(both), 'Plain text body that is long enough to win.')
        self.assertEqual(G.domain_keys('news.galaxus.ch'), ['news.galaxus.ch', 'galaxus.ch'])
        self.assertEqual(G.imap_utf7('Rechnungen/März'), 'Rechnungen/M&AOQ-rz')
        self.assertEqual(G.imap_utf7('A&B'), 'A&-B')
        self.assertEqual(G.quote_mailbox('[Gmail]/All "Mail"'), '"[Gmail]/All \\"Mail\\""')
        self.assertEqual(G.parse_ref('1234'), (1234, 'INBOX'))
        self.assertEqual(G.parse_ref('55@Rechnungen'), (55, 'Rechnungen'))
        self.assertEqual(G.parse_ref(7, 'inbox'), (7, 'INBOX'))
        for bad in ('x', True, -1, 0, '1@' + 'x' * 200, None):
            with self.assertRaises(V.VaultError, msg=bad):
                G.parse_ref(bad)
        self.assertEqual(G.safe_filename('../../etc/pass"wd', 3, 1, 'application/pdf'), 'pass_wd.pdf')
        self.assertEqual(G.safe_filename(None, 3, 2, 'image/png'), 'gmail-3-2.png')

    def test_command_allowlist(self):
        for name, args in (('STORE', ('1', '+FLAGS', '(\\Seen)')), ('COPY', ('1', 'X')), ('MOVE', ('1', 'X')),
                           ('EXPUNGE', ()), ('SELECT', ('INBOX',)), ('CLOSE', ()), ('APPEND', ('INBOX',)),
                           ('DELETE', ('X',)), ('UID', ('STORE', '1', '+FLAGS', '(\\Deleted)')),
                           ('UID', ('COPY', '1', 'Trash')), ('UID', ('MOVE', '1', 'Trash')), ('UID', ('EXPUNGE', '1')),
                           ('UID', ('FETCH', '1', '(BODY[])')), ('UID', ('FETCH', '1', '(RFC822)')),
                           ('UID', ('FETCH', '1', '(UID RFC822.TEXT)')), ('UID', ('FETCH', '1', '(BINARY[1])')),
                           ('FETCH', ('1', '(BODY.PEEK[])')), ('AUTHENTICATE', ('PLAIN',))):
            with self.assertRaises(G.ReadOnlyViolation, msg=(name, args)):
                G.check_command(name, args)
        for name, args in (('UID', ('FETCH', '1', '(UID INTERNALDATE RFC822.SIZE BODY.PEEK[]<0.1048576>)')),
                           ('UID', ('FETCH', '1:*', '(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])')),
                           ('UID', ('SEARCH', 'UID', '5:*')), ('EXAMINE', ('"INBOX"',)), ('LOGIN', ('a', 'b')),
                           ('NOOP', ()), ('LOGOUT', ()), ('CAPABILITY', ())):
            G.check_command(name, args)

    def test_secret_spec(self):
        cfg = T.make_cfg('gmail-secret-spec')
        st = V.SecretStore(cfg)
        self.assertEqual(st.validate('gmail', {'address': ADDR, 'app_password': APP_PW_SHOWN}),
                         {'address': ADDR, 'app_password': APP_PW})
        for bad in ({'address': 'nope', 'app_password': APP_PW}, {'address': ADDR, 'app_password': 'short'},
                    {'address': ADDR, 'app_password': APP_PW + '1'}, {'address': ADDR}):
            with self.assertRaises(V.VaultError, msg=bad):
                st.validate('gmail', bad)


class ImapClientTests(ReadOnlyCheck):
    def setUp(self):
        self.imap = FakeIMAP()
        self.cfg, self.store, self.g, self.feed, self.events, self.rules = make_gmail(f'gm-{self._testMethodName}',
                                                                                      self.imap)
        self.store.set('gmail', {'address': ADDR, 'app_password': APP_PW})

    def test_client_refuses_writes_before_sending(self):
        self.imap.add('INBOX', PERSON())
        with self.g.session() as im:
            n0 = len(self.imap.log)
            for call in (lambda: im.select('INBOX'), lambda: im.store('1', '+FLAGS', '(\\Seen)'),
                         lambda: im.uid('STORE', '1', '+FLAGS', '(\\Deleted)'), lambda: im.uid('COPY', '1', 'X'),
                         lambda: im.expunge(), lambda: im.close(), lambda: im.create('X'), lambda: im.delete('X'),
                         lambda: im.rename('A', 'B'), lambda: im.append('INBOX', None, None, b'x'),
                         lambda: im.uid('FETCH', '1', '(RFC822)'), lambda: im.uid('FETCH', '1', '(BODY[])'),
                         lambda: im.subscribe('X')):
                with self.assertRaises((G.ReadOnlyViolation, imaplib.IMAP4.error)):
                    call()
            self.assertEqual(len(self.imap.log), n0)                   # nothing reached the server
            self.g.examine(im, 'INBOX')
            raw, ts, size = self.g._fetch(im, 1)
            self.assertIn(b'Herzschmerz', raw)
            self.assertIsNone(self.g._fetch(im, 99))
        self.assertIn('EXAMINE', self.imap.names())

    def test_idle_new_mail_renew_and_reconnect(self):
        stop = threading.Event()
        old = (G.IDLE_RENEW, G.BACKOFF)
        G.IDLE_RENEW, G.BACKOFF = 1, (0.2, 0.2)
        try:
            th = threading.Thread(target=self.g.run_idle, args=(stop,), daemon=True)
            th.start()
            self.assertTrue(wait_for(lambda: self.g.watch['state'] == 'idle'), self.g.watch)
            self.assertTrue(wait_for(lambda: self.imap.names().count('IDLE') >= 2, 6))   # renewed after 1 s
            self.assertIn('DONE', self.imap.names())
            self.assertTrue(wait_for(lambda: self.imap.idlers))
            self.g.wake.clear()
            self.imap.add('INBOX', PERSON())
            self.assertTrue(self.g.wake.wait(5))                       # IDLE saw EXISTS: the poll wakes at once
            self.assertTrue(self.g.watch['last_new_mail'])
            self.imap.drop_all()                                       # connection lost
            self.assertTrue(wait_for(lambda: self.g.watch['reconnects'] >= 1, 8), self.g.watch)
            self.assertTrue(wait_for(lambda: self.g.watch['state'] == 'idle', 8), self.g.watch)
            stop.set()
            th.join(8)
            self.assertFalse(th.is_alive())
        finally:
            G.IDLE_RENEW, G.BACKOFF = old
            stop.set()

    def test_wrong_password_blocks_retries_and_alerts(self):
        self.imap.password = 'zyxw' * 4
        with self.assertRaises(G.AuthFailed) as cm:
            self.g.connect()
        self.assertNotIn(APP_PW, str(cm.exception))
        with self.assertRaises(G.AuthFailed):
            self.g.connect()                                           # blocked: no second LOGIN
        self.assertEqual(self.imap.names().count('LOGIN'), 1)
        self.assertEqual([a[0] for a in self.g.alerts], ['gmail-auth'])
        self.assertIn('vault-console secret gmail', self.g.alerts[0][2])
        self.g.credentials_changed()                                   # a new secret: try again at once
        self.imap.password = APP_PW
        with self.g.session() as im:
            self.assertIn('IDLE', im.capabilities)
        blob = self.cfg.audit_path.read_text() + T.all_files_text(self.cfg.state) + T.all_files_text(self.cfg.inbox)
        self.assertIn('gmail_login_refused', blob)
        self.assertNotIn(APP_PW, blob)


class PollFeedTests(ReadOnlyCheck):
    def setUp(self):
        self.imap = FakeIMAP()
        self.cfg, self.store, self.g, self.feed, self.events, self.rules = make_gmail(f'gm-{self._testMethodName}',
                                                                                      self.imap)
        self.store.set('gmail', {'address': ADDR, 'app_password': APP_PW})
        T.llm_mode('plain')

    def tearDown(self):
        T.llm_mode('ok')
        super().tearDown()

    def positions(self):
        return {k: v['last_uid'] for k, v in json.loads(self.g.state_path.read_text())['folders'].items()}

    def test_first_run_no_backlog_then_triage_and_anonymize(self):
        self.imap.add('INBOX', PERSON())                               # old mail: never surfaced
        self.assertFalse(self.g.poll_once(self.feed))
        self.assertEqual(self.positions(), {'INBOX': 1})
        self.assertEqual(self.events.head(), 0)
        for raw in (BILL(), NEWS(), PERSON()):
            self.imap.add('INBOX', raw)
        gmail_triage_says('bill', 'newsletter', 'reply_needed')
        n0 = len(T.llm_calls())
        self.assertFalse(self.g.poll_once(self.feed))
        calls = T.llm_calls()[n0:]
        self.assertEqual([c['args'][0] for c in calls], ['--json'])     # privacy plan A: triage only, no text
        sysp = calls[0]['args'][calls[0]['args'].index('--system') + 1]
        self.assertIn('bill (an invoice', sysp)
        self.assertNotIn(T.PHONE, calls[0]['text'])                   # regex net before the LLM
        self.assertIn('[email: Galaxus Rechnungen (news.galaxus.ch)] Subject: Ihre Rechnung', calls[0]['text'])
        self.assertIn('[bulk mail]', self.g.item('INBOX', 9, NEWS(), None, len(NEWS()))['text'])
        rows, nxt, more, reset = self.events.since(0)
        self.assertEqual([(r['source'], r['label'], r['actionable'], r['text']) for r in rows],
                         [('gmail', 'bill', 1, None), ('gmail', 'newsletter', 0, None),
                          ('gmail', 'reply_needed', 1, None)])
        bill, news, person = rows
        self.assertEqual((bill['chat'], bill['chat_key'], bill['chat_type'], bill['ref'], bill['account']),
                         ('Galaxus Rechnungen (news.galaxus.ch)', 'news.galaxus.ch', 'email', 'main:2', 'main'))
        self.assertRegex(bill['sender_key'], r'^m[0-9a-f]{10}$')
        self.assertEqual(json.loads(bill['att'])['pdf'], 1)            # privacy plan A: counts, never names
        self.assertNotIn('Rechnung-2026-77', json.dumps(rows))
        blob = json.dumps(rows)
        for leak in ('anna.muster', 'rechnung@', 'news@', T.PHONE, T.IBAN, 'Herzschmerz'):
            self.assertNotIn(leak, blob)
        self.assertEqual(self.positions(), {'INBOX': 4})
        self.assertEqual(self.g.poll['processed'], 3)

    def test_llm_failure_keeps_position_then_retries(self):
        self.g.poll_once(self.feed)
        self.imap.add('INBOX', PERSON())
        T.llm_mode('fail')
        with self.assertRaises(V.LLMUnavailable):
            self.g.poll_once(self.feed)
        self.assertEqual(self.positions(), {'INBOX': 0})
        self.assertEqual(self.events.head(), 0)
        T.llm_mode('plain')
        gmail_triage_says('reply_needed')
        self.g.poll_once(self.feed)
        self.assertEqual(self.positions(), {'INBOX': 1})
        self.assertEqual(self.events.head(), 1)

    def test_rules_by_domain_and_address_uidvalidity_and_folders(self):
        self.g.set_config({'folders': ['Rechnungen/März', 'inbox', 'Fehlt']})
        self.assertEqual(self.g.folders(), ['INBOX', 'Rechnungen/März', 'Fehlt'])
        self.g.poll_once(self.feed)
        self.assertEqual(self.positions(), {'INBOX': 0, 'Rechnungen/März': 0})
        self.assertIn('Fehlt', self.g.poll['error'] or '')
        self.assertTrue(self.g.poll['last_ok_at'])
        self.rules.set('gmail', 'mute', chat='@Galaxus.ch')              # the parent domain mutes news.galaxus.ch
        self.rules.set('gmail', 'priority', sender='Anna.Muster@gmx.ch')   # stored lowercased
        self.imap.add('INBOX', BILL())
        self.imap.add('INBOX', PERSON())
        self.imap.add('Rechnungen/März', NEWS())
        gmail_triage_says('other')                                     # one item per folder batch
        self.g.poll_once(self.feed)
        rows = self.events.since(0)[0]
        self.assertEqual(sorted((r['label'], r['why'] or '', r['priority'], bool(r['text'])) for r in rows),
                         [('collapsed', 'muted', 0, False), ('other', '', 0, False), ('other', '', 1, False)])
        self.assertEqual(self.positions(), {'INBOX': 2, 'Rechnungen/März': 1})
        self.assertEqual(rows[-1]['ref'], 'main:1@Rechnungen/März')
        self.imap.uidvalidity['INBOX'] = 99                            # the folder was rebuilt: start at the end
        self.imap.add('INBOX', PERSON())
        h = self.events.head()
        self.g.poll_once(self.feed)
        self.assertEqual((self.positions()['INBOX'], self.events.head()), (3, h))

    def test_watcher_and_poll_threads_end_to_end(self):
        stop = threading.Event()
        old = G.POLL_SECONDS
        G.POLL_SECONDS = 30
        try:
            threading.Thread(target=self.g.run_idle, args=(stop,), daemon=True).start()
            threading.Thread(target=self.g.run_poll, args=(stop, self.feed), kwargs={'start_delay': 0},
                             daemon=True).start()
            self.assertTrue(wait_for(lambda: self.g.state_path.exists() and self.imap.idlers))
            gmail_triage_says('bill')
            t0 = time.time()
            self.imap.add('INBOX', BILL())
            self.assertTrue(wait_for(lambda: self.events.head() == 1, 15), (self.g.watch, self.g.poll))
            self.assertLess(time.time() - t0, 15)                      # IDLE, not the 30 s poll
            self.assertEqual(self.events.since(0)[0][0]['label'], 'bill')
        finally:
            stop.set()
            G.POLL_SECONDS = old
            self.g.wake.set()

    def test_poll_only_without_idle(self):
        self.imap.idle_cap = False
        stop = threading.Event()
        th = threading.Thread(target=self.g.run_idle, args=(stop,), daemon=True)
        th.start()
        self.assertTrue(wait_for(lambda: self.g.watch['state'] == 'poll-only'))
        stop.set()
        self.g.credentials_changed()
        th.join(5)
        self.assertNotIn('IDLE', self.imap.names())


# ============================================================================================ API

@T.legacy_text
class ApiGmailTests(T.ApiBase, ReadOnlyCheck):
    name = 'api-gmail'

    @classmethod
    def setUpClass(cls):
        cls.imap = FakeIMAP()
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0'}
        super().setUpClass()
        cls.app.store.set('paperless', {'url': T.PAPERLESS.url, 'token': T.PL_TOKEN})
        cls.app.store.set('telegram', {'bot_token': T.BOT_TOKEN, 'chat_id': T.CHAT_ID})
        cls.uids = [cls.imap.add('INBOX', raw) for raw in (BILL(), NEWS(), PERSON())]
        cls.imap.add('INBOX', mail('Post CH <noreply@post.ch>', 'Ihr Paket für März', 'Paket kommt am Mittwoch.'))

    def setUp(self):
        super().setUp()
        T.llm_mode('plain')
        if not self.app.store.is_set('gmail'):
            st, r = self.call('POST', '/secrets/gmail', {'address': ADDR, 'app_password': APP_PW_SHOWN})
            self.assertEqual(st, 200, r)
            self.assertIn('Gmail IMAP login OK, INBOX opened read-only (4 mails)', r['check'])

    def tearDown(self):
        T.llm_mode('ok')
        ReadOnlyCheck.tearDown(self)

    def test_status_search_get_config(self):
        st, r = self.call('GET', '/gmail/status')
        self.assertEqual(st, 200, r)
        self.assertEqual((r['configured'], r['read_only'], [(a['account'], a['domain'], a['folders'])
                                                            for a in r['accounts']]),
                         (True, True, [('main', 'gmail.com', ['INBOX'])]))
        self.assertNotIn('lukas', json.dumps(r))                       # never the address's local part
        st, s = self.call('GET', '/status')
        self.assertEqual((s['secrets']['gmail'], s['gmail']['configured'], s['events']['sources']),
                         (True, True, ['telegram', 'gmail']))
        st, r = self.call('POST', '/gmail/search', {'q': 'Rechnung', 'n': 5})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['count'], r['total']), (1, 1))
        m = r['results'][0]
        self.assertEqual((m['ref'], m['account'], m['from'], m['subject']),
                         ('main:1', 'main', 'Galaxus Rechnungen (news.galaxus.ch)', 'Ihre Rechnung 2026-77'))
        self.assertEqual(m['attachments'][0]['type'], 'application/pdf')
        self.assertNotIn(T.PHONE, json.dumps(r))
        self.assertIn('X-GM-RAW "Rechnung"', [ln for n, ln in self.imap.log if n == 'UID SEARCH'][-1])
        st, r = self.call('POST', '/gmail/search', {'q': 'für März'})   # non-ASCII: a UTF-8 literal
        self.assertEqual((st, r['count']), (200, 1), r)
        self.assertIn('CHARSET UTF-8 X-GM-RAW', [ln for n, ln in self.imap.log if n == 'UID SEARCH'][-1])
        st, r = self.call('POST', '/gmail/get', {'uid': '3', 'chars': 2000})   # one account: a bare uid is enough
        self.assertEqual(st, 200, r)
        self.assertEqual((r['ref'], r['account']), ('main:3', 'main'))
        self.assertEqual((r['from'], r['subject']), ('Anna Muster (gmx.ch)', 'Samstag?'))
        self.assertIn('[private: health]', r['text'])
        self.assertNotIn('anna.muster', json.dumps(r))
        for bad in ({'uid': 'x'}, {'uid': 3, 'folder': 'Nope'}, {'uid': 999}):
            st, e = self.call('POST', '/gmail/get', bad)
            self.assertIn(st, (400, 404), (bad, e))
        st, e = self.call('POST', '/gmail/search', {'q': ''})
        self.assertEqual((st, e['code']), (400, 'bad_param'))
        st, r = self.call('POST', '/gmail/config', {'folders': ['Rechnungen'], 'owner_name': 'Lukas Meier'})
        self.assertEqual((st, r['account'], r['folders']), (200, 'main', ['INBOX', 'Rechnungen']), r)
        st, e = self.call('POST', '/gmail/config', {'folders': 'x'})
        self.assertEqual(st, 400)
        st, r = self.call('GET', '/gmail/config')
        self.assertEqual([(a['account'], a['owner_name']) for a in r['accounts']], [('main', 'Lukas Meier')])
        self.call('POST', '/gmail/config', {'folders': []})
        ev = [e['event'] for e in self.app.audit.read()]
        for name in ('gmail_search', 'gmail_get', 'gmail_config', 'secret_set'):
            self.assertIn(name, ev)

    def test_fast_search_quick_card_and_retriage(self):
        """Regression: a default search (one triage call per page) and the default card (anonymize the mail + an
        answer call) took 200 s. Search: the feed's label or the label cache, "?" otherwise, no LLM call; triage=true:
        ONE call for the rest, cached. Card: from the feed row, the cache or ONE triage call. Retriage: stored feed
        rows get today's triage (counts + cursors only)."""
        T.llm_mode('ok')
        n0 = len(T.llm_calls())
        st, r = self.call('POST', '/gmail/search', {'q': 'Rechnung', 'text': False})
        self.assertEqual(st, 200, r)
        self.assertEqual([(m['ref'], m['category']) for m in r['results']], [('main:1', '?')])
        self.assertNotIn('subject', r['results'][0])
        self.assertEqual(len(T.llm_calls()), n0)                         # no LLM call by default
        head = self.app.events.head()
        self.app.events.add([{'source': 'gmail', 'ts': 1760000000, 'chat_key': 'news.galaxus.ch',
                              'chat': 'Galaxus Rechnungen (news.galaxus.ch)', 'chat_type': 'email', 'label': 'bill',
                              'actionable': 1, 'ref': 'main:1', 'wants': 'payment', 'urgency': 'week',
                              'who': 'Galaxus Rechnungen (news.galaxus.ch)', 'account': 'main',
                              'att': json.dumps({'n': 1, 'pdf': 1, 'image': 0})}])
        st, r = self.call('POST', '/gmail/search', {'q': 'Rechnung', 'text': False})
        self.assertEqual(r['results'][0]['category'], 'bill')
        st, c = self.call('POST', '/gmail/get', {'uid': '1', 'text': False})    # bare uid -> the feed's REF
        self.assertEqual(st, 200, c)
        self.assertEqual((c['kind'], c['ref'], c['category'], c['via'], c['action'], c['urgency'], c['attachments']),
                         ('mail_card', 'main:1', 'bill', 'feed', 'pay', 'week', {'n': 1, 'pdf': 1, 'image': 0}))
        self.assertIn('to-paperless main:1', c['hint'])
        self.assertEqual(len(T.llm_calls()), n0)                         # the feed's triage: still no LLM call
        gmail_triage_says('reply_needed')
        st, r = self.call('POST', '/gmail/search', {'q': 'Samstag', 'text': False, 'triage': True})
        self.assertEqual((st, [m['category'] for m in r['results']]), (200, ['reply_needed']), r)
        self.assertEqual(len(T.llm_calls()), n0 + 1)                     # ONE call for the page
        st, r = self.call('POST', '/gmail/search', {'q': 'Samstag', 'text': False})
        self.assertEqual(([m['category'] for m in r['results']], len(T.llm_calls())), (['reply_needed'], n0 + 1))
        gmail_triage_says('delivery')
        st, c = self.call('POST', '/gmail/get', {'uid': 'main:4', 'text': False})
        self.assertEqual((st, c['category'], c['via'], c['from'], c['cached']),
                         (200, 'delivery', 'triage', 'Post CH (post.ch)', False), c)
        self.assertEqual(len(T.llm_calls()), n0 + 2)
        st, c = self.call('POST', '/gmail/get', {'uid': 'main:4', 'text': False})
        self.assertEqual((c['category'], c['via'], len(T.llm_calls())), ('delivery', 'cache', n0 + 2))
        for bad in ({'q': 'x', 'triage': 'yes'},):
            st, e = self.call('POST', '/gmail/search', dict(bad, text=False))
            self.assertEqual(st, 400, e)
        st, e = self.call('POST', '/gmail/get', {'uid': 'main:4', 'text': False, 'deep': 'yes'})
        self.assertEqual(st, 400, e)
        gmail_triage_says('deadline')
        st, rr = self.call('POST', '/events/retriage', {'since': head})
        self.assertEqual(st, 200, rr)
        self.assertEqual((rr['retriaged'], rr['changed'], rr['missing'], rr['more']), (1, 1, 0, False), rr)
        self.assertEqual(self.app.events.labels('gmail', ['main:1'])['main:1']['label'], 'deadline')
        self.assertEqual(self.app.events.head(), head + 1)                # same cursor: the cron feed sees it once
        for bad in ({'since': -1}, {'since': 'x'}, {'since': 0, 'max': 99}):
            st, e = self.call('POST', '/events/retriage', bad)
            self.assertEqual(st, 400, (bad, e))
        self.assertIn('events_retriage', [e['event'] for e in self.app.audit.read()])

    def test_policy_v4_paraphrase_and_the_watch(self):
        # Policy v4: subjects, snippets and bodies leave as checked paraphrases (this stub's
        # "paraphrase": Treffpunkt -> Meeting point); the owner's full watch shows exactly that as "Claude got"
        uid = self.imap.add('INBOX', mail('Anna Muster <anna.muster@gmx.ch>', 'Velotour Samstag',
                                          'Treffpunkt Bahnhof 07:30, er hat Herzschmerz'))
        self.app.tap.bot_full_until = time.time() + 60
        try:
            n0 = len(T.llm_calls())
            st, r = self.call('POST', '/gmail/search', {'q': 'Velotour', 'n': 5})
            self.assertEqual((st, r.get('count')), (200, 1), r)
            self.assertEqual([c['args'][-1] for c in T.llm_calls()[n0:]], ['--paraphrase'])
            self.assertIn('Meeting point Bahnhof 07:30', r['results'][0]['snippet'])
            st, g = self.call('POST', '/gmail/get', {'uid': str(uid)})
            self.assertEqual(st, 200, g)
            self.assertEqual(T.llm_calls()[-1]['args'][-2:], ['--all-amounts', '--paraphrase'])
            self.assertIn('Meeting point Bahnhof 07:30, er hat [private: health]', g['text'])
            for path in ('/gmail/search', '/gmail/get'):
                ev = [e for e in self.app.tap.raw_since(0) if e['path'] == path][-1]
                self.assertIn('Meeting point Bahnhof 07:30', ev['readable'], path)
                self.assertNotIn('Treffpunkt', ev['readable'], path)
                self.assertNotIn('Herzschmerz', ev['readable'] + ev['body'], path)
        finally:
            self.app.tap.bot_full_until = 0.0
            self.app.tap.sweep_raw()

    def test_receipt_amounts_masked(self):
        # Regression: `vault gmail search` showed "$108.34" from receipts. Mail is his own money (policy v3.1):
        # every amount -> [amount] in search, get, attachment names and events, even when the LLM keeps it (this stub)
        uid = self.imap.add('INBOX', mail('Apple <no_reply@email.apple.com>', 'Your receipt from Apple, $108.34',
                                          "Order total: $108.34 | USD 12.00 | CHF 1'234.50 | € 9,99\nTotal: 45.00\n"
                                          "Pickup on 21.10. um 10.30 Uhr",
                                          attachments=[('Invoice-108.34.pdf', PDF, 'application/pdf')]))
        n0 = len(T.llm_calls())
        st, r = self.call('POST', '/gmail/search', {'q': 'receipt from Apple', 'n': 5})
        self.assertEqual((st, r.get('count')), (200, 1), r)
        self.assertIn('--all-amounts', T.llm_calls()[n0]['args'])
        st, g = self.call('POST', '/gmail/get', {'uid': str(uid)})
        self.assertEqual(st, 200, g)
        self.assertIn('--all-amounts', T.llm_calls()[-1]['args'])
        for res in (r, g):
            blob = json.dumps(res, ensure_ascii=False)
            for fig in ('108.34', '12.00', "1'234.50", '9,99', '45.00'):
                self.assertNotIn(fig, blob)
            self.assertIn('21.10. um 10.30 Uhr', blob)                    # dates and times stay
        m = r['results'][0]
        self.assertEqual(m['subject'], 'Your receipt from Apple, [amount]')
        self.assertIn('Order total: [amount] | [amount] | [amount] | [amount]', m['snippet'])
        self.assertEqual((m['attachments'][0]['name'], g['attachments'][0]['name']),
                         ('Invoice-[amount].pdf', 'Invoice-[amount].pdf'))
        self.assertEqual(g['subject'], 'Your receipt from Apple, [amount]')
        self.assertIn('Total: [amount]', g['text'])
        self.assertEqual(G.name_amounts('Scan 13.10.2026 v1.2.pdf'), 'Scan 13.10.2026 v1.2.pdf')

    def test_to_paperless_and_raw_flow(self):
        n0 = len(T.PAPERLESS.requests)
        st, r = self.call('POST', '/gmail/to-paperless', {'uid': 1, 'attachment': 1, 'title': 'Galaxus 2026-77'})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['type'], r['bytes'], r['paperless']['document_id']), ('application/pdf', len(PDF), 42))
        up = [x for x in T.PAPERLESS.requests[n0:] if x[1] == '/api/documents/post_document/'][-1]
        self.assertIn(PDF, up[3])
        self.assertIn(b'filename="Rechnung-2026-77.pdf"', up[3])
        st, e = self.call('POST', '/gmail/to-paperless', {'uid': 1, 'attachment': 2})
        self.assertEqual((st, e['code']), (400, 'bad_param'))
        a = [x for x in self.app.audit.read() if x['event'] == 'gmail_to_paperless'][-1]
        self.assertEqual((a['uid'], a['bytes'], a['document_id']), (1, len(PDF), 42))
        out = self.raw_flow('gmail', {'uid': '3'})                     # raw: only with the owner's OK
        self.assertIn('anna.muster@gmx.ch', out['text'])
        self.assertIn('Herzschmerz', out['text'])
        self.assertTrue(any('mail main:3 from Anna Muster (gmx.ch)' in str(m.get('text')) for m in T.TELEGRAM.sent))
        out = self.raw_flow('gmail', {'uid': 1, 'attachment': 1})
        self.assertEqual((out['kind'], out['filename'], base64.b64decode(out['content_b64'])),
                         ('file', 'Rechnung-2026-77.pdf', PDF))
        out = self.raw_flow('gmail', {'uid': 2, 'eml': True})
        self.assertIn(b'Top Deals der Woche', base64.b64decode(out['content_b64']))
        st, e = self.call('POST', '/raw/request', {'source': 'gmail', 'query': {'uid': 'bad'}, 'reason': 'test it'})
        self.assertEqual(st, 400)

    def test_events_feed_and_secrets_never_logged(self):
        st, r = self.call('GET', '/events?since=latest')
        cur = r['next_cursor']
        self.assertEqual(r['live']['gmail'], 'unconfigured')           # the watcher threads don't run in ApiBase
        self.app.gmail.poll_once(self.app.feed)                        # first poll: position at the end
        self.imap.add('INBOX', mail('Swisscom <billing@swisscom.ch>', 'Kontoauszug Oktober', 'Betrag CHF 79.90.'))
        gmail_triage_says('bill')
        self.app.gmail.poll_once(self.app.feed)
        st, r = self.call('GET', f'/events?since={cur}&source=gmail')
        self.assertEqual(st, 200, r)
        e = r['events'][-1]
        self.assertEqual((e['source'], e['label'], e['actionable'], e['chat_key'], e['chat']),
                         ('gmail', 'bill', True, 'swisscom.ch', 'Swisscom (swisscom.ch)'))
        self.assertNotIn('text', e)                                     # privacy plan A: events never carry text
        self.assertNotIn('79.90', json.dumps(e))
        self.assertEqual(set(e.get('att') or {'n': 0, 'pdf': 0, 'image': 0}), {'n', 'pdf', 'image'})
        self.assertRegex(e['ref'], r'^main:\d+$')
        self.assertEqual(e['account'], 'main')
        st, r2 = self.call('GET', f"/events?since={r['next_cursor']}")
        self.assertEqual(r2['events'], [])
        st, r3 = self.call('GET', f'/events?since={cur}&source=telegram')
        self.assertEqual(r3['events'], [])
        # the secret never shows up: audit log, alerts, state files, the live view (log lines + bodies)
        blob = T.all_files_text(self.cfg.data) + json.dumps(self.app.tap.since(last=500, full=True))
        self.assertNotIn(APP_PW, blob.replace(json.dumps({'address': ADDR, 'app_password': APP_PW}), ''))
        self.assertNotIn(APP_PW_SHOWN, blob)
        lines = json.dumps(self.app.tap.since(last=500, full=True))
        self.assertNotIn(ADDR, lines)
        self.assertIn('POST /secrets/gmail', lines)


class ConsoleGmailTests(T.ApiBase, ReadOnlyCheck):
    """`vault-console secret gmail`: the owner types address + app password at the Unraid terminal."""
    name = 'console-gmail'

    @classmethod
    def setUpClass(cls):
        cls.imap = FakeIMAP()
        cls.box2 = cls.imap.add_user(ADDR2, APP_PW2)
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0'}
        super().setUpClass()

    def tearDown(self):
        ReadOnlyCheck.tearDown(self)

    def test_console_secret_gmail(self):
        cfg = V.Config(T.make_env(self.name, VAULT_PORT=str(self.srv.server_address[1])))
        out, asked = [], []
        answers = {'label': '', 'address': ADDR, 'replace': 'y'}       # Enter at the label prompt = main

        def ask(prompt):
            asked.append(('plain', prompt))
            return answers['label' if prompt.startswith('Account label') else
                           'replace' if 'Replace' in prompt else 'address']

        def ask_secret(prompt):
            asked.append(('hidden', prompt))
            return APP_PW_SHOWN
        rc = D.console_main(['secret', 'gmail'], ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)
        self.assertEqual(rc, 0, out)
        self.assertIn('READ-ONLY', out[0])
        self.assertIn('Google account > Security > 2-Step Verification', out[0])
        self.assertIn('App passwords', out[0])
        self.assertEqual([k for k, _ in asked], ['plain', 'plain', 'hidden'])    # label, address, app password
        self.assertTrue(asked[0][1].startswith('Account label'))
        self.assertTrue(asked[2][1].endswith(' (not shown): '))
        self.assertEqual(out[-1], 'secret gmail: stored; Gmail IMAP login OK, INBOX opened read-only (0 mails)')
        self.assertFalse(any(APP_PW in str(x) or APP_PW_SHOWN in str(x) for x in out))
        self.assertEqual(self.app.store.get('gmail')['app_password'], APP_PW)          # spaces dropped
        self.assertNotIn(APP_PW, self.cfg.audit_path.read_text())
        asked.clear()
        rc = D.console_main(['secret', 'gmail'], ask=ask, ask_secret=lambda p: 'zyxw' * 4, out=out.append, cfg=cfg)
        self.assertEqual(rc, 0, out)                                    # replaced by the owner; the check says why
        self.assertIn('Gmail accounts in the vault: main', '\n'.join(out))
        self.assertTrue(any('Replace it? [y/N]' in p for _, p in asked))  # Enter (main) never replaces silently
        self.assertIn('secret gmail: replaced; stored, but the check failed: Gmail refused the login', out[-1])
        self.assertFalse(any('zyxw' * 4 in str(x) for x in out))
        answers['replace'] = ''
        rc = D.console_main(['secret', 'gmail', 'main'], ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)
        self.assertEqual((rc, out[-1]), (1, 'gmail account main: unchanged'))
        # a second account: the label on the command line (no label prompt), its own secret gmail:work
        asked.clear()
        answers['address'] = ADDR2
        def ask_secret2(prompt):
            asked.append(('hidden', prompt))
            return APP_PW2
        rc = D.console_main(['secret', 'gmail', 'Work'], ask=ask, ask_secret=ask_secret2, out=out.append, cfg=cfg)
        self.assertEqual(rc, 0, out)
        self.assertEqual([k for k, _ in asked], ['plain', 'hidden'])   # no label prompt: it came with the command
        self.assertEqual(out[-1], 'secret gmail:work: stored; Gmail IMAP login OK (account work), INBOX opened '
                                  'read-only (0 mails)')
        self.assertEqual(self.app.store.gmail_labels(), ['main', 'work'])
        self.assertEqual(self.app.store.get('gmail')['app_password'], 'zyxw' * 4)     # main untouched
        for bad in (['secret', 'gmail', 'all'], ['secret', 'gmail', '9x'], ['secret', 'gmail', 'a/b']):
            rc = D.console_main(bad, ask=ask, ask_secret=ask_secret, out=out.append, cfg=cfg)
            self.assertEqual(rc, 1, bad)
            self.assertIn('nothing stored', out[-1])
        self.assertEqual(self.app.store.gmail_labels(), ['main', 'work'])
        st, r = self.call('GET', '/secrets')
        self.assertEqual(r['secrets'], {'telegram': False, 'paperless': False, 'firefly': False,
                                        'homeassistant': False, 'gmail': True,
                                        'gmail:work': True})
        # the console key reaches /secrets/gmail:<label>, the API token can't replace without the owner's code
        st, e = self.call('POST', '/secrets/gmail:work', {'address': ADDR2, 'app_password': APP_PW2})
        self.assertEqual((st, e['code']), (409, 'already_set'))
        self.assertFalse(any(APP_PW2 in str(x) for x in out))


# ============================================================================================ several accounts

class MultiAccountTests(ReadOnlyCheck):
    """Two accounts on one fake server (one mailbox each) through GmailAccounts, the object vaultd uses."""

    def setUp(self):
        self.imap = FakeIMAP()
        self.box2 = self.imap.add_user(ADDR2, APP_PW2)
        self.cfg, self.store, self.gs, self.feed, self.events, self.rules = make_accounts(
            f'gm-{self._testMethodName}', self.imap)
        self.store.set('gmail', {'address': ADDR, 'app_password': APP_PW})
        self.store.set('gmail:work', {'address': ADDR2, 'app_password': APP_PW2})
        T.llm_mode('plain')

    def tearDown(self):
        T.llm_mode('ok')
        super().tearDown()
        self.assertFalse(self.box2.seen_set)                           # the second mailbox: never \Seen either

    def positions(self, label):
        return {k: v['last_uid'] for k, v in json.loads(self.gs.acct(label).state_path.read_text())['folders'].items()}

    def test_secrets_labels_and_refs(self):
        st = self.store
        self.assertEqual(st.gmail_labels(), ['main', 'work'])
        self.assertEqual(st.names(), {'telegram': False, 'paperless': False, 'firefly': False,
                                      'homeassistant': False, 'gmail': True,
                                      'gmail:work': True})
        self.assertEqual((st.path('gmail').name, st.path('gmail:work').name), ('vault-gmail.json', 'vault-gmail-work.json'))
        self.assertEqual([V.secret_name(n) for n in ('gmail', 'gmail:main', 'gmail:work', 'gmail:Work', 'gmail:all',
                                                     'gmail:9x', 'gmail:a/b', 'gmail:', 'paperless:x', None)],
                         ['gmail', 'gmail', 'gmail:work', None, None, None, None, None, None, None])
        self.assertEqual(st.get('gmail:work')['address'], ADDR2)
        self.assertEqual(st.get('gmail:main')['address'], ADDR)      # gmail:main = gmail (the first account)
        with self.assertRaises(V.VaultError) as cm:                     # set once: replacing needs the owner
            st.set('gmail:work', {'address': ADDR2, 'app_password': APP_PW2})
        self.assertEqual(cm.exception.code, 'already_set')
        with self.assertRaises(V.VaultError) as cm:
            st.set('gmail:all', {'address': ADDR2, 'app_password': APP_PW2})
        self.assertEqual(cm.exception.code, 'unknown_secret')
        self.assertEqual(G.split_ref('work:12@Rechnungen/März'), ('work', 12, 'Rechnungen/März'))
        self.assertEqual(G.split_ref(' Work:7 '), ('work', 7, 'INBOX'))
        self.assertEqual(G.split_ref('12'), (None, 12, 'INBOX'))
        self.assertEqual(G.split_ref(5, 'Rechnungen'), (None, 5, 'Rechnungen'))
        self.assertEqual((G.make_ref(3, 'INBOX', 'work'), G.make_ref(3, 'A/B', 'main')), ('work:3', 'main:3@A/B'))
        for bad in ('all:1', ':1', 'wo rk:1', 'work:', '1:2', 'work:x'):
            with self.assertRaises(V.VaultError, msg=bad):
                G.split_ref(bad)
        for lab in ('a', 'b', 'c'):                                     # at most GMAIL_MAX_ACCOUNTS (5)
            st.set(f'gmail:{lab}', {'address': ADDR2, 'app_password': APP_PW2})
        with self.assertRaises(V.VaultError) as cm:
            st.set('gmail:d', {'address': ADDR2, 'app_password': APP_PW2})
        self.assertEqual(cm.exception.code, 'too_many_accounts')

    def test_own_state_positions_config_and_events(self):
        gs = self.gs
        self.assertFalse(gs.poll_once(self.feed))                      # first poll of each: start at the end
        self.assertEqual((self.positions('main'), self.positions('work')), ({'INBOX': 0}, {'INBOX': 0}))
        self.assertTrue((self.cfg.state / 'gmail.json').is_file() and (self.cfg.state / 'gmail.work.json').is_file())
        self.imap.add('INBOX', BILL())
        self.box2.add('INBOX', PERSON())
        self.box2.add('INBOX', NEWS())
        gmail_triage_says('bill')
        gs.poll_once(self.feed, 'main')
        gmail_triage_says('reply_needed', 'newsletter')
        gs.poll_once(self.feed, 'work')
        rows = self.events.since(0)[0]
        self.assertEqual([(r['account'], r['label'], r['ref']) for r in rows],
                         [('main', 'bill', 'main:1'), ('work', 'reply_needed', 'work:1'), ('work', 'newsletter', 'work:2')])
        self.assertEqual((self.positions('main'), self.positions('work')), ({'INBOX': 1}, {'INBOX': 2}))
        self.assertEqual((gs.acct('main').poll['processed'], gs.acct('work').poll['processed']), (1, 2))
        # folder config per account
        self.assertEqual(gs.set_config({'account': 'work', 'folders': ['Rechnungen']})['folders'],
                         ['INBOX', 'Rechnungen'])
        self.assertEqual((gs.acct('main').folders(), gs.acct('work').folders()), (['INBOX'], ['INBOX', 'Rechnungen']))
        self.assertTrue((self.cfg.state / 'gmail-config.work.json').is_file())
        with self.assertRaises(V.VaultError) as cm:                     # two accounts: say which one
            gs.set_config({'folders': []})
        self.assertEqual(cm.exception.code, 'account_needed')
        gs.poll_once(self.feed, 'work')
        self.assertEqual(self.positions('work'), {'INBOX': 2, 'Rechnungen': 0})
        self.assertEqual(self.positions('main'), {'INBOX': 1})
        # status: labels and domains, never an address
        stt = gs.status()
        self.assertEqual([(a['account'], a['domain'], a['configured']) for a in stt['accounts']],
                         [('main', 'gmail.com', True), ('work', 'firma.ch', True)])
        sm = gs.summary()
        self.assertEqual(([a['account'] for a in sm['accounts']], sm['configured']), (['main', 'work'], True))
        blob = json.dumps([rows, stt, sm, gs.board()])
        for leak in ('lukas', 'meier', 'anna.muster', APP_PW, APP_PW2):
            self.assertNotIn(leak, blob)
        # the board shows each account when there are several (labels and states only)
        board = B.StatusBoard(self.cfg, V.Notifier(self.store, 'http://127.0.0.1:9'), lambda: {}, events=self.events,
                              enabled=lambda: (False, 'test'), log=lambda *a: None)
        body = board.render(T.board_snap(gmail_watch='auth_failed', gmail_accounts=[
            {'account': 'main', 'watch': 'idle', 'error': False},
            {'account': 'work', 'watch': 'auth_failed', 'error': True}]))[0]
        self.assertIn('Gmail ❌', body)
        self.assertIn('✉️ main ✅ · work ❌', body)
        self.assertNotIn('✉️ main', board.render(T.board_snap(gmail_accounts=[
            {'account': 'main', 'watch': 'idle', 'error': False}]))[0])

    def test_auth_block_and_alerts_per_account(self):
        gs = self.gs
        self.box2.password = 'zyxw' * 4                                # the work app password was revoked
        with self.assertRaises(G.AuthFailed) as cm:
            gs.acct('work').connect()
        self.assertIn('(account work)', str(cm.exception))
        with self.assertRaises(G.AuthFailed):
            gs.acct('work').connect()                                  # blocked: no second LOGIN for work
        self.assertEqual(sum(1 for n, ln in self.imap.log if n == 'LOGIN'), 1)
        with gs.acct('main').session() as im:                          # main is not blocked
            self.assertIn('IDLE', im.capabilities)
        self.assertEqual([a[0] for a in gs.alerts], ['gmail-auth-work'])
        self.assertIn('vault-console secret gmail work', gs.alerts[0][2])
        self.assertIn('account work', gs.alerts[0][1] + gs.alerts[0][2])
        gs.acct('work').watch['state'] = 'auth_failed'
        gs.acct('main').watch['state'] = 'idle'
        self.assertEqual(gs.watch_state(), 'auth_failed')              # the worst state shows on board/status
        gs.credentials_changed('work')                                 # a new secret: try again at once
        self.box2.password = APP_PW2
        self.assertEqual(gs.check('work'), 'Gmail IMAP login OK (account work), INBOX opened read-only (0 mails)')
        blob = self.cfg.audit_path.read_text() + T.all_files_text(self.cfg.state)
        self.assertIn('gmail_login_refused', blob)
        for leak in (APP_PW, APP_PW2, ADDR, ADDR2):
            self.assertNotIn(leak, blob)

    def test_read_only_and_api_paths_per_account(self):
        gs = self.gs
        self.imap.add('INBOX', PERSON())
        self.box2.add('INBOX', BILL())
        for label in ('main', 'work'):                                 # each account's connection refuses writes
            with gs.acct(label).session() as im:
                n0 = len(self.imap.log)
                for call in (lambda: im.select('INBOX'), lambda: im.store('1', '+FLAGS', '(\\Seen)'),
                             lambda: im.uid('MOVE', '1', 'X'), lambda: im.uid('COPY', '1', 'X'),
                             lambda: im.expunge(), lambda: im.append('INBOX', None, None, b'x'),
                             lambda: im.uid('FETCH', '1', '(RFC822)'), lambda: im.uid('STORE', '1', '+FLAGS', '(x)')):
                    with self.assertRaises((G.ReadOnlyViolation, imaplib.IMAP4.error), msg=label):
                        call()
                self.assertEqual(len(self.imap.log), n0, label)        # nothing reached the server
        r = gs.search('Rechnung')                                      # default: every account
        self.assertEqual((r['accounts'], [(m['ref'], m['account']) for m in r['results']]),
                         (['main', 'work'], [('work:1', 'work')]))
        r = gs.search('Samstag', account='main')
        self.assertEqual(([m['ref'] for m in r['results']], r['accounts']), (['main:1'], ['main']))
        with self.assertRaises(V.VaultError) as cm:
            gs.get('1')                                                # two accounts: a bare uid is ambiguous
        self.assertEqual(cm.exception.code, 'account_needed')
        m = gs.get('work:1')
        self.assertEqual((m['account'], m['ref'], m['from']), ('work', 'work:1', 'Galaxus Rechnungen (news.galaxus.ch)'))
        self.assertEqual(gs.get('1', account='main')['from'], 'Anna Muster (gmx.ch)')
        with self.assertRaises(V.VaultError):
            gs.get('work:1', account='main')                           # REF and account disagree
        with self.assertRaises(V.VaultError) as cm:
            gs.get('nope:1')
        self.assertEqual(cm.exception.code, 'no_account')
        kind, summary, (fn, data) = gs.raw({'uid': 'work:1', 'eml': True})
        self.assertEqual((kind, fn), ('file', 'gmail-work-1.eml'))
        self.assertIn('mail work:1 from Galaxus Rechnungen (news.galaxus.ch)', summary)
        kind, summary, text = gs.raw({'uid': 1, 'account': 'main'})
        self.assertIn('Herzschmerz', text)                             # raw: only after the owner's OK (vaultd)
        self.assertEqual(sorted({n.split()[1] for n in self.imap.names() if n.startswith('UID ')}), ['FETCH', 'SEARCH'])

    def test_parallel_search_timing_and_a_slow_account(self):
        """Regression: one account took ~54 s, both > 120 s one after the other. The accounts run in parallel,
        one UID FETCH per account (not one per mail), stage times per account (numbers only), and an account past
        SEARCH_ACCOUNT_TIMEOUT is cut off: the other one answers, with an error line."""
        gs = self.gs
        for _ in range(3):
            self.imap.add('INBOX', BILL())
        for _ in range(2):
            self.box2.add('INBOX', BILL())
        self.imap.fetch_calls = self.box2.fetch_calls = 0
        r = gs.search('Rechnung', n=10, text=False)
        self.assertEqual((r['count'], r['total'], r['accounts']), (5, 5, ['main', 'work']))
        self.assertEqual(sorted(r['timing']), ['main', 'work'])
        for lab, hits in (('main', 3), ('work', 2)):
            t = r['timing'][lab]
            self.assertTrue({'connect', 'open', 'search', 'fetch', 'total'} <= set(t), t)
            cmds = t.pop('cmds')
            self.assertTrue(all(isinstance(v, (int, float)) for v in t.values()), t)   # numbers only
            self.assertEqual([c[0] for c in cmds], ['GREETING', 'CAPABILITY', 'LOGIN', 'CAPABILITY', 'EXAMINE',
                                                    'UID SEARCH', 'UID FETCH', 'LOGOUT'])
            self.assertTrue(all(isinstance(x, float) or isinstance(x, int) for c in cmds for x in c[1:]), cmds)
            self.assertEqual((t['hits'], t['fetched']), (hits, hits))
        self.assertEqual((self.imap.fetch_calls, self.box2.fetch_calls), (1, 1))   # one round trip per account
        self.assertEqual(len(gs.search('Rechnung', n=2, text=False)['results']), 2)
        self.imap.search_delay = self.box2.search_delay = 1.5               # in sequence: >= 3 s
        t0 = time.monotonic()
        r = gs.search('Rechnung', text=False)
        self.assertEqual(r['count'], 5)
        self.assertLess(time.monotonic() - t0, 2.8)
        rows, errs = gs.find_rows('Rechnung', 'Rechnung', n=10)              # find: the same, in parallel
        self.assertEqual((len(rows), errs), (5, {}))
        self.assertLess(time.monotonic() - t0, 5.6)
        old = G.SEARCH_ACCOUNT_TIMEOUT
        try:
            G.SEARCH_ACCOUNT_TIMEOUT = 1
            self.imap.search_delay, self.box2.search_delay = 0, 3
            t0 = time.monotonic()
            r = gs.search('Rechnung', text=False)
            self.assertLess(time.monotonic() - t0, 2.5)
            self.assertEqual((r['accounts'], r['count']), (['main'], 3))
            self.assertIn('timed out after 1 s', r['errors']['work'])
            self.assertEqual(r['timing']['work']['total'], '>1')
            rows, errs = gs.find_rows('Rechnung', 'Rechnung', n=10)
            self.assertEqual((len(rows), list(errs)), (3, ['work']))
            r = gs.search('Rechnung', account='work', text=False)          # one account: no cut-off
            self.assertEqual(r['count'], 2)
        finally:
            G.SEARCH_ACCOUNT_TIMEOUT = old
            self.box2.search_delay = 0
        self.assertTrue(wait_for(lambda: not any(t.name.startswith('gmail-search') for t in threading.enumerate())))

    def test_threads_per_account_and_a_late_account(self):
        stop = threading.Event()
        old = G.POLL_SECONDS
        G.POLL_SECONDS = 30
        (self.cfg.secrets / 'vault-gmail-work.json').unlink()          # only main when the vault starts
        gs = self.gs
        gs.poll_delay = 0
        try:
            gs.start(stop, self.feed)
            self.assertTrue(wait_for(lambda: gs.acct('main').watch['state'] == 'idle'), gs.acct('main').watch)
            self.assertFalse(gs.acct('work').started)
            self.store.set('gmail:work', {'address': ADDR2, 'app_password': APP_PW2})
            gs.credentials_changed('work')                             # vaultd does this after POST /secrets/gmail:work
            self.assertTrue(wait_for(lambda: gs.acct('work').watch['state'] == 'idle' and self.box2.idlers, 10),
                            gs.acct('work').watch)
            self.assertTrue(wait_for(lambda: gs.acct('work').state_path.exists(), 10))
            gmail_triage_says('bill')
            t0 = time.time()
            self.box2.add('INBOX', BILL())
            self.assertTrue(wait_for(lambda: self.events.head() == 1, 15), (gs.acct('work').watch, gs.acct('work').poll))
            self.assertLess(time.time() - t0, 15)                      # IDLE of the work account, not the 30 s poll
            self.assertEqual(self.events.since(0)[0][0]['account'], 'work')
            self.assertEqual(gs.watch_state(), 'idle')
        finally:
            stop.set()
            G.POLL_SECONDS = old
            for a in gs.accounts.values():
                a.wake.set()
                a.creds_changed.set()


@T.legacy_text
class ApiMultiGmailTests(T.ApiBase, ReadOnlyCheck):
    """The API with two accounts: secrets gmail + gmail:work, status, search over all, REFs with the account,
    config per account, to-paperless, raw, events with the account label; nothing shows an address."""
    name = 'api-gmail-multi'

    @classmethod
    def setUpClass(cls):
        cls.imap = FakeIMAP()
        cls.box2 = cls.imap.add_user(ADDR2, APP_PW2)
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0'}
        super().setUpClass()
        cls.app.store.set('paperless', {'url': T.PAPERLESS.url, 'token': T.PL_TOKEN})
        cls.app.store.set('telegram', {'bot_token': T.BOT_TOKEN, 'chat_id': T.CHAT_ID})
        now = time.time()
        cls.imap.add('INBOX', PERSON())
        cls.imap.add('INBOX', mail('Swisscom <billing@swisscom.ch>', 'Rechnung Oktober', 'Betrag CHF 79.90.'),
                     ts=now - 3600)
        cls.box2.add('INBOX', BILL(), ts=now - 7200)
        cls.box2.add('INBOX', mail('Post CH <noreply@post.ch>', 'Paket Rechnung', 'Paket kommt am Mittwoch.'),
                     ts=now - 60)

    def setUp(self):
        super().setUp()
        T.llm_mode('plain')

    def tearDown(self):
        T.llm_mode('ok')
        ReadOnlyCheck.tearDown(self)
        self.assertFalse(self.box2.seen_set)

    def test_two_accounts_api(self):
        st, r = self.call('POST', '/secrets/gmail', {'address': ADDR, 'app_password': APP_PW_SHOWN})
        self.assertEqual((st, r['account']), (200, 'main'), r)
        st, r = self.call('POST', '/secrets/gmail:work', {'address': ADDR2, 'app_password': APP_PW2})
        self.assertEqual((st, r['name'], r['account']), (200, 'gmail:work', 'work'), r)
        self.assertEqual(r['check'], 'Gmail IMAP login OK (account work), INBOX opened read-only (2 mails)')
        for name, code in (('gmail:work', 409), ('gmail:all', 404), ('gmail:Work', 404), ('gmail:main', 409)):
            st, e = self.call('POST', f'/secrets/{name}', {'address': ADDR2, 'app_password': APP_PW2})
            self.assertEqual(st, code, (name, e))
        st, r = self.call('POST', '/raw/request', {'source': 'secret-rotate', 'query': {'name': 'gmail:work'},
                                                   'reason': 'new app password'})
        self.assertEqual(st, 200, r)                                   # replacing needs the owner's code
        st, r = self.call('GET', '/gmail/status')
        self.assertEqual([(a['account'], a['domain']) for a in r['accounts']], [('main', 'gmail.com'), ('work', 'firma.ch')])
        st, s = self.call('GET', '/status')
        self.assertEqual((s['secrets']['gmail:work'], [a['account'] for a in s['gmail']['accounts']]),
                         (True, ['main', 'work']))
        st, r = self.call('POST', '/gmail/search', {'q': 'Rechnung'})  # every account, newest first
        self.assertEqual(st, 200, r)
        self.assertEqual((r['accounts'], r['total'], sorted((m['account'], m['ref']) for m in r['results'])),
                         (['main', 'work'], 3, [('main', 'main:2'), ('work', 'work:1'), ('work', 'work:2')]))
        self.assertEqual([m['ref'] for m in r['results']], ['work:2', 'main:2', 'work:1'])   # merged by date
        st, r = self.call('POST', '/gmail/search', {'q': 'Rechnung', 'account': 'work', 'n': 1})
        self.assertEqual((st, r['accounts'], r['count'], r['total']), (200, ['work'], 1, 2), r)
        st, e = self.call('POST', '/gmail/search', {'q': 'Rechnung', 'account': 'nope'})
        self.assertEqual((st, e['code']), (404, 'no_account'))
        st, r = self.call('POST', '/gmail/get', {'uid': 'work:1'})
        self.assertEqual((st, r['account'], r['from']), (200, 'work', 'Galaxus Rechnungen (news.galaxus.ch)'), r)
        st, e = self.call('POST', '/gmail/get', {'uid': '1'})
        self.assertEqual((st, e['code']), (400, 'account_needed'))
        st, r = self.call('POST', '/gmail/get', {'uid': 1, 'account': 'main'})
        self.assertEqual((st, r['ref'], r['from']), (200, 'main:1', 'Anna Muster (gmx.ch)'), r)
        st, r = self.call('POST', '/gmail/to-paperless', {'uid': 'work:1', 'attachment': 1, 'title': 'Galaxus'})
        self.assertEqual((st, r['ref'], r['account'], r['paperless']['document_id']), (200, 'work:1', 'work', 42), r)
        out = self.raw_flow('gmail', {'uid': 'work:1', 'attachment': 1})
        self.assertEqual((out['filename'], base64.b64decode(out['content_b64'])), ('Rechnung-2026-77.pdf', PDF))
        self.assertTrue(any('mail work:1 from Galaxus Rechnungen (news.galaxus.ch)' in str(m.get('text'))
                            for m in T.TELEGRAM.sent))
        st, e = self.call('POST', '/gmail/config', {'folders': ['Rechnungen']})
        self.assertEqual((st, e['code']), (400, 'account_needed'))
        st, r = self.call('POST', '/gmail/config', {'account': 'work', 'folders': ['Rechnungen']})
        self.assertEqual((st, r['account'], r['folders']), (200, 'work', ['INBOX', 'Rechnungen']), r)
        st, r = self.call('GET', '/gmail/config')
        self.assertEqual([(a['account'], a['folders']) for a in r['accounts']],
                         [('main', ['INBOX']), ('work', ['INBOX', 'Rechnungen'])])
        st, r = self.call('GET', '/gmail/config?account=work')
        self.assertEqual([a['account'] for a in r['accounts']], ['work'])
        self.call('POST', '/gmail/config', {'account': 'work', 'folders': []})
        # events carry the account
        st, r = self.call('GET', '/events?since=latest')
        cur = r['next_cursor']
        self.app.gmail.poll_once(self.app.feed)                        # first poll of each: positions at the end
        self.box2.add('INBOX', mail('Swisscom <billing@swisscom.ch>', 'Kontoauszug Oktober', 'Betrag CHF 79.90.'))
        gmail_triage_says('bill')
        self.app.gmail.poll_once(self.app.feed)
        st, r = self.call('GET', f'/events?since={cur}&source=gmail')
        e = r['events'][-1]
        self.assertEqual((e['account'], e['ref'], e['label'], e['chat']),
                         ('work', 'work:3', 'bill', 'Swisscom (swisscom.ch)'), r)
        # neither address nor password shows up anywhere the assistant or the logs can see
        blob = json.dumps(self.app.tap.since(last=500, full=True)) + self.cfg.audit_path.read_text()
        for leak in (ADDR, ADDR2, APP_PW, APP_PW2, APP_PW_SHOWN):
            self.assertNotIn(leak, blob)
        self.assertIn('POST /secrets/gmail:work', blob)


# ============================================================================================ clients (~/bin)

@unittest.skipUnless((T.CLI_DIR / 'vault').is_file(), 'client not here (image)')
@T.legacy_text
class CliGmailTests(T.ApiBase, ReadOnlyCheck):
    name = 'cli-gmail'

    @classmethod
    def setUpClass(cls):
        cls.imap = FakeIMAP()
        cls.extra_env = {'VAULT_GMAIL_IMAP': f'127.0.0.1:{cls.imap.port}', 'VAULT_GMAIL_TLS': '0'}
        super().setUpClass()
        cls.app.store.set('gmail', {'address': ADDR, 'app_password': APP_PW})
        cls.app.store.set('paperless', {'url': T.PAPERLESS.url, 'token': T.PL_TOKEN})
        cls.app.store.set('telegram', {'bot_token': T.BOT_TOKEN, 'chat_id': T.CHAT_ID})
        home = T.TMP / 'cli-gmail-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        for n in ('vault', 'vault-events'):
            (home / 'bin' / n).symlink_to(T.CLI_DIR / n)
        tok = T.TMP / 'cli-gmail-token'
        tok.write_text(T.TOKEN + '\n')
        tok.chmod(0o600)
        cls.home = home
        cls.env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': cls.url, 'VAULT_TOKEN_FILE': str(tok),
                   'VAULT_EVENTS_CLIENT': str(home / 'bin' / 'vault'), 'VAULT_EVENTS_INBOX': str(home / 'inbox')}

    def setUp(self):
        super().setUp()
        T.llm_mode('plain')

    def tearDown(self):
        T.llm_mode('ok')
        ReadOnlyCheck.tearDown(self)

    def run_(self, *args):
        p = subprocess.run([str(self.home / 'bin' / args[0]), *args[1:]], env=self.env, capture_output=True,
                           text=True, timeout=90)
        return p.returncode, p.stdout, p.stderr

    def test_cli_and_vault_events_note(self):
        rc, out, err = self.run_('vault', 'gmail', 'status')
        self.assertEqual(rc, 0, err)
        self.assertIn('gmail: 1 account (read-only)', out)
        self.assertIn('[main] …@gmail.com, folders: INBOX', out)
        self.assertNotIn('lukas', out)
        self.assertEqual(self.run_('vault-events', '--cron')[0], 0)    # cursor at the end of the feed
        self.app.gmail.poll_once(self.app.feed)                        # position at the end
        self.imap.add('INBOX', BILL())
        self.imap.add('INBOX', NEWS())
        gmail_triage_says('bill', 'newsletter')
        self.app.gmail.poll_once(self.app.feed)
        rc, out, err = self.run_('vault', 'gmail', 'search', 'Rechnung')
        self.assertEqual(rc, 0, err)
        self.assertRegex(out, r'#main:1 .* Galaxus Rechnungen \(news\.galaxus\.ch\) · Ihre Rechnung 2026-77  '
                              r'\[1 attachment\(s\)\]')
        self.assertIn('(account main)', out)
        rc, out, err = self.run_('vault', 'gmail', 'search', 'Rechnung', '--account', 'nope')
        self.assertNotEqual(rc, 0)
        rc, out, err = self.run_('vault', 'gmail', 'get', 'main:1')
        self.assertEqual(rc, 0, err)
        self.assertIn('Attachments: 1. Rechnung-2026-77.pdf (application/pdf', out)
        n0 = len(T.llm_calls())                                         # fast defaults, no LLM
        rc, out, err = self.run_('vault', 'gmail', 'search', 'Rechnung', '--no-text')
        self.assertEqual(rc, 0, err)
        self.assertRegex(out, r'#main:1 .* · bill')                      # the feed's triage
        rc, out, err = self.run_('vault', 'gmail', 'get', 'main:1', '--no-text')
        self.assertEqual(rc, 0, err)
        self.assertIn('(quick card from the live feed; --deep for dates)', out)
        self.assertEqual(len(T.llm_calls()), n0)
        rc, out, err = self.run_('vault', 'gmail', 'to-paperless', '1', '1', '--title', 'Galaxus')
        self.assertEqual((rc, 'document 42' in out), (0, True), out + err)
        rc, out, err = self.run_('vault', 'gmail', 'config', '--folders', 'Rechnungen')
        self.assertEqual(json.loads(out)['folders'], ['INBOX', 'Rechnungen'], err)
        self.run_('vault', 'gmail', 'config', '--folders', '')
        rc, out, err = self.run_('vault', 'events', 'mute', '--source', 'gmail', '--chat', 'digitec.ch')
        self.assertEqual((rc, out.strip()), (0, 'gmail chat digitec.ch: mute (1 rule(s) in total)'), err)
        rc, out, err = self.run_('vault-events', '--cron')
        self.assertEqual(rc, 0, err)
        notes = sorted((self.home / 'inbox').glob('vault-events-*.md'))
        self.assertEqual(len(notes), 1)
        note = notes[0].read_text()
        self.assertIn('gmail · Galaxus Rechnungen (news.galaxus.ch) · bill · 1 PDF [mail main:1]', note)   # A: no text
        self.assertIn('the bills scan picks it up', note)
        self.assertIn('vault gmail to-paperless REF', note)
        self.assertIn('1 chatter message(s)', note)
        rc, out, err = self.run_('vault', 'raw', 'request', '--source', 'gmail', '--uid', '1', '--account', 'main',
                                 '--attachment', '1', '--reason', 'owner wants the PDF')
        self.assertEqual(rc, 10, out + err)
        rc, out, err = self.run_('vault', 'status')
        self.assertIn('gmail: configured, watcher unconfigured', out)
        n1 = len(T.llm_calls())                                         # re-triage on demand (14.10)
        gmail_triage_says('deadline', 'newsletter')
        rc, out, err = self.run_('vault', 'events', '--since', '0', '--retriage')
        self.assertEqual(rc, 0, err)
        self.assertIn('re-triaged 2 Gmail event(s) (1 changed, 0 no longer in the mailbox)', err)
        self.assertEqual(len(T.llm_calls()), n1 + 1)                     # one call for both
        rc, out, err = self.run_('vault-events', '--show', '--since', '0')
        self.assertEqual(rc, 0, err)
        self.assertIn('· deadline · 1 PDF [mail main:1]', out)          # the note as it reads now
        self.assertEqual(self.run_('vault-events', '--since', '0')[0], 2)   # --since only with --show


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(T.TMP, ignore_errors=True)
