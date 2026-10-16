"""Gmail source of the privacy vault (including polling, so the assistant hears about
new mails as they come in).

Secret `gmail` {address, app_password}: the owner types it at the Unraid terminal (`vault-console secret gmail`); a
Google app password (Google account > Security > 2-Step Verification > App passwords).

Several accounts: secret `gmail` is the account labelled
"main" (as before); every further account is its own secret `gmail:<label>` (`vault-console secret gmail <label>`).
Each account (class Gmail) has its own IMAP login, IDLE + poll threads, state file (UID positions), folder config,
auth block and alerts; GmailAccounts (what vaultd uses) starts them, also for an account added while the vault runs.
Mail REFs carry the account: "work:1234" or "work:1234@Folder" (a bare "1234" works while only one account exists).
Results and events show the account LABEL, never an address.

READ-ONLY by construction: IMAP over TLS to imap.gmail.com:993 (no SMTP code at all). Mailboxes are only opened with
EXAMINE, message data is only fetched with BODY.PEEK, and ReadOnlyIMAP refuses every other command before anything is
sent (STORE, COPY, MOVE, EXPUNGE, APPEND, SELECT, CLOSE, CREATE, DELETE, RENAME, SUBSCRIBE, ...): the vault never
marks, flags, moves, deletes or sends mail.

New mail: one thread holds IMAP IDLE on INBOX (renewed every 29 min; reconnects with backoff) and wakes the poll
thread, which also runs every 15 min by itself (the fallback, and the only watcher for the extra folders/labels in
the config). The poll fetches mails above the stored UID position of each folder (first run or a new UIDVALIDITY:
start at the end, no backlog), parses them locally (text/plain preferred, HTML -> text; attachments: name, type and
size only) and hands them to the event feed as source "gmail": the local LLM triages each mail (bill, deadline,
appointment, reply_needed, delivery, account_security, newsletter, other) and anonymizes what is surfaced. A folder's
position only moves after the feed stored the batch (LLM down: the same mails are fetched again later).

Senders leave the vault as display name + domain only (never the address's local part); sender_key is a keyed
pseudonym. Mute/priority rules (/events/rules, source gmail): chat = a domain (subdomains match too), sender = an
address or its pseudonym.

vaultd routes: GET /gmail/status, POST /gmail/search {q, n, folder, account (default: all)}, POST /gmail/get {uid
(REF), folder, chars, account}, GET|POST /gmail/config {account, folders, owner_name}, POST /gmail/to-paperless {uid,
attachment, folder, account, title, ...}. Raw mail text or original attachments only through the raw-request flow
(source "gmail", query {uid, folder?, account?, attachment? | eml?})."""
import base64
import concurrent.futures as cf
import contextlib
import email
import email.policy
import email.utils
import hashlib
import hmac
import html
import imaplib
import json
import os
import re
import select
import ssl
import threading
import time
from html.parser import HTMLParser

import vaultlib as V
from vaultlib import VaultError

IMAP_HOST, IMAP_PORT = 'imap.gmail.com', 993
IDLE_RENEW = 29 * 60                     # RFC 2177: servers may drop an IDLE after 30 min
POLL_SECONDS = 15 * 60                   # fallback poll (and the extra folders)
ERROR_RETRY = 120
BACKOFF = (5, 15, 60, 300, 900)
AUTH_BLOCK = 1800                        # after a refused login: no new attempt for 30 min (or until a new secret)
CONNECT_TIMEOUT = 60
TRIAGE_FETCH = 1 << 20                   # first 1 MB of a new mail for triage (text + attachment headers)
SEARCH_FETCH = 64 << 10
MAX_FETCH = 30 << 20                     # Gmail's own limit is 25 MB
EXCERPT_CHARS = 700
MAX_FOLDERS = 10
MAX_SEARCH = 50
SEARCH_ACCOUNT_TIMEOUT = 12              # s per account when several are searched: the rest answers, with an error line
#   (a two-account search under 15 s; a throttled account (mail import) answers each command in ~10 s)
PAPERLESS_TYPES = {'application/pdf': '.pdf', 'image/png': '.png', 'image/jpeg': '.jpg', 'image/tiff': '.tiff',
                   'image/webp': '.webp', 'image/gif': '.gif'}


class ReadOnlyViolation(VaultError):
    def __init__(self, what):
        super().__init__(f'refused: {what} is not a read-only IMAP command (the vault never changes mail)', 500,
                         'read_only')


class AuthFailed(VaultError):
    def __init__(self, msg):
        super().__init__(msg, 502, 'gmail_auth')


# ============================================================================================ read-only IMAP

ALLOWED_COMMANDS = frozenset({'CAPABILITY', 'LOGIN', 'EXAMINE', 'LIST', 'STATUS', 'NOOP', 'LOGOUT', 'UID'})
ALLOWED_UID = frozenset({'SEARCH', 'FETCH'})
FETCH_ITEMS = frozenset({'UID', 'FLAGS', 'INTERNALDATE', 'RFC822.SIZE', 'ENVELOPE', 'BODYSTRUCTURE', 'X-GM-LABELS',
                         'X-GM-MSGID', 'X-GM-THRID'})
_PEEK_RE = re.compile(r'BODY\.PEEK\[[A-Z0-9.() -]*\](?:<\d+(?:\.\d+)?>)?')


def check_command(name, args):
    """Raise ReadOnlyViolation unless the IMAP command can never change the mailbox."""
    n = str(name).upper()
    if n not in ALLOWED_COMMANDS:
        raise ReadOnlyViolation(n)
    if n == 'UID':
        sub = str(args[0]).upper() if args else ''
        if sub not in ALLOWED_UID:
            raise ReadOnlyViolation(f'UID {sub}')
        if sub == 'FETCH':
            items = args[2] if len(args) > 2 else ''
            items = items.decode('ascii', 'replace') if isinstance(items, bytes) else str(items)
            rest = _PEEK_RE.sub(' ', items.upper()).replace('(', ' ').replace(')', ' ')
            bad = [t for t in rest.split() if t not in FETCH_ITEMS]
            if bad:
                raise ReadOnlyViolation(f'FETCH {" ".join(bad)[:60]} (only BODY.PEEK and metadata)')


class _Reader:
    """imaplib's `file`, but with a buffer we can see: IDLE waits with select() and must know whether a line is
    already buffered. Socket timeouts raise OSError (the connection is then dropped and rebuilt)."""

    def __init__(self, sock):
        self.sock, self.buf = sock, bytearray()

    def _fill(self):
        d = self.sock.recv(65536)
        if d:
            self.buf += d
        return bool(d)

    def readline(self, limit=-1):
        while True:
            i = self.buf.find(b'\n')
            if i >= 0 or (0 < limit <= len(self.buf)):
                n = i + 1 if i >= 0 else limit
                if limit > 0:
                    n = min(n, limit)
                out = bytes(self.buf[:n])
                del self.buf[:n]
                return out
            if not self._fill():
                out = bytes(self.buf)
                self.buf.clear()
                return out

    def read(self, n):
        while len(self.buf) < n and self._fill():
            pass
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def ready(self):
        if self.buf:
            return True
        pending = getattr(self.sock, 'pending', None)
        return bool(pending and pending() > 0)

    def close(self):
        self.buf.clear()


class _ReadOnly:
    """Mixin for imaplib.IMAP4 / IMAP4_SSL: every command passes check_command() before it is sent, plus IDLE."""

    trace = None                                       # a list -> [command, s to its first line, s to done] per command

    def __init__(self, *a, trace=None, **kw):
        self.trace, self._t = trace, None
        if trace is not None:                          # the greeting (+ CAPABILITY) happen inside imaplib's __init__
            self._t = ['GREETING', time.monotonic(), None]
        super().__init__(*a, **kw)

    def open(self, *a, **kw):
        super().open(*a, **kw)
        self.file = _Reader(self.sock)

    def _command(self, name, *args):
        check_command(name, args)
        if self.trace is not None:
            self._trace_done()
            self._t = [str(name) + (' ' + str(args[0]).upper() if name == 'UID' and args else ''), time.monotonic(),
                       None]
        return super()._command(name, *args)

    def _get_line(self):
        line = super()._get_line()
        if self._t is not None and self._t[2] is None:
            self._t[2] = time.monotonic()
        return line

    def _command_complete(self, name, tag):
        try:
            return super()._command_complete(name, tag)
        finally:
            self._trace_done()

    def _trace_done(self):
        """Numbers only: the command's name and how long the server took (first line, done)."""
        if self.trace is not None and self._t is not None and len(self.trace) < 40:
            now = time.monotonic()
            name, t0, first = self._t
            self.trace.append([name, round((first or now) - t0, 2), round(now - t0, 2)])
        self._t = None

    def idle(self, timeout, should_stop=lambda: False):
        """IMAP IDLE (RFC 2177) on the selected mailbox for up to `timeout` s -> True when the server reported new
        mail (EXISTS/RECENT). Ends with DONE and waits for the tagged OK."""
        if 'IDLE' not in self.capabilities:
            raise self.error('server has no IDLE')
        tag = self._new_tag()
        self.tagged_commands.pop(tag, None)
        self.send(tag + b' IDLE\r\n')
        new = False
        while True:
            line = self._get_line()
            if line.startswith(b'+'):
                break
            if line.startswith(tag):
                raise self.error(f'IDLE refused: {line[len(tag):][:80]!r}')
            new = new or bool(re.match(rb'\* \d+ (?:EXISTS|RECENT)', line))
        end = time.monotonic() + timeout
        while not new and not should_stop():
            left = end - time.monotonic()
            if left <= 0:
                break
            if not self.file.ready():
                r, _, _ = select.select([self.sock], [], [], min(left, 2.0))
                if not r:
                    continue
            line = self._get_line()
            if re.match(rb'\* \d+ (?:EXISTS|RECENT)', line):
                new = True
            elif line.startswith(b'* BYE'):
                raise self.abort('server closed the IDLE (BYE)')
        self.send(b'DONE\r\n')
        while True:
            line = self._get_line()
            if line.startswith(tag + b' '):
                if not line[len(tag) + 1:].upper().startswith(b'OK'):
                    raise self.error(f'IDLE ended badly: {line[len(tag):][:80]!r}')
                return new
            new = new or bool(re.match(rb'\* \d+ (?:EXISTS|RECENT)', line))


class ReadOnlyIMAP(_ReadOnly, imaplib.IMAP4):
    pass


class ReadOnlyIMAP_SSL(_ReadOnly, imaplib.IMAP4_SSL):
    pass


# ============================================================================================ parsing helpers

def imap_utf7(s):
    """Mailbox name -> IMAP modified UTF-7 (RFC 3501 5.1.3)."""
    out, buf = [], []

    def flush():
        if buf:
            b = ''.join(buf).encode('utf-16-be')
            out.append('&' + base64.b64encode(b).decode().rstrip('=').replace('/', ',') + '-')
            buf.clear()
    for ch in s:
        if 0x20 <= ord(ch) <= 0x7e:
            flush()
            out.append('&-' if ch == '&' else ch)
        else:
            buf.append(ch)
    flush()
    return ''.join(out)


def quote_mailbox(name):
    enc = imap_utf7(name)
    return '"' + enc.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _fold_name(name):
    if not isinstance(name, str):
        return None
    n = name.strip()
    if not (0 < len(n) <= 100) or V._CTRL.search(n):
        return None
    return 'INBOX' if n.upper() == 'INBOX' else n


class _Text(HTMLParser):
    BLOCK = {'p', 'div', 'br', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'section', 'article',
             'blockquote', 'ul', 'ol', 'hr', 'header', 'footer'}
    SKIP = {'script', 'style', 'head', 'title', 'noscript', 'template'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append('\n')
        elif tag == 'td':
            self.out.append(' ')

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCK:
            self.out.append('\n')

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_to_text(s):
    p = _Text()
    try:
        p.feed(s or '')
        p.close()
    except Exception:
        return re.sub(r'<[^>]+>', ' ', html.unescape(s or ''))
    return ''.join(p.out)


def tidy(s):
    s = (s or '').replace('\r\n', '\n').replace('\r', '\n').replace('\xa0', ' ').replace('‌', '')
    lines = [' '.join(ln.split()) for ln in s.split('\n')]
    s = '\n'.join(lines)
    return re.sub(r'\n{3,}', '\n\n', s).strip()


def oneline(s, n):
    s = ' '.join((s or '').split())
    return s if len(s) <= n else s[:n - 1] + '…'


def parse_message(raw):
    try:
        return email.message_from_bytes(raw or b'', policy=email.policy.default)
    except Exception:
        return email.message_from_bytes(raw or b'', policy=email.policy.compat32)


def header(msg, name):
    try:
        v = msg.get(name)
        return '' if v is None else ' '.join(str(v).split())
    except Exception:
        return ''


def _part_text(part):
    try:
        content = part.get_content()
    except Exception:
        try:
            data = part.get_payload(decode=True) or b''
            content = data.decode(part.get_content_charset() or 'utf-8', 'replace')
        except Exception:
            content = ''
    if not isinstance(content, str):
        content = ''
    return html_to_text(content) if part.get_content_type() == 'text/html' else content


def body_text(msg):
    """text/plain preferred; HTML -> text when there is no plain part or it's only a stub ("view in browser")."""
    try:
        plain = msg.get_body(preferencelist=('plain',))
        rich = msg.get_body(preferencelist=('html',))
    except Exception:
        plain = rich = None
        if not msg.is_multipart() and msg.get_content_maintype() == 'text':
            plain = msg
    t = tidy(_part_text(plain)) if plain is not None else ''
    if rich is not None and len(t) < 40:
        h = tidy(_part_text(rich))
        if len(h) > len(t):
            t = h
    return t


def _is_attachment(part):
    if part.is_multipart():
        return False
    disp = part.get_content_disposition()
    fn = part.get_filename()
    if disp == 'attachment':
        return True
    if fn and part.get_content_maintype() != 'text':
        return not (disp == 'inline' and part.get('Content-ID'))     # an image embedded in the HTML: not a file
    return False


def attachment_parts(msg):
    try:
        return [p for p in msg.walk() if _is_attachment(p)]
    except Exception:
        return []


def _payload(part):
    try:
        return part.get_payload(decode=True) or b''
    except Exception:
        return b''


def attachments_meta(msg):
    out = []
    for n, p in enumerate(attachment_parts(msg), 1):
        out.append({'index': n, 'name': V.clean_text(p.get_filename() or 'unnamed', 120),
                    'type': p.get_content_type(), 'size': len(_payload(p))})
    return out


# Amounts in attachment names ("Invoice-108.34.pdf", "Quittung_CHF_45.00.pdf"): the separators hide them from the
# money net, so cents are masked here (dates like 13.10.2026 stay). Mail is the owner's own money (policy v3.1).
NAME_CENTS = re.compile(r'(?<![\d.,])\d{1,6}[.,]\d{2}(?!\d|[.,]\d)')


def name_amounts(name):
    return NAME_CENTS.sub('[amount]', name or '')


def att_line(atts):
    return '; '.join(f"{a['index']}. {name_amounts(a['name'])} ({a['type'].split('/')[-1]}, {V.human_size(a['size'])})"
                     for a in atts[:10]) + (f'; +{len(atts) - 10} more' if len(atts) > 10 else '')


def sender_of(msg):
    """-> (display name, address lowercased, domain)."""
    name, addr = email.utils.parseaddr(header(msg, 'From'))
    addr = addr.strip().lower()
    domain = addr.rsplit('@', 1)[1] if '@' in addr else ''
    name = V.clean_text(name, 60)
    if '@' in name:
        name = ''
    return name, addr, domain


def show_sender(name, domain):
    return f'{name} ({domain})' if name and domain else (name or domain or '?')


def display_from(name, domain):
    """Privacy plan A: companies "Name (domain)"; freemail senders (gmail, gmx, bluewin, ...) by first name only."""
    import answer
    return answer.display_from(name, domain)


def att_counts(atts):
    """Attachments as counts only (privacy plan A): {n, pdf, image}."""
    atts = atts or []
    return {'n': len(atts), 'pdf': sum(1 for a in atts if 'pdf' in str(a.get('type') or '').lower()),
            'image': sum(1 for a in atts if str(a.get('type') or '').lower().startswith('image/'))}


def domain_keys(domain):
    """'news.galaxus.ch' -> ['news.galaxus.ch', 'galaxus.ch'] (rules on a domain match its subdomains)."""
    parts = domain.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts) - 1)] or ([domain] if domain else [])


def safe_filename(name, uid, n, ctype):
    fn = os.path.basename((name or '').replace('\\', '/'))
    fn = re.sub(r'[\x00-\x1f\x7f"/\\]', '_', fn).strip(' .')[:150]
    ext = PAPERLESS_TYPES.get(ctype)
    if not fn:
        fn = f'gmail-{uid}-{n}{ext or ".bin"}'
    elif ext and '.' not in fn:
        fn += ext
    return fn


_REF_RE = re.compile(r'(?:([A-Za-z][A-Za-z0-9_-]{0,15}):)?(\d{1,10})(?:@(.{1,100}))?')


def split_ref(ref, folder=None):
    """'1234', '1234@Folder', 'work:1234' or 'work:1234@Folder' (as events and search show it) or an int ->
    (account label or None, uid, folder)."""
    if isinstance(ref, bool):
        raise VaultError('uid must be a number', 400, 'bad_param')
    label = None
    m = _REF_RE.fullmatch(ref.strip()) if isinstance(ref, str) else None
    if isinstance(ref, int):
        uid, f = ref, folder
    elif m:
        if m.group(1):
            label = V.gmail_label(m.group(1))
            if label is None:
                raise VaultError('bad account label in the REF', 400, 'bad_param')
        uid, f = int(m.group(2)), (m.group(3) or folder)
    else:
        raise VaultError('uid must be a number (or a REF like 1234, work:1234 or work:1234@Folder from the '
                         'events/search)', 400, 'bad_param')
    if not 1 <= uid < 2 ** 32:
        raise VaultError('uid out of range', 400, 'bad_param')
    f = _fold_name(f if f is not None else 'INBOX')
    if f is None:
        raise VaultError('bad folder name', 400, 'bad_param')
    return label, uid, f


def parse_ref(ref, folder=None):
    """-> (uid, folder) of a REF (its account prefix, if any, is dropped: GmailAccounts uses split_ref)."""
    return split_ref(ref, folder)[1:]


def make_ref(uid, folder, account=None):
    base = str(uid) if folder == 'INBOX' else f'{uid}@{folder}'
    return f'{account}:{base}' if account else base


def anon_many(policy, texts, what, owner=None, paraphrase=True):
    """One --anonymize call for several texts ('### item N' blocks); one call per text if the split fails. Mail is the
    owner's own money (policy v3.1): every amount -> [amount] (--all-amounts + the money net in code). Policy v4
    (paraphrase): subjects and snippets leave as checked paraphrases in their own language (v4.1)."""
    if not texts:
        return []
    joined = '\n\n'.join(f'### item {n}\n{t}' for n, t in enumerate(texts, 1))
    out = policy.anonymize(joined, owner_name=owner, what=what, timeout=1800, all_amounts=True, paraphrase=paraphrase)
    parts = V.split_items(out, len(texts))
    if parts is None:
        parts = [policy.anonymize(t, owner_name=owner, what=what, timeout=900, all_amounts=True,
                                  paraphrase=paraphrase) for t in texts]
    return [p.strip() for p in parts]


# ============================================================================================ the source

class Gmail:
    """ONE Gmail account. Label 'main' = secret `gmail`, state gmail.json + gmail-config.json (as before); label L =
    secret `gmail:L`, state gmail.L.json + gmail-config.L.json. Own IMAP login, IDLE + poll, positions, folder
    config, auth block and alerts."""

    def __init__(self, cfg, store, policy, audit, key, alert=None, log=print, clock=time.time, label='main'):
        if V.gmail_label(label) != label:
            raise ValueError(f'bad Gmail account label {label!r}')
        self.cfg, self.store, self.policy, self.audit, self.key = cfg, store, policy, audit, key
        self.alert = alert or (lambda *a, **k: None)
        self.log, self.clock = log, clock
        self.label, self.secret = label, V.gmail_secret(label)
        sfx = '' if label == 'main' else f'.{label}'
        self.state_path = cfg.state / f'gmail{sfx}.json'
        self.conf_path = cfg.state / f'gmail-config{sfx}.json'
        self.console_cmd = 'vault-console secret gmail' + ('' if label == 'main' else f' {label}')
        self.started = False                           # GmailAccounts started its IDLE + poll threads
        self.owner_fallback = None                     # -> the owner's name from elsewhere (main account, Telegram)
        self.wake = threading.Event()                  # new mail seen (IDLE) or a new secret: poll now
        self.creds_changed = threading.Event()
        self._lock = threading.Lock()
        self._auth_until = 0.0
        self.tg_owner = ''                             # the owner's name as Telegram knows it (fallback)
        self.watch = {'state': 'disabled' if cfg.env.get('VAULT_NO_GMAIL') == '1' else 'unconfigured',
                      'since': None, 'detail': None, 'reconnects': 0, 'last_new_mail': None}
        self.poll = {'last_at': None, 'last_ok_at': None, 'error': None, 'processed': 0, 'fails': 0, 'running': False}
        srv = (cfg.env.get('VAULT_GMAIL_IMAP') or '').strip()     # host:port override (tests: a local fake)
        if srv:
            host, _, port = srv.rpartition(':')
            self.server = (host, int(port), cfg.env.get('VAULT_GMAIL_TLS', '1') != '0')
        else:
            self.server = (IMAP_HOST, IMAP_PORT, True)
        if not self.server[2] and self.server[0] not in ('127.0.0.1', 'localhost', '::1'):
            raise SystemExit('VAULT_GMAIL_TLS=0 is only allowed for a local test server')

    # ---------------------------------------------------------------- config + state
    def configured(self):
        return self.store.is_set(self.secret)

    def kind(self, what):
        """Alert name per account: gmail-auth (main), gmail-auth-work, ..."""
        return what if self.label == 'main' else f'{what}-{self.label}'

    @property
    def tag(self):
        return '' if self.label == 'main' else f' (account {self.label})'

    def config(self):
        try:
            d = json.loads(self.conf_path.read_text())
            d = d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            d = {}
        folders = [f for f in (_fold_name(x) for x in d.get('folders') or []) if f]
        folders = ['INBOX'] + [f for f in dict.fromkeys(folders) if f != 'INBOX']
        return {'folders': folders[:MAX_FOLDERS], 'owner_name': V.clean_text(d.get('owner_name') or '', 100)}

    def set_config(self, body):
        cur = self.config()
        if 'folders' in body:
            fl = body['folders']
            if not isinstance(fl, list) or len(fl) > MAX_FOLDERS:
                raise VaultError(f'folders must be a list of at most {MAX_FOLDERS} folder/label names', 400,
                                 'bad_param')
            names = [_fold_name(x) for x in fl]
            if None in names:
                raise VaultError('every folder must be a name of 1-100 characters', 400, 'bad_param')
            cur['folders'] = ['INBOX'] + [f for f in dict.fromkeys(names) if f != 'INBOX']
        if 'owner_name' in body:
            on = body['owner_name']
            if on is not None and not (isinstance(on, str) and len(on) <= 100):
                raise VaultError('owner_name must be a string', 400, 'bad_param')
            cur['owner_name'] = V.clean_text(on or '', 100)
        unknown = set(body) - {'folders', 'owner_name'}
        if unknown:
            raise VaultError(f'unknown config key(s): {", ".join(sorted(unknown))}', 400, 'bad_param')
        with self._lock:
            V.write_private(self.conf_path, json.dumps(cur, ensure_ascii=False, indent=1))
        self.audit.log('gmail_config', account=self.label, folders=len(cur['folders']),
                       owner_name=bool(cur['owner_name']))
        self.wake.set()
        return cur

    def folders(self):
        return self.config()['folders']

    def owner(self):
        return (self.config()['owner_name'] or (self.owner_fallback() if self.owner_fallback else '')
                or self.tg_owner)

    def _state(self):
        try:
            d = json.loads(self.state_path.read_text())
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self, st):
        V.write_private(self.state_path, json.dumps(st))

    def pseudonym(self, addr):
        return 'm' + hmac.new(self.key, b'gmail:' + addr.encode('utf-8'), hashlib.sha256).hexdigest()[:10]

    def domain(self):
        """The address's domain only (results show the account label, never the address)."""
        try:
            return self.store.get(self.secret)['address'].rpartition('@')[2]
        except VaultError:
            return None

    def _set_watch(self, state, detail=None):
        if self.watch['state'] != state:
            self.watch['since'] = V.now_iso()
        self.watch.update(state=state, detail=detail)

    # ---------------------------------------------------------------- connection
    def _scrub(self, s):
        s = str(s)
        try:
            sec = self.store.get(self.secret)
            for v in (sec.get('app_password'), sec.get('address')):
                if v:
                    s = s.replace(v, '[secret]')
        except VaultError:
            pass
        return V.clean_text(s, 200)

    def credentials_changed(self):
        self._auth_until = 0.0
        self.creds_changed.set()
        self.wake.set()

    def connect(self, trace=None):
        """A logged-in read-only IMAP connection. Refused logins block new attempts for AUTH_BLOCK s (Google locks
        accounts that keep failing) unless the secret is replaced."""
        sec = self.store.get(self.secret)              # NotConfigured
        if self.clock() < self._auth_until:
            raise AuthFailed(f'Gmail refused the app password{self.tag}; waiting for a new one ({self.console_cmd})')
        host, port, tls = self.server
        try:
            if tls:
                im = ReadOnlyIMAP_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=CONNECT_TIMEOUT,
                                      trace=trace)
            else:
                im = ReadOnlyIMAP(host, port, timeout=CONNECT_TIMEOUT, trace=trace)
        except (OSError, imaplib.IMAP4.error) as e:
            raise VaultError(f'cannot reach Gmail IMAP: {self._scrub(e)}', 502, 'source_failed')
        try:
            im.login(sec['address'], sec['app_password'])
            typ, dat = im.capability()                 # the list can grow after login (IDLE, X-GM-EXT-1)
            if typ == 'OK' and dat and isinstance(dat[-1], bytes):
                im.capabilities = tuple(dat[-1].decode('ascii', 'replace').upper().split())
        except imaplib.IMAP4.abort as e:
            self._close(im)
            raise VaultError(f'Gmail connection failed: {self._scrub(e)}', 502, 'source_failed')
        except imaplib.IMAP4.error as e:                # a NO/BAD answer to LOGIN: the password was refused
            self._close(im)
            self._auth_until = self.clock() + AUTH_BLOCK
            self.audit.log('gmail_login_refused', account=self.label)
            self.alert(self.kind('gmail-auth'), f'Gmail login refused{self.tag}',
                       f'Gmail refused the vault\'s app password (IMAP login, account {self.label}). The owner sets a '
                       f'new one at the Unraid terminal: `docker exec -it claude-vault {self.console_cmd}` (Google '
                       'account > Security > 2-Step Verification > App passwords). No new login attempt for 30 min.',
                       hours=24)
            raise AuthFailed(f'Gmail refused the login{self.tag}: {self._scrub(e)}')
        except OSError as e:
            self._close(im)
            raise VaultError(f'Gmail connection failed: {self._scrub(e)}', 502, 'source_failed')
        finally:
            sec = None
        return im

    @staticmethod
    def _close(im):
        try:
            im.logout()
        except Exception:
            try:
                im.shutdown()
            except Exception:
                pass

    @contextlib.contextmanager
    def session(self, trace=None):
        im = self.connect(trace)
        try:
            yield im
        except (imaplib.IMAP4.error, OSError) as e:
            raise VaultError(f'Gmail IMAP failed: {self._scrub(e)}', 502, 'source_failed')
        finally:
            self._close(im)

    def examine(self, im, folder):
        """Open a folder READ-ONLY (EXAMINE) -> (uidvalidity, uidnext or None, exists)."""
        typ, dat = im.select(quote_mailbox(folder), readonly=True)
        if typ != 'OK':
            raise VaultError(f'no such Gmail folder/label: {folder!r}', 404, 'no_folder')

        def num(key):
            v = (im.untagged_responses.get(key) or [None])[-1]
            try:
                return int(v)
            except (TypeError, ValueError):
                return None
        try:
            exists = int(dat[-1])
        except (TypeError, ValueError, IndexError):
            exists = 0
        return num('UIDVALIDITY'), num('UIDNEXT'), exists

    @staticmethod
    def _search(im, *tokens, text=None):
        """UID SEARCH with IMAP tokens; `text` (a search string) is appended quoted, or as a UTF-8 literal when it
        is not plain ASCII."""
        if text is None or (re.fullmatch(r'[\x20-\x7e]+', text) and '"' not in text and '\\' not in text):
            typ, dat = im.uid('SEARCH', *tokens, *([f'"{text}"'] if text is not None else []))
        else:
            im.literal = text.encode('utf-8')
            typ, dat = im.uid('SEARCH', 'CHARSET', 'UTF-8', *tokens)
        if typ != 'OK':
            raise VaultError('Gmail search failed', 502, 'source_failed')
        return sorted({int(x) for x in b' '.join(d for d in dat if isinstance(d, bytes)).split() if x.isdigit()})

    @staticmethod
    def _fetch(im, uid, limit=None):
        """-> (raw bytes, internaldate epoch, size) or None if the mail is gone. BODY.PEEK only (never sets \\Seen)."""
        part = f'BODY.PEEK[]<0.{limit}>' if limit else 'BODY.PEEK[]'
        typ, dat = im.uid('FETCH', str(uid), f'(UID INTERNALDATE RFC822.SIZE {part})')
        if typ != 'OK':
            raise VaultError(f'Gmail fetch of mail {uid} failed', 502, 'source_failed')
        meta, body = b'', None
        for d in dat or []:
            if isinstance(d, tuple):
                meta += d[0] + b' '
                if body is None:
                    body = d[1]
            elif isinstance(d, bytes):
                meta += d + b' '
        m = re.search(rb'UID (\d+)', meta)
        if body is None or not m or int(m.group(1)) != uid:
            return None
        ts = None
        it = imaplib.Internaldate2tuple(meta)
        if it:
            ts = time.mktime(it)
        sm = re.search(rb'RFC822\.SIZE (\d+)', meta)
        return body, ts, int(sm.group(1)) if sm else len(body)

    @staticmethod
    def _fetch_many(im, uids, limit=None):
        """One UID FETCH for several mails (one round trip instead of one per mail) -> {uid: (raw, ts, size)}.
        BODY.PEEK only. Mails that are gone are simply missing."""
        if not uids:
            return {}
        part = f'BODY.PEEK[]<0.{limit}>' if limit else 'BODY.PEEK[]'
        typ, dat = im.uid('FETCH', ','.join(str(u) for u in uids), f'(UID INTERNALDATE RFC822.SIZE {part})')
        if typ != 'OK':
            raise VaultError('Gmail fetch failed', 502, 'source_failed')
        recs = []                                      # [meta, body]: a tuple starts a mail, bytes after it are its tail
        for d in dat or []:
            if isinstance(d, tuple):
                recs.append([d[0] + b' ', d[1]])
            elif isinstance(d, bytes):
                if re.match(rb'\d+ \(', d) or not recs:      # a FETCH answer without a literal (e.g. a flags update)
                    recs.append([d + b' ', None])
                else:
                    recs[-1][0] += d + b' '
        out = {}
        for meta, body in recs:
            m = re.search(rb'UID (\d+)', meta)
            if body is None or not m:
                continue
            ts = None
            it = imaplib.Internaldate2tuple(meta)
            if it:
                ts = time.mktime(it)
            sm = re.search(rb'RFC822\.SIZE (\d+)', meta)
            out.setdefault(int(m.group(1)), (body, ts, int(sm.group(1)) if sm else len(body)))
        return out

    def _size(self, im, uid):
        typ, dat = im.uid('FETCH', str(uid), '(UID RFC822.SIZE)')
        blob = b' '.join(d if isinstance(d, bytes) else d[0] for d in dat or [] if d)
        m = re.search(rb'RFC822\.SIZE (\d+)', blob)
        if typ != 'OK' or not m:
            raise VaultError(f'no mail with uid {uid} in this folder', 404, 'not_found')
        return int(m.group(1))

    def _message(self, im, uid, folder):
        """The whole mail (up to MAX_FETCH) -> (msg, ts, size, truncated)."""
        self.examine(im, folder)
        size = self._size(im, uid)
        got = self._fetch(im, uid, MAX_FETCH if size > MAX_FETCH else None)
        if got is None:
            raise VaultError(f'no mail with uid {uid} in {folder!r}', 404, 'not_found')
        raw, ts, size = got
        return parse_message(raw), ts, size, size > len(raw)

    def triage_items(self, uids, folder='INBOX'):
        """Quick card / re-triage: the feed's triage item of each uid (first TRIAGE_FETCH bytes, regex-
        masked one-line text; vault-internal) -> {uid: item}. Missing mails are left out."""
        out = {}
        with self.session() as im:
            self.examine(im, folder)
            for uid in uids:
                got = self._fetch(im, uid, TRIAGE_FETCH)
                if got is not None:
                    out[uid] = self.item(folder, uid, *got)
        return out

    # ---------------------------------------------------------------- new mail -> event feed
    def item(self, folder, uid, raw, ts, size):
        """One new mail -> an event-feed item (vault-internal: real names, regex-masked one-line text)."""
        msg = parse_message(raw)
        try:
            name, addr, domain = sender_of(msg)
            subject = V.clean_text(header(msg, 'Subject'), 300) or '(no subject)'
            atts = attachments_meta(msg)
            excerpt = oneline(body_text(msg), EXCERPT_CHARS)
            bulk = bool(msg.get('List-Unsubscribe') or msg.get('List-Id')
                        or header(msg, 'Precedence').lower() in ('bulk', 'list', 'junk'))
        except Exception:
            name, addr, domain, subject, atts, excerpt, bulk = '', '', '', '(could not read this mail)', [], '', False
        parts = [f'Subject: {subject}'] + (['[bulk mail]'] if bulk else []) + ([excerpt] if excerpt else [])
        if atts:
            parts.append('Attachments: ' + att_line(atts))
        if size > len(raw):
            parts.append(f'[mail is {V.human_size(size)}; only the first {V.human_size(len(raw))} were read]')
        disp = show_sender(name, domain)
        pseud = self.pseudonym(addr) if addr else ''
        return {'ts': ts or self.clock(), 'chat_key': domain or '?', 'chat': disp, 'chat_type': 'email',
                'sender': disp, 'sender_key': pseud, 'msg_id': make_ref(uid, folder, self.label),
                'account': self.label, 'att': att_counts(atts),
                'text': self.policy.regex_net(' | '.join(parts)),
                'match_chats': domain_keys(domain), 'match_senders': [k for k in (addr, pseud) if k]}

    def collect(self):
        """One poll: per folder, the new mails above the stored position (at most MAX_BATCH per folder) ->
        ([(folder, uidvalidity, last_uid, items)], more, errors). Positions are NOT moved here."""
        st = self._state().get('folders') or {}
        out, more, fresh, errors = [], False, {}, []
        with self.session() as im:
            for folder in self.folders():
                try:
                    uv, nxt, exists = self.examine(im, folder)
                except VaultError as e:
                    errors.append(f'{folder}: {e}')
                    continue
                cur = st.get(folder)
                if not cur or cur.get('uidvalidity') != uv:
                    if nxt is None:
                        allu = self._search(im, 'ALL') if exists else []
                        nxt = (allu[-1] + 1) if allu else 1
                    fresh[folder] = {'uidvalidity': uv, 'last_uid': nxt - 1}
                    continue
                last = int(cur.get('last_uid') or 0)
                if nxt is not None and nxt <= last + 1:
                    continue
                uids = [u for u in self._search(im, 'UID', f'{last + 1}:*') if u > last]
                if not uids:
                    continue
                batch = uids[:V.EventFeed.MAX_BATCH]
                more = more or len(uids) > len(batch)
                items = []
                for uid in batch:
                    got = self._fetch(im, uid, TRIAGE_FETCH)
                    if got is not None:
                        items.append(self.item(folder, uid, *got))
                out.append((folder, uv, batch[-1], items))
        if fresh:
            with self._lock:
                s = self._state()
                s.setdefault('folders', {}).update(fresh)
                self._save_state(s)
        return out, more, errors

    def poll_once(self, feed):
        """Fetch new mail, run it through the feed, then move the positions. -> True if more mail waits."""
        self.poll['last_at'] = V.now_iso()
        self.poll['running'] = True                    # the vault's pinned status shows "Checking Gmail"
        try:
            batches, more, errors = self.collect()
            owner = self.owner()
            for folder, uv, last_uid, items in batches:
                if items:
                    feed.process('gmail', {'owner_name': owner, 'items': items})
                with self._lock:
                    s = self._state()
                    s.setdefault('folders', {})[folder] = {'uidvalidity': uv, 'last_uid': last_uid}
                    self._save_state(s)
                self.poll['processed'] += len(items)
        finally:
            self.poll['running'] = False
        self.poll.update(last_ok_at=V.now_iso(), error='; '.join(errors)[:300] or None, fails=0)
        return more

    def run_poll(self, stop_ev, feed, start_delay=15):
        stop_ev.wait(start_delay)
        while not stop_ev.is_set():
            self.wake.clear()
            more, wait = False, POLL_SECONDS
            if self.configured() and self.watch['state'] != 'disabled':
                try:
                    more = self.poll_once(feed)
                except AuthFailed as e:
                    self.poll['error'] = str(e)
                except VaultError as e:                # LLM busy/down, Gmail unreachable: retry soon
                    self.poll['error'], wait = str(e)[:200], ERROR_RETRY
                    self.poll['fails'] += 1
                except Exception as e:
                    self.poll['error'], wait = type(e).__name__, ERROR_RETRY
                    self.poll['fails'] += 1
                    self.log(f'gmail poll: {type(e).__name__} {self._scrub(e)}')
                if self.poll['fails'] == 6:            # ~12 min of failures in a row
                    self.alert(self.kind('gmail-poll'), f'Gmail polling keeps failing{self.tag}',
                               f'The vault could not process new mail of account {self.label} 6 times in a row (last: '
                               f'{self.poll["error"]}). Check `vault gmail status`.')
            if not more:
                self.wake.wait(wait)
            stop_ev.wait(2)

    def run_idle(self, stop_ev):
        """IDLE watcher on INBOX: wakes the poll thread on new mail. Reconnects with backoff."""
        fails = 0
        while not stop_ev.is_set():
            if self.watch['state'] == 'disabled':
                return
            if not self.configured():
                self._set_watch('unconfigured')
                self.creds_changed.wait(60)
                self.creds_changed.clear()
                continue
            self.creds_changed.clear()
            im = None
            try:
                im = self.connect()
                if 'IDLE' not in im.capabilities:
                    self._set_watch('poll-only', 'the server has no IDLE: polling every 15 min')
                    self._close(im)
                    im = None
                    self.creds_changed.wait(6 * 3600)
                    continue
                self.examine(im, 'INBOX')
                self._set_watch('idle')
                while not stop_ev.is_set() and not self.creds_changed.is_set():
                    new = im.idle(IDLE_RENEW, lambda: stop_ev.is_set() or self.creds_changed.is_set())
                    fails = 0
                    if new:
                        self.watch['last_new_mail'] = V.now_iso()
                        self.wake.set()
            except AuthFailed as e:
                self._set_watch('auth_failed', str(e)[:200])
                self.creds_changed.wait(max(5.0, self._auth_until - self.clock()))
            except Exception as e:                     # network, BYE, timeouts: reconnect with backoff
                fails += 1
                self.watch['reconnects'] += 1
                wait = BACKOFF[min(fails, len(BACKOFF)) - 1]
                self._set_watch('reconnecting', f'{type(e).__name__}: {self._scrub(e)}; retry in {wait} s')
                self.wake.set()                        # the poll covers the gap
                stop_ev.wait(wait)
            finally:
                if im is not None:
                    self._close(im)

    def status(self):
        st = self._state().get('folders') or {}
        cfg = self.config()
        conf = self.configured()
        return {'account': self.label, 'configured': conf, 'domain': self.domain() if conf else None,
                'folders': cfg['folders'], 'owner_name_set': bool(cfg['owner_name']),
                'watcher': dict(self.watch, idle_renew_minutes=IDLE_RENEW // 60),
                'poll': dict(self.poll, every_minutes=POLL_SECONDS // 60),
                'positions': {f: (st.get(f) or {}).get('last_uid') for f in cfg['folders']}}

    def check(self):
        """After the owner stored the secret: log in and look at INBOX (read-only)."""
        with self.session() as im:
            uv, nxt, exists = self.examine(im, 'INBOX')
        return f'Gmail IMAP login OK{self.tag}, INBOX opened read-only ({exists} mails)'

    # ---------------------------------------------------------------- API: search, get
    def search_rows(self, q, n, f, plain=None, timing=None, capture=None):
        """IMAP part of a search (GmailAccounts.search anonymizes and merges): -> (rows, total). Vault-internal.
        plain: the text to use instead of q on a server without Gmail's search syntax (find, plan v2 #10).
        timing: a dict this fills with the stage times in s (connect, open, search, fetch, total) and the counts
        (hits, fetched): numbers only (one account took ~54 s). capture: V.capture_wanted() of the
        request thread (thread-local; searches of several accounts run in worker threads)."""
        capture = V.capture_wanted() if capture is None else capture
        tm = timing if timing is not None else {}
        trace = []                                     # [command, s to first line, s to done] (numbers only)
        t0 = time.monotonic()

        def lap(key, since):
            now = time.monotonic()
            tm[key] = round(now - since, 2)
            return now
        rows = []
        try:
            with self.session(trace) as im:
                t = lap('connect', t0)
                self.examine(im, f)
                t = lap('open', t)
                key = 'X-GM-RAW' if 'X-GM-EXT-1' in im.capabilities else 'TEXT'
                uids = self._search(im, key, text=q if key == 'X-GM-RAW' or plain is None else plain)
                t = lap('search', t)
                total = tm['hits'] = len(uids)
                want = list(reversed(uids[-n:]))
                got_all = self._fetch_many(im, want, SEARCH_FETCH)
                lap('fetch', t)
                tm['fetched'] = len(got_all)
                rows = self._rows(want, got_all, capture)
        finally:
            tm['total'] = round(time.monotonic() - t0, 2)
            tm['cmds'] = trace
        return rows, total

    def _rows(self, uids, got_all, capture=False):
        """search_rows' rows from the fetched mails, in the order of `uids`."""
        rows = []
        for uid in uids:
            got = got_all.get(uid)
            if got is None:
                continue
            raw, ts, size = got
            msg = parse_message(raw)
            name, addr, domain = sender_of(msg)
            rows.append({'account': self.label, 'uid': uid, 'ts': ts, 'size': size,
                         'from': show_sender(name, domain), '_name': name, '_domain': domain,
                         'subject': V.clean_text(header(msg, 'Subject'), 300) or '(no subject)',
                         'snippet': oneline(body_text(msg), 240), 'atts': attachments_meta(msg)})
            if capture:                                # the owner's full watch only: RAW stays in memory
                rows[-1]['_raw'] = (f"{name} <{addr}> · {V.now_iso(ts)[:16] if ts else '?'}\n"
                                    f"Subject: {header(msg, 'Subject')}\n{oneline(body_text(msg), 240)}")
        return rows

    def get(self, uid, folder='INBOX', chars=4000):
        with self.session() as im:
            msg, ts, size, trunc = self._message(im, uid, folder)
        name, addr, domain = sender_of(msg)
        subject = V.clean_text(header(msg, 'Subject'), 300) or '(no subject)'
        body = body_text(msg)
        cut = len(body) > chars
        doc = f'Subject: {subject}\n\n{body[:chars]}'
        V.capture_raw('Gmail message', f"From: {name} <{addr}> · {V.now_iso(ts)[:16] if ts else '?'}\n{doc}")
        anon = self.policy.anonymize(doc, owner_name=self.owner() or None, what='gmail get', timeout=1800,
                                     all_amounts=True, paraphrase=True)      # policy v4: checked paraphrase
        first, _, rest = anon.partition('\n')
        if first.startswith('Subject:'):
            subj, text = first.removeprefix('Subject:').strip(), rest.strip()
        else:
            subj, text = '', anon.strip()
        net = self.mail_net
        self.audit.log('gmail_get', account=self.label, uid=uid, folder=folder, chars=len(text))
        return {'ref': make_ref(uid, folder, self.label), 'account': self.label, 'uid': uid, 'folder': folder,
                'date': V.now_iso(ts) if ts else None,
                'from': net(show_sender(name, domain)), 'subject': subj, 'text': text,
                'text_truncated': cut, 'size': size, 'mail_truncated': trunc,
                'attachments': [dict(x, name=net(x['name'])) for x in attachments_meta(msg)]}

    def mail_net(self, text):
        """Fields that skip the LLM (sender display, attachment names): regex net + the mail money net."""
        return name_amounts(self.policy.money_net(self.policy.regex_net(text)))

    def anon_doc(self, uid, folder='INBOX', chars=8000):
        """Facts (plan v2 #6): one mail anonymized WITHOUT the v4 paraphrase (policy v3.1: every amount masked), for
        the vault's own extraction only: this text never leaves; only the checked facts built from it do."""
        with self.session() as im:
            msg, ts, size, trunc = self._message(im, uid, folder)
        name, addr, domain = sender_of(msg)
        subject = V.clean_text(header(msg, 'Subject'), 300) or '(no subject)'
        doc = f'Subject: {subject}\n\n{body_text(msg)[:chars]}'
        V.capture_raw('Gmail message', f"From: {name} <{addr}> · {V.now_iso(ts)[:16] if ts else '?'}\n{doc}")
        anon = self.policy.anonymize(doc, owner_name=self.owner() or None, what='gmail facts', timeout=1800,
                                     all_amounts=True, cls='bulk')
        self.audit.log('gmail_facts_read', account=self.label, uid=uid, folder=folder)
        return {'text': anon, 'ts': ts, 'from': self.mail_net(display_from(name, domain)),
                'ref': make_ref(uid, folder, self.label), 'account': self.label,
                'atts': att_counts(attachments_meta(msg))}

    # ---------------------------------------------------------------- raw (owner-approved) + paperless
    def _attachment(self, msg, uid, n):
        parts = attachment_parts(msg)
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(parts):
            raise VaultError(f'attachment must be 1..{len(parts)} (this mail has {len(parts)})', 400, 'bad_param')
        p = parts[n - 1]
        data = _payload(p)
        if not data:
            raise VaultError('that attachment is empty or unreadable', 409, 'empty')
        ctype = p.get_content_type()
        return safe_filename(p.get_filename(), uid, n, ctype), data, ctype

    def media(self, uid, folder, n=None):
        """For /media (2026-10-13): a mail's attachments as metadata (n None), or (meta, bytes) of attachment n.
        EXAMINE + BODY.PEEK only, like every read here."""
        with self.session() as im:
            msg, ts, size, trunc = self._message(im, uid, folder)
        name, addr, domain = sender_of(msg)
        meta = {'ref': make_ref(uid, folder, self.label), 'account': self.label,
                'date': V.now_iso(ts) if ts else None, 'from': self.policy.regex_net(show_sender(name, domain))}
        if n is None:
            return dict(meta, items=attachments_meta(msg), mail_truncated=bool(trunc))
        if trunc:
            raise VaultError('this mail is larger than the vault reads at once; its attachments may be cut', 413,
                             'mail_too_large')
        fn, data, ctype = self._attachment(msg, uid, n)
        return dict(meta, name=fn, type=ctype), data

    def raw_summary(self, msg, uid, folder):
        name, addr, domain = sender_of(msg)
        return f'mail {make_ref(uid, folder, self.label)} from {show_sender(name, domain)}'

    def raw(self, uid, folder, query):
        """For POST /raw/request source gmail (via GmailAccounts.raw): -> (kind, summary, payload). {uid, folder?} =
        the mail as text (headers + body + attachment list); + attachment N = that file; + eml: true = the .eml."""
        with self.session() as im:
            if query.get('eml'):
                self.examine(im, folder)
                got = self._fetch(im, uid)
                if got is None:
                    raise VaultError(f'no mail with uid {uid} in {folder!r}', 404, 'not_found')
                msg = parse_message(got[0])
                return 'file', self.raw_summary(msg, uid, folder) + ', whole mail (.eml)', \
                    (f"gmail-{'' if self.label == 'main' else self.label + '-'}{uid}.eml", got[0])
            msg, ts, size, trunc = self._message(im, uid, folder)
        if query.get('attachment') is not None:
            fn, data, ctype = self._attachment(msg, uid, query.get('attachment'))
            return 'file', self.raw_summary(msg, uid, folder) + f", attachment {query['attachment']} ({ctype})", \
                (fn, data)
        lines = [f'{h}: {header(msg, h)}' for h in ('From', 'To', 'Cc', 'Date', 'Subject') if header(msg, h)]
        atts = attachments_meta(msg)
        text = '\n'.join(lines) + '\n\n' + body_text(msg) + ('\n\nAttachments: ' + att_line(atts) if atts else '')
        if trunc:
            text += f'\n[the mail is {V.human_size(size)}; only the first {V.human_size(MAX_FETCH)} were read]'
        return 'text', self.raw_summary(msg, uid, folder), text + '\n'

    def to_paperless(self, uid, folder, body, paperless):
        """An attachment straight into the owner's paperless (stays inside his systems: no raw release; audited)."""
        n = body.get('attachment', 1)
        with self.session() as im:
            msg, ts, size, trunc = self._message(im, uid, folder)
        fn, data, ctype = self._attachment(msg, uid, n)
        if ctype not in PAPERLESS_TYPES and not fn.lower().endswith(tuple(PAPERLESS_TYPES.values()) + ('.jpeg',
                                                                                                     '.tif')):
            raise VaultError(f'attachment {n} is {ctype}: paperless takes PDF or images', 415, 'bad_type')
        up = {k: body[k] for k in ('title', 'created', 'correspondent', 'document_type', 'tags', 'create', 'wait',
                                   'timeout') if body.get(k) is not None}
        res = paperless.upload(dict(up, filename=fn, content_b64=base64.b64encode(data).decode()))
        self.audit.log('gmail_to_paperless', account=self.label, uid=uid, folder=folder, attachment=n, type=ctype,
                       bytes=len(data), document_id=res.get('document_id') if isinstance(res, dict) else None)
        return {'ref': make_ref(uid, folder, self.label), 'account': self.label, 'attachment': n, 'type': ctype,
                'bytes': len(data), 'paperless': res}


# ============================================================================================ all accounts

class GmailAccounts:
    """Every Gmail account of the vault; this is what vaultd talks to. One IDLE + one poll thread per account (an
    account whose secret arrives while the vault runs starts at once), the account of a call (`account`, else the
    REF's prefix, else the only one), search over all accounts by default (results merged, newest first), and the
    combined state for /status, the pinned board and the event feed's live view."""
    STATE_ORDER = ('auth_failed', 'reconnecting', 'unconfigured', 'poll-only', 'idle')    # worst first

    def __init__(self, cfg, store, policy, audit, key, alert=None, log=print, clock=time.time):
        self.cfg, self.store, self.policy, self.audit, self.key = cfg, store, policy, audit, key
        self.alert, self.log, self.clock = alert, log, clock
        self.disabled = cfg.env.get('VAULT_NO_GMAIL') == '1'
        self.accounts = {}
        self._lock = threading.Lock()
        self._run = None                               # (stop_ev, feed) once start() ran
        self.poll_delay = 15                           # s before an account's first poll (tests: 0)
        self.tg_owner = ''                             # the owner's name as Telegram knows it (fallback)
        self.server = self.acct('main').server         # checks the IMAP server setting at start-up

    # ---------------------------------------------------------------- accounts
    def labels(self):
        """The accounts with a secret: main first, then the others by label."""
        return self.store.gmail_labels()

    def acct(self, label):
        with self._lock:
            a = self.accounts.get(label)
            if a is None:
                a = self.accounts[label] = Gmail(self.cfg, self.store, self.policy, self.audit, self.key,
                                                 alert=self.alert, log=self.log, clock=self.clock, label=label)
                a.owner_fallback = self.fallback_owner
            return a

    def active(self):
        return [self.acct(lab) for lab in self.labels()]

    def configured(self):
        return bool(self.labels())

    def fallback_owner(self):
        main = self.accounts.get('main')
        return (main.config()['owner_name'] if main is not None else '') or self.tg_owner

    def resolve(self, account=None, ref_label=None, pre=False):
        """The ONE account a call is about: `account`, else the REF's account, else the only account there is.
        pre: while no account exists yet, 'main' may be configured ahead (folders, owner name)."""
        a = None
        if account not in (None, ''):
            if isinstance(account, str) and account.strip().lower() == 'all':
                raise VaultError('this needs one account (account "all" only works for a search)', 400, 'bad_param')
            a = V.gmail_label(account)
            if a is None:
                raise VaultError('account must be an account label like main or work', 400, 'bad_param')
        if ref_label and a and ref_label != a:
            raise VaultError(f'the REF is from account {ref_label!r}, but account says {a!r}', 400, 'bad_param')
        a = a or ref_label
        labels = self.labels()
        if pre and not labels and a in (None, 'main'):
            return self.acct('main')
        if not labels:
            raise V.NotConfigured('gmail')
        if a is None:
            if len(labels) > 1:
                raise VaultError(f'several Gmail accounts ({", ".join(labels)}): give the account, or a REF that '
                                 f'carries it like {labels[1]}:1234', 400, 'account_needed')
            a = labels[0]
        if a not in labels:
            raise VaultError(f'no Gmail account {a!r} in the vault (accounts: {", ".join(labels)})', 404,
                             'no_account')
        return self.acct(a)

    # ---------------------------------------------------------------- threads
    def start(self, stop_ev, feed):
        if self.disabled:                              # VAULT_NO_GMAIL=1: no watcher, no poll
            return
        self._run = (stop_ev, feed)
        for a in self.active():
            self._start(a)

    def _start(self, a):
        with self._lock:
            if a.started or self._run is None or self.disabled:
                return
            a.started = True
        stop_ev, feed = self._run
        threading.Thread(target=a.run_idle, args=(stop_ev,), name=f'gmail-idle-{a.label}', daemon=True).start()
        threading.Thread(target=a.run_poll, args=(stop_ev, feed), kwargs={'start_delay': self.poll_delay},
                         name=f'gmail-poll-{a.label}', daemon=True).start()

    def credentials_changed(self, label='main'):
        """A secret was stored: clear its login block, restart its watcher, poll now (start the threads of a new
        account)."""
        a = self.acct(label)
        a.credentials_changed()
        self._start(a)

    def check(self, label='main'):
        return self.acct(label).check()

    def poll_once(self, feed, account=None):
        """One poll of one account (or of each): -> True if more mail waits."""
        more = False
        for a in ([self.resolve(account)] if account else self.active()):
            more = a.poll_once(feed) or more
        return more

    # ---------------------------------------------------------------- state
    def watch_state(self):
        """The worst watcher state of the configured accounts (board, /status, the event feed's live view)."""
        if self.disabled:
            return 'disabled'
        states = [a.watch['state'] for a in self.active()]
        for st in self.STATE_ORDER:
            if st in states:
                return st
        return states[0] if states else 'unconfigured'

    def checking(self):
        return any(a.poll.get('running') for a in self.active())

    def has_error(self):
        return any(a.poll.get('error') for a in self.active())

    def board(self):
        """[{account, watch, error}] per configured account (the pinned board shows them when there are several)."""
        return [{'account': a.label, 'watch': a.watch['state'], 'error': bool(a.poll.get('error'))}
                for a in self.active()]

    def summary(self):
        """The gmail part of GET /status."""
        rows = [{'account': a.label, 'watcher': a.watch['state'], 'last_poll': a.poll['last_ok_at'],
                 'error': a.poll['error']} for a in self.active()]
        errs = [(f"{r['account']}: " if len(rows) > 1 else '') + r['error'] for r in rows if r['error']]
        polls = [r['last_poll'] for r in rows]
        return {'configured': bool(rows), 'watcher': self.watch_state(),
                'last_poll': min(polls) if polls and all(polls) else None, 'error': '; '.join(errs)[:300] or None,
                'accounts': rows}

    def status(self):
        host, port, tls = self.server
        return {'configured': self.configured(), 'read_only': True,
                'server': f'{host}:{port}' + ('' if tls else ' (no TLS: test)'), 'watcher': self.watch_state(),
                'idle_renew_minutes': IDLE_RENEW // 60, 'poll_every_minutes': POLL_SECONDS // 60,
                'accounts': [a.status() for a in self.active()]}

    # ---------------------------------------------------------------- config
    def config(self, account=None):
        accs = [self.resolve(account, pre=True)] if account not in (None, '') else (self.active()
                                                                                  or [self.acct('main')])
        return {'accounts': [dict(a.config(), account=a.label) for a in accs]}

    def set_config(self, body):
        body = dict(body)
        a = self.resolve(body.pop('account', None), pre=True)
        return dict(a.set_config(body), account=a.label)

    # ---------------------------------------------------------------- API: search, get, paperless, raw
    def each_account(self, accs, fn, timeout=None, single_raises=True):
        """fn(account, timing) for every account, in parallel (two accounts one after the other took
        over 120 s) -> ({label: result}, {label: error line}, {label: timing}, first error). An account that takes
        longer than `timeout` s (default SEARCH_ACCOUNT_TIMEOUT) is reported as an error and the others answer;
        its thread finishes on its own (the IMAP socket timeout bounds it). One account: no thread, no timeout,
        its VaultError is raised (single_raises)."""
        timeout = SEARCH_ACCOUNT_TIMEOUT if timeout is None else timeout
        timing = {a.label: {} for a in accs}
        got, errors, first = {}, {}, None
        if len(accs) == 1 and single_raises:
            a = accs[0]
            got[a.label] = fn(a, timing[a.label])
            return got, errors, timing, None
        ex = cf.ThreadPoolExecutor(max_workers=max(1, len(accs)), thread_name_prefix='gmail-search')
        try:
            futs = {ex.submit(fn, a, timing[a.label]): a for a in accs}
            _, pending = cf.wait(futs, timeout=timeout)
            for fut, a in futs.items():
                if fut in pending:
                    errors[a.label] = f'timed out after {timeout} s (results from the other accounts only)'
                    timing[a.label] = dict(timing[a.label], total=f'>{timeout}')
                    first = first or VaultError(f'Gmail search timed out{a.tag}', 504, 'timeout')
                    continue
                try:
                    got[a.label] = fut.result()
                except VaultError as e:
                    errors[a.label] = str(e)[:200]
                    first = first or e
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        return got, errors, {k: dict(v) for k, v in timing.items()}, first

    def search(self, q, n=10, folder='INBOX', account=None, text=True, classify=None):
        """Gmail search syntax in one account or (default) in all of them; anonymized subject + snippet. text=False
        (privacy plan A): {ref, date, account, from (company or freemail first name), category, attachment counts},
        no subject and no snippet; classify(refs, items) -> a category per row (the feed's triage, the label cache,
        or with --triage ONE triage call for the rest; None -> "?"; no LLM call by default)."""
        if not isinstance(q, str) or not 0 < len(q.strip()) <= 300 or V._CTRL.search(q):
            raise VaultError('q must be a search text of 1-300 characters (Gmail search syntax works)', 400,
                             'bad_param')
        f = _fold_name(folder)
        if f is None:
            raise VaultError('bad folder name', 400, 'bad_param')
        every = account is None or (isinstance(account, str) and account.strip().lower() in ('', 'all'))
        accs = self.active() if every else [self.resolve(account)]
        if not accs:
            raise V.NotConfigured('gmail')
        cap = V.capture_wanted()
        got, errors, timing, first = self.each_account(
            accs, lambda a, tm: a.search_rows(q.strip(), n, f, timing=tm, capture=cap))
        rows, total, done = [], 0, []
        for a in accs:
            if a.label in got:
                rows += got[a.label][0]
                total += got[a.label][1]
                done.append(a.label)
        if not done:
            raise first
        self.log('gmail search timing: ' + '; '.join(f"{k} " + ' '.join(f'{x}={y}' for x, y in v.items())
                                                     for k, v in timing.items()))
        if len(done) > 1:
            rows.sort(key=lambda r: r['ts'] or 0, reverse=True)
            rows = rows[:n]
        V.capture_raw('Gmail search', '\n\n'.join(r.pop('_raw', '') for r in rows))
        if not text:
            net = accs[0].mail_net
            items = [{'chat_type': 'email', 'chat': show_sender(r['_name'], r['_domain']),
                      'text': self.policy.regex_net(' | '.join([f"Subject: {r['subject']}", r['snippet']]
                                                               + (['Attachments: ' + att_line(r['atts'])]
                                                                  if r['atts'] else [])))} for r in rows]
            refs = [make_ref(r['uid'], f, r['account']) for r in rows]
            cats = classify(refs, items) if (classify and items) else [None] * len(rows)
            out = [{'ref': ref, 'account': r['account'],
                    'date': V.now_iso(r['ts']) if r['ts'] else None, 'from': net(display_from(r['_name'], r['_domain'])),
                    'category': c if c in V.GMAIL_LABELS else '?', 'attachments': att_counts(r['atts'])}
                   for ref, r, c in zip(refs, rows, cats)]
            self.audit.log('gmail_search', q=q, folder=f, accounts=','.join(done), count=len(out), total=total,
                           text=False)
            res = {'count': len(out), 'total': total, 'folder': f, 'accounts': done, 'results': out,
                   'timing': timing,
                   'note': 'no subject or text; category from the live feed\'s triage, "?" = not triaged yet '
                           '(--triage: one local-LLM call for those); vault gmail get REF = a card; text needs --text '
                           '+ the owner\'s OK'}
            if errors:
                res['errors'] = errors
            return res
        anon = anon_many(self.policy, [f"Subject: {r['subject']}\n{r['snippet']}" for r in rows], 'gmail search',
                         accs[0].owner() or None)
        net = accs[0].mail_net
        out = []
        for r, an in zip(rows, anon):
            subj, _, snip = an.partition('\n')
            out.append({'ref': make_ref(r['uid'], f, r['account']), 'account': r['account'], 'uid': r['uid'],
                        'folder': f, 'date': V.now_iso(r['ts']) if r['ts'] else None, 'from': net(r['from']),
                        'subject': subj.removeprefix('Subject:').strip(), 'snippet': ' '.join(snip.split()),
                        'size': r['size'], 'attachments': [dict(x, name=net(x['name'])) for x in r['atts']]})
        self.audit.log('gmail_search', q=q, folder=f, accounts=','.join(done), count=len(out), total=total)
        res = {'count': len(out), 'total': total, 'folder': f, 'accounts': done, 'results': out, 'timing': timing}
        if errors:
            res['errors'] = errors
        return res

    def get(self, ref, folder=None, chars=4000, account=None):
        label, uid, f = split_ref(ref, folder)
        return self.resolve(account, label).get(uid, f, chars)

    def norm_ref(self, ref, folder=None, account=None):
        """A REF as the user gave it ('43203', 'main:43203', ...) -> the feed's form ('main:43203')."""
        label, uid, f = split_ref(ref, folder)
        return make_ref(uid, f, self.resolve(account, label).label)

    def triage_items(self, refs):
        """{ref: feed triage item} for REFs in the feed's form (vault-internal), grouped per account and folder."""
        groups = {}
        for ref in refs:
            label, uid, f = split_ref(ref)
            groups.setdefault((label, f), []).append((uid, ref))
        out = {}
        for (label, f), pairs in groups.items():
            got = self.resolve(None, label).triage_items([u for u, _ in pairs], f)
            out.update({ref: got[u] for u, ref in pairs if u in got})
        return out

    def anon_doc(self, ref, folder=None, chars=8000, account=None):
        """Facts (plan v2 #6): the REF's mail, anonymized, not paraphrased (vault-internal)."""
        if ref in (None, ''):
            raise VaultError('uid is required: a mail REF like main:1234 (from search or events)', 400, 'bad_param')
        label, uid, f = split_ref(ref, folder)
        return self.resolve(account, label).anon_doc(uid, f, chars)

    def find_rows(self, q, plain, n=10, folder='INBOX'):
        """Find (plan v2 #10): raw rows of every account (Gmail syntax q; plain on other servers), newest first, for
        the vault's own ranking and its one anonymize call -> (rows, {label: error}). Vault-internal."""
        accs = self.active()
        if not accs:
            raise V.NotConfigured('gmail')
        cap = V.capture_wanted()
        got, errors, _, _ = self.each_account(
            accs, lambda a, tm: a.search_rows(q, n, folder, plain=plain, timing=tm, capture=cap), single_raises=False)
        rows = []
        for a in accs:
            for x in (got.get(a.label) or ([], 0))[0]:
                x['folder'] = folder
                rows.append(x)
        if errors and len(errors) == len(accs):
            raise VaultError('gmail: ' + next(iter(errors.values())), 502, 'source_failed')
        rows.sort(key=lambda r: r['ts'] or 0, reverse=True)
        return rows[:n], errors

    def mail_net(self, text):
        return name_amounts(self.policy.money_net(self.policy.regex_net(text)))

    def to_paperless(self, body, paperless):
        label, uid, f = split_ref(body.get('uid'), body.get('folder'))
        return self.resolve(body.get('account'), label).to_paperless(uid, f, body, paperless)

    def media(self, ref, n=None, folder=None, account=None):
        if not isinstance(ref, str) or not ref.strip():
            raise VaultError('ref must be a mail REF (main:1234 or work:1234@Folder)', 400, 'bad_param')
        label, uid, f = split_ref(ref, folder)
        return self.resolve(account, label).media(uid, f, n)

    def raw(self, query):
        if not isinstance(query, dict):
            raise VaultError('query must be an object {uid, folder?, account?, attachment? | eml?}', 400, 'bad_query')
        label, uid, f = split_ref(query.get('uid'), query.get('folder'))
        return self.resolve(query.get('account'), label).raw(uid, f, query)
