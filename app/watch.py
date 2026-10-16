"""/watch in the vault's own bot: the real-time audit in the owner's chat.

  /watch on [full] [30m|2h]   stream Claude's API calls for that long (default 30 min, at most 12 h)
  /watch full [30m|2h]        the same as /watch on full
  /watch off                  stop (it also stops by itself when the time is up, and at every vault restart)
  /watch | /watch state       the current state with buttons: Watch 30 min · Watch full 30 min · Full 2 h · Off
Forgiving: colons after the command or a word are ignored, and
anything it doesn't know answers with the state and the buttons. The buttons (callback data w:on:30, w:full:30,
w:full:120, w:off) count only from the owner's chat, like his messages (ApprovalBot.handle checks first).

Layout: one plain line per call,
"HH:MM:SS emoji verb · details · outcome · time", e.g. "00:05:12 🔎 ask tg · 'Wochenende' · yesno → ✅ answer: no
2026-10-10 (past) last weekend · 3 msgs, 0 dropped · 14 s"; no JSON, no dict dumps; built only from the live view's
already-scrubbed fields (header/outcome/answer_bits: enums, dates and counts, never names or text). LLM busy and job
progress polls are one line edited in place ("🧠 LLM busy: answer yesno (tg, part 1/1) · 14 s") until another line
goes out. Full adds Original and Claude got as quotes in plain "key: value" lines (plain_body).
Earlier layout: parse_mode HTML, one message per call. Header: an emoji per source
(💬 Telegram · 📧 Gmail · 📄 Paperless · 🖼 media · 🔑 raw request …), the action in plain words, the query, then
time · duration · size ("💬 Telegram search · 'Hochziit' · 14:13 · 35 s · 2.1 KB"). Compact (no full): the other
allowlisted parameters and an italic last line with what was hidden by category ("hidden: 1 AHV · 2 links" or
"nothing hidden"). Full: bold sections Request, Original (the source text that went in) and Claude got, the last two
as <blockquote expandable> cut to ~1200 characters each, in a readable form (vaultlib.tap_readable / readable_tg:
one line per message "Sender · time: text", no ### headers, refs or policy footers; vault-console watch --full keeps
the exact bytes), the redaction placeholders in Claude got in bold, then the hidden line. Text is escaped (&, <, >)
after it is cut, so no entity or tag is ever cut in half; if Telegram refuses the markup the message goes out as
plain text. Original exists only while a full watch runs (LiveTap.raw_ok), in memory only, for the owner only;
tokens, links with tokens, one-time codes, the vault's secret values and live raw codes are scrubbed from it.
Everything comes from the live view's ring buffer (vaultlib.LiveTap), scrubbed once more right before it is sent.
More than 3 calls within 5 s: the rest go out together, one message per 5 s. Silent (disable_notification). Routine
polls with nothing new (GET /events with no events, /status, /alerts, /metrics) are only counted. The audit gets
watch_on / watch_off, never content.
"""
import datetime as dt
import html
import json
import re
import threading
import time

import vaultlib as V

DEFAULT_MIN = 30
MAX_MIN = 12 * 60
WINDOW = 5.0                                   # calls within 5 s -> one message; at most one message per 5 s
PART_CHARS = 1200                              # full: each part (RAW, RESPONSE) cut to ~1200 chars
MSG_CHARS = 3900
MAX_PENDING = 40
SINGLE_MAX = 3                                 # more calls than this within WINDOW s go out together
ROUTINE = {('GET', '/events'), ('GET', '/tg/events'), ('GET', '/status'), ('GET', '/alerts'), ('GET', '/metrics')}
ROUTINE_EVERY = 600                            # routine-only counts: at most one message per 10 min
KINDS = {'/media/extract': 'media facts', '/llm/run': 'llm run', '/finance/status': 'finance status'}
USAGE = ('/watch on [full] [30m|2h]: stream Claude\'s vault calls here, live (full: with what Claude got)\n'
         '/watch full 2h · /watch off · /watch: state')
BUTTONS = [[('Watch 30 min', 'w:on:30'), ('Watch full 30 min', 'w:full:30')],
           [('Full 2 h', 'w:full:120'), ('Off', 'w:off')]]
CMD_RE = re.compile(r'/watch(?:@[A-Za-z0-9_]{1,64})?(?![A-Za-z0-9_@])(.*)', re.I | re.S)
BUTTON_RE = re.compile(r'w:(?:(on|full):(\d{1,3})|(off))')


def kind_of(method, path):
    parts = [p for p in path.split('/') if p]
    if path in KINDS:
        return KINDS[path]
    if parts[:1] == ['secrets']:
        return 'secret ' + ('set' if method == 'POST' else 'list')
    if parts[:1] == ['jobs']:
        return 'job polls' if method == 'GET' else 'job ' + (parts[-1] if len(parts) > 2 else 'submit')
    return ' '.join(parts[:2]).replace('-', ' ') or path


def parse_duration(words):
    """'30m', '2h', '90' (minutes) -> minutes, or None."""
    for w in words:
        m = re.fullmatch(r'(\d{1,4})\s*(m|min|h)?', w)
        if m:
            n = int(m.group(1)) * (60 if m.group(2) == 'h' else 1)
            return max(1, min(n, MAX_MIN))
    return None


SOURCE_EMOJI = (('/tg/', '💬'), ('/gmail/', '📧'), ('/paperless/', '📄'), ('/media/', '🖼'), ('/raw/', '🔑'),
                ('/events', '🔔'), ('/firefly/', '💰'), ('/finance/', '💰'), ('/llm/', '🧠'), ('/secrets', '🔐'))
HIDDEN_WORDS = {'phone': ('phone number', 'phone numbers'), 'email': ('email address', 'email addresses'),
                'address': ('address', 'addresses'), 'iban': ('IBAN', 'IBANs'), 'card': ('card number', 'card numbers'),
                'ahv': ('AHV', 'AHV'), 'id': ('ID number', 'ID numbers'), 'birthdate': ('birth date', 'birth dates'),
                'location': ('location', 'locations'), 'plate': ('plate', 'plates'), 'link': ('link', 'links'),
                'secret': ('secret', 'secrets'), 'surname': ('surname', 'surnames'),
                'account': ('account number', 'account numbers'), 'number': ('number', 'numbers'),
                'name': ('name', 'names'), 'username': ('username', 'usernames'), 'code': ('code', 'codes'),
                'redacted': ('redaction', 'redactions'), 'amount': ('amount', 'amounts')}
MARK_RE = re.compile('|'.join([V.TAP_PRIVATE_RE.pattern, V.TAP_MASK_RE.pattern, r'\[not paraphrased\]']), re.I)
_TAG_RE = re.compile(r'</?(?:b|i|code|blockquote)(?: expandable)?>')


def esc(s):
    """HTML text for parse_mode HTML: &, < and > escaped (Telegram's three)."""
    return html.escape(str(s), quote=False)


def marked(s):
    """Escaped text with the redaction placeholders in bold, so they stand out in 'Claude got'."""
    return MARK_RE.sub(lambda m: f'<b>{m.group(0)}</b>', esc(s))


def plain(h):
    """The HTML message as plain text (fallback when Telegram refuses the markup)."""
    return html.unescape(_TAG_RE.sub('', h))


def plain_cut(h, n):
    """A block too long for one message: its plain text, cut, escaped again (never a tag cut in half)."""
    return esc(plain(h)[:max(0, n - 40)].rstrip() + '\n…(cut)')


def emoji_of(path):
    return next((e for p, e in SOURCE_EMOJI if path.startswith(p)), '⚙️')


def cut(text, total, cap):
    """At most `cap` characters + '…(N more chars)' (plain text: escaping comes after the cut)."""
    text = (text or '').strip()
    more = max(total or 0, len(text)) - min(len(text), cap)
    return text[:cap].rstrip() + (f'\n…({more} more chars)' if more > 0 else '')


def hidden_line(ev):
    """'hidden: 1 health passage · 1 AHV · 2 links' / 'nothing hidden' (content routes only), or None."""
    if ev.get('raw'):
        return 'RAW text released (owner-approved)'
    if ev['status'] != 200 or ev.get('exit') or not (ev.get('filtered') or ev.get('private') or ev.get('masked')):
        return None
    parts = [f"{n} {c} passage{'s' if n > 1 else ''}" for c, n in
             sorted((ev.get('private') or {}).items(), key=lambda kv: (-kv[1], kv[0]))]
    for k, n in sorted((ev.get('masked') or {}).items(), key=lambda kv: (-kv[1], kv[0])):
        one, many = HIDDEN_WORDS.get(k, (k, k + 's'))
        parts.append(f'{n} {one if n == 1 else many}')
    return 'hidden: ' + ' · '.join(parts) if parts else 'nothing hidden'


def _mins(s):
    return f'{s} s' if s < 60 else f'{s / 60:.0f} min'


def job_bit(job):
    """An async job (plan v2 #4): '⏳ job queued (#2, ETA ~3 min)' at its submit, '✅ job done' when it ended."""
    if job.get('phase') == 'submit':
        if job.get('coalesced'):
            return '⏳ job (joined the same one, already running)'
        extra = [f"#{job['position']}"] if job.get('position') else []
        if job.get('eta_s') is not None:
            extra.append(f"ETA ~{_mins(int(job['eta_s']))}")
        return '⏳ job ' + str(job.get('state') or 'queued') + (f" ({', '.join(extra)})" if extra else '')
    return '✅ job done' if job.get('state') == 'done' else '⚠️ job ended'


# ---------------------------------------------------------------- one line per call (JSON-formatted lines were hard to
# follow): 'HH:MM:SS emoji verb · details · outcome · time', built only from the
# live view's already-scrubbed fields (lead, params through the scrubber, body, readable); no JSON, no dict dumps.
VERBS = {'/answer': ('🔎', 'ask'), '/tg/search': ('🔎', 'search Telegram'), '/tg/recent': ('💬', 'read recent Telegram'),
         '/tg/unread-summary-data': ('💬', 'Telegram unread digest'), '/tg/summarize': ('💬', 'Telegram digest'),
         '/tg/digest': ('💬', 'Telegram digest'), '/tg/find-chat': ('💬', 'find a chat'), '/tg/who': ('💬', 'who is who'),
         '/tg/chats': ('💬', 'list chats'), '/tg/alias': ('💬', 'chat aliases'), '/gmail/search': ('📧', 'search Gmail'),
         '/gmail/get': ('📧', 'read a mail'), '/gmail/to-paperless': ('📧', 'file a mail to Paperless'),
         '/paperless/get': ('📄', 'read a Paperless doc'), '/paperless/search': ('📄', 'search Paperless'),
         '/paperless/recent': ('📄', 'recent Paperless docs'), '/paperless/suggest': ('📄', 'Paperless suggestions'),
         '/raw/request': ('🔐', 'text request'), '/raw/release': ('🔓', 'text release check'),
         '/events': ('🔔', 'check new events'), '/tg/events': ('🔔', 'check new Telegram events'),
         '/llm/run': ('🧠', "LLM on Claude's own text"), '/facts': ('🗂', 'extract facts'), '/find': ('🔎', 'find'),
         '/media/extract': ('🖼', 'read a photo/file'), '/media/list': ('🖼', 'list files'),
         '/firefly/summary': ('💰', 'Firefly summary'), '/finance/status': ('💰', 'finance status')}
DETAIL_KEYS = ('chat', 'kind', 'since', 'ref', 'id', 'account', 'n')
AN_KINDS = ('yesno', 'when', 'who', 'deadline', 'actionable', 'requests', 'count', 'short', 'interests', 'mail_card')
PAIR_RE = re.compile(r'(\w{1,30})=("(?:[^"\\]|\\.)*"?|\[[^\]]*\]?|\{[^}]*\}?|\([^)]*\)|\S+)')


def _val(v):
    """One request value as plain words: strings unquoted, lists 'a, b', nested values '…'."""
    if v.startswith('"'):
        try:
            return str(json.loads(v))
        except ValueError:
            return v.strip('"')
    if v.startswith('['):
        return ', '.join(x.strip().strip('"') for x in v.strip('[]').split(',') if x.strip()) or '–'
    return '…' if v.startswith('{') else v


def pairs(params):
    """The live view's 'k=v …' (already allowlisted; scrubbed by the caller) -> {k: plain value}."""
    return {k: _val(v) for k, v in PAIR_RE.findall(params or '')}


def body_of(ev):
    """The scrubbed response body as a dict when it is whole JSON (render_body), else None."""
    if ev.get('body_chars', 0) > ev.get('body_cut', 0):
        return None
    try:
        d = json.loads(ev.get('body') or '')
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def dur(ms):
    sec = (ms or 0) / 1000
    return f'{sec:.1f} s' if sec < 10 else f'{sec:.0f} s' if sec < 60 else f'{sec / 60:.1f} min'


def hms(ts):
    return dt.datetime.fromtimestamp(ts, V.TZ).strftime('%H:%M:%S')


def answer_bits(kind, a):
    """A checked answer in a few words, numbers and dates only (no names or text: those are in full)."""
    a = a if isinstance(a, dict) else {}
    when = ''.join([f" {a['date']}" if a.get('date') else '', ' (past)' if a.get('timing') == 'past' else '',
                    f" {a['relative']}" if a.get('relative') else '',
                    ' ⚠️ not on the asked days' if a.get('in_window') is False else ''])
    if kind == 'yesno':
        return f"{a.get('answer', '?')}{when}"
    if kind == 'when':
        return (when.strip() or 'no date') + (f" {a['start']}" if a.get('start') else '') + \
            (' · place ✓' if a.get('venue') or a.get('address') else '')
    if kind == 'who':
        n, k = len(a.get('who') or []), len(a.get('nicknames') or [])
        return f"{n} name(s)" + (f", {k} nickname(s)" if k else '') if n or k else 'nobody named'
    if kind == 'count':
        return f"{a.get('n', 0)} match(es)"
    if kind == 'requests':
        return f"{len(a.get('requests') or [])} request(s)"
    if kind == 'short':
        return 'unclear' if a.get('answer') in (None, 'unclear') else f"short answer ({len(str(a['answer']).split())} words)"
    if kind in ('deadline', 'actionable'):
        flag = a.get('has_deadline') if kind == 'deadline' else a.get('actionable')
        return ('yes' if flag else 'no') + when + (f" · {a['action']}" if a.get('action') else '')
    if kind == 'interests':
        return f"{len(a.get('interests') or [])} interest(s)"
    return 'done'


def outcome(ev, b):
    """'✅ answer: no 2026-10-10 (past) last weekend · 3 msgs, 0 dropped' and the like; '⚠️ 409 sessions_off'."""
    if ev['status'] != 200:
        return f"⚠️ {ev['status']}" + (f" {ev['code']}" if ev.get('code') else '')
    if ev.get('exit'):
        return f"⚠️ exit {ev['exit']}"
    if ev.get('raw'):
        return '🔓 text released (you approved it)'
    path, b = ev['path'], b or {}
    if path == '/raw/request':
        return 'waiting for your ✅' if b.get('status') in ('pending', None) else str(b.get('status'))
    if path == '/raw/release':
        return {'pending': '⏳ still waiting for your ✅', 'denied': '❌ you denied it',
                'expired': '⌛ expired'}.get(b.get('status'), str(b.get('status') or 'done'))
    if path == '/answer' and b.get('kind') == 'mail_card':
        return f"✅ card: {b.get('category', '?')}" + (f" · {b['action']}" if b.get('actionable') else '')
    if path == '/answer' and 'answer' in b:
        return (f"✅ answer: {answer_bits(b.get('kind'), b.get('answer'))} · {b.get('messages', 0)} msgs, "
                f"{b.get('dropped', 0)} dropped")
    if b.get('kind') == 'digest':
        w = b.get('window') or {}
        return f"✅ digest: {w.get('chats', 0)} chats, {w.get('messages', 0)} msgs, {len(b.get('needs_you') or [])} need you"
    if b.get('kind') == 'hits':
        return f"✅ {b.get('count', 0)} hit(s)"
    for k, word in (('results', 'mail(s)'), ('events', 'event(s)'), ('documents', 'doc(s)'), ('hits', 'hit(s)')):
        if isinstance(b.get(k), list):
            return f"✅ {len(b[k])} {word}"
    return '✅ done'


def verb(ev, b, p):
    """(emoji, verb): an ask names its source; a follow-up shows its turn ('↪️ follow-up 2/6')."""
    path = (ev.get('job') or {}).get('route') or ev['path']
    if path == '/answer':
        sess = (b or {}).get('session') if isinstance((b or {}).get('session'), dict) else {}
        turn = (b or {}).get('turn') if isinstance((b or {}).get('turn'), int) else None
        if (turn or 1) > 1 or (p.get('session') not in (None, 'true', 'True') and 'source' not in p):
            return '↪️', 'follow-up' + (f" {turn}/{turn + int(sess.get('turns_left') or 0)}" if turn else '')
        return '🔎', 'ask ' + {'telegram': 'tg'}.get(p.get('source'), p.get('source') or '')
    if path in VERBS:
        return VERBS[path]
    return emoji_of(path), V.route_words(ev['method'], path)


def header(ev, scrub=lambda s: s):
    """One line per call, e.g. "00:05:12 🔎 ask tg · 'Wochenende' · yesno · session → ✅ answer: no 2026-10-10 (past)
    last weekend · 3 msgs, 0 dropped · 14 s". An async job: its submit '⏳ queued: …', its end with the job's time."""
    p = pairs(scrub(ev.get('params') or ''))
    b = body_of(ev)
    job = ev.get('job') or {}
    emo, what = verb(ev, b, p)
    if ev['path'] == '/answer' and b and b.get('kind') in AN_KINDS and not p.get('kind'):
        p['kind'] = b['kind']                          # a follow-up's kind (from the words): '↪️ follow-up 2/6 · when'
    bits = [f"{hms(ev['ts'])} {emo} {what}"]
    if ev.get('lead'):
        bits.append(f"'{ev['lead']}'")
    bits += [p[k] if k in ('kind', 'since') else f'{k} {p[k]}' for k in DETAIL_KEYS
             if p.get(k) not in (None, '', '(hidden)')][:4]
    if p.get('session') in ('true', 'True'):
        bits.append('new session')
    if job.get('phase') == 'submit':
        return ' · '.join(bits) + ' → ' + job_bit(job)
    line = ' · '.join(bits) + ' → ' + outcome(ev, b) + f" · {dur(ev['ms'])}" + (' (job)' if job else '')
    hid = hidden_line(ev)
    return line + (f' · 🙈 {hid}' if hid and hid != 'nothing hidden' else ' · nothing hidden' if hid else '')


def plain_body(text):
    """A JSON body (render_body, maybe cut) as 'key: value' lines: no braces, brackets or quotes."""
    out = []
    for ln in (text or '').split('\n'):
        st = ln.strip().rstrip(',')
        if st in ('{', '}', '[', ']', '{}', '[]', ''):
            continue
        ind = '  ' * max(0, (len(ln) - len(ln.lstrip()) - 2) // 2)
        m = re.match(r'^"((?:[^"\\]|\\.)*)":\s*(.*)$', st)
        if m:
            k, v = m.group(1), m.group(2)
            v = '' if v in ('{', '[') else '–' if v in ('{}', '[]', 'null') else _val(v)
            out.append(f'{ind}{k}: {v}'.rstrip())
        else:
            out.append(f'{ind}- {_val(st)}' if st.startswith('"') or re.match(r'^[-\d.]+$|^(?:true|false)$', st)
                       else ind + st)
    return '\n'.join(out)


def tick_line(ev):
    """A job poll or a /status poll while the LLM works -> '🧠 LLM busy: answer yesno (tg, part 1/1) · 14 s' /
    '⏳ job 1a2b3c4d running · answer part 1/2 · 14 s', or None (not a progress tick)."""
    if ev['method'] != 'GET' or ev['status'] != 200 or not (ev['path'] == '/status' or ev['path'].startswith('/jobs/')):
        return None
    b = body_of(ev)
    if ev['path'].startswith('/jobs/') and b and b.get('state'):
        pr = b.get('progress') if isinstance(b.get('progress'), dict) else {}
        step = pr.get('step') or (f"{pr.get('done', 0)}/{pr['total']} parts" if pr.get('total') else '')
        return ' · '.join(x for x in (f"⏳ job {str(b.get('id') or '')[:8]} {b['state']}", str(step)[:60],
                                       dur(int(b.get('elapsed_s') or 0) * 1000)) if x)
    if ev['path'] == '/status':
        run = (((b or {}).get('llm') or {}).get('queue') or {}).get('running') if b else None
        if not run:
            m = re.search(r'"running":\s*\{[^{}]*?"what":\s*"([^"]{1,60})"[^{}]*?"elapsed_s":\s*(\d+)', ev.get('body') or '')
            run = {'what': m.group(1), 'elapsed_s': int(m.group(2))} if m else None
        if isinstance(run, dict) and run.get('what'):
            return f"🧠 LLM busy: {str(run['what'])[:60]} · {dur(int(run.get('elapsed_s') or 0) * 1000)}"
    return None


def readable_raw(raw, now=None):
    """The captured source text ('── label ──' parts) as the owner reads it: Telegram one line per message."""
    parts = re.split(r'(?m)^── (.*?) ──$\n?', raw or '')
    out = [parts[0].strip()] if parts[0].strip() else []
    for label, text in zip(parts[1::2], parts[2::2]):
        out.append(V.readable_tg(text, now) if label.startswith('Telegram') else text.strip())
    return '\n\n'.join(x for x in out if x) or '(no source text)'


def entry(ev, full=False, now=None, scrub=lambda s: s):
    """One call. Compact: its one line. Full: the line, then Original (what went in) and Claude got as expandable
    quotes in plain 'key: value' lines, each cut to ~PART_CHARS."""
    out = [esc(header(ev, scrub))]
    if not full or (ev.get('job') or {}).get('phase') == 'submit':
        return out[0]
    if ev.get('raw_in') is not None:
        txt = readable_raw(ev['raw_in'], now)
        txt = cut(txt, len(txt) + max(0, ev.get('raw_chars', 0) - len(ev['raw_in'])), PART_CHARS)
        out += [f'<b>Original</b>\n<blockquote expandable>{esc(txt)}</blockquote>']
    elif ev['path'] in V.TAP_RAW_ROUTES:
        out += ['<b>Original</b>\n<i>(not captured: the call began before the full watch)</i>']
    if ev.get('readable') is not None and not ev['readable'].lstrip().startswith('{'):
        got = cut(ev['readable'], ev.get('readable_chars', 0), PART_CHARS)
    else:
        txt = plain_body(ev.get('body', ''))
        got = cut(txt, len(txt) + max(0, ev.get('body_chars', 0) - len(ev.get('body', ''))), PART_CHARS)
    out += [f'<b>Claude got</b>\n<blockquote expandable>{marked(got or "(empty)")}</blockquote>']
    return '\n\n'.join(out)


def routine(ev):
    if ev['method'] == 'GET' and ev['path'].startswith('/jobs') and ev['status'] in (200, 404):
        return True                                    # job polls; the job's answer shows once, when it ends
    if (ev['method'], ev['path']) not in ROUTINE or ev['status'] != 200:
        return False
    if ev['path'] in ('/events', '/tg/events'):
        return '"events": []' in (ev.get('body') or '')
    return True


class WatchBot:
    def __init__(self, tap, notifier, audit, scrub=lambda s: s, clock=time.time, log=print):
        self.tap, self.notifier, self.audit, self.scrub, self.clock, self.log = tap, notifier, audit, scrub, clock, log
        self.until = None                              # off by default and after every restart
        self.full = False
        self.cursor = 0
        self.pending, self.first_ts, self.last_sent = [], None, 0.0
        self.arrivals, self.batch_since = [], None     # arrival times within WINDOW; batching since
        self.routine, self.routine_sent = {}, 0.0
        self.ticks, self.tick_msg = [], None           # LLM busy / job progress polls: one line, edited in place
        self._lock = threading.Lock()

    @property
    def on(self):
        return self.until is not None

    def status(self):
        """For /status: numbers and flags only."""
        return {'on': self.on, 'full': self.on and self.full,
                'until': V.now_iso(self.until) if self.on else None, 'raw_kept': self.tap.raw_kept}

    def say(self, text, silent=True, buttons=None, html=False):
        """To the owner's chat through the vault's bot (protected; silent: no notification sound). The text is
        scrubbed once more with the live view's scrubber (secret values, live raw codes) right before it goes out.
        buttons (the state's inline keyboard) always notify. html: parse_mode HTML (the call blocks; if Telegram
        refuses the markup, the same text goes out once more as plain text)."""
        text = self.scrub(text)
        if html and self.scrub(plain(text)) != plain(text):     # a secret value written with &, < or >
            text = esc(self.scrub(plain(text)))
        if not html:
            text = text[:4000]
        elif len(plain(text)) > 4000:                    # Telegram counts the text after parsing the markup
            text = plain_cut(text, 4000)
        if getattr(self.notifier, 'test_mode', False):
            self.log(f'watch: test mode, {len(text)} chars not sent')
            return None
        try:
            try:
                if buttons:
                    return self.notifier.send(text, buttons)
                elif silent:
                    return self.notifier.send_silent(text, html=html)[0]
                else:
                    return self.notifier.send(text, html=html)
            except V.NotifyError as e:
                if not html or e.status != 400:
                    raise
                self.log('watch: HTML refused by Telegram; sent as plain text')
                (self.notifier.send_silent if silent else self.notifier.send)(plain(text)[:4000])
        except (V.NotifyError, V.VaultError, KeyError) as e:
            self.log(f'watch: message not sent ({type(e).__name__})')
        return None

    def tick_out(self, line):
        """An LLM busy / job progress line: edits the last one in place while nothing else went out in between
        (scrubbed like say), else a new silent message."""
        line = self.scrub(line)[:4000]
        t = self.tick_msg
        if t and t['text'] == line:
            return
        if t and t.get('id') and not getattr(self.notifier, 'test_mode', False):
            try:
                self.notifier.edit(t['id'], line)
                t['text'] = line
                return
            except (V.NotifyError, V.VaultError, KeyError) as e:
                self.log(f'watch: progress line not edited ({type(e).__name__}); sent anew')
        mid = self.say(line)
        self.tick_msg = {'id': mid, 'text': line}

    # ---------------------------------------------------------------- the owner's commands (poll thread)
    def _is_owner(self, frm, chat):
        try:
            owner = self.notifier.chat_id()
        except (V.VaultError, KeyError, TypeError):
            return False
        return bool(owner) and str(frm) == owner and str(chat) == owner

    def on_message(self, msg):
        """True if msg was the owner's /watch (handled here). Anything else, and /watch from any other chat, goes on
        to the finance intake, which refuses other chats and audits it (finance_refused).
        Forgiving: '/watch: full', '/watch on: full 2h', '/watch state' (trailing colons and punctuation ignored)."""
        text = str((msg or {}).get('text') or '').strip()
        m = CMD_RE.fullmatch(text)
        if not m or (m.group(1) and not m.group(1)[0].isspace() and m.group(1)[0] != ':'):
            return False
        if not self._is_owner((msg.get('from') or {}).get('id', ''), (msg.get('chat') or {}).get('id', '')):
            return False
        words = [w for w in (w.strip(':;,.!?').lower() for w in m.group(1).replace(':', ' ').split()) if w]
        if words[:1] == ['on']:
            self.start(parse_duration(words[1:]) or DEFAULT_MIN, 'full' in words[1:])
        elif words[:1] == ['full']:
            self.start(parse_duration(words[1:]) or DEFAULT_MIN, True)
        elif words[:1] == ['off']:
            self.end('owner')
        else:                                          # '', state, status, or anything it doesn't know
            self.show_state()
        return True

    def show_state(self):
        """The state + the inline buttons (Watch 30 min · Watch full 30 min · Full 2 h · Off)."""
        if self.on:
            left = max(1, int((self.until - self.clock()) // 60))
            head = f"👁 Watch is on{' (full)' if self.full else ''} for {left} more min. /watch off stops it."
        else:
            head = '👁 Watch is off.'
        self.say(head + '\n' + USAGE, silent=False, buttons=BUTTONS)

    def on_callback(self, cq):
        """A press on the state's buttons (ApprovalBot.handle routes data 'w:…' here after its owner check; checked
        again). -> the answer text shown on the button."""
        msg = cq.get('message') if isinstance(cq.get('message'), dict) else {}
        if not self._is_owner((cq.get('from') or {}).get('id', ''), (msg.get('chat') or {}).get('id', '')):
            return None
        m = BUTTON_RE.fullmatch(str(cq.get('data') or ''))
        if not m:
            return 'Unknown button'
        if m.group(3):
            self.end('owner')
            return 'Watch off ✓'
        minutes = max(1, min(int(m.group(2)), MAX_MIN))
        self.start(minutes, m.group(1) == 'full')
        return f"Watch{' full' if m.group(1) == 'full' else ''} on for {minutes} min ✓"

    def start(self, minutes, full):
        with self._lock:
            self.until = self.clock() + minutes * 60
            self.full = bool(full)
            self.cursor = self.tap.seq                 # only calls from now on
            self.pending, self.first_ts, self.routine = [], None, {}
            self.arrivals, self.batch_since, self.ticks, self.tick_msg = [], None, [], None
            self.routine_sent = self.clock()
            self.tap.bot_full_until = self.until if self.full else 0.0    # RAW only while a full watch runs
        self.audit.log('watch_on', full=self.full, minutes=minutes)
        self.say(f"👁 Watch on{' (full: with what Claude got)' if self.full else ''} for {minutes} min: Claude's vault "
                 f"calls appear here. /watch off stops it.", silent=False)

    def stop(self, why):
        with self._lock:
            was = self.on
            self.until, self.pending, self.first_ts, self.routine = None, [], None, {}
            self.arrivals, self.batch_since, self.ticks, self.tick_msg = [], None, [], None
            self.tap.bot_full_until = 0.0
        self.tap.sweep_raw()                           # no full watch left: the buffer keeps no RAW text
        if was:
            self.audit.log('watch_off', why=why)
            self.say('👁 Watch off.' if why == 'owner' else '👁 Watch ended (time is up). /watch on starts it again.',
                     silent=False)
        elif why == 'owner':
            self.say('👁 Watch is off.', silent=False)

    # ---------------------------------------------------------------- streaming (own thread)
    def run(self, stop_ev):
        """One thread for the vault's lifetime; it only does something while the watch is on."""
        while not stop_ev.wait(1.0):
            try:
                if self.on:
                    self.tick()
                self.tap.sweep_raw()                   # e.g. the console's watch --full went away
            except Exception as e:
                self.log(f'watch: {type(e).__name__}')

    def collect(self, now):
        with self._lock:
            for ev in self.tap.raw_since(self.cursor):
                self.cursor = max(self.cursor, ev['seq'])
                if ev.get('via') != 'api':
                    continue                           # the owner's console calls are his own
                if tick_line(ev):                      # progress: one line, edited in place
                    self.ticks.append(ev)
                    continue
                if routine(ev):
                    k = kind_of(ev['method'], ev['path'])
                    self.routine[k] = self.routine.get(k, 0) + 1
                    continue
                self.pending.append(ev)
                self.arrivals.append(now)

    def tick(self, now=None):
        """Collect new calls from the ring buffer; send one batch when its 5-s window and the 5-s gap are over.
        When the time is up: one last batch, then the watch ends."""
        now = self.clock() if now is None else now
        if not self.on:
            return 0
        self.collect(now)
        if now >= self.until:
            sent = self.flush(now, final=True)
            self.stop('timeout')
            return sent
        return self.flush(now)

    def end(self, why):
        """/watch off: what is still pending goes out first (one last batch), then the watch ends."""
        if self.on:
            now = self.clock()
            self.collect(now)
            self.flush(now, final=True)
        self.stop(why)

    def flush(self, now, final=False):
        """One message per call, at once. More than SINGLE_MAX calls within WINDOW s: the rest wait and go out
        together, one message per WINDOW s (what doesn't fit waits for the next one). -> messages sent."""
        msgs = []
        with self._lock:
            self.arrivals = [t for t in self.arrivals if now - t < WINDOW]
            if len(self.pending) > MAX_PENDING:
                skipped = len(self.pending) - MAX_PENDING
                self.pending = self.pending[-MAX_PENDING:]
                self.pending[0] = dict(self.pending[0], skipped=skipped)
            if self.pending and self.batch_since is None and len(self.arrivals) <= SINGLE_MAX:
                msgs = [self.render([ev]) for ev in self.pending]
                self.pending = []
            elif self.pending:
                if self.batch_since is None:
                    self.batch_since = now
                if final or now - self.batch_since >= WINDOW:
                    used, size = 0, 0
                    for ev in self.pending:
                        n = len(plain(entry(ev, self.full, now, self.scrub))) + 20
                        if used and size + n > MSG_CHARS:
                            break
                        used, size = used + 1, size + n
                    msgs.append(self.render(self.pending[:used]))
                    self.pending = self.pending[used:]
                    self.batch_since = now if self.pending else None
                    if final and self.pending:
                        msgs[-1] += f'\n\n<i>… {len(self.pending)} more call(s) not shown (the watch ended)</i>'
                        self.pending, self.batch_since = [], None
            if self.routine and (msgs or final or now - self.routine_sent >= ROUTINE_EVERY):
                line = '<i>+ routine polls: ' + esc(', '.join(f'{k} {n}' for k, n in sorted(self.routine.items()))) \
                    + '</i>'
                if msgs:
                    msgs[-1] += '\n\n' + line
                else:
                    msgs.append(line)
                self.routine, self.routine_sent = {}, now
            if msgs:
                self.last_sent = now
                self.tick_msg = None                   # a call line went out: the next progress line is new
            tick = f"{hms(self.ticks[-1]['ts'])} {tick_line(self.ticks[-1])}" if self.ticks else None
            self.ticks = []
        for m in msgs:
            self.say(m, html=True)
        if tick:
            self.tick_out(tick)
        return len(msgs)

    def render(self, evs):
        """One message: the calls' HTML blocks (a line between them in a batch), each cut to MSG_CHARS."""
        sep = '\n\n━━━━━━━━\n\n' if self.full else '\n'
        blocks = []
        for ev in evs:
            b = entry(ev, self.full, self.clock(), self.scrub)
            if ev.get('skipped'):
                b = f"<i>… {ev['skipped']} earlier call(s) not shown (too many at once)</i>\n\n" + b
            blocks.append(b if len(plain(b)) <= MSG_CHARS else plain_cut(b, MSG_CHARS))
        return sep.join(blocks)
