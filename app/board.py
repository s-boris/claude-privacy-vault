"""Pinned status message in the owner's vault-bot chat: what the vault is doing, plus some
stats.

ONE message the vault sends silently, pins (disable_notification) and then edits in place: at most every MIN_EDIT s
when something changed, at least every REFRESH s (the clock line), right away on the owner's /status. If he deletes it
(the edit fails with 400) the vault sends a new one and pins it; if he unpins it, the next check (getChat: the most
recent pinned message by sending date) pins it again, unless he pinned something newer himself. Edits never notify.
Only in the chat of the vault's OWN bot (ApprovalBot polling): a bot shared with the assistant's chat bot would put
this pin over the assistant's own status board. Never in test mode or with VAULT_NO_STATUS_BOARD=1.

Counts and states only, never content: no chat names, senders, subjects, queries, reasons or document titles. The
counters (Claude's API calls by kind, redactions in what left the vault, raw asks and the owner's decisions, Firefly
imports) live in /data/state/status-board.json (reset at midnight Zurich); new Telegram messages / mails and how many
of them were surfaced to Claude come from the event store itself."""
import datetime as dt
import json
import re
import threading
import time

import vaultlib as V

# API paths whose calls count as "Claude asked the vault for data" (status polls, the event feed, release polls and
# housekeeping are not counted). Order matters: the first matching prefix wins.
CALL_KINDS = (('/tg/', 'TG'), ('/paperless/', 'docs'), ('/gmail/', 'mail'), ('/firefly/', 'money'),
              ('/finance/', 'money'), ('/llm/run', 'LLM'), ('/raw/request', 'raw'), ('/media/request', 'raw'),
              ('/media/', 'media'))
NOT_COUNTED = frozenset({'/tg/status', '/tg/chats', '/tg/events', '/tg/credentials', '/tg/login', '/tg/login-qr',
                         '/tg/login-cancel', '/tg/2fa', '/tg/selfcheck', '/gmail/status', '/gmail/config',
                         '/firefly/status', '/finance/status', '/paperless/task'})
KIND_ORDER = ('TG', 'mail', 'docs', 'money', 'LLM', 'raw')
FINANCE_BUSY = {'import': 'Firefly import', 'dry run': 'Firefly dry run', 'download': 'Receiving a bank export',
                'report': 'Firefly report'}
RAW_KIND = {'text': 'raw text', 'file': 'a file', 'secret': 'a secret change', 'media': 'files'}
SAFE_WORD = re.compile(r'[^a-z -]')


def llm_activity(what):
    """The LLM gate's job label -> a short, content-free phrase."""
    w = str(what or '').strip().lower()
    n = re.search(r'\((\d{1,4})\)', w)
    n = int(n.group(1)) if n else None
    if w.startswith('tgread summarize'):
        return 'Summarizing Telegram chats'
    if w.startswith('tgread '):
        return f"Telegram {SAFE_WORD.sub('', w[7:])[:20].strip() or 'job'}"
    if w.startswith('telegram triage'):
        return f'Sorting {n} new Telegram msg(s)' if n else 'Sorting new Telegram msgs'
    if w.startswith('gmail triage'):
        return f'Sorting {n} new mail(s)' if n else 'Sorting new mails'
    if w.startswith('event anonymize'):
        return f'Anonymizing {n} item(s)' if n else 'Anonymizing new items'
    if w.startswith('gmail'):
        return 'Anonymizing mail for Claude'
    if w.startswith('paperless'):
        return 'Anonymizing a document'
    if w.startswith('llm-run'):
        return 'Local LLM job for Claude'
    return 'Anonymizing'


def ok_icon(state):
    return {'ok': '✅', 'off': '➖', 'warn': '⚠️', 'down': '❌', 'paused': '⏸'}.get(state, '❔')


def gmail_health(watch, error=False, configured=True):
    """One Gmail account's (or all accounts' worst) watcher state -> ok | off | warn | down."""
    return ('off' if not configured or watch == 'disabled' else 'down' if watch == 'auth_failed' else
            'warn' if watch not in ('idle', 'poll-only') or error else 'ok')


class StatusBoard:
    MIN_EDIT = 30            # s between two edits when something changed
    MIN_FORCED = 3           # s: /status may not hammer the API either
    REFRESH = 600            # s: edit at least this often (clock line) and check the pin
    RECREATE_GAP = 120       # s: never two new messages closer than this
    TICK = 5                 # s between checks in the thread
    SAVE_EVERY = 30          # s: counters to disk at most this often
    MAX_LINES = 14

    def __init__(self, cfg, notifier, snapshot, events=None, enabled=None, log=print, clock=time.time):
        self.cfg, self.notifier, self.snapshot, self.events, self.log, self.clock = \
            cfg, notifier, snapshot, events, log, clock
        self.enabled = enabled or (lambda: (True, ''))
        self.path = cfg.state / 'status-board.json'
        self._lock = threading.RLock()
        self.wake = threading.Event()
        self.forced = False
        self.backoff_until = 0.0
        self.state, self.detail = 'starting', ''
        self.dirty, self.saved_at = False, 0.0
        try:
            self.st = json.loads(self.path.read_text())
            if not isinstance(self.st, dict):
                raise ValueError
        except (OSError, ValueError):
            self.st = {}
        self.st.setdefault('msg', None)          # {id, date, chat, bot, created, last_edit, body, pinned}
        self._roll()

    # ---------------------------------------------------------------- counters (thread-safe, content-free)
    def _today(self, now=None):
        return dt.datetime.fromtimestamp(self.clock() if now is None else now, V.TZ).date().isoformat()

    def _roll(self, now=None):
        day = self._today(now)
        with self._lock:
            if (self.st.get('counts') or {}).get('day') != day:
                self.st['counts'] = {'day': day, 'calls': {}, 'private': 0, 'masked': 0, 'raw_asked': 0,
                                     'raw_ok': 0, 'raw_no': 0, 'raw_expired': 0, 'ff_imports': 0, 'ff_tx': 0,
                                     'edits': 0, 'text_rel': 0}
                self.dirty = True
            return self.st['counts']

    def note_call(self, ev):
        """One API call as LiveTap saw it (vaultd.record_call): its kind and the redactions in its answer."""
        if not isinstance(ev, dict) or ev.get('via') != 'api' or ev.get('status') == 401:
            return
        path = str(ev.get('path') or '')
        kind = None
        if path not in NOT_COUNTED:
            kind = next((k for p, k in CALL_KINDS if path == p or path.startswith(p)), None)
        priv = sum(int(v) for v in (ev.get('private') or {}).values())
        masked = sum(int(v) for v in (ev.get('masked') or {}).values())
        if ev.get('status') != 200 or ev.get('exit'):
            priv = masked = 0
        if not kind and not priv and not masked:
            return
        with self._lock:
            c = self._roll()
            if kind:
                c['calls'][kind] = c['calls'].get(kind, 0) + 1
            c['private'] += priv
            c['masked'] += masked
            self.dirty = True

    def note_audit(self, event, rec):
        """Audit listener: raw asks, the owner's decisions, Firefly imports."""
        key = {'raw_request': 'raw_asked', 'raw_approved': 'raw_ok', 'raw_denied': 'raw_no',
               'raw_expired': 'raw_expired', 'finance_import': 'ff_imports', 'text_release': 'text_rel'}.get(event)
        if not key:
            return
        with self._lock:
            c = self._roll()
            c[key] = c.get(key, 0) + 1
            if key == 'ff_imports':
                try:
                    c['ff_tx'] += max(0, int((rec or {}).get('sent') or 0))
                except (TypeError, ValueError):
                    pass
            self.dirty = True
        if key in ('raw_asked', 'raw_ok', 'raw_no'):
            self.wake.set()                          # the owner sees "waiting for your ✅" quickly

    def counts(self):
        with self._lock:
            return json.loads(json.dumps(self._roll()))

    def day_events(self, now=None):
        if self.events is None:
            return {}
        local = dt.datetime.fromtimestamp(self.clock() if now is None else now, V.TZ)
        midnight = local.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        try:
            return self.events.day_counts(midnight)
        except Exception as e:
            self.log(f'status board: event counts failed ({type(e).__name__})')
            return {}

    # ---------------------------------------------------------------- the owner's /status
    def on_message(self, msg):
        """True if msg was the owner's /status (handled here: refresh now); anything else goes on to finance."""
        text = str((msg or {}).get('text') or '').strip()
        if not text.startswith('/') or text.split()[0].split('@')[0].lower() != '/status':
            return False
        try:
            owner = self.notifier.chat_id()
        except (V.VaultError, KeyError, TypeError):
            return False
        frm, chat = str((msg.get('from') or {}).get('id', '')), str((msg.get('chat') or {}).get('id', ''))
        if frm != owner or chat != owner:
            return False                             # finance refuses + audits it
        self.force()
        return True

    def force(self):
        self.forced = True
        self.wake.set()

    # ---------------------------------------------------------------- rendering (counts and states only)
    def activity(self, s, now):
        acts = []
        pend = [r for r in s.get('pending') or [] if r.get('state') == 'pending']
        if pend:
            if len(pend) == 1:
                r = pend[0]
                left = max(0, int((r.get('expires', now) - now) // 60))
                how = '✅' if r.get('approval') == 'buttons' else 'code'
                acts.append(f"Waiting for your {how}: {RAW_KIND.get(r.get('kind'), 'raw data')} "
                            f"({SAFE_WORD.sub('', str(r.get('source') or '?'))[:14]}), {left} min left")
            else:
                acts.append(f'Waiting for your ✅ on {len(pend)} requests')
        busy = s.get('llm_busy')
        if busy:
            since = dt.datetime.fromtimestamp(busy[1], V.TZ).strftime('%H:%M')
            acts.append(f'{llm_activity(busy[0])} since {since}')
        fb = s.get('finance_busy')
        if fb:
            acts.append(FINANCE_BUSY.get(fb, 'Firefly job'))
        if s.get('tg_sync'):
            acts.append('Syncing Telegram')
        if s.get('gmail_check'):
            acts.append('Checking Gmail')
        return acts or ['Idle']

    def health(self, s):
        h = {}
        tl = s.get('tg_live') or 'disabled'
        h['TG live'] = ('off' if not s.get('tg_logged_in') else 'ok' if tl == 'running' else
                        'paused' if tl in ('disabled', 'waiting', 'starting') else 'down' if tl in
                        ('guard_blocked', 'not_authorized') else 'warn')
        h['Gmail'] = gmail_health(s.get('gmail_watch'), s.get('gmail_error'), s.get('gmail_configured'))
        h['Paperless'] = 'ok' if s.get('paperless') else 'off'
        h['Firefly'] = 'ok' if s.get('firefly') else 'off'
        llm = s.get('llm') or 'down'
        h['LLM'] = llm if llm in ('ok', 'off') else 'warn' if llm == 'starting' else 'down'
        h['Feed'] = 'warn' if s.get('events_error') else 'ok'
        return h

    def render(self, s, now=None):
        """-> (body, stamp): the message is body + '\\n' + stamp; only a body change counts as a change."""
        now = self.clock() if now is None else now
        c = self.counts()
        ev = self.day_events(now)
        h = self.health(s)
        bad = [v for v in h.values() if v == 'down']
        warn = [v for v in h.values() if v == 'warn'] or s.get('alerts')
        dot = '🔴' if bad else '🟡' if warn else '🟢'
        acts = self.activity(s, now)
        lines = [f'{dot} ' + ' · '.join(acts[:2]) + (f' (+{len(acts) - 2})' if len(acts) > 2 else ''),
                 '━━ Today ━━']
        calls = c['calls']
        n = sum(calls.values())
        kinds = [f'{k} {calls[k]}' for k in KIND_ORDER if calls.get(k)]
        lines.append(f'🤖 Claude: {n} request{"" if n == 1 else "s"}' + (f" ({' · '.join(kinds)})" if kinds else ''))
        lines.append(f"🔐 Raw: {c['raw_asked']} asked · ✅ {c['raw_ok']} · ❌ {c['raw_no']}"
                     + (f" · ⌛ {c['raw_expired']}" if c['raw_expired'] else '')
                     + (f" · 📝 text releases today: {c['text_rel']}" if c.get('text_rel') else ''))
        red = c['private'] + c['masked']
        lines.append(f'🙈 Redacted: {red}' + (f" ({c['private']} private · {c['masked']} masked)" if red else ''))
        for src, icon, label, rest in (('telegram', '💬', 'Telegram', 'chatter'), ('gmail', '✉️', 'Mail', 'other')):
            e = ev.get(src) or {}
            new, surf = int(e.get('new') or 0), int(e.get('for_claude') or 0)
            if src == 'gmail' and not s.get('gmail_configured') and not new:
                lines.append(f'{icon} {label}: not set up')
            else:
                lines.append(f'{icon} {label}: {new} new' + (f' → {surf} for Claude, {new - surf} {rest}' if new else ''))
        lines.append(f"🏦 Firefly: {c['ff_imports']} import{'' if c['ff_imports'] == 1 else 's'}"
                     + (f" (+{c['ff_tx']} tx)" if c['ff_imports'] else ''))
        lines.append('━━ Health ━━')
        items = [f'{k} {ok_icon(v)}' for k, v in h.items()]
        lines.append(' · '.join(items[:3]))
        lines.append(' · '.join(items[3:] + ([s['perf']] if s.get('perf') else [])))   # + ⏱ wait p95 · LLM busy
        accs = s.get('gmail_accounts') or []
        if len(accs) > 1:                              # several Gmail accounts: each one's health (labels only)
            lines.append('✉️ ' + ' · '.join(f"{a.get('account')} {ok_icon(gmail_health(a.get('watch'), a.get('error')))}"
                                            for a in accs))
        if s.get('alerts'):
            lines.append(f"⚠️ {s['alerts']} open alert{'' if s['alerts'] == 1 else 's'}")
        pol = str(s.get('policy') or '')
        m = re.search(r'v(\d+(?:\.\d+)?)', pol)
        d = re.search(r'(\d{4})-(\d{2})-(\d{2})', pol)
        pv = (f'v{m.group(1)}' if m else '?') + (f' ({d.group(2)}-{d.group(3)})' if d else '')
        stamp = f"🕐 {dt.datetime.fromtimestamp(now, V.TZ):%H:%M} · policy {pv}"
        body = '\n'.join(lines[:self.MAX_LINES - 1])
        return body, stamp

    # ---------------------------------------------------------------- Telegram side
    def _save(self, force=False):
        now = self.clock()
        with self._lock:
            if not force and (not self.dirty or now - self.saved_at < self.SAVE_EVERY):
                return
            data = json.dumps(self.st, indent=1)
            self.dirty, self.saved_at = False, now
        V.write_private(self.path, data)

    def _ids(self):
        return str(self.notifier.chat_id()), self.notifier.bot_id()

    def _backoff(self, e, now):
        st = getattr(e, 'status', None)
        m = re.search(r'retry after (\d+)', str(e), re.I)
        wait = int(m.group(1)) + 1 if st == 429 and m else 3600 if st == 403 else 300 if st in (401, 404) else 60
        self.backoff_until = now + min(wait, 3600)
        self.state, self.detail = 'backoff', f'Telegram error {st or "network"}; retry in {min(wait, 3600)} s'

    def _create(self, text, now):
        msg = self.st.get('msg') or {}
        if msg.get('created') and now - msg['created'] < self.RECREATE_GAP and msg.get('chat') == self._ids()[0]:
            self.state, self.detail = 'backoff', 'not re-creating twice within 2 min'
            self.backoff_until = now + self.RECREATE_GAP - (now - msg['created'])
            return 'backoff'
        mid, date = self.notifier.send_silent(text)
        chat, bot = self._ids()
        with self._lock:
            self.st['msg'] = {'id': mid, 'date': date or int(now), 'chat': chat, 'bot': bot, 'created': now,
                              'last_edit': now, 'body': None, 'pinned': False}
            self.dirty = True
        self.log(f'status board: new status message sent ({"re-created" if msg else "first"})')
        self._pin(now)
        return 'created'

    def _pin(self, now):
        m = self.st['msg']
        try:
            self.notifier.pin(m['id'])
            m['pinned'], m['pin_checked'] = True, now
            self.state, self.detail = 'pinned', ''
        except V.NotifyError as e:
            m['pinned'] = False
            self.state, self.detail = 'unpinned', f'pin failed: {str(e)[:120]}'
            self.log(f'status board: pin failed ({getattr(e, "status", None)})')
            if getattr(e, 'status', None) == 400 and 'not found' in str(e).lower():
                m['gone'] = True                     # deleted: the next step sends a new one
        self.dirty = True

    def _check_pin(self, now):
        """getChat -> the most recent pinned message by sending date. Not ours and older than ours (or none):
        ours was unpinned -> pin it again. Newer than ours: the owner pinned something himself; leave it."""
        m = self.st['msg']
        m['pin_checked'] = now
        try:
            p = self.notifier.pinned()
        except V.NotifyError as e:
            self.log(f'status board: pin check failed ({getattr(e, "status", None)})')
            return
        if p and p[0] == m['id']:
            m['pinned'], self.state, self.detail = True, 'pinned', ''
        elif p is None or int(p[1] or 0) <= int(m.get('date') or 0):
            self.log('status board: status message was unpinned; pinning it again')
            self._pin(now)
        else:
            m['pinned'], self.state, self.detail = False, 'unpinned', 'the owner pinned a newer message'
        self.dirty = True

    def step(self, now=None):
        """One check. -> what happened: off | backoff | created | edited | unchanged | throttled."""
        now = self.clock() if now is None else now
        on, why = self.enabled()
        if not on:
            self.state, self.detail = 'off', why
            self._save()
            return 'off'
        if self.state == 'off':                       # back on (e.g. the vault bot polls now): no stale 'off'
            self.state, self.detail = ('pinned' if (self.st.get('msg') or {}).get('pinned') else 'starting'), ''
        forced, self.forced = self.forced, False
        if now < self.backoff_until and not forced:
            self._save()
            return 'backoff'
        s = self.snapshot()
        body, stamp = self.render(s, now)
        text = f'{body}\n{stamp}'
        m = self.st.get('msg')
        try:
            if not m or not m.get('id') or m.get('gone') or (m.get('chat'), m.get('bot')) != self._ids():
                res = self._create(text, now)
                if res == 'created':
                    with self._lock:
                        self.st['msg']['body'] = body
                        self._roll()['edits'] += 1
                self._save(force=True)
                return res
            since = now - float(m.get('last_edit') or 0)
            due = since >= self.REFRESH
            changed = body != m.get('body')
            if forced and since >= self.MIN_FORCED or due or changed and since >= self.MIN_EDIT:
                try:
                    self.notifier.edit(m['id'], text)
                except V.NotifyError as e:
                    if getattr(e, 'status', None) == 400 and 'not modified' in str(e).lower():
                        pass
                    elif getattr(e, 'status', None) == 400:
                        self.log('status board: edit failed (message deleted?); sending a new one')
                        m['gone'] = True
                        res = self._create(text, now)
                        if res == 'created':
                            self.st['msg']['body'] = body
                        self._save(force=True)
                        return res
                    else:
                        raise
                with self._lock:
                    m.update(last_edit=now, body=body)
                    self._roll()['edits'] += 1
                    self.dirty = True
                if forced or due or now - float(m.get('pin_checked') or 0) >= self.REFRESH:
                    self._check_pin(now)
                if self.state in ('starting', 'backoff', 'error'):
                    self.state, self.detail = ('pinned', '') if m.get('pinned') else ('unpinned', self.detail)
                self._save()
                return 'edited'
            self._save()
            return 'unchanged' if not changed else 'throttled'
        except V.NotifyError as e:
            self._backoff(e, now)
            self.log(f'status board: {self.detail}')
            self._save(force=True)
            return 'backoff'
        except V.VaultError as e:                    # no telegram secret (yet)
            self.state, self.detail = 'off', str(e)[:120]
            return 'off'

    def run(self, stop_ev):
        stop_ev.wait(10)                             # let the approval bot do its first poll
        while not stop_ev.is_set():
            try:
                self.step()
            except Exception as e:
                self.state, self.detail = 'error', type(e).__name__
                self.log(f'status board: {type(e).__name__}')
            self.wake.wait(self.TICK)
            self.wake.clear()
        self._save(force=True)

    def status(self):
        """For GET /status (and `vault status`): the board's state, never its text."""
        m = self.st.get('msg') or {}
        iso = lambda t: V.now_iso(t) if t else None     # noqa: E731
        return {'state': self.state, 'detail': self.detail or None, 'message': bool(m.get('id')),
                'pinned': bool(m.get('pinned')), 'created_at': iso(m.get('created')),
                'last_edit': iso(m.get('last_edit')), 'pin_checked': iso(m.get('pin_checked')),
                'edits_today': self.counts().get('edits', 0)}
