"""Follow-up ask sessions (vault memory plan C1, 2026-10-15): `vault ask tg --chat Anna "is the party on Saturday?"
--session`, then `vault ask --session s-7k2q "and where?"` over the same messages, with no re-explaining and no new
search.

Memory only, nothing on disk. Per session the vault keeps the scope (source; chat or query, since, n; or one mail's
ref/folder/account), the refs of the messages the first answer read (so follow-ups read the same messages) and the
previous turns as {question, kind, checked answer}. All of these already left the vault, so nothing new is held.
Limits: 15 min idle, 60 min hard cap, 6 turns (the opening ask is turn 1), 20 sessions (LRU). A session is bound to
the caller's token hash and dropped on a vault restart, on `tg purge|exclude|wipe` and on `end`.

A follow-up is the unchanged kind pipeline over the same parts (anonymization is cached, so it costs the answer call):
its question is composed in code from the earlier turns' checked values (`Earlier: «q1» → yes, 2026-10-24. Now:
«and where?»`, at most 300 chars). Its kind is --kind, else a keyword map (wann/when/kada/wo/where/gdje -> when,
wer/wem/who/ko/kim -> who (first names + flagged nicknames), wie viele/how many/koliko -> count,
ob/stimmt/da li or a leading is/ist -> yesno, else short); a who question never runs as short. The scope is fixed: another
chat, search or mail needs a new ask (no drift across chats).
Switch: env VAULT_ASK_SESSIONS=1 (default off: --session answers 409 sessions_off)."""
import hashlib
import re
import secrets
import threading
import time
from collections import OrderedDict

import vaultlib as V
from vaultlib import VaultError

IDLE_S = 15 * 60
CAP_S = 60 * 60
MAX_TURNS = 6
MAX_SESSIONS = 20
Q_MAX = 300
FOLLOWUP_KINDS = ('yesno', 'when', 'who', 'deadline', 'actionable', 'requests', 'count', 'short', 'interests')
ID_RE = re.compile(r's-[a-z0-9]{6,16}')
_ALPHA = 'abcdefghijkmnpqrstuvwxyz23456789'
_W = r'(?<![^\W_])'                                    # a word start (also after punctuation and «)
WHO_RE = re.compile(_W + r'(?:wer|wem|wen|who|whom|whose|ko|tko|kim)(?![^\W_])', re.I)
KIND_MAP = (
    ('when', re.compile(_W + r'(?:wann|when|kada|um\s+wie\s*viel|wo|wohin|woher|where|gdje)(?![^\W_])', re.I)),
    ('who', WHO_RE),                                   # a names list, never free text
    ('count', re.compile(_W + r'(?:wie\s*viele?|wie\s+oft|how\s+many|how\s+often|koliko)(?![^\W_])', re.I)),
    ('yesno', re.compile(_W + r'(?:ob|stimmt|da\s+li)(?![^\W_])|^\W*(?:(?:and|und|also|but|aber|i|a)\s+)?'
                         r'(?:is|are|does|do|did|will|can|ist|sind|je\s+li)(?![^\W_])', re.I)),
)


def sha8(sid):
    return hashlib.sha256(str(sid).encode()).hexdigest()[:8]


def is_who(q):
    """A who/wer question: it gets the names list (kind who), never short's free text."""
    return bool(WHO_RE.search(q or ''))


def followup_kind(q):
    for kind, rx in KIND_MAP:
        if rx.search(q or ''):
            return kind
    return 'short'


def render_value(v, key=None):
    """A checked answer -> a short line of its values (code-rendered; refs and empty fields left out)."""
    if v is None or v == '' or v == [] or v == {}:
        return ''
    if isinstance(v, bool):
        return f"{key or 'answer'}: {'yes' if v else 'no'}"
    if isinstance(v, (int, float)):
        return f'{key}: {v}' if key and key != 'answer' else str(v)
    if isinstance(v, str):
        return ' '.join(v.split())
    if isinstance(v, list):
        return ' + '.join(x for x in (render_value(i) for i in v[:5]) if x)
    if isinstance(v, dict):
        return ', '.join(x for x in (render_value(x, k) for k, x in v.items()
                                     if k not in ('refs', 'ref', 'note', 'attachments', 'cached')) if x)
    return ''


def compose(turns, q):
    """Earlier turns' checked values + the follow-up -> one question of at most Q_MAX chars (newest turns first in,
    then put back in order)."""
    now = f'Now: «{q}»'
    if len(now) > Q_MAX:
        return q[:Q_MAX]
    room, parts = Q_MAX - len(now) - 1, []
    for t in reversed(turns):
        tq = ' '.join(str(t.get('q') or 'the card').split())[:80]
        vals = render_value(t.get('answer'))[:100] or 'no answer'
        s = f'Earlier: «{tq}» → {vals}.'
        if len(s) + 1 > room:
            break
        parts.insert(0, s)
        room -= len(s) + 1
    return ' '.join(parts + [now])


class Session:
    __slots__ = ('id', 'owner', 'scope', 'refs', 'turns', 'created', 'last', 'busy')

    def __init__(self, sid, owner, scope, refs, created):
        self.id, self.owner, self.scope, self.refs = sid, owner, dict(scope), list(refs)
        self.turns, self.created, self.last, self.busy = [], created, created, False

    def expires(self):
        return min(self.last + IDLE_S, self.created + CAP_S)

    def info(self):
        return {'id': self.id, 'expires': V.now_iso(self.expires()), 'turns_left': MAX_TURNS - len(self.turns)}


class Sessions:
    def __init__(self, audit, enabled=False, clock=time.time):
        self.audit, self.enabled, self.clock = audit, enabled, clock
        self._s = OrderedDict()
        self._lock = threading.Lock()

    def check_on(self):
        if not self.enabled:
            raise VaultError('follow-up sessions are off in this vault (VAULT_ASK_SESSIONS); ask without --session',
                             409, 'sessions_off')

    def _log(self, action, s, **kw):
        self.audit.log('answer_session', action=action, session=sha8(s.id), turns=len(s.turns), **kw)

    def _expire(self, now):
        for sid in [k for k, s in self._s.items() if now >= s.expires() and not s.busy]:
            self._log('expired', self._s.pop(sid))

    @staticmethod
    def new_id():
        return 's-' + ''.join(secrets.choice(_ALPHA) for _ in range(8))

    def open(self, owner, scope, refs, q, kind, answer, sid=None):
        """The opening ask (turn 1) -> the session's info."""
        self.check_on()
        now = self.clock()
        with self._lock:
            self._expire(now)
            while len(self._s) >= MAX_SESSIONS:         # LRU: the least recently used goes
                old = next((k for k, s in self._s.items() if not s.busy), None)
                if old is None:
                    raise VaultError('too many follow-up sessions in use; end one or wait', 429, 'busy')
                self._log('expired', self._s.pop(old), why='lru')
            sid = sid or self.new_id()
            s = Session(sid, owner, scope, refs, now)
            s.turns.append({'q': q, 'kind': kind, 'answer': answer})
            self._s[sid] = s
            self._log('open', s, source=scope.get('source'))
            return s.info()

    def begin(self, owner, sid):
        """A follow-up starts: the live session of this caller, marked busy (one turn at a time)."""
        self.check_on()
        if not (isinstance(sid, str) and ID_RE.fullmatch(sid)):
            raise VaultError('session: an id like s-7k2qab4m from an earlier ask with --session', 400, 'bad_param')
        now = self.clock()
        with self._lock:
            self._expire(now)
            s = self._s.get(sid)
            if s is None or s.owner != owner:           # another caller's session looks the same as none
                raise VaultError('no such follow-up session (expired after 15 min idle or 60 min, ended, or dropped '
                                 'by a purge or restart); ask again with --session', 410, 'session_gone')
            if s.busy:
                raise VaultError('this session is answering a follow-up already; wait for it', 409, 'session_busy')
            s.busy = True
            self._s.move_to_end(sid)
            return s

    def finish(self, s, q, kind, answer):
        """A follow-up answered -> the session's info (dropped once its turns are used up)."""
        with self._lock:
            s.busy = False
            s.last = self.clock()
            s.turns.append({'q': q, 'kind': kind, 'answer': answer})
            self._log('followup', s, kind=kind)
            info = s.info()
            if info['turns_left'] <= 0 and self._s.get(s.id) is s:
                self._log('expired', self._s.pop(s.id), why='turns')
            return info

    def release(self, s):
        """A follow-up failed: the session stays as it was."""
        with self._lock:
            s.busy = False
            s.last = self.clock()

    def end(self, owner, sid):
        self.check_on()
        with self._lock:
            s = self._s.get(sid) if isinstance(sid, str) else None
            if s is None or s.owner != owner:
                return {'session': {'id': sid, 'ended': False, 'note': 'no such session (already gone)'}}
            self._s.pop(sid)
            self._log('end', s)
            return {'session': {'id': sid, 'ended': True, 'turns': len(s.turns)}}

    def drop_all(self, reason='purged'):
        """tg purge / exclude / wipe: every session goes (its refs may point at purged messages)."""
        with self._lock:
            gone = list(self._s.values())
            self._s.clear()
        for s in gone:
            self._log(reason, s)
        return len(gone)

    def count(self):
        with self._lock:
            return len(self._s)
