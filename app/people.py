"""Person cards v1 (vault memory plan C2, 2026-10-15): metadata only. Switch: env VAULT_PEOPLE=1 (default off: every
/people route answers 409 people_off and nothing is built or stored).

A card per Telegram DM contact with at least 10 messages in the last 12 months, not a bot, not him (decision D3):
person (his chat alias, else the first name: the first word; an honorific + surname is "someone"), key
(p- + a keyed HMAC of the Telegram user id; the id itself never leaves the vault and is not stored here), relation
(only the owner, D1), dm, dm_since (month), groups_shared (count), last_contact {from_them, from_owner} (dates) and
messages {30d, 90d, 365d: {in, out}} (counts). Lists show at most 20 cards (D3). No Gmail (D2).

Derived, not accumulated: the cards are rebuilt from tgread's vault-internal `people-stats` (SQL counts, no text)
every night at 03:00 and after `tg purge|exclude add` (dropped at once, rebuilt on the next read or tick), so a
card disappears when its person leaves the scope. Only his relations and "forget" entries persist
(/data/state/people.db, 0600, secure_delete). There is no notes field, no LLM and no text: every value is an enum,
a date, a count, a first name or a pseudonym (plan §5.3). Cards are output only: never fed into answer, triage or
facts prompts (plan §7).

Relation (D1): never inferred from message content. Either his tap in the vault bot (`vault people relation NAME`
asks "Who is Anna to you?" with `p:` buttons, at most 5 questions a day, the buttons work 7 days), or my relay of
his own words (`vault people relation NAME VALUE`), which the vault bot confirms to him with a silent line and an
Undo button. Both go through the vault bot, so both sit behind a second switch: VAULT_PEOPLE_ASK=1 (default off:
409 relation_ask_off). Forget: the card and its relation are deleted and kept off (only the pseudonym is kept);
unforget lets the person back at the next build. `tg wipe --data|--all` deletes people.db.

C5 (2026-10-15, switch VAULT_PEOPLE_ASKS=1): cards also carry open_asks (app/asks.py: from them = the event feed's
triage rows by Telegram user id; from him = a nightly owner-perspective triage of his own DM messages; open -> replied
-> expired after 21 days or due + 7) and topics_90d (app/topics.py: the index's DM chunks against calibrated topic
prototypes, code only; private/other never shown). Still enums, dates, counts and refs only; still output only. A
night worker (01:00-06:30) runs the outgoing triage and, when needed, the topic calibration at background priority;
cards are refreshed at most hourly on read so that statuses follow new messages."""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time

import answer as AN
import asks as AK
import topics as TP
import vaultlib as V
from vaultlib import VaultError

RELATIONS = ('family', 'partner', 'friend', 'colleague', 'work', 'service', 'acquaintance', 'other')
CODES = {'fa': 'family', 'pa': 'partner', 'fr': 'friend', 'co': 'colleague', 'wo': 'work', 'se': 'service',
         'ac': 'acquaintance', 'ot': 'other'}
CODE_OF = {v: k for k, v in CODES.items()}
LABELS = {'family': '👪 Family', 'partner': '❤️ Partner', 'friend': '🤝 Friend', 'colleague': '💼 Colleague',
          'work': '🏢 Work', 'service': '🔧 Service', 'acquaintance': '👋 Acquaintance', 'other': '❔ Other'}
MIN_MSGS, DAYS = 10, 365                                # D3: DM contacts with >= 10 messages in 12 months
MAX_SHOW = 20                                           # D3: I see at most 20 cards at a time
ASKS_PER_DAY = 20                                       # relation questions in the vault bot a day (more than 5;
#                                                        env VAULT_PEOPLE_ASKS_PER_DAY)
ASK_DAYS = 7                                            # a question's (or an Undo's) buttons work this long
BUILD_HOUR = 3                                          # nightly rebuild at 03:00 Zurich
KEY_RE = re.compile(r'p-[0-9a-f]{8}')
CB_RE = re.compile(r'p:([a-z0-9]{8}):([0-9a-f]{8}):([a-z]{2})')
ACTIVE_RE = re.compile(r'([1-9]\d{0,3})d')
NOTE = 'derived from Telegram metadata (counts and dates) and the owner\'s own relation taps; never message text'
NOTE2 = ('derived from Telegram metadata, the owner\'s relation taps, checked triage enums (open asks) and topic '
         'classes of the semantic index; never message text')
REFRESH_S = 3600                                        # C5: cards older than this are rebuilt on read
REFRESH_WHAT = ('asks', 'topics', 'calibrate')
_ALPHA = 'abcdefghijkmnpqrstuvwxyz23456789'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS cards (key TEXT PRIMARY KEY, person TEXT NOT NULL, dm_since INTEGER,
  groups_shared INTEGER NOT NULL DEFAULT 0, last_in INTEGER, last_out INTEGER,
  in30 INTEGER NOT NULL DEFAULT 0, out30 INTEGER NOT NULL DEFAULT 0, in90 INTEGER NOT NULL DEFAULT 0,
  out90 INTEGER NOT NULL DEFAULT 0, in365 INTEGER NOT NULL DEFAULT 0, out365 INTEGER NOT NULL DEFAULT 0,
  built REAL NOT NULL);
CREATE TABLE IF NOT EXISTS relations (key TEXT PRIMARY KEY, value TEXT NOT NULL, by TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS forgotten (key TEXT PRIMARY KEY, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS asks (qid TEXT PRIMARY KEY, key TEXT NOT NULL, nonce TEXT NOT NULL, kind TEXT NOT NULL,
  msg_id INTEGER NOT NULL DEFAULT 0, sent REAL NOT NULL, state TEXT NOT NULL, value TEXT, prev TEXT);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
'''


def day(ts):
    return dt.datetime.fromtimestamp(ts, V.TZ).date().isoformat() if ts else None


def month(ts):
    return dt.datetime.fromtimestamp(ts, V.TZ).strftime('%Y-%m') if ts else None


def display(uid, name, aliases):
    """His alias for the DM chat wins; else the first name (answer.first_name: an honorific + surname -> someone)."""
    a = (aliases or {}).get(str(uid))
    if a:
        return a
    n = AN.first_name(name)
    return 'someone' if n in ('?', '') else n


class People:
    def __init__(self, cfg, tg, notifier, audit, key, net=None, aliases=None, clock=time.time, log=print):
        self.cfg, self.tg, self.notifier, self.audit, self.clock, self.log = cfg, tg, notifier, audit, clock, log
        self.enabled, self.ask_on = bool(cfg.people), bool(cfg.people_ask)
        self.asks_per_day = int(getattr(cfg, 'people_asks_per_day', ASKS_PER_DAY) or ASKS_PER_DAY)
        self.key = key if isinstance(key, bytes) else str(key).encode()
        self.net = net or (lambda s: s)
        self.aliases = aliases or (lambda: {})
        self.path = cfg.state / 'people.db'
        self.dirty, self.error = False, ''
        self._db = None
        self._lock = threading.RLock()
        # C5: open asks + topics (VAULT_PEOPLE_ASKS); events/index/policy/gate are wired by vaultd (wire_v2)
        self.v2 = self.enabled and bool(getattr(cfg, 'people_v2', False))
        self.asks = AK.Asks(self, clock=clock, log=log)
        self.topics = TP.Topics(self, clock=clock, log=log)
        self.v2_error, self.night = '', {'state': 'idle'}
        self._night_thread, self._night_retry = None, 0.0
        self._open, self._scope = None, {}

    def wire_v2(self, events=None, index=None, policy=None, gate=None, model=''):
        self.asks.events, self.asks.policy, self.asks.gate = events, policy, gate
        self.asks.model = (model or "local").rsplit("/", 1)[-1].split("-it")[0][:40]
        self.topics.index, self.topics.policy, self.topics.gate = index, policy, gate

    # ---------------------------------------------------------------- store
    def check_on(self):
        if not self.enabled:
            raise VaultError('person cards are off in this vault (VAULT_PEOPLE)', 409, 'people_off')

    def db(self):
        with self._lock:
            if self._db is None:
                V.ensure_dir(self.path.parent)
                db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
                db.row_factory = sqlite3.Row
                db.execute('PRAGMA secure_delete=ON')
                db.executescript(SCHEMA)
                db.executescript(AK.SCHEMA)
                db.commit()
                for p in (self.path, self.path.with_name(self.path.name + '-journal')):
                    try:
                        os.chmod(p, 0o600)
                    except OSError:
                        pass
                self._db = db
            return self._db

    def meta(self, k):
        r = self.db().execute('SELECT v FROM meta WHERE k=?', (k,)).fetchone()
        return r[0] if r else None

    def pkey(self, uid):
        return 'p-' + hmac.new(self.key, f'tg-person:{int(uid)}'.encode(), hashlib.sha256).hexdigest()[:8]

    # ---------------------------------------------------------------- build (nightly, after purges, on demand)
    def build(self, reason='nightly'):
        self.check_on()
        t0 = self.clock()
        stats = self.tg.people_stats(MIN_MSGS, DAYS)
        try:
            aliases = self.aliases() or {}
        except Exception:
            aliases = {}
        with self._lock:
            db = self.db()
            forgotten = {r[0] for r in db.execute('SELECT key FROM forgotten')}
            old = {r[0] for r in db.execute('SELECT key FROM cards')}
            rows, now = {}, self.clock()
            for p in stats.get('people') or []:
                if not isinstance(p, dict) or not isinstance(p.get('uid'), int):
                    continue
                k = self.pkey(p['uid'])
                if k in forgotten:
                    continue
                n = lambda f: max(0, int(p.get(f) or 0))                     # noqa: E731
                rows[k] = (k, display(p['uid'], p.get('name'), aliases)[:40], p.get('first_ts'), n('groups_shared'),
                           p.get('last_in'), p.get('last_out'), n('in30'), n('out30'), n('in90'), n('out90'),
                           n('in365'), n('out365'), now)
            db.execute('DELETE FROM cards')
            db.executemany('INSERT INTO cards VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', list(rows.values()))
            exp = db.execute("UPDATE asks SET state='expired' WHERE state='open' AND sent < ?",
                             (now - ASK_DAYS * 86400,)).rowcount
            db.execute("INSERT INTO meta VALUES ('built', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(now),))
            db.commit()
            self.dirty, self.error = False, ''
        out = {'cards': len(rows), 'new': len(set(rows) - old), 'dropped': len(old - set(rows)),
               'asks_expired': exp, 'seconds': round(self.clock() - t0, 2)}
        if self.v2:
            out.update(self._build_v2(stats, rows))
            out['seconds'] = round(self.clock() - t0, 2)
        self.audit.log('people_build', reason=reason, **out)
        return out

    def _build_v2(self, stats, rows):
        """C5 after the metadata cards: feed asks -> statuses/expiry/scope -> chunk topics (code) -> person topics.
        A failure here never costs the v1 cards (v2_error says which step)."""
        keys, last = {}, {}
        for p in stats.get('people') or []:
            if isinstance(p, dict) and isinstance(p.get('uid'), int):
                k = self.pkey(p['uid'])
                if k in rows:
                    keys[k] = p['uid']
                    last[k] = (p.get('last_in'), p.get('last_out'))
        self._scope = keys
        out, step = {}, 'harvest'
        try:
            out.update(self.asks.harvest(keys))
            step = 'refresh'
            out.update(self.asks.refresh(last))
            step = 'topics'
            if self.topics.index is not None:
                out['chunks_labelled'] = self.topics.label_pending()
                top = self.topics.person_topics(list(keys.values()))
                with self._lock:
                    db = self.db()
                    db.execute('DELETE FROM person_topics')
                    db.executemany('INSERT INTO person_topics VALUES (?, ?, ?)',
                                   [(k, x['topic'], x['n']) for k, uid in keys.items() for x in top.get(uid, [])])
                    db.commit()
                out['topics_people'] = sum(1 for uid in keys.values() if top.get(uid))
            self.v2_error = ''
        except Exception as e:
            self.v2_error = f'{step}: {type(e).__name__}'
            self.log(f'people v2 build ({step}) failed: {type(e).__name__}')
        return out

    def built_at(self):
        v = self.meta('built')
        return float(v) if v else None

    def ensure_built(self):
        b = self.built_at()
        if self.dirty or b is None or (self.v2 and self.clock() - b > REFRESH_S):
            self.build('on_demand')

    def tick(self, now=None):
        """Once a minute (vaultd ticker): the nightly rebuild at 03:00 Zurich, a first build, a rebuild after a
        purge. Needs the Telegram archive (logged in)."""
        if not self.enabled:
            return
        now = self.clock() if now is None else now
        local = dt.datetime.fromtimestamp(now, V.TZ)
        cut = local.replace(hour=BUILD_HOUR, minute=0, second=0, microsecond=0).timestamp()
        built = self.built_at()
        why = ('first' if built is None else 'purge' if self.dirty
               else 'nightly' if now >= cut > built else None)
        if not self.tg.logged_in():
            return
        if why:
            try:
                self.build(why)
            except Exception as e:
                self.error = f'{type(e).__name__}'
                self.log(f'people build failed: {self.error}')
        if self.v2:
            self._night_tick(now)

    # ---------------------------------------------------------------- C5: the night worker
    def _night_tick(self, now):
        """01:00-06:30 Zurich, once a night: his DM messages' triage (backlog first), then a topic calibration if
        none fits the running embed model. Its own thread; every LLM call at background priority (live asks first)."""
        if not AK.in_night(now) or now < self._night_retry:
            return
        if self._night_thread is not None and self._night_thread.is_alive():
            return
        day = dt.datetime.fromtimestamp(now, V.TZ).date().isoformat()
        if self.meta('night_done') == day:
            return
        self._night_thread = threading.Thread(target=self.night_pass, args=(day,), daemon=True, name='people-night')
        self._night_thread.start()

    def night_pass(self, day):
        deadline = AK.night_end(self.clock())
        self.night = {'state': 'running', 'started': V.now_iso(self.clock())}
        out = {}
        try:
            self.build('night')
            keys = dict(getattr(self, '_scope', {}) or {})
            names = self._names(keys)
            self.night['step'] = 'dm-out triage'
            out['asks'] = self.asks.scan_out(keys, names, deadline=deadline)
            if (self.topics.state() in ('uncalibrated', 'model_changed') and self.meta('cal_tried') != day
                    and self.clock() < deadline - 3600):
                self._set_meta('cal_tried', day)
                self.night['step'] = 'topics calibration'
                try:
                    out['topics'] = {k: v for k, v in self.topics.calibrate(deadline=deadline - 600).items()
                                     if k in ('n_labelled', 'applied', 'chosen', 'gate', 'seconds')}
                except VaultError as e:
                    out['topics'] = {'error': e.code}
            self.build('night')
            self._set_meta('night_done', day)
            self.night = {'state': 'done', 'at': V.now_iso(self.clock()), 'asks': out.get('asks'),
                          'topics': out.get('topics')}
        except Exception as e:
            self._night_retry = self.clock() + 900
            self.night = {'state': 'failed', 'at': V.now_iso(self.clock()), 'error': type(e).__name__}
            self.log(f'people night pass failed: {type(e).__name__}')

    def _set_meta(self, k, v):
        with self._lock:
            db = self.db()
            db.execute('INSERT INTO meta VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', (k, str(v)))
            db.commit()

    def _names(self, keys):
        """{uid: card name} (the triage prompt's "[to: name]"; vault-internal)."""
        with self._lock:
            names = {r['key']: r['person'] for r in self.db().execute('SELECT key, person FROM cards')}
        return {uid: names.get(k, 'someone') for k, uid in keys.items()}

    def refresh(self, b, report=None):
        """POST /people/refresh {what: asks|topics|calibrate, sample, dry, force} (async job op people.refresh).
        asks: feed asks + statuses now; with sample N (<= 30) a dry run of the owner-perspective triage over his newest
        messages (numbers only, nothing stored). topics: chunk labels + person topics now (code only). calibrate: the
        topic calibration (numbers only); by day only as a dry run with sample <= 40 unless force."""
        self.check_on()
        if not self.v2:
            raise VaultError('open asks and topics are off in this vault (VAULT_PEOPLE_ASKS)', 409, 'people_v2_off')
        what = (b or {}).get('what')
        if what not in REFRESH_WHAT:
            raise VaultError(f'what: one of {", ".join(REFRESH_WHAT)}', 400, 'bad_param')
        sample, dry, force = b.get('sample'), bool(b.get('dry')), bool(b.get('force'))
        if sample is not None and not (isinstance(sample, int) and not isinstance(sample, bool) and 1 <= sample <= 600):
            raise VaultError('sample: 1..600', 400, 'bad_param')
        if what == 'asks':
            if sample is not None and sample > AK.OUT_BATCH:
                raise VaultError(f'sample: at most {AK.OUT_BATCH} for asks', 400, 'bad_param')
            r = self.build('refresh')
            out = {k: r.get(k) for k in ('cards', 'feed_new', 'feed_capped', 'asks_replied', 'asks_expired',
                                         'asks_dropped')}
            if sample:
                keys = dict(getattr(self, '_scope', {}) or {})
                out['dry_run'] = self.asks.scan_out(keys, self._names(keys), sample=sample, report=report)
            return out
        if what == 'topics':
            r = self.build('refresh')
            return {'state': self.topics.state(), 'chunks_labelled': r.get('chunks_labelled'),
                    'topics_people': r.get('topics_people')}
        night = AK.in_night(self.clock())
        if not (night or force or (dry and (sample or TP.CAL_N) <= 40)):
            raise VaultError('a full calibration runs at night (the night worker); by day only a dry run with sample '
                             '<= 40, or force', 409, 'night_only')
        res = self.topics.calibrate(sample=sample or TP.CAL_N, apply=not dry, report=report)
        if res.get('applied'):
            self.build('calibrated')
        return res

    def on_purge(self, cmd, params):
        """tg purge | exclude add: the derived cards go at once (rebuilt without that chat on the next read or
        tick). tg wipe --data|--all: people.db goes entirely (relations and forget entries too)."""
        if not self.enabled:
            return
        p = params or {}
        if cmd == 'wipe' and not (p.get('data') or p.get('all')):
            return
        with self._lock:
            if cmd == 'wipe':
                if self._db is not None:
                    self._db.close()
                    self._db = None
                for f in (self.path, self.path.with_name(self.path.name + '-journal')):
                    try:
                        f.unlink()
                    except FileNotFoundError:
                        pass
                self.dirty = False
            else:
                db = self.db()
                db.execute('DELETE FROM cards')
                db.execute('DELETE FROM person_topics')     # C5: rebuilt; the purged chat's asks go at the next build
                db.commit()
                self.dirty = True
                self.topics.drop_centroids()                # C5: a blend's centroids may hold the purged chat
        self.audit.log('people_purge', cmd=cmd)

    # ---------------------------------------------------------------- cards
    def _rel(self, key):
        r = self.db().execute('SELECT value, by, at FROM relations WHERE key=?', (key,)).fetchone()
        return {'value': r['value'], 'by': r['by'], 'at': day(r['at'])} if r else None

    def card(self, r, full=True):
        c = {'person': self.net(r['person']), 'key': r['key'], 'relation': self._rel(r['key']),
             'last_contact': {'from_them': day(r['last_in']), 'from_owner': day(r['last_out'])}}
        if not full:
            c['messages_30d'] = {'in': r['in30'], 'out': r['out30']}
            if self.v2:
                c['open_asks'] = (self._open or {}).get(r['key'], 0)
                c['topics'] = [x['topic'] for x in self._topics(r['key'])]
            return c
        c.update(dm=True, dm_since=month(r['dm_since']), groups_shared=r['groups_shared'],
                 messages={'30d': {'in': r['in30'], 'out': r['out30']}, '90d': {'in': r['in90'], 'out': r['out90']},
                           '365d': {'in': r['in365'], 'out': r['out365']}},
                 built=V.now_iso(r['built']), note=NOTE)
        if self.v2:
            asks, n = self.asks.for_card(r['key'])
            c.update(open_asks=asks, open_asks_total=n, topics_90d=self._topics(r['key']),
                     topics_status=self.topics.state(), note=NOTE2)
        return c

    def _topics(self, key):
        return [{'topic': t, 'n': n} for t, n in self.db().execute(
            'SELECT topic, n FROM person_topics WHERE key=? ORDER BY n DESC, topic', (key,)) if t in TP.SHOWN][:TP.TOP]

    def list(self, active=None, n=MAX_SHOW, relation=None, asks=False):
        self.check_on()
        self._open = None
        if active is not None and not (isinstance(active, str) and ACTIVE_RE.fullmatch(active)):
            raise VaultError('active: days like 90d (1..9999)', 400, 'bad_param')
        if not (isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= MAX_SHOW):
            raise VaultError(f'n must be 1..{MAX_SHOW}', 400, 'bad_param')
        if relation is not None and relation not in RELATIONS + ('unset', 'set'):
            raise VaultError(f'relation: one of {", ".join(RELATIONS)}, set or unset', 400, 'bad_param')
        self.ensure_built()
        with self._lock:
            db = self.db()
            rows = db.execute('SELECT * FROM cards ORDER BY MAX(COALESCE(last_in, 0), COALESCE(last_out, 0)) DESC, '
                              'in365 + out365 DESC').fetchall()
            rels = {r['key']: r['value'] for r in db.execute('SELECT key, value FROM relations')}
            total = len(rows)
            if active:
                cut = self.clock() - int(active[:-1]) * 86400
                rows = [r for r in rows if max(r['last_in'] or 0, r['last_out'] or 0) >= cut]
            if relation == 'unset':
                rows = [r for r in rows if r['key'] not in rels]
            elif relation == 'set':
                rows = [r for r in rows if r['key'] in rels]
            elif relation:
                rows = [r for r in rows if rels.get(r['key']) == relation]
            if self.v2:
                self._open = self.asks.open_counts()
                if asks:
                    rows = [r for r in rows if self._open.get(r['key'])]
            cards = [self.card(r, full=False) for r in rows[:n]]
        self.audit.log('people_list', count=len(cards), total=total,
                       fields=['person', 'key', 'relation', 'last_contact', 'messages_30d']
                       + (['open_asks', 'topics'] if self.v2 else []))
        return {'cards': cards, 'shown': len(cards), 'matching': len(rows), 'total': total,
                'built': V.now_iso(self.built_at()) if self.built_at() else None,
                'scope': {'source': 'telegram DMs', 'min_messages': MIN_MSGS, 'days': DAYS, 'max_shown': MAX_SHOW},
                'note': NOTE2 if self.v2 else NOTE}

    def find(self, person):
        """NAME (the card's person, case-insensitive) or KEY -> the card row; 404 none, 409 several."""
        if not (isinstance(person, str) and 0 < len(person.strip()) <= 64 and not V._CTRL.search(person)):
            raise VaultError('person: a name or a key (p-xxxxxxxx), at most 64 characters', 400, 'bad_param')
        p = ' '.join(person.split())
        db = self.db()
        if KEY_RE.fullmatch(p):
            rows = db.execute('SELECT * FROM cards WHERE key=?', (p,)).fetchall()
        else:
            rows = [r for r in db.execute('SELECT * FROM cards') if r['person'].casefold() == p.casefold()]
        if not rows:
            raise VaultError('no card for that person (cards: Telegram DM contacts with at least 10 messages in 12 '
                             'months; `vault people` lists them)', 404, 'not_found')
        if len(rows) > 1:
            raise VaultError(f'{len(rows)} cards match; use the key: ' + ', '.join(r['key'] for r in rows[:5]), 409,
                             'ambiguous')
        return rows[0]

    def show(self, person):
        self.check_on()
        self.ensure_built()
        with self._lock:
            c = self.card(self.find(person))
        self.audit.log('people_show', person=c['key'], fields=sorted(c))
        return {'card': c}

    # ---------------------------------------------------------------- relation (D1: only the owner)
    def check_ask(self):
        if not self.ask_on:
            raise VaultError('relation questions and relays in the vault bot are off (VAULT_PEOPLE_ASK); cards work '
                             'without a relation', 409, 'relation_ask_off')

    def _set_rel(self, db, key, value, by):
        if value is None:
            db.execute('DELETE FROM relations WHERE key=?', (key,))
        else:
            db.execute('INSERT INTO relations VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, '
                       'by=excluded.by, at=excluded.at', (key, value, by, self.clock()))

    def relation(self, person, value=None):
        self.check_on()
        self.check_ask()
        if value is not None and value not in RELATIONS + ('unset',):
            raise VaultError(f'relation: one of {", ".join(RELATIONS)} or unset', 400, 'bad_param')
        self.ensure_built()
        with self._lock:
            r = self.find(person)
            return self.ask(r) if value is None else self.relay(r, value)

    def ask(self, r):
        """The vault bot asks him "Who is NAME to you?" with the relation buttons (`p:` callbacks)."""
        db, now = self.db(), self.clock()
        open_ = db.execute("SELECT sent FROM asks WHERE key=? AND kind='ask' AND state='open' AND sent >= ?",
                           (r['key'], now - ASK_DAYS * 86400)).fetchone()
        if open_:
            return {'asked': False, 'pending_since': day(open_['sent']), 'person': self.net(r['person']),
                    'key': r['key']}
        n = db.execute("SELECT COUNT(*) FROM asks WHERE kind='ask' AND sent >= ?", (now - 86400,)).fetchone()[0]
        if n >= self.asks_per_day:
            raise VaultError(f'at most {self.asks_per_day} relation questions a day; try tomorrow', 429,
                             'rate_limited')
        qid, nonce = ''.join(secrets.choice(_ALPHA) for _ in range(8)), secrets.token_hex(4)
        cur = self._rel(r['key'])
        since = month(r['dm_since'])
        text = (f"👤 Who is {self.net(r['person'])} to you?\n"
                f"(Telegram DM{' since ' + since[5:] + '.' + since[:4] if since else ''}"
                f"{' · now: ' + cur['value'] if cur else ''} · for Claude's person cards; only you set this)")
        labels = [(LABELS[v], f'p:{qid}:{nonce}:{CODE_OF[v]}') for v in RELATIONS]
        buttons = [labels[0:3], labels[3:6], labels[6:8] + [('✖ Skip', f'p:{qid}:{nonce}:sk')]]
        try:
            mid = self.notifier.send(text, buttons=buttons)
        except V.NotifyError as e:
            raise VaultError(f'the vault bot could not ask ({e})', 502, 'notify_failed')
        db.execute('INSERT INTO asks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                   (qid, r['key'], nonce, 'ask', int(mid or 0), now, 'open', None, None))
        db.commit()
        self.audit.log('people_relation_ask', person=r['key'])
        return {'asked': True, 'person': self.net(r['person']), 'key': r['key'], 'questions_left_today':
                self.asks_per_day - n - 1}

    def relay(self, r, value):
        """His own words relayed by me (D1): set as assistant_relay; the vault bot tells him silently, with Undo."""
        db = self.db()
        prev = self._rel(r['key'])
        prev_raw = db.execute('SELECT value, by, at FROM relations WHERE key=?', (r['key'],)).fetchone()
        new = None if value == 'unset' else value
        qid, nonce = ''.join(secrets.choice(_ALPHA) for _ in range(8)), secrets.token_hex(4)
        what = f"{self.net(r['person'])} = {new}" if new else f"{self.net(r['person'])}: relation removed"
        try:
            mid = self.notifier.send(f'👤 Claude set {what} (from what you told it)',
                                     buttons=[[('↩️ Undo', f'p:{qid}:{nonce}:un')]], silent=True)
        except V.NotifyError as e:
            raise VaultError(f'the vault bot could not confirm it to the owner ({e}); nothing set', 502,
                             'notify_failed')
        self._set_rel(db, r['key'], new, 'assistant_relay')
        db.execute('INSERT INTO asks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                   (qid, r['key'], nonce, 'relay', int(mid or 0), self.clock(), 'open', value,
                    json.dumps(dict(prev_raw)) if prev_raw else None))
        db.commit()
        self.audit.log('people_relation', person=r['key'], value=value, by='assistant_relay')
        return {'person': self.net(r['person']), 'key': r['key'], 'relation': self._rel(r['key']),
                'previous': prev['value'] if prev else None, 'confirmed_to_owner': True}

    def on_callback(self, cq):
        """A `p:` press (ApprovalBot.handle routes it here after its owner-chat check) -> the answer shown on the
        button. Valid only with the question's nonce, on the message it was sent as, while it is open (7 days)."""
        m = CB_RE.fullmatch(str(cq.get('data') or ''))
        if not m or not self.enabled:
            self.audit.log('people_callback_refused', why='bad_data' if self.enabled else 'off')
            return 'Unknown button'
        qid, nonce, code = m.groups()
        msg = cq.get('message') if isinstance(cq.get('message'), dict) else {}
        with self._lock:
            db = self.db()
            a = db.execute('SELECT * FROM asks WHERE qid=?', (qid,)).fetchone()
            if (a is None or not hmac.compare_digest(a['nonce'], nonce)
                    or (a['msg_id'] and a['msg_id'] != msg.get('message_id'))):
                self.audit.log('people_callback_refused', why='mismatch')
                return 'This button is not valid'
            if a['state'] != 'open':
                return f"Already {a['state']}"
            c = db.execute('SELECT person FROM cards WHERE key=?', (a['key'],)).fetchone()
            who = self.net(c['person']) if c else 'this person'
            if self.clock() - a['sent'] > ASK_DAYS * 86400:
                db.execute("UPDATE asks SET state='expired' WHERE qid=?", (qid,))
                db.commit()
                self._edit(a['msg_id'], f'👤 {who}: this question expired')
                return 'This question expired'
            if a['kind'] == 'ask' and code == 'sk':
                db.execute("UPDATE asks SET state='skipped' WHERE qid=?", (qid,))
                db.commit()
                self.audit.log('people_relation', person=a['key'], value='skipped', by='owner_tap')
                self._edit(a['msg_id'], f'👤 {who}: skipped')
                return 'Skipped ✓'
            if a['kind'] == 'ask' and code in CODES:
                v = CODES[code]
                self._set_rel(db, a['key'], v, 'owner_tap')
                db.execute("UPDATE asks SET state='answered', value=? WHERE qid=?", (v, qid))
                db.commit()
                self.audit.log('people_relation', person=a['key'], value=v, by='owner_tap')
                self._edit(a['msg_id'], f'👤 {who} = {LABELS[v]} ✓')
                return f'{who} = {v} ✓'
            if a['kind'] == 'relay' and code == 'un':
                prev = json.loads(a['prev']) if a['prev'] else None
                if prev:
                    db.execute('INSERT INTO relations VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET '
                               'value=excluded.value, by=excluded.by, at=excluded.at',
                               (a['key'], prev['value'], prev['by'], prev['at']))
                else:
                    db.execute('DELETE FROM relations WHERE key=?', (a['key'],))
                db.execute("UPDATE asks SET state='undone' WHERE qid=?", (qid,))
                db.commit()
                self.audit.log('people_relation', person=a['key'], value=prev['value'] if prev else 'unset',
                               by='undo')
                self._edit(a['msg_id'], f'↩️ Undone: {who}' + (f" is {prev['value']} again" if prev
                                                                  else ' has no relation again'))
                return 'Undone ✓'
        self.audit.log('people_callback_refused', why='bad_code')
        return 'Unknown button'

    def _edit(self, msg_id, text):
        if not msg_id:
            return
        try:
            self.notifier.edit(msg_id, text)
        except Exception as e:
            self.log(f'people: edit failed ({type(e).__name__})')

    # ---------------------------------------------------------------- forget (only on his request)
    def forget(self, person, undo=False):
        self.check_on()
        if not undo:
            self.ensure_built()
            with self._lock:
                db = self.db()
                r = self.find(person)
                db.execute('DELETE FROM cards WHERE key=?', (r['key'],))
                db.execute('DELETE FROM relations WHERE key=?', (r['key'],))
                db.execute("UPDATE asks SET state='forgotten' WHERE key=? AND state='open'", (r['key'],))
                self.asks.forget(r['key'])
                db.execute('INSERT OR REPLACE INTO forgotten VALUES (?, ?)', (r['key'], self.clock()))
                db.commit()
            self.audit.log('people_forget', person=r['key'], action='forget')
            return {'person': self.net(r['person']), 'key': r['key'], 'forgotten': True}
        p = ' '.join(str(person or '').split())
        if not (0 < len(p) <= 64) or V._CTRL.search(p):
            raise VaultError('person: a name or a key (p-xxxxxxxx), at most 64 characters', 400, 'bad_param')
        with self._lock:
            db = self.db()
            gone = {r[0] for r in db.execute('SELECT key FROM forgotten')}
            if KEY_RE.fullmatch(p):
                keys = [p] if p in gone else []
            else:                                       # by name: the forgotten keys are matched against today's stats
                try:
                    aliases = self.aliases() or {}
                except Exception:
                    aliases = {}
                keys = [self.pkey(x['uid']) for x in self.tg.people_stats(MIN_MSGS, DAYS).get('people') or []
                        if isinstance(x.get('uid'), int) and self.pkey(x['uid']) in gone
                        and display(x['uid'], x.get('name'), aliases).casefold() == p.casefold()]
            if not keys:
                raise VaultError('no forgotten person by that name or key', 404, 'not_found')
            if len(keys) > 1:
                raise VaultError(f'{len(keys)} forgotten people match; use the key: ' + ', '.join(keys[:5]), 409,
                                 'ambiguous')
            db.execute('DELETE FROM forgotten WHERE key=?', (keys[0],))
            db.commit()
            self.dirty = True
        self.audit.log('people_forget', person=keys[0], action='unforget')
        return {'key': keys[0], 'forgotten': False, 'note': 'the card comes back at the next build (if in scope)'}

    # ---------------------------------------------------------------- status
    def status(self):
        if not self.enabled:
            return {'enabled': False, 'ask': self.ask_on}
        try:
            with self._lock:
                db = self.db()
                n = {t: db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('cards', 'relations',
                                                                                        'forgotten')}
                n['asks_open'] = db.execute("SELECT COUNT(*) FROM asks WHERE state='open'").fetchone()[0]
            b = self.built_at()
        except sqlite3.Error as e:
            return {'enabled': True, 'ask': self.ask_on, 'error': type(e).__name__}
        out = {'enabled': True, 'ask': self.ask_on, **n, 'built': V.now_iso(b) if b else None,
               'error': self.error or None, 'v2': self.v2}
        if self.v2:
            try:
                with self._lock:
                    cfg = self.topics.setting() or {}
                    out.update(open_asks=self.asks.stats(), topics={
                        'state': self.topics.state(), 'calibrated': V.now_iso(cfg['at']) if cfg.get('at') else None,
                        **{k: cfg.get(k) for k in ('n', 'accuracy', 'shown_precision', 'macro_f1', 'coverage',
                                                   'blend', 'threshold', 'margin')}},
                               night=dict(self.night), v2_error=self.v2_error or None)
            except sqlite3.Error as e:
                out['v2_error'] = type(e).__name__
        return out
