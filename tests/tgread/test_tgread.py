#!/home/node/opt/tgread-venv/bin/python3 -I
"""Offline tests for tgread (canonical copy: ~/opt/claude-vault/vendor/tgread; it runs in the privacy vault, and
~/bin/tgread is a wrapper around `vault tg`). Env: TGREAD_BIN (script under test), TGREAD_PY (python to run it with,
else its shebang), SECRETSCAN_BIN. No network: sockets are disabled, and "Telegram" is a fake server that answers
the REAL Telethon client from inside its send queue (so the guard layers, Telethon's paging and our sync logic all
run for real). Run: ~/opt/tgread-tests/run.sh [-v] [TestClass[.test_name]]

Fixture rule (this folder is versioned by `brain`, whose commits are scanned by secretscan): never write a complete
card number or token literally; build such values at runtime."""
import ast
import asyncio
import contextlib
import datetime as dt
import importlib.machinery
import importlib.util
import inspect
import io
import json
import logging
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

TGREAD = os.environ.get('TGREAD_BIN') or '/home/node/opt/claude-vault/vendor/tgread'
SECRETSCAN = os.environ.get('SECRETSCAN_BIN') or '/home/node/bin/secretscan.py'
TGREAD_CMD = [os.environ['TGREAD_PY'], '-I', TGREAD] if os.environ.get('TGREAD_PY') else [TGREAD]
UTC = dt.timezone.utc
NOW = int(dt.datetime(2026, 10, 10, 12, 0, tzinfo=UTC).timestamp())
ROOT = Path(tempfile.mkdtemp(prefix='tgread-tests-'))

# ---------------------------------------------------------------- hermetic environment (before loading tgread)
os.environ['TGREAD_HOME'] = str(ROOT / 'home0')
os.environ['TGREAD_INBOX'] = str(ROOT / 'home0' / 'inbox')
os.environ['TGREAD_NOW'] = str(NOW)
os.environ['TGREAD_SECRETSCAN'] = SECRETSCAN
os.environ['SECRETSCAN_SOURCES'] = str(ROOT / 'ssrc')          # secretscan reads fake sources, not ~/.secrets
os.environ.pop('TGREAD_DEBUG', None)
FAKE_SECRET = 'Qz' + 'x7' * 7 + 'Mk' + 'w4' * 4                   # token-shaped, built at runtime
(ROOT / 'ssrc' / '.secrets').mkdir(parents=True)
(ROOT / 'ssrc' / '.secrets' / 'test.env').write_text(f'API_TOKEN={FAKE_SECRET}\n')


def _no_network(*a, **k):
    raise OSError('network is disabled in the tgread tests')


socket.socket.connect = _no_network
socket.socket.connect_ex = _no_network
socket.create_connection = _no_network
logging.getLogger().addHandler(logging.NullHandler())

_loader = importlib.machinery.SourceFileLoader('tgread_under_test', TGREAD)
_spec = importlib.util.spec_from_loader('tgread_under_test', _loader)
T = importlib.util.module_from_spec(_spec)
_loader.exec_module(T)
TL = T._telethon()
import telethon                                                    # noqa: E402  (after the guard is installed)
from telethon import errors as te, functions as tf, types as tt, utils as tu   # noqa: E402
from telethon.network.requeststate import RequestState             # noqa: E402
from telethon.tl.alltlobjects import tlobjects                     # noqa: E402
from telethon.tl.tlobject import TLRequest                         # noqa: E402

ORIG_RO = T.ReadOnlyTelegram


def _good_prime():
    """Telegram's 2048-bit SRP prime, taken from Telethon's own source (so the fake 2FA parameters are valid)."""
    import telethon.password as tp
    tree = ast.parse(textwrap.dedent(inspect.getsource(tp.check_prime_and_good)))
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == 'bytes' and n.args \
                and isinstance(n.args[0], ast.Tuple):
            return bytes(ast.literal_eval(n.args[0]))
    raise RuntimeError('prime not found')


GOOD_PRIME = _good_prime()


def card(prefix):
    """A Luhn-valid card number with the given prefix (16 digits), built at runtime."""
    body = prefix + '0' * (15 - len(prefix))
    total = 0
    for i, ch in enumerate(reversed(body)):
        x = int(ch)
        if i % 2 == 0:
            x = x * 2 - 9 if x > 4 else x * 2
        total += x
    return body + str((10 - total % 10) % 10)


def ts(hours_ago):
    return dt.datetime.fromtimestamp(NOW - hours_ago * 3600, UTC)


# ---------------------------------------------------------------- fake Telegram
class FakeConn:
    _connected = True

    def __init__(self):
        self.task = None

    async def disconnect(self):
        self._connected = False
        if self.task is not None:
            self.task.cancel()

    def __str__(self):
        return 'FakeConn'


class FakeTelegram:
    """Answers requests popped from the client's MessagePacker (i.e. after all guard layers). Records every request
    type (wrappers unwrapped) in self.names."""
    WRAPPERS = (tf.InvokeWithLayerRequest, tf.InitConnectionRequest, tf.InvokeWithoutUpdatesRequest)

    def __init__(self):
        self.me = tt.User(id=1000, is_self=True, access_hash=11, first_name='Lukas', last_name='Meier',
                          username='lukas_m')
        self.users = {self.me.id: self.me}
        self.chats, self.order = {}, []
        self.names, self.outer = [], []
        self.logged_in = True
        self.flood = {}
        self.fail = {}
        self.history_calls = 0
        self.global_id = 5000
        self.full_members = {}
        self.client = None
        self.login = None

    # ---- world building
    def add_user(self, uid, first, last=None, username=None, bot=False, contact=True):
        u = tt.User(id=uid, access_hash=uid * 7, first_name=first, last_name=last, username=username,
                    bot=bot or None, contact=contact or None)
        self.users[uid] = u
        return u

    def add_chat(self, kind, cid=None, title=None, user=None, username=None, members=None, muted=False,
                 archived=False):
        if kind in ('user', 'bot', 'self'):
            ent = user if user is not None else self.me
            peer, marked = tt.PeerUser(ent.id), ent.id
        elif kind == 'group':
            ent = tt.Chat(id=cid, title=title, photo=tt.ChatPhotoEmpty(), participants_count=members or 5,
                          date=ts(9000), version=1)
            peer, marked = tt.PeerChat(cid), -cid
        else:
            ent = tt.Channel(id=cid, title=title, photo=tt.ChatPhotoEmpty(), date=ts(9000), access_hash=cid * 3,
                             megagroup=(kind == 'supergroup') or None, broadcast=(kind == 'channel') or None,
                             username=username)
            peer = tt.PeerChannel(cid)
            marked = tu.get_peer_id(peer)
            if members:
                self.full_members[cid] = members
        self.chats[marked] = {'kind': kind, 'entity': ent, 'peer': peer, 'msgs': [], 'muted': muted,
                              'archived': archived, 'read': 0, 'next': 1}
        self.order.append(marked)
        return marked

    def add_msg(self, marked, hours_ago, text, sender=None, out=False, media=None, fwd=None, reply_to=None,
                action=None):
        c = self.chats[marked]
        if c['kind'] in ('supergroup', 'channel'):
            mid = c['next']
            c['next'] += 1
        else:
            self.global_id += 1
            mid = self.global_id
        from_id = None
        if c['kind'] in ('group', 'supergroup'):
            from_id = tt.PeerUser(self.me.id if out else sender.id)
        kw = dict(id=mid, peer_id=c['peer'], date=ts(hours_ago), out=out or None, from_id=from_id)
        if action is not None:
            m = tt.MessageService(action=action, **kw)
        else:
            m = tt.Message(message=text, media=media, fwd_from=fwd, post=(c['kind'] == 'channel') or None,
                           reply_to=tt.MessageReplyHeader(reply_to_msg_id=reply_to) if reply_to else None, **kw)
        c['msgs'].append(m)
        c['msgs'].sort(key=lambda x: -x.id)
        return mid

    def find(self, marked, mid):
        return next(m for m in self.chats[marked]['msgs'] if m.id == mid)

    def delete(self, marked, mid):
        self.chats[marked]['msgs'] = [m for m in self.chats[marked]['msgs'] if m.id != mid]

    # ---- plumbing
    def attach(self, client):
        self.client = client
        sender = client._sender
        fake = self

        async def fake_connect():
            loop = asyncio.get_running_loop()
            conn = FakeConn()
            sender._connection = conn
            sender._MTProtoSender__disconnected = loop.create_future()   # what _connect() does
            conn.task = loop.create_task(fake.serve(sender))

        sender._connect = fake_connect

    async def serve(self, sender):
        packer = sender._send_queue
        while True:
            while packer._deque:
                state = packer._deque.popleft()
                try:
                    res = self.handle(state.request)
                except BaseException as e:
                    if not state.future.done():
                        state.future.set_exception(e)
                else:
                    if not state.future.done():
                        state.future.set_result(res)
            await asyncio.sleep(0.001)

    def handle(self, outer):
        req = outer
        while isinstance(req, self.WRAPPERS):
            req = req.query
        name = T.tl_name(type(req))
        self.outer.append(T.tl_name(type(outer)))
        self.names.append(name)
        if name in self.fail:
            raise self.fail[name](req)
        secs = self.flood.get(name)
        if secs:
            s = secs.pop(0)
            if not secs:
                del self.flood[name]
            raise te.FloodWaitError(request=req, capture=s)
        h = getattr(self, 'h_' + name.replace('.', '_'), None)
        if h is None:
            raise AssertionError(f'fake Telegram: unexpected request {name}')
        return h(req)

    def _peer_id(self, peer):
        if isinstance(peer, tt.InputPeerSelf):
            return self.me.id
        return tu.get_peer_id(peer)

    def _entities(self, msgs, marked=None):
        users, chats = {self.me.id: self.me}, {}
        for m in msgs:
            for p in (getattr(m, 'from_id', None), getattr(getattr(m, 'fwd_from', None), 'from_id', None)):
                if isinstance(p, tt.PeerUser) and p.user_id in self.users:
                    users[p.user_id] = self.users[p.user_id]
            pm = tu.get_peer_id(m.peer_id)
            ent = self.chats.get(pm, {}).get('entity')
            if isinstance(ent, tt.User):
                users[ent.id] = ent
            elif ent is not None:
                chats[pm] = ent
        if marked is not None:
            ent = self.chats[marked]['entity']
            if isinstance(ent, tt.User):
                users[ent.id] = ent
            else:
                chats[marked] = ent
        return list(users.values()), list(chats.values())

    # ---- handlers
    def h_help_GetConfigRequest(self, req):
        return SimpleNamespace(dc_options=[])

    def h_PingRequest(self, req):
        return tt.Pong(msg_id=0, ping_id=req.ping_id)

    def h_users_GetUsersRequest(self, req):
        out = []
        for u in req.id:
            if isinstance(u, tt.InputUserSelf):
                if not self.logged_in:
                    raise te.AuthKeyUnregisteredError(request=req)
                out.append(self.me)
            elif getattr(u, 'user_id', None) in self.users:
                out.append(self.users[u.user_id])
        return out

    def h_updates_GetStateRequest(self, req):
        if not self.logged_in:
            raise te.AuthKeyUnregisteredError(request=req)
        return tt.updates.State(pts=1, qts=0, date=ts(0), seq=1, unread_count=0)

    def h_updates_GetDifferenceRequest(self, req):
        return tt.updates.DifferenceEmpty(date=ts(0), seq=1)

    def h_messages_GetDialogsRequest(self, req):
        if not self.logged_in:
            raise te.AuthKeyUnregisteredError(request=req)
        ds, tops = [], []
        for marked in self.order:
            c = self.chats[marked]
            top = c['msgs'][0] if c['msgs'] else None
            unread = sum(1 for m in c['msgs'] if not m.out and m.id > c['read'])
            ns = tt.PeerNotifySettings(mute_until=dt.datetime(2038, 1, 1, tzinfo=UTC) if c['muted'] else None)
            ds.append(tt.Dialog(peer=c['peer'], top_message=top.id if top else 0, read_inbox_max_id=c['read'],
                                read_outbox_max_id=0, unread_count=unread, unread_mentions_count=0,
                                unread_reactions_count=0, unread_poll_votes_count=0, notify_settings=ns,
                                folder_id=1 if c['archived'] else None,
                                pts=1 if c['kind'] in ('supergroup', 'channel') else None))
            if top:
                tops.append(top)
        users, chats = self._entities(tops)
        for marked in self.order:
            ent = self.chats[marked]['entity']
            if isinstance(ent, tt.User):
                if ent.id not in {u.id for u in users}:
                    users.append(ent)
            elif ent not in chats:
                chats.append(ent)
        return tt.messages.Dialogs(dialogs=ds, messages=tops, chats=chats, users=users)

    def h_messages_GetHistoryRequest(self, req):
        self.history_calls += 1
        marked = self._peer_id(req.peer)
        c = self.chats[marked]
        msgs = c['msgs']
        if req.offset_id:
            p = next((i for i, m in enumerate(msgs) if m.id < req.offset_id), len(msgs))
        elif req.offset_date:
            p = next((i for i, m in enumerate(msgs) if m.date < req.offset_date), len(msgs))
        else:
            p = 0
        lo = p + req.add_offset
        sl = msgs[max(lo, 0):max(lo + req.limit, 0)]
        if req.max_id:
            sl = [m for m in sl if m.id < req.max_id]
        if req.min_id:
            sl = [m for m in sl if m.id > req.min_id]
        users, chats = self._entities(sl, marked)
        if c['kind'] in ('supergroup', 'channel'):
            return tt.messages.ChannelMessages(pts=1, count=len(msgs), messages=sl, topics=[], chats=chats,
                                               users=users)
        if len(sl) == len(msgs):
            return tt.messages.Messages(messages=sl, topics=[], chats=chats, users=users)
        return tt.messages.MessagesSlice(count=len(msgs), messages=sl, topics=[], chats=chats, users=users)

    def _by_ids(self, marked, ids):
        want = {getattr(i, 'id', i) for i in ids}
        return [m for m in self.chats[marked]['msgs'] if m.id in want]

    def h_messages_GetMessagesRequest(self, req):
        found = []
        for marked, c in self.chats.items():
            if c['kind'] not in ('supergroup', 'channel'):
                found += self._by_ids(marked, req.id)
        users, chats = self._entities(found)
        return tt.messages.Messages(messages=found, topics=[], chats=chats, users=users)

    def h_channels_GetMessagesRequest(self, req):
        marked = tu.get_peer_id(tt.PeerChannel(req.channel.channel_id))
        found = self._by_ids(marked, req.id)
        users, chats = self._entities(found, marked)
        return tt.messages.ChannelMessages(pts=1, count=len(found), messages=found, topics=[], chats=chats,
                                           users=users)

    def h_channels_GetFullChannelRequest(self, req):
        return SimpleNamespace(full_chat=SimpleNamespace(participants_count=self.full_members.get(
            req.channel.channel_id)), chats=[], users=[])

    def h_upload_GetFileRequest(self, req):
        data = b'\xff\xd8 fake jpeg \xff\xd9'
        return tt.upload.File(type=tt.storage.FileJpeg(), mtime=0, bytes=data if req.offset == 0 else b'')

    # ---- login
    def h_auth_ExportLoginTokenRequest(self, req):
        L = self.login
        L['exports'] += 1
        step = L['script'].pop(0)
        if step[0] == 'token':
            if len(step) > 2 and step[2]:
                loop = asyncio.get_running_loop()
                loop.call_later(0.3, lambda: self.client._updates_queue.put_nowait(
                    tt.UpdateShort(update=tt.UpdateLoginToken(), date=dt.datetime.now(UTC))))
            return tt.auth.LoginToken(expires=dt.datetime.now(UTC) + dt.timedelta(seconds=step[1]),
                                      token=os.urandom(16))
        if step[0] == 'password':
            raise te.SessionPasswordNeededError(request=req)
        self.logged_in = True
        return tt.auth.LoginTokenSuccess(authorization=tt.auth.Authorization(user=self.me))

    def h_account_GetPasswordRequest(self, req):
        L = self.login
        if L.get('write_pw'):
            pw = L['write_pw'].pop(0)
            p = Path(L['pw_path'])
            tmp = p.with_name(p.name + '.tmp')
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, L.get('pw_mode', 0o600))
            os.write(fd, (pw + '\n').encode())
            os.close(fd)
            os.chmod(tmp, L.get('pw_mode', 0o600))
            os.replace(tmp, p)
        algo = tt.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow(
            salt1=os.urandom(8), salt2=os.urandom(16), g=3, p=GOOD_PRIME)
        b = pow(3, int.from_bytes(os.urandom(256), 'big'), int.from_bytes(GOOD_PRIME, 'big'))
        return tt.account.Password(new_algo=tt.PasswordKdfAlgoUnknown(), new_secure_algo=tt.SecurePasswordKdfAlgoUnknown(),
                                   secure_random=os.urandom(32), has_password=True, current_algo=algo,
                                   srp_B=b.to_bytes(256, 'big'), srp_id=42, hint='first pet')

    def h_auth_CheckPasswordRequest(self, req):
        L = self.login
        L['checks'] += 1
        if L['bad_checks'] > 0:
            L['bad_checks'] -= 1
            raise te.PasswordHashInvalidError(request=req)
        self.logged_in = True
        return tt.auth.Authorization(user=self.me)


def wire(fake):
    """Make every ReadOnlyTelegram that tgread creates talk to `fake` (instead of the network)."""
    class FakeWired(ORIG_RO):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            fake.attach(self._c)
    T.ReadOnlyTelegram = FakeWired


ANNA, BOB, PETER, BOT = 2001, 2002, 2003, 2100


def standard_world():
    f = FakeTelegram()
    anna = f.add_user(ANNA, 'Anna', 'Muster', 'anna_m')
    bob = f.add_user(BOB, 'Bob', 'Keller')
    peter = f.add_user(PETER, 'Peter', 'Muster', contact=False)
    bot = f.add_user(BOT, 'WeatherBot', None, 'weather_bot', bot=True)
    climbers = [f.add_user(3000 + i, f'Climber{i}', 'Fels', contact=False) for i in range(10)]

    a = f.add_chat('user', user=anna)
    f.add_msg(a, 400 * 24, 'alte Nachricht ausserhalb des Fensters')
    f.add_msg(a, 30, 'Hoi Lukas! Meine neue Nummer: +41 79 123 45 67, Mail anna.muster@gmail.com')
    f.add_msg(a, 29, 'Merci Anna, IBAN für die Konzerttickets: CH93 0076 2011 6238 5295 7', out=True)
    read = f.add_msg(a, 28, 'Ich wohne jetzt an der Examplestrasse 12, 1234 Exampletown. Konzert am 12.10.2026 um '
                            '18:30, CHF 45.50')
    f.add_msg(a, 2, 'Treffpunkt Bahnhof Zürich, Türcode: 4711 und Code: 8890')
    f.chats[a]['read'] = read

    b = f.add_chat('user', user=bob, archived=True)
    f.add_msg(b, 50, 'Bob hier, archivierter Chat')
    f.add_msg(b, 49, 'ok', out=True)

    g = f.add_chat('group', 300, 'Familie Muster')
    f.add_msg(g, 20, 'Grüsse von Peter, ruf mich an 044 668 18 00', sender=peter)
    f.add_msg(g, 19, 'Gerne! Anna kommt auch', out=True)
    f.add_msg(g, 18, 'Ich bringe Kuchen', sender=anna)

    s = f.add_chat('supergroup', 400, 'Climbing Crew')
    for i in range(1, 151):
        f.add_msg(s, 151 - i, f'climb session {i} at the gym' + (' - Anna kommt auch' if i == 120 else ''),
                  sender=climbers[i % 10])
    f.chats[s]['read'] = 140

    ch = f.add_chat('channel', 500, 'Rhein News', username='rheinnews')
    for i in range(20):
        f.add_msg(ch, (19 - i) * 3, f'News {i}: Wetter in Examplecity' +
                  (' - Kontakt redaktion@localnews.example' if i == 19 else ''))

    me = f.add_chat('self')
    f.add_msg(me, 5, 'Notiz an mich: Velo service', out=True)

    bc = f.add_chat('bot', user=bot)
    f.add_msg(bc, 3, 'Forecast: sunny, 18°C', sender=bot)

    sp = f.add_chat('supergroup', 600, 'Spam Deals', muted=True)
    for i in range(5):
        f.add_msg(sp, 10 - i, f'Deal {i}: 50% off', sender=climbers[0])
    f.ids = {'anna': a, 'bob': b, 'group': g, 'crew': s, 'news': ch, 'self': me, 'bot': bc, 'spam': sp}
    return f


STUB_LLM = r'''#!/usr/bin/python3 -I
import json, os, sys
data = sys.stdin.read()
log = os.environ.get('STUB_LOG')
if log:
    with open(log, 'a') as f:
        f.write(json.dumps({'args': sys.argv[1:], 'stdin': data}) + '\n')
mode = os.environ.get('STUB_MODE', 'map')
if mode == 'fail':
    print('llm-local: local LLM unavailable (stub)', file=sys.stderr)
    sys.exit(3)
if mode == 'empty':
    sys.exit(0)
out = data
for pair in filter(None, os.environ.get('STUB_MAP', '').split(';')):
    a, b = pair.split('=', 1)
    out = out.replace(a, b)
if mode == 'leak':
    out += '\nleak: call 079 765 43 21 or mail leak.person@example.org, regards Anna Muster and Peter'
if '--summary' in sys.argv:
    out = 'SUMMARY:\n' + out
print(out)
'''


# ---------------------------------------------------------------- base
class Base(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(dir=ROOT))
        os.environ['TGREAD_HOME'] = str(self.home)
        os.environ['TGREAD_INBOX'] = str(self.home / 'inbox')
        T.set_paths(self.home)
        T.GUARD.blocked.clear()
        T.GUARD.profile = 'read'
        T.ReadOnlyTelegram = ORIG_RO

    def tearDown(self):
        T.ReadOnlyTelegram = ORIG_RO
        T.GUARD.profile = 'read'

    def write_config(self, **kw):
        cfg = dict(T.DEFAULT_CONFIG)
        cfg.update(request_delay_seconds=0, **kw)
        T.ensure_private_dir(T.CONFIG_DIR)
        T.write_private_json(T.CONFIG_PATH, cfg)
        return T.load_config()

    def write_creds(self):
        T.ensure_private_dir(T.SECRETS_DIR)
        T.write_private_json(T.CREDS_PATH, {'api_id': 12345, 'api_hash': 'ab' * 16})
        return T.load_creds()

    def sync(self, fake, cfg=None, **kw):
        cfg = cfg or T.load_config()
        api = self.write_creds() if not T.CREDS_PATH.exists() else T.load_creds()
        wire(fake)
        db = T.open_db()
        try:
            return T.sync_once(db, cfg, api, **kw)
        finally:
            db.close()

    def db(self):
        return T.open_db()

    def msgs(self, chat_id):
        with contextlib.closing(self.db()) as db:
            return [dict(r) for r in db.execute('SELECT * FROM messages WHERE chat_id=? ORDER BY msg_id', (chat_id,))]

    def run_main(self, *argv, stdin=None):
        T._logging_ready = False
        out, err = io.StringIO(), io.StringIO()
        old_stdin = sys.stdin
        sys.stdin = stdin if stdin is not None else io.StringIO('')
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = T.main(list(argv))
        finally:
            sys.stdin = old_stdin
            for h in logging.getLogger().handlers[:]:
                if isinstance(h, logging.FileHandler):
                    h.close()
            logging.getLogger().handlers[:] = [logging.NullHandler()]
            T._logging_ready = False
        return code, out.getvalue(), err.getvalue()

    def cli(self, *args, input=None, env=None):
        e = dict(os.environ, TGREAD_HOME=str(self.home), TGREAD_INBOX=str(self.home / 'inbox'))
        e.update(env or {})
        return subprocess.run([*TGREAD_CMD, *args], input=input, capture_output=True, text=True, env=e, timeout=180)

    def install_stub(self, mode='map', mapping=None):
        bindir = self.home / 'bin'
        bindir.mkdir(exist_ok=True)
        p = bindir / 'llm-local'
        p.write_text(STUB_LLM)
        p.chmod(0o700)
        self.stub_log = self.home / 'stub.log'
        return {'STUB_MODE': mode, 'STUB_LOG': str(self.stub_log), 'STUB_MAP': mapping or ''}

    def stub_calls(self):
        if not self.stub_log.exists():
            return []
        return [json.loads(x) for x in self.stub_log.read_text().splitlines() if x.strip()]


# ================================================================ guard
class GuardTests(Base):
    def all_requests(self):
        return sorted({c for c in tlobjects.values() if issubclass(c, TLRequest)}, key=T.tl_name)

    def test_allowlist_snapshot(self):
        self.assertEqual(T.TELETHON_PIN, telethon.__version__)
        self.assertEqual(set(T.READ_BASE), {
            'help.GetConfigRequest', 'updates.GetStateRequest', 'updates.GetDifferenceRequest',
            'updates.GetChannelDifferenceRequest', 'users.GetUsersRequest', 'users.GetFullUserRequest',
            'messages.GetDialogsRequest', 'messages.GetHistoryRequest', 'messages.GetMessagesRequest',
            'messages.GetChatsRequest', 'channels.GetMessagesRequest', 'channels.GetChannelsRequest',
            'channels.GetFullChannelRequest'})
        self.assertEqual(set(T.LOGIN_EXTRA), {'auth.ExportLoginTokenRequest', 'auth.ImportLoginTokenRequest',
                                              'account.GetPasswordRequest', 'auth.CheckPasswordRequest'})
        self.assertEqual(set(T.DOWNLOAD_EXTRA), {'upload.GetFileRequest', 'auth.ExportAuthorizationRequest',
                                                 'auth.ImportAuthorizationRequest'})
        self.assertEqual(T.PROFILES['live'], T.READ_BASE)          # live: no extra request type at all
        for m in ('run_until_disconnected', 'catch_up', 'set_receive_updates', 'send_read_acknowledge'):
            self.assertIn(m, T.BLOCKED_METHODS)                      # and no high-level method unblocked
        self.assertTrue(T.guards_installed())

    def test_every_request_type_against_every_profile_and_layer(self):
        reqs = self.all_requests()
        self.assertGreater(len(reqs), 800)
        service = {T.tl_name(c) for c in T.GUARD.service}
        for profile, names in T.PROFILES.items():
            T.GUARD.profile = profile
            for layer in ('client', 'sender', 'wire'):
                passed = set()
                for cls in reqs:
                    obj = cls.__new__(cls)
                    try:
                        T.check_request(obj, layer)
                        passed.add(T.tl_name(cls))
                    except T.ReadOnlyViolation:
                        pass
                expect = set(names) | (service if layer != 'client' else set())
                self.assertEqual(passed, expect, f'{profile}/{layer}')
        T.GUARD.blocked.clear()

    def test_dangerous_requests_blocked_in_all_profiles(self):
        peer = tt.InputPeerSelf()
        dangerous = [
            tf.messages.SendMessageRequest(peer=peer, message='x'),
            tf.messages.ReadHistoryRequest(peer=peer, max_id=10),
            tf.channels.ReadHistoryRequest(channel=tt.InputChannel(1, 2), max_id=10),
            tf.messages.SetTypingRequest(peer=peer, action=tt.SendMessageTypingAction()),
            tf.account.UpdateStatusRequest(offline=False),
            tf.account.UpdateStatusRequest(offline=True),
            tf.messages.DeleteMessagesRequest(id=[1]),
            tf.messages.EditMessageRequest(peer=peer, id=1, message='x'),
            tf.messages.ForwardMessagesRequest(from_peer=peer, id=[1], to_peer=peer),
            tf.messages.GetMessagesViewsRequest(peer=peer, id=[1], increment=True),
            tf.messages.ReadMentionsRequest(peer=peer),
            tf.messages.ReadReactionsRequest(peer=peer),
            tf.messages.ReadMessageContentsRequest(id=[1]),
            tf.messages.SendReactionRequest(peer=peer, msg_id=1),
            tf.auth.AcceptLoginTokenRequest(token=b'x'),
            tf.auth.ResetAuthorizationsRequest(),
            tf.auth.LogOutRequest(),
            tf.account.InitTakeoutSessionRequest(),
            tf.channels.JoinChannelRequest(channel=tt.InputChannel(1, 2)),
            tf.channels.LeaveChannelRequest(channel=tt.InputChannel(1, 2)),
            tf.contacts.BlockRequest(id=peer),
            tf.InvokeWithTakeoutRequest(takeout_id=1, query=tf.messages.GetHistoryRequest(
                peer=peer, offset_id=0, offset_date=None, add_offset=0, limit=1, max_id=0, min_id=0, hash=0)),
            tf.InvokeWithLayerRequest(layer=1, query=tf.messages.SendMessageRequest(peer=peer, message='x')),
            tf.InvokeWithoutUpdatesRequest(query=tf.messages.ReadHistoryRequest(peer=peer, max_id=1)),
            [tf.updates.GetStateRequest(), tf.messages.ReadHistoryRequest(peer=peer, max_id=1)],
        ]
        for profile in T.PROFILES:
            T.GUARD.profile = profile
            for req in dangerous:
                for layer in ('client', 'sender', 'wire'):
                    with self.assertRaises(T.ReadOnlyViolation, msg=f'{profile}/{layer}/{req!r:.60}'):
                        T.check_request(req, layer)
        T.GUARD.blocked.clear()

    def test_wrapped_init_request_allowed(self):
        init = tf.InitConnectionRequest(api_id=1, device_model='d', system_version='s', app_version='a',
                                        system_lang_code='en', lang_pack='', lang_code='en',
                                        query=tf.help.GetConfigRequest())
        T.check_request(tf.InvokeWithLayerRequest(layer=229, query=tf.InvokeWithoutUpdatesRequest(query=init)),
                        'sender')
        with self.assertRaises(T.ReadOnlyViolation):     # pings only below the client layer
            T.check_request(tf.PingRequest(ping_id=1), 'client')
        T.check_request(tf.PingRequest(ping_id=1), 'wire')

    def test_layer3_wire_and_payload_mismatch(self):
        async def go():
            ok = RequestState(tf.updates.GetStateRequest())
            T._check_state(ok)
            bad = RequestState(tf.messages.ReadHistoryRequest(peer=tt.InputPeerSelf(), max_id=1))
            with self.assertRaises(T.ReadOnlyViolation):
                T._check_state(bad)
            sneaky = RequestState(tf.updates.GetStateRequest())
            sneaky.data = bytes(tf.messages.SendMessageRequest(peer=tt.InputPeerSelf(), message='x', random_id=1))
            with self.assertRaises(T.ReadOnlyViolation):
                T._check_state(sneaky)
            ack = RequestState(tt.MsgsAck(msg_ids=[1]))       # service ack: no API call
            T._check_state(ack)
            packer = TL.MessagePacker(None, loggers=_loggers())
            with self.assertRaises(T.ReadOnlyViolation):
                packer.append(bad)
            with self.assertRaises(T.ReadOnlyViolation):
                packer.extend([ok, bad])
            self.assertEqual(len(packer._deque), 0)            # nothing reached the queue
            packer.append(ok)
            self.assertEqual(len(packer._deque), 1)
        asyncio.run(go())
        T.GUARD.blocked.clear()

    def test_real_sender_blocks_and_client_methods_blocked(self):
        fake = standard_world()

        async def go():
            tg = ORIG_RO(12345, 'ab' * 16, session=TL.MemorySession())
            fake.attach(tg._c)
            await tg.connect()
            c = tg._c
            try:
                for name in ('send_message', 'send_read_acknowledge', 'action', 'delete_messages', 'edit_message',
                             'forward_messages', 'log_out', 'catch_up', 'start', 'send_file', 'pin_message'):
                    with self.assertRaises(T.ReadOnlyViolation, msg=name):
                        r = getattr(c, name)('me', 'hi')
                        if asyncio.iscoroutine(r):
                            await r
                # bypassing the method overrides still ends at the request guard
                with self.assertRaises(T.ReadOnlyViolation):
                    await TL.TelegramClient.send_message(c, 'me', 'hi')
                with self.assertRaises(T.ReadOnlyViolation):
                    await TL.TelegramClient.send_read_acknowledge(c, 'me', max_id=5)
                with self.assertRaises(T.ReadOnlyViolation):
                    async with TL.TelegramClient.action(c, 'me', 'typing'):
                        await asyncio.sleep(0.05)            # let the typing task try to send
                with self.assertRaises(T.ReadOnlyViolation):
                    await c(tf.account.UpdateStatusRequest(offline=False))
                with self.assertRaises(T.ReadOnlyViolation):
                    await c(tf.channels.ReadHistoryRequest(channel=tt.InputChannel(400, 1200), max_id=5))
                with self.assertRaises(T.ReadOnlyViolation):    # straight into the real MTProtoSender
                    c._sender.send(tf.messages.ReadHistoryRequest(peer=tt.InputPeerSelf(), max_id=1))
                with self.assertRaises(T.ReadOnlyViolation):
                    c._sender.send([tf.updates.GetStateRequest(), tf.messages.SetTypingRequest(
                        peer=tt.InputPeerSelf(), action=tt.SendMessageTypingAction())])
                with self.assertRaises(T.ReadOnlyViolation):
                    await c.qr_login()                          # only in the login profile
                with self.assertRaises(T.ReadOnlyViolation):
                    await c.sign_in(password='x')
                me = await c.get_me()                           # reads still work
                self.assertEqual(me.id, 1000)
            finally:
                await tg.disconnect()
        asyncio.run(go())
        dangerous = {'messages.SendMessageRequest', 'messages.ReadHistoryRequest', 'channels.ReadHistoryRequest',
                     'messages.SetTypingRequest', 'account.UpdateStatusRequest', 'auth.LogOutRequest'}
        self.assertFalse(dangerous & set(fake.names), fake.names)
        self.assertTrue(set(fake.names) <= set(T.READ_BASE), fake.names)
        T.GUARD.blocked.clear()

    def test_telethon_sources_never_send_status_or_read_receipts_on_their_own(self):
        pkg = Path(telethon.__file__).parent
        skip = ('tl/functions', 'tl/types', 'tl/alltlobjects.py', 'tl/patched')
        found = {}
        names = ('UpdateStatusRequest', 'ReadHistoryRequest', 'SetTypingRequest', 'ReadMentionsRequest',
                 'ReadReactionsRequest', 'GetMessagesViewsRequest', 'ReadMessageContentsRequest',
                 'AcceptLoginTokenRequest', 'ResetAuthorizationsRequest')
        for f in pkg.rglob('*.py'):
            rel = f.relative_to(pkg).as_posix()
            if rel.startswith(skip):
                continue
            txt = f.read_text(encoding='utf-8')
            for n in names:
                if n in txt:
                    found.setdefault(n, set()).add(rel)
        # only behind client methods that tgread blocks (send_read_acknowledge, action)
        self.assertEqual(found, {'ReadHistoryRequest': {'client/messages.py'},
                                 'ReadMentionsRequest': {'client/messages.py'},
                                 'ReadReactionsRequest': {'client/messages.py'},
                                 'SetTypingRequest': {'client/chats.py'}})

    def test_version_pin_refuses_other_telethon(self):
        saved, ver = T._TL, telethon.__version__
        try:
            T._TL = None
            telethon.__version__ = '9.9.9'
            with self.assertRaises(T.TgreadError):
                T._telethon()
        finally:
            telethon.__version__ = ver
            T._TL = saved

    def test_violation_is_not_an_oserror(self):
        self.assertFalse(issubclass(T.ReadOnlyViolation, OSError))
        self.assertFalse(issubclass(T.ReadOnlyViolation, te.RPCError))


def _loggers():
    class L(dict):
        def __missing__(self, k):
            return logging.getLogger(k)
    return L()


# ================================================================ permissions / credentials
class PermTests(Base):
    def make_session(self, mode=0o600):
        T.ensure_private_dir(T.SECRETS_DIR)
        T.SESSION_PATH.write_bytes(b'')
        os.chmod(T.SESSION_PATH, mode)

    def test_good_permissions(self):
        self.make_session()
        self.write_creds()
        T.preflight()

    def test_loose_session_refused(self):
        self.make_session(0o644)
        with self.assertRaises(T.PermError) as cm:
            T.preflight()
        self.assertIn('chmod 600', str(cm.exception))

    def test_symlink_and_hardlink_refused(self):
        self.make_session()
        T.SESSION_PATH.rename(self.home / 'real.session')
        T.SESSION_PATH.symlink_to(self.home / 'real.session')
        with self.assertRaises(T.PermError):
            T.preflight()
        T.SESSION_PATH.unlink()
        os.link(self.home / 'real.session', T.SESSION_PATH)
        with self.assertRaises(T.PermError):
            T.preflight()

    def test_loose_creds_journal_and_secrets_dir_refused(self):
        self.make_session()
        self.write_creds()
        os.chmod(T.CREDS_PATH, 0o640)
        with self.assertRaises(T.PermError):
            T.preflight()
        os.chmod(T.CREDS_PATH, 0o600)
        j = Path(f'{T.SESSION_PATH}-journal')
        j.write_bytes(b'')
        os.chmod(j, 0o604)
        with self.assertRaises(T.PermError):
            T.preflight()
        j.unlink()
        os.chmod(T.SECRETS_DIR, 0o777)
        with self.assertRaises(T.PermError):
            T.preflight()
        os.chmod(T.SECRETS_DIR, 0o755)       # readable is ok, writable by others is not
        T.preflight()

    def test_foreign_owner_refused(self):
        self.make_session()
        real = T.os.getuid
        try:
            T.os.getuid = lambda: real() + 1
            with self.assertRaises(T.PermError):
                T.check_private_file(T.SESSION_PATH, 'session file')
        finally:
            T.os.getuid = real

    def test_cli_refuses_with_exit_5(self):
        self.make_session(0o644)
        p = self.cli('recent')
        self.assertEqual(p.returncode, 5, p.stderr)
        self.assertIn('refusing to run', p.stderr)

    def test_set_credentials_never_echoes(self):
        h = 'c0ffee' + 'ab' * 13
        for payload in (f'4242\n{h}\n', json.dumps({'api_id': 4242, 'api_hash': h}), f'api_id=4242\napi_hash={h}\n'):
            p = self.cli('set-credentials', input=payload)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn(h, p.stdout + p.stderr)
            self.assertEqual(stat.S_IMODE(os.stat(T.CREDS_PATH).st_mode), 0o600)
            self.assertEqual(json.loads(T.CREDS_PATH.read_text()), {'api_id': 4242, 'api_hash': h})
        p = self.cli('set-credentials', input=f'4242\n{h[:-2]}zz\n')
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(h[:20], p.stdout + p.stderr)

    def test_logs_never_contain_api_hash(self):
        api = self.write_creds()
        T._logging_ready = False
        T.setup_logging()
        try:
            logging.getLogger('telethon').warning('connecting with %s', api[1])
            for h in logging.getLogger().handlers:
                h.flush()
            self.assertNotIn(api[1], T.LOG_PATH.read_text())
            self.assertIn('[redacted]', T.LOG_PATH.read_text())
        finally:
            for h in logging.getLogger().handlers[:]:
                h.close()
            logging.getLogger().handlers[:] = [logging.NullHandler()]
            T._logging_ready = False


# ================================================================ sync (real Telethon client + fake Telegram)
class SyncTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg = self.write_config()

    def test_initial_sync_window_types_and_side_effect_free(self):
        f = standard_world()
        stats = self.sync(f, self.cfg)
        ids = f.ids
        self.assertEqual(len(self.msgs(ids['anna'])), 4)                 # 400-day-old message outside the window
        self.assertEqual(len(self.msgs(ids['crew'])), 150)               # first page + backfill
        self.assertEqual(len(self.msgs(ids['news'])), 20)
        self.assertEqual(len(self.msgs(ids['group'])), 3)
        with contextlib.closing(self.db()) as db:
            chats = {r['chat_id']: dict(r) for r in db.execute('SELECT * FROM chats')}
            self.assertEqual(chats[ids['crew']]['history_done'], 1)
            self.assertEqual(chats[ids['anna']]['history_done'], 0)      # older history exists, beyond the window
            self.assertFalse(T.needs_backfill(chats[ids['anna']], NOW - 365 * 86400))
            self.assertEqual(chats[ids['self']]['type'], 'self')
            self.assertEqual(chats[ids['bot']]['type'], 'bot')
            self.assertEqual(chats[ids['news']]['type'], 'channel')
            self.assertEqual(chats[ids['crew']]['type'], 'supergroup')
            self.assertEqual(chats[ids['group']]['type'], 'group')
            self.assertEqual(chats[ids['spam']]['muted'], 1)
            self.assertEqual(chats[ids['bob']]['archived'], 1)
            out = db.execute('SELECT * FROM messages WHERE chat_id=? AND out=1', (ids['anna'],)).fetchone()
            self.assertEqual(out['sender_id'], 1000)
            self.assertEqual(T.meta_get(db, 'me_name'), 'Lukas Meier')
            hit = db.execute("SELECT m.chat_id FROM messages_fts JOIN messages m ON m.id = messages_fts.rowid "
                             "WHERE messages_fts MATCH 'konzerttickets'").fetchall()
            self.assertEqual([r[0] for r in hit], [ids['anna']])
            post = db.execute('SELECT * FROM messages WHERE chat_id=? LIMIT 1', (ids['news'],)).fetchone()
            self.assertEqual(post['sender_name'], 'Rhein News')
        self.assertEqual(stats['errors'], 0)
        # read-only proof for the whole connect + sync
        self.assertTrue(set(f.names) <= set(T.READ_BASE), sorted(set(f.names)))
        for bad in ('account.UpdateStatusRequest', 'messages.ReadHistoryRequest', 'channels.ReadHistoryRequest',
                    'messages.SetTypingRequest', 'messages.GetMessagesViewsRequest'):
            self.assertNotIn(bad, f.names)
        self.assertEqual(T.GUARD.blocked, [])
        self.assertEqual(f.names.count('updates.GetDifferenceRequest'), 1)   # only connect's; update loop is off
        self.assertTrue(all(o == 'InvokeWithoutUpdatesRequest' or o == 'InvokeWithLayerRequest' for o in f.outer))
        self.assertEqual(stat.S_IMODE(os.stat(T.SESSION_PATH).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(T.DB_PATH).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(T.DATA_DIR).st_mode), 0o700)

    def test_second_sync_without_changes_makes_no_history_requests(self):
        f = standard_world()
        self.sync(f, self.cfg)
        f.names.clear()
        f.history_calls = 0
        self.sync(f, self.cfg)
        self.assertEqual(f.history_calls, 0)

    def test_incremental_new_edit_delete(self):
        f = standard_world()
        a = f.ids['anna']
        self.sync(f, self.cfg)
        edited = f.chats[a]['msgs'][1]                     # 'Ich wohne jetzt ...'
        edited.message = 'Ich wohne jetzt woanders, Velo-Treff am Rhein'
        edited.edit_date = ts(1)
        gone = f.chats[a]['msgs'][2].id                    # the IBAN message
        f.delete(a, gone)
        f.add_msg(a, 1, 'Neu: Bouldern am Samstag?')
        f.add_msg(a, 0.5, 'Antwort folgt', out=True)
        self.sync(f, self.cfg)
        rows = {r['msg_id']: r for r in self.msgs(a)}
        self.assertNotIn(gone, rows)
        self.assertEqual(rows[edited.id]['text'], edited.message)
        self.assertIsNotNone(rows[edited.id]['edit_ts'])
        self.assertTrue(any(r['text'].startswith('Neu: Bouldern') for r in rows.values()))
        with contextlib.closing(self.db()) as db:
            q = lambda w: db.execute("SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH ?", (w,)).fetchone()[0]
            self.assertEqual(q('woanders'), 1)
            self.assertEqual(q('Examplestrasse'), 0)          # FTS index follows edits
            self.assertEqual(q('Konzerttickets'), 0)       # and deletions

    def test_big_gap_resumes_after_interruption(self):
        f = standard_world()
        s = f.ids['crew']
        self.sync(f, self.cfg)
        climber = f.users[3001]
        for i in range(250):
            f.add_msg(s, 0.9 - i * 0.003, f'gap message {i}', sender=climber)
        orig = T.SyncCtx.deadline_passed
        start = f.history_calls
        T.SyncCtx.deadline_passed = lambda self: f.history_calls >= start + 2   # stop after the first walk page
        try:
            stats = self.sync(f, self.cfg)
        finally:
            T.SyncCtx.deadline_passed = orig
        self.assertTrue(stats['stopped'])
        n1 = len(self.msgs(s))
        self.assertGreater(n1, 150)
        self.assertLess(n1, 400)
        self.sync(f, self.cfg)
        ids = [r['msg_id'] for r in self.msgs(s)]
        self.assertEqual(ids, list(range(1, 401)))         # complete, no gaps, no duplicates

    def test_backfill_is_resumable(self):
        f = standard_world()
        s = f.add_chat('supergroup', 700, 'Big Group')
        u = f.users[3002]
        for i in range(350):
            f.add_msg(s, 350 - i, f'old talk {i}', sender=u)
        calls = []
        orig_h = f.h_messages_GetHistoryRequest

        def counting(req):
            if f._peer_id(req.peer) == s:
                calls.append(1)
            return orig_h(req)
        f.h_messages_GetHistoryRequest = counting
        orig = T.SyncCtx.deadline_passed
        T.SyncCtx.deadline_passed = lambda self: len(calls) >= 2      # first page + one backfill page
        try:
            stats = self.sync(f, self.cfg)
        finally:
            T.SyncCtx.deadline_passed = orig
        self.assertTrue(stats['stopped'])
        self.assertEqual(len(self.msgs(s)), 200)
        self.sync(f, self.cfg)
        self.assertEqual([r['msg_id'] for r in self.msgs(s)], list(range(1, 351)))

    def test_since_then_full(self):
        f = standard_world()
        self.sync(f, self.cfg, since_ts=NOW - 24 * 3600)
        self.assertEqual(len(self.msgs(f.ids['anna'])), 1)            # only the message from 2 h ago
        self.assertEqual(len(self.msgs(f.ids['crew'])), 24)            # hourly messages 1..24 h ago
        self.sync(f, self.cfg)
        self.assertEqual(len(self.msgs(f.ids['anna'])), 4)
        self.assertEqual(len(self.msgs(f.ids['crew'])), 150)

    def test_exclude_include_only_too_large_archived(self):
        f = standard_world()
        self.sync(f, self.cfg)
        a, news, bob = f.ids['anna'], f.ids['news'], f.ids['bob']
        self.assertTrue(self.msgs(a))
        cfg = self.write_config(exclude_chats=[a], include_archived=False, skip_channels_over_members=1000)
        f.full_members[500] = 50000
        f.add_msg(a, 0.2, 'secret new message after exclusion')
        f.names.clear()
        self.sync(f, cfg)
        self.assertEqual(self.msgs(a), [])                             # excluded: purged ...
        self.assertEqual(self.msgs(news), [])                          # too large
        self.assertEqual(self.msgs(bob), [])                           # archived
        with contextlib.closing(self.db()) as db:
            st = {r['chat_id']: r['status'] for r in db.execute('SELECT chat_id, status FROM chats')}
            self.assertEqual(st[a], 'excluded')
            self.assertEqual(st[news], 'too_large')
            self.assertEqual(st[bob], 'archived')
            self.assertEqual(db.execute("SELECT COUNT(*) FROM messages WHERE text LIKE '%secret new%'").fetchone()[0], 0)
        cfg = self.write_config(include_only=['Familie Muster'])
        self.sync(f, cfg)
        with contextlib.closing(self.db()) as db:
            left = {r[0] for r in db.execute('SELECT DISTINCT chat_id FROM messages')}
        self.assertEqual(left, {f.ids['group']})

    def test_excluded_chat_is_never_fetched(self):
        f = standard_world()
        a = f.ids['anna']
        cfg = self.write_config(exclude_chats=['@anna_m'])
        seen = []
        orig = f.h_messages_GetHistoryRequest

        def spy(req):
            seen.append(f._peer_id(req.peer))
            return orig(req)
        f.h_messages_GetHistoryRequest = spy
        self.sync(f, cfg)
        self.assertNotIn(a, seen)
        self.assertEqual(self.msgs(a), [])

    def test_forced_exclude_env_wins_over_config(self):
        """TGREAD_FORCE_EXCLUDE (set by the privacy vault: its bot chat + 777000) can't be undone by the config."""
        f = standard_world()
        a = f.ids['anna']
        os.environ['TGREAD_FORCE_EXCLUDE'] = f'777000, {a},junk,@anna_m,-x'
        try:
            cfg = self.write_config(exclude_chats=[])
            self.assertEqual(cfg['exclude_chats'], [777000, a, '@anna_m'])
            T.save_config({**cfg, 'exclude_chats': []})                  # e.g. `exclude rm`: re-added on load
            self.assertIn(a, T.load_config()['exclude_chats'])
            seen = []
            orig = f.h_messages_GetHistoryRequest

            def spy(req):
                seen.append(f._peer_id(req.peer))
                return orig(req)
            f.h_messages_GetHistoryRequest = spy
            self.sync(f, T.load_config())
            self.assertNotIn(a, seen)
            self.assertEqual(self.msgs(a), [])
            self.assertTrue(self.msgs(f.ids['crew']))
        finally:
            os.environ.pop('TGREAD_FORCE_EXCLUDE', None)
        self.assertEqual(T.forced_excludes(), [])

    def test_small_flood_wait_is_slept_through(self):
        f = standard_world()
        f.flood['messages.GetHistoryRequest'] = [1]
        t0 = time.time()
        self.sync(f, self.cfg)
        self.assertGreaterEqual(time.time() - t0, 0.9)
        self.assertEqual(len(self.msgs(f.ids['crew'])), 150)

    def test_large_flood_wait_saves_progress_and_pauses(self):
        f = standard_world()
        self.write_creds()
        T.ensure_private_dir(T.SECRETS_DIR)
        f.flood['messages.GetHistoryRequest'] = [5000]
        with self.assertRaises(T.TempFail):
            self.sync(f, self.cfg)
        with contextlib.closing(self.db()) as db:
            self.assertEqual(int(T.meta_get(db, 'flood_until')), NOW + 5000)
        T.SESSION_PATH.touch()
        code, out, err = self.run_main('sync', '--quiet')
        self.assertEqual(code, 0)                                      # cron: silent pause, no connection
        self.assertEqual(out + err, '')

    def test_revoked_session_one_inbox_note(self):
        f = standard_world()
        self.sync(f, self.cfg)
        f.logged_in = False
        wire(f)
        code, out, err = self.run_main('sync', '--quiet')
        self.assertEqual(code, 3)
        notes = list((self.home / 'inbox').glob('tgread-auth-*.md'))
        self.assertEqual(len(notes), 1)
        self.assertIn('login-qr', notes[0].read_text())
        code, _, _ = self.run_main('sync', '--quiet')
        self.assertEqual(code, 3)
        self.assertEqual(len(list((self.home / 'inbox').glob('tgread-auth-*.md'))), 1)   # deduplicated

    def test_cron_sync_missing_login_note(self):
        self.write_creds()
        code, out, err = self.run_main('sync', '--quiet')
        self.assertEqual(code, 3)
        self.assertEqual(len(list((self.home / 'inbox').glob('tgread-auth-*.md'))), 1)

    def test_per_chat_error_is_recorded_and_sync_continues(self):
        f = standard_world()
        orig = f.h_messages_GetHistoryRequest

        def flaky(req):
            if f._peer_id(req.peer) == f.ids['group']:
                raise te.ChatAdminRequiredError(request=req)
            return orig(req)
        f.h_messages_GetHistoryRequest = flaky
        stats = self.sync(f, self.cfg)
        self.assertEqual(stats['errors'], 1)
        self.assertEqual(len(self.msgs(f.ids['crew'])), 150)
        with contextlib.closing(self.db()) as db:
            st = db.execute('SELECT status FROM chats WHERE chat_id=?', (f.ids['group'],)).fetchone()[0]
        self.assertTrue(st.startswith('error:'))

    def test_download_profile_and_neutral_filename(self):
        f = standard_world()
        a = f.ids['anna']
        photo = tt.Photo(id=77, access_hash=78, file_reference=b'', date=ts(1), dc_id=2,
                         sizes=[tt.PhotoSize(type='x', w=10, h=10, size=16)])
        mid = f.add_msg(a, 0.1, 'Foto vom Konzert', media=tt.MessageMediaPhoto(photo=photo))
        self.sync(f, self.cfg)
        T.SESSION_PATH.chmod(0o600)
        f.names.clear()
        wire(f)
        code, out, err = self.run_main('download', '--chat', str(a), '--msg', str(mid))
        self.assertEqual(code, 0, err)
        path = Path(out.split('path=')[1].split()[0])
        self.assertEqual(path.name, f'{a}_{mid}.jpg')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn('upload.GetFileRequest', f.names)
        self.assertTrue(set(f.names) <= set(T.PROFILES['download']), f.names)


# ================================================================ login (real client + fake Telegram)
# ================================================================ live listener + event-feed queue
class LiveTests(Base):
    VAULT_BOT = 7012345678

    def setUp(self):
        super().setUp()
        os.environ['TGREAD_FORCE_EXCLUDE'] = f'777000,{self.VAULT_BOT}'
        self.cfg = self.write_config(live_events=True)
        self.api = self.write_creds()

    def tearDown(self):
        os.environ.pop('TGREAD_FORCE_EXCLUDE', None)
        super().tearDown()

    @staticmethod
    def update(f, m, extra=()):
        upd = tt.UpdateNewMessage(message=m, pts=0, pts_count=0)
        marked = tu.get_peer_id(m.peer_id)
        users, chats = f._entities([m], marked if marked in f.chats else None)
        upd._entities = {tu.get_peer_id(x): x for x in list(users) + list(chats) + list(extra)}
        return upd

    def run_live(self, f, inject, seconds=1.5):
        wire(f)
        said = []

        async def go():
            db = T.open_db()
            task = asyncio.ensure_future(T._live_session(self.api, db, self.cfg, sync_minutes=60, max_seconds=seconds,
                                                         say=said.append))
            for _ in range(800):
                if any(s.startswith('SYNC_DONE') for s in said):
                    break
                await asyncio.sleep(0.01)
            for upd in inject(f):
                await f.client._dispatch_update(upd)
            await task
            db.close()
        asyncio.run(go())
        return said

    def queue(self):
        with contextlib.closing(self.db()) as db:
            return [dict(r) for r in db.execute('SELECT * FROM live_queue ORDER BY qid')]

    def test_live_session_stores_queues_and_stays_read_only(self):
        f = standard_world()
        tg_service = f.add_user(777000, 'Telegram')
        vault_bot = f.add_user(self.VAULT_BOT, 'VaultBot', bot=True)
        vb = f.add_chat('bot', user=vault_bot)                    # in the dialogs: the sync marks it excluded
        f.add_msg(vb, 1, 'old approval message', sender=vault_bot)
        newbie = f.add_user(2500, 'Nora', 'Neu', contact=False)
        ids = f.ids

        def inject(f):
            a = f.add_msg(ids['anna'], 0, 'Kannst du morgen um 18 Uhr? Ruf an: +41 79 123 45 67')
            o = f.add_msg(ids['anna'], 0, 'Ja, passt!', out=True)                  # the owner's own reply
            v = f.add_msg(vb, 0, 'Code: 123456 approval', sender=vault_bot)         # the vault's bot chat
            svc = tt.Message(id=9001, peer_id=tt.PeerUser(777000), date=dt.datetime.fromtimestamp(NOW, UTC),
                             message='Login code: 55555. Do not give this code to anyone')
            nm = tt.Message(id=9002, peer_id=tt.PeerUser(2500), date=dt.datetime.fromtimestamp(NOW, UTC),
                            message='Hallo, hier ist Nora vom Kletterkurs: Zahlung bis Freitag?')
            return [self.update(f, f.find(ids['anna'], a)), self.update(f, f.find(ids['anna'], o)),
                    self.update(f, f.find(vb, v)), self.update(f, svc, [tg_service]), self.update(f, nm, [newbie])]
        said = self.run_live(f, inject)
        self.assertIn('LIVE_READY', said)
        self.assertEqual(said.count('LIVE_QUEUED'), 2, said)
        # strictly read-only on the wire: only the read allowlist, nothing blocked
        self.assertTrue(set(f.names) <= set(T.READ_BASE), sorted(set(f.names)))
        self.assertEqual(T.GUARD.blocked, [])
        q = self.queue()
        # the channel post from the feed's first second (catch-up sync), then the pushed incoming ones (allowed chats)
        self.assertEqual([(r['chat_id']) for r in q], [ids['news'], ids['anna'], 2500])
        texts = [m['text'] for m in self.msgs(ids['anna'])]
        self.assertIn('Ja, passt!', texts)                                     # own message archived ...
        self.assertTrue(all(r['msg_id'] != max(m['msg_id'] for m in self.msgs(ids['anna'])) for r in q))  # ... not queued
        self.assertEqual(self.msgs(vb), [])                                    # vault bot chat: never stored
        self.assertEqual(self.msgs(777000), [])                                # Telegram's login codes: never stored
        self.assertEqual([m['text'][:5] for m in self.msgs(2500)], ['Hallo'])  # a brand-new chat is stored
        with contextlib.closing(self.db()) as db:
            self.assertEqual(db.execute('SELECT status FROM chats WHERE chat_id=2500').fetchone()[0], 'sync')
            self.assertGreater(float(T.meta_get(db, 'live_heartbeat')), 0)
            self.assertEqual(int(float(T.meta_get(db, 'live_since'))), NOW)
            # history from the catch-up sync was NOT queued (feed starts now)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM live_queue WHERE ts < ?', (NOW,)).fetchone()[0], 0)
            out = T.live_items(db, T.load_config())
        self.assertEqual(out['source'], 'telegram')
        self.assertEqual(out['owner_name'], 'Lukas Meier')
        self.assertEqual([i['chat_key'] for i in out['items']], [str(ids['news']), str(ids['anna']), '2500'])
        self.assertEqual((out['items'][0]['quiet'], out['items'][0]['public']), ('channel', True))
        a = out['items'][1]
        self.assertEqual((a['chat'], a['sender'], a['chat_type'], a['quiet']), ('Anna', 'Anna', 'user', None))
        self.assertIn('Kannst du morgen um 18 Uhr?', a['text'])
        self.assertNotIn('+41 79 123 45 67', a['text'])                         # regex net before the vault's LLM
        self.assertEqual(out['last_qid'], q[-1]['qid'])
        self.assertEqual(out['pending'], 0)

    def test_live_handler_refuses_guarded_use_outside_live(self):
        tg = ORIG_RO(12345, 'ab' * 16, session=TL.MemorySession())
        with self.assertRaises(T.ReadOnlyViolation):
            tg.on_new_message(lambda e: None)

    def test_sync_queues_only_when_the_feed_is_on_and_only_recent_incoming(self):
        f = standard_world()
        self.sync(f, self.write_config(live_events=False))
        self.assertEqual(self.queue(), [])
        with contextlib.closing(self.db()) as db:
            T.meta_set(db, 'live_since', NOW - 3 * 3600)
        f2 = standard_world()
        a = f2.add_msg(f2.ids['anna'], 1, 'neu: Treffen am Samstag?')
        f2.add_msg(f2.ids['anna'], 0.5, 'meine Antwort', out=True)
        f2.add_msg(f2.ids['news'], 0.2, 'News 20: Riverside beleuchtet')
        f2.add_msg(f2.ids['spam'], 0.3, 'Deal 9: 70% off', sender=f2.users[3000])
        old = f2.add_msg(f2.ids['group'], 5, 'zu alt für den Feed', sender=f2.users[ANNA])
        self.sync(f2, self.write_config(live_events=True))
        q = self.queue()
        self.assertIn((f2.ids['anna'], a), [(r['chat_id'], r['msg_id']) for r in q])
        self.assertTrue(all(r['ts'] >= NOW - 3 * 3600 for r in q))
        self.assertIn('zu alt für den Feed', [m['text'] for m in self.msgs(f2.ids['group'])])   # archived ...
        self.assertNotIn((f2.ids['group'], old), [(r['chat_id'], r['msg_id']) for r in q])     # ... not queued
        with contextlib.closing(self.db()) as db:
            outs = {(r['chat_id'], r['msg_id']) for r in db.execute('SELECT chat_id, msg_id FROM messages WHERE out=1')}
            out = T.live_items(db, T.load_config(), max_items=50)
        self.assertFalse(outs & {(r['chat_id'], r['msg_id']) for r in q})     # never the owner's own
        quiet = {i['chat_key']: i['quiet'] for i in out['items']}
        self.assertEqual(quiet.get(str(f2.ids['news'])), 'channel')            # broadcast: only counted by the vault
        self.assertEqual(quiet.get(str(f2.ids['spam'])), 'muted')              # muted in Telegram: a hint for triage
        self.assertIsNone(quiet.get(str(f2.ids['anna']), 'missing'))
        self.assertNotIn(str(f2.ids['bob']), quiet)                            # archived chat: not synced at all here
        code, so, se = self.run_main('live-items', '--peek', '--after', '0')
        self.assertEqual((code, json.loads(so)['pending']), (0, len(q)), se)
        code, so, se = self.run_main('exclude', 'add', str(f2.ids['anna']))
        self.assertEqual(code, 0, se)
        with contextlib.closing(self.db()) as db:
            out2 = T.live_items(db, T.load_config(), max_items=50)
        self.assertNotIn(str(f2.ids['anna']), {i['chat_key'] for i in out2['items']})   # excluded since: skipped
        code, so, se = self.run_main('live-items', '--max', '0')
        self.assertEqual(code, T.EXIT_USAGE)

    def test_status_shows_the_listener(self):
        f = standard_world()
        self.run_live(f, lambda f: [], seconds=0.5)
        code, so, se = self.run_main('status')
        self.assertEqual(code, 0, se)
        self.assertRegex(so, r'live: listening \(heartbeat .*\); event feed on, queue \d+ message\(s\), last id \d+')
        self.assertIn(f'live ({len(T.READ_BASE)} request types)', so)


class LoginTests(Base):
    def test_qr_refresh_2fa_file_wrong_then_right(self):
        f = standard_world()
        f.logged_in = False
        pw_path = self.home / '.secrets' / 'tgread.2fa'
        f.login = {'exports': 0, 'checks': 0, 'bad_checks': 1, 'pw_path': str(pw_path),
                   'write_pw': ['wrong-one', 'right-one'],
                   'script': [('token', 1.5), ('token', 30, True), ('password',)]}
        self.write_creds()
        wire(f)
        png = self.home / 'qr' / 'login.png'
        seen_png = []
        orig_write = T.write_qr_png

        def spy(url, path):
            orig_write(url, path)
            seen_png.append((url.startswith('tg://login?token='), stat.S_IMODE(os.stat(path).st_mode)))
        T.write_qr_png = spy
        try:
            code, out, err = self.run_main('login-qr', '--out', str(png), '--timeout', '30',
                                           '--password-file', str(pw_path))
        finally:
            T.write_qr_png = orig_write
        self.assertEqual(code, 0, out + err)
        self.assertIn('QR_READY path=', out)
        self.assertIn('QR_REFRESHED', out)
        self.assertIn('PASSWORD_NEEDED hint="first pet"', out)
        self.assertIn('PASSWORD_INVALID attempts_left=2', out)
        self.assertIn('LOGIN_OK user_id=1000', out)
        self.assertNotIn('tg://login', out)                              # the token URL is never printed
        self.assertNotIn('right-one', out + err)
        self.assertEqual(seen_png[:2], [(True, 0o600), (True, 0o600)])
        self.assertFalse(png.exists())                                   # QR image deleted at the end
        self.assertFalse(pw_path.exists())                               # one-time password file shredded
        self.assertEqual(stat.S_IMODE(os.stat(T.SESSION_PATH).st_mode), 0o600)
        self.assertTrue(set(f.names) <= set(T.PROFILES['login']), sorted(set(f.names)))
        self.assertEqual(f.login['checks'], 2)
        with contextlib.closing(self.db()) as db:
            self.assertEqual(T.meta_get(db, 'me_name'), 'Lukas Meier')

    def test_qr_success_without_2fa(self):
        f = standard_world()
        f.logged_in = False
        f.login = {'exports': 0, 'checks': 0, 'bad_checks': 0, 'script': [('token', 30, True), ('success',)]}
        self.write_creds()
        wire(f)
        code, out, err = self.run_main('login-qr', '--timeout', '20')
        self.assertEqual(code, 0, out + err)
        self.assertIn('LOGIN_OK', out)
        self.assertNotIn('PASSWORD_NEEDED', out)
        self.assertFalse(T.QR_DEFAULT.exists())
        code, out, err = self.run_main('login-qr')
        self.assertIn('ALREADY_LOGGED_IN', out)

    def test_password_file_must_be_private(self):
        p = self.home / 'pw'
        lines = []

        async def go():
            p.write_text('leaky\n')
            os.chmod(p, 0o644)

            async def later():
                await asyncio.sleep(0.5)
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.write(fd, b'good\n')
                os.close(fd)
            task = asyncio.create_task(later())
            pw = await T.read_password_file(p, 10, lines.append, poll=0.1)
            await task
            return pw
        self.assertEqual(asyncio.run(go()), 'good')
        self.assertTrue(any(x.startswith('PASSWORD_FILE_REJECTED') for x in lines))
        self.assertFalse(p.exists())


# ================================================================ masking
class MaskTests(unittest.TestCase):
    def m(self, s):
        return T.mask_text(s)

    def assertMasked(self, text, raw, tag):
        out = self.m(text)
        self.assertNotIn(raw, out, out)
        self.assertIn(tag, out, out)

    def assertKept(self, text):
        self.assertEqual(self.m(text), text)

    def test_phones(self):
        for p in ('+41 79 123 45 67', '079 123 45 67', '0041791234567', '+49 (0) 30 1234567', '044 668 18 00',
                  '+1 (415) 555-2671', '079/123 45 67', '+41791234567', '078.123.45.67'):
            self.assertMasked(f'ruf an: {p} danke', p, '[PHONE]')
        out = self.m('Nummern: 079 123 45 67 / 078 765 43 21')
        self.assertEqual(out.count('[PHONE]'), 2, out)

    def test_emails(self):
        self.assertMasked('mail an anna.muster@gmail.com bitte', 'anna.muster@gmail.com', '[EMAIL]')
        self.assertMasked('x a+b@sub.example.ch.', 'a+b@sub.example.ch', '[EMAIL]')
        self.assertKept('ping @anna_m oder foo@bar')

    def test_iban_ahv_cards_accounts(self):
        for iban in ('CH93 0076 2011 6238 5295 7', 'CH9300762011623852957', 'DE89 3704 0044 0532 0130 00'):
            self.assertMasked(f'IBAN {iban} ok', iban, '[IBAN]')
        self.assertMasked('AHV 756.1234.5678.97', '756.1234.5678.97', '[AHV]')
        self.assertMasked('AHV-Nr 7561234567897.', '7561234567897', '[AHV]')
        visa = card('4111')                               # secretscan (runs first) already redacts real IINs
        grouped = ' '.join(visa[i:i + 4] for i in range(0, 16, 4))
        for v in (grouped, visa):
            out = self.m(f'Karte {v} bis 12/28')
            self.assertNotIn(v, out)
            self.assertTrue('[CARD]' in out or '[redacted]' in out, out)
        other = card('9123')                              # Luhn-valid, IIN unknown to secretscan
        grouped = ' '.join(other[i:i + 4] for i in range(0, 16, 4))
        self.assertMasked(f'Karte {grouped} bis 12/28', grouped, '[CARD]')
        self.assertMasked(f'Karte {other}', other, '[CARD]')
        self.assertMasked('Ref 12345678901234567890', '12345678901234567890', '[NUMBER]')
        self.assertMasked('PC-Konto 80-470-3', '80-470-3', '[ACCOUNT]')
        self.assertMasked('Kontonummer: 1234 5678 90', '1234 5678 90', '[ACCOUNT]')

    def test_addresses(self):
        for a in ('Examplestrasse 12, 1234 Exampletown', 'Bahnhofstrasse 1', 'Hauptstr. 7a', 'Obere Gasse 3',
                  'Im Gässli 5', 'Rue du Marché 12', '12, rue de Lausanne', 'Via Nassa 5', '221B Baker Street',
                  'CH-8001 Zürich', 'Postfach 123', 'Zur Linde 4', 'Langstrasse 120, 8004 Zürich'):
            out = self.m(f'Adresse: {a}. Bis bald')
            self.assertIn('[ADDRESS]', out, f'{a} -> {out}')
            self.assertNotIn(a, out)
            self.assertTrue(out.endswith('. Bis bald'), out)                  # the sentence's period survives
        kept = T.mask_text('Ich wohne an der Examplestrasse 12, 1234 Exampletown, Tel. 079 123 45 67', addresses=False)
        self.assertIn('Examplestrasse 12, 1234 Exampletown', kept)                 # llm-local policy v2 path
        self.assertIn('[PHONE]', kept)

    def test_coordinates_and_secrets(self):
        self.assertMasked('bin hier 47.3769, 8.5417 jetzt', '47.3769, 8.5417', '[LOCATION]')
        for s, raw in (('Passwort: hunter2', 'hunter2'), ('WLAN-Passwort ist Sommer2024!', 'Sommer2024!'),
                       ('Code: 4711', '4711'), ('pin=8890', '8890'), ('PIN 1234 bitte', '1234'),
                       ('password: s3cr3t', 's3cr3t'), ('Türcode: 4711', '4711'), ('Zugangscode ist 8890', '8890'),
                       ('Alarmcode = 1357', '1357'), ('Wi-Fi password is hunter2', 'hunter2')):
            self.assertMasked(s, raw, '[SECRET]')
        self.assertKept('Dresscode: schwarz')

    def test_urls(self):
        self.assertKept('schau https://www.example.com/artikel/zuerich-rhein')
        self.assertKept('https://www.youtube.com/watch?v=dQw4w9WgXcQ')
        for u, host in (('https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUv/view?usp=sharing',
                         'drive.google.com'),
                        ('https://x.com/reset?token=abc', 'x.com'), ('https://t.me/+AbCdEf123', 't.me'),
                        ('https://t.me/joinchat/AAAAAEk', 't.me'), ('https://chat.whatsapp.com/Abc', 'chat.whatsapp.com'),
                        ('https://user:pw@host.example.com/x', 'host.example.com'),
                        ('https://wa.me/41791234567', 'wa.me'),
                        ('https://maps.google.com/?q=47.3769,8.5417', 'maps.google.com'),
                        ('https://shop.ch/order?email=a@b.ch', 'shop.ch'),
                        ('https://zoom.us/j/1234567890?pwd=abc', 'zoom.us')):
            self.assertMasked(f'link: {u} .', u, f'[URL:{host}]')
        self.assertMasked('tg://login?token=AbC', 'tg://login?token=AbC', '[URL:tg]')

    def test_secretscan_stage(self):
        self.assertMasked(f'my token is {FAKE_SECRET} ok', FAKE_SECRET, '[redacted]')

    def test_no_false_positives(self):
        for s in ('Konzert am 12.10.2026 um 18:30, CHF 45.50', 'Treffen 2026-10-12 18:00', 'Kosten 1\'250.- total',
                  'Fr. 20 pro Person', 'Server 198.51.100.5 läuft', 'Telethon 1.45.0', 'es hat +3°C', '50% off',
                  'Exampletown', 'am Montag 3 Bier', 'Im Mai 2026', 'Zum Glück 2 Tickets',
                  'Am Freitag 20 Uhr', 'Zimmer 0815', 'Order 12345', 'Bus 33 um 7:45', 'Seite 12 von 30',
                  'climb session 120 at the gym', 'Auf der Arbeit 2 Stunden', 'Tel. Nr. kommt noch'):
            self.assertKept(s)

    def test_long_digit_runs_stay_fast(self):
        t = time.monotonic()
        for s in ('1' * 4096, '1 ' * 2048, 'a1' * 2048, '+' + '4' * 4000):
            T.mask_text(s)
            T._WORD_RE.findall(s)
        self.assertLess(time.monotonic() - t, 2.0)


# ================================================================ pseudonyms / presenter
class PresenterTests(Base):
    def setUp(self):
        super().setUp()
        self.write_config()
        f = standard_world()
        f.add_user(2004, 'Anna', 'Keller', contact=True)               # a second Anna, with a private chat
        f.add_msg(f.add_chat('user', user=f.users[2004]), 7, 'Hallo von der anderen Anna')
        f.add_user(2005, 'Will', 'Smith')
        f.add_msg(f.add_chat('user', user=f.users[2005]), 6, 'yo')
        self.sync(f, T.load_config())
        self.f = f

    def test_aliases_stable_and_owner_is_you(self):
        with contextlib.closing(self.db()) as db:
            pr = T.Presenter(db, 'alias')
            chats = T.chat_map(db)
            a1 = pr.chat_label(chats[ANNA])
            self.assertRegex(a1, r'^Person [A-Z]+$')
            self.assertEqual(T.Presenter(db, 'alias').chat_label(chats[ANNA]), a1)   # stable
            row = db.execute('SELECT * FROM messages WHERE chat_id=? AND out=1', (ANNA,)).fetchone()
            self.assertEqual(pr.sender_label(row, chats[ANNA]), 'You')
            self.assertEqual(pr.chat_label(chats[self.f.ids['self']]), 'Saved Messages')
            self.assertEqual(pr.chat_label(chats[self.f.ids['bot']]), 'WeatherBot')  # bots keep names
            peter = db.execute('SELECT * FROM messages WHERE sender_id=?', (PETER,)).fetchone()
            pr2 = T.Presenter(db, 'alias', T.focus_ids([peter]))
            p_alias = pr2.sender_label(peter, chats[self.f.ids['group']])
            self.assertRegex(p_alias, r'^Person [A-Z]+$')
            text = pr2.scrub('Lukas Meier und Peter Muster treffen Bob Keller; Lukas bringt Peters Velo')
            self.assertNotIn('Lukas', text)
            self.assertNotIn('Peter', text)
            self.assertNotIn('Bob Keller', text)
            self.assertIn('You', text)
            self.assertIn(f"{p_alias}'s Velo", text)

    def test_ambiguous_common_and_unknown(self):
        with contextlib.closing(self.db()) as db:
            pr = T.Presenter(db, 'alias')
            self.assertIn('[NAME]', pr.scrub('Anna kommt'))                    # two close Annas
            self.assertNotIn('Muster', pr.scrub('Anna Muster kommt'))           # full name is unique
            self.assertEqual(pr.scrub('i will go'), 'i will go')                # common word, lower case
            self.assertNotIn('Will ', pr.scrub('Will kommt'))
            self.assertIn('[USERNAME]', pr.scrub('frag @someone_else'))
            self.assertNotIn('anna_m', pr.scrub('frag @anna_m'))
            self.assertIn('[URL:instagram.com]', pr.scrub('https://instagram.com/peter.muster.fotos'))
            self.assertEqual(T.mask_text(T.Presenter(db, 'alias', [ANNA]).scrub('Mail anna.muster@gmail.com ok')),
                             'Mail [EMAIL] ok')                                 # emails stay whole for the mask
            climber = db.execute('SELECT * FROM messages WHERE sender_id=3001').fetchone()
            pc = T.Presenter(db, 'alias', T.focus_ids([climber]), T.chat_ids([climber]))
            alias = pc.sender_label(climber)
            self.assertEqual(pc.scrub('Climber1 Fels kommt'), f'{alias} kommt')    # digits inside a name
            self.assertEqual(pc.scrub('climber1 kommt'), f'{alias} kommt')
            self.assertNotIn('Climber2', pc.scrub('Climber2 auch'))           # fellow poster of the small group
            self.assertEqual(pr.scrub('Climber2 auch'), 'Climber2 auch')        # not close to this output
            pr_real = T.Presenter(db, 'real')
            self.assertEqual(pr_real.scrub('Anna kommt'), 'Anna kommt')
            self.assertEqual(pr_real.scrub_leftovers('Anna Muster said hi to Lukas'), '[NAME] said hi to You')


# ================================================================ CLI output path (subprocess, stub llm-local)
class CliTests(Base):
    PII = ('+41 79 123 45 67', 'anna.muster@gmail.com', 'CH93 0076', 'Examplestrasse 12', '044 668 18 00', '4711',
           '8890', 'redaktion@localnews.example')
    NAMES = ('Anna', 'Muster', 'Lukas', 'Meier', 'Peter', 'Keller')

    def setUp(self):
        super().setUp()
        self.write_config()
        self.f = standard_world()
        self.sync(self.f, T.load_config())

    def assertClean(self, out, names=True, addresses=True):
        for v in self.PII:
            if addresses or v != 'Examplestrasse 12':
                self.assertNotIn(v, out)
        if names:
            for n in self.NAMES:
                self.assertNotIn(n, out)

    def test_default_goes_through_local_llm_with_premasked_input(self):
        env = self.install_stub(mapping='Lukas Meier=You;Lukas=You')     # llm-local policy v2: names stay
        p = self.cli('recent', '-n', '200', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertClean(p.stdout, names=False, addresses=False)
        self.assertIn('[PHONE]', p.stdout)
        self.assertIn('[EMAIL]', p.stdout)
        self.assertIn('[IBAN]', p.stdout)
        self.assertIn('Examplestrasse 12, 1234 Exampletown', p.stdout)        # addresses pass (policy v2)
        self.assertNotIn('[ADDRESS]', p.stdout)
        self.assertIn('Anna Muster', p.stdout)                           # names pass: no [NAME] net
        self.assertNotIn('[NAME]', p.stdout)
        self.assertIn(T.FOOTER_LLM, p.stdout)
        self.assertNotIn('WARNING', p.stdout)
        calls = self.stub_calls()
        self.assertEqual(len(calls), 1)                                  # one call: consistent output
        self.assertEqual(calls[0]['args'], ['--anonymize', '--owner-name', 'Lukas Meier'])
        sent = calls[0]['stdin']
        self.assertIn('Anna Muster', sent)                               # exact names go to the LOCAL model
        self.assertIn('Examplestrasse 12', sent)                            # and addresses
        for v in self.PII[:-1]:
            if v != 'Examplestrasse 12':
                self.assertNotIn(v, sent)                                # but phone numbers etc. never do
        self.assertNotIn('Rhein News', sent)                             # public channel skips the LLM
        self.assertIn('Rhein News', p.stdout)
        self.assertLess(p.stdout.index('### Rhein News'), p.stdout.index('### Climbing Crew'))   # order kept
        self.assertIn('[EMAIL]', p.stdout)

    def test_llm_leak_is_caught_by_regex_and_name_net(self):
        env = self.install_stub(mode='leak', mapping='Lukas=You')
        p = self.cli('search', 'Kuchen', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn('079 765 43 21', p.stdout)
        self.assertNotIn('leak.person@example.org', p.stdout)
        self.assertIn('regards Anna Muster and Peter', p.stdout)         # policy v2: names are not a leak
        self.write_config(local_llm_anonymize_args=['--anonymize', '--strict'])
        env = self.install_stub(mode='leak', mapping='Anna Muster=Person A;Anna=Person A;Peter Muster=Person B;'
                                                     'Peter=Person B;Lukas=You')
        p = self.cli('search', 'Kuchen', env=env)      # Peter is not in this output but posts in its small group
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn('079 765 43 21', p.stdout)
        self.assertNotIn('leak.person@example.org', p.stdout)
        self.assertNotIn('Anna Muster', p.stdout)
        self.assertIn('regards [NAME] and [NAME]', p.stdout)

    def test_paraphrase_args_pass_through_with_their_footer(self):
        # vault policy v4: the vault sets --paraphrase in both arg lists; tgread passes them on
        # unchanged and says so in the footer
        self.write_config(local_llm_anonymize_args=['--anonymize', '--paraphrase'],
                          local_llm_summary_args=['--summary', '--paraphrase'])
        env = self.install_stub(mapping='Lukas Meier=You;Lukas=You')
        p = self.cli('recent', '-n', '200', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertClean(p.stdout, names=False, addresses=False)
        self.assertIn(T.FOOTER_LLM_PARA, p.stdout)
        self.assertNotIn(T.FOOTER_LLM, p.stdout)
        self.assertEqual(self.stub_calls()[-1]['args'], ['--anonymize', '--paraphrase', '--owner-name', 'Lukas Meier'])
        p = self.cli('summarize', '--hours', '48', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.stub_calls()[-1]['args'][:2], ['--summary', '--paraphrase'])

    def test_strict_mode_keeps_the_old_name_net_and_address_masks(self):
        self.write_config(local_llm_anonymize_args=['--anonymize', '--strict'],
                          local_llm_summary_args=['--summary', '--strict'])
        env = self.install_stub(mapping='Anna Muster=Person A;Anna=Person A;Peter Muster=Person B;Peter=Person B')
        p = self.cli('recent', '-n', '200', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertClean(p.stdout)
        self.assertIn('[ADDRESS]', p.stdout)
        self.assertIn(T.FOOTER_LLM_STRICT, p.stdout)
        call = self.stub_calls()[-1]
        self.assertEqual(call['args'], ['--anonymize', '--strict', '--owner-name', 'Lukas Meier'])
        self.assertNotIn('Examplestrasse 12', call['stdin'])               # addresses masked before the LLM
        p = self.cli('summarize', '--hours', '48', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertClean(p.stdout)
        self.assertEqual(self.stub_calls()[-1]['args'][:2], ['--summary', '--strict'])

    def test_fallback_when_llm_fails_or_missing(self):
        env = self.install_stub(mode='fail')
        p = self.cli('unread-summary-data', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith('WARNING: local LLM anonymizer unavailable (llm-local exited with 3'))
        self.assertClean(p.stdout)
        self.assertIn('Person ', p.stdout)
        self.assertIn(T.FOOTER_FALLBACK, p.stdout)
        shutil.rmtree(self.home / 'bin')
        p = self.cli('search', 'Nummer', env=env)
        self.assertTrue(p.stdout.startswith('WARNING: local LLM anonymizer unavailable (~/bin/llm-local is not '
                                            'installed'), p.stdout)
        self.assertClean(p.stdout)
        for mode in ('empty',):
            env = self.install_stub(mode=mode)
            p = self.cli('recent', env=env)
            self.assertIn('WARNING: local LLM anonymizer unavailable', p.stdout)
            self.assertClean(p.stdout)
        self.write_config(llm_fallback=False)                            # strict mode: nothing, exit 6
        env = self.install_stub(mode='fail')
        p = self.cli('recent', env=env)
        self.assertEqual(p.returncode, 6, p.stderr)
        self.assertEqual(p.stdout, '')
        self.assertIn('llm_fallback is false', p.stderr)

    def test_disabled_llm_warns(self):
        self.write_config(use_local_llm=False)
        env = self.install_stub()
        p = self.cli('recent', env=env)
        self.assertTrue(p.stdout.startswith('WARNING: the local LLM anonymizer is disabled'))
        self.assertClean(p.stdout)
        self.assertEqual(self.stub_calls(), [])

    def test_oversized_llm_input_is_refused_with_advice(self):
        self.write_config(local_llm_max_chars=1000)
        env = self.install_stub()
        p = self.cli('recent', '-n', '200', env=env)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn('too much for the local LLM anonymizer', p.stderr)
        self.assertIn('--llm-max-chars', p.stderr)
        self.assertEqual(p.stdout, '')
        self.assertEqual(self.stub_calls(), [])                        # nothing was sent, no silent fallback
        p = self.cli('summarize', env=env)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(self.stub_calls(), [])
        p = self.cli('recent', '-n', '200', '--llm-max-chars', '100000', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stderr, r'tgread: local LLM anonymizer: \d+ characters, expect ~\d+ (s|min)')
        self.assertEqual(len(self.stub_calls()), 1)

    def test_unread_selection(self):
        env = self.install_stub(mapping='Anna Muster=Person A;Anna=Person A')
        p = self.cli('unread-summary-data', '--hours', '24', env=env)
        out = p.stdout
        self.assertIn('Treffpunkt Bahnhof', out)                         # unread, 2 h ago
        self.assertNotIn('Ich wohne jetzt', out)                         # read
        self.assertNotIn('Deal 0', out)                                  # muted chat left out
        self.assertNotIn('archivierter Chat', out)                       # archived chat left out
        self.assertIn('climb session 150', out)
        self.assertNotIn('climb session 140 ', out)                      # read up to 140
        self.assertNotIn('Velo service', out)                            # Saved Messages are not "unread"
        self.assertIn('muted and archived chats left out', out)
        p = self.cli('unread-summary-data', '--include-muted', env=env)
        self.assertIn('Deal 0', p.stdout)

    def test_summarize(self):
        shutil.rmtree(self.home / 'bin', ignore_errors=True)
        p = self.cli('summarize', '--hours', '48')
        self.assertEqual(p.returncode, 6)
        self.assertIn('not installed', p.stderr)
        env = self.install_stub(mapping='Lukas Meier=You;Lukas=You')
        p = self.cli('summarize', '--hours', '48', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('SUMMARY:', p.stdout)
        self.assertClean(p.stdout, names=False, addresses=False)        # policy v2: names/addresses stay
        self.assertNotIn('[NAME]', p.stdout)
        call = self.stub_calls()[-1]
        self.assertEqual(call['args'][:1], ['--summary'])
        self.assertIn('--owner-name', call['args'])
        self.assertIn('Rhein News', call['stdin'])                       # summaries include public channels
        p = self.cli('summarize', '--chat', 'Familie Muster', '--hours', '48', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('1 chat(s)', p.stdout)

    def test_window_counts_only(self):
        # plan v2 #4: the vault plans its chunked summaries from `window`: ids and numbers, never text or names
        p = self.cli('window', '--hours', '48')
        self.assertEqual(p.returncode, 0, p.stderr)
        w = json.loads(p.stdout)
        for word in ('Kuchen', 'Anna', 'Familie', 'Climbing', 'Rhein', 'Treffpunkt', 'climb session'):
            self.assertNotIn(word, p.stdout)
        self.assertGreaterEqual(len(w['chats']), 4)                      # archived Bob and the self chat left out
        self.assertEqual([c['last_ts'] for c in w['chats']], sorted((c['last_ts'] for c in w['chats']), reverse=True))
        self.assertEqual(w['msgs'], sum(c['msgs'] for c in w['chats']))
        self.assertEqual(sum(d['msgs'] for d in w['chats'][0]['days']), w['chats'][0]['msgs'])
        self.assertTrue(all(set(c) == {'chat_id', 'msgs', 'chars', 'first_ts', 'last_ts', 'days', 'total', 'unread'}
                            for c in w['chats']))
        self.assertTrue(all(c['chat_id'].lstrip('-').isdigit() for c in w['chats']))   # strings: JSON survives the net
        fam = self.cli('window', '--hours', '48', '--chats', 'Familie Muster')
        f = json.loads(fam.stdout)
        self.assertEqual((len(f['chats']), f['msgs']), (1, 3), fam.stderr)
        cap = json.loads(self.cli('window', '--hours', '48', '--per-chat', '5').stdout)
        crew = max(cap['chats'], key=lambda c: c['total'])
        self.assertEqual((crew['msgs'], crew['total'] > 5), (5, True))
        since = w['since']
        until = since + 24 * 3600
        part = json.loads(self.cli('window', '--since', f'@{since}', '--until', f'@{until}').stdout)
        self.assertEqual((part['since'], part['until']), (since, until))
        self.assertTrue(all(since <= c['first_ts'] and c['last_ts'] < until for c in part['chats']))
        self.assertLess(part['msgs'], w['msgs'])
        bad = self.cli('window', '--since', f'@{until}', '--until', f'@{since}')
        self.assertEqual(bad.returncode, 2)

    def test_summarize_parts_options(self):
        # the vault's chunks: --chats + --since/--until + --no-counts (no unread counts in the LLM's text: stable)
        env = self.install_stub(mapping='Lukas Meier=You;Lukas=You')
        since = json.loads(self.cli('window', '--hours', '48').stdout)['since']
        p = self.cli('summarize', '--chats', 'Familie Muster', 'Climbing Crew', '--since', f'@{since}', '--no-counts',
                     env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertRegex(p.stdout, r'^Summary of \d+ message\(s\) in 2 chat\(s\), since \d{4}-\d\d-\d\d \d\d:\d\d ')
        sent = self.stub_calls()[-1]['stdin']
        self.assertIn('Familie Muster', sent)
        self.assertNotIn('Rhein News', sent)
        self.assertNotIn('unread', sent)
        self.assertNotIn('last 48 h', sent)
        p2 = self.cli('summarize', '--chats', 'Familie Muster', 'Climbing Crew', '--since', f'@{since}', '--no-counts',
                      env=env)
        self.assertEqual(self.stub_calls()[-1]['stdin'], sent)            # same messages, same text: cache-friendly
        p = self.cli('summarize', '--chat', 'Familie Muster', '--chats', 'Climbing Crew', env=env)
        self.assertEqual(p.returncode, 2)
        p = self.cli('summarize', '--hours', '48', env=env)              # the old form is unchanged
        self.assertRegex(p.stdout, r'^Summary of \d+ message\(s\) in \d+ chat\(s\), last 48 h ')
        self.assertIn('unread', self.stub_calls()[-1]['stdin'])

    def test_raw_is_exact(self):
        p = self.cli('search', 'Nummer', '--raw')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.startswith('RAW OUTPUT'))
        self.assertIn('+41 79 123 45 67', p.stdout)
        self.assertIn('Anna Muster', p.stdout)

    def test_vault_reads_expand_json_no_paraphrase(self):
        # plan v2 #10: --expand matches word variants (Swiss German / German / English, ue = ü, word starts)
        q = T.build_fts_query('Hochzeit Fritig', expand=True)
        self.assertIn('"hochziit"*', q)
        self.assertIn('"freitag"*', q)
        self.assertIn('wedding', T.expand_word('Hochziit'))
        self.assertIn('junggesellenabschied', T.expand_word('jga'))
        self.assertIn('fuer', T.expand_word('für'))
        env = self.install_stub()
        p = self.cli('search', 'Kuchen', '--expand', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('hit(s)', p.stdout)
        # the vault's own raw reads: --json only together with --raw
        p = self.cli('search', 'Kuchen', '--json', env=env)
        self.assertEqual(p.returncode, 2)
        p = self.cli('search', 'Kuchen', '--expand', '--raw', '--json', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        hits = json.loads(p.stdout)['hits']
        self.assertTrue(hits and all({'chat_id', 'chat', 'msg_id', 'ts', 'line'} <= set(h) for h in hits))
        self.assertTrue(any('Kuchen' in h['line'] for h in hits))
        # plan v2 #6: --no-paraphrase drops only the paraphrase from the anonymizer's args
        self.write_config(local_llm_anonymize_args=['--anonymize', '--paraphrase'])
        p = self.cli('recent', '-n', '3', '--no-paraphrase', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        args = self.stub_calls()[-1]['args']
        self.assertIn('--anonymize', args)
        self.assertNotIn('--paraphrase', args)
        p = self.cli('recent', '-n', '3', env=env)
        self.assertIn('--paraphrase', self.stub_calls()[-1]['args'])

    def test_chats_listing(self):
        p = self.cli('chats')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertClean(p.stdout)
        self.assertIn('Climbing Crew', p.stdout)
        self.assertIn('Saved Messages', p.stdout)
        crew = str(tu.get_peer_id(tt.PeerChannel(400)))                     # -1000000000400: ids stay exact
        self.assertIn(crew, p.stdout)
        self.assertNotIn('[NUMBER]', p.stdout)
        p2 = self.cli('recent', '--chat', crew, '-n', '3', env=self.install_stub())
        self.assertIn(f'(supergroup, chat {crew})', p2.stdout)
        p2 = self.cli('recent', '--chat', crew, '-n', '3', env=self.install_stub(mode='fail'))
        self.assertIn(f'(supergroup, chat {crew})', p2.stdout)
        p = self.cli('chats', '--grep', 'anna')                          # matches the real title, shows the alias
        self.assertEqual(len([x for x in p.stdout.splitlines() if 'user' in x]), 1)
        self.assertClean(p.stdout)
        p = self.cli('chats', '--no-pseudonyms')
        self.assertIn('Anna Muster', p.stdout)

    def test_search_by_name_and_context(self):
        env = self.install_stub(mapping='Anna Muster=Person A;Anna=Person A;Peter Muster=Person B;Peter=Person B')
        p = self.cli('search', 'Kuchen', '--from', 'Anna', '--context', '1', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('1 hit(s)', p.stdout)
        self.assertIn('<== match', p.stdout)
        self.assertIn('Gerne!', p.stdout)                                 # context line before the hit
        p = self.cli('search', 'climb', '--chat', 'Climbing Crew', '-n', '3', env=env)
        self.assertIn('3 hit(s)', p.stdout)
        p = self.cli('search', 'xyzzy-nothing', env=env)
        self.assertIn('0 hit(s)', p.stdout)

    def test_exclude_purge_and_list(self):
        p = self.cli('exclude', 'add', 'Familie Muster')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('deleted 3 stored message(s)', p.stdout)
        self.assertNotIn('Muster', p.stdout)
        cfg = json.loads(T.CONFIG_PATH.read_text())
        self.assertEqual(cfg['exclude_chats'], [self.f.ids['group']])
        self.assertEqual(self.msgs(self.f.ids['group']), [])
        p = self.cli('exclude', 'list')
        self.assertIn(str(self.f.ids['group']), p.stdout)
        p = self.cli('exclude', 'rm', str(self.f.ids['group']))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(T.CONFIG_PATH.read_text())['exclude_chats'], [])
        p = self.cli('purge', 'Climbing Crew')
        self.assertEqual(p.returncode, 2)
        p = self.cli('purge', 'Climbing Crew', '--yes')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"tgread exclude add {self.f.ids['crew']})", p.stdout)   # the hint keeps the exact id
        self.assertEqual(self.msgs(self.f.ids['crew']), [])
        p = self.cli('exclude', 'add', '@nobody_known')                 # not yet seen: still recorded
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('@nobody_known', json.loads(T.CONFIG_PATH.read_text())['exclude_chats'])

    def test_status_allowlist_wipe(self):
        p = self.cli('status')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('archive:', p.stdout)
        self.assertIn('cron:', p.stdout)
        self.assertIn('local LLM: unavailable', p.stdout)
        p = self.cli('allowlist')
        self.assertIn('messages.GetHistoryRequest', p.stdout)
        self.assertNotIn('SendMessage', p.stdout.split('Everything else')[0])
        p = self.cli('wipe', '--all')
        self.assertEqual(p.returncode, 2)
        p = self.cli('wipe', '--all', '--yes')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(T.DB_PATH.exists())
        self.assertFalse(T.SESSION_PATH.exists())
        self.assertIn('Settings > Devices', p.stdout)

    def test_no_raw_values_anywhere_in_default_outputs(self):
        env = self.install_stub(mode='fail')
        outs = []
        for args in (('recent', '-n', '500'), ('search', 'Nummer'), ('search', 'IBAN'), ('search', 'Examplestrasse'),
                     ('unread-summary-data', '--hours', '1000', '--include-read', '--include-muted',
                      '--include-archived'), ('chats', '--all'), ('exclude', 'list')):
            p = self.cli(*args, env=env)
            self.assertEqual(p.returncode, 0, (args, p.stderr))
            outs.append(p.stdout + p.stderr)
        blob = '\n'.join(outs)
        self.assertClean(blob)



# ================================================================ media list, chat directory, id shield (2026-10-13)
class MediaDirectoryTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg = self.write_config()
        self.f = standard_world()
        a = self.f.users[ANNA]
        self.dive = self.f.add_chat('group', 301, 'Grouptrip 2026')
        doc = tt.Document(id=91, access_hash=92, file_reference=b'', date=ts(1), mime_type='application/pdf',
                          size=184000, dc_id=2, attributes=[tt.DocumentAttributeFilename(file_name='ExampleAir_eticket.pdf')])
        self.doc_mid = self.f.add_msg(self.dive, 3, 'Hier das Ticket, Madeira Tauchen', sender=a,
                                      media=tt.MessageMediaDocument(document=doc))
        self.f.add_msg(self.dive, 2, 'Tauchen am Riff, Treffpunkt 07:30', sender=self.f.users[PETER])
        self.sync(self.f, self.cfg)
        with contextlib.closing(self.db()) as db:
            self.fam = db.execute("SELECT chat_id FROM chats WHERE title='Familie Muster'").fetchone()[0]
            self.crew = db.execute("SELECT chat_id FROM chats WHERE title='Climbing Crew'").fetchone()[0]

    def test_media_list_metadata_only_and_new_columns(self):
        row = [m for m in self.msgs(self.dive) if m['msg_id'] == self.doc_mid][0]
        self.assertEqual((row['media_size'], row['media_mime']), (184000, 'application/pdf'))
        code, out, err = self.run_main('media', '--chat', str(self.dive), '--json')
        self.assertEqual(code, 0, err)
        d = json.loads(out)
        self.assertEqual(d['chat']['id'], self.dive)
        self.assertEqual([(i['msg'], i['type'], i['name'], i['size'], i['mime']) for i in d['items']],
                         [(self.doc_mid, 'document', 'ExampleAir_eticket.pdf', 184000, 'application/pdf')])
        code, out, err = self.run_main('media', '--chat', str(self.dive))
        self.assertEqual(code, 0, err)
        self.assertIn('ExampleAir_eticket.pdf', out)
        self.assertNotIn('Hier das Ticket', out)                       # no message text
        with contextlib.closing(self.db()) as db:                     # older rows: facts unknown, then filled
            db.execute('UPDATE messages SET media_size=NULL, media_mime=NULL WHERE msg_id=?', (self.doc_mid,))
            db.commit()
        row = dict(row, media_size=184000, media_mime='application/pdf')    # seen again by a sync: facts only
        with contextlib.closing(self.db()) as db:
            self.assertEqual(T.upsert_message(db, row), 'same')
            db.commit()
        row = [m for m in self.msgs(self.dive) if m['msg_id'] == self.doc_mid][0]
        self.assertEqual(row['media_size'], 184000)

    def test_migration_adds_columns_to_an_old_db(self):
        p = self.home / 'old.db'
        with contextlib.closing(T.sqlite3.connect(str(p))) as db:
            db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL, msg_id INTEGER '
                       'NOT NULL, ts INTEGER NOT NULL, date TEXT NOT NULL, sender_id INTEGER, sender_name TEXT, out '
                       'INTEGER NOT NULL DEFAULT 0, text TEXT NOT NULL DEFAULT \'\', reply_to INTEGER, media_type TEXT, '
                       'media_desc TEXT, fwd_from TEXT, fwd_from_id INTEGER, service TEXT, edit_ts INTEGER, '
                       'UNIQUE(chat_id, msg_id))')
            db.commit()
        with contextlib.closing(T.open_db(p)) as db:
            cols = {r[1] for r in db.execute('PRAGMA table_info(messages)')}
        self.assertTrue({'media_size', 'media_mime', 'media_duration'} <= cols)

    def test_download_reports_original_name(self):
        T.SESSION_PATH.chmod(0o600)
        wire(self.f)
        code, out, err = self.run_main('download', '--chat', str(self.dive), '--msg', str(self.doc_mid))
        self.assertEqual(code, 0, err)
        self.assertIn('name="ExampleAir_eticket.pdf"', out)
        self.assertIn('mime=application/pdf', out)
        self.assertEqual(Path(out.split('path=')[1].split()[0]).name, f'{self.dive}_{self.doc_mid}.pdf')

    def test_alias_round_trip_resolution_and_cleanup(self):
        code, out, err = self.run_main('alias', 'set', str(self.dive), 'Dive  Group', '--tag', 'Tauchen')
        self.assertEqual(code, 0, err)
        self.assertIn('dive group', out)
        code, out, err = self.run_main('media', '--chat', 'DIVE group', '--json')     # alias wherever --chat is
        self.assertEqual((code, json.loads(out)['chat']['id']), (0, self.dive), err)
        code, out, err = self.run_main('alias', 'list')
        self.assertIn('dive group [tag tauchen] -> Grouptrip 2026', out)
        for bad in ('12345', 'me', 'Person B', '@x'):
            self.assertEqual(self.run_main('alias', 'set', str(self.dive), bad)[0], T.EXIT_USAGE, bad)
        self.assertEqual(self.run_main('alias', 'rm', 'dive group')[0], 0)
        self.assertNotEqual(self.run_main('media', '--chat', 'dive group')[0], 0)
        self.run_main('alias', 'set', str(self.dive), 'dive group')
        self.assertEqual(self.run_main('purge', str(self.dive), '--yes')[0], 0)
        with contextlib.closing(self.db()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM chat_aliases').fetchone()[0], 0)

    def test_find_chat_ranking_no_text_excluded_never(self):
        self.run_main('alias', 'set', str(self.crew), 'kletterhalle')
        code, out, err = self.run_main('find-chat', 'kletterhalle')
        self.assertEqual(code, 0, err)
        lines = [x for x in out.splitlines()[1:] if x.strip()]
        self.assertIn('Climbing Crew', lines[0])
        self.assertIn('alias kletterhalle', lines[0])
        code, out, err = self.run_main('find-chat', 'Madeira tauchen')
        lines = [x for x in out.splitlines()[1:] if x.strip()]
        self.assertIn('Grouptrip 2026', lines[0])                         # content hits
        self.assertNotIn('Hier das Ticket', out)
        self.assertNotIn('Riff', out)
        code, out, err = self.run_main('find-chat', 'grouptrip')          # title beats content
        self.assertIn('match: title', out)
        with contextlib.closing(self.db()) as db:
            db.execute("UPDATE chats SET status='excluded' WHERE chat_id=?", (self.dive,))
            db.commit()
        code, out, err = self.run_main('find-chat', 'grouptrip tauchen')
        self.assertNotIn('Grouptrip', out)
        self.assertNotEqual(self.run_main('media', '--chat', str(self.dive))[0], 0)    # excluded: refused

    def test_who_dm_groups_and_cap(self):
        code, out, err = self.run_main('who', 'Anna Muster')
        self.assertEqual(code, 0, err)
        self.assertIn(f"DM chat {self.f.ids['anna']}", out)
        self.assertIn(f' {self.fam}  group', out)
        self.assertIn('Grouptrip 2026', out)
        self.assertNotIn('Kuchen', out)
        old = T.WHO_MAX_GROUPS
        T.WHO_MAX_GROUPS = 1
        try:
            code, out, err = self.run_main('who', 'Anna Muster')
        finally:
            T.WHO_MAX_GROUPS = old
        self.assertIn('… and 1 more group(s)', out)

    def test_id_shield_keeps_chat_ids_from_the_llm(self):
        env = self.install_stub(mapping=f'chat {self.dive}=chat [phone];#{self.doc_mid}=#[phone]')
        p = self.cli('recent', '--chat', str(self.dive), '-n', '5', env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f'chat {self.dive})', p.stdout)
        self.assertIn(f'(#{self.doc_mid})', p.stdout)
        self.assertNotIn('[phone]', p.stdout)
        sent = self.stub_calls()[-1]['stdin']
        self.assertNotIn(str(self.dive), sent)
        self.assertIn('chat C1)', sent)

class PeopleStatsTests(Base):
    """Vault memory plan C2 (15.10): `people-stats` (vault-internal, JSON) -> DM contacts with >= --min messages in
    --days: counts and dates only, never text; bots, the owner, excluded and force-excluded chats never appear."""
    ZOE, MAX = 2004, 2005

    def setUp(self):
        super().setUp()
        os.environ['TGREAD_FORCE_EXCLUDE'] = '777000'
        self.write_config()

    def tearDown(self):
        os.environ.pop('TGREAD_FORCE_EXCLUDE', None)
        super().tearDown()

    def world(self):
        f = standard_world()
        for i in range(12):                              # Anna: 12 more in the last 12 days (4 of them his)
            f.add_msg(f.ids['anna'], 24 * (i + 1), f'Hallo {i} Geheimwort', out=i % 3 == 0)
        zoe = f.add_user(self.ZOE, 'Zoe', 'Beispiel')
        z = f.add_chat('user', user=zoe)
        for i in range(3):                               # below the threshold
            f.add_msg(z, 10 + i, f'Zoe {i} Geheimwort')
        mx = f.add_user(self.MAX, 'Max', 'Probe')
        m = f.add_chat('user', user=mx)
        for i in range(11):                              # 11 messages 100..110 days ago: in the year, not in 90 days
            f.add_msg(m, 24 * (100 + i), f'Max {i} Geheimwort', out=i == 0)
        return f

    def stats(self, *argv):
        code, out, err = self.run_main('people-stats', *argv)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_counts_and_dates_only(self):
        self.sync(self.world())
        r = self.stats()
        self.assertEqual((r['source'], r['min'], r['days'], r['now']), ('telegram', 10, 365, NOW))
        by = {p['uid']: p for p in r['people']}
        self.assertEqual(sorted(by), [ANNA, self.MAX])  # Zoe (3), Bob (archived), Peter (no DM), bot, owner: none
        a = by[ANNA]
        self.assertEqual(set(a), {'uid', 'name', 'in30', 'out30', 'in90', 'out90', 'in365', 'out365', 'last_in',
                                  'last_out', 'first_ts', 'groups_shared'})
        self.assertEqual((a['in30'], a['out30'], a['in365'], a['out365']), (11, 5, 11, 5))
        self.assertEqual((a['last_in'], a['last_out']), (NOW - 2 * 3600, NOW - 24 * 3600))
        self.assertEqual((a['name'], a['groups_shared']), ('Anna Muster', 1))      # posted in "Familie Muster"
        mx = by[self.MAX]
        self.assertEqual((mx['in30'], mx['in90'], mx['in365'], mx['out365']), (0, 0, 10, 1))
        self.assertEqual(r['people'][0]['uid'], ANNA)    # most recent first
        blob = json.dumps(r)
        for bad in ('Geheimwort', 'Hallo', 'Kuchen', '+41 79'):
            self.assertNotIn(bad, blob)
        self.assertEqual([p['uid'] for p in self.stats('--min', '12', '--days', '30')['people']], [ANNA])
        self.assertEqual(self.stats('--min', '200')['people'], [])
        self.assertEqual(self.run_main('people-stats', '--min', '0')[0], T.EXIT_USAGE)

    def test_excluded_and_forced_excludes_never_appear(self):
        self.sync(self.world())
        code, out, err = self.run_main('exclude', 'add', str(self.MAX))
        self.assertEqual(code, 0, err)
        self.assertEqual([p['uid'] for p in self.stats()['people']], [ANNA])
        os.environ['TGREAD_FORCE_EXCLUDE'] = f'777000,{ANNA}'
        self.assertEqual(self.stats()['people'], [])


class IndexRowsTests(Base):
    """Vault memory plan C3 (15.10): `index-rows` (vault-internal, raw JSON for the embedding index): DMs and groups
    only, oldest row first, paged by row id; channels, bots, self, excluded and force-excluded chats never appear.
    `fts-query`: the expressions of `search --expand` for a list of queries (no data access)."""

    def setUp(self):
        super().setUp()
        os.environ['TGREAD_FORCE_EXCLUDE'] = '777000'
        self.write_config()

    def tearDown(self):
        os.environ.pop('TGREAD_FORCE_EXCLUDE', None)
        super().tearDown()

    def rows(self, *argv):
        code, out, err = self.run_main('index-rows', *argv)
        self.assertEqual(code, 0, err)
        return json.loads(out)

    def test_dm_and_groups_only_paged(self):
        self.sync(standard_world())
        r = self.rows('--max', '5000')
        kinds = {x['chat']: x['kind'] for x in r['rows']}
        self.assertTrue(r['rows'])
        self.assertNotIn(-1000000000500, kinds)            # the channel
        self.assertEqual(set(kinds.values()) <= {'dm', 'group'}, True)
        self.assertIn('dm', kinds.values())
        self.assertIn('group', kinds.values())
        x = r['rows'][0]
        self.assertEqual(set(x), {'id', 'chat', 'msg', 'ts', 'edit_ts', 'out', 'sid', 'sender', 'kind', 'text'})
        ids = [x['id'] for x in r['rows']]
        self.assertEqual(ids, sorted(ids))
        self.assertTrue(all(x['sender'] == 'me' for x in r['rows'] if x['out']))
        self.assertTrue(all(x['text'] for x in r['rows']))
        chats = {x['chat'] for x in r['rows']}
        db = T.open_db()
        types = {row['chat_id']: row['type'] for row in db.execute('SELECT chat_id, type FROM chats')}
        self.assertTrue(all(types[c] in ('user', 'group', 'supergroup') for c in chats), chats)
        p1 = self.rows('--max', '3')                        # paging: the next page starts after `last`
        p2 = self.rows('--after-rowid', str(p1['last']), '--max', '5000')
        self.assertEqual([x['id'] for x in p1['rows'] + p2['rows']], ids)
        self.assertEqual(self.run_main('index-rows', '--max', '0')[0], T.EXIT_USAGE)

    def test_c4_chat_tail_chats_and_lines(self):
        """C4: --chat/--since-ts (one chat's tail), --chats (ids only), index-lines (search-style hits, only
        indexable chats, oldest first)."""
        self.sync(standard_world())
        allr = self.rows('--max', '5000')['rows']
        chat = allr[0]['chat']
        mine = [x for x in allr if x['chat'] == chat]
        cut = mine[len(mine) // 2]['ts']
        tail = self.rows('--chat', str(chat), '--since-ts', str(cut))['rows']
        self.assertTrue(tail)
        self.assertEqual([x['id'] for x in tail], [x['id'] for x in mine if x['ts'] >= cut])
        self.assertEqual(self.run_main('index-rows', '--since-ts', '5')[0], T.EXIT_USAGE)   # needs --chat
        code, out, err = self.run_main('index-rows', '--chats')
        self.assertEqual(code, 0, err)
        ids = json.loads(out)['chats']
        self.assertEqual(set(ids), set(ids) | {x['chat'] for x in allr})
        self.assertTrue(all(isinstance(x, int) for x in ids))
        self.assertNotIn(-1000000000500, ids)               # the channel
        pairs = [[x['chat'], x['msg']] for x in allr[:3]] + [[-1000000000500, 1], [chat, 999999]]
        code, out, err = self.run_main('index-lines', stdin=io.StringIO(json.dumps(pairs)))
        self.assertEqual(code, 0, err)
        hits = json.loads(out)['hits']
        self.assertEqual(len(hits), 3)                      # the channel and a missing message are skipped
        self.assertEqual(set(hits[0]), {'chat_id', 'chat', 'chat_type', 'msg_id', 'ts', 'line'})
        self.assertEqual([h['ts'] for h in hits], sorted(h['ts'] for h in hits))
        self.assertTrue(all(h['line'].startswith('[') and f"(#{h['msg_id']}" in h['line'] for h in hits))
        for bad in ('{"x": 1}', '[[1]]', '[["a", 2]]', json.dumps([[1, 2]] * 401)):
            self.assertEqual(self.run_main('index-lines', stdin=io.StringIO(bad))[0], T.EXIT_USAGE, bad)

    def test_excluded_chats_never_appear(self):
        self.sync(standard_world())
        code, out, err = self.run_main('exclude', 'add', str(ANNA))
        self.assertEqual(code, 0, err)
        self.assertNotIn(ANNA, {x['chat'] for x in self.rows()['rows']})

    def test_fts_query(self):
        code, out, err = self.run_main('fts-query', stdin=io.StringIO(json.dumps(['Grillfest Samstag', '!!'])))
        self.assertEqual(code, 0, err)
        got = json.loads(out)
        self.assertEqual(len(got), 2)
        self.assertIn(' AND ', got[0])
        self.assertIsNone(got[1])
        code, out, err = self.run_main('fts-query', '--any', stdin=io.StringIO(json.dumps(['Grill Samstag'])))
        self.assertIn(' OR ', json.loads(out)[0])
        self.assertEqual(self.run_main('fts-query', stdin=io.StringIO('{"no": 1}'))[0], T.EXIT_USAGE)


if __name__ == '__main__':
    try:
        unittest.main(verbosity=1)
    finally:
        shutil.rmtree(ROOT, ignore_errors=True)
