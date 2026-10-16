#!/usr/bin/python3 -I
"""Person cards v1 (vault memory plan C2, 2026-10-15), invented fixtures only: metadata cards from tgread's
people-stats (fields, display rules: his alias wins, first names, honorific -> someone; keyed pseudonyms, never the
id), the D3 cap (<= 20 shown) and filters, relation only from the owner (`p:` buttons in the vault bot, owner chat
only, nonce + message checked, <= 20 questions a day (env VAULT_PEOPLE_ASKS_PER_DAY); my relay with a silent FYI + Undo), forget/unforget, purge
hooks (purge/exclude drop the derived cards, wipe deletes people.db), the nightly 03:00 tick, the switches
(VAULT_PEOPLE, VAULT_PEOPLE_ASK), privacy invariants (no text route, every string through the regex net, audit
holds pseudonyms only, people-stats unreachable by the API, cards never fed into prompts), and the CLI.
Run: python3 -I tests/test_people.py (uses test_vault.py's fakes)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402
import datetime as dt  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402
import people as PP  # noqa: E402

V, D, S = TV.V, TV.D, TV.S
DAY = 86400
NOW = int(time.time())
APP_DIR = Path(TV.ROOT) / 'app'


def person(uid, name, last_in_d, last_out_d, in30=6, out30=5, first_d=300, groups=1):
    return {'uid': uid, 'name': name, 'in30': in30, 'out30': out30, 'in90': in30 + 3, 'out90': out30 + 2,
            'in365': in30 + 10, 'out365': out30 + 8,
            'last_in': NOW - last_in_d * DAY if last_in_d is not None else None,
            'last_out': NOW - last_out_d * DAY if last_out_d is not None else None,
            'first_ts': NOW - first_d * DAY, 'groups_shared': groups}


FIXTURE = ([person(5001, 'Anna Beispiel', 2, 3, 41, 37, first_d=340, groups=3),
            person(5002, 'Herr Huber', 10, 12),
            person(5003, 'Lea Test', 1, 1),             # his alias for this DM chat: "Mami"
            person(5004, 'Anna Zweite', 40, 45),       # a second Anna: ambiguous by name
            person(5005, 'Beat Fake', 200, 210)]       # no contact for 200 days
           + [person(6000 + i, f'Zed{chr(97 + i)} Fake', 60 + i, 61 + i) for i in range(22)])
REAL_BITS = ('Beispiel', 'Huber', 'Lea', 'Zweite', '5001', '5003', '6000', 'Fake')
ALIASES = 'Mami -> Lea Test (user, chat 5003)\n'


def strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)


class PeopleBase(TV.ApiBase):
    name = 'api-people'
    extra_env = {'VAULT_PEOPLE': '1', 'VAULT_PEOPLE_ASK': '1'}

    def setUp(self):
        super().setUp()
        if not self.app.store.is_set('telegram'):       # set after the vault started: a new bot, polled
            self.app.store.set('telegram', {'bot_token': TV.BOT_TOKEN, 'chat_id': TV.CHAT_ID})
        self.argvs, self.stats = [], [dict(p) for p in FIXTURE]

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            self.argvs.append(list(argv))
            if argv[0] == 'people-stats':
                return 0, json.dumps({'source': 'telegram', 'now': NOW, 'min': 10, 'days': 365,
                                      'people': self.stats}), ''
            if argv[0] == 'alias':
                return 0, ALIASES, ''
            return 0, 'ok\n', ''
        self.app.tg._exec = fake_exec
        self.app.tg._aliases = None
        self.app.tg.ensure_config = lambda: False
        pp = self.app.people
        if pp._db is not None or pp.path.exists():
            pp.db().executescript('DELETE FROM relations; DELETE FROM forgotten; DELETE FROM asks;')
        pp.build('test')
        TV.TELEGRAM.updates = []
        TV.TELEGRAM.fail = False
        self.app.approval.step()                         # a bot set after the first start: polled from now on

    def cards(self, **q):
        qs = '&'.join(f'{k}={v}' for k, v in q.items())
        st, r = self.call('GET', '/people' + (f'?{qs}' if qs else ''))
        self.assertEqual(st, 200, r)
        return r

    def key_of(self, uid):
        return self.app.people.pkey(uid)

    def show(self, who):
        return self.call('POST', '/people/show', {'person': who})

    def press(self, data, mid, chat=TV.CHAT_ID, frm=None):
        TV.TELEGRAM.press(data, mid, chat=chat, frm=frm)
        self.app.approval.step()

    def people_audit(self):
        return [e for e in self.app.audit.read(days=1, limit=500) if e['event'].startswith('people_')]


class CardTests(PeopleBase):
    def test_list_fields_only_cap_order_and_net(self):
        r = self.cards()
        self.assertEqual((r['shown'], r['matching'], r['total']), (20, 27, 27))
        self.assertEqual([c['person'] for c in r['cards'][:3]], ['Mami', 'Anna', 'someone'])
        for c in r['cards']:
            self.assertEqual(set(c), {'person', 'key', 'relation', 'last_contact', 'messages_30d'})
            self.assertTrue(PP.KEY_RE.fullmatch(c['key']), c['key'])
        self.assertEqual(len({c['key'] for c in r['cards']}), 20)
        a = r['cards'][1]
        self.assertEqual(a['messages_30d'], {'in': 41, 'out': 37})
        self.assertEqual(a['last_contact']['from_them'], dt.datetime.fromtimestamp(NOW - 2 * DAY, V.TZ).date().isoformat())
        self.assertEqual(r['scope'], {'source': 'telegram DMs', 'min_messages': 10, 'days': 365, 'max_shown': 20})
        blob = json.dumps(r)
        for bad in REAL_BITS:
            self.assertNotIn(bad, blob)
        for s in strings(r):
            self.assertEqual(self.app.policy.regex_net(s), s)     # every string passes the regex net unchanged
        act = self.cards(active='30d')
        self.assertEqual([c['person'] for c in act['cards']], ['Mami', 'Anna', 'someone'])
        self.assertEqual(self.cards(n=2)['shown'], 2)
        for q in ('n=21', 'n=0', 'active=soon', 'relation=boss'):
            st, e = self.call('GET', f'/people?{q}')
            self.assertEqual((st, e['code']), (400, 'bad_param'), q)
        ev = self.people_audit()
        self.assertTrue(any(e['event'] == 'people_list' and e['count'] == 2 for e in ev))
        self.assertTrue(any(e['event'] == 'people_build' and e['cards'] == 27 for e in ev))
        st, s = self.call('GET', '/status')
        self.assertEqual((s['people']['enabled'], s['people']['ask'], s['people']['cards']), (True, True, 27))

    def test_show_card_display_rules_and_ambiguity(self):
        st, e = self.show('anna')
        self.assertEqual((st, e['code']), (409, 'ambiguous'))
        self.assertIn(self.key_of(5001), e['error'])
        st, r = self.show(self.key_of(5001))
        self.assertEqual(st, 200, r)
        c = r['card']
        self.assertEqual((c['person'], c['dm'], c['groups_shared'], c['relation']), ('Anna', True, 3, None))
        self.assertEqual(c['messages'], {'30d': {'in': 41, 'out': 37}, '90d': {'in': 44, 'out': 39},
                                         '365d': {'in': 51, 'out': 45}})
        self.assertEqual(c['dm_since'], dt.datetime.fromtimestamp(NOW - 340 * DAY, V.TZ).strftime('%Y-%m'))
        self.assertIn('never message text', c['note'])
        self.assertEqual(self.show('MAMI')[1]['card']['key'], self.key_of(5003))     # his alias wins
        self.assertEqual(self.show('Lea')[0], 404)                                   # the real name is not a handle
        self.assertEqual(self.show('someone')[1]['card']['key'], self.key_of(5002))  # "Herr Huber" -> someone
        self.assertEqual(self.show('nobody')[0], 404)
        self.assertEqual(self.show('x\x07y')[0], 400)
        self.assertEqual(self.show('')[0], 400)
        blob = json.dumps(self.people_audit())
        for bad in ('Mami', 'Anna', 'someone') + REAL_BITS:
            self.assertNotIn(bad, blob)                  # the audit holds pseudonyms only
        self.assertIn(self.key_of(5001), blob)

    def test_keys_are_keyed_pseudonyms(self):
        k = self.key_of(5001)
        self.assertNotIn('5001', k)
        self.assertEqual(k, self.app.people.pkey(5001))
        other = PP.People(self.cfg, None, None, None, b'another-key' * 3)
        self.assertNotEqual(other.pkey(5001), k)


class RelationTests(PeopleBase):
    name = 'api-people-rel'

    def ask(self, who):
        st, r = self.call('POST', '/people/relation', {'person': who})
        self.assertEqual(st, 200, r)
        return r, 100 + len(TV.TELEGRAM.sent), TV.TELEGRAM.sent[-1]

    def rel(self, who):
        return self.show(who)[1]['card']['relation']

    def test_question_buttons_owner_tap_only(self):
        r, mid, sent = self.ask('Mami')
        self.assertEqual((r['asked'], r['person'], r['key'], r['questions_left_today']), (True, 'Mami',
                                                                                         self.key_of(5003), 19))
        self.assertIn('👤 Who is Mami to you?', sent['text'])
        self.assertEqual(sent['protect_content'], 'true')
        rows = json.loads(sent['reply_markup'])['inline_keyboard']
        data = [b['callback_data'] for row in rows for b in row]
        self.assertEqual(len(data), 9)
        self.assertTrue(all(PP.CB_RE.fullmatch(d) and len(d) <= 64 for d in data))
        fr = next(d for d in data if d.endswith(':fr'))
        r2, _, _ = self.ask('Mami')                      # an open question: not asked twice
        self.assertFalse(r2['asked'])
        self.assertEqual(len(TV.TELEGRAM.sent), mid - 100)
        self.press(fr, mid, chat='555', frm='555')       # another chat: ignored
        self.press(fr, mid, frm='555')                   # someone else in the owner chat: ignored
        self.press(fr[:-11] + '00000000:fr', mid)        # wrong nonce
        self.press(fr, mid + 7)                          # another message
        self.assertIsNone(self.rel('Mami'))
        self.press(fr, mid)
        self.assertEqual({k: v for k, v in self.rel('Mami').items() if k != 'at'}, {'value': 'friend', 'by': 'owner_tap'})
        self.assertIn('Mami = 🤝 Friend ✓', TV.TELEGRAM.method_calls('editMessageText')[-1]['text'])
        self.press(fr.replace(':fr', ':fa'), mid)        # answered: stays friend
        self.assertEqual(self.rel('Mami')['value'], 'friend')
        self.assertEqual(TV.TELEGRAM.method_calls('answerCallbackQuery')[-1]['text'], 'Already answered')
        self.assertEqual([c['person'] for c in self.cards(relation='friend')['cards']], ['Mami'])
        self.assertEqual(self.cards(relation='set')['matching'], 1)
        self.assertEqual(self.cards(relation='unset')['matching'], 26)
        acts = [(e.get('value'), e.get('by')) for e in self.people_audit() if e['event'] == 'people_relation']
        self.assertIn(('friend', 'owner_tap'), acts)
        refused = [e for e in self.app.audit.read(days=1, limit=500) if e['event'] in ('people_callback_refused',
                                                                                       'raw_callback_refused')]
        self.assertGreaterEqual(len(refused), 3)
        # skip, then the daily cap (default 20, env VAULT_PEOPLE_ASKS_PER_DAY; 5 here to keep the fixture small)
        self.assertEqual((PP.ASKS_PER_DAY, self.app.people.asks_per_day, self.cfg.people_asks_per_day), (20, 20, 20))
        for raw, want in (('7', 7), ('0', 1), ('500', 100), ('x', 20)):
            self.assertEqual(V.Config({**os.environ, 'VAULT_PEOPLE_ASKS_PER_DAY': raw}).people_asks_per_day, want)
        self.app.people.asks_per_day = 5
        r, mid2, sent2 = self.ask(self.key_of(5001))
        sk = next(b['callback_data'] for row in json.loads(sent2['reply_markup'])['inline_keyboard'] for b in row
                  if b['callback_data'].endswith(':sk'))
        self.press(sk, mid2)
        self.assertIsNone(self.rel(self.key_of(5001)))
        for who in ('someone', 'Zeda', 'Zedb'):
            self.ask(who)
        st, e = self.call('POST', '/people/relation', {'person': 'Zedc'})
        self.assertEqual((st, e['code']), (429, 'rate_limited'))

    def test_relay_fyi_and_undo(self):
        st, r = self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'family'})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['relation']['value'], r['relation']['by'], r['previous'], r['confirmed_to_owner']),
                         ('family', 'assistant_relay', None, True))
        sent, mid = TV.TELEGRAM.sent[-1], 100 + len(TV.TELEGRAM.sent)
        self.assertIn('Claude set Mami = family', sent['text'])
        self.assertEqual(sent['disable_notification'], 'true')
        undo = json.loads(sent['reply_markup'])['inline_keyboard'][0][0]['callback_data']
        self.assertTrue(undo.endswith(':un'))
        self.press(undo, mid)
        self.assertIsNone(self.rel('Mami'))
        self.assertIn('Undone', TV.TELEGRAM.method_calls('editMessageText')[-1]['text'])
        # his tap, then my relay, then his Undo: back to his own value
        r, mid, sent = self.ask('Mami')
        self.press(next(b['callback_data'] for row in json.loads(sent['reply_markup'])['inline_keyboard']
                        for b in row if b['callback_data'].endswith(':fr')), mid)
        self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'colleague'})
        self.assertEqual(self.rel('Mami')['by'], 'assistant_relay')
        undo = json.loads(TV.TELEGRAM.sent[-1]['reply_markup'])['inline_keyboard'][0][0]['callback_data']
        self.press(undo, 100 + len(TV.TELEGRAM.sent))
        self.assertEqual((self.rel('Mami')['value'], self.rel('Mami')['by']), ('friend', 'owner_tap'))
        st, r = self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'unset'})
        self.assertEqual((st, r.get('relation'), r['previous']), (200, None, 'friend'))
        self.assertIsNone(self.rel('Mami'))
        st, e = self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'boss'})
        self.assertEqual((st, e['code']), (400, 'bad_param'))
        TV.TELEGRAM.fail = True                          # no FYI to him -> nothing set
        try:
            st, e = self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'family'})
        finally:
            TV.TELEGRAM.fail = False
        self.assertEqual((st, e['code']), (502, 'notify_failed'))
        self.assertIsNone(self.rel('Mami'))

    def test_expired_question(self):
        r, mid, sent = self.ask('someone')
        fr = next(b['callback_data'] for row in json.loads(sent['reply_markup'])['inline_keyboard'] for b in row
                  if b['callback_data'].endswith(':fr'))
        self.app.people.db().execute('UPDATE asks SET sent = sent - ?', (PP.ASK_DAYS * DAY + 60,))
        self.press(fr, mid)
        self.assertIsNone(self.rel('someone'))
        self.assertEqual(TV.TELEGRAM.method_calls('answerCallbackQuery')[-1]['text'], 'This question expired')


class ForgetPurgeTests(PeopleBase):
    name = 'api-people-forget'

    def test_forget_and_unforget(self):
        self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'family'})
        st, r = self.call('POST', '/people/forget', {'person': 'Mami'})
        self.assertEqual((st, r['forgotten'], r['key']), (200, True, self.key_of(5003)))
        self.assertEqual(self.show('Mami')[0], 404)
        self.assertEqual(self.cards()['total'], 26)
        self.call('POST', '/people/rebuild', {})
        self.assertNotIn('Mami', [c['person'] for c in self.cards(active='30d')['cards']])
        self.assertEqual(self.app.people.db().execute('SELECT COUNT(*) FROM relations').fetchone()[0], 0)
        st, e = self.call('POST', '/people/forget', {'person': 'Zeda', 'undo': True})
        self.assertEqual((st, e['code']), (404, 'not_found'))
        st, r = self.call('POST', '/people/forget', {'person': 'mami', 'undo': True})
        self.assertEqual((st, r['forgotten']), (200, False))
        self.assertEqual(self.show('Mami')[1]['card']['relation'], None)            # back, without the old relation
        st, r = self.call('POST', '/people/forget', {'person': self.key_of(5002)})
        st, r = self.call('POST', '/people/forget', {'person': self.key_of(5002), 'undo': True})
        self.assertEqual(st, 200, r)
        self.assertEqual(self.cards()['total'], 27)
        acts = [e['action'] for e in self.people_audit() if e['event'] == 'people_forget']
        self.assertEqual(acts.count('forget'), 2)

    def test_purge_drops_cards_wipe_deletes_db(self):
        self.call('POST', '/people/relation', {'person': 'Mami', 'relation': 'family'})
        self.app.tg.run('purge', {'chat': '5003', 'yes': True})
        self.assertTrue(self.app.people.dirty)
        self.assertEqual(self.app.people.db().execute('SELECT COUNT(*) FROM cards').fetchone()[0], 0)
        self.stats = [p for p in self.stats if p['uid'] != 5003]                     # the archive lost that chat
        self.assertEqual(self.cards()['total'], 26)                                # rebuilt on the next read
        self.assertEqual(self.app.people.db().execute('SELECT COUNT(*) FROM relations').fetchone()[0], 1)
        self.app.tg.run('exclude', {'action': 'add', 'chats': ['5001']})
        self.assertTrue(self.app.people.dirty)
        self.app.tg.run('wipe', {'session': True, 'yes': True})                     # session only: cards stay
        self.assertTrue(self.app.people.path.exists())
        self.app.tg.run('wipe', {'data': True, 'yes': True})
        self.assertFalse(self.app.people.path.exists())
        self.assertEqual(self.cards()['total'], 26)
        self.assertEqual(self.app.people.db().execute('SELECT COUNT(*) FROM relations').fetchone()[0], 0)
        self.assertIn('people_purge', [e['event'] for e in self.people_audit()])
        self.assertEqual(os.stat(self.app.people.path).st_mode & 0o777, 0o600)


class TickTests(unittest.TestCase):
    """The nightly rebuild at 03:00 Zurich, a first build, a rebuild after a purge; nothing while logged out."""

    def test_tick(self):
        class FakeTG:
            calls, logged = 0, True

            def logged_in(self):
                return self.logged

            def people_stats(self, m, d):
                self.calls += 1
                return {'people': [person(7001, 'Nora Fake', 1, 1)]}

            def alias_map(self):
                return {}

        class Audit:
            events = []

            def log(self, event, **kw):
                self.events.append(dict(kw, event=event))
        t = [dt.datetime(2026, 10, 16, 1, 0, tzinfo=V.TZ).timestamp()]
        tg, au = FakeTG(), Audit()
        pp = PP.People(TV.make_cfg('people-tick', VAULT_PEOPLE='1'), tg, None, au, b'k' * 32,
                       clock=lambda: t[0], log=lambda m: None)
        tg.logged = False
        pp.tick()
        self.assertEqual(tg.calls, 0)                    # no archive yet: nothing
        tg.logged = True
        pp.tick()
        self.assertEqual(tg.calls, 1)                    # first build
        for hh, mm, want in ((2, 59, 1), (3, 1, 2), (3, 30, 2), (23, 0, 2)):
            t[0] = dt.datetime(2026, 10, 16, hh, mm, tzinfo=V.TZ).timestamp()
            pp.tick()
            self.assertEqual(tg.calls, want, (hh, mm))
        t[0] = dt.datetime(2026, 10, 17, 3, 0, 30, tzinfo=V.TZ).timestamp()
        pp.tick()
        self.assertEqual(tg.calls, 3)
        pp.on_purge('exclude', {'action': 'add'})
        pp.tick()
        self.assertEqual(tg.calls, 4)
        self.assertEqual([e['reason'] for e in au.events if e['event'] == 'people_build'],
                         ['first', 'nightly', 'nightly', 'purge'])


class PeopleOffTests(TV.ApiBase):
    name = 'api-people-off'

    def test_switch_off(self):
        for method, path, body in (('GET', '/people', None), ('POST', '/people/show', {'person': 'x'}),
                                   ('POST', '/people/relation', {'person': 'x'}),
                                   ('POST', '/people/forget', {'person': 'x'}), ('POST', '/people/rebuild', {})):
            st, e = self.call(method, path, body)
            self.assertEqual((st, e['code']), (409, 'people_off'), path)
        self.assertEqual(self.call('GET', '/status')[1]['people'], {'enabled': False, 'ask': False})
        self.app.people.tick()
        self.app.people.on_purge('wipe', {'data': True})
        self.assertFalse(self.app.people.path.exists())  # nothing stored while off


class AskOffTests(PeopleBase):
    name = 'api-people-askoff'
    extra_env = {'VAULT_PEOPLE': '1'}

    def test_relation_trigger_off(self):
        n = len(TV.TELEGRAM.sent)
        for body in ({'person': 'Mami'}, {'person': 'Mami', 'relation': 'friend'}):
            st, e = self.call('POST', '/people/relation', body)
            self.assertEqual((st, e['code']), (409, 'relation_ask_off'))
        self.assertEqual(len(TV.TELEGRAM.sent), n)       # the owner got nothing
        self.assertEqual(self.cards()['total'], 27)       # cards still work


class InvariantTests(unittest.TestCase):
    def test_no_text_path_and_no_feedback(self):
        for path in ('/people', '/people/show', '/people/relation', '/people/forget', '/people/rebuild'):
            self.assertNotIn(path, D.TEXT_ROUTES)
            self.assertNotIn(path, V.TAP_RAW_ROUTES)
        self.assertNotIn('people-stats', S.TG_SPECS)    # vault-internal: no /tg/<command> reaches it
        self.assertTrue({'person', 'relation', 'active', 'undo'} <= V.TAP_SAFE_KEYS)
        self.assertNotIn('people', {op for op in TV.J.OPS})
        for f in ('answer.py', 'facts.py', 'sessions.py', 'find.py'):
            src = (APP_DIR / f).read_text('utf-8')
            self.assertNotIn('import people', src, f)   # cards are output only: never in a prompt (plan §7)
        self.assertEqual((V.Config({'VAULT_PEOPLE': '1'}).people, V.Config({}).people), (True, False))
        self.assertEqual((V.Config({'VAULT_PEOPLE_ASK': '1'}).people_ask, V.Config({}).people_ask), (True, False))
        self.assertEqual(set(PP.CODES.values()), set(PP.RELATIONS))
        self.assertEqual(PP.MAX_SHOW, 20)
        self.assertEqual((PP.MIN_MSGS, PP.DAYS), (10, 365))


class PeopleTgRouteTests(PeopleBase):
    name = 'api-people-tg'

    def test_people_stats_not_reachable(self):
        st, e = self.call('POST', '/tg/people-stats', {})
        self.assertIn(st, (400, 404), e)
        self.assertFalse([a for a in self.argvs if a[:1] == ['people-stats'] and st == 200])

    def test_z_cli(self):
        """~/bin/vault people ... -> this in-process vault: lines of fields, no real names (invented values)."""
        if not (TV.CLI_DIR / 'vault').exists():
            self.skipTest('no ~/bin/vault client here (inside the image)')
        home = TV.TMP / 'cli-people-home'
        (home / 'bin').mkdir(parents=True, exist_ok=True)
        if not (home / 'bin' / 'vault').exists():
            (home / 'bin' / 'vault').symlink_to(TV.CLI_DIR / 'vault')
        tok = TV.TMP / 'cli-people-token'
        tok.write_text(TV.TOKEN + '\n')
        tok.chmod(0o600)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'VAULT_URL': self.url, 'VAULT_TOKEN_FILE': str(tok)}

        def run(*args):
            return subprocess.run([str(home / 'bin' / 'vault'), 'people', *args], env=env, capture_output=True,
                                  text=True, timeout=60)
        p = run('--active', '30d')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('👤 3 of 3 card(s) (27 in all)', p.stdout)
        self.assertIn(f'- Mami [{self.key_of(5003)}] · - · last: them ', p.stdout)
        self.assertIn('30d: 41 in / 37 out', p.stdout)
        p = run('show', 'Mami')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('relation: not set (only he sets it)', p.stdout)
        self.assertIn('messages in/out: 30d 6/5 · 90d 9/7 · 365d 16/13', p.stdout)
        p = run('show', 'Anna')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('use the key', p.stderr + p.stdout)
        p = run('relation', 'Mami', 'friend')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('set Mami = friend (assistant_relay; was unset)', p.stdout)
        p = run('--json', '-n', '2')
        self.assertEqual((p.returncode, json.loads(p.stdout)['shown']), (0, 2))
        for out in (p.stdout,):
            for bad in REAL_BITS:
                self.assertNotIn(bad, out)


if __name__ == '__main__':
    unittest.main(verbosity=1)
