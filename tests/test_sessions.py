#!/usr/bin/python3 -I
"""Follow-up ask sessions (vault memory plan C1, 2026-10-15): idle TTL, hard cap, turns, LRU, the caller binding,
one turn at a time, scope lock, purge drops them, the kind map, the composed question (<= 300 chars, checked values
only), /answer with session=true / ID / end over the same messages (by ref; new messages stay out), the switch
(VAULT_ASK_SESSIONS off -> 409), audit metadata only (no question text).
Run: python3 -I tests/test_sessions.py (uses test_vault.py's fakes and stub LLM)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import unittest  # noqa: E402
import sessions as SS  # noqa: E402
import test_facts as TF  # noqa: E402

V = TV.V
NEW_MSG = '[2026-12-29 10:00] Zoe: Neue Nachricht nach dem ersten Ask (#105)'


class FakeAudit:
    def __init__(self):
        self.events = []

    def log(self, event, **meta):
        self.events.append(dict(meta, event=event))


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class SessionUnitTests(unittest.TestCase):
    def setUp(self):
        self.audit, self.clock = FakeAudit(), Clock()
        self.ss = SS.Sessions(self.audit, enabled=True, clock=self.clock)

    def open(self, owner='tok'):
        return self.ss.open(owner, {'source': 'tg', 'chat': 'x'}, [['#1', '2026-01-01 10:00']], 'q1', 'yesno',
                            {'answer': 'yes', 'refs': ['#1']})

    def test_off_by_default(self):
        ss = SS.Sessions(self.audit)
        with self.assertRaises(V.VaultError) as e:
            ss.open('tok', {}, [], 'q', 'short', {})
        self.assertEqual((e.exception.status, e.exception.code), (409, 'sessions_off'))

    def test_idle_ttl_and_hard_cap(self):
        info = self.open()
        self.assertTrue(SS.ID_RE.fullmatch(info['id']))
        self.assertEqual(info['turns_left'], SS.MAX_TURNS - 1)
        self.clock.t += SS.IDLE_S - 1
        s = self.ss.begin('tok', info['id'])
        self.ss.finish(s, 'q2', 'short', {'answer': 'b'})
        self.clock.t += SS.IDLE_S + 1                    # idle too long
        with self.assertRaises(V.VaultError) as e:
            self.ss.begin('tok', info['id'])
        self.assertEqual((e.exception.status, e.exception.code), (410, 'session_gone'))
        self.assertIn('expired', [x.get('action') for x in self.audit.events])
        info = self.open()                               # hard cap: 60 min even when busy talking
        for _ in range(4):
            self.clock.t += 14 * 60
            s = self.ss.begin('tok', info['id'])
            self.ss.release(s)
        self.clock.t += 5 * 60
        with self.assertRaises(V.VaultError):
            self.ss.begin('tok', info['id'])

    def test_turns_owner_busy_end(self):
        info = self.open()
        with self.assertRaises(V.VaultError) as e:
            self.ss.begin('other-token', info['id'])     # bound to the caller's token hash
        self.assertEqual(e.exception.code, 'session_gone')
        s = self.ss.begin('tok', info['id'])
        with self.assertRaises(V.VaultError) as e:
            self.ss.begin('tok', info['id'])             # one turn at a time
        self.assertEqual(e.exception.code, 'session_busy')
        self.ss.release(s)
        left = None
        for n in range(SS.MAX_TURNS - 1):
            s = self.ss.begin('tok', info['id'])
            left = self.ss.finish(s, f'q{n}', 'short', {'answer': 'x'})['turns_left']
        self.assertEqual(left, 0)
        with self.assertRaises(V.VaultError):            # used up: gone
            self.ss.begin('tok', info['id'])
        info = self.open()
        self.assertFalse(self.ss.end('other-token', info['id'])['session']['ended'])
        self.assertTrue(self.ss.end('tok', info['id'])['session']['ended'])
        with self.assertRaises(V.VaultError):
            self.ss.begin('tok', info['id'])
        with self.assertRaises(V.VaultError) as e:
            self.ss.begin('tok', 'not an id')
        self.assertEqual(e.exception.status, 400)

    def test_lru_cap_and_purge(self):
        ids = [self.open()['id'] for _ in range(SS.MAX_SESSIONS)]
        self.ss.begin('tok', ids[0]) and None            # ids[0] busy -> the next oldest goes
        new = self.open()['id']
        self.assertEqual(self.ss.count(), SS.MAX_SESSIONS)
        with self.assertRaises(V.VaultError):
            self.ss.begin('tok', ids[1])
        self.assertEqual(self.ss.drop_all(), SS.MAX_SESSIONS)
        with self.assertRaises(V.VaultError):
            self.ss.begin('tok', new)
        acts = [x['action'] for x in self.audit.events if x['event'] == 'answer_session']
        self.assertEqual(acts.count('purged'), SS.MAX_SESSIONS)
        for ev in self.audit.events:                     # metadata only: sha8 of the id, never a question
            self.assertEqual(len(ev['session']), 8)
            self.assertNotIn('q1', json.dumps(ev))

    def test_kind_map(self):
        cases = {'und wo?': 'when', 'and where is it?': 'when', 'Wann genau?': 'when', 'a kada?': 'when',
                 'gdje je to?': 'when', 'um wieviel Uhr?': 'when', 'wie viele kommen?': 'count',
                 'how many people?': 'count', 'koliko ljudi?': 'count', 'stimmt das?': 'yesno',
                 'weisst du ob Beat kommt?': 'yesno', 'is it confirmed?': 'yesno', 'und ist Anna dabei?': 'yesno',
                 'da li dolazi?': 'yesno', 'what is the plan?': 'short', 'wer bringt was?': 'who',
                 'wer kommt mit?': 'who', 'who is coming?': 'who', 'mit wem?': 'who', 'ko dolazi?': 'who',
                 'Wann und mit wem?': 'when', 'wert?': 'short',
                 'this one?': 'short', 'wohnung?': 'short'}
        for q, kind in cases.items():
            self.assertEqual(SS.followup_kind(q), kind, q)

    def test_compose_checked_values_only_and_capped(self):
        turns = [{'q': 'Ist die Party am Samstag?', 'kind': 'yesno',
                  'answer': {'answer': 'yes', 'date': '2026-10-24', 'refs': ['#9']}}]
        c = SS.compose(turns, 'und wo?')
        self.assertEqual(c, 'Earlier: «Ist die Party am Samstag?» → yes, 2026-10-24. Now: «und wo?»')
        turns.append({'q': 'und wo?', 'kind': 'when', 'answer': {'venue': 'Seeblick', 'who': ['Anna', 'Beat'],
                                                                  'refs': ['#9']}})
        turns.append({'q': None, 'kind': 'mail_card', 'answer': {'category': 'bill', 'actionable': True}})
        c = SS.compose(turns, 'x' * 200)
        self.assertLessEqual(len(c), SS.Q_MAX)
        self.assertTrue(c.endswith('Now: «' + 'x' * 200 + '»'))
        self.assertIn('bill, actionable: yes', c)        # the newest turn goes in first
        self.assertNotIn('#9', SS.compose(turns, 'q'))  # refs never re-enter a prompt
        self.assertEqual(len(SS.compose(turns, 'y' * 300)), 300)
        self.assertEqual(SS.render_value({'n': 3, 'first': '2026-01-02'}), 'n: 3, 2026-01-02')


class SessionApiTests(TV.ApiBase):
    name = 'api-sessions'
    extra_env = {'VAULT_ASK_SESSIONS': '1'}

    def setUp(self):
        super().setUp()
        shutil.rmtree(self.cfg.state / 'answer-cache', ignore_errors=True)
        self.argvs, self.tg_out = [], TF.TG_OUT
        self.app.answer.clock = lambda: 1796126400        # 2026-12-01 12:00: the fixture's dates stay ahead

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            self.argvs.append(list(argv))
            if argv[0] == 'alias':
                return 0, '', ''
            if argv[0] == 'search':
                return 0, json.dumps({'hits': [
                    {'line': '[2026-12-28 18:02] Anna Muster: Wir treffen uns am 3.1. (#101)', 'ts': 1798477320,
                     'chat': 'Grouptrip 2026', 'chat_id': -1000000000123, 'chat_type': 'group', 'msg_id': 101}]}), ''
            return 0, self.tg_out, ''
        self.app.tg._exec = fake_exec
        self.app.tg._aliases = None
        self.app.tg.ensure_config = lambda: False

    def llm(self, d):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(d))

    def answer_calls(self):
        return [c for c in TV.llm_calls() if '--schema' in c['args']]

    def test_three_turns_same_messages_one_call_each(self):
        self.llm({'answer': 'yes', 'date': '3.1.', 'refs': [1]})
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'yesno',
                                              'question': 'Treffen wir uns im Hallenbad?', 'session': True})
        self.assertEqual(st, 200, r)
        sid = r['session']['id']
        self.assertEqual((r['answer']['answer'], r['session']['turns_left'], r['messages']), ('yes', 5, 4))
        self.tg_out = TF.TG_OUT.replace('\n\n(private', '\n' + NEW_MSG + '\n\n(private')   # a new message arrives
        n0 = len(self.answer_calls())
        self.llm({'date': '3.1.', 'start': '18:00', 'venue': 'Hallenbad Seeblick', 'refs': [1]})
        st, r2 = self.call('POST', '/answer', {'session': sid, 'question': 'und wo?'})
        self.assertEqual(st, 200, r2)
        self.assertEqual((r2['kind'], r2['turn'], r2['messages'], r2['question']), ('when', 2, 4, 'und wo?'))
        self.assertEqual(r2['answer']['venue'], 'Hallenbad Seeblick')
        self.assertEqual(r2['chat'], 'group')
        calls = self.answer_calls()[n0:]
        self.assertEqual(len(calls), 1)                  # one LLM call per follow-up (one part)
        self.assertIn('Question: Earlier: «Treffen wir uns im Hallenbad?» → yes, 2027-01-03. Now: «und wo?»',
                      calls[0]['text'])
        self.assertNotIn('Neue Nachricht', calls[0]['text'])       # the same messages, not the new one
        recent = [a for a in self.argvs if a[0] == 'recent'][-1]
        self.assertIn('--no-paraphrase', recent)
        self.assertTrue([a for a in recent if a.startswith('--since=@')], recent)   # pinned to the first ask
        self.llm({'matches': [1, 2]})
        st, r3 = self.call('POST', '/answer', {'session': sid, 'question': 'wie viele Nachrichten dazu?'})
        self.assertEqual((st, r3['kind'], r3['answer']['n'], r3['session']['turns_left']), (200, 'count', 2, 3))
        ev = [e for e in self.app.audit.read(days=1, limit=200) if e['event'] in ('answer', 'answer_session')]
        self.assertTrue(any(e['event'] == 'answer' and e.get('turn') == 2 and len(e.get('session', '')) == 8
                            for e in ev))
        self.assertTrue(any(e['event'] == 'answer_session' and e['action'] == 'followup' for e in ev))
        self.assertNotIn('Hallenbad', json.dumps(ev))     # no question or answer text in the audit
        st, r4 = self.call('POST', '/answer', {'session': sid, 'end': True})
        self.assertEqual((st, r4['session']['ended']), (200, True))
        st, r5 = self.call('POST', '/answer', {'session': sid, 'question': 'und wann?'})
        self.assertEqual((st, r5['code']), (410, 'session_gone'))

    def test_times_always_carry_their_date(self):
        """Live 15.10 09:40: a follow-up "wann genau?" came back as a time alone while the plan was on the asked
        days. A time now always comes with its date: from the cited message when it names one day (message), else
        the session's earlier checked date (earlier), else date_unknown; never guessed."""
        self.llm({'answer': 'yes', 'date': '3.1.', 'refs': [1]})
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'yesno',
                                              'question': 'Treffen wir uns im Hallenbad?', 'session': True})
        self.assertEqual((st, r['answer']['date']), (200, '2027-01-03'), r)
        sid = r['session']['id']
        self.llm({'start': '18:00', 'refs': [2]})        # the time alone, resting on a message naming no day
        st, r2 = self.call('POST', '/answer', {'session': sid, 'question': 'wann genau?'})
        self.assertEqual(st, 200, r2)
        self.assertEqual((r2['kind'], r2['answer']['start'], r2['answer']['date'], r2['answer']['date_from']),
                         ('when', '18:00', '2027-01-03', 'earlier'))
        self.assertNotIn('date_unknown', r2['answer'])
        self.assertNotIn('timing', r2['answer'])         # measured like any other date (timed): not past
        c = self.answer_calls()[-1]
        self.assertIn('date: the day it happens on, always', c['text'] + ' '.join(map(str, c['args'])))
        self.llm({'start': '18:00', 'refs': [1]})        # cited message names the day: filled from it
        st, r3 = self.call('POST', '/answer', {'session': sid, 'question': 'um wie viel Uhr genau?'})
        self.assertEqual((r3['answer']['date'], r3['answer']['date_from']), ('2027-01-03', 'message'))
        self.llm({'start': '18:00', 'refs': [2]})        # no session, no day named: flagged, not guessed
        st, r4 = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'when',
                                               'question': 'Wann genau?'})
        self.assertEqual(st, 200, r4)
        self.assertEqual((r4['answer']['start'], r4['answer'].get('date'), r4['answer']['date_unknown']),
                         ('18:00', None, True))
        self.llm({'date': '3.1.', 'start': '18:00', 'refs': [1]})   # the model's own date: untouched
        st, r5 = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'when',
                                               'question': 'Wann ist das Treffen?'})
        self.assertEqual((r5['answer']['date'], r5['answer'].get('date_from')), ('2027-01-03', None))

    def test_scope_locked_and_purge_drops(self):
        self.llm({'answer': 'Hallenbad', 'refs': [1]})
        st, r = self.call('POST', '/answer', {'source': 'tg', 'query': 'Hallenbad', 'question': 'Wo?', 'session': True})
        self.assertEqual(st, 200, r)
        sid = r['session']['id']
        for extra in ({'chat': 'Other chat'}, {'query': 'Lisa'}, {'since': '90d'}, {'source': 'gmail'}):
            st, e = self.call('POST', '/answer', dict({'session': sid, 'question': 'und Lisa?'}, **extra))
            self.assertEqual((st, e['code']), (400, 'scope_locked'), extra)
        st, e = self.call('POST', '/answer', {'session': sid})
        self.assertEqual(st, 400, e)                     # a follow-up needs a question
        st, e = self.call('POST', '/answer', {'session': sid, 'question': 'x', 'kind': 'digest'})
        self.assertEqual(st, 400, e)
        st, r2 = self.call('POST', '/answer', {'session': sid, 'question': 'und wer?'})    # a names list (15.10)
        self.assertEqual((st, r2['kind'], r2['messages'], r2['query']), (200, 'who', 1, 'Hallenbad'))
        self.app.tg.run('purge', {'chat': 'Grouptrip 2026', 'yes': True})
        st, e = self.call('POST', '/answer', {'session': sid, 'question': 'und wann?'})
        self.assertEqual((st, e['code']), (410, 'session_gone'))
        acts = [x['action'] for x in self.app.audit.read(days=1, limit=200) if x['event'] == 'answer_session']
        self.assertIn('purged', acts)

    def test_gmail_session_scoped_to_one_mail(self):
        reads = []

        class FakeGmail:
            def anon_doc(self, ref, folder, chars, account):
                reads.append((ref, folder, chars, account))
                return {'ref': ref, 'account': 'main', 'from': 'Anna', 'ts': 1798477320,
                        'text': 'Hallo, das Treffen ist am 3.1. um 18:00 im Hallenbad Seeblick.'}
        old, self.app.answer.gmail = self.app.answer.gmail, FakeGmail()
        try:
            self.llm({'answer': 'yes', 'refs': [1]})
            st, r = self.call('POST', '/answer', {'source': 'gmail', 'ref': '4711', 'kind': 'yesno',
                                                  'question': 'Gibt es ein Treffen?', 'session': True})
            self.assertEqual(st, 200, r)
            self.llm({'date': '3.1.', 'start': '18:00', 'venue': 'Hallenbad Seeblick', 'refs': [1]})
            st, r2 = self.call('POST', '/answer', {'session': r['session']['id'], 'question': 'wann genau?'})
            self.assertEqual((st, r2['kind'], r2['ref'], r2['answer'].get('start')), (200, 'when', '4711', '18:00'))
            self.assertEqual(reads[-1], reads[0])            # the same mail, same options
            st, e = self.call('POST', '/answer', {'session': r['session']['id'], 'question': 'x', 'ref': '4712'})
            self.assertEqual((st, e['code']), (400, 'scope_locked'))
        finally:
            self.app.answer.gmail = old

    def test_no_digest_sessions_and_bad_values(self):
        st, e = self.call('POST', '/answer', {'source': 'tg', 'chat': 'x', 'session': True})
        self.assertEqual(st, 400, e)                     # digest: no follow-ups
        st, e = self.call('POST', '/answer', {'source': 'tg', 'chat': 'x', 'question': 'q', 'session': 5})
        self.assertEqual(st, 400, e)
        st, e = self.call('POST', '/answer', {'source': 'tg', 'chat': 'x', 'question': 'q', 'end': True})
        self.assertEqual(st, 400, e)


class InvariantTests(unittest.TestCase):
    def test_no_text_path(self):
        D = TV.D
        self.assertNotIn('/answer', D.TEXT_ROUTES)        # sessions add no text route
        self.assertEqual(TV.J.OPS['answer'], ('POST', '/answer'))
        self.assertTrue({'session', 'end', 'turn', 'kind'} <= V.TAP_SAFE_KEYS)
        self.assertNotIn('question', V.TAP_SAFE_KEYS)    # the owner's live view hides the question as before
        self.assertEqual(V.Config({'VAULT_ASK_SESSIONS': '1'}).ask_sessions, True)
        self.assertEqual(V.Config({}).ask_sessions, False)


class SessionsOffTests(TV.ApiBase):
    name = 'api-sessions-off'

    def test_switch_off_is_409(self):
        st, e = self.call('POST', '/answer', {'source': 'tg', 'chat': 'x', 'question': 'q', 'session': True})
        self.assertEqual((st, e['code']), (409, 'sessions_off'))
        st, e = self.call('POST', '/answer', {'session': 's-abcdefgh', 'question': 'q'})
        self.assertEqual((st, e['code']), (409, 'sessions_off'))


if __name__ == '__main__':
    unittest.main(verbosity=1)
