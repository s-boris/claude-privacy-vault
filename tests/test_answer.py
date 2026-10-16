#!/usr/bin/python3 -I
"""Answers, not text (privacy plan A, 2026-10-14): checks per kind (invented values dropped, first names only, a
[placeholder] never inside a value, dates resolved in code, the regex net drops what it would mask), /answer over the
anonymized (never paraphrased) chat with one grammar-constrained call and a cache, the digest default of tg
summarize (groups by alias, else "group"; no message text), tg search hits without text, text=true only with a
reason and only through the owner's ✅ (text_release audited), mail senders (freemail: first name), period_years
(only years >= 2000), the location raw source, jobs ops.
Run: python3 -I tests/test_answer.py (uses test_vault.py's fakes and stub LLM)."""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
import answer as AN  # noqa: E402
import facts as FX  # noqa: E402
import jobs as J  # noqa: E402
import test_facts as TF  # noqa: E402

V, D, S = TV.V, TV.D, TV.S
PART = FX.parse_log(TF.TG_OUT)[1]
WINDOW = {'chats': [{'chat_id': -1000000000123, 'msgs': 4, 'chars': 300, 'unread': 0, 'first_ts': 0,
                     'days': [{'day': '2026-12-28', 'msgs': 2, 'chars': 150}]}], 'sync': 'synced just now'}
DIGEST = {'needs_you': [{'from': 'Carla', 'wants': 'decision', 'refs': [4]}, {'from': 'Zoe', 'wants': 'reply'},
                        {'from': 'Anna', 'wants': 'bogus'}],
          'plans': [{'date': '3.1.', 'start': '18:00', 'what': 'treffen Hallenbad', 'venue': 'Hallenbad Seeblick',
                     'with': ['Anna Muster', 'Zoe'], 'refs': [1]},
                    {'date': 'Samstag', 'what': 'Znacht', 'venue': 'Seerestaurant Imaginaer', 'refs': [3]},
                    {'date': '5.2.', 'what': 'Tauchkurs in Aegypten'}],
          'signals': [{'type': 'problem', 'topic': 'private', 'who': 'Beat'}, {'type': 'wish', 'topic': 'bogus'}],
          'topics': ['sport', 'private', 'bogus']}


def wait_for(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def net(s):
    return s.replace(TF.PHONE, '[phone]')


class CheckTests(unittest.TestCase):
    def ck(self):
        return AN.ACheck(PART, net)

    def test_when_drops_invented_values_and_keeps_first_names(self):
        c = self.ck()
        r = c.run_kind('when', {'date': '3.1.', 'start': '18:00', 'venue': 'Hallenbad Seeblick',
                                'address': 'Seestrasse 1', 'who': ['Anna Muster', 'Zoe', 'You'], 'status': 'maybe',
                                'refs': [1]})
        self.assertEqual((r['date'], r['start'], r['venue'], r['address'], r['who'], r['status'], r['refs']),
                         ('2027-01-03', '18:00', 'Hallenbad Seeblick', None, ['Anna', 'You'], None, ['#101']))
        self.assertEqual(c.why, {'address': 1, 'who': 1, 'status': 1})

    def test_honorific_surname_becomes_someone(self):
        """Real-model eval 14.10: "Herr Huber" (who) and "Frau Gerolds Garten" (venue) got through as honorific +
        surname. Person fields -> "someone", venues/addresses lose the span, short text says "someone"; facts too."""
        part = [{'ts': '2026-10-11 09:24', 'sender': 'Marco', 'ref': '#1',
                 'text': 'Party am Samstag 18.10. um 19:00 im Frau Gerolds Garten, Geroldstrasse'},
                {'ts': '2026-10-11 11:36', 'sender': 'Jonas', 'ref': '#2',
                 'text': 'Der Vermieter, Herr Huber, will bis Freitag 17.10. eine Zusage. Ich sage Herrn Huber zu.'}]
        c = AN.ACheck(part, net)
        when = c.run_kind('when', {'date': '18.10.', 'start': '19:00', 'venue': 'Frau Gerolds Garten',
                                   'address': 'Frau Gerolds Garten, Geroldstrasse',
                                   'who': ['Marco', 'Herr Huber', 'Herrn Huber', 'Herr'], 'refs': [1]})
        self.assertEqual((when['venue'], when['address'], when['who']), (None, 'Geroldstrasse', ['Marco', 'someone']))
        req = c.run_kind('requests', {'requests': [{'who': 'Herr Huber', 'wants': 'decision', 'refs': [2]}]})
        self.assertEqual([(x['who'], x['wants']) for x in req['requests']], [('someone', 'decision')])
        dig = c.run_kind('digest', {'needs_you': [{'from': 'Herrn Huber', 'wants': 'reply', 'refs': [2]}],
                                    'plans': [{'date': '18.10.', 'what': 'Party', 'venue': 'Frau Gerolds Garten',
                                               'with': ['Jonas', 'Herr Huber'], 'refs': [1]}],
                                    'signals': [{'type': 'request', 'topic': 'home', 'who': 'Herr Huber'}]})
        self.assertEqual((dig['needs_you'][0]['from'], dig['plans'][0]['venue'], dig['plans'][0]['with'],
                          dig['signals'][0]['who']), ('someone', None, ['Jonas', 'someone'], 'someone'))
        short = c.run_kind('short', {'answer': 'Zusage an Herrn Huber', 'refs': [2]})
        self.assertEqual(short['answer'], 'Zusage an someone')
        blob = json.dumps([when, req, dig, short], ensure_ascii=False)
        self.assertNotIn('Huber', blob)
        self.assertNotIn('Gerolds Garten', blob)
        self.assertGreaterEqual(c.why.get('honorific', 0), 6)
        self.assertEqual((AN.first_name('Herr Huber'), AN.first_name('Frauke Meier'),
                          AN.display_from('Herr Peter Huber', 'livit.ch')), ('someone', 'Frauke', 'someone (livit.ch)'))
        fx = FX.Check(part, net)
        ev = fx.item('events', {'what': 'Party', 'date': '18.10.', 'venue': 'Frau Gerolds Garten',
                                'who': ['Herr Huber', 'Marco'], 'msgs': [1]})
        self.assertEqual((ev.get('venue'), ev['who']), (None, ['someone', 'Marco']))
        self.assertEqual(fx.item('todos', {'what': 'Zusage', 'who': 'Herrn Huber', 'msgs': [2]})['who'], 'someone')

    def test_placeholder_becomes_topic_private(self):
        r = self.ck().run_kind('interests', {'interests': [{'phrase': '[private: health]', 'topic': 'sport'},
                                                           {'phrase': 'Flossen', 'topic': 'sport'},
                                                           {'phrase': 'Tauchkurs in Aegypten bald', 'topic': 'travel'}]})
        self.assertEqual(r['interests'], [{'phrase': None, 'topic': 'private'}, {'phrase': 'Flossen', 'topic': 'sport'}])

    def test_short_answer_words_from_the_text_only(self):
        self.assertEqual(self.ck().run_kind('short', {'answer': 'im Hallenbad Seeblick'})['answer'], 'im Hallenbad Seeblick')
        self.assertEqual(self.ck().run_kind('short', {'answer': 'im Kino Capitol'})['answer'], 'unclear')
        long = ' '.join(['Anna'] * 13)
        self.assertEqual(self.ck().run_kind('short', {'answer': long})['answer'], 'unclear')

    def test_count_and_requests(self):
        r = self.ck().run_kind('count', {'matches': [1, 3, 99, True]})
        self.assertEqual((r['n'], r['first'], r['last']), (2, '2026-12-28', '2026-12-29'))
        r = self.ck().run_kind('requests', {'requests': [{'who': 'Carla', 'wants': 'decision', 'refs': [4]},
                                                         {'who': 'Carla Meier-Invented', 'wants': 'reply'},
                                                         {'who': 'group', 'wants': 'info'},
                                                         {'who': 'Beat', 'wants': 'gossip'}]})
        self.assertEqual([(x['who'], x['wants']) for x in r['requests']],
                         [('Carla', 'decision'), ('group', 'info')])

    def test_mail_card_bill_has_no_deadline(self):
        part = [{'ts': '2026-10-10 09:00', 'sender': 'Swisscom (swisscom.ch)', 'ref': 'main:1',
                 'text': 'Subject: Rechnung\n\nBitte zahlen Sie [amount] bis 31.10.2026. Termin am 12.11.2026 im Shop.'}]
        c = AN.ACheck(part, net)
        r = c.run_kind('mail_card', {'category': 'bill', 'actionable': True, 'action': 'pay', 'deadline': '31.10.2026',
                                     'appointment': {'date': '12.11.2026'}, 'reply_needed': False}, mail=True)
        self.assertEqual((r['category'], r['action'], r['deadline'], r['appointment']), ('bill', 'pay', None, None))
        r = c.run_kind('mail_card', {'category': 'deadline', 'actionable': True, 'action': 'send',
                                     'deadline': '31.10.2026', 'reply_needed': False}, mail=True)
        self.assertEqual(r['deadline'], '2026-10-31')

    def test_net_drops_identifiers(self):
        drop = {}
        self.assertEqual(AN.net_values({'a': f'ruf {TF.PHONE}', 'b': 'ok', 'refs': ['#1']}, net, drop),
                         {'a': None, 'b': 'ok', 'refs': ['#1']})
        self.assertEqual(drop, {'netted': 1})

    def test_display_helpers(self):
        self.assertEqual(AN.display_from('Anna Muster', 'gmail.com'), 'Anna')
        self.assertEqual(AN.display_from('Swisscom', 'swisscom.ch'), 'Swisscom (swisscom.ch)')
        self.assertEqual(AN.display_from('', 'bluewin.ch'), 'someone')
        al = {'-5': 'dive group'}
        self.assertEqual([AN.chat_display('-5', 'group', 'Grouptrip', al), AN.chat_display('-6', 'supergroup', 'X', al),
                          AN.chat_display('7', 'user', 'Anna Muster', al), AN.chat_display('-8', 'channel', 'N', al)],
                         ['dive group', 'group', 'Anna', 'channel'])

    def test_period_years_only_from_2000(self):
        self.assertEqual(S.period_years('geb. 03.04.1978\nvom 01.01.2025 bis 31.12.2025'), [2025, 2025])


class AnswerApiTests(TV.ApiBase):
    name = 'api-answer'

    def setUp(self):
        super().setUp()
        if not self.app.store.is_set('telegram'):       # raw requests (text=true) need the vault's bot
            self.app.store.set('telegram', {'bot_token': TV.BOT_TOKEN, 'chat_id': TV.CHAT_ID})
        shutil.rmtree(self.cfg.state / 'answer-cache', ignore_errors=True)
        self.argvs = []
        self.alias = ''
        self.app.answer.clock = lambda: 1796126400        # 2026-12-01 12:00: the fixture's dates stay ahead

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            self.argvs.append(list(argv))
            if argv[0] == 'window':
                return 0, json.dumps(WINDOW), ''
            if argv[0] == 'alias':
                return 0, self.alias, ''
            if argv[0] == 'search':
                return 0, json.dumps({'hits': [
                    {'line': '[2026-12-28 18:02] Anna Muster: Wir treffen uns am 3.1. (#101)', 'ts': 1798477320,
                     'chat': 'Grouptrip 2026', 'chat_id': -1000000000123, 'chat_type': 'group', 'msg_id': 101}]}), ''
            return 0, TF.TG_OUT, ''
        self.app.tg._exec = fake_exec
        self.app.tg._aliases = None
        self.app.tg.ensure_config = lambda: False

    def answer_calls(self):
        return [c for c in TV.llm_calls() if '--schema' in c['args']]

    def test_when_answer_from_anonymized_text_one_call_cached(self):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps({'date': '3.1.', 'start': '18:00', 'venue': 'Hallenbad Seeblick',
                                                          'who': ['Anna'], 'refs': [1]}))
        n0 = len(self.answer_calls())
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'when',
                                              'question': 'Wann ist das Treffen im Hallenbad?'})
        self.assertEqual(st, 200, r)
        recent = [a for a in self.argvs if a[0] == 'recent'][-1]
        self.assertIn('--no-paraphrase', recent)
        self.assertNotIn('--raw', recent)
        calls = self.answer_calls()[n0:]
        self.assertEqual(len(calls), 1)
        schema = json.loads(calls[0]['args'][calls[0]['args'].index('--schema') + 1])
        self.assertEqual(schema['properties']['status']['enum'], list(FX.STATUS))
        self.assertIn('Question: Wann ist das Treffen', calls[0]['text'])
        self.assertEqual(r['answer'], {'date': '2027-01-03', 'start': '18:00', 'venue': 'Hallenbad Seeblick',
                                       'who': ['Anna'], 'refs': ['#101']})
        self.assertEqual(r['chat'], 'group')
        self.assertNotIn('Flossen', json.dumps(r))
        st, r2 = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'when',
                                               'question': 'Wann ist das Treffen im Hallenbad?'})
        self.assertEqual((st, r2['cached_parts'], len(self.answer_calls()) - n0), (200, 1, 1))
        ev = [e for e in self.app.audit.read(days=1, limit=50) if e['event'] == 'answer']
        self.assertTrue(ev and ev[-1]['kind'] == 'when' and 'question' not in ev[-1])
        cache = list((self.cfg.state / 'answer-cache').glob('*/*.json'))
        self.assertTrue(cache and all(p.stat().st_mode & 0o777 == 0o600 for p in cache))
        self.app.tg.run('purge', {'chat': 'Grouptrip 2026', 'yes': True})        # tg purge clears the answers
        self.assertFalse((self.cfg.state / 'answer-cache').exists())

    def test_llm_failure_is_an_error_never_partial(self):
        (TV.STUB_DIR / 'llm-json').write_text('not json')
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Grouptrip 2026', 'kind': 'yesno',
                                              'question': 'Kommt Beat?'})
        self.assertEqual(st, 502, r)
        self.assertNotIn('answer', r)
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'x', 'kind': 'yesno'})
        self.assertEqual(st, 400, r)                                      # a yes/no needs a question
        st, r = self.call('POST', '/answer', {'source': 'gmail', 'kind': 'digest'})
        self.assertEqual(st, 400, r)

    def test_summarize_default_is_a_digest_without_text(self):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(DIGEST))
        st, r = self.call('POST', '/tg/summarize', {'hours': 48, 'text': False})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['kind'], 'digest')
        self.assertEqual(r['window']['chats'], 1)
        self.assertEqual(r['needs_you'], [{'from': 'Carla', 'wants': 'decision', 'refs': ['#104'], 'chat': 'group'}])
        self.assertEqual([(p['date'], p.get('venue'), p.get('with')) for p in r['plans']],
                         [('2027-01-02', None, None), ('2027-01-03', 'Hallenbad Seeblick', ['Anna'])])
        self.assertEqual(r['signals'][0], {'type': 'problem', 'topic': 'private', 'who': 'Beat', 'chat': 'group'})
        self.assertEqual(r['topics'], {'sport': 1, 'private': 1})
        blob = json.dumps(r, ensure_ascii=False)
        for word in ('Flossen', 'Boot', '[private', 'Grouptrip', 'Muster'):
            self.assertNotIn(word, blob)
        self.alias = 'dive group -> Grouptrip 2026 (group, chat -1000000000123)\n'
        self.app.tg._aliases = None
        st, r = self.call('POST', '/tg/recent', {'chat': 'Grouptrip 2026', 'text': False})
        self.assertEqual((st, r['needs_you'][0]['chat']), (200, 'dive group'))

    def test_search_default_is_hits_without_text(self):
        st, r = self.call('POST', '/tg/search', {'query': 'Hallenbad', 'text': False})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['hits'], [{'ref': '#101', 'ts': r['hits'][0]['ts'], 'chat': 'group',
                                      'chat_key': '-1000000000123', 'from': 'Anna'}])
        self.assertNotIn('treffen', json.dumps(r))

    def test_text_needs_a_reason_and_the_owners_ok(self):
        st, r = self.call('POST', '/tg/recent', {'chat': 'Grouptrip 2026', 'text': True})
        self.assertEqual((st, r.get('code')), (400, 'reason_required'), r)
        st, r = self.call('POST', '/tg/recent', {'chat': 'Grouptrip 2026', 'text': 'yes', 'reason': 'xyz'})
        self.assertEqual(st, 400, r)
        st, r = self.call('POST', '/tg/recent', {'chat': 'Grouptrip 2026', 'text': True,
                                                 'reason': 'he asked what Anna wrote exactly'})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['status'], r['text_release'], r['route']), ('pending', True, '/tg/recent'))
        self.assertNotIn('stdout', r)
        self.assertNotIn('treffen', json.dumps(r))
        self.assertTrue(wait_for(lambda: self.app.raw.reqs[r['request_id']].get('ready'), 10))
        ev = [e for e in self.app.audit.read(days=1, limit=100) if e['event'] in ('text_release', 'raw_request')]
        self.assertEqual([e['event'] for e in ev[-2:]], ['raw_request', 'text_release'])   # the request first (14.10)
        self.assertEqual((ev[-1]['route'], ev[-2]['source'], ev[-1]['request_id']),
                         ('/tg/recent', 'text', r['request_id']))
        self.assertGreater(ev[-1]['bytes'], 0)
        self.assertEqual(self.app.board.counts().get('text_rel'), 1)
        st, r = self.call('POST', '/tg/recent', {'chat': 'Grouptrip 2026'})   # TEXT_DEFAULT = False (chunk 4, 14.10)
        self.assertEqual((st, r.get('kind')), (200, 'digest'), r)
        self.assertNotIn('stdout', r)
        self.assertFalse(D.TEXT_DEFAULT)

    def test_text_request_goes_out_before_the_slow_search(self):
        """Regression: a Telegram text search hung 120 s and no request existed. Now the ✅ request goes out at
        once (pending, preparing); the search runs meanwhile; an approval before it is ready answers 'preparing';
        the text is released once it exists. A failing search ends the request as 'failed' (no text)."""
        gate, real = threading.Event(), self.app.tg.run

        def slow(cmd, b):
            gate.wait(20)
            return real(cmd, b)
        self.app.tg.run = slow
        try:
            t0 = time.monotonic()
            st, r = self.call('POST', '/tg/search', {'query': 'Hallenbad', 'text': True,
                                                     'reason': 'he asked what Anna wrote about it'})
            self.assertLess(time.monotonic() - t0, 3)
            self.assertEqual((st, r['status'], r.get('preparing'), r['text_release']), (200, 'pending', True, True), r)
            rid = r['request_id']
            self.assertFalse([e for e in self.app.audit.read(days=1, limit=200)
                              if e['event'] == 'text_release' and e.get('request_id') == rid])
            self.assertEqual(self.app.raw.decide(rid, True, 'console')[0], 'approved')
            st, p = self.call('POST', '/raw/release', {'request_id': rid, 'wait': 0})
            self.assertEqual((st, p['status'], p.get('preparing')), (200, 'pending', True), p)
            gate.set()
            st, p = self.call('POST', '/raw/release', {'request_id': rid, 'wait': 20})
            self.assertEqual((st, p['status'], p['kind']), (200, 'released', 'text'), p)
            self.assertTrue(p['text'])
        finally:
            gate.set()
            self.app.tg.run = real

        def boom(cmd, b):
            raise V.VaultError('no chat matches that name', 404, 'not_found')
        self.app.tg.run = boom
        try:
            st, r = self.call('POST', '/tg/recent', {'chat': 'nope', 'text': True, 'reason': 'he asked for it'})
            self.assertEqual((st, r['status']), (200, 'pending'), r)
            rid = r['request_id']
            self.assertTrue(wait_for(lambda: self.app.raw.reqs[rid]['state'] == 'failed', 10))
            st, p = self.call('POST', '/raw/release', {'request_id': rid})
            self.assertEqual((st, p.get('code')), (502, 'request_failed'), p)
            self.assertIn('text_release_failed', [e['event'] for e in self.app.audit.read(days=1, limit=200)])
        finally:
            self.app.tg.run = real

    def test_deferred_raw_request_state_machine(self):
        class N:
            def send(self, text, buttons=None):
                return 7

        class A:
            def __init__(self):
                self.ev = []

            def log(self, ev, **kw):
                self.ev.append(ev)
        now = [1000.0]
        raw = V.RawRequests(N(), A(), b'k' * 32, clock=lambda: now[0])
        r = raw.create('text', 'tg search', 'he asked', None, deferred=True)
        self.assertTrue(r['preparing'])
        rid = r['request_id']
        self.assertEqual(raw.decide(rid, False, 'console')[0], 'denied')
        self.assertFalse(raw.fill(rid, 'TEXT'))                         # denied meanwhile: the text is dropped
        self.assertIsNone(raw.reqs[rid]['payload'])
        rid = raw.create('text', 'tg search', 'he asked', None, deferred=True)['request_id']
        raw.decide(rid, True, 'console')
        now[0] += raw.PICKUP + 60                                       # no pickup clock while it is being made
        self.assertEqual(raw.reqs[rid]['state'], 'approved')
        self.assertTrue(raw.fill(rid, 'TEXT'))
        now[0] += raw.PICKUP - 10
        self.assertEqual(raw.release(rid), 'TEXT')
        rid = raw.create('text', 'tg search', 'he asked', None, deferred=True)['request_id']
        raw.decide(rid, True, 'console')                                # approved, but never ready
        now[0] += raw.PREPARE_MAX + 1
        with self.assertRaises(V.VaultError) as cm:
            raw.release(rid)
        self.assertEqual(cm.exception.code, 'request_failed')

    def test_location_raw_source_needs_home_assistant(self):
        self.assertIn('location', V.RAW_SOURCES)
        st, r = self.call('POST', '/raw/request', {'source': 'location', 'reason': 'where to meet him'})
        self.assertEqual((st, r.get('code')), (409, 'not_configured'), r)
        msg = V.owner_message('text', 'he asked for the exact words', 'location', 'exact place')
        self.assertIn('exact location', msg)

    def test_owner_messages_are_short_lines(self):
        """Regression (the line-break fix was missing in the vault): what is asked, why, what, validity and what to tap,
        each on its own short line (plain text: Telegram keeps every newline)."""
        msg = V.owner_message('text', 'he asked where he is', 'location', 'exact place and coordinates (Home Assistant)')
        self.assertEqual(msg.split('\n'), ['📍 Claude asks for your exact location', 'Why: he asked where he is',
                                           'What: exact place and coordinates (Home Assistant)', '',
                                           '⏱ Valid 15 min', '✅ Allow once: only if you asked for this',
                                           '❌ Deny: otherwise', '(or ignore it: it expires by itself)'])
        for kind, src in (('text', 'tg'), ('text', 'text'), ('file', 'paperless-file'), ('secret', 'secret-rotate'),
                          ('media', 'tg'), ('text', 'location')):
            for code in (None, '123456'):
                m = V.owner_message(kind, 'r' * 200, src, 's' * 100, code=code, size=5000,
                                    preview=['📎 a.pdf (PDF, 1 page)'] if kind == 'media' else None)
                self.assertGreaterEqual(m.count('\n'), 6, m)
                short = [ln for ln in m.split('\n') if not ln.startswith(('Why: ', 'What: ', 'Secret: '))]
                self.assertTrue(all(len(ln) <= 48 for ln in short), m)

    def test_jobs_ops(self):
        self.assertEqual(J.OPS['answer'], ('POST', '/answer'))
        self.assertEqual(J.OPS['tg.digest'], ('POST', '/tg/digest'))


# A live test (fixture, invented text): "Are there plans for this weekend?" was answered from a
# chat about LAST weekend ("unclear, date 2026-10-07"), and "wer kommt mit?" came back as the dialect phrase
# "De mäge und de geko" (kind short).
TG_WEEKEND = '\n'.join([
    'Recent messages (chat 4242, since 30d): 3; chats newest first, messages oldest first. Times Europe/Zurich.',
    '',
    '### Marco (user, chat 4242)',
    '[2026-10-07 19:02] Marco: Am Wochenende gehen wir an den Cannstatter Wasen in Stuttgart (#201)',
    '[2026-10-07 19:05] You: wer kommt mit? (#202)',
    '[2026-10-07 19:06] Marco: de mäge und de geko (#203)',
    '',
    '(private passages and identifiers removed by the local LLM; names and addresses kept as written.)'])
NOW_1510 = 1792015500                                   # Thu 2026-10-15 00:05 Europe/Zurich
TODAY = AN.dt.date(2026, 10, 15)


class TimeWordsAndWhoTests(unittest.TestCase):
    def test_question_time_words_resolve_against_today(self):
        cases = {'Are there plans for this weekend?': ('this weekend', '2026-10-17', '2026-10-18'),
                 'Are there plans for last weekend?': ('last weekend', '2026-10-10', '2026-10-11'),
                 'Was läuft am Wochenende?': ('this weekend', '2026-10-17', '2026-10-18'),
                 'nächstes Wochenende?': ('next weekend', '2026-10-24', '2026-10-25'),
                 'prošli vikend?': ('last weekend', '2026-10-10', '2026-10-11'),
                 'Was ist heute?': ('today', '2026-10-15', '2026-10-15'),
                 'und morgen?': ('tomorrow', '2026-10-16', '2026-10-16'),
                 'Freitag morgen?': ('Friday', '2026-10-16', '2026-10-16'),
                 'nächste Woche?': ('next week', '2026-10-19', '2026-10-25'),
                 'letzten Samstag?': ('last Saturday', '2026-10-10', '2026-10-10'),
                 'am 24.10.?': ('2026-10-24', '2026-10-24', '2026-10-24')}
        for q, (label, a, b) in cases.items():
            w = AN.ask_window(q, TODAY)
            self.assertEqual((w['label'], w['from'].isoformat(), w['to'].isoformat()), (label, a, b), q)
        for q in ('Do we have plans?', 'Is it so?', 'wer kommt mit?', 'wo?'):          # "do", "so": not weekdays
            self.assertIsNone(AN.ask_window(q, TODAY), q)
        # a MESSAGE's "am Wochenende" still counts from the message (Wed 7.10 -> Sat 10.10), not from today
        self.assertEqual(FX.resolve_date('Am Wochenende', AN.dt.date(2026, 10, 7)), AN.dt.date(2026, 10, 10))
        self.assertEqual(FX.resolve_date('letztes Wochenende', AN.dt.date(2026, 10, 7)), AN.dt.date(2026, 10, 3))

    def test_a_plan_outside_the_asked_days_is_not_the_answer(self):
        this_we = AN.ask_window('this weekend?', TODAY)
        r = AN.timed('yesno', {'answer': 'yes', 'date': '2026-10-10', 'refs': ['#201']}, this_we, TODAY)
        self.assertEqual((r['answer'], r['timing'], r['relative'], r['in_window']),
                         ('no', 'past', 'last weekend', False))
        r = AN.timed('yesno', {'answer': 'unclear', 'date': '2026-10-07'}, this_we, TODAY)
        self.assertEqual((r['answer'], r['timing'], r['in_window']), ('unclear', 'past', False))
        last_we = AN.ask_window('last weekend?', TODAY)
        r = AN.timed('yesno', {'answer': 'yes', 'date': '2026-10-10'}, last_we, TODAY)
        self.assertEqual((r['answer'], r['in_window'], r['timing']), ('yes', True, 'past'))
        part = FX.parse_log(TG_WEEKEND)[1]                       # an ISO date must be grounded (smoke test 15.10:
        c = AN.ACheck(part, net)                                 # the prompt's today came back as the date)
        self.assertEqual(c.run_kind('yesno', {'answer': 'unclear', 'date': '2026-10-15'})['date'], None)
        self.assertEqual(c.why.get('date'), 1)
        self.assertEqual(c.run_kind('yesno', {'answer': 'yes', 'date': '2026-10-07', 'refs': [1]})['date'],
                         '2026-10-07')                           # the cited message's own day is fine
        self.assertEqual(c.run_kind('yesno', {'answer': 'yes', 'date': '2026-10-10', 'refs': [1]})['date'],
                         '2026-10-10')                           # ... and its "Am Wochenende" (from 7.10)
        self.assertEqual(c.why.get('date'), 1)
        r = AN.timed('when', {'date': '2026-10-17'}, None, TODAY)
        self.assertEqual((r.get('timing'), r['relative'], 'in_window' in r), (None, 'this weekend', False))
        merged = AN.merge('when', [{'date': '2026-10-17', 'in_window': True}, {'date': '2026-10-10', 'in_window': False}])
        self.assertEqual(merged['date'], '2026-10-17')               # the asked days win over a later part
        self.assertIn('Today is Thursday 2026-10-15. The question asks about this weekend: Saturday 2026-10-17 to '
                      'Sunday 2026-10-18.', AN.time_line(TODAY, this_we))

    def test_yesno_on_other_days_is_no_real_ambiguity_stays_unclear(self):
        # eval 15.10 (tests/eval_answers.py): "Are there plans for this weekend?" over search hits holding only past
        # plans came back "unclear"; "no (only past dates)" is right, a maybe ON the asked days stays unclear
        we = AN.ask_window('Are there plans for this weekend?', TODAY)
        part = FX.parse_log(TG_WEEKEND)[1]                    # 7.10 "Am Wochenende" = Sat 10.10; #202 names no day
        r = AN.settle('yesno', {'answer': 'unclear', 'refs': ['#201']}, part, we, TODAY)
        self.assertEqual((r['answer'], r['in_window'], r['reason']), ('no', False, 'only past dates'))
        self.assertEqual(AN.settle('yesno', {'answer': 'unclear'}, part, we, TODAY), {'answer': 'unclear'})
        # live smoke test 15.10: no refs, a PAST date; another hit's "Mein Wochenende war ruhig" (Mon 12.10) resolves
        # to the coming weekend, so only the messages behind the date count (#202 names no day: its own, past)
        quiet = part + [{'ts': '2026-10-12 12:10', 'sender': 'Tim', 'ref': '#204', 'text': 'Mein Wochenende war ruhig'}]
        r = AN.settle('yesno', {'answer': 'unclear', 'date': '2026-10-07', 'timing': 'past', 'in_window': False},
                      quiet, we, TODAY)
        self.assertEqual((r['answer'], r['reason']), ('no', 'only past dates'))
        future = {'answer': 'unclear', 'date': '2026-10-16', 'in_window': False}   # "sag's dir bis Freitag": kept
        self.assertEqual(AN.settle('yesno', future, quiet, we, TODAY), future)
        # root cause fixed in facts.resolve_date (15.10, tense): the message itself now names the PAST weekend, so
        # citing it settles to "no" without settle's past-date narrowing (which stays as a safety net)
        mon = AN.dt.date(2026, 10, 12)
        self.assertEqual(AN.named_days('Mein Wochenende war ruhig', mon), {AN.dt.date(2026, 10, 10)})
        self.assertEqual(AN.named_days('Wie isch dis Wucheend gsi? Am Samstag gömmer go wandere', mon),
                         {AN.dt.date(2026, 10, 10), AN.dt.date(2026, 10, 17)})
        r = AN.settle('yesno', {'answer': 'unclear', 'refs': ['#204']}, quiet, we, TODAY)
        self.assertEqual((r['answer'], r['reason']), ('no', 'only past dates'))
        c = AN.ACheck(quiet, net)                        # the model's last-weekend date for it is grounded now
        self.assertEqual(c.run_kind('yesno', {'answer': 'no', 'date': '2026-10-10', 'refs': [4]})['date'],
                         '2026-10-10')
        self.assertIsNone(c.run_kind('yesno', {'answer': 'no', 'date': '2026-10-17', 'refs': [4]})['date'])
        self.assertEqual(c.run_kind('when', {'date': 'Wochenende', 'refs': [4]})['date'], '2026-10-10')
        both = [{'ts': '2026-10-14 09:00', 'sender': 'Lara', 'ref': '#9',
                 'text': 'Letztes Wochenende war toll, dieses Wochenende gehen wir wandern'}]
        self.assertEqual(AN.named_days(both[0]['text'], AN.dt.date(2026, 10, 14)),
                         {AN.dt.date(2026, 10, 10), AN.dt.date(2026, 10, 17)})
        self.assertEqual(AN.settle('yesno', {'answer': 'unclear'}, both, we, TODAY)['answer'], 'unclear')
        # "so" is no Sunday inside a sentence; each clause is checked in its message ("Sa oder So?");
        # gestern / yesterday name the day before the message
        tue = AN.dt.date(2026, 10, 13)
        self.assertEqual(AN.named_days('Das war so schön, oder?', tue), set())
        self.assertEqual(AN.named_days('Ja, so', tue), set())
        self.assertEqual(AN.named_days('Sa oder So?', tue), {AN.dt.date(2026, 10, 17), AN.dt.date(2026, 10, 18)})
        self.assertEqual(AN.named_days('Gestern war mega, morgen wieder', tue),
                         {AN.dt.date(2026, 10, 12), AN.dt.date(2026, 10, 14)})
        later = [{'ts': '2026-10-14 09:00', 'sender': 'Nina', 'ref': '#7', 'text': 'Konzert am 24.10. im ArenaA'}]
        r = AN.settle('yesno', {'answer': 'unclear'}, later, we, TODAY)
        self.assertEqual((r['answer'], r['reason']), ('no', 'only other dates'))
        for a in ({'answer': 'unclear', 'date': '2026-10-17', 'in_window': True}, {'answer': 'yes'}, {'answer': 'no'}):
            self.assertEqual(AN.settle('yesno', a, later, we, TODAY), a)          # only an unclear is settled
        self.assertEqual(AN.settle('yesno', {'answer': 'unclear'}, later, None, TODAY), {'answer': 'unclear'})
        self.assertEqual(AN.settle('short', {'answer': 'unclear'}, later, we, TODAY), {'answer': 'unclear'})
        sent_then = [{'ts': '2026-10-10 23:00', 'sender': 'Nina', 'ref': '#8', 'text': 'Party war mega, gestern auch'}]
        last_we = AN.ask_window('Was there a party last weekend?', TODAY)          # written ON the asked days: kept
        self.assertEqual(AN.settle('yesno', {'answer': 'unclear'}, sent_then, last_we, TODAY)['answer'], 'unclear')
        r = AN.timed('yesno', {'answer': 'yes', 'date': '2026-10-10'}, we, TODAY)  # a yes on another day: no + why
        self.assertEqual((r['answer'], r['reason']), ('no', 'only past dates'))
        self.assertNotIn('reason', AN.timed('yesno', {'answer': 'no', 'date': '2026-10-17'}, we, TODAY))
        # parts: yes, then a maybe ON the asked days, then no
        m = AN.merge('yesno', [{'answer': 'unclear', 'in_window': True}, {'answer': 'no', 'reason': 'only past dates'}])
        self.assertEqual(m['answer'], 'unclear')
        self.assertEqual(AN.merge('yesno', [{'answer': 'no'}, {'answer': 'unclear'}])['answer'], 'no')
        self.assertEqual(AN.merge('yesno', [{'answer': 'yes'}, {'answer': 'unclear', 'in_window': True}])['answer'],
                         'yes')

    def test_who_gives_names_or_flagged_nicknames_never_a_phrase(self):
        part = FX.parse_log(TG_WEEKEND)[1]
        c = AN.ACheck(part, net)
        self.assertEqual(c.run_kind('who', {'who': ['De mäge und de geko'], 'refs': [3]}),
                         {'who': [], 'nicknames': ['Mäge', 'Geko'], 'refs': ['#203']})
        r = c.run_kind('who', {'who': ['Marco', 'de', 'Ich', 'Alle', 'Zoe', 'You', 'Herr Huber']})
        self.assertEqual((r['who'], r['nicknames']), (['Marco', 'You', 'someone'], []))
        # leak path: a phrase, single text words not used like a name, a placeholder -> all dropped
        c = AN.ACheck(part, net)
        r = c.run_kind('who', {'who': ['gehen wir an den Cannstatter Wasen in Stuttgart', 'gehen', 'kommt',
                                       'mit', 'wir', '[private: health]', 'mäge geko wasen stuttgart']})
        self.assertEqual((r['who'], r['nicknames']), ([], []))
        self.assertGreaterEqual(c.why.get('who', 0), 6)
        r = AN.ACheck(part, net).run_kind('who', {'who': ['de mäge', 'de geko', 'mäge', 'geko', 'x', 'y', 'z']})
        self.assertEqual(r['nicknames'], ['Mäge', 'Geko'])
        w = AN.ACheck(part, net).run_kind('when', {'date': 'Am Wochenende', 'venue': 'Cannstatter Wasen',
                                                   'who': ['De mäge und de geko', 'Marco'], 'refs': [1]})
        self.assertEqual((w['date'], w['who'], w['nicknames']), ('2026-10-10', ['Marco'], ['Mäge', 'Geko']))
        # routing: who/wer is kind who, also over an explicit short (no free-text path for a who question)
        for b in ({'question': 'wer kommt mit?'}, {'question': 'Who is coming?', 'kind': 'short'},
                  {'question': 'ko dolazi?'}):
            self.assertEqual(AN.Answer.pick_kind(b, 'tg'), 'who', b)
        self.assertEqual(AN.Answer.pick_kind({'question': 'wo?'}, 'tg'), 'short')
        self.assertEqual(AN.Answer.pick_kind({'question': 'wer?', 'kind': 'when'}, 'tg'), 'when')


class TimeWordsAndWhoApiTests(TV.ApiBase):
    name = 'api-time-who'
    extra_env = {'VAULT_ASK_SESSIONS': '1'}

    def setUp(self):
        super().setUp()
        shutil.rmtree(self.cfg.state / 'answer-cache', ignore_errors=True)

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            return (0, '', '') if argv[0] == 'alias' else (0, TG_WEEKEND, '')
        self.app.tg._exec = fake_exec
        self.app.tg._aliases = None
        self.app.tg.ensure_config = lambda: False
        self.app.answer.clock = lambda: NOW_1510

    def llm(self, d):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(d))

    def answer_calls(self):
        return [c for c in TV.llm_calls() if '--schema' in c['args']]

    def test_owner_case_this_weekend_then_wo_and_wer(self):
        self.llm({'answer': 'yes', 'date': 'Am Wochenende', 'refs': [1]})
        n0 = len(self.answer_calls())
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Marco', 'since': '30d', 'kind': 'yesno',
                                              'question': 'Are there plans for this weekend?', 'session': True})
        self.assertEqual(st, 200, r)
        self.assertEqual(r['answer'], {'answer': 'no', 'date': '2026-10-10', 'timing': 'past',
                                       'relative': 'last weekend', 'in_window': False, 'reason': 'only past dates',
                                       'refs': ['#201']})
        self.assertEqual((r['asked'], r['today']),
                         ({'label': 'this weekend', 'from': '2026-10-17', 'to': '2026-10-18'}, '2026-10-15'))
        call = self.answer_calls()[n0]
        self.assertIn('Today is Thursday 2026-10-15. The question asks about this weekend: Saturday 2026-10-17 to '
                      'Sunday 2026-10-18.\nQuestion: Are there plans for this weekend?', call['text'])
        system = call['args'][call['args'].index('--system') + 1]
        self.assertIn("counts from THAT message's date, not from today", system)
        sid = r['session']['id']
        self.llm({'date': 'Am Wochenende', 'venue': 'Cannstatter Wasen', 'refs': [1]})
        st, r2 = self.call('POST', '/answer', {'session': sid, 'question': 'wo?'})
        self.assertEqual((st, r2['kind'], r2['answer']['venue'], r2['answer']['in_window'], r2['asked']['label']),
                         (200, 'when', 'Cannstatter Wasen', False, 'this weekend'))     # the earlier turn's days
        self.llm({'who': ['De mäge und de geko'], 'refs': [3]})
        st, r3 = self.call('POST', '/answer', {'session': sid, 'question': 'wer kommt mit?'})
        self.assertEqual((st, r3['kind'], r3['answer']), (200, 'who', {'nicknames': ['Mäge', 'Geko'],
                                                                      'refs': ['#203']}))
        self.assertNotIn('De mäge', json.dumps(r3, ensure_ascii=False))
        self.llm({'answer': 'De mäge und de geko', 'who': ['de mäge und de geko'], 'refs': [3]})
        st, r4 = self.call('POST', '/answer', {'session': sid, 'question': 'und wer noch?', 'kind': 'short'})
        self.assertEqual((st, r4['kind']), (200, 'who'))                  # an explicit short is still a names list
        self.assertNotIn('mäge und', json.dumps(r4, ensure_ascii=False))
        st, r5 = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Marco', 'question': 'Wer kommt mit?'})
        self.assertEqual((st, r5['kind']), (200, 'who'))                  # an opening ask too

    def test_last_weekend_is_answered_yes(self):
        self.llm({'answer': 'yes', 'date': 'Am Wochenende', 'refs': [1]})
        st, r = self.call('POST', '/answer', {'source': 'tg', 'chat': 'Marco', 'kind': 'yesno',
                                              'question': 'Are there plans for last weekend?'})
        self.assertEqual(st, 200, r)
        self.assertEqual((r['answer']['answer'], r['answer']['date'], r['answer']['in_window'], r['asked']['from']),
                         ('yes', '2026-10-10', True, '2026-10-10'))


if __name__ == '__main__':
    unittest.main(verbosity=1)
