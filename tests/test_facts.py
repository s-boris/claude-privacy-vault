#!/usr/bin/python3 -I
"""Facts, find and calendar suggestions (plan v2 #6, #10, #11, 2026-10-13).
Facts: an invented venue, name or description is dropped; the extractor only ever gets the anonymizer's output
(tgread runs with --no-paraphrase, never in raw mode; a spy reads the model's input); dates from the message times across
a year boundary; refs fixed to the messages that say it; the regex net / money net catch what the model emits; an LLM
failure returns an error and nothing partial; cached parts cost no call. Find: Swiss German / German / English
variants, ue = ü, word starts; ranking (own words first, then newest); ONE anonymize call; paperless metadata only;
a failing source gives a partial result. Plans: a plan item gets facts from the non-paraphrased wording; chatter
triggers no extraction; a facts failure keeps the event; /plans dedupes and keeps to its window; /events carries
the facts; vault-events prints "Suggest:" lines.
Run: python3 -I tests/test_facts.py (uses test_vault.py's fakes and stub LLM)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_vault as TV  # noqa: E402

import datetime as dt  # noqa: E402
import importlib.machinery  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402

import facts as FX  # noqa: E402
import find as FD  # noqa: E402
import jobs as J  # noqa: E402

V, D, S = TV.V, TV.D, TV.S
PHONE = '079 555 ' + '12 34'

TG_OUT = '\n'.join([
    'Recent messages (chat -1000000000123, since 60d): 4; chats newest first, messages oldest first. Times Europe/Zurich.',
    '',
    '### Grouptrip 2026 (group, chat -1000000000123)',
    '[2026-12-28 18:02] Anna: Wir treffen uns am 3.1. um 18:00 im Hallenbad Seeblick, Seestrasse 12 (#101)',
    '[2026-12-28 18:05] Beat: Ich bringe die Flossen mit [private: health] (#102 reply to #101)',
    '[2026-12-29 09:10] Anna: Samstag Znacht bei mir?',
    '    Wer kommt? (#103)',
    '[2026-12-29 09:12] Carla: Wer bucht das Boot für Februar? (#104)',
    '',
    '(private passages and identifiers removed by the local LLM; names and addresses kept as written.)'])
LLM_FACTS = {
    'events': [
        {'what': 'treffen Hallenbad', 'date': '3.1.', 'start': '18:00', 'venue': 'Hallenbad Seeblick',
         'address': 'Seestrasse 12', 'who': ['Anna', 'Zoe'], 'status': 'planned', 'msgs': [1]},
        {'what': 'Znacht', 'date': 'Samstag', 'venue': 'Seerestaurant Imaginaer', 'msgs': [3]},
        {'what': 'Tauchkurs in Aegypten', 'date': '5.2.', 'msgs': [2]}],
    'todos': [{'what': 'bringe die Flossen mit', 'who': 'Beat', 'msgs': [1]}],
    'places': [{'name': 'Hallenbad Seeblick', 'address': 'Seestrasse 12', 'msgs': [1]}],
    'decisions': 'garbage',
    'questions': [{'what': 'Wer bucht das Boot für Februar?', 'msgs': [4]}]}


def calls_with(flag):
    return [c for c in TV.llm_calls() if flag in c['args']]


def facts_calls():
    return [c for c in TV.llm_calls() if '--system' in c['args'] and c['args'][c['args'].index('--system') + 1]
            == FX.SYSTEM]


# Synthetic (from a live test): a reply of Wed 14.10 that quotes a mail of Tue 13.10.
QUOTED_TS = dt.datetime(2026, 10, 14, 9, 30, tzinfo=V.TZ).timestamp()
QUOTED_MAIL = '\n'.join([
    'Subject: Re: Termin', '', 'Danke, ich schaue es mir an.', '',
    'Am Di., 13. Okt. 2026 um 11:04 Uhr schrieb Anna Muster <anna@example.ch>:',
    '> Ein Termin für morgen um 15:00 Uhr wurde eingestellt.', '>',
    '> Feedback bis Freitag morgen.', '> Gruss Anna'])
QUOTED_FACTS = {'events': [{'what': 'Termin', 'date': 'morgen', 'start': '15:00 Uhr', 'msgs': [2]}],
                'todos': [{'what': 'Feedback', 'due': 'Freitag morgen', 'msgs': [1]}]}   # cites the wrong message


class DateTests(unittest.TestCase):
    def test_quoted_mail_and_weekday_morning(self):
        """Regression: "Termin für morgen" written 13.10, quoted in a reply of 14.10, came out as Thu 15.10;
        "Feedback bis Freitag morgen" too. Quotes count from their own date; a weekday + morgen is that weekday."""
        r = FX.resolve_date
        tue, wed = dt.date(2026, 10, 13), dt.date(2026, 10, 14)
        self.assertEqual(r('morgen', tue), wed)
        for ref in (tue, wed):
            self.assertEqual(r('Freitag morgen', ref), dt.date(2026, 10, 16))
            self.assertEqual(r('bis Freitagmorgen', ref), dt.date(2026, 10, 16))
        self.assertEqual(r('Freitag', dt.date(2026, 10, 16)), dt.date(2026, 10, 16))   # on or after
        self.assertEqual(r('morgen früh', wed), dt.date(2026, 10, 15))
        self.assertEqual(FX.quote_date('Am Di., 13. Okt. 2026 um 11:04 Uhr schrieb Anna <a@example.ch>:', wed),
                         '2026-10-13 11:04')
        self.assertEqual(FX.quote_date('On Tue, Oct 13, 2026 at 1:04 PM Anna <a@example.ch> wrote:', wed),
                         '2026-10-13 13:04')
        self.assertEqual(FX.quote_date('> Gesendet: Dienstag, 13. Oktober 2026 11:04', wed), '2026-10-13 11:04')
        self.assertIsNone(FX.quote_date('Am Montag schrieb ich dir', wed))            # no explicit date
        self.assertIsNone(FX.quote_date('Am 13.10.2027 schrieb Anna:', wed))           # after the mail
        msgs = FX.mail_msgs({'text': QUOTED_MAIL, 'ts': QUOTED_TS, 'from': 'Anna (example.ch)', 'ref': 'main:88'})
        self.assertEqual([m['ts'] for m in msgs], ['2026-10-14 09:30', '2026-10-13 11:04'])
        self.assertIn('Termin für morgen', msgs[1]['text'])
        self.assertNotIn('Termin', msgs[0]['text'].replace('Re: Termin', ''))
        wrapped = QUOTED_MAIL.replace('2026 um 11:04 Uhr schrieb Anna Muster <anna@example.ch>:',
                                      '2026 um 11:04 Uhr\nschrieb Anna Muster <anna@example.ch>:').replace(
            'Am Di.', 'On Di.')
        self.assertEqual([m['ts'] for m in FX.mail_msgs({'text': wrapped, 'ts': QUOTED_TS, 'from': 'A',
                                                         'ref': 'x'})], ['2026-10-14 09:30', '2026-10-13 11:04'])
        self.assertEqual(len(FX.mail_msgs({'text': 'Hallo\n\nbis morgen', 'ts': QUOTED_TS, 'from': 'A',
                                           'ref': 'x'})), 1)                       # no quote: one message

    def test_resolve(self):
        tue = dt.date(2026, 12, 29)
        r = FX.resolve_date
        self.assertEqual(r('3.1.', dt.date(2026, 12, 28)), dt.date(2027, 1, 3))          # across the new year
        self.assertEqual(r('20.12.', dt.date(2027, 1, 5)), dt.date(2026, 12, 20))
        self.assertEqual(r('Samstag', tue), dt.date(2027, 1, 2))
        self.assertEqual(r('Samschtig', tue), dt.date(2027, 1, 2))
        self.assertEqual(r('next Friday', tue), dt.date(2027, 1, 1))
        self.assertEqual(r('Dienstag', tue), tue)                     # on or after the reference date
        self.assertEqual(r('nächsten Dienstag', tue), dt.date(2027, 1, 5))
        self.assertEqual(r('morgen', tue), dt.date(2026, 12, 30))
        self.assertEqual(r('hüt znacht', tue), tue)
        self.assertEqual(r('Sa 17.10.', dt.date(2026, 10, 13)), dt.date(2026, 10, 17))
        self.assertEqual(r('3. November', dt.date(2026, 10, 13)), dt.date(2026, 11, 3))
        self.assertEqual(r('Nov 21, 2026', None), None)
        self.assertEqual(r('21.11.2026', tue), dt.date(2026, 11, 21))
        self.assertEqual(r('2026-11-21', tue), dt.date(2026, 11, 21))
        self.assertIsNone(r('irgendwann', tue))
        self.assertIsNone(r('18.30', tue))                                             # a time, not a date
        self.assertEqual(FX.norm_time('um 18.30'), '18:30')
        self.assertEqual(FX.norm_time('20 Uhr'), '20:00')
        self.assertEqual(FX.norm_time('8pm'), '20:00')
        self.assertIsNone(FX.norm_time('am 4i'))

    def test_tense(self):
        """Regression: "Mein Wochenende war ruhig" written on a Monday came out as the COMING weekend. Past-tense
        markers (war, hatte, isch gsi, hesch gmacht, was, went, letzte/last, seit) next to a weekday / weekend word
        in the same clause -> the latest one on or before the message's day; future verbs, plan words and für/bis
        keep the old reading (the next one on or after); neutral text unchanged."""
        r = FX.resolve_date
        mon, fri, sat, sun = (dt.date(2026, 10, d) for d in (12, 16, 17, 18))
        last_sat, this_sat, next_sat = dt.date(2026, 10, 10), dt.date(2026, 10, 17), dt.date(2026, 10, 24)
        past = ['Mein Wochenende war ruhig', 'Wie war dein Wochenende?', 'Das Wochenende war mega', 'Am Samstag hatte '
                'ich Besuch', 'Am Samstag waren wir im Kino', 'Was hast du am Wochenende gemacht?', 'Wir haben am '
                'Samstag gegrillt', 'Seit Samstag bin ich krank', 'Am Samschtig isch d Party gsi',
                'Wie isch dis Wucheend gsi?', 'Was hesch am Wucheend gmacht?', 'Mir händ eus am Samstag troffe',
                'My weekend was quiet', 'How was your weekend?', 'We went hiking on Saturday', 'Was it fun on '
                'Saturday?', 'We had guests on the weekend', 'I did nothing on Saturday', 'last weekend',
                'letztes Wochenende', 'letzten Samstag', 'last Saturday', 'am letzten Samstag', 'Samstag letzte Woche']
        for text in past:                              # Monday and Friday: the Saturday before (10.10)
            for ref in (mon, fri):
                self.assertEqual(r(text, ref), last_sat, (text, ref))
        future = ['Am Wochenende werden wir wandern', 'Am Samstag wird gefeiert', 'Am Wuchenend chunnt d Lara',
                  'Am Samstag chunsch au?', 'next weekend', 'nächstes Wochenende', 'kommendes Wochenende',
                  'Am Wochenende gömmer go wandere', 'I will be there on Saturday', "We'll meet on the weekend",
                  "We're going hiking on Saturday", 'Am Wochenende möchte ich wandern', 'Ich habe Tickets für '
                  'Samstag gekauft', 'Ich hatte für Samstag reserviert', 'Er hat am Samstag gesagt er kommt',
                  'Wir hatten am Samstag geplant zu grillieren', 'I booked a table for Saturday',
                  'Ich war bis Samstag weg', 'Am Samstag war noch nichts abgemacht']
        neutral = ['Wochenende', 'am Wochenende', 'Samstag', 'Am Samstag gehen wir wandern', 'Was machst du am '
                   'Wochenende?', 'Was machsch am Wucheend?', 'Was isch am Weekend?', 'Am Samstag haben wir geöffnet',
                   'Am Samstag hat er Geburtstag', 'Ich war krank. Am Samstag gehen wir wandern',
                   'War super gestern, am Samstag gehen wir wandern', 'Am Samstag sind wir in Zürich',
                   'Am Samstag ist die letzte Vorstellung', 'What are you doing on the weekend?']
        for text in future + neutral:                  # as before: the next one on or after
            self.assertEqual(r(text, mon), this_sat, text)
            self.assertEqual(r(text, fri), this_sat, text)
        self.assertEqual(r('next weekend', sat), next_sat)
        self.assertEqual(r('Samstag', sun), next_sat)                                  # unchanged on a Sunday
        self.assertEqual(r('Am Samstag hatte ich Besuch', sun), this_sat)              # yesterday
        self.assertEqual(r('Mein Wochenende war ruhig', sun), this_sat)                # the current weekend so far
        self.assertEqual(r('Mein Wochenende war ruhig', sat), this_sat)
        self.assertEqual(r('last Saturday', sat), last_sat)                            # strictly before
        self.assertEqual(r('last Saturday', sun), this_sat)
        self.assertEqual(r('Samstag letzte Woche', sun), last_sat)                     # previous Mon-Sun week
        self.assertEqual(r('Am Freitag war ich beim Arzt', fri), fri)                  # same day: today
        self.assertEqual(r('Am Freitag war ich beim Arzt', mon), dt.date(2026, 10, 9))
        self.assertEqual(r('Am Freitag gehe ich zum Arzt', mon), fri)
        self.assertEqual(r('Freitag morgen war ich müde', mon), dt.date(2026, 10, 9))  # weekday + morning
        self.assertEqual(r('morgen', mon), dt.date(2026, 10, 13))                      # REL words: no tense
        self.assertEqual(r('heute war viel los', mon), mon)
        self.assertEqual(r('Am 17.10. war Markt', mon), this_sat)                       # written dates: no tense
        # each weekday word: its own clause decides ("Letztes Wochenende war toll, dieses Wochenende wandern")
        self.assertEqual(r('dieses Wochenende wandern', mon), this_sat)
        # a quoted date ("Wochenende", "am Samstag") takes the tense of its message's words around it
        self.assertEqual(r('Wochenende', mon, context='Mein Wochenende war ruhig'), last_sat)
        self.assertEqual(r('am Samstag', fri, context='Hey! Am Samstag waren wir im Kino'), last_sat)
        self.assertEqual(r('am Samstag', mon, context='Am Samstag gehen wir ins Kino'), this_sat)
        self.assertEqual(r('Samstag', mon, context='letzten Samstag war toll'), last_sat)
        self.assertEqual(r('Samstag', mon, context='nicht dieser, sondern nächsten Samstag'), this_sat)
        both = 'Am Samstag waren wir im Kino, am Samstag gehen wir ins Theater'           # two readings: as before
        self.assertEqual(r('am Samstag', mon, context=both), this_sat)
        self.assertEqual(r('Samstag', mon, context='nichts davon'), this_sat)           # not in it: as before

    def test_weekday_abbreviations(self):
        """Regression: a whole message "Das war so schön" counted as naming a Sunday. The short forms (so, do, mi,
        sa, fr, di, mo; English sun, sat, wed, mon, tue) are ordinary words too (de, gsw, en, hr): they count only
        when clearly a date: a date or time right after ("Fr 19:00"), a date word before ("am Sa", "next Fri"), a
        daypart after ("Sa znacht"), another weekday next to it ("Sa/So", "Mo-Fr"), a trailing dot ("Do."),
        capitalized inside a sentence ("Hast du Sa Zeit?") or alone as the whole text ("Sa?"). Lowercase so/do/mi/
        sa/di/mo never. A quoted date is checked where its message wrote it."""
        r = FX.resolve_date
        tue = dt.date(2026, 10, 13)
        wed, thu, fri, sat, sun, mon = (dt.date(2026, 10, d) for d in (14, 15, 16, 17, 18, 19))
        words = ['Das war so schön', 'So schön!', 'So, jetzt gehts los', 'Ok so', 'Ja, so', 'So.', 'So?', 'So...',
                 'Was machst du so?', 'So oder so, ich komme', 'Bin so um 19 Uhr da', 'Ich komme so 19:00',
                 'Das isch so lässig gsi', 'Ruf mi a', 'Gib mer di Nummer', 'Di Mueter chunnt au',
                 'Ich gang mit Mo go schwimme', 'Fr. Müller hat angerufen', 'Ich habe Fr. Meier geschrieben',
                 'do 19:00 sam doma', 'Idem sa njim u kino', 'Mi smo doma',
                 'Do you want to come?', 'I do like it', 'The sun was out all day', 'I sat there for hours',
                 'We love the Sun.', 'that was crazy fr fr', "c'mon, let's go"]
        for text in words:
            self.assertIsNone(r(text, tue), text)
        dated = [('Fr 19:00 bei mir?', fri), ('Sa um 20 Uhr Party', sat), ('Mi 18.30 Training', wed),
                 ('Treffen am Sa?', sat), ('Hast du Sa Zeit?', sat), ('Sa.', sat), ('Sa?', sat), ('Bis Mo!', mon),
                 ('Sa oder So?', sat), ('Mo-Fr im Büro', mon), ('Am So gehen wir wandern', sun),
                 ('Kommst du am So. auch?', sun), ('Sa./So. geschlossen', sat), ('Wir sehen uns Do.', thu),
                 ('So Abend grillieren?', sun), ('Sa 17.10.', sat),
                 ('Am Sa gömmer go schwimme', sat), ('Chunsch am Fr?', fri), ('Bis am Mi', wed),
                 ('Sa znacht bi mir?', sat), ('Sa am 8i?', sat),
                 ('See you on Sat', sat), ('Fri 7pm?', fri), ('next Fri', fri), ('Mon-Fri at the office', mon),
                 ('Sat/Sun works for me', sat)]
        for text, day in dated:
            self.assertEqual(r(text, tue), day, text)
        self.assertEqual(r('Am Sa war ich krank', tue), dt.date(2026, 10, 10))         # the tense still applies
        self.assertEqual(r('Fr morgen?', tue), fri)                                    # Friday morning
        self.assertEqual(r('So morgen gehts los', tue), wed)                           # "So, morgen ...": tomorrow
        self.assertEqual(r('Samstag', tue), sat)                                       # full names: unchanged
        self.assertEqual(r('Freitagabend', tue), fri)
        # a quoted date is checked in its message (facts, answers); a quote not found there: as before
        self.assertEqual(r('So', tue, context='Treffen am So um 10?'), sun)
        self.assertEqual(r('so', tue, context='Kommst du So?'), sun)
        self.assertEqual(r('Sa', tue, context='Sa?'), sat)
        self.assertIsNone(r('so', tue, context='Das war so schön'))
        self.assertIsNone(r('So', tue, context='So schön!'))
        self.assertEqual(r('So', tue, context='nichts davon'), sun)

    def test_relative_days(self):
        """Regression: gestern / yesterday / vorgestern (geschter, vorgeschter) were not resolved at all. heute,
        morgen, übermorgen and these count from the message's own date. "morgen" after am / guten / jeden / den /
        heute / gestern or a weekday is the morning, not tomorrow. A message that also names another day (heute,
        morgen, a weekday, the weekend) keeps that day: gestern comes last."""
        r = FX.resolve_date
        tue = dt.date(2026, 10, 13)

        def d(n):
            return tue + dt.timedelta(days=n)
        cases = [('gestern', -1), ('Gestern war mega', -1), ('Wie war die Party gestern?', -1), ('vorgestern', -2),
                 ('Vorgestern hatte ich Besuch', -2), ('heute', 0), ('Heute Abend Kino?', 0), ('morgen', 1),
                 ('Morgen um 9 beim Bahnhof', 1), ('bis morgen!', 1), ('morgen früh', 1), ('übermorgen', 2),
                 ('Übermorgen fliege ich', 2),
                 ('geschter', -1), ('Geschter isch es lässig gsi', -1), ('vorgeschter', -2), ('hüt', 0),
                 ('Hüt znacht?', 0), ('morn', 1), ('Morn am 8i', 1), ('übermorn', 2), ('Chunsch morn au?', 1),
                 ('yesterday', -1), ('Yesterday was great', -1), ('the day before yesterday', -2), ('today', 0),
                 ('tonight?', 0), ('tomorrow', 1), ('See you tomorrow', 1), ('the day after tomorrow', 2),
                 ('heute Morgen war ich joggen', 0), ('Gestern Morgen war ich joggen', -1), ('gestern morgen', -1),
                 ('Vorgestern am Morgen', -2)]
        for text, n in cases:
            self.assertEqual(r(text, tue), d(n), text)
        for text in ('Guten Morgen!', 'Am Morgen bin ich müde', 'Jeden Morgen joggen', 'Den ganzen Morgen gearbeitet',
                     'Schönen Morgen dir', 'Morgen allerseits', 'Good morning'):
            self.assertIsNone(r(text, tue), text)
        self.assertEqual(r('Freitag morgen', tue), dt.date(2026, 10, 16))              # Friday morning (14.10)
        self.assertEqual(r('War super gestern, am Samstag gehen wir wandern', tue), dt.date(2026, 10, 17))
        self.assertEqual(r('Gestern Kino, heute Ruhe', tue), tue)
        self.assertEqual(r('gestern', dt.date(2027, 1, 1)), dt.date(2026, 12, 31))     # across the new year
        self.assertEqual(r('gestern', tue, context='Gestern war mega'), d(-1))         # quoted

    def test_parse_log_and_chunks(self):
        chat, msgs = FX.parse_log(TG_OUT)
        self.assertEqual(chat, 'Grouptrip 2026')
        self.assertEqual([m['ref'] for m in msgs], ['#101', '#102', '#103', '#104'])
        self.assertEqual(msgs[2]['text'], 'Samstag Znacht bei mir?\nWer kommt?')
        many = [{'ts': f'2026-10-{d:02d} 10:00', 'sender': 'A', 'text': 'x' * 900, 'ref': f'#{d}'}
                for d in range(1, 21)]
        parts = FX.chunks(many)
        self.assertTrue(all(sum(len(m['text']) + 25 for m in p) <= FX.CHUNK_CHARS for p in parts))
        self.assertEqual(sum(len(p) for p in parts), 20)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.cfg = TV.make_cfg('facts-check')
        self.gate = V.LLMGate(flush=lambda: None)
        self.pol = V.Policy(self.cfg, self.gate)
        _, self.msgs = FX.parse_log(TG_OUT)

    def test_grounding_refs_and_drops(self):
        ck = FX.Check(self.msgs, self.pol.regex_net)
        f = ck.run(LLM_FACTS)
        ev = f['events']
        self.assertEqual(len(ev), 2)                                                   # the invented one is gone
        self.assertEqual(ev[0]['date'], '2027-01-03')
        self.assertEqual(ev[0]['date_text'], '3.1.')
        self.assertEqual(ev[0]['start'], '18:00')
        self.assertEqual(ev[0]['who'], ['Anna'])
        self.assertEqual(ev[0]['refs'], ['#101'])
        self.assertEqual(ev[1]['date'], '2027-01-02')
        self.assertNotIn('venue', ev[1])                                               # invented venue dropped
        self.assertEqual(f['todos'][0]['refs'], ['#102'])                              # wrong citation fixed
        self.assertEqual(f['questions'][0]['refs'], ['#104'])
        self.assertEqual(f['places'][0]['name'], 'Hallenbad Seeblick')
        self.assertEqual(ck.why, {'who': 1, 'venue': 1, 'what': 1, 'refs': 1, 'decisions': 1})
        self.assertNotIn('Aegypten', json.dumps(f))

    def test_event_date_takes_its_message_tense(self):
        """Regression: the model quotes only "Wochenende"; the cited message's "war" makes it the past weekend."""
        part = [{'ts': '2026-10-12 08:10', 'sender': 'Tim', 'ref': '#1', 'text': 'Mein Wochenende war ruhig'},
                {'ts': '2026-10-12 08:12', 'sender': 'Lara', 'ref': '#2', 'text': 'Am Wochenende gehen wir wandern'}]
        llm = {'events': [{'what': 'ruhig', 'date': 'Wochenende', 'msgs': [1]},
                          {'what': 'wandern', 'date': 'Wochenende', 'msgs': [2]}]}
        ev = FX.Check(part, self.pol.regex_net).run(llm)['events']
        self.assertEqual([(e['date_text'], e['date']) for e in ev],
                         [('Wochenende', '2026-10-10'), ('Wochenende', '2026-10-17')])

    def test_regex_and_money_net_last(self):
        part = [{'ts': '2026-10-10 18:00', 'sender': 'Anna', 'ref': '#1',
                 'text': f'Treffpunkt Bahnhof, ruf an unter {PHONE}, Rechnung CHF 120 bezahlen'}]
        llm = {'places': [{'name': 'Bahnhof', 'address': PHONE, 'msgs': [1]}],
               'todos': [{'what': 'Rechnung CHF 120 bezahlen', 'msgs': [1]}]}
        out = FX.Check(part, self.pol.regex_net).run(llm)
        self.assertNotIn('555', json.dumps(out))                                       # the net masked the phone
        mail = FX.Check(part, lambda s: self.pol.money_net(self.pol.regex_net(s))).run(llm)
        self.assertNotIn('CHF 120', json.dumps(mail, ensure_ascii=False))
        # v3.1 fix (13.10): the mail money net keeps postcodes and never turns a phone into [amount]
        addr = 'Paid. Ship to Examplestrasse 1, 1234 Exampletown (+41) 791234567, total $12.34'
        out = self.pol.money_net(addr)
        self.assertIn('1234 Exampletown', out)
        self.assertIn('791234567', out)
        self.assertNotIn('$12.34', out)

    def test_caps_and_bad_answers(self):
        ck = FX.Check(self.msgs, self.pol.regex_net)
        many = {'questions': [{'what': 'Wer bucht das Boot', 'msgs': [4]}] * 40}
        self.assertEqual(len(ck.run(many)['questions']), FX.PART_MAX)
        with self.assertRaises(V.VaultError):
            ck.run(['not', 'a', 'dict'])
        self.assertEqual(FX.Check(self.msgs, self.pol.regex_net).run({'events': [{'what': 'x' * 300}]})['events'], [])


class FactsApiTests(TV.ApiBase):
    name = 'api-facts'

    def setUp(self):
        super().setUp()
        shutil.rmtree(self.cfg.state / 'facts-cache', ignore_errors=True)
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(LLM_FACTS))
        self.argvs = []

        def fake_exec(argv, timeout, stdin=None, stop_on_gone=False):
            self.argvs.append(list(argv))
            return 0, TG_OUT, 'tgread: local LLM anonymizer: 400 characters'
        self.app.tg._exec = fake_exec
        self.app.tg.ensure_config = lambda: False

    def test_tg_facts_from_anonymized_text_only(self):
        n0 = len(TV.llm_calls())
        st, r = self.call('POST', '/tg/facts', {'chat': 'Grouptrip 2026', 'since': '60d'})
        self.assertEqual(st, 200, r)
        argv = self.argvs[-1]
        self.assertEqual(argv[0], 'recent')
        self.assertIn('--no-paraphrase', argv)
        self.assertNotIn('--raw', argv)
        spy = facts_calls()[-1]                                                        # what the model got
        self.assertIn('[m1] 2026-12-28 18:02 Anna: Wir treffen uns am 3.1.', spy['text'])
        self.assertIn('[private: health]', TV.llm_calls()[-1]['text'] + json.dumps(r))
        self.assertEqual(len(TV.llm_calls()) - n0, 1)                                  # one structured call
        self.assertEqual(r['chat'], 'Grouptrip 2026')
        self.assertEqual(r['messages'], 4)
        self.assertEqual(r['events'][0]['date'], '2027-01-03')
        self.assertEqual(r['todos'][0]['refs'], ['#102'])
        self.assertEqual(r['dropped_fields'], {'decisions': 1, 'refs': 1, 'venue': 1, 'what': 1, 'who': 1})
        st, r2 = self.call('POST', '/tg/facts', {'chat': 'Grouptrip 2026', 'since': '60d'})
        self.assertEqual((st, r2['cached_parts']), (200, 1))                           # cached: no model call
        self.assertEqual(len(TV.llm_calls()) - n0, 1)
        self.assertEqual(r2['events'], r['events'])
        cache = list((self.cfg.state / 'facts-cache').glob('*/*.json'))
        self.assertTrue(cache and all(p.stat().st_mode & 0o777 == 0o600 for p in cache))
        self.assertTrue(self.app.policy.clear_cache())                                 # tg purge/exclude/wipe
        self.assertFalse((self.cfg.state / 'facts-cache').exists())

    def test_failure_returns_nothing_partial(self):
        TV.llm_mode('fail')
        st, r = self.call('POST', '/tg/facts', {'chat': 'Grouptrip 2026'})
        self.assertNotEqual(st, 200)
        self.assertNotIn('events', r)
        TV.llm_mode('ok')
        (TV.STUB_DIR / 'llm-json').write_text('not json')
        st, r = self.call('POST', '/tg/facts', {'chat': 'Grouptrip 2026'})
        self.assertEqual(st, 502, r)
        self.assertNotIn('events', r)

    def test_validation_and_jobs(self):
        for body in ({}, {'chat': 'x\ny'}, {'chat': 'x', 'since': 'yesterday-ish'}, {'chat': 'x', 'n': 9999}):
            self.assertEqual(self.call('POST', '/tg/facts', body)[0], 400, body)
        self.assertEqual(J.OPS['tg.facts'], ('POST', '/tg/facts'))
        self.assertEqual(J.OPS['find'], ('POST', '/find'))
        st, j = self.call('POST', '/jobs', {'op': 'tg.facts', 'params': {'chat': 'Grouptrip 2026'}})
        self.assertEqual(st, 200, j)
        for _ in range(60):
            st, g = self.call('GET', f"/jobs/{j['id']}?wait=1")
            if g['state'] not in ('queued', 'running'):
                break
        self.assertEqual(g['state'], 'done', g)
        self.assertEqual(g['result']['chat'], 'Grouptrip 2026')

    def test_gmail_facts_money_net(self):
        class FakeGmail:
            def anon_doc(_, ref, folder, chars, account):
                return {'text': 'Subject: Rechnung\n\nBitte bis 30.11. CHF 120 bezahlen. Termin am 4.11. um 9 Uhr.',
                        'ts': time.time(), 'from': 'Praxis (example.ch)', 'ref': 'main:77', 'account': 'main'}
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps({
            'todos': [{'what': 'CHF 120 bezahlen', 'due': '30.11.', 'msgs': [1]}],
            'events': [{'what': 'Termin', 'date': '4.11.', 'start': '9 Uhr', 'msgs': [1]}]}))
        self.app.facts.gmail = FakeGmail()
        st, r = self.call('POST', '/gmail/facts', {'uid': 'main:77'})
        self.assertEqual(st, 200, r)
        self.assertNotIn('CHF 120', json.dumps(r, ensure_ascii=False))
        self.assertEqual(r['events'][0]['start'], '09:00')
        self.assertEqual(r['events'][0]['refs'], ['main:77'])

    def test_gmail_facts_quoted_relative_dates(self):
        """Regression (synthetic fixture): /gmail/facts and the event feed date "morgen" in a quoted mail of 13.10
        as the 14th (not Thu 15.10) and "Freitag morgen" as Fri 16.10 (not Thu 15.10)."""
        class FakeGmail:
            def anon_doc(_, ref, folder, chars, account):
                return {'text': QUOTED_MAIL, 'ts': QUOTED_TS, 'from': 'Anna (example.ch)', 'ref': 'main:88',
                        'account': 'main'}
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps(QUOTED_FACTS))
        self.app.facts.gmail = FakeGmail()
        st, r = self.call('POST', '/gmail/facts', {'uid': 'main:88'})
        self.assertEqual(st, 200, r)
        ev, todo = r['events'][0], r['todos'][0]
        self.assertEqual((ev['date'], ev['date_text'], ev['start'], ev['refs']),
                         ('2026-10-14', 'morgen', '15:00', ['main:88']))
        self.assertEqual((todo['due'], todo['due_text']), ('2026-10-16', 'Freitag morgen'))
        got = self.app.facts.for_events([{'ts': QUOTED_TS, 'sender': 'Anna (example.ch)', 'text': QUOTED_MAIL}],
                                        'gmail')
        self.assertEqual(sorted((f['kind'], f.get('date') or f.get('due')) for f in got[0]),
                         [('event', '2026-10-14'), ('todo', '2026-10-16')])


HITS = [{'chat_id': -1000000000123, 'chat': 'Grouptrip 2026', 'chat_type': 'group', 'msg_id': 7, 'ts': 1760000000,
         'line': '[2025-10-09 10:53] Anna: Hochziit vom PersonG isch am 12.05. (#7)'},
        {'chat_id': 42, 'chat': 'PersonE', 'chat_type': 'user', 'msg_id': 9, 'ts': 1750000000,
         'line': '[2025-06-15 17:06] PersonE: Die Hochzeit wird gross Herzschmerz (#9)'}]


@TV.legacy_text
class FindTests(TV.ApiBase):
    name = 'api-find'

    def setUp(self):
        super().setUp()
        TV.llm_mode('plain')
        self.app.tg.find_hits = lambda q, since=None, n=15: [dict(h) for h in HITS]
        self.app.gmail.find_rows = lambda q, plain, n=10, folder='INBOX': ([
            {'account': 'main', 'uid': 5, 'ts': 1755000000, 'size': 10, 'from': 'PersonG (example.ch)',
             'subject': 'Einladung Hochzeit', 'snippet': 'Wir heiraten am 12.05.', 'atts': []}], {})
        self.app.paperless.search = lambda q, n=5: {'count': 1, 'results': [
            {'id': 3, 'created': '2025-01-02', 'title': 'Hochzeitsfoto Rechnung', 'document_type': 'Rechnung',
             'correspondent': 'Fotograf', 'tags': [], 'url': 'x'}]}

    def test_variants_and_folding(self):
        tg = self.app.policy.tg()
        self.assertIn('hochziit', tg.expand_word('Hochzeit'))
        self.assertIn('wedding', tg.expand_word('Hochziit'))
        self.assertIn('freitag', tg.expand_word('Fritig'))
        self.assertIn('junggesellenabschied', tg.expand_word('JGA'))
        self.assertIn('geburtstag', tg.expand_word('Geburi'))
        self.assertIn('fuer', tg.expand_word('für'))
        self.assertIn('hochzeit', tg.expand_word('Hochzeiten'))                       # word starts
        q = tg.build_fts_query('Hochzeit', expand=True)
        self.assertIn('"hochziit"*', q)
        self.assertNotIn('--expand', S.build_tg_argv('search', {'query': 'x'}))
        self.assertIn('--expand', S.build_tg_argv('search', {'query': 'x', 'expand': True}))
        self.assertIn('{hochzeit hochziit', FD.gmail_query(tg.expand_query('Hochzeit'), '30d'))
        self.assertTrue(FD.gmail_query(tg.expand_query('Hochzeit'), '30d').endswith('newer_than:30d'))
        self.assertLessEqual(len(FD.paperless_query(tg.expand_query('Hochzeit Fritig JGA Geburi'))), FD.PL_MAX)

    def test_ranked_one_anonymize_call(self):
        n0 = len(calls_with('--anonymize'))
        st, r = self.call('POST', '/find', {'q': 'Hochzeit', 'since': '30d'})
        self.assertEqual(st, 200, r)
        self.assertEqual(len(calls_with('--anonymize')) - n0, 1)                     # ONE call for tg + gmail
        last = calls_with('--anonymize')[-1]['args']
        self.assertIn('--paraphrase', last)
        self.assertIn('--all-amounts', last)                                           # mail in the batch
        # the query's own word (2) before a variant only (1), then newest first
        self.assertEqual([(x['source'], x['score']) for x in r['results']],
                         [('gmail', 2), ('tg', 2), ('paperless', 2), ('tg', 1)])
        self.assertEqual(r['results'][0]['ref'], 'main:5')
        self.assertTrue(any('Hochziit' in (x.get('text') or '') for x in r['results']))
        self.assertNotIn('Herzschmerz', json.dumps(r, ensure_ascii=False))
        doc = next(x for x in r['results'] if x['source'] == 'paperless')
        self.assertNotIn('content', doc)
        self.assertEqual(doc['title'], 'Hochzeitsfoto Rechnung')
        ranks = [x['rank'] for x in r['results']]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))

    def test_partial_and_validation(self):
        def boom(*a, **k):
            raise V.VaultError('imap down', 502, 'source_failed')
        self.app.gmail.find_rows = boom
        st, r = self.call('POST', '/find', {'q': 'Hochzeit', 'sources': ['tg', 'gmail']})
        self.assertEqual(st, 200, r)
        self.assertIn('gmail', r['errors'])
        self.assertTrue(r['results'] and all(x['source'] == 'tg' for x in r['results']))
        self.app.tg.find_hits = boom
        st, r = self.call('POST', '/find', {'q': 'Hochzeit', 'sources': ['tg', 'gmail']})
        self.assertEqual(st, 502)
        for body in ({}, {'q': ''}, {'q': 'x', 'sources': ['web']}, {'q': 'x', 'n': 0}, {'q': 'x', 'since': 'soon'}):
            self.assertEqual(self.call('POST', '/find', body)[0], 400, body)


class PlansTests(TV.ApiBase):
    name = 'api-plans'

    def setUp(self):
        super().setUp()
        TV.llm_mode('plain')
        shutil.rmtree(self.cfg.state / 'facts-cache', ignore_errors=True)
        self.app.feed.facts.run_json = self.app.facts._run_json
        self.app.feed.facts_state.update(ok=0, failed=0)

    def item(self, text, n, ts=None):
        ts = ts or time.time() - 60
        line = f"[{V.now_iso(ts)[:16].replace('T', ' ')}] Anna: {text} (#{n})"
        return {'ts': ts, 'chat_key': '-777', 'chat': 'No Fomo Gang', 'chat_type': 'group', 'sender': 'Anna',
                'sender_key': '5', 'text': line, 'quiet': None, 'msg_id': n}

    def triage(self, labels, facts):
        (TV.STUB_DIR / 'llm-json').write_text(json.dumps({'results': [
            {'i': i, 'label': lab, 'actionable': lab != 'chatter'} for i, lab in enumerate(labels, 1)], **facts}))

    def test_plan_item_gets_facts_from_unparaphrased_text(self):
        self.triage(['plan_datetime', 'chatter'], {'events': [
            {'what': 'Oktoberfest', 'date': 'Samstag', 'start': '16:00', 'venue': 'Büsingen', 'msgs': [1]}]})
        rows = self.app.feed.process('telegram', {'owner_name': 'Alex', 'items': [
            self.item('Oktoberfest am Samstag um 16:00 in Büsingen, Treffpunkt Bahnhof', 55),
            self.item('haha', 56)]})
        spy = facts_calls()[-1]['text']
        self.assertIn('Treffpunkt', spy)                                               # not the paraphrase
        self.assertNotIn('Meeting point', spy)
        plan = next(r for r in rows if r['ref'] == '55')
        self.assertIsNone(plan['text'])                                    # privacy plan A: no text, only facts
        f = json.loads(plan['facts'])
        today = dt.datetime.now(V.TZ).date()
        sat = today + dt.timedelta(days=(5 - today.weekday()) % 7 or 7)
        self.assertEqual((f[0]['kind'], f[0]['date'], f[0]['start'], f[0]['venue']),
                         ('event', sat.isoformat(), '16:00', 'Büsingen'))
        self.assertIsNone(next(r for r in rows if r['ref'] == '56')['facts'])
        st, ev = self.call('GET', '/events?since=0&max=50')
        self.assertTrue(any(e.get('facts') for e in ev['events']))
        st, p = self.call('GET', '/plans?days=14')
        self.assertEqual(st, 200, p)
        self.assertEqual([(x['date'], x['what'], x['chat']) for x in p['plans']][-1:],
                         [(sat.isoformat(), 'Oktoberfest', 'group')])    # privacy plan A: a group w/o alias

    def test_chatter_no_extraction_and_failure_keeps_event(self):
        self.triage(['chatter'], {'events': []})
        n0 = len(facts_calls())
        self.app.feed.process('telegram', {'owner_name': 'Alex', 'items': [self.item('haha am Samstag', 60)]})
        self.assertEqual(len(facts_calls()), n0)                                       # chatter: no facts call

        def fail(*a, **k):
            raise V.LLMUnavailable('local LLM timed out after 900 s')
        self.app.feed.facts.run_json = fail
        self.triage(['plan_datetime'], {})
        rows = self.app.feed.process('telegram', {'owner_name': 'Alex', 'items': [
            self.item('Grillabend am Freitag um 19 Uhr', 61)]})
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]['facts'])
        self.assertEqual((rows[0]['label'], rows[0]['text']), ('plan_datetime', None))   # the event stays
        self.assertEqual(self.app.feed.facts_state['failed'], 1)

    def test_plans_dedupe_and_window(self):
        today = dt.datetime.now(V.TZ).date()
        d3, d30 = (today + dt.timedelta(days=3)).isoformat(), (today + dt.timedelta(days=30)).isoformat()
        ev = lambda what, d, **kw: dict({'kind': 'event', 'what': what, 'date': d}, **kw)   # noqa: E731
        rows = [{'source': 'telegram', 'ts': int(time.time()), 'chat_key': '-9', 'chat': 'Gang', 'label': 'plan_datetime',
                 'actionable': 1, 'text': 'x', 'ref': str(n), 'facts': json.dumps(fs)} for n, fs in enumerate([
                     [ev('Grillabend', d3, start='19:00')], [ev('grillabend', d3, start='19:00')],
                     [ev('Konzert', d30)], [ev('Kino', d3, status='cancelled')],
                     [{'kind': 'todo', 'what': 'Boot buchen', 'due': d3}]], 300)]
        self.app.events.add(rows)
        st, p = self.call('GET', '/plans?days=14')
        whats = [x['what'] for x in p['plans']]
        self.assertEqual(whats.count('Grillabend') + whats.count('grillabend'), 1)
        self.assertIn('Boot buchen', whats)
        self.assertNotIn('Konzert', whats)
        self.assertNotIn('Kino', whats)
        g = next(x for x in p['plans'] if x['what'].lower() == 'grillabend')
        self.assertEqual(g['mentions'], 2)
        self.assertEqual(self.call('GET', '/plans?days=0')[0], 400)


class VaultEventsSuggestTests(unittest.TestCase):
    PATH = '/home/node/bin/vault-events'

    @unittest.skipUnless(os.path.exists(PATH), 'the vault-events client is not in the image')
    def test_suggest_lines(self):
        ld = importlib.machinery.SourceFileLoader('vault_events', self.PATH)
        spec = importlib.util.spec_from_loader('vault_events', ld)
        m = importlib.util.module_from_spec(spec)
        ld.exec_module(m)
        day = dt.date.today() + dt.timedelta(days=4)
        events = [{'cursor': 1, 'source': 'telegram', 'ts': V.now_iso(), 'chat': 'No Fomo Gang', 'sender': 'Anna',
                   'label': 'plan_datetime', 'actionable': True, 'text': 'Oktoberfest', 'chat_key': '-1',
                   'facts': [{'kind': 'event', 'what': 'Oktoberfest', 'date': day.isoformat(), 'start': '16:00',
                              'venue': 'Büsingen'},
                             {'kind': 'event', 'what': 'Old', 'date': '2020-01-01'}]}]
        note = m.note_text(events, 0, 1)
        self.assertIn(f"Suggest: {day.strftime('%a %d.%m')} 16:00 Oktoberfest, Büsingen · No Fomo Gang", note)
        self.assertNotIn('Old', note)


if __name__ == '__main__':
    unittest.main(verbosity=1)
