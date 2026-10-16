#!/usr/bin/python3 -I
"""Answer-quality eval for POST /answer (`vault ask`), 2026-10-15: typical questions of each kind (yesno, when, who,
count, short) in German, Swiss German and English over INVENTED fixture chats (never real messages), each with an
expected verdict. Every case runs the real pipeline (Answer.result: today + the asked days in the prompt, one
grammar-constrained call per part, ACheck, timed, merge) with today fixed to Thu 2026-10-15 (this weekend = 17./18.10).

  python3 -I tests/eval_answers.py --real [--save FILE] [--only ID|KIND,...] [-v]
      the real local model through llm-local: env EVAL_LLM_LOCAL, else /opt/vault/vendor/llm-local (in the image),
      else ~/bin/llm-local (backend vault: `vault llm-run`, the vault's own model). ~10-25 s a case on CPU.
  python3 -I tests/eval_answers.py --replay FILE [--only ...] [-v]
      score recorded model outputs again: for code-side changes only (a changed prompt or fixture misses the
      recording; such cases are counted as stale, not scored). tests/eval_answers.rec.json = the answer-7 run.
  python3 -I tests/eval_answers.py            the fixtures are consistent (asked windows, kinds); no model
Prints one line per case (verdict, expected, got) and the score per kind and in total. --min 0.8 exits 1 below it.
Record runs of the whole set in tests/eval_answers.log (date, commit, score per kind)."""
import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'app'))
if os.environ.get('EVAL_APP_DIR'):                     # score another answer.py (e.g. the deployed one) on the same set
    sys.path.insert(0, os.environ['EVAL_APP_DIR'])
import answer as AN  # noqa: E402

NOW = 1792015500                         # Thu 2026-10-15 00:05 Europe/Zurich
TODAY = AN.dt.date(2026, 10, 15)


def chat(*lines, ref0=100):
    """'YYYY-MM-DD HH:MM|Sender|text' lines (oldest first) -> messages as the vault builds them."""
    out = []
    for i, ln in enumerate(lines):
        ts, sender, text = ln.split('|', 2)
        out.append({'ts': ts, 'sender': sender, 'text': text, 'ref': f'#{ref0 + i}'})
    return out


# ~20 keyword-search hits for "Wochenende"/"weekend" over the last 30 days from several chats; the only plans in
# them are past ones (a live case: "Are there plans for this weekend?" came back "unclear").
HITS_PAST = [
    '2026-09-18 17:40|Lara|Schönes Wochenende euch allen!',
    '2026-09-21 08:12|You|Und, wie war dein Wochenende?',
    '2026-09-25 16:55|Sarah|Have a nice weekend everyone, see you Monday',
    '2026-09-26 10:03|Nina|Dieses Wochenende bin ich in Bern bei meinen Eltern',
    '2026-09-28 12:30|Tim|Weekend was way too short',
    '2026-10-01 19:20|Marco|Am Wochenende ist Oktoberfest in München, kommst du mit?',
    '2026-10-01 19:31|You|Ja klar, fürs Wochenende bin ich dabei',
    '2026-10-05 09:14|Lara|Was für ein Wochenende 😅',
    '2026-10-07 19:02|Marco|Am Wochenende gehen wir an den Cannstatter Wasen in Stuttgart',
    '2026-10-08 18:47|PersonF|Hast du am Wochenende Zeit, beim Zügeln zu helfen?',
    '2026-10-08 20:15|You|Am Wochenende geht leider nicht, bin in Stuttgart',
    '2026-10-09 07:58|Sarah|Any plans for the weekend?',
    '2026-10-09 08:20|You|Stuttgart this weekend, Wasen with Marco',
    '2026-10-11 21:05|Nina|Wie war das Wochenende in Stuttgart?',
    '2026-10-12 07:45|Ben|Weekend was fun, thanks again for the BBQ',
    '2026-10-12 12:10|Tim|Mein Wochenende war ruhig, nur Netflix',
    '2026-10-13 18:30|Lara|Das letzte Wochenende war echt anstrengend',
    '2026-10-14 09:02|PersonF|Danke nochmal fürs Wochenende, Umzug ist geschafft',
]
HITS_MAYBE = HITS_PAST + ['2026-10-14 21:10|Tim|Vielleicht gehen wir am Wochenende an den Rhein, mal schauen wie '
                          'das Wetter wird']
HITS_BURIED_YES = HITS_PAST[:12] + [
    '2026-10-13 20:41|Nina|Samstag Abend Geburtstagsznacht bei mir, kommst du? 🎂 Wochenende wird gut',
    '2026-10-13 20:50|You|Klar, am Wochenende bin ich dabei!'] + HITS_PAST[12:]

CASES = [
    # ---------------------------------------------------------------- yesno
    {'id': 'yn_hits_past_only', 'kind': 'yesno', 'lang': 'en', 'q': 'Are there plans for this weekend?',
     'msgs': chat(*HITS_PAST), 'asked': 'this weekend', 'expect': {'answer': 'no'}},
    {'id': 'yn_hits_buried_yes', 'kind': 'yesno', 'lang': 'de', 'q': 'Haben wir dieses Wochenende etwas vor?',
     'msgs': chat(*HITS_BURIED_YES), 'asked': 'this weekend', 'expect': {'answer': 'yes', 'date': '2026-10-17'}},
    {'id': 'yn_in_window_en', 'kind': 'yesno', 'lang': 'en', 'q': 'Anything planned for Saturday?',
     'msgs': chat('2026-10-12 18:02|Ben|Escape room on Saturday at 15:00? I can book for four',
                  '2026-10-12 18:10|You|Yes, book it', '2026-10-12 18:11|Ben|Booked 👍'),
     'asked': 'Saturday', 'expect': {'answer': 'yes', 'date': '2026-10-17'}},
    {'id': 'yn_no_plan_ch', 'kind': 'yesno', 'lang': 'gsw', 'q': 'Hämmer am Wuchenend öppis abgmacht?',
     'msgs': chat('2026-10-13 19:10|Reto|Hesch de Match geschter gseh?', '2026-10-13 19:14|You|Jo, brutal gsi',
                  '2026-10-13 19:15|Reto|De Goalie isch e Katastrophe', '2026-10-14 12:01|Reto|Bis bald mal'),
     'asked': 'this weekend', 'expect': {'answer': 'no'}},
    {'id': 'yn_unclear_ch', 'kind': 'yesno', 'lang': 'gsw', 'q': 'Chunt de Beat am Samschtig mit is Kino?',
     'msgs': chat('2026-10-13 18:20|You|Samschtig Kino, bisch dabii?',
                  '2026-10-13 19:45|Beat|Muess no luege, sägs dir bis am Friitig'),
     'asked': 'Saturday', 'expect': {'answer': 'unclear'}},
    {'id': 'yn_next_we_other_dates', 'kind': 'yesno', 'lang': 'en', 'q': 'Do we have plans next weekend?',
     'msgs': chat('2026-10-05 08:30|Sarah|Last weekend was great, thanks for the hike',
                  '2026-10-12 17:00|Sarah|This Saturday we hike the Säntis, train at 7:10',
                  '2026-10-12 17:05|You|Perfect, see you Saturday'),
     'asked': 'next weekend', 'expect': {'answer': 'no'}},
    {'id': 'yn_fact_yes_de', 'kind': 'yesno', 'lang': 'de', 'q': 'Hat Lara das Paket schon abgeholt?',
     'msgs': chat('2026-10-12 10:00|You|Kannst du mein Paket bei der Post abholen?',
                  '2026-10-13 17:22|Lara|Paket abgeholt, liegt bei mir im Gang'),
     'asked': None, 'expect': {'answer': 'yes'}},
    {'id': 'yn_fact_no_en', 'kind': 'yesno', 'lang': 'en', 'q': 'Has Marco sent the concert tickets yet?',
     'msgs': chat('2026-10-10 11:00|You|Can you send me the concert tickets?',
                  '2026-10-11 09:30|Marco|Not yet, I will send them next week, promise'),
     'asked': None, 'expect': {'answer': 'no'}},
    {'id': 'yn_today_de', 'kind': 'yesno', 'lang': 'de', 'q': 'Ist heute etwas abgemacht?',
     'msgs': chat('2026-10-14 16:20|Tim|Treffen wir uns morgen um 19 Uhr im Kafi Seeblick?',
                  '2026-10-14 16:31|You|Ja, passt'),
     'asked': 'today', 'expect': {'answer': 'yes', 'date': '2026-10-15'}},
    {'id': 'yn_last_we_yes', 'kind': 'yesno', 'lang': 'en', 'q': 'Was there a party last weekend?',
     'msgs': chat('2026-10-07 13:00|Nina|Am Samstag ist Party bei mir, ab 21 Uhr!', '2026-10-07 13:05|You|Bin da'),
     'asked': 'last weekend', 'expect': {'answer': 'yes', 'date': '2026-10-10'}},
    {'id': 'yn_hits_past_only_de', 'kind': 'yesno', 'lang': 'de', 'q': 'Ist am Wochenende etwas geplant?',
     'msgs': chat(*HITS_PAST), 'asked': 'this weekend', 'expect': {'answer': 'no'}},
    {'id': 'yn_hits_past_only_ch', 'kind': 'yesno', 'lang': 'gsw', 'q': 'Hämmer da Wuchenend öppis los?',
     'msgs': chat(*HITS_PAST), 'asked': 'this weekend', 'expect': {'answer': 'no'}},
    {'id': 'yn_tomorrow_other_day', 'kind': 'yesno', 'lang': 'de', 'q': 'Habe ich morgen etwas abgemacht?',
     'msgs': chat('2026-10-13 18:00|Lara|Samstag Kino um 20 Uhr?', '2026-10-13 18:02|You|Ja gern',
                  '2026-10-12 09:00|Tim|Am Dienstag Lunch war super'),
     'asked': 'tomorrow', 'expect': {'answer': 'no'}},
    {'id': 'yn_next_week_maybe', 'kind': 'yesno', 'lang': 'de', 'q': 'Gehen wir nächste Woche klettern?',
     'msgs': chat('2026-10-14 19:00|PersonF|Vielleicht nächste Woche mal klettern, schauen wir spontan',
                  '2026-10-14 19:10|You|Mal schauen'),
     'asked': 'next week', 'expect': {'answer': 'unclear'}},
    # held out (written after the prompt was tuned, 15.10): a maybe ON the asked days among past-only hits
    {'id': 'yn_hits_maybe', 'kind': 'yesno', 'lang': 'en', 'q': 'Are there plans for this weekend?',
     'msgs': chat(*HITS_MAYBE), 'asked': 'this weekend', 'expect': {'answer': 'unclear'}},
    # ---------------------------------------------------------------- when
    {'id': 'when_concert_de', 'kind': 'when', 'lang': 'de', 'q': 'Wann ist das Konzert?',
     'msgs': chat('2026-10-09 12:00|Nina|Tickets für ArtistA sind da! Am 24.10. im ArenaA, Einlass 20:00',
                  '2026-10-09 12:04|You|Mega, freu mich'),
     'asked': None, 'expect': {'date': '2026-10-24', 'start': '20:00', 'venue_has': 'ArenaA'}},
    {'id': 'when_climb_ch', 'kind': 'when', 'lang': 'gsw', 'q': 'Wänn gömmer go klättere?',
     'msgs': chat('2026-10-13 21:00|PersonF|Klättere am Samschtig am 10i im Gaswerk?', '2026-10-13 21:03|You|Jo passt'),
     'asked': None, 'expect': {'date': '2026-10-17', 'venue_has': 'Gaswerk'}},
    {'id': 'when_dinner_en', 'kind': 'when', 'lang': 'en', 'q': 'When is the team dinner?',
     'msgs': chat('2026-10-05 09:00|Sarah|Team dinner is on Tuesday',
                  '2026-10-12 08:15|Sarah|Update: team dinner moved to Thursday 22 October, 19:30 at Zeughauskeller'),
     'asked': None, 'expect': {'date': '2026-10-22', 'start': '19:30', 'venue_has': 'Zeughauskeller'}},
    {'id': 'when_none_de', 'kind': 'when', 'lang': 'de', 'q': 'Wann ist das Grillfest?',
     'msgs': chat('2026-10-10 18:00|Tim|Wir sollten mal wieder grillieren', '2026-10-10 18:05|You|Ja, unbedingt'),
     'asked': None, 'expect': {'date': None}},
    # ---------------------------------------------------------------- who
    {'id': 'who_cinema_de', 'kind': 'who', 'lang': 'de', 'q': 'Wer kommt am Samstag mit ins Kino?',
     'msgs': chat('2026-10-13 18:00|You|Samstag Kino, wer ist dabei?', '2026-10-13 18:05|Lara|Ich bin dabei',
                  '2026-10-13 18:09|Tim|Ich auch!', '2026-10-13 18:30|Jonas|Kann leider nicht, bin weg'),
     'asked': 'Saturday', 'expect': {'who': ['Lara', 'Tim'], 'not': ['Jonas']}},
    {'id': 'who_key_ch', 'kind': 'who', 'lang': 'gsw', 'q': 'Wer hät de Schlüssel vom Keller?',
     'msgs': chat('2026-10-12 19:00|You|Wo isch de Chällerschlüssel?',
                  '2026-10-12 19:10|Mia|De Reto hät de Schlüssel no, er bringt en morn'),
     'asked': None, 'expect': {'who': ['Reto'], 'not': ['Mia']}},
    {'id': 'who_party_en', 'kind': 'who', 'lang': 'en', 'q': "Who is organizing PersonE's birthday party?",
     'msgs': chat("2026-10-10 14:00|Ben|Mia is organizing PersonE's party, I'm only bringing the cake",
                  '2026-10-10 14:02|You|Great, thanks'),
     'asked': None, 'expect': {'who': ['Mia'], 'not': ['Ben']}},
    {'id': 'who_none_de', 'kind': 'who', 'lang': 'de', 'q': 'Wer bringt den Kuchen mit?',
     'msgs': chat('2026-10-12 12:00|Lara|Party bei mir am Samstag!', '2026-10-12 12:05|Tim|Super, ich komme'),
     'asked': None, 'expect': {'who': [], 'not': ['Lara', 'Tim']}},
    # ---------------------------------------------------------------- count
    {'id': 'count_cable_de', 'kind': 'count', 'lang': 'de', 'q': 'Wie oft hat Nina nach dem Ladekabel gefragt?',
     'msgs': chat('2026-10-01 10:00|Nina|Hast du mein Ladekabel noch?', '2026-10-01 10:30|You|Ja, bring ich mit',
                  '2026-10-05 09:00|Nina|Denkst du an das Ladekabel?', '2026-10-06 20:00|Nina|Schöner Abend gestern',
                  '2026-10-09 08:00|Nina|Ich brauche das Ladekabel echt bald zurück',
                  '2026-10-09 08:05|You|Sorry, morgen!'),
     'asked': None, 'expect': {'n': 3}},
    {'id': 'count_hike_en', 'kind': 'count', 'lang': 'en', 'q': 'How many messages mention the Säntis hike?',
     'msgs': chat('2026-10-05 08:30|Sarah|Shall we do the Säntis hike next?', '2026-10-06 12:00|You|Lunch today?',
                  '2026-10-12 17:00|Sarah|Säntis hike on Saturday, train at 7:10', '2026-10-12 17:05|You|Perfect'),
     'asked': None, 'expect': {'n': 2}},
    {'id': 'count_none_en', 'kind': 'count', 'lang': 'en', 'q': 'How many times did Ben mention the trip to Rome?',
     'msgs': chat('2026-10-02 09:00|Ben|Morning! Coffee later?', '2026-10-02 09:30|You|Sure, 10:00',
                  '2026-10-08 18:00|Ben|BBQ on Sunday?'),
     'asked': None, 'expect': {'n': 0}},
    # ---------------------------------------------------------------- short
    {'id': 'short_meet_de', 'kind': 'short', 'lang': 'de', 'q': 'Wo treffen wir uns am Samstag?',
     'msgs': chat('2026-10-13 20:00|PersonF|Samstag Treffpunkt Bahnhof Examplecity, Gleis 3, um 9 Uhr',
                  '2026-10-13 20:02|You|Ok'),
     'asked': 'Saturday', 'expect': {'has': 'Bahnhof Examplecity'}},
    {'id': 'short_bring_en', 'kind': 'short', 'lang': 'en', 'q': 'What should I bring to the barbecue?',
     'msgs': chat('2026-10-11 11:00|Ben|BBQ on Sunday! Can you bring the salad and some ice?',
                  '2026-10-11 11:05|You|Sure'),
     'asked': None, 'expect': {'has': 'salad'}},
    {'id': 'short_unclear_ch', 'kind': 'short', 'lang': 'gsw', 'q': 'Weli Film lueged mir?',
     'msgs': chat('2026-10-13 18:40|Tim|Kei Ahnig weli Film, mir mönd no abstimme',
                  '2026-10-13 18:42|You|Mached es Umfrag'),
     'asked': None, 'expect': {'answer': 'unclear'}},
]


# ------------------------------------------------------------------------------------------------ scoring
def verdict(case, ans):
    """-> (pass, short text of what came back)."""
    e, a = case['expect'], ans or {}
    k = case['kind']
    if k == 'yesno':
        got = f"{a.get('answer')} {a.get('date') or ''}".strip() + (f" ({a['reason']})" if a.get('reason') else '')
        ok = a.get('answer') == e['answer'] and ('date' not in e or a.get('date') == e['date'])
    elif k == 'when':
        got = ' '.join(str(a.get(x)) for x in ('date', 'start', 'venue') if a.get(x)) or '-'
        ok = (a.get('date') == e['date'] and ('start' not in e or a.get('start') == e['start'])
              and ('venue_has' not in e or e['venue_has'].lower() in str(a.get('venue') or '').lower()))
    elif k == 'who':
        names = list(a.get('who') or []) + list(a.get('nicknames') or [])
        got = ', '.join(names) or '-'
        low = {x.lower() for x in names}
        ok = all(x.lower() in low for x in e['who']) and not any(x.lower() in low for x in e.get('not', ()))
    elif k == 'count':
        got = str(a.get('n'))
        ok = a.get('n') == e['n']
    else:
        got = str(a.get('answer'))
        ok = (str(a.get('answer')).lower() == e['answer'] if 'answer' in e
              else e['has'].lower() in str(a.get('answer') or '').lower())
    return ok, got


def expected_text(case):
    e = case['expect']
    return ' '.join(f'{k}={v}' for k, v in e.items())


# ------------------------------------------------------------------------------------------------ the pipeline
class _Gate:
    def lease(self, **kw):
        return contextlib.nullcontext()


class _Audit:
    def log(self, *a, **k):
        pass


class _Cfg:
    def __init__(self, state):
        self.state = state


class _Policy:
    def __init__(self, runner):
        self.runner = runner

    def run_llm(self, args, text, timeout=900, **kw):
        return self.runner(list(args), text)

    @staticmethod
    def regex_net(s):
        return s

    @staticmethod
    def money_net(s):
        return s


def call_key(args, text):
    return hashlib.sha256(json.dumps([args, text], ensure_ascii=False).encode('utf-8')).hexdigest()[:24]


def llm_bin():
    for p in (os.environ.get('EVAL_LLM_LOCAL'), '/opt/vault/vendor/llm-local', os.path.expanduser('~/bin/llm-local')):
        if p and os.path.exists(p):
            return p
    sys.exit('no llm-local found (set EVAL_LLM_LOCAL)')


def run_case(case, runner, state):
    a = AN.Answer(_Cfg(Path(state)), _Policy(runner), _Gate(), _Audit(), clock=lambda: NOW)
    kind = a.pick_kind({'question': case['q'], 'kind': case['kind']}, 'tg')
    r = a.result({'source': 'telegram', 'query': 'eval'}, 'tg', kind, case['q'], '30d', case['msgs'], False, None)
    return r


class Stale(Exception):
    pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--real', action='store_true', help='run the real local model')
    ap.add_argument('--replay', metavar='FILE', help='score recorded model outputs again')
    ap.add_argument('--save', metavar='FILE', help='--real: record the model outputs (JSON) for --replay')
    ap.add_argument('--only', help='case ids or kinds, comma-separated')
    ap.add_argument('--min', type=float, help='exit 1 if the total score is below this (0..1)')
    ap.add_argument('-v', action='store_true', help='print the checked answer of every case')
    o = ap.parse_args()
    sel = set((o.only or '').split(',')) - {''}
    cases = [c for c in CASES if not sel or c['id'] in sel or c['kind'] in sel]
    ids = [c['id'] for c in CASES]
    assert len(ids) == len(set(ids)), 'duplicate case ids'
    for c in CASES:                                     # the fixtures: asked windows as noted, kinds as routed
        w = AN.ask_window(c['q'], TODAY)
        assert (w['label'] if w else None) == c['asked'], (c['id'], w)
        assert AN.Answer.pick_kind({'question': c['q'], 'kind': c['kind']}, 'tg') == c['kind'], c['id']
    if not (o.real or o.replay):
        print(f'{len(CASES)} cases consistent ({", ".join(sorted({c["kind"] for c in CASES}))}); '
              'run with --real or --replay FILE to score')
        return 0
    rec = {}
    if o.replay:
        rec = json.loads(Path(o.replay).read_text('utf-8'))
    saved, binp = {}, (llm_bin() if o.real else None)

    def runner(args, text):
        k = call_key(args, text)
        if o.replay:
            if k not in rec:
                raise Stale(k)
            return rec[k]
        p = subprocess.run([binp] + args, input=text, capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            raise RuntimeError(f'llm-local exit {p.returncode}: {(p.stderr or "").strip().splitlines()[-1:]}')
        saved[k] = p.stdout.strip()
        return p.stdout.strip()

    score, t_all = {}, time.time()
    for c in cases:
        t0 = time.time()
        with tempfile.TemporaryDirectory() as st:
            try:
                r = run_case(c, runner, st)
                ok, got = verdict(c, r.get('answer'))
                mark = 'PASS' if ok else 'FAIL'
            except Stale:
                ok, got, mark, r = None, 'no recording for this prompt', 'STALE', {}
            except Exception as e:                  # noqa: BLE001 - one broken case must not end the eval
                ok, got, mark, r = False, f'error: {type(e).__name__}: {e}', 'ERR ', {}
        if ok is not None:
            s = score.setdefault(c['kind'], [0, 0])
            s[0] += int(ok)
            s[1] += 1
        print(f'{mark} {c["id"]:<24} {c["lang"]:<3} expect {expected_text(c):<44} got {got}  '
              f'({time.time() - t0:.0f} s)', flush=True)
        if o.v and r:
            print('     ' + json.dumps(r.get('answer'), ensure_ascii=False))
    if o.save and saved:
        old = json.loads(Path(o.save).read_text('utf-8')) if Path(o.save).exists() else {}
        old.update(saved)
        Path(o.save).write_text(json.dumps(old, ensure_ascii=False, indent=0), 'utf-8')
    tot = [sum(v[0] for v in score.values()), sum(v[1] for v in score.values())]
    print('score: ' + ' · '.join(f'{k} {v[0]}/{v[1]}' for k, v in score.items())
          + f' · total {tot[0]}/{tot[1]}' + (f' = {tot[0] / tot[1]:.2f}' if tot[1] else '')
          + f' ({AN.ANSWER_VERSION}, {time.time() - t_all:.0f} s)')
    if o.min is not None and tot[1] and tot[0] / tot[1] < o.min:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
