"""Answers, not text (privacy plan A, 2026-10-14): the vault answers questions about the owner's chats and mail with
short, checked values instead of handing out their text.

Input: anonymized text (policy v3, NOT paraphrased) that never leaves the vault: TG.anon_messages (one chat), tgread's
search hits (anonymized here in one call), Gmail.anon_doc (every amount masked). One local-LLM call per part of up to
5,000 chars, grammar-constrained per kind (llm-local --schema), cached in /data/state/answer-cache (0600, 30 days;
`tg purge|exclude|wipe` clear it).

Kinds (values are enums, booleans, ISO dates, ints or first names; * = checked against the source text):
  yesno       {answer: yes|no|unclear, date?, refs}
  when        {date, start, end, venue*, address*, who[], status, refs}   (a time always with its date: date_from
              message|earlier when code filled it, else date_unknown)
  deadline    {has_deadline, date, date_text*, action, refs}  (a mail labelled bill: no date)
  actionable  {actionable, action, due, refs}
  requests    [{who: first name|org*|group, wants, due, refs}]
  count       {n, first, last, refs}
  who         {who: first names[], nicknames: single words[] (flagged), refs}   (who/wer questions; never short)
  short       {answer*: at most 12 words, refs}
  interests   at most 5 x {phrase*: at most 4 words, topic}   (gift radar)
  mail_card   {ref, date, from, category, actionable, action, deadline, appointment, reply_needed, attachments}
  digest      {window, needs_you[], plans[], signals[], topics{}}  (tg summarize/recent/unread default)
Checks in code: fixed fields; a [placeholder] never appears inside a value (it becomes topic `private`); first names
only (the first word of a name written in the text; an honorific + surname such as "Herr Huber" is "someone",
venues drop it, short text says "someone"); dates via facts.resolve_date; then the regex net (mail: + the
money net). An LLM failure is an error, never a partial answer.
Time: the prompt carries TODAY and the question's relative
time words resolved in code against today (ask_window: this/next/last weekend, week, month, heute/morgen/gestern,
weekdays, dates); message-relative dates stay with facts.resolve_date. Each dated answer is measured in code
(timed): timing past, relative (last weekend ...), in_window false when it lies outside the asked days (a yes then
becomes no); the result shows `asked`. Yes/no verdicts (eval 15.10, tests/eval_answers.py): nothing on the asked days
is a no, not unclear (prompt); an unclear whose messages each name a day, none of them asked (settle), is a no too,
with reason "only past dates" / "only other dates"; a maybe ON the asked days stays unclear and wins over a no. Who: who/wer
questions run as kind who (also over an explicit short): single words checked against the text, first names
(written capitalized there) or flagged nicknames; articles, pronouns and phrases are dropped."""
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

import facts as FX
import index as IX
import sessions as SS
import vaultlib as V
from vaultlib import VaultError

ANSWER_VERSION = 'answer-10'                       # 10: a when's date always; 9: short weekdays, gestern; 8: day tense; 7: yes/no; 4-6: dates
CACHE_DAYS = 30
CHUNK_CHARS = 5000
MAX_CHATS = 25                                          # digest: the busiest chats of the window
MAX_MSGS_CHAT = 300
MAX_LIST = 30
KINDS = ('yesno', 'when', 'who', 'deadline', 'actionable', 'requests', 'count', 'short', 'interests', 'mail_card',
         'digest')
QUESTION_KINDS = ('yesno', 'when', 'who', 'count', 'short', 'interests')
TIMED_KINDS = ('yesno', 'when', 'who', 'deadline', 'actionable', 'requests', 'count', 'short')   # get today's date
DATE_FIELD = {'yesno': 'date', 'when': 'date', 'deadline': 'date', 'actionable': 'due'}
ACTIONS = ('reply', 'pay', 'sign', 'book', 'attend', 'send', 'decide', 'pick_up', 'call', 'none')
WANTS = ('reply', 'decision', 'meeting', 'document', 'payment', 'pickup', 'call', 'favour', 'info')
URGENCY = ('now', 'today', 'week', 'none')
TOPICS = ('travel', 'party', 'sport', 'food', 'work', 'tech', 'games', 'media', 'shopping', 'home', 'admin',
          'family_event', 'birthday', 'logistics', 'other', 'private')
SIGNALS = ('plan', 'event', 'problem', 'wish', 'purchase', 'request')
FREEMAIL = re.compile(r'(?:^|\.)(?:gmail|googlemail|gmx|bluewin|outlook|hotmail|live|msn|icloud|me|mac|yahoo|ymail|'
                      r'proton|protonmail|pm|web|hispeed|sunrise|aol)\.[a-z.]{2,6}$', re.I)
ISO = re.compile(r'\d{4}-\d{2}-\d{2}')
NAME = re.compile(r"[^\W\d_][^\W\d_'-]*(?:[-'][^\W\d_]+)?")
# not a person (articles, pronouns, group words)
NOT_NAMES = frozenset(FX.GLUE | set(
    'ich du er sie es wir ihr mich dich dir uns euch ihm ihn ihnen man jemand niemand alle allen beide beiden leute '
    'freunde jungs mädels kollegen familie team gruppe wer wen wem kommt kommen mitkommen '
    'i me my he him she her it we they them someone somebody anyone anybody nobody everyone everybody people friends '
    'guys group who all both ja ne nein svi niko neko nitko netko ekipa raja mi vi oni ona on '
    'yes no unclear unknown none'.split()))
NICK_PREV = frozenset('de dr d der die den dem s the la le el il und and u i mit with sa , & + /'.split())
MAX_NICKS = 4
WHO_SEP = re.compile(r'\s*(?:[,;&+/]|(?<![^\W_])(?:und|and|u|i|sowie|plus|with|mit|sa)(?![^\W_]))\s*', re.I)
SINCE_RE = re.compile(r'\d{1,4}[mhdw]|\d{4}-\d{2}-\d{2}|@\d{9,11}')
NOTE = ('answer read by the local LLM from the anonymized text only (never paraphrased text); names are first names, '
        'values checked against the text, dates resolved in code; no message text leaves the vault')


# ------------------------------------------------------------------------------------------------ schemas
def _o(props, req=()):
    return {'type': 'object', 'properties': props, 'required': list(req), 'additionalProperties': False}


def _arr(item, n):
    return {'type': 'array', 'items': item, 'maxItems': n}


S = {'type': 'string', 'maxLength': 120}
B = {'type': 'boolean'}


def _e(vals):
    return {'type': 'string', 'enum': list(vals)}


REFS = _arr({'type': 'integer', 'minimum': 1, 'maximum': 999}, 5)
NAMES = _arr({'type': 'string', 'maxLength': 60}, 8)
SCHEMAS = {
    'yesno': _o({'answer': _e(('yes', 'no', 'unclear')), 'date': S, 'refs': REFS}, ('answer',)),
    'when': _o({'date': S, 'start': S, 'end': S, 'venue': S, 'address': S, 'who': NAMES, 'status': _e(FX.STATUS),
                'refs': REFS}),
    'deadline': _o({'has_deadline': B, 'date': S, 'action': _e(ACTIONS), 'refs': REFS}, ('has_deadline',)),
    'actionable': _o({'actionable': B, 'action': _e(ACTIONS), 'due': S, 'refs': REFS}, ('actionable',)),
    'requests': _o({'requests': _arr(_o({'who': S, 'wants': _e(WANTS), 'due': S, 'refs': REFS}, ('who', 'wants')),
                                     10)}, ('requests',)),
    'count': _o({'matches': _arr({'type': 'integer', 'minimum': 1, 'maximum': 999}, 200)}, ('matches',)),
    'short': _o({'answer': S, 'refs': REFS}, ('answer',)),
    'who': _o({'who': NAMES, 'refs': REFS}, ('who',)),
    'interests': _o({'interests': _arr(_o({'phrase': S, 'topic': _e(TOPICS), 'refs': REFS}, ('phrase', 'topic')), 5)},
                    ('interests',)),
    'mail_card': _o({'category': _e(V.GMAIL_LABELS), 'actionable': B, 'action': _e(ACTIONS), 'deadline': S,
                     'appointment': _o({'date': S, 'start': S, 'venue': S}), 'reply_needed': B},
                    ('category', 'actionable', 'action', 'reply_needed')),
    'digest': _o({'needs_you': _arr(_o({'from': S, 'wants': _e(WANTS), 'due': S, 'refs': REFS}, ('from', 'wants')), 10),
                  'plans': _arr(_o({'date': S, 'start': S, 'what': S, 'venue': S, 'with': NAMES, 'refs': REFS},
                                   ('date', 'what')), 10),
                  'signals': _arr(_o({'type': _e(SIGNALS), 'topic': _e(TOPICS), 'who': S, 'when': S},
                                     ('type', 'topic')), 10),
                  'topics': _arr(_e(TOPICS), 6)}, ('needs_you', 'plans', 'signals', 'topics')),
}
HEAD = ('You answer for the owner\'s personal assistant from part of his chats or mail. The text is anonymized: "You" '
        'is the owner; [private: ...] and other [brackets] mark removed details. Messages: "[mN] YYYY-MM-DD HH:MM '
        'Sender: text". Use ONLY this text. Copy names, places, dates and words exactly as written there; never '
        'translate, explain or invent. Leave a field out when the text does not say it. Never put a [bracket] '
        'placeholder or anything private (health, money amounts, relationships, intimate details) into a value. '
        'refs: the numbers N of the messages [mN] the answer rests on. Output JSON only.\n')
TASK = {
    'yesno': 'Question: {q}\nanswer: yes when the text shows it; no when the text shows the opposite, or when the '
             'question is about given days and nothing in the text is on those days (plans on earlier or later days, '
             'such as a past weekend, mean no); unclear only when the text is about it but leaves it open (maybe, '
             'not decided, no reply yet). date: the day the thing found happens on, as written in its message.',
    'who': 'Question: {q}\nwho: only the people who are the answer (a sender only when the answer is about the '
           'sender, as in "I\'m in"; not someone who just tells about others or asks), each ONE first name or '
           'nickname copied from the text, '
           'without articles or other words (not "de Anna" or "Anna und Beat": "Anna", "Beat"); "You" for the owner; '
           'empty if the text does not say.',
    'when': 'Question: {q}\nWhen and where does it happen? date: the day it happens on, always (also when the question '
            'asks only for the time), as written; start and end time as written; venue and address as '
            'written; who: the first names of the people taking part; status: planned, proposed, confirmed, '
            'cancelled or done.',
    'deadline': 'Question: {q}\nIs there a deadline or due date the owner must meet? has_deadline; date: as written; '
                'action: what he must do.',
    'actionable': 'Question: {q}\nDoes the owner have to do something? actionable; action; due: the date as written.',
    'requests': 'Question: {q}\nWhat do people ask of the owner? One entry per open request: who (the first name, '
                'the organisation, or "group"), wants, due (the date as written).',
    'count': 'Question: {q}\nmatches: the numbers N of every message [mN] that matches the question (empty if none).',
    'short': 'Question: {q}\nanswer: at most 12 words, using words from the text ("unclear" if it does not say).',
    'interests': 'Person: {q}\nWhat does this person like, want, collect or enjoy (for gift ideas)? At most 5 phrases '
                 'of at most 4 words each, copied from the text, each with a topic. Nothing private.',
    'mail_card': 'This is ONE e-mail to the owner (amounts are [amount]). category: bill (he has to pay it), deadline '
                 '(a due date other than paying), appointment (meeting, booking, ticket, event with a date), '
                 'reply_needed (a person waits for his answer), delivery, account_security, newsletter, other. '
                 'actionable: he has to pay, do, decide, reply or pick up something; action: what. deadline: the due '
                 'date as written (not for a bill). appointment: date and start as written, venue as written. '
                 'reply_needed: a person waits for his answer.',
    'digest': 'Flags for the owner\'s assistant from this part of one chat. needs_you: each open question or request '
              'to the owner (from: the first name; wants; due: the date as written). plans: each dated plan, meeting '
              'or event (date and start as written; what: at most 6 words from the text; venue as written; with: '
              'first names). signals: notable things (type; topic; who: a first name; when: as written). topics: '
              'what this part is about. Private matters (health, money, relationships, intimate things): topic '
              'private, no details.',
}
TIME_RULE = ('Dates: every message has its own date; a relative date in a message ("morgen", "am Wochenende", '
             '"Samstag") counts from THAT message\'s date, not from today. When the question names a day or period, '
             'only things on that day or in that period answer it; a plan on another day does not (yesno: no, with '
             'date = the day it was on). Write a date exactly as the message writes it ("am Wochenende", "Samstag", '
             '"17.10."), never as YYYY-MM-DD and never today\'s date unless the message itself says heute/today.\n')
DEFAULT_Q = {'deadline': 'Is there a deadline for the owner?', 'actionable': 'Does the owner have to do something?',
             'requests': 'What do people ask of the owner?', 'interests': 'the other person in this chat'}


def schema_arg(kind):
    return json.dumps(SCHEMAS[kind], separators=(',', ':'))


def display_from(name, domain):
    """Mail sender for the assistant: companies "Name (domain)"; freemail (gmail, gmx, bluewin, ...): first name."""
    name, domain = (name or '').strip(), (domain or '').strip().lower()
    if domain and FREEMAIL.search(domain):
        m = NAME.search(name)
        return m.group(0) if m else 'someone'
    name = FX.unhonor(name)                            # "Herr Peter Huber" at a company -> "someone (domain)"
    return f'{name} ({domain})' if name and domain else (name or domain or '?')


def first_name(label):
    if FX.has_honor(label):
        return 'someone'
    m = NAME.search(str(label or ''))
    return m.group(0) if m else '?'


def chat_display(chat_id, ctype, label, aliases):
    """A chat for the assistant: its alias (vault tg alias), a person's first name, else "group"."""
    a = (aliases or {}).get(str(chat_id))
    if a:
        return a
    if ctype in ('user', 'private', 'bot'):
        return first_name(label)
    if ctype == 'self':
        return 'Saved Messages'
    return 'channel' if ctype == 'channel' else 'group'


def pin_since(msgs, since):
    """A session's chat window pinned to its oldest message (a minute before), so follow-ups find the same messages
    while new ones arrive (plan C1)."""
    ts = min((m.get('ts') or '' for m in msgs), default='')
    try:
        t = dt.datetime.strptime(ts, '%Y-%m-%d %H:%M').replace(tzinfo=V.TZ)
    except ValueError:
        return since
    return f'@{int(t.timestamp()) - 60}'


def since_ts(since, now):
    s = str(since).strip()
    if s.startswith('@'):
        return int(s[1:])
    if ISO.fullmatch(s):
        return int(dt.datetime.fromisoformat(s).replace(tzinfo=V.TZ).timestamp())
    mult = {'m': 60, 'h': 3600, 'd': 86400, 'w': 7 * 86400}[s[-1]]
    return int(now - int(s[:-1]) * mult)


# ------------------------------------------------------------------------------------------------ time words
# A QUESTION's relative time words count from today (a live case: "this weekend" was answered with last weekend's
# plan); a MESSAGE's count from that message (facts.resolve_date). Full weekday names only: "do", "so", "mi" are
# words in a question.
Q_WD = {n: i for n, i in FX.WD.items() if len(n) >= 5}
Q_WD.update({'ponedjeljak': 0, 'ponedeljak': 0, 'utorak': 1, 'srijeda': 2, 'srijedu': 2, 'sreda': 2, 'sredu': 2,
             'četvrtak': 3, 'cetvrtak': 3, 'petak': 4, 'subota': 5, 'subotu': 5, 'nedjelja': 6, 'nedjelju': 6,
             'nedelja': 6, 'nedelju': 6})
Q_DAY = {'today': 0, 'heute': 0, 'heut': 0, 'hüt': 0, 'hüüt': 0, 'tonight': 0, 'danas': 0, 'večeras': 0,
         'veceras': 0, 'tomorrow': 1, 'morgen': 1, 'morn': 1, 'moorn': 1, 'sutra': 1, 'yesterday': -1, 'gestern': -1,
         'geschter': -1, 'jučer': -1, 'jucer': -1, 'juče': -1, 'juce': -1, 'übermorgen': 2, 'übermorn': 2,
         'prekosutra': 2, 'vorgestern': -2, 'vorgeschter': -2, 'prekjučer': -2, 'prekjuče': -2}
Q_UNIT = {**{w: 'weekend' for w in FX.WEEKEND + ('vikend', 'vikenda', 'vikendu', 'weekends')},
          **{w: 'week' for w in ('week', 'woche', 'wuche', 'tjedan', 'tjedna', 'tjednu', 'sedmica', 'sedmice',
                                 'sedmicu', 'sedmici')},
          **{w: 'month' for w in ('month', 'monat', 'monet', 'mjesec', 'mjeseca', 'mjesecu', 'mesec', 'meseca')}}
Q_LAST = set(FX.LAST) | {'prošli', 'prošlog', 'prošle', 'prošlu', 'prosli', 'proslog', 'prosle', 'proslu'}
Q_NEXT = (set(FX.NEXT) - {'kommenden', 'kommende', 'kommendes'}) | {
    'sljedeći', 'sljedećeg', 'sljedeće', 'sljedecu', 'sljedeci', 'slijedeći', 'idući', 'idućeg', 'iduće', 'iduci',
    'iduceg', 'naredni', 'narednog', 'naredne'}
Q_DATE = re.compile(r'\d{4}-\d{1,2}-\d{1,2}|(?<![\d.:])\d{1,2}\.\d{1,2}\.?(?:\d{4}|\d{2})?(?![\d:])'
                    r'|(?<![\w])\d{1,2}\.?\s*' + FX._MON + r'|(?<![\w])' + FX._MON + r'\s+\d{1,2}(?![\d])', re.I)
WD_EN = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')


def _month_end(d):
    return (d.replace(day=28) + dt.timedelta(days=4)).replace(day=1) - dt.timedelta(days=1)


def ask_window(q, today):
    """The first day or period a question names, resolved against TODAY -> {'label', 'from', 'to'} (dates) or None.
    this/next/last weekend (Sat-Sun; "this" = the coming one, the current one on Sat/Sun; next = +7), week (Mon-Sun),
    month; heute/morgen/gestern/übermorgen, today/tomorrow/yesterday, danas/sutra/jučer; full weekday names (the next
    one on or after today; last = the one before today); written dates."""
    t = ' '.join(str(q or '').casefold().split())
    best = None
    m = Q_DATE.search(t)
    if m:
        d = FX.resolve_date(m.group(0), today)
        if d:
            best = (m.start(), {'label': d.isoformat(), 'from': d, 'to': d})
    toks = list(re.finditer(r'[^\W\d_]+', t))
    for j, tm in enumerate(toks):
        if best and tm.start() >= best[0]:
            break
        w = tm.group(0)
        prev = {x.group(0) for x in toks[max(0, j - 2):j]}
        mod = 'last' if prev & Q_LAST else 'next' if prev & Q_NEXT else 'this'
        win = None
        if w in Q_UNIT:
            unit, shift = Q_UNIT[w], {'last': -1, 'next': 1, 'this': 0}[mod]
            if unit == 'weekend':
                sat = FX.weekend_sat(today) + dt.timedelta(days=7 * shift)
                win = (sat, sat + dt.timedelta(days=1))
            elif unit == 'week':
                mon = today - dt.timedelta(days=today.weekday()) + dt.timedelta(days=7 * shift)
                win = (mon, mon + dt.timedelta(days=6))
            else:
                first = today.replace(day=1)
                if shift < 0:
                    first = (first - dt.timedelta(days=1)).replace(day=1)
                elif shift > 0:
                    first = _month_end(first) + dt.timedelta(days=1)
                win = (first, _month_end(first))
            label = f'{mod} {unit}'
        elif w in Q_DAY and not (w == 'morgen' and j and toks[j - 1].group(0) in ('am', 'guten', 'jeden', 'every')):
            d = today + dt.timedelta(days=Q_DAY[w])
            win, label = (d, d), {0: 'today', 1: 'tomorrow', -1: 'yesterday', 2: 'the day after tomorrow',
                                  -2: 'the day before yesterday'}[Q_DAY[w]]
        else:
            wd = FX.DAYPART.sub('', w) if FX.DAYPART.sub('', w) in Q_WD else w
            if wd in Q_WD:
                if mod == 'last':
                    d = today - dt.timedelta(days=(today.weekday() - Q_WD[wd]) % 7 or 7)
                else:
                    d = today + dt.timedelta(days=(Q_WD[wd] - today.weekday()) % 7)
                win, label = (d, d), (('last ' if mod == 'last' else '') + WD_EN[Q_WD[wd]])
        if win:
            best = (tm.start(), {'label': label, 'from': win[0], 'to': win[1]})
            break
    return best[1] if best else None


def rel_label(d, today):
    """A date in plain words relative to today (code): today, tomorrow, yesterday, this/last/next weekend or week."""
    n = (d - today).days
    if n in (0, 1, -1):
        return ('today', 'tomorrow', 'yesterday')[n]
    sat = FX.weekend_sat(today)
    for k, name in ((0, 'this weekend'), (-7, 'last weekend'), (7, 'next weekend')):
        if 0 <= (d - (sat + dt.timedelta(days=k))).days <= 1:
            return name
    week = (d - (today - dt.timedelta(days=today.weekday()))).days // 7
    return {0: 'this week', -1: 'last week', 1: 'next week'}.get(week)


def time_line(today, window):
    """The prompt's first line: today, and what the question's time words mean (both computed in code)."""
    s = f'Today is {WD_EN[today.weekday()]} {today.isoformat()}.'
    if window:
        a, b = window['from'], window['to']
        span = (f'{WD_EN[a.weekday()]} {a.isoformat()}' if a == b else
                f'{WD_EN[a.weekday()]} {a.isoformat()} to {WD_EN[b.weekday()]} {b.isoformat()}')
        s += f' The question asks about {window["label"]}: {span}.'
    return s


def timed(kind, ans, window, today):
    """A checked answer's date measured in code: timing past when it is before today, relative (last
    weekend, tomorrow ...), in_window false when the question named days and the date lies outside them; a yes is
    then a no (the plan found is on another day) and is not presented as the answer for the asked days."""
    key = DATE_FIELD.get(kind)
    if not key or not isinstance(ans, dict) or not ans.get(key):
        return ans
    try:
        d = dt.date.fromisoformat(str(ans[key]))
    except ValueError:
        return ans
    out = dict(ans)
    if d < today:
        out['timing'] = 'past'
    rel = rel_label(d, today)
    if rel:
        out['relative'] = rel
    if window:
        out['in_window'] = window['from'] <= d <= window['to']
        if not out['in_window'] and kind == 'yesno' and out.get('answer') == 'yes':
            out['answer'] = 'no'
        if not out['in_window'] and kind == 'yesno' and out.get('answer') == 'no':
            out['reason'] = OTHER_DAYS[d < today]
    return out


OTHER_DAYS = {True: 'only past dates', False: 'only other dates'}


def undated(kind, ans):
    """A when answer with a time but no date (live 15.10 09:40: the follow-up "wann genau?" came back as a time
    alone while the plan was on the asked days)."""
    return (kind == 'when' and isinstance(ans, dict) and not ans.get('date')
            and bool(ans.get('start') or ans.get('end')))


def dated(kind, ans, part, window):
    """Answers about times carry their date: an undated when gets it in code from the messages it
    rests on (the cited ones, else the part) when they name exactly one day, or exactly one of the asked days
    (date_from: message). Nothing is guessed: else it stays undated (Answer.result then uses an earlier session
    turn's checked date, or flags date_unknown)."""
    if not undated(kind, ans) or not part:
        return ans
    refs = set(ans.get('refs') or [])
    days = set()
    for m in [m for m in part if m.get('ref') and m['ref'] in refs] or part:
        days |= named_days(m['text'], FX.msg_date(m['ts']))
    if window and len(days) > 1:
        inside = {d for d in days if window['from'] <= d <= window['to']}
        days = inside if len(inside) == 1 else days
    return dict(ans, date=days.pop().isoformat(), date_from='message') if len(days) == 1 else ans
CLAUSE = re.compile(r'[,;!?\n]+|(?<!\d)\.|\s(?:und|and|aber|but|oder|or|dann|then|u)\s', re.I)


def named_days(text, ref):
    """Every day a message names, each clause resolved on its own ("letztes Wochenende war toll, dieses Wochenende
    wandern" names both weekends) -> set of dt.date. A clause is checked in its message: "Sa oder So?" names both
    days, "Ja, so" none."""
    out = {FX.resolve_date(text, ref)}
    out |= {FX.resolve_date(p, ref, context=text) for p in CLAUSE.split(str(text or '')) if p and p.strip()}
    return {d for d in out if d}


def settle(kind, ans, part, window, today):
    """A yesno about given days (a live case: "Are there plans for this weekend?" over search hits holding only a past
    plan came back unclear): unclear -> no (reason: only past / other dates) when the messages it rests on (the cited
    ones; else, for a past date, those behind it; else the whole part) each name a day and none of those days, nor any message's own day, is an asked day.
    The model's date on an asked day, or a message naming no day, keeps it unclear (real ambiguity)."""
    if kind != 'yesno' or not window or not isinstance(ans, dict) or ans.get('answer') != 'unclear' \
            or ans.get('in_window') is True or not part:
        return ans
    lo, hi = window['from'], window['to']
    refs = set(ans.get('refs') or [])
    basis, past = [m for m in part if m.get('ref') and m['ref'] in refs], None
    if not basis and ans.get('timing') == 'past':       # no refs, a past date: the messages behind that date; there
        past = dt.date.fromisoformat(ans['date'])       # a message naming no day is on its own (past) day (live 15.10)
        basis = [m for m in part if FX.msg_date(m['ts']) == past
                 or past in named_days(m['text'], FX.msg_date(m['ts']))]
    days = []
    for m in basis or part:
        own = FX.msg_date(m['ts'])
        named = named_days(m['text'], own) or ({own} if past and own == past else set())
        if own is None or not named or lo <= own <= hi or any(lo <= d <= hi for d in named):
            return ans
        days += named
    return dict(ans, answer='no', in_window=False, reason=OTHER_DAYS[max(days) < today])


# ------------------------------------------------------------------------------------------------ checks
class ACheck(FX.Check):
    """facts.Check + enums, booleans, first names and resolved dates for the answer kinds."""

    def __init__(self, part, net):
        super().__init__(part, net)
        self.wl, self.cap, self.nick_ok = set(), {}, set()
        for m in part:
            self.wl |= {w.lower() for w in NAME.findall(f"{m['sender']} {m['text']}")}
            for w in NAME.findall(f"{m['sender']} {m['text']}"):       # written capitalized there: a name
                if w[:1].isupper():
                    self.cap.setdefault(w.lower(), w)
            toks = re.findall(r"[^\W\d_][^\W\d_'-]*|[,&+/]", m['text'])
            for i, w in enumerate(toks):                # lower case used like a name: "de geko", "mäge und geko"
                if w[:1].islower() and (i == 0 or toks[i - 1].lower() in NICK_PREV):
                    self.nick_ok.add(w.lower())

    def enum(self, field, v, vals, default=None):
        if isinstance(v, str) and v.strip().lower() in vals:
            return v.strip().lower()
        if v not in (None, ''):
            self.drop(field)
        return default

    def boolean(self, field, v):
        if isinstance(v, bool):
            return v
        if v is not None:
            self.drop(field)
        return None

    def first(self, field, v, allow=()):
        """A first name: the first word of a name written in the text (or one of `allow`)."""
        if not isinstance(v, str) or not v.strip():
            return None
        s = v.strip()
        if s.lower() in allow:
            return s.lower()
        if FX.PLACEHOLDER.search(s):
            self.drop(field)
            return None
        m = NAME.match(s)
        if not m or not m.group(0)[:1].isupper() or m.group(0).lower() not in self.wl or len(m.group(0)) > 30 \
                or m.group(0).lower() in NOT_NAMES:          # "De", "Ich", "Alle": not a first name
            self.drop(field)
            return None
        if FX.has_honor(s):                              # "Herr Huber", "Dr. Frei": a surname, not a first name
            self.drop('honorific')
            return 'someone'
        return m.group(0)

    def names(self, field, v):
        """Digest 'with': first names and nicknames in one list (each a single checked word)."""
        n, k = self.people(field, v)
        return (n + [x for x in k if x not in n])[:FX.MAX_WHO]

    def people(self, field, v):
        """who lists: each value split at und/and/,/&, leading articles and pronouns dropped, then ONE
        word that is written in the text. -> (first names: written capitalized there, flagged nicknames: only written
        in lower case there, after an article, und/and or a comma, or first in a message; at most 4). A phrase (more
        than two words), a [placeholder], a word not in the text or not used like a name there is dropped;
        an honorific + surname is "someone". Never free text."""
        names, nicks = [], []

        def add(lst, x):
            if x not in names and x not in nicks:
                lst.append(x)
        for x in (v if isinstance(v, list) else [v] if v else [])[:FX.MAX_WHO]:
            if not isinstance(x, str) or not x.strip():
                continue
            s = x.strip()
            if FX.PLACEHOLDER.search(s):
                self.drop(field)
                continue
            if FX.has_honor(s):
                self.drop('honorific')
                add(names, 'someone')
                continue
            pieces = [p for p in WHO_SEP.split(s) if p and p.strip()]
            if len(pieces) > 4:
                self.drop(field)
                continue
            for p in pieces:
                toks = NAME.findall(p)
                while len(toks) > 1 and toks[0].lower() in NOT_NAMES:
                    toks.pop(0)
                if len(toks) == 1 and toks[0].lower() == 'you':
                    add(names, 'You')
                    continue
                w = toks[0] if toks and len(toks) <= 2 else None
                if not w or w.lower() in NOT_NAMES or len(w) > 30 or w.lower() not in self.wl:
                    self.drop(field)                     # a phrase, an article or pronoun, or not in the text
                    continue
                if w.lower() in self.cap:
                    add(names, self.cap[w.lower()])
                elif w.lower() in self.nick_ok and len(nicks) < MAX_NICKS:
                    add(nicks, w[:1].upper() + w[1:])
                else:
                    self.drop(field)                     # a lower-case word not used like a name there
        return names[:FX.MAX_WHO], nicks

    def who(self, field, v):
        """requests: a first name, "group", or an organisation written in the text (<= 4 words); an honorific +
        surname ("Herr Huber") -> "someone"."""
        if isinstance(v, str) and len(FX.words(v)) > 1:
            c = self.exact(field, v)
            if c and FX.has_honor(c):
                self.drop('honorific')
                return 'someone'
            return c if c and len(FX.words(c)) <= 4 else None
        return self.first(field, v, allow=('group', 'you'))

    def idx(self, cited, anchors=()):
        return self.refs(cited if cited is not None else [], [a for a in anchors if isinstance(a, str)])

    def date(self, field, v, idx):
        """-> (ISO date or None, the text as written or None)."""
        if not isinstance(v, str) or not v.strip():
            return None, None
        s = v.strip()
        if ISO.fullmatch(s):
            try:
                d = dt.date.fromisoformat(s)
            except ValueError:
                self.drop(field)
                return None, None
            ref = FX.msg_date(self.part[-1]['ts'])
            if ref is None or abs((d - ref).days) > 3 * 366:
                self.drop(field)
                return None, None
            msgs = [self.part[i] for i in (idx or range(len(self.part)))]
            own = ({FX.msg_date(m['ts']) for m in msgs}
                   | {FX.resolve_date(m['text'], FX.msg_date(m['ts'])) for m in msgs})
            if d not in own and not any(s in m['text'] for m in self.part):
                self.drop(field)                         # not written, not a cited message's day nor what its own
                return None, None                        # "am Wochenende" means: e.g. the prompt's today (15.10)
            return d.isoformat(), None
        c = self.exact(field, s)
        if not c:
            return None, None
        d = self.resolve(idx, c)
        return (d.isoformat() if d else None), c

    def time(self, field, v):
        c = self.exact(field, v)
        return FX.norm_time(c) if c else None

    def short(self, field, v, words):
        if isinstance(v, str) and v.strip().lower() == 'unclear':
            return 'unclear'
        c = self.subset(field, v)
        if c and (len(FX.words(c)) > words or FX.PLACEHOLDER.search(c)):
            self.drop(field)
            return None
        if c and FX.HONOR.search(c):
            self.drop('honorific')
            c = FX.unhonor(c)
        return c

    def ref_ids(self, idx):
        return [self.part[i]['ref'] for i in idx if self.part[i].get('ref')][:FX.MAX_REFS]

    # -------------------------------------------------------------- per kind
    def run_kind(self, kind, llm, mail=False):
        if not isinstance(llm, dict):
            raise VaultError('the local LLM gave no JSON object for the answer', 502, 'answer_failed')
        return getattr(self, f'k_{kind}')(llm, mail)

    def k_yesno(self, d, mail):
        idx = self.idx(d.get('refs'))
        date, _ = self.date('date', d.get('date'), idx)
        return {'answer': self.enum('answer', d.get('answer'), ('yes', 'no', 'unclear'), 'unclear'), 'date': date,
                'refs': self.ref_ids(idx)}

    def k_when(self, d, mail):
        idx = self.idx(d.get('refs'), [d.get('venue'), d.get('date')])
        date, _ = self.date('date', d.get('date'), idx)
        who, nicks = self.people('who', d.get('who'))
        return {'date': date, 'start': self.time('start', d.get('start')), 'end': self.time('end', d.get('end')),
                'venue': self.place('venue', d.get('venue')), 'address': self.place('address', d.get('address')),
                'who': who, 'nicknames': nicks, 'status': self.enum('status', d.get('status'), FX.STATUS),
                'refs': self.ref_ids(idx)}

    def k_who(self, d, mail):
        who, nicks = self.people('who', d.get('who'))
        idx = self.idx(d.get('refs'), [x for x in who + nicks if x not in ('You', 'someone')])
        return {'who': who, 'nicknames': nicks, 'refs': self.ref_ids(idx)}

    def k_deadline(self, d, mail):
        idx = self.idx(d.get('refs'), [d.get('date')])
        date, text = self.date('date', d.get('date'), idx)
        has = self.boolean('has_deadline', d.get('has_deadline'))
        return {'has_deadline': bool(has or date), 'date': date, 'date_text': text,
                'action': self.enum('action', d.get('action'), ACTIONS), 'refs': self.ref_ids(idx)}

    def k_actionable(self, d, mail):
        idx = self.idx(d.get('refs'), [d.get('due')])
        due, _ = self.date('due', d.get('due'), idx)
        act = self.enum('action', d.get('action'), ACTIONS)
        return {'actionable': bool(self.boolean('actionable', d.get('actionable'))) and act != 'none', 'action': act,
                'due': due, 'refs': self.ref_ids(idx)}

    def k_requests(self, d, mail):
        out = []
        for r in (d.get('requests') if isinstance(d.get('requests'), list) else [])[:10]:
            if not isinstance(r, dict):
                self.drop('requests')
                continue
            who, wants = self.who('who', r.get('who')), self.enum('wants', r.get('wants'), WANTS)
            if not who or not wants:
                continue
            idx = self.idx(r.get('refs'), [r.get('who')])
            due, _ = self.date('due', r.get('due'), idx)
            out.append({'who': who, 'wants': wants, 'due': due, 'refs': self.ref_ids(idx)})
        return {'requests': out}

    def k_count(self, d, mail):
        n = len(self.part)
        idx = sorted({i - 1 for i in d.get('matches') or [] if isinstance(i, int) and not isinstance(i, bool)
                      and 1 <= i <= n})
        days = [FX.msg_date(self.part[i]['ts']) for i in idx]
        days = [x for x in days if x]
        return {'n': len(idx), 'first': min(days).isoformat() if days else None,
                'last': max(days).isoformat() if days else None, 'refs': self.ref_ids(idx[-FX.MAX_REFS:])}

    def k_short(self, d, mail):
        ans = self.short('answer', d.get('answer'), 12)
        idx = self.idx(d.get('refs'), [ans] if ans and ans != 'unclear' else [])
        return {'answer': ans or 'unclear', 'refs': self.ref_ids(idx)}

    def k_interests(self, d, mail):
        out = []
        for r in (d.get('interests') if isinstance(d.get('interests'), list) else [])[:5]:
            if not isinstance(r, dict):
                continue
            topic = self.enum('topic', r.get('topic'), TOPICS, 'other')
            ph = r.get('phrase')
            if topic == 'private' or (isinstance(ph, str) and FX.PLACEHOLDER.search(ph)):
                out.append({'phrase': None, 'topic': 'private'})
                continue
            p = self.short('phrase', ph, 4)
            if p and p != 'unclear':
                out.append({'phrase': p, 'topic': topic})
        return {'interests': out}

    def k_mail_card(self, d, mail):
        cat = self.enum('category', d.get('category'), V.GMAIL_LABELS, 'other')
        idx = [0]
        dl, _ = self.date('deadline', d.get('deadline'), idx)
        ap = d.get('appointment') if isinstance(d.get('appointment'), dict) else {}
        ad, _ = self.date('appointment', ap.get('date'), idx)
        appt = {'date': ad, 'start': self.time('start', ap.get('start')), 'venue': self.place('venue', ap.get('venue'))}
        act = self.enum('action', d.get('action'), ACTIONS)
        return {'category': cat, 'actionable': bool(self.boolean('actionable', d.get('actionable'))) and cat not in
                ('newsletter', 'other'), 'action': act,
                'deadline': None if cat == 'bill' else dl,                     # no bill fields from Gmail (13.10)
                'appointment': appt if ad and cat != 'bill' else None,
                'reply_needed': bool(self.boolean('reply_needed', d.get('reply_needed')))}

    def k_digest(self, d, mail):
        needs, plans, sig = [], [], []
        for r in (d.get('needs_you') if isinstance(d.get('needs_you'), list) else [])[:10]:
            if not isinstance(r, dict):
                continue
            who, wants = self.first('from', r.get('from'), allow=('group',)), self.enum('wants', r.get('wants'), WANTS)
            if who and wants:
                idx = self.idx(r.get('refs'), [r.get('from')])
                due, _ = self.date('due', r.get('due'), idx)
                needs.append({'from': who, 'wants': wants, 'due': due, 'refs': self.ref_ids(idx)})
        for r in (d.get('plans') if isinstance(d.get('plans'), list) else [])[:10]:
            if not isinstance(r, dict):
                continue
            what = self.short('what', r.get('what'), 6)
            idx = self.idx(r.get('refs'), [r.get('what'), r.get('venue')])
            date, _ = self.date('date', r.get('date'), idx)
            if not what or what == 'unclear' or not date:
                continue
            plans.append({'date': date, 'start': self.time('start', r.get('start')), 'what': what,
                          'venue': self.place('venue', r.get('venue')), 'with': self.names('with', r.get('with')),
                          'refs': self.ref_ids(idx)})
        for r in (d.get('signals') if isinstance(d.get('signals'), list) else [])[:10]:
            if not isinstance(r, dict):
                continue
            typ, topic = self.enum('type', r.get('type'), SIGNALS), self.enum('topic', r.get('topic'), TOPICS, 'other')
            if not typ:
                continue
            when, _ = self.date('when', r.get('when'), [])
            sig.append({'type': typ, 'topic': topic, 'who': self.first('who', r.get('who'), allow=('you',)),
                        'when': when})
        topics = [t for t in (d.get('topics') if isinstance(d.get('topics'), list) else []) if t in TOPICS][:6]
        return {'needs_you': needs, 'plans': plans, 'signals': sig, 'topics': sorted(set(topics))}


def net_values(v, net, drop):
    """The regex net (mail: + the money net) on every string value; a value the net changed (it held an identifier)
    or that holds a [placeholder] is dropped (counted in `drop`)."""
    if isinstance(v, dict):
        return {k: (x if k in ('refs', 'ref') else net_values(x, net, drop)) for k, x in v.items()}
    if isinstance(v, list):
        return [x for x in (net_values(y, net, drop) for y in v) if x is not None]
    if isinstance(v, str):
        n = net(v)
        if n != v or FX.PLACEHOLDER.search(n):
            drop['netted'] = drop.get('netted', 0) + 1
            return None
        return n
    return v


def merge(kind, res):
    """Per-part answers (oldest part first) -> one answer."""
    if not res:
        return {}
    if kind == 'yesno':                                  # yes, then open ON the asked days, then no
        for pick in (lambda r: r.get('answer') == 'yes',
                     lambda r: r.get('answer') == 'unclear' and r.get('in_window') is True,
                     lambda r: r.get('answer') == 'no'):
            hit = [r for r in res if pick(r)]
            if hit:
                return hit[-1]
        return res[-1]
    if kind in ('when', 'deadline', 'actionable', 'short'):
        key = {'when': 'date', 'deadline': 'has_deadline', 'actionable': 'actionable', 'short': 'answer'}[kind]
        hit = [r for r in res if r.get(key) and r.get(key) != 'unclear']
        inside = [r for r in hit if r.get('in_window') is not False]      # the asked days first
        return (inside or hit or res)[-1]
    if kind == 'who':
        who, nicks, refs = [], [], []
        for r in res:
            who += [x for x in r.get('who') or [] if x not in who]
            nicks += [x for x in r.get('nicknames') or [] if x not in nicks]
            refs += r.get('refs') or []
        return {'who': who[:FX.MAX_WHO], 'nicknames': [x for x in nicks if x not in who][:FX.MAX_WHO],
                'refs': refs[-FX.MAX_REFS:]}
    if kind == 'count':
        firsts = [r['first'] for r in res if r.get('first')]
        lasts = [r['last'] for r in res if r.get('last')]
        return {'n': sum(r.get('n') or 0 for r in res), 'first': min(firsts) if firsts else None,
                'last': max(lasts) if lasts else None, 'refs': [x for r in res for x in r.get('refs') or []][-5:]}
    if kind == 'requests':
        return {'requests': [x for r in res for x in r.get('requests') or []][-MAX_LIST:]}
    if kind == 'interests':
        seen, out = set(), []
        for r in reversed(res):
            for x in r.get('interests') or []:
                k = (str(x.get('phrase')).lower(), x.get('topic'))
                if k not in seen:
                    seen.add(k)
                    out.append(x)
        return {'interests': out[:5]}
    return res[-1]


def part_size(msgs):
    """FX.chunks' measure of a list of messages (chars + per-line overhead)."""
    return sum(len(m['sender']) + min(len(m['text']), FX.MSG_CHARS) + 24 for m in msgs)


def _clean_none(d):
    if isinstance(d, dict):
        return {k: _clean_none(v) for k, v in d.items() if v not in (None, [], {})}
    if isinstance(d, list):
        return [_clean_none(x) for x in d]
    return d


# ------------------------------------------------------------------------------------------------ the service
class Answer:
    def __init__(self, cfg, policy, gate, audit, tg=None, gmail=None, model='', clock=time.time):
        self.cfg, self.policy, self.gate, self.audit, self.tg, self.gmail = cfg, policy, gate, audit, tg, gmail
        self.model, self.clock = model, clock
        self.cache_dir = Path(cfg.state) / 'answer-cache'
        self.run_json = self._run_json                 # tests swap in a spy
        self.triage = None                             # vaultd: the event feed's triage (gmail search categories)
        self.sessions = SS.Sessions(audit, enabled=bool(getattr(cfg, 'ask_sessions', False)), clock=clock)
        self.index = None                              # vaultd: memory plan C4's index (hybrid retrieval)

    # -------------------------------------------------------------- model + cache
    def _run_json(self, kind, text, cls, what):
        mt = {'digest': 1500, 'requests': 900, 'count': 900, 'interests': 600, 'mail_card': 500}.get(kind, 400)
        with self.gate.lease(private=True, what=what, timeout=900, cls=cls):
            return self.policy.run_llm(['--system', HEAD + (TIME_RULE if kind in TIMED_KINDS else '') + '\n'
                                        + TASK[kind].split('\n', 1)[-1], '--json', '--schema',
                                        schema_arg(kind), '--temp', '0', '--max-tokens', str(mt)], text, timeout=900)

    def cache_key(self, *parts):
        blob = json.dumps([ANSWER_VERSION, V.POLICY_VERSION, self.model, *parts], ensure_ascii=False)
        return hashlib.sha256(blob.encode('utf-8')).hexdigest()

    def cache_get(self, k):
        p = self.cache_dir / k[:2] / f'{k}.json'
        try:
            if time.time() - p.stat().st_mtime > CACHE_DAYS * 86400:
                p.unlink()
                return None
            d = json.loads(p.read_text('utf-8'))
            return d if isinstance(d, dict) and 'answer' in d else None
        except (OSError, ValueError):
            return None

    def cache_put(self, k, res):
        try:
            V.ensure_dir(self.cache_dir)
            V.write_private(self.cache_dir / k[:2] / f'{k}.json', json.dumps(res, ensure_ascii=False))
            if os.urandom(1)[0] < 8:
                cut = time.time() - CACHE_DAYS * 86400
                for p in self.cache_dir.glob('*/*.json'):
                    if p.stat().st_mtime < cut:
                        p.unlink()
        except OSError:
            pass

    def clear_cache(self):
        had = self.cache_dir.exists()
        shutil.rmtree(self.cache_dir, ignore_errors=True)
        return had

    def net_for(self, mail):
        return (lambda s: self.policy.money_net(self.policy.regex_net(s))) if mail else self.policy.regex_net

    def today(self):
        return dt.datetime.fromtimestamp(self.clock(), V.TZ).date()

    def part_answer(self, source, kind, q, part, cls, mail, n, of, pre=''):
        """One part -> (checked answer, why, cached). Raises on an LLM failure. pre: today + the asked days (a line
        before the question, so the cache is per day)."""
        task = TASK[kind].split('\n', 1)[0].replace('{q}', q) if '{q}' in TASK[kind] else ''
        task = (pre + '\n' + task) if pre and task else task
        text = (task + '\n\n' if task else '') + FX.render(part)
        k = self.cache_key(source, kind, q, text, [m.get('ref') for m in part])
        res = self.cache_get(k)
        if res is not None:
            return res['answer'], res.get('why') or {}, True
        out = self.run_json(kind, text, cls, f'answer {kind} ({source}, part {n}/{of})')
        try:
            llm = json.loads(out)
        except (TypeError, ValueError):
            raise VaultError('the local LLM gave no usable JSON for the answer; nothing returned', 502,
                             'answer_failed')
        ck = ACheck(part, self.net_for(mail))
        ans = net_values(ck.run_kind(kind, llm, mail), self.net_for(mail), ck.why)
        self.cache_put(k, {'answer': ans, 'why': ck.why})
        return ans, ck.why, False

    def answer_msgs(self, source, kind, q, msgs, mail=False, report=None, window=None, single=False):
        """single (memory plan C4: hybrid retrieval chose these messages for one part): one part whenever they fit
        CHUNK_CHARS, without the day-change cut of FX.chunks."""
        parts = ([msgs] if single and msgs and part_size(msgs) <= CHUNK_CHARS else FX.chunks(msgs, CHUNK_CHARS))
        cls = 'live' if len(parts) <= 1 else 'bulk'
        res, why, cached = [], {}, 0
        today = self.today()
        pre = time_line(today, window) if kind in TIMED_KINDS else ''
        for n, part in enumerate(parts, 1):
            if report:
                report('progress', done=n - 1, total=len(parts), step=f'answer part {n}/{len(parts)}')
            ans, w, c = self.part_answer(source, kind, q, part, cls, mail, n, len(parts), pre=pre)
            res.append(settle(kind, timed(kind, dated(kind, ans, part, window), window, today), part, window, today))
            cached += int(c)
            for f, x in w.items():
                why[f] = why.get(f, 0) + int(x)
        return merge(kind, res), why, len(parts), cached

    # -------------------------------------------------------------- params
    @staticmethod
    def question(b, kind):
        q = b.get('question')
        if q is None:
            if kind in QUESTION_KINDS and kind != 'interests':
                raise VaultError(f'kind {kind} needs a question', 400, 'bad_param')
            return DEFAULT_Q.get(kind, '')
        if not (isinstance(q, str) and 0 < len(q.strip()) <= 300 and not V._CTRL.search(q)):
            raise VaultError('question must be 1..300 characters', 400, 'bad_param')
        return ' '.join(q.split())

    @staticmethod
    def since(b, default='30d'):
        s = b.get('since') or default
        if not (isinstance(s, str) and SINCE_RE.fullmatch(s.strip())):
            raise VaultError('since: e.g. 30d, 12w, 48h or 2026-09-01', 400, 'bad_param')
        return s.strip()

    @staticmethod
    def num(b, key, lo, hi, default):
        n = b.get(key, default)
        if n is None:
            return default
        if not (isinstance(n, int) and not isinstance(n, bool) and lo <= n <= hi):
            raise VaultError(f'{key} must be {lo}..{hi}', 400, 'bad_param')
        return n

    # -------------------------------------------------------------- POST /answer
    def run(self, b, report=None, owner=None):
        """POST /answer. session=true opens a follow-up session on this ask (plan C1); session=ID continues one
        (question [+ kind] only: the scope is fixed); session=ID + end=true ends it."""
        b = dict(b or {})
        sess, end = b.pop('session', None), b.pop('end', None)
        if isinstance(sess, str):
            if end:
                self.sessions.check_on()
                return self.sessions.end(owner or '', sess)
            return self.followup(sess, b, report, owner or '')
        if end or sess not in (None, False, True):
            raise VaultError('session: true (open) or a session id; end needs the id', 400, 'bad_param')
        if sess:
            self.sessions.check_on()
            kind = self.pick_kind(b, {'telegram': 'tg'}.get(b.get('source'), b.get('source')))
            if kind == 'digest':
                raise VaultError('a session needs a question or one mail: digests have no follow-ups', 400,
                                 'bad_param')
            sid = self.sessions.new_id()
            scope = {'_audit': {'session': SS.sha8(sid), 'turn': 1}}
            res = self.ask(b, report, scope)
            if 'answer' in res or res.get('kind') == 'mail_card':
                ans = res.get('answer') if 'answer' in res else {k: res.get(k) for k in (
                    'category', 'actionable', 'action', 'deadline', 'appointment', 'reply_needed')}
                scope.pop('_audit', None)
                q = ' '.join(str(b['question']).split()) if b.get('question') else None
                res['session'] = self.sessions.open(owner or '', scope, scope.pop('_refs', []), q, kind, ans, sid=sid)
            return res
        return self.ask(b, report)

    @staticmethod
    def pick_kind(b, src):
        """--kind, else short with a question (digest / the card without); a who/wer question is kind who even
        over an explicit short: a names list, never free text."""
        q = b.get('question')
        kind = b.get('kind') or ('short' if q else 'digest' if src == 'tg' else 'mail_card')
        if kind == 'short' and isinstance(q, str) and SS.is_who(q):
            kind = 'who'
        return kind

    def window_for(self, *qs):
        """The days the (first) question with time words asks about, resolved against today."""
        today = self.today()
        for q in qs:
            w = ask_window(q, today) if q else None
            if w:
                return w
        return None

    def followup(self, sid, b, report, owner):
        """One follow-up turn: the same messages (by ref), the earlier turns' checked values composed into the
        question in code, the unchanged kind pipeline (one answer call per part)."""
        extra = sorted(k for k, v in b.items() if v is not None and k not in ('question', 'kind', 'source'))
        if extra:
            raise VaultError(f'the session scope is fixed ({", ".join(extra)} not allowed in a follow-up); another chat, '
                             'search or mail needs a new ask', 400, 'scope_locked')
        s = self.sessions.begin(owner, sid)
        try:
            src = s.scope['source']
            if b.get('source') not in (None, src, {'tg': 'telegram'}.get(src)):
                raise VaultError('the session scope is fixed (source); a new source needs a new ask', 400,
                                 'scope_locked')
            if b.get('question') is None:
                raise VaultError('a follow-up needs a question', 400, 'bad_param')
            q = self.question(b, 'short')
            kind = b.get('kind') or SS.followup_kind(q)
            if kind == 'short' and SS.is_who(q):
                kind = 'who'                             # never free text for a who question
            if kind not in SS.FOLLOWUP_KINDS:
                raise VaultError(f'a follow-up kind is one of {", ".join(SS.FOLLOWUP_KINDS)}', 400, 'bad_param')
            composed = SS.compose(s.turns, q)
            turn = len(s.turns) + 1
            head, since, msgs, mail = self.scope_msgs(s.scope, report, refs=s.refs)
            window = self.window_for(q, *[t.get('q') for t in reversed(s.turns)])   # its own words, else earlier
            prior = next((t['answer']['date'] for t in reversed(s.turns) if t.get('kind') in ('yesno', 'when')
                          and isinstance(t.get('answer'), dict) and t['answer'].get('date')), None)
            res = self.result(head, src, kind, composed, since, msgs, mail, report,
                              audit_extra={'session': SS.sha8(sid), 'turn': turn}, window=window, prior_date=prior)
            if src == 'gmail' and kind == 'deadline' and s.scope.get('bill_hint'):
                res.get('answer', {}).pop('date', None)
        except BaseException:
            self.sessions.release(s)
            raise
        res['question'] = self.policy.regex_net(q)
        res['turn'] = turn
        res['session'] = self.sessions.finish(s, q, kind, res.get('answer'))
        return res

    def scope_msgs(self, scope, report, refs=None):
        """A session's scope -> (head, since, the same anonymized messages (by ref), mail?) for a follow-up."""
        keep = {tuple(r) for r in refs or ()}
        if scope['source'] == 'gmail':
            d = self._doc(scope, report)
            head = {'source': 'gmail', 'ref': d['ref'], 'account': d['account'], 'from': d['from'],
                    'date': V.now_iso(d['ts']) if d.get('ts') else None}
            return head, None, self.mail_msgs(d), True
        if scope.get('chat'):
            if report:
                report('progress', done=0, total=0, step='anonymizing the chat (cached)')
            out = self.tg.anon_messages(scope['chat'], scope['pin'], min(500, scope['n'] + 100))
            label, msgs = FX.parse_log(out)
            head = dict(scope['head'])
        elif scope.get('pairs'):                       # memory plan C4: the messages hybrid retrieval picked
            msgs = self.anon_hits(self.tg.index_lines(scope['pairs']))
            head = dict(scope['head'])
        else:
            msgs = self.hit_msgs(scope['query'], scope['since'], scope['n'], scope.get('extra'))
            head = dict(scope['head'])
        return head, scope['since'], [m for m in msgs if (m.get('ref'), m.get('ts')) in keep], False

    def ask(self, b, report=None, scope=None):
        """One ask (no session). scope: a dict to fill with what a follow-up needs (plan C1)."""
        b = dict(b)
        src = {'telegram': 'tg'}.get(b.get('source'), b.get('source'))
        if src not in ('tg', 'gmail'):
            raise VaultError('source must be tg or gmail', 400, 'bad_param')
        kind = self.pick_kind(b, src)
        if kind not in KINDS:
            raise VaultError(f'kind must be one of {", ".join(KINDS)}', 400, 'bad_param')
        if (kind == 'digest' and src != 'tg') or (kind == 'mail_card' and src != 'gmail'):
            raise VaultError(f'kind {kind} works for {"tg" if kind == "digest" else "gmail"} only', 400, 'bad_param')
        if kind == 'digest':
            return self.digest(b, report=report)
        sc = scope if scope is not None else {}
        if src == 'gmail':
            sc.update(source='gmail', ref=b.get('ref') or b.get('uid'), folder=b.get('folder'),
                      account=b.get('account'), chars=self.num(b, 'chars', 500, 30000, 8000))
        if kind == 'mail_card':
            return self.mail_card(b, report=report, audit_extra=sc.get('_audit'))
        q = self.question(b, kind)
        if src == 'gmail':
            return self.gmail_answer(b, kind, q, report, scope=sc)
        chat, query = b.get('chat'), b.get('query')
        if bool(chat) == bool(query):
            raise VaultError('give chat (one chat) or query (search hits), not both', 400, 'bad_param')
        since = self.since(b, '30d')
        mode = self.retrieval_mode(b)
        budget = self.num(b, 'chars', 500, IX.CHUNK_BUDGET, IX.HYBRID_CHARS) if query else None
        if chat:
            if not (isinstance(chat, str) and 0 < len(chat.strip()) <= 200 and '\n' not in chat):
                raise VaultError('chat: a chat id, alias or name (vault tg find-chat)', 400, 'bad_param')
            if report:
                report('progress', done=0, total=0, step='anonymizing the chat')
            out = self.tg.anon_messages(chat.strip(), since, self.num(b, 'n', 1, 500, 300))
            label, msgs = FX.parse_log(out)
            m = re.search(r'(?m)^### .+? \((\w+), chat (-?\d+)\)', out)
            head = {'source': 'telegram', 'chat': chat_display(m.group(2) if m else chat, m.group(1) if m else '',
                                                               label, self.tg.alias_map())}
            sc.update(source='tg', chat=chat.strip(), since=since, n=self.num(b, 'n', 1, 500, 300), head=head,
                      pin=pin_since(msgs, since))
            msgs, info = self.ranked_chat(mode, kind, q, since, msgs, m.group(2) if m else None)
        else:
            n = self.num(b, 'n', 1, 50, 20)
            head = {'source': 'telegram', 'query': self.policy.regex_net(V.clean_text(query, 200))}
            sc.update(source='tg', query=query, since=since, n=n, head=head,
                      extra={k: b[k] for k in ('chat', 'from', 'until') if isinstance(b.get(k), str)})
            msgs, info = self.search_msgs(mode, query, q if b.get('question') else None, since, n, b, budget)
            if info.get('mode') == 'hybrid':
                sc['pairs'] = info.pop('_pairs')
        info.pop('_pairs', None)
        sc['_refs'] = [[m.get('ref'), m.get('ts')] for m in msgs]
        audit = dict(sc.get('_audit') or {}, retrieval=info['mode'], chunks=info.get('chunks'))
        return self.result(head, 'tg', kind, q, since, msgs, False, report, audit_extra=audit, retrieval=info)

    def result(self, head, src, kind, q, since, msgs, mail, report, audit_extra=None, window=False, prior_date=None,
               retrieval=None):
        """prior_date: a follow-up's latest earlier checked event date (plan C1 sessions): an undated when (a time
        alone) takes it (date_from: earlier); without one it is flagged date_unknown."""
        chars = sum(len(m['text']) for m in msgs)
        if window is False:
            window = self.window_for(q) if kind in TIMED_KINDS else None
        if msgs:
            ans, why, parts, cached = self.answer_msgs(src, kind, q, msgs, mail=mail, report=report, window=window,
                                                       single=(retrieval or {}).get('mode') in ('hybrid', 'ranked'))
        else:
            ans, why, parts, cached = merge(kind, [ACheck([], self.net_for(mail)).run_kind(kind, {}, mail)]), {}, 0, 0
        if undated(kind, ans):
            ans = (timed(kind, dict(ans, date=prior_date, date_from='earlier'), window, self.today()) if prior_date
                   else dict(ans, date_unknown=True))
        self.audit.log('answer', source=src, kind=kind, parts=parts, chars_in=chars, dropped_fields=sum(why.values()),
                       **(audit_extra or {}))
        out = dict(head, kind=kind, question=self.policy.regex_net(q) if q else None, since=since,
                   messages=len(msgs), parts=parts, cached_parts=cached, answer=_clean_none(ans),
                   dropped=sum(why.values()), note=NOTE)
        if kind in TIMED_KINDS:                          # code-resolved dates only
            out['today'] = self.today().isoformat()
            if window:
                out['asked'] = {'label': window['label'], 'from': window['from'].isoformat(),
                                'to': window['to'].isoformat()}
        if why:
            out['dropped_fields'] = dict(sorted(why.items()))
        if retrieval:                                  # memory plan C4: numbers and enums only
            out['retrieval'] = {k: v for k, v in retrieval.items() if v is not None}
        return {k: v for k, v in out.items() if v is not None}

    def hit_msgs(self, query, since, n, b=None):
        """tgread search hits -> anonymized messages (ONE --anonymize call, never paraphrased; vault-internal)."""
        if not (isinstance(query, str) and 0 < len(query.strip()) <= 200 and not V._CTRL.search(query)):
            raise VaultError('query must be 1..200 characters', 400, 'bad_param')
        return self.anon_hits(self.tg.find_hits(query.strip(), since=since, n=n, extra=b))

    def anon_hits(self, hits):
        """Search-style hits (tgread search --json, or index-lines) -> anonymized messages, oldest first (ONE
        --anonymize call, never paraphrased; vault-internal)."""
        if not hits:
            return []
        lines = [FX.REF_TAIL.sub('', str(h.get('line') or '')) for h in hits]
        joined = '\n\n'.join(f'### item {k}\n{t}' for k, t in enumerate(lines, 1))
        out = self.policy.anonymize(joined, what=f'answer anonymize ({len(lines)})', timeout=1800, cls='live',
                                    paraphrase=False)
        parts = V.split_items(out, len(lines)) or [self.policy.anonymize(t, what='answer anonymize', timeout=900,
                                                                          cls='live', paraphrase=False) for t in lines]
        msgs = []
        for h, p in sorted(zip(hits, parts), key=lambda x: x[0].get('ts') or 0):
            m = FX.LINE_RE.match(' '.join(p.split()))
            ts = h.get('ts') if isinstance(h.get('ts'), (int, float)) else None
            msgs.append({'ts': m.group(1) if m else (dt.datetime.fromtimestamp(ts, V.TZ).strftime('%Y-%m-%d %H:%M')
                                                     if ts else '2000-01-01 00:00'),
                         'sender': m.group(2).strip() if m else '?', 'text': (m.group(3) if m else p).strip(),
                         'ref': f"#{h.get('msg_id')}"})
        return msgs

    # -------------------------------------------------------------- retrieval (memory plan C4)
    def retrieval_mode(self, b):
        """--retrieval hybrid|keyword per call; default hybrid when VAULT_INDEX=1, else keyword (today's path)."""
        r = b.get('retrieval')
        if r not in (None, 'hybrid', 'keyword'):
            raise VaultError('retrieval: hybrid or keyword', 400, 'bad_param')
        return r or ('hybrid' if getattr(self.cfg, 'index_on', False) else 'keyword')

    def search_msgs(self, mode, query, question, since, n, b, budget):
        """--search: keyword hits (today), or hybrid: FTS hits + the question's vector neighbours fused into chunks
        within `budget` chars (one part). Falls back to keyword per call when the index can't serve (reason enum)."""
        if not (isinstance(query, str) and 0 < len(query.strip()) <= 200 and not V._CTRL.search(query)):
            raise VaultError('query must be 1..200 characters', 400, 'bad_param')
        fallback = None
        if mode == 'hybrid':
            if any(isinstance(b.get(k), str) and b[k].strip() for k in ('chat', 'from', 'until')):
                fallback = 'filters'                   # chat/from/until filters: tgread's keyword search does them
            elif self.index is None:
                fallback = 'off'
            else:
                try:
                    return self.hybrid_msgs(query.strip(), question, since, b, budget)
                except IX.Unavailable as e:
                    fallback = e.reason
        msgs = self.hit_msgs(query, since, n, b)
        return msgs, {'mode': 'keyword', 'keyword_hits': len(msgs), 'fallback': fallback}

    def hybrid_msgs(self, query, question, since, b, budget):
        hits = self.tg.find_hits(query, since=since, n=IX.TOP, extra=b)
        vq = question if question and query.lower() in question.lower() else \
            (f'{question} ({query})' if question else query)
        try:
            res = self.index.retrieve(vq, [(h.get('chat_id'), h.get('msg_id')) for h in hits
                                           if isinstance(h.get('chat_id'), int) and isinstance(h.get('msg_id'), int)],
                                      since_ts=since_ts(since, self.clock()), budget=budget)
        except IX.Unavailable:
            raise
        except Exception:
            raise IX.Unavailable('error')
        pairs = []
        for c in res['chunks']:
            for m in c['msgs']:
                if [c['chat'], m] not in pairs:
                    pairs.append([c['chat'], m])
        msgs = self.anon_hits(self.tg.index_lines(pairs)) if pairs else []
        return msgs, {'mode': 'hybrid', 'keyword_hits': res['keyword_hits'], 'vector_hits': res['vector_hits'],
                      'chunks': len(res['chunks']), 'chars': res['chars'], '_pairs': pairs}

    def ranked_chat(self, mode, kind, q, since, msgs, chat_id):
        """--chat over a long window (plan §4.5 #5): for question kinds, when the window needs more than one part,
        only the chat's chunks that best match the question (+ the newest) are read: one part instead of several.
        count, requests, interests and digest stay exhaustive."""
        info = {'mode': 'window'}
        if mode != 'hybrid' or kind not in IX.RANKED_KINDS or not msgs or len(FX.chunks(msgs, CHUNK_CHARS)) <= 1:
            return msgs, info
        if self.index is None or not chat_id or not re.fullmatch(r'-?\d+', str(chat_id)):
            return msgs, dict(info, fallback='off' if self.index is None else 'error')
        try:
            res = self.index.retrieve(q, (), since_ts=since_ts(since, self.clock()), chat=int(chat_id),
                                      budget=IX.RANKED_CHARS, cap=None, recency=True)
        except IX.Unavailable as e:
            return msgs, dict(info, fallback=e.reason)
        except Exception:
            return msgs, dict(info, fallback='error')
        by_ref = {m.get('ref'): m for m in msgs}
        keep, size, used = set(), 0, 0
        for c in res['chunks']:                        # rank order; sizes of the anonymized messages: one part
            add = [r for r in (f'#{x}' for x in c['msgs']) if r in by_ref and r not in keep]
            extra = part_size([by_ref[r] for r in add])
            if keep and size + extra > CHUNK_CHARS:
                continue
            keep.update(add)
            size += extra
            used += 1
        sel = [m for m in msgs if m.get('ref') in keep]
        if not sel:
            return msgs, dict(info, fallback='no_match')
        return sel, {'mode': 'ranked', 'vector_hits': res['vector_hits'], 'chunks': used, 'chars': size,
                     'window_messages': len(msgs)}

    # -------------------------------------------------------------- tg search (default output)
    def tg_hits(self, b, ask=None, kind=None, report=None):
        """/tg/search without text: hits {ref, ts, chat (alias|first name|group), from (first name)}; ask: an answer
        over the hits (kind default short)."""
        b = dict(b or {})
        q = b.get('query')
        if not (isinstance(q, str) and 0 < len(q.strip()) <= 200 and not V._CTRL.search(q)):
            raise VaultError('query must be 1..200 characters', 400, 'bad_param')
        since = self.since(b, '365d')
        n = self.num(b, 'n', 1, 50, 15)
        hits = self.tg.find_hits(q.strip(), since=since, n=n, extra=b)
        aliases = self.tg.alias_map()
        out = []
        for h in hits:
            line = str(h.get('line') or '')
            m = re.match(r'^\[[^\]]+\] ([^\n:]{1,120}?):', line)
            ts = h.get('ts') if isinstance(h.get('ts'), (int, float)) else None
            out.append({'ref': f"#{h.get('msg_id')}", 'ts': V.now_iso(ts) if ts else None,
                        'chat': chat_display(h.get('chat_id'), h.get('chat_type'), h.get('chat'), aliases),
                        'chat_key': str(h.get('chat_id') or ''), 'from': first_name(m.group(1)) if m else '?'})
        self.audit.log('tg_hits', query=q, since=since, count=len(out))
        res = {'kind': 'hits', 'source': 'telegram', 'query': self.policy.regex_net(V.clean_text(q, 200)),
               'since': since, 'count': len(out), 'hits': out,
               'note': 'hits only (no text); ask=QUESTION answers over them; text needs --text + the owner\'s OK'}
        if ask is not None:
            res['answer'] = self.run({'source': 'tg', 'query': q, 'since': since, 'n': n, 'kind': kind or 'short',
                                      'question': ask}, report=report)
        return res

    # -------------------------------------------------------------- digest
    def digest_params(self, cmd, b):
        """/tg/recent, /tg/summarize, /tg/unread-summary-data params -> digest params."""
        b = dict(b or {})
        p = {k: b[k] for k in ('chat', 'since', 'hours', 'include_muted', 'include_archived') if b.get(k) is not None}
        if cmd == 'unread-summary-data' or b.get('unread'):
            p['unread'] = True
        if cmd == 'unread-summary-data' and 'hours' not in p and 'since' not in p:
            p['hours'] = 24 * 7
        if b.get('n') is not None:
            p['n'] = b['n']
        if b.get('per_chat') is not None:
            p['n'] = b['per_chat']
        return p

    def digest(self, b, report=None):
        b = dict(b or {})
        now = self.clock()
        hours = b.get('hours')
        if b.get('since'):
            st = since_ts(self.since(b), now)
        else:
            try:
                hours = float(hours if hours is not None else 24)
            except (TypeError, ValueError):
                raise VaultError('hours must be a number', 400, 'bad_param')
            if not 0.01 <= hours <= 24 * 365:
                raise VaultError('hours must be 0.01..8760', 400, 'bad_param')
            st = int(now - hours * 3600)
        per_chat = self.num(b, 'n', 1, 500, MAX_MSGS_CHAT)
        wp = {'since': f'@{st}'}
        for k in ('chat', 'unread', 'include_muted', 'include_archived'):
            if b.get(k):
                wp[k] = b[k]
        if report:
            report('progress', done=0, total=None, step='window')
        win, err = self.tg.window(wp)
        if win is None:
            raise VaultError('tgread window: ' + V.clean_text((err or {}).get('stderr') or 'failed', 200), 502,
                             'source_failed')
        chats = sorted(win.get('chats') or [], key=lambda c: -int(c.get('msgs') or 0))
        skipped = max(0, len(chats) - MAX_CHATS)
        chats = chats[:MAX_CHATS]
        aliases = self.tg.alias_map()
        needs, plans, sig, topics, why = [], [], [], {}, {}
        total, nparts, cached = 0, 0, 0
        for ci, c in enumerate(chats):
            if report:
                report('progress', done=ci, total=len(chats), step=f'chat {ci + 1}/{len(chats)}')
            out = self.tg.anon_messages(str(c['chat_id']), f'@{st}', min(per_chat, max(1, int(c.get('msgs') or 1) + 5)))
            label, msgs = FX.parse_log(out)
            m = re.search(r'(?m)^### .+? \((\w+), chat (-?\d+)\)', out)
            disp = chat_display(c['chat_id'], m.group(1) if m else c.get('type'), label, aliases)
            total += len(msgs)
            parts = FX.chunks(msgs, CHUNK_CHARS)
            for n, part in enumerate(parts, 1):
                ans, w, was = self.part_answer('tg', 'digest', '', part, 'bulk', False, n, len(parts))
                nparts += 1
                cached += int(was)
                for f, x in w.items():
                    why[f] = why.get(f, 0) + int(x)
                needs += [dict(x, chat=disp) for x in ans.get('needs_you') or []]
                plans += [dict(x, chat=disp) for x in ans.get('plans') or []]
                sig += [dict(x, chat=disp) for x in ans.get('signals') or []]
                for t in ans.get('topics') or []:
                    topics[t] = topics.get(t, 0) + 1
        plans.sort(key=lambda x: (x.get('date') or '', x.get('start') or ''))
        self.audit.log('answer', source='tg', kind='digest', parts=nparts, chars_in=total,
                       dropped_fields=sum(why.values()))
        res = {'kind': 'digest', 'source': 'telegram',
               'window': {'hours': round((now - st) / 3600, 2), 'since': V.now_iso(st), 'chats': len(chats),
                          'messages': total, 'skipped_chats': skipped, 'sync': win.get('sync')},
               'needs_you': _clean_none(needs[-MAX_LIST:]), 'plans': _clean_none(plans[:MAX_LIST]),
               'signals': _clean_none(sig[-40:]), 'topics': dict(sorted(topics.items(), key=lambda x: -x[1])),
               'parts': nparts, 'cached_parts': cached, 'dropped': sum(why.values()), 'note': NOTE}
        if why:
            res['dropped_fields'] = dict(sorted(why.items()))
        return res

    # -------------------------------------------------------------- gmail
    def mail_msgs(self, d):
        return FX.mail_msgs(d, CHUNK_CHARS)            # quoted mails keep their own date

    def _doc(self, b, report):
        ref = b.get('ref') or b.get('uid')
        chars = self.num(b, 'chars', 500, 30000, 8000)
        if report:
            report('progress', done=0, total=0, step='anonymizing the mail')
        return self.gmail.anon_doc(ref, b.get('folder'), chars, b.get('account'))

    def gmail_answer(self, b, kind, q, report, scope=None):
        d = self._doc(b, report)
        head = {'source': 'gmail', 'ref': d['ref'], 'account': d['account'], 'from': d['from'],
                'date': V.now_iso(d['ts']) if d.get('ts') else None}
        if scope is not None:
            scope['bill_hint'] = bool(d.get('bill_hint'))
        res = self.result(head, 'gmail', kind, q, None, self.mail_msgs(d), True, report,
                          audit_extra=(scope or {}).get('_audit'))
        if kind == 'deadline' and d.get('bill_hint'):
            res.get('answer', {}).pop('date', None)
        return res

    def mail_card(self, b, report=None, audit_extra=None):
        d = self._doc(b, report)
        msgs = self.mail_msgs(d)[:1]                   # the card: the start of the mail (one call)
        if msgs:
            ans, why, _, cached = self.answer_msgs('gmail', 'mail_card', '', msgs, mail=True, report=report)
        else:
            ans, why, cached = {'category': 'other', 'actionable': False, 'action': 'none',
                                'reply_needed': False}, {}, 0
        self.audit.log('answer', source='gmail', kind='mail_card', parts=len(msgs),
                       chars_in=sum(len(m['text']) for m in msgs), dropped_fields=sum(why.values()),
                       **(audit_extra or {}))
        card = {'kind': 'mail_card', 'ref': d['ref'], 'account': d['account'],
                'date': V.now_iso(d['ts']) if d.get('ts') else None, 'from': d['from'], **_clean_none(ans),
                'attachments': d.get('atts') or {'n': 0, 'pdf': 0, 'image': 0}, 'cached': bool(cached),
                'note': 'a card, not the mail: no subject, no text; amounts never; text needs --text + the owner\'s OK'}
        if card.get('category') == 'bill':
            card.pop('deadline', None)
            card['hint'] = f"file the bill: vault gmail to-paperless {d['ref']} N"
        return card
