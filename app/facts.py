"""Facts (plan v2 #6, 2026-10-13): events, to-dos, places, decisions and open questions as JSON, built from text that
is already anonymized inside the vault (policy v3; NOT the v4 paraphrase, whose wording is the model's) -> one
structured local-LLM call per part (<= CHUNK_CHARS) -> code checks -> regex net (mail: + the money net).

Used by `vault facts tg|gmail` (POST /tg/facts, /gmail/facts; jobs tg.facts / gmail.facts) and by the event feed's
calendar suggestions (plan v2 #11: EventFeed -> Facts.for_events, GET /plans).

Code checks (G4): fields come from fixed lists; every value is in the anonymized text: names, dates, times, venues
and addresses as written (token by token, case-insensitive), `what` a short description whose every word (glue words
like "at", "mit", "zum" aside) is in the messages; refs point at the messages that say it (a wrong citation is
replaced by the messages that hold its words); dates are worked out in code from the message's own timestamp
(Europe/Zurich): "Samstag", "17.10.", "morgen", "gestern", "3.1." written in late December = next January; short
weekdays ("so", "Sa") only where clearly a date (_abbr_ok); sizes are capped.
The regex net runs last. An LLM failure is an error with nothing partial. Results are cached per part
(/data/state/facts-cache, 0600; key = facts version, policy, model and the part's text; 30 days; `tg purge|exclude|
wipe` clear it together with the anonymization cache)."""
import bisect
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

import vaultlib as V
from vaultlib import VaultError
from media import Grounding, MONTHS

FACTS_VERSION = 'facts-4'                          # 4: short weekdays, gestern; 3: weekday tense (15.10); 2: honorific
KINDS = ('events', 'todos', 'places', 'decisions', 'questions')
FIELDS = {'events': ('what', 'date', 'start', 'end', 'venue', 'address', 'who', 'status'),
          'todos': ('what', 'who', 'due'),
          'places': ('name', 'address'),
          'decisions': ('what',),
          'questions': ('what', 'who')}
STATUS = ('planned', 'proposed', 'confirmed', 'cancelled', 'done')
PART_MAX = 25                                         # items per kind from one model answer
MAX_PER_KIND = {'events': 40, 'todos': 40, 'places': 30, 'decisions': 30, 'questions': 30}
MAX_LEN = 120
MAX_WHO = 8
MAX_REFS = 5
CHUNK_CHARS = 5000
MSG_CHARS = 1500
CACHE_DAYS = 30
NOTE = ('facts read from the anonymized text only (not the paraphrase); every value was found in it; dates worked '
        'out in code from the message times (Europe/Zurich); refs = the messages that say it')

SYSTEM = (
    'You read an anonymized chat log or e-mail. Each line is one message: "[mN] YYYY-MM-DD HH:MM Sender: text". '
    'Extract what matters for the owner\'s calendar and to-do list. Return a JSON object {"events": [{"what": "", '
    '"date": "", "start": "", "end": "", "venue": "", "address": "", "who": [], "status": "", "msgs": []}], '
    '"todos": [{"what": "", "who": "", "due": "", "msgs": []}], "places": [{"name": "", "address": "", "msgs": []}], '
    '"decisions": [{"what": "", "msgs": []}], "questions": [{"what": "", "who": "", "msgs": []}]}. '
    'events: planned meetings, trips, parties, appointments, flights, deadlines that have a day; todos: something '
    'someone has to do, bring, book or pay attention to; places: venues, meeting points, addresses; decisions: what '
    'was agreed; questions: open questions nobody answered yet. '
    'Copy every value EXACTLY as it is written in the messages, in their language and spelling, as a short span: '
    '"what" in at most 8 words taken from the messages; "date" and "due" as written ("Samstag", "17.10.", "morgen", '
    '"next Friday", "3. November"); "start"/"end" as written ("18:00", "um 7", "20 Uhr"); "who": first names as '
    'written. status: one of planned, proposed, confirmed, cancelled, done. msgs: the numbers N of the messages it '
    'comes from. Use "" or [] when something is not there; never guess. Leave out placeholders in square brackets, '
    'prices, amounts, codes and links. Output JSON only.')

GLUE = frozenset((
    'a an the at in on to for with and or of by from about into is are be will this that next new '
    'im am um an auf aus mit und oder für fuer zum zur der die das den dem des ein eine einen einem einer bei von vom '
    'vor nach ins beim bis zu als dr d de e en es si mir mer uf vo gäge gege no nöd nid'
).split())
WORD = re.compile(r'[^\W_]+')
PLACEHOLDER = re.compile(r'\[[^\[\]]{1,60}\]')
# Honorific + surname ("Herr Huber", "Herrn Huber", "Frau Gerolds Garten", "Dr. Frei", "Fam. Meier") is a surname,
# never a first name (real-model eval 14.10): person fields -> "someone", places lose the span, short text gets
# "someone" (has_honor / place_unhonor / unhonor; counted as `honorific`).
_HON = (r"(?:[Hh]errn?|[Ff]rau|[Ff]r[äa]ulein|Hr|Fr|Dr|Prof|Doktor|Professor(?:in)?|Familie|Fam|Mrs?|Ms|Mx|Miss|"
        r"Mister|Madame|Mme|Monsieur|Mademoiselle|Mlle|Signor[ae]?|Sig(?:\.ra)?|Dott(?:\.ssa)?)")
HONOR_WORD = re.compile(r"\s*" + _HON + r"(?!\w)\.?")
HONOR = re.compile(r"(?<![\w.])" + _HON + r"(?:\.\s*|\s+)(?:(?:Dr|Prof|med|dent|phil|iur|dipl|rer|nat)(?:\.\s*|\s+))*"
                   r"[A-ZÀ-ÖØ-Þ][\w'’-]*(?:\s+[A-ZÀ-ÖØ-Þ][\w'’-]*){0,2}")

LINE_RE = re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\] ([^\n:]{1,120}?): ?(.*)$')
REF_TAIL = re.compile(r'\s*\(#(\d+)(?: reply to #(\d+))?\)(?:\s+<== match)?\s*$')
HEAD_RE = re.compile(r'^### (.+?) \((\w+), chat [^)]*\)')

WEEKDAYS = {0: ('mo', 'mon', 'montag', 'mäntig', 'mentig', 'monday'),
            1: ('di', 'tue', 'tues', 'dienstag', 'zischtig', 'ziischtig', 'tuesday'),
            2: ('mi', 'wed', 'mittwoch', 'mittwuch', 'wednesday'),
            3: ('do', 'thu', 'thur', 'thurs', 'donnerstag', 'dunschtig', 'donschtig', 'thursday'),
            4: ('fr', 'fri', 'freitag', 'fritig', 'friitig', 'friday'),
            5: ('sa', 'sat', 'samstag', 'samschtig', 'saturday'),
            6: ('so', 'sun', 'sonntag', 'sunntig', 'sunday')}
WD = {n: i for i, names in WEEKDAYS.items() for n in names}
REL = {'heute': 0, 'heut': 0, 'hüt': 0, 'hüüt': 0, 'today': 0, 'tonight': 0, 'hinech': 0, 'hinecht': 0,
       'morgen': 1, 'morn': 1, 'moorn': 1, 'tomorrow': 1, 'übermorgen': 2, 'übermorn': 2}
# the days before the message: checked last, so a message that also names today, tomorrow, a weekday
# or the weekend keeps that day ("War super gestern, am Samstag gehen wir wandern" = Saturday)
REL_PAST = {'gestern': -1, 'geschter': -1, 'yesterday': -1, 'vorgestern': -2, 'vorgeschter': -2, 'ehgestern': -2,
            'ehgeschter': -2}
_MON = r'(jan|feb|mär|maer|mar|mrz|apr|mai|may|jun|jul|aug|sep|okt|oct|nov|dez|dec)[a-zä]*\.?'


def words(s):
    return WORD.findall(str(s or '').casefold())


def fold(s):
    return ' '.join(w for w in words(s) if w not in GLUE)


def has_honor(s):
    """A person value that is (or holds) an honorific + surname: "Herr Huber", "Dr. Frei", "Frau"."""
    s = str(s or '')
    return bool(HONOR.search(s) or HONOR_WORD.match(s))


def unhonor(s):
    """Short text: each honorific + surname -> "someone"."""
    return HONOR.sub('someone', s) if isinstance(s, str) else s


def place_unhonor(s):
    """A venue/address/place without its honorific + surname ("bei Herrn Huber" -> None, "Praxis Dr. Frei am
    Limmatquai" -> "Praxis am Limmatquai", "Frau Gerolds Garten, Geroldstrasse" -> "Geroldstrasse")."""
    if not isinstance(s, str) or not HONOR.search(s):
        return s
    c = re.sub(r'\s{2,}', ' ', HONOR.sub(' ', s)).strip(' ,;:-–()')
    c = re.sub(r'\s+([,;:)])', r'\1', c)
    return c if [w for w in words(c) if w not in GLUE and len(w) > 1] else None


# ------------------------------------------------------------------------------------------------ dates and times
def _ymd(y, m, d):
    try:
        x = dt.date(int(y), int(m), int(d))
    except ValueError:
        return None
    return x if 2000 <= x.year <= 2100 else None


def infer_year(day, mon, ref):
    """Day and month without a year -> the date near the message: more than 60 days before it = next year (a
    "3.1." written on 28.12.), more than 300 days after it = last year."""
    d = _ymd(ref.year, mon, day)
    if d is None:
        return _ymd(ref.year + 1, mon, day)               # 29.2.
    if d < ref - dt.timedelta(days=60):
        d = _ymd(ref.year + 1, mon, day)
    elif d > ref + dt.timedelta(days=300):
        d = _ymd(ref.year - 1, mon, day)
    return d


def _mon(s):
    s = s.lower().rstrip('.')
    return MONTHS.get(s[:4] if s.startswith('maer') else s[:3])


def _tense(ws, cl, j):
    """How the words around the weekday/weekend word ws[j] place it (a live case: "Mein Wochenende war ruhig" on a
    Monday is the PAST weekend): 'next' / 'last' (the word right before), 'lastweek' ("Samstag letzte Woche"),
    'past' (seit/since before it, or a past-tense marker in its clause within TENSE_SPAN words and nothing there that
    points ahead: future verb, plan word, für/bis/for/by right before it), else None = as before (on or after)."""
    prev = ws[j - 1] if j else ''
    if prev in NEXT:
        return 'next'
    if prev in LAST:
        return 'last'
    if j + 2 < len(ws) and ws[j + 1] in LAST and ws[j + 2] in WEEK:
        return 'lastweek'
    if SINCE & set(ws[max(0, j - 2):j]):
        return 'past'
    if prev in AHEAD_PREP:
        return None
    near = {ws[k] for k in range(max(0, j - TENSE_SPAN), min(len(ws), j + TENSE_SPAN + 1))
            if k != j and cl[k] == cl[j]}
    if near & AHEAD or near & set(NEXT):
        return None
    if (near & PAST or ('was' in near and near & EN_HINT)
            or (near & HAVE and any(PARTICIPLE.match(w) and w not in NOT_PARTICIPLE for w in near))):
        return 'past'
    return None


def _occurrences(tt, ct):
    """Every start index of the token sequence tt in ct."""
    n = len(tt)
    return [k for k in range(len(ct) - n + 1) if n and ct[k:k + n] == tt] if n else []


def _words_and_clauses(t):
    toks = list(TOKEN.finditer(t))
    cuts = [m.start() for m in CLAUSE.finditer(t)]
    return [m.group(0) for m in toks], [bisect.bisect_right(cuts, m.start()) for m in toks]


def resolve_date(text, ref, context=None):
    """A date as written in a message ("Samstag", "Sa 17.10.", "17.10.2026", "3. Nov", "morgen", "next Friday",
    "2026-11-21") -> dt.date or None. ref: the message's own date (Europe/Zurich). A weekday or "Wochenende" is the
    next one on or after ref, unless the words around it say otherwise (_tense): past tense / seit -> the latest one
    on or before ref. context: the message the date was quoted from (facts, answers); its words around
    the quoted date decide the tense when the quote alone doesn't (every occurrence must agree, else as before)."""
    if not text or ref is None:
        return None
    t = ' '.join(str(text).casefold().split())
    m = re.search(r'(?<!\d)(\d{4})-(\d{1,2})-(\d{1,2})(?!\d)', t)
    if m:
        return _ymd(m[1], m[2], m[3])
    m = re.search(r'(?<![\d.])(\d{1,2})\.(\d{1,2})\.(\d{4}|\d{2})(?![\d])', t)
    if m:
        return _ymd(int(m[3]) + (2000 if len(m[3]) == 2 else 0), m[2], m[1])
    m = re.search(r'(?<![\d.:])(\d{1,2})\.(\d{1,2})(?:\.|(?![\d.:]))', t)
    if m and 1 <= int(m[2]) <= 12:
        return infer_year(int(m[1]), int(m[2]), ref)
    m = re.search(r'(?<![\w])(\d{1,2})\.?\s*' + _MON + r'(?:\s*(\d{4}))?(?![\w])', t)
    if m and _mon(m[2]):
        return _ymd(m[3], _mon(m[2]), m[1]) if m[3] else infer_year(int(m[1]), _mon(m[2]), ref)
    m = re.search(r'(?<![\w])' + _MON + r'\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s*(\d{4}))?(?![\w])', t)
    if m and _mon(m[1]):
        return _ymd(m[3], _mon(m[1]), m[2]) if m[3] else infer_year(int(m[2]), _mon(m[1]), ref)
    ws, cl = _words_and_clauses(t)

    def tense(j):
        mode = _tense(ws, cl, j)
        if mode is None and context:
            c = ' '.join(str(context).casefold().split())
            cws, ccl = _words_and_clauses(c)
            modes = {_tense(cws, ccl, k + j) for k in _occurrences(ws, cws)}
            mode = modes.pop() if len(modes) == 1 else None
        return mode

    orig = ' '.join(str(text).split())
    ok = {}

    def is_day(i):
        """ws[i] names a weekday: a full name always; a short form ("so", "Sa") only where clearly a date
        (_abbr_ok), in the text itself or, for a quote, where its message wrote it."""
        w = ws[i]
        if w not in WD or w not in ABBR:
            return w in WD
        if i not in ok:
            ok[i] = _abbr_ok(orig, w, ws[:i].count(w))
            if not ok[i] and context:
                c = ' '.join(str(context).split())
                n = len(_abbr_hits(c, w))
                ok[i] = (any(_abbr_ok(c, w, k) for k in range(n))
                         or not n and all(x in DATE_WORDS for x in ws))   # a pure date quote not found in it
        return ok[i]

    for j, w in enumerate(ws):                         # "Freitag morgen" = Friday morning, not tomorrow
        if w in REL and not (w == 'morgen' and _morning(ws, j, is_day)):
            if w == 'tomorrow' and ws[max(0, j - 2):j] == ['day', 'after']:
                return ref + dt.timedelta(days=2)
            return ref + dt.timedelta(days=REL[w])
    for j, w in enumerate(ws):
        s = DAYPART.sub('', w)
        if s in WD and s not in ABBR:                  # "Freitagmorgen", "Samstagabend": the weekday (full names)
            w = s
        elif not is_day(j):                            # "so", "do", "mi" in a sentence: no weekday
            continue
        # the next such weekday ON or after the reference date
        delta = (WD[w] - ref.weekday()) % 7            # "next Friday" written on a Friday: +7
        mode = tense(j)
        if mode == 'next' and not delta:
            delta = 7
        elif mode == 'last':                       # "letzten Samstag": the one before ref
            delta = delta - 7 if delta else -7
        elif mode == 'past':                       # "Am Samstag war ...": the latest one on or before ref
            delta = delta - 7 if delta else 0
        elif mode == 'lastweek':                   # "Samstag letzte Woche": in the previous Mon-Sun week
            delta = WD[w] - ref.weekday() - 7
        return ref + dt.timedelta(days=delta)
    for j, w in enumerate(ws):                         # "am Wochenende": that weekend's Saturday
        if w in WEEKEND:
            sat = weekend_sat(ref)
            mode = tense(j)
            if mode in ('last', 'lastweek'):
                sat -= dt.timedelta(days=7)
            elif mode == 'next' and ref.weekday() >= 5:
                sat += dt.timedelta(days=7)
            elif mode == 'past' and ref.weekday() < 5:  # "Mein Wochenende war ruhig" on Mon-Fri: the one before
                sat -= dt.timedelta(days=7)
            return sat
    for j, w in enumerate(ws):                         # gestern / yesterday / vorgestern
        if w in REL_PAST:
            if w == 'yesterday' and ws[max(0, j - 2):j] == ['day', 'before']:
                return ref - dt.timedelta(days=2)
            return ref + dt.timedelta(days=REL_PAST[w])
    return None


def _morning(ws, j, is_day):
    """"morgen" at ws[j] means the morning, not tomorrow: "am / guten / jeden / den ganzen / heute / gestern Morgen",
    a weekday before it ("Freitag morgen", "Sa morgen"), or a greeting ("Morgen allerseits")."""
    if j:
        return ws[j - 1] in MORNING_PREV or is_day(j - 1)
    return len(ws) > 1 and ws[1] in GREET_NEXT


def _abbr_hits(s, w):
    return list(re.finditer(r'(?<![^\W\d_])' + re.escape(w) + r'(?![^\W\d_])', s, re.I))


def _wd_tok(tok):
    """A weekday as written next to another one ("Sa/So", "Mo-Fr"): a full name, or a short form in a date's case."""
    lw = tok.casefold()
    return lw in WD and (lw not in ABBR or lw in ABBR_PLAIN or tok[:1].isupper())


def _abbr_ok(s, w, k):
    """Is the k-th occurrence of the short weekday form w ("so", "sa", "sat") in s (original case) clearly a date?
    A live case: "Das war so schön" named a Sunday. Lowercase so/do/mi/sa/di/mo and sun/sat/wed/mon/tue never
    (words in de, gsw, en, hr: "bin so um 19 da", "do 19:00" = until); else a date or time right after, a date word
    before, a daypart after, another weekday next to it, a trailing dot, capitalized inside a sentence, or alone."""
    hits = _abbr_hits(s, w)
    if k >= len(hits):
        return False
    m = hits[k]
    tok, before, after = m.group(0), s[:m.start()], s[m.end():]
    cap = tok[:1].isupper()
    if not cap and w not in ABBR_PLAIN:
        return False
    p = re.search(r'([^\W\d_]+)\s+$', before)
    prev = p[1].casefold() if p else ''
    n = re.match(r'\.?[\s-]*([^\W\d_]+)', after)
    nxt_tok = n[1] if n else ''
    nxt = nxt_tok.casefold()
    lead = before.rstrip()
    start = not lead or not lead[-1].isalnum()         # starts a sentence (or follows punctuation / an emoji)
    if prev in ARTICLE:
        return False                                   # "the Sun", "die So..."
    if re.match(r'\.\s*[^\W\d_]', after) and nxt_tok[:1].isupper() and nxt not in DAYPART_WORDS and nxt not in WD:
        return False                                   # "Fr. Müller", "So. Jetzt ..."
    if ABBR_TIME.match(after):
        return True                                    # "Fr 19:00", "Sa um 20 Uhr", "Mi 18.30", "Fri 7pm"
    if prev in DATE_PREV:
        return True                                    # "am Sa", "bis Mo", "on Sat", "next Fri"
    if nxt in DAYPART_WORDS and not (start and w == 'so' and nxt in ('morgen', 'morn')):
        return True                                    # "Sa znacht", "Fr morgen"; "So morgen gehts los" = so, tomorrow
    a, b = ABBR_NEXT_TO.match(after), ABBR_AFTER_DAY.search(before)
    if (a and _wd_tok(a[1])) or (b and _wd_tok(b[1])):
        return True                                    # "Sa/So", "Mo-Fr", "Sa oder So" (not "So oder so")
    if re.match(r'\.(?!\.)', after) and (nxt or not start):
        return True                                    # "Wir sehen uns Do.", "Sa. ab 10" (not "So." alone)
    if cap and not start and w in ABBR_MIDCAP:
        return True                                    # "Hast du Sa Zeit?"
    return cap and w in ABBR_ALONE and WORDS_RE.findall(s) == [tok]   # "Sa?" alone (not "So?", "Do!")


def weekend_sat(day):
    """The Saturday of "this weekend" seen from `day`: the coming one on Mon-Fri, the current one on Sat/Sun."""
    return day + dt.timedelta(days=(5 - day.weekday()) % 7) if day.weekday() < 6 else day - dt.timedelta(days=1)


DAYPART = re.compile(r'(?:morgen|vormittag|mittag|nachmittag|abend|nacht|znacht|morning|afternoon|evening|night)$')
NEXT = ('next', 'nächsten', 'nächste', 'nächstes', 'naechsten', 'naechstes', 'kommenden', 'kommende', 'kommendes',
        'nöchschte', 'nächscht')
LAST = ('last', 'past', 'previous', 'letzte', 'letztes', 'letzten', 'letztem', 'letschte', 'letschts', 'letscht',
        'vergangene', 'vergangenes', 'vergangenen', 'vergangenem', 'vorig', 'vorige', 'voriges', 'vorigen', 'vorigem')
WEEKEND = ('wochenende', 'wochenend', 'weekend', 'wuchenend', 'wucheend', 'wekend')

# ---- short weekday forms (_abbr_ok). so/do/mi/sa/di/mo and
# sun/sat/wed/mon/tue are ordinary words too (de, gsw, en, hr), "fr" is "for real": only clear date uses count.
ABBR = frozenset(n for n in WD if len(n) <= 3)
ABBR_PLAIN = frozenset(('fr', 'thu', 'fri'))           # no ordinary word: lowercase is fine in a date context
ABBR_MIDCAP = frozenset(('mi', 'do', 'fr', 'sa', 'so'))  # capitalized inside a sentence; not Mo/Di (names), nor English
ABBR_ALONE = frozenset(('mo', 'di', 'mi', 'fr', 'sa'))   # the whole text ("Sa?"); not "So?" / "Do!"
DATE_PREV = frozenset(('am', 'ab', 'bis', 'vom', 'von', 'vo', 'jeden', 'jede', 'jedes', 'jedem', 'diesen', 'dieser',
                       'dieses', 'on', 'this', 'every', 'until', 'till', 'by', 'from', 'für', 'fürs', 'per')
                      + NEXT + LAST)
DAYPART_WORDS = frozenset(('morgen', 'morgens', 'früh', 'vormittag', 'mittag', 'nachmittag', 'abend', 'abends',
                           'nacht', 'znacht', 'zmittag', 'zmorge', 'morge', 'abig', 'obig', 'namittag', 'morning',
                           'afternoon', 'evening', 'night', 'noon'))
ARTICLE = frozenset(('the', 'a', 'an', 'my', 'your', 'die', 'der', 'das', 'des', 'ein', 'eine', 'mein', 'dein'))
ABBR_TIME = re.compile(r'\.?,?\s*(?:\d{1,2}\.\d{1,2}|\d{1,2}[:.]\d{2}|\d{1,2}\s*(?:uhr|h|am|pm)(?![^\W\d_])'
                       r'|(?:um|at|ab|am|from|vo|von)\s+\d{1,2}(?!\d))', re.I)
_SEP = r'(?:\s*[-–/&+,]\s*|\s+(?:oder|or|und|and|u|bis|to|till)\s+)'
ABBR_NEXT_TO = re.compile(r'\.?' + _SEP + r'([^\W\d_]+)', re.I)      # "Sa/So", "Mo-Fr", "Sa oder So"
ABBR_AFTER_DAY = re.compile(r'([^\W\d_]+)\.?' + _SEP + r'$', re.I)
WORDS_RE = re.compile(r'[^\W\d_]+')
MORNING_PREV = frozenset(('am', 'guten', 'gute', 'jeden', 'jedem', 'jede', 'every', 'den', 'dem', 'der', 'des',
                          'diesen', 'diesem', 'dieser', 'ganzen', 'frühen', 'heute', 'heut', 'hüt', 'hüüt',
                          'gestern', 'geschter', 'vorgestern', 'vorgeschter', 'vom', 'zum', 'einen', 'einem',
                          'nächsten', 'naechsten', 'schönen', 'schöne', 'pro'))
GREET_NEXT = frozenset(('allerseits', 'mitenand', 'miteinand', 'zäme', 'leute', 'ihr'))
DATE_WORDS = (frozenset(WD) | frozenset(REL) | frozenset(REL_PAST) | DATE_PREV | DAYPART_WORDS | frozenset(WEEKEND)
              | frozenset(('um', 'uhr', 'at', 'h', 'pm', 'the', 'day', 'after', 'before')))

# ---- tense around a weekday / weekend word (resolve_date, _tense). Conservative: only clear markers
# in the same clause flip a day to the past; anything pointing ahead keeps the old "on or after" reading.
TOKEN = re.compile(r'[a-zäöü]+')
CLAUSE = re.compile(r'[,;!?\n]+|(?<!\d)\.|\s(?:und|and|aber|but|oder|or|dann|then|u)\s')
TENSE_SPAN = 10                                     # words either side, within the clause
WEEK = frozenset(('woche', 'wuche', 'week'))
SINCE = frozenset(('seit', 'since'))
AHEAD_PREP = frozenset(('für', 'fürs', 'for', 'bis', 'until', 'till', 'by', 'ab', 'spätestens'))
PAST = frozenset((
    'war', 'waren', 'warst', 'wart', 'wars', 'hatte', 'hatten', 'hattest', 'hattet', 'gewesen', 'gehabt',
    'gegangen', 'gefahren', 'geflogen', 'gelaufen', 'gekommen', 'geblieben', 'gereist', 'gewandert',
    'gsi', 'gsii', 'gsy', 'gha', 'gmacht', 'gfahre', 'gloffe', 'gschlafe', 'gfiiret', 'gfiret', 'gässe', 'gnoh',
    'gholt', 'gspilt', 'gange', 'gschaffet', 'gluegt', 'gchauft', 'gfunde', 'troffe',
    'were', 'weren', 'wasn', 'had', 'hadn', 'did', 'didn', 'went'))
EN_HINT = frozenset(('my', 'it', 'its', 'the', 'he', 'she', 'they', 'you', 'your', 'our', 'his', 'her', 'their',
                     'this', 'that', 'how', 'on', 'at', 'of', 'with', 'there', 'what', 'where', 'who', 'when'))
HAVE = frozenset(('hat', 'habe', 'hab', 'hast', 'haben', 'habt', 'han', 'hani', 'hesch', 'het', 'hend', 'händ', 'hän',
                  'hämmer', 'hemmer', 'hets', 'hats'))
PARTICIPLE = re.compile(r'ge[a-zäöü]{2,}t$|(?:gegessen|gesehen|geschlafen|getroffen|gefunden|geschrieben|gelesen'
                        r'|getrunken|gesprochen|genommen|gegeben|gefallen|geworden|gewonnen|geholfen|gelegen|gesessen'
                        r'|gestanden|besucht|verbracht|erlebt|bekommen|erzählt|vergessen|verpasst|genossen|verloren)$')
NOT_PARTICIPLE = frozenset(('gesamt', 'gerecht', 'gescheit', 'gewandt', 'gerät', 'geöffnet', 'geoeffnet'))  # open
AHEAD = frozenset((
    'wird', 'werde', 'wirst', 'werden', 'werdet', 'wirds', 'will', 'willst', 'wollen', 'wollt', 'möchte', 'möchten',
    'möchtest', 'möchtet', 'moechte', 'chunnt', 'chunsch', 'chömed', 'chömmed', 'chum', 'chumm', 'wirsch', 'wött',
    'wötsch', 'wönd', 'wänd', 'möcht', 'gömmer', 'gömer', 'gönd',
    'll', 'shall', 'going', 'gonna', 'coming', 'upcoming', 'plan', 'plans', 'planning', 'planned', 'book', 'booked',
    'plane', 'planen', 'planst', 'plant', 'geplant', 'vorgehabt', 'gebucht', 'reserviert', 'reserved', 'abgemacht',
    'ausgemacht', 'verabredet', 'abgesagt', 'cancelled', 'canceled', 'verschoben', 'postponed', 'rescheduled',
    'gesagt', 'said', 'told', 'gefragt', 'asked', 'gemeint', 'meant', 'gedacht', 'thought', 'wollte', 'wollten',
    'wanted', 'sollte', 'sollten', 'should', 'eingeladen', 'invited', 'angemeldet', 'registered', 'zugesagt',
    'bestätigt', 'confirmed', 'versprochen', 'promised'))

# a mail client's quote header: the quoted message's date is in it (Gmail de/en/fr/it/es, Apple Mail, Outlook)
QUOTE_HEAD = re.compile(r'^[\s>]*(?:(?:am|on|le|il|el)\b.{0,200}?\b(?:schrieb|wrote|a écrit|ha scritto|escribió)\b'
                        r'|(?:gesendet|sent|date|datum|envoyé)\s*:)', re.I)


def quote_date(line, ref):
    """A quote header ("Am Di., 13. Okt. 2026 um 11:04 Uhr schrieb …:", "On Tue, Oct 13, 2026 at 11:04 AM … wrote:",
    Outlook's "Gesendet: Dienstag, 13. Oktober 2026 11:04") -> 'YYYY-MM-DD HH:MM' of the quoted message, else None.
    Only an explicit date counts (a year or d.m.), at most 400 days before the mail and not after it."""
    if not line or ref is None or not QUOTE_HEAD.match(line):
        return None
    head = re.sub(r'^[\s>]*', '', line)
    if not re.search(r'(?<!\d)(?:19|20)\d\d(?!\d)|(?<![\d.])\d{1,2}\.\d{1,2}\.', head):
        return None
    d = resolve_date(head, ref)
    if d is None or not ref - dt.timedelta(days=400) <= d <= ref + dt.timedelta(days=1):
        return None
    m = re.search(r'(?<!\d)(\d{1,2})[:.](\d{2})(?!\d)\s*([ap]\.?m\.?)?', head, re.I)
    hh, mm = (int(m[1]), int(m[2])) if m and int(m[1]) < 24 and int(m[2]) < 60 else (12, 0)
    if m and m[3] and hh < 12 and m[3][0].lower() == 'p':
        hh += 12
    return f'{d.isoformat()} {hh:02d}:{mm:02d}'


def mail_msgs(d, size=None):
    """A mail (Gmail.anon_doc: text, ts, from, ref) -> messages [{ts, sender, text, ref}] for the facts and answer
    checks: whole paragraphs packed up to `size`. A quoted message (after its quote header) gets messages of its own
    with ITS date, so relative dates in it count from the day it was written (a live case: "Termin für morgen",
    written 13.10 and quoted in a reply of 14.10, is the 14th)."""
    size = size or CHUNK_CHARS
    ts = V.now_iso(d['ts'])[:16].replace('T', ' ') if d.get('ts') else '2000-01-01 00:00'
    ref = msg_date(ts)
    lines = (d.get('text') or '').split('\n')
    segs, cur_ts, buf = [], ts, []
    for i, line in enumerate(lines):
        q = quote_date(line, ref)
        if q is None and i + 1 < len(lines) and not QUOTE_HEAD.match(lines[i + 1]):
            q = quote_date(line + ' ' + lines[i + 1], ref)            # a header wrapped onto two lines
        if q is not None:
            segs.append((cur_ts, buf))
            cur_ts, buf = q, []
        buf.append(line)
    segs.append((cur_ts, buf))
    msgs = []
    for sts, seg in segs:
        cur = ''
        for p in (p for p in re.split(r'\n\s*\n', '\n'.join(seg)) if p.strip()):
            if cur and len(cur) + len(p) > size - 200:
                msgs.append({'ts': sts, 'sender': d['from'], 'text': cur, 'ref': d['ref']})
                cur = ''
            cur = (cur + '\n' + p) if cur else p
        if cur:
            msgs.append({'ts': sts, 'sender': d['from'], 'text': cur, 'ref': d['ref']})
    return msgs


def norm_time(text):
    """A time as written ("18:00", "18.30", "20 Uhr", "8pm", "um 19h") -> "HH:MM", or None (e.g. Swiss "am 4i":
    the text stays as written in *_text)."""
    t = ' '.join(str(text or '').casefold().split())
    m = re.search(r'(?<![\d.:])([01]?\d|2[0-3])[:.h]([0-5]\d)(?!\d)', t)
    if m:
        return f'{int(m[1]):02d}:{m[2]}'
    m = re.search(r'(?<![\d.:])(1[0-2]|0?[1-9])(?::([0-5]\d))?\s*(am|pm)(?![a-z])', t)
    if m:
        h = int(m[1]) % 12 + (12 if m[3] == 'pm' else 0)
        return f'{h:02d}:{m[2] or "00"}'
    m = re.search(r'(?<![\d.:])([01]?\d|2[0-3])\s*(?:uhr|h)(?![a-z])', t)
    if m:
        return f'{int(m[1]):02d}:00'
    return None


def msg_date(ts):
    """'2026-10-10 18:02' (tgread's Europe/Zurich time) -> dt.date."""
    try:
        return dt.date.fromisoformat(str(ts)[:10])
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ messages
def parse_log(text):
    """tgread's anonymized output -> (chat label or None, [{ts, sender, text, ref}]). Lines: '[2026-10-10 18:02]
    Anna: text [photo] (#123 reply to #120)'; continuation lines are indented by 4 spaces; '### label (type, chat
    ID)' heads a chat."""
    chat, msgs, cur = None, [], None
    for line in (text or '').split('\n'):
        if line.startswith('### '):
            m = HEAD_RE.match(line)
            if m and chat is None:
                chat = m.group(1).strip()
            cur = None
            continue
        m = LINE_RE.match(line)
        if m:
            cur = {'ts': m.group(1), 'sender': m.group(2).strip(), 'text': m.group(3), 'ref': None}
            msgs.append(cur)
        elif cur is not None and line.startswith('    '):
            cur['text'] += '\n' + line[4:]
        else:
            cur = None
    for x in msgs:
        r = REF_TAIL.search(x['text'])
        if r:
            x['ref'] = f'#{r.group(1)}'
            x['text'] = x['text'][:r.start()]
        x['text'] = x['text'].strip()
    return chat, msgs


def chunks(msgs, size=CHUNK_CHARS):
    """Messages (oldest first) -> parts of whole days where it fits: a part ends at a day change once it is half
    full, and at any message once it is full."""
    parts, cur, n = [], [], 0
    for m in msgs:
        ln = len(m['sender']) + min(len(m['text']), MSG_CHARS) + 24
        if cur and (n + ln > size or (n >= size // 2 and m['ts'][:10] != cur[-1]['ts'][:10])):
            parts.append(cur)
            cur, n = [], 0
        cur.append(m)
        n += ln
    if cur:
        parts.append(cur)
    return parts


def render(part):
    return '\n'.join(f"[m{i}] {m['ts']} {m['sender']}: {' '.join(m['text'].split())[:MSG_CHARS]}"
                     for i, m in enumerate(part, 1))


# ------------------------------------------------------------------------------------------------ checks
class Check:
    """The model's answer for one part -> grounded, capped facts (refs as the messages' own refs) + drop counts."""

    def __init__(self, part, net):
        self.part, self.net = part, net
        bodies = [f"{m['sender']}: {m['text']}" for m in part]
        self.g_all = Grounding('\n'.join(bodies))
        self.g_msg = [Grounding(b) for b in bodies]
        self.w_msg = [set(words(b)) for b in bodies]
        self.w_all = set().union(*self.w_msg) if self.w_msg else set()
        self.why = {}

    def drop(self, field):
        self.why[field] = self.why.get(field, 0) + 1

    def clean(self, v):
        if not isinstance(v, str):
            return None
        v = V.clean_text(v, 400)
        if not v or len(v) > MAX_LEN or not WORD.search(PLACEHOLDER.sub(' ', v)):
            return None                                  # empty, too long or only placeholders
        return v

    def exact(self, field, v):
        """A name, date, time, venue or address: written in the text as is (token by token)."""
        if v in (None, '', []):
            return None
        c = self.clean(v)
        if c is None or not self.g_all.has(c):
            self.drop(field)
            return None
        return c

    def subset(self, field, v):
        """A short description: every word (glue words aside) is in the text."""
        if v in (None, ''):
            return None
        c = self.clean(v)
        ws = [w for w in words(c)] if c else []
        if c is None or len(ws) > 14 or not [w for w in ws if w not in GLUE] \
                or any(w not in self.w_all for w in ws if w not in GLUE):
            self.drop(field)
            return None
        return c

    def person(self, field, v):
        """A person as written in the text; an honorific + surname ("Herr Huber") -> "someone"."""
        c = self.exact(field, v)
        if c and has_honor(c):
            self.drop('honorific')
            return 'someone'
        return c

    def place(self, field, v):
        """A venue/address/place as written in the text, minus any honorific + surname (nothing left -> None)."""
        c = self.exact(field, v)
        if c and HONOR.search(c):
            self.drop('honorific')
            return place_unhonor(c)
        return c

    def refs(self, cited, anchors):
        """Cited message numbers -> indexes; if none of them holds the anchor words, the messages that do (<= 3)."""
        n = len(self.part)
        idx = []
        for i in cited if isinstance(cited, list) else [cited]:
            if isinstance(i, str) and re.fullmatch(r'm?\d{1,4}', i.strip()):
                i = int(i.strip().lstrip('m'))
            if isinstance(i, int) and not isinstance(i, bool) and 1 <= i <= n and i - 1 not in idx:
                idx.append(i - 1)
        want = {w for a in anchors if a for w in words(a) if w not in GLUE}
        if not want:
            return idx[:MAX_REFS]

        def score(i):
            return len(want & self.w_msg[i])
        if idx and max(score(i) for i in idx) > 0:
            return [i for i in idx if score(i) > 0][:MAX_REFS]
        best = max((score(i) for i in range(n)), default=0)
        if best == 0:
            return idx[:MAX_REFS]
        if idx:
            self.drop('refs')                            # cited the wrong messages: replaced
        return [i for i in range(n) if score(i) == best][:3]

    def ref_msg(self, idx, text):
        """The message a relative date counts from: the cited one that holds it, else the first cited one, else the
        part's last message."""
        cands = [i for i in idx if text and self.g_msg[i].has(text)] or idx or [len(self.part) - 1]
        return self.part[cands[0]]

    def ref_day(self, idx, text):
        return msg_date(self.ref_msg(idx, text)['ts'])

    def resolve(self, idx, text):
        """A quoted date -> dt.date, counted from its message, whose words around the quote give the tense."""
        m = self.ref_msg(idx, text)
        return resolve_date(text, msg_date(m['ts']), context=m.get('text'))

    def item(self, kind, it):
        if not isinstance(it, dict):
            self.drop(kind)
            return None
        main = 'name' if kind == 'places' else 'what'
        out = {}
        if kind == 'places':
            out['name'] = self.place('name', it.get('name'))
        else:
            out['what'] = unhonor(self.subset('what', it.get('what')))
        if not out[main]:
            return None
        if 'address' in FIELDS[kind]:
            out['address'] = self.place('address', it.get('address'))
        if kind == 'events':
            for f in ('date', 'start', 'end'):
                out[f] = self.exact(f, it.get(f))
            out['venue'] = self.place('venue', it.get('venue'))
            st = it.get('status')
            if isinstance(st, str) and st.strip().lower() in STATUS:
                out['status'] = st.strip().lower()
            elif st not in (None, ''):
                self.drop('status')
            who = it.get('who')
            names = []
            for w in (who if isinstance(who, list) else [who] if who else [])[:MAX_WHO * 2]:
                c = self.person('who', w)
                if c and c not in names:
                    names.append(c)
            out['who'] = names[:MAX_WHO]
        elif kind in ('todos', 'questions'):
            w = it.get('who')
            out['who'] = self.person('who', w[0] if isinstance(w, list) and w else w if isinstance(w, str) else None)
        if kind == 'todos':
            out['due'] = self.exact('due', it.get('due'))
        idx = self.refs(it.get('msgs', it.get('refs')), [out[main], out.get('date'), out.get('due'),
                                                          out.get('venue')])
        for f, src in (('date', 'date'), ('due', 'due')):
            if out.get(src):
                text = out[src]
                d = self.resolve(idx, text)
                out[f + '_text'], out[f] = text, (d.isoformat() if d else None)
        for f in ('start', 'end'):
            if out.get(f):
                out[f + '_text'], out[f] = out[f], norm_time(out[f])
        out['refs'] = list(dict.fromkeys(self.part[i]['ref'] for i in idx if self.part[i].get('ref')))
        return self.netted(out)

    def netted(self, out):
        """The regex net (mail: + the money net) on every value; empty fields left out."""
        res = {}
        for k, v in out.items():
            if isinstance(v, list):
                v = [self.net(x) if isinstance(x, str) and k != 'refs' else x for x in v]
                if v:
                    res[k] = v
            elif isinstance(v, str):
                res[k] = v if k in ('date', 'due', 'start', 'end', 'status') else self.net(v)
            elif v is not None:
                res[k] = v
        return res

    def run(self, llm):
        facts = {k: [] for k in KINDS}
        if not isinstance(llm, dict):
            raise VaultError('the local LLM gave no JSON object for the facts', 502, 'facts_failed')
        for kind in KINDS:
            items = llm.get(kind)
            if items in (None, ''):
                continue
            if not isinstance(items, list):
                self.drop(kind)
                continue
            if len(items) > PART_MAX:
                self.why[kind] = self.why.get(kind, 0) + len(items) - PART_MAX
            for it in items[:PART_MAX]:
                x = self.item(kind, it)
                if x:
                    facts[kind].append(x)
        return facts


def dedupe(facts):
    """Merge the parts: the same fact (kind, words of what/name, date) once, refs joined; capped per kind."""
    out = {}
    for kind in KINDS:
        seen, keep = {}, []
        for x in facts.get(kind) or []:
            key = (fold(x.get('what') or x.get('name')), x.get('date') or x.get('due') or x.get('date_text') or '')
            if key in seen:
                y = seen[key]
                for r in x.get('refs') or []:
                    if r not in y.setdefault('refs', []) and len(y['refs']) < MAX_REFS * 2:
                        y['refs'].append(r)
                for f, v in x.items():
                    y.setdefault(f, v)
                continue
            seen[key] = x
            keep.append(x)
        out[kind] = keep[:MAX_PER_KIND[kind]]
    return out


# ------------------------------------------------------------------------------------------------ the extractor
class Facts:
    def __init__(self, cfg, policy, gate, audit, model='', tg=None, gmail=None, clock=time.time):
        self.cfg, self.policy, self.gate, self.audit, self.model = cfg, policy, gate, audit, model
        self.tg, self.gmail, self.clock = tg, gmail, clock
        self.cache_dir = Path(cfg.state) / 'facts-cache'
        self.run_json = self._run_json                   # tests swap in a spy

    # -------------------------------------------------------------- model + cache
    def _run_json(self, text, cls, what):
        with self.gate.lease(private=True, what=what, timeout=900, cls=cls):
            return self.policy.run_llm(['--system', SYSTEM, '--json', '--temp', '0', '--max-tokens', '1800'], text,
                                       timeout=900)

    def cache_key(self, source, text, refs):
        blob = json.dumps([FACTS_VERSION, V.POLICY_VERSION, self.model, source, text, refs], ensure_ascii=False)
        return hashlib.sha256(blob.encode('utf-8')).hexdigest()

    def cache_get(self, k):
        p = self.cache_dir / k[:2] / f'{k}.json'
        try:
            if time.time() - p.stat().st_mtime > CACHE_DAYS * 86400:
                p.unlink()
                return None
            d = json.loads(p.read_text('utf-8'))
            return d if isinstance(d, dict) and isinstance(d.get('facts'), dict) else None
        except (OSError, ValueError):
            return None

    def cache_put(self, k, res):
        try:
            V.ensure_dir(self.cache_dir)
            V.write_private(self.cache_dir / k[:2] / f'{k}.json', json.dumps(res, ensure_ascii=False))
            if os.urandom(1)[0] < 8:                   # now and then: drop entries older than CACHE_DAYS
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

    # -------------------------------------------------------------- core
    def extract(self, msgs, source, cls='bulk', mail=False, report=None):
        """Anonymized messages [{ts, sender, text, ref}] -> (facts, why, parts, cached). Raises on an LLM failure:
        nothing partial."""
        net = (lambda s: self.policy.money_net(self.policy.regex_net(s))) if mail else self.policy.regex_net
        parts = chunks(msgs)
        merged, why, cached = {k: [] for k in KINDS}, {}, 0
        for n, part in enumerate(parts, 1):
            if report:
                report('progress', done=n - 1, total=len(parts), step=f'facts part {n}/{len(parts)}')
            text = render(part)
            k = self.cache_key(source, text, [m.get('ref') for m in part])
            res = self.cache_get(k)
            if res is None:
                out = self.run_json(text, cls, f'facts ({source}, part {n}/{len(parts)})')
                try:
                    llm = json.loads(out)
                except (TypeError, ValueError):
                    raise VaultError('the local LLM gave no usable JSON for the facts; nothing returned', 502,
                                     'facts_failed')
                ck = Check(part, net)
                res = {'facts': ck.run(llm), 'why': ck.why}
                self.cache_put(k, res)
            else:
                cached += 1
            for kind in KINDS:
                merged[kind] += res['facts'].get(kind) or []
            for f, c in (res.get('why') or {}).items():
                why[f] = why.get(f, 0) + int(c)
        if report:
            report('progress', done=len(parts), total=len(parts), step='facts done')
        return dedupe(merged), why, len(parts), cached

    def _result(self, head, facts, why, parts, cached, mail=False):
        net = (lambda s: self.policy.money_net(self.policy.regex_net(s))) if mail else self.policy.regex_net
        out = dict(head)
        for kind in KINDS:                              # the regex net once more on what leaves (G2)
            out[kind] = [{f: (net(v) if isinstance(v, str) and f not in ('date', 'due', 'start', 'end', 'status')
                              else [net(x) if isinstance(x, str) and f != 'refs' else x for x in v]
                              if isinstance(v, list) else v) for f, v in x.items()} for x in facts[kind]]
        out.update(parts=parts, cached_parts=cached, dropped=sum(why.values()), note=NOTE)
        if why:
            out['dropped_fields'] = dict(sorted(why.items()))
        return out

    # -------------------------------------------------------------- sources
    def tg_facts(self, b, report=None):
        b = b or {}
        chat, since, n = b.get('chat'), b.get('since') or '60d', b.get('n', 400)
        if not (isinstance(chat, str) and 0 < len(chat.strip()) <= 200 and '\n' not in chat):
            raise VaultError('chat is required: a chat id, alias or name (vault tg find-chat)', 400, 'bad_param')
        if not (isinstance(since, str) and re.fullmatch(r'\d{1,4}[mhdw]|\d{4}-\d{2}-\d{2}', since.strip())):
            raise VaultError('since: e.g. 60d, 12w or 2026-09-01', 400, 'bad_param')
        if not (isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= 500):
            raise VaultError('n must be 1..500 (the newest messages of the window)', 400, 'bad_param')
        if report:
            report('progress', done=0, total=0, step='anonymizing the chat')
        out = self.tg.anon_messages(chat.strip(), since.strip(), n)
        label, msgs = parse_log(out)
        head = {'source': 'telegram', 'chat': self.policy.regex_net(V.clean_text(label or chat, 100)),
                'since': since.strip(), 'messages': len(msgs)}
        if not msgs:
            return self._result(head, {k: [] for k in KINDS}, {}, 0, 0)
        facts, why, parts, cached = self.extract(msgs, 'telegram', cls='bulk', report=report)
        self.audit.log('facts', source='telegram', chat=chat, since=since, messages=len(msgs), parts=parts,
                       cached=cached, kept=sum(len(v) for v in facts.values()), dropped=sum(why.values()))
        return self._result(head, facts, why, parts, cached)

    def gmail_facts(self, b, report=None):
        b = b or {}
        ref = b.get('uid') or b.get('ref')
        chars = b.get('chars', 8000)
        if not (isinstance(chars, int) and not isinstance(chars, bool) and 500 <= chars <= 30000):
            raise VaultError('chars must be 500..30000', 400, 'bad_param')
        if report:
            report('progress', done=0, total=0, step='anonymizing the mail')
        d = self.gmail.anon_doc(ref, b.get('folder'), chars, b.get('account'))
        msgs = mail_msgs(d)                              # long mails: whole paragraphs; quotes keep their own date
        head = {'source': 'gmail', 'ref': d['ref'], 'account': d['account'], 'date': V.now_iso(d['ts']) if d.get('ts')
                else None, 'from': d['from']}
        facts, why, parts, cached = self.extract(msgs, 'gmail', cls='bulk', mail=True, report=report)
        self.audit.log('facts', source='gmail', ref=d['ref'], parts=parts, cached=cached,
                       kept=sum(len(v) for v in facts.values()), dropped=sum(why.values()))
        return self._result(head, facts, why, parts, cached, mail=True)

    # -------------------------------------------------------------- event feed (plan v2 #11)
    def for_events(self, items, source):
        """Surfaced plan/appointment/deadline items of one feed batch: [{ts, sender, text}] with text = the item's
        anonymized, NOT paraphrased wording -> {item index: [fact, ...]} (kind + fields, no refs). ONE background
        call for the batch (a cached part costs none). Raises on an LLM failure (the caller stores the events
        without facts)."""
        msgs = []
        for n, it in enumerate(items):
            text = str(it.get('text') or '')
            m = LINE_RE.match(text.split('\n')[0]) if text else None
            if m:                                        # Telegram lines carry "[time] Sender: " already
                _, one = parse_log(text)
                body = one[0]['text'] if one else m.group(3)
                sender = m.group(2).strip()
            else:
                body, sender = text, str(it.get('sender') or '?')
            if source == 'gmail' and body.strip():      # a quoted mail keeps its own date
                msgs += mail_msgs({'text': body.strip(), 'ts': it.get('ts'), 'from': V.clean_text(sender, 60),
                                   'ref': f'i{n}'})
                continue
            ts = V.now_iso(it['ts'])[:16].replace('T', ' ') if it.get('ts') else '2000-01-01 00:00'
            msgs.append({'ts': ts, 'sender': V.clean_text(sender, 60), 'text': body.strip(), 'ref': f'i{n}'})
        facts, why, parts, cached = self.extract(msgs, f'events-{source}', cls='background', mail=source == 'gmail')
        out = {}
        for kind in KINDS:
            for x in facts[kind]:
                refs = [r for r in x.get('refs') or [] if re.fullmatch(r'i\d+', str(r))]
                if not refs:
                    continue
                y = {f: v for f, v in x.items() if f != 'refs'}
                y['kind'] = kind[:-1] if kind.endswith('s') else kind
                out.setdefault(int(refs[0][1:]), []).append(y)
        return out

    def plans(self, store, days=14, now=None):
        """GET /plans: the dated facts (events by date, to-dos by due date) of the event feed in [today, today +
        days], duplicates merged, sorted by date and time."""
        now = self.clock() if now is None else now
        today = dt.datetime.fromtimestamp(now, V.TZ).date()
        end = today + dt.timedelta(days=days)
        net = self.policy.regex_net
        out = []
        for r in store.with_facts(now - store.KEEP_DAYS * 86400):
            try:
                fs = json.loads(r['facts'])
            except (TypeError, ValueError):
                continue
            for f in fs if isinstance(fs, list) else []:
                if not isinstance(f, dict) or f.get('kind') not in ('event', 'todo'):
                    continue
                d = f.get('date') if f['kind'] == 'event' else f.get('due')
                try:
                    day = dt.date.fromisoformat(str(d))
                except ValueError:
                    continue
                if not today <= day <= end or f.get('status') == 'cancelled':
                    continue
                p = {'date': day.isoformat(), 'weekday': day.strftime('%a'), 'kind': f['kind'],
                     'what': net(f.get('what') or ''), 'source': r['source'], 'chat': net(r['chat'] or ''),
                     'chat_key': r['chat_key'], 'ref': r['ref'], 'cursor': r['cursor']}
                for k in ('start', 'end', 'venue', 'address', 'status', 'date_text', 'due_text', 'start_text'):
                    if f.get(k):
                        p[k] = f[k] if k in ('start', 'end', 'status') else net(f[k])
                if r.get('account'):
                    p['account'] = r['account']
                dup = next((q for q in out if q['date'] == p['date'] and (
                    fold(q['what']) == fold(p['what'])
                    or (p.get('start') and q.get('start') == p.get('start') and p.get('venue')
                        and fold(q.get('venue')) == fold(p.get('venue'))))), None)
                if dup:
                    dup['mentions'] = dup.get('mentions', 1) + 1
                    for k, v in p.items():
                        dup.setdefault(k, v)
                    continue
                out.append(p)
        out.sort(key=lambda p: (p['date'], p.get('start') or '99:99', p['what']))
        return {'days': days, 'from': today.isoformat(), 'to': end.isoformat(), 'count': len(out), 'plans': out,
                'note': 'dated facts of the event feed (last 7 days of messages); anonymized; check the calendar '
                        'for duplicates before adding'}
