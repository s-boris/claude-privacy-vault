#!/usr/bin/python3 -I
"""planted.py MODE FILE: verify llm-local output for the synthetic chat (chat150.tmpl, 165 lines).
  check-anon            default policy v2: identifiers gone; the 5 planted private passages replaced by
                        "[private: <right category>]" with the rest of their message kept; first names, addresses,
                        facts and unattached surnames verbatim; surnames of people attached to private passages
                        masked; no Person aliases; owner -> You; 165 lines
  check-strict          --strict: like the old policy (names aliased, address gone) plus the private passages
  check-summary         summary of the default mode: no identifiers, no private details, key facts present;
                        policy v3: no price of a bigger purchase (headphones 279), small everyday costs
                        optional (WARN when missing)
  check-summary-strict  summary of --strict: also no real names
  check-money policy v3, fixtures/money.txt (owner Nico): the owner's investment, salary,
                        bulk purchase and a business deal -> [private: money|business] (or at least every figure and
                        detail gone); the meeting time, the trip, the bill due date and a cinema debt stay verbatim
  check-money-summary   summary of fixtures/money.txt: no money/business figures or details, the plans present
Prints a report; exit 0 if all hard checks pass (WARN lines are soft). Secret-looking values are built at runtime."""
import sys; sys.dont_write_bytecode = True
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render

CARD = render.VALUES["{{TEST_CARD}}"]
LINES = 165
# identifiers: must NOT appear in any mode
IDENTIFIERS = [
    ("phone 1", r"79\s?123\s?45\s?67"), ("phone 2", r"765\s?43\s?21"), ("phone 3", r"76\s?555\s?12\s?34"),
    ("IBAN", r"CH93|6238\s?5295"), ("AHV", r"756\.1234"), ("card", re.escape(CARD) + "|" + CARD.replace(" ", "")),
    ("email", r"lena\.brunner92|@gmail"), ("birthdate", r"1996"), ("plate", r"ZH\s?123\s?456"),
    ("drive token", r"1Qz8xK3vT9mPa2LwR7bN4cYd6E"), ("airbnb share id", r"f3a9c2e1"),
]
# names and the home address: must NOT appear with --strict
STRICT_ONLY = [
    ("name Marco", r"\bMarco\b"), ("name Lena", r"\bLena\b"), ("name Jonas", r"\bJonas\b"), ("name Ali", r"\bAli\b"),
    ("name Sophie", r"\bSophie"), ("name Nico", r"\bNico\b"), ("surname Keller", r"\bKeller\b"),
    ("surname Brunner", r"\bBrunner\b"), ("surname Weber", r"\bWeber\b"), ("surname Demir", r"\bDemir\b"),
    ("surname Huber", r"\bHuber\b"), ("surname Frei", r"\bFrei\b"), ("address", r"Seefeldstrasse|8008"),
]
# the planted private passages: (line prefix, label, details that must be gone, right categories,
# acceptable-but-not-ideal categories (WARN), part of the same message that must survive or None)
PRIVATE = [
    ("[2026-10-11 14:30] ", "health (Swiss German)", [r"Diabetes", r"Insulin", r"Arzt"], {"health"}, set(),
     "Am Samstig bin i aber trotzdem debi!"),
    ("[2026-10-11 16:40] ", "breakup (German)", [r"Schluss gemacht", r"betrogen", r"Sarah"], {"relationship"},
     {"dating"}, "Zum Fussball komme ich aber trotzdem."),
    ("[2026-10-11 19:35] ", "dating detail (English)", [r"Tinder", r"spending the night"], {"dating"}, {"sexual"},
     "see you all at the party!"),
    ("[2026-10-12 09:22] ", "debt (Swiss German)", [r"9000", r"Schulde", r"Betreibigsamt", r"Tobias"], {"money"},
     {"confidential", "gossip"}, None),
    ("[2026-10-12 20:25] ", "mental health (English, by the owner)", [r"anxiety", r"panic", r"therapy"],
     {"mental health"}, {"health"}, "looking forward to Saturday!"),
]
# non-private facts that must survive verbatim (all modes)
FACTS_ANON = ["18.10.", "19:00", "279.-", "35.-", "Mittwuch 15.10.", "1450.-", "290.-", "Freitag 17.10. um 12:00",
              "Donnerstag 16.10. um 19:00 auf der Sportanlage Juchhof", "Klangwerk Festival", "89.- pro Ticket",
              "du schuldsch mir no 23.50 vom Pizza", "362.50", "Confiserie Sprüngli", "17:30", "16.–18. Januar 2027",
              "Laax", "Winterthur", "Bose QuietComfort", "TWINT", "Hardbrücke", "Langstrasse", "frei neh",
              "Benzin und Vignette dur 4", "Ich säg ihre mir gönd nur zu zweit es Bier go trinke",
              "sie söll nüt merke", "exam on Jan 19", "that party yesterday was too much"]
# default mode: must survive verbatim (names, addresses, venues, an unattached surname)
KEEP_V2 = ["Marco", "Lena", "Jonas", "Ali", "Sophie", "Seefeldstrasse 112, 8008 Zürich", "Herr Huber",
           "Herrn Huber", "Frau Gerolds Garten", "Geroldstrasse", "@You du hesch"]
SOFT_V2 = ["good dentist in Zurich", "Dr. Frei am Limmatquai", "Ich brauch auch mal wieder einen Termin"]
# writers of private passages: surname masked everywhere in the default mode
ATTACHED_SURNAMES = ["Brunner", "Weber", "Demir", "Keller"]
SOFT_STRICT = ["Frau Gerolds Garten"]
# facts a good summary contains (regex, case-insensitive)
FACTS_SUMMARY = [("party Sat 18 Oct 19:00", r"(18\.?\s?(10|oct)|oct\w*\.? 18).{0,80}19[:.]00|19[:.]00.{0,80}(18\.?\s?(10|oct)|oct\w*\.? 18)"),
                 ("ski Laax 16-18 Jan", r"laax"),
                 ("ski deadline Fri 17 Oct 12:00", r"17.{0,40}12[:.]00|12[:.]00.{0,40}17"),
                 ("football Thu 16 Oct 19:00 Juchhof", r"juchhof"),
                 ("cake pickup 17:30 (You)", r"17[:.]30"), ("speaker (You)", r"speaker|box|jbl")]
# policy v3 (13.10): small everyday costs "may be mentioned" (missing = WARN); a bigger purchase's price never
SOFT_FACTS_SUMMARY = [("gift 35 each", r"\b35\b"), ("festival 89", r"\b89\b"), ("pizza 23.50", r"23\.50")]
ABSENT_SUMMARY = [("headphones price 279 (a bigger purchase)", r"(?<![\d#.'])279(?![\d])")]
PLACEHOLDER = re.compile(r"\[private: ([a-z ,]+)\]")
# policy v3: (line prefix, label, details that must be gone, right categories, part of the message to keep or None)
MONEY_LINES = 9
MONEY = [("[2026-10-13 18:01] ", "investment plan (German)", [r"25.?000", r"Tranche", r"MSCI"], {"money", "business"},
          None),
         ("[2026-10-13 18:03] ", "salary (Swiss German)", [r"11.?200", r"Lohn"], {"money"}, "Mittwuch passt."),
         ("[2026-10-13 18:04] ", "bulk purchase (English)", [r"6.?400", r"booster", r"resell"], {"business", "money"},
          None),
         ("[2026-10-13 18:05] ", "business deal (Swiss German)", [r"18.?000", r"Garage Meier", r"Website"],
          {"business", "money"}, None)]
MONEY_KEEP = ["Mittwuch 19:00 im Minimum", "Team-Meeting am Dienstag 21.10. um 14:00 im Büro an der Hardturmstrasse",
              "Zug nach Lugano am Samstag 25.10. um 08:32", "Die Swisscom-Rechnung ist am 30.10. fällig",
              "18.- fürs Kino"]
MONEY_SUMMARY_FACTS = [("climbing Wed 19:00", r"19[:.]00"), ("meeting Tue 21.10. 14:00", r"14[:.]00"),
                       ("trip to Lugano", r"lugano"), ("bill due 30.10.", r"30\.?\s?(10|oct)|oct\w*\.? 30")]


def check_money(out, summary, fails, warns, notes):
    lines = out.splitlines()
    for prefix, label, gone, right, keep in MONEY:
        hay = out if summary else next((l for l in lines if l.startswith(prefix)), None)
        if hay is None:
            fails.append("money %s: line %s missing" % (label, prefix.strip()))
            continue
        for rx in gone:
            if re.search(rx, hay, re.I):
                fails.append("money %s: detail not redacted (%s)" % (label, rx))
        if summary:
            continue
        cats = {c.strip() for m in PLACEHOLDER.finditer(hay) for c in m.group(1).split(",")}
        if cats & right:
            notes.append("money %s: [private: %s]" % (label, ", ".join(sorted(cats))))
        elif "[amount]" in hay or cats:
            warns.append("money %s: details gone, but placeholder %s" % (label, ", ".join(sorted(cats)) or "[amount]"))
        if keep and keep not in hay:
            fails.append("money %s: the rest of the message was not kept (%r)" % (label, keep))
    if summary:
        for label, rx in MONEY_SUMMARY_FACTS:
            if not re.search(rx, out, re.I | re.S):
                fails.append("summary misses: " + label)
        return
    if len([l for l in lines if l.strip()]) != MONEY_LINES:
        fails.append("line count != %d" % MONEY_LINES)
    for f in MONEY_KEEP:
        if f not in out:
            fails.append("fact lost: " + f)
    if not re.search(r"\] You: ", out):
        fails.append("owner not shown as You")


def check_private(out, fails, warns, notes):
    lines = out.splitlines()
    planted = set()
    for prefix, label, gone, right, close, keep in PRIVATE:
        line = next((l for l in lines if l.startswith(prefix)), None)
        if line is None:
            fails.append("private %s: line %s missing" % (label, prefix.strip()))
            continue
        planted.add(prefix)
        for rx in gone:
            if re.search(rx, line):
                fails.append("private %s: detail not redacted (%s)" % (label, rx))
        cats = {c.strip() for m in PLACEHOLDER.finditer(line) for c in m.group(1).split(",")}
        if not cats:
            fails.append("private %s: no [private: ...] placeholder" % label)
        elif cats & right:
            notes.append("private %s: [private: %s]" % (label, ", ".join(sorted(cats))))
        elif cats & close:
            warns.append("private %s: category %s (expected %s)" % (label, ", ".join(sorted(cats)), "/".join(right)))
        else:
            fails.append("private %s: wrong category %s (expected %s)" % (label, ", ".join(sorted(cats)), "/".join(right)))
        if keep and keep not in line:
            fails.append("private %s: the rest of the message was not kept (%r)" % (label, keep))
    extra = [l for l in lines if PLACEHOLDER.search(l) and not any(l.startswith(p) for p in planted)]
    for l in extra:
        warns.append("extra redaction (not planted): " + l[:150])
    return len(extra)


def main():
    mode, path = sys.argv[1], sys.argv[2]
    out = open(path, encoding="utf-8").read()
    fails, warns, notes = [], [], []
    strict = mode in ("check-strict", "check-summary-strict")
    if mode in ("check-money", "check-money-summary"):
        check_money(out, mode == "check-money-summary", fails, warns, notes)
        for n in notes:
            print("ok   " + n)
        for w in warns:
            print("WARN " + w)
        for f in fails:
            print("FAIL " + f)
        print("%s: %s (%d fails, %d warnings)" % (mode, "OK" if not fails else "FAILED", len(fails), len(warns)))
        sys.exit(1 if fails else 0)
    for label, rx in IDENTIFIERS + (STRICT_ONLY if strict else []):
        if re.search(rx, out):
            fails.append("PII leaked: " + label)
    if mode in ("check-anon", "check-strict"):
        lines = [l for l in out.splitlines() if l.strip()]
        if len(lines) != LINES:
            fails.append("line count %d != %d (messages dropped or merged)" % (len(lines), LINES))
        for f in FACTS_ANON:
            if f not in out:
                fails.append("fact lost: " + f)
        check_private(out, fails, warns, notes)
        if not re.search(r"\] You: ", out):
            fails.append("owner not shown as You")
        if strict:
            if not re.search(r"\] Person [A-Z]: ", out):
                fails.append("no Person aliases")
            for f in SOFT_STRICT:
                if f not in out:
                    warns.append("public venue over-redacted: " + f)
        else:
            if re.search(r"\bPerson [A-Z]\b", out):
                fails.append("Person aliases in the default mode (names must stay)")
            for f in KEEP_V2:
                if f not in out:
                    fails.append("name/address/venue lost: " + f)
            for s in ATTACHED_SURNAMES:
                if re.search(r"\b%s\b" % s, out):
                    fails.append("surname of a person attached to a private passage not masked: " + s)
            if "[surname]" not in out:
                fails.append("no [surname] placeholder")
            for f in SOFT_V2:
                if f not in out:
                    warns.append("over-redacted (soft): " + f)
    else:
        for prefix, label, gone, right, close, keep in PRIVATE:
            for rx in gone:
                if re.search(rx, out, re.I):
                    fails.append("summary mentions private detail of %s (%s)" % (label, rx))
        if not strict:
            for s in ATTACHED_SURNAMES:
                if re.search(r"\b%s\b" % s, out):
                    fails.append("summary has a masked surname: " + s)
        for label, rx in FACTS_SUMMARY:
            if not re.search(rx, out, re.I | re.S):
                fails.append("summary misses: " + label)
        for label, rx in SOFT_FACTS_SUMMARY:
            if not re.search(rx, out, re.I | re.S):
                warns.append("optional small cost missing: " + label)
        for label, rx in ABSENT_SUMMARY:
            if re.search(rx, out):
                fails.append("summary states the %s (policy v3: never)" % label)
    for n in notes:
        print("ok   " + n)
    for w in warns:
        print("WARN " + w)
    for f in fails:
        print("FAIL " + f)
    print("%s: %s (%d fails, %d warnings)" % (mode, "OK" if not fails else "FAILED", len(fails), len(warns)))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
