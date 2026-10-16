"""Swiss German paraphrase eval (policy v4.1): python3 -I swiss_eval.py LLM_LOCAL SOURCE OUTPUT -> one verdict per line.
Checks in code, per message: the facts listed in EXPECT (a time stays a time, the date stays, the negation stays), no
number used in another role (num_roles), a negated sentence keeps a negation, no translation into English, and no number
the source doesn't have. A '[not paraphrased]' line is the safe fallback: counted, never a failure. Exit 1 on a failure."""
import importlib.machinery
import importlib.util
import re
import sys

l = importlib.machinery.SourceFileLoader('llm', sys.argv[1])
s = importlib.util.spec_from_loader('llm', l)
m = importlib.util.module_from_spec(s)
l.exec_module(m)
# ref -> (any of these must be in the paraphrase, none of these may be)
EXPECT = {1: ([r'\b(nid|nöd|nicht|nicht mehr|nümme|nüme|nümm|nöme|kein\w*|not|no|no longer|cannot|can.t)\b'], [r'(?i)\bbooking is required\b']),
          2: ([r'(?i)\b(4i|vieri|4 ?uhr|um 4|am 4\b|16)'], [r'(?i)\b4(th|\.)', r'(?i)\bfourth\b']),
          3: ([r'(?i)halbi? ?5|4[:.]30|16[:.]30', r'(?i)samstig|samstag|saturday'], []),
          4: ([r'(?i)\b(nöd|nid|nicht|not)\b', r'(?i)17'], []),
          5: ([r'(?i)24\.? ?(oktober|okt|october|10\.)|24\.10', r'(?i)\b(vieri|4i|4 ?uhr|um 4|16)'], [r'(?i)\b4(th|\.)']),
          6: ([r'(?i)fritig|freitag|friday', r'(?i)\b2\b|\bzwei\b'], []),
          7: ([r'(?i)\b(kei\w*|kein\w*|no|not)\b', r'(?i)\b(um 8|8 ?uhr|8i|20)'], []),
          8: ([r'(?i)\b(nüt|nichts|nix|kein\w*|nothing|no)\b', r'22'], []),
          9: ([r'3\.11\.?'], []),
          10: ([r'(?i)\b(nie|niemals|never)\b', r'(?i)\b12\.'], []),
          11: ([r'(?i)\b(8i|8 ?uhr|ab 8|20)', r'(?i)zwölfi|12 ?uhr|\b12\b'], []),
          12: ([r'21\.11\.?', r'06[:.]15', r'(?i)\b(4i|vieri|4 ?uhr|um 4)'], [r'(?i)\b4(th|\.)'])}
LINE = re.compile(r'^\[[^\]]+\] (\w+): (.*?) \(#(\d+)\)\s*$')
src = {int(x.group(3)): x.group(2) for x in map(LINE.match, open(sys.argv[2], encoding='utf-8')) if x}
fails, kept, n = 0, 0, 0
for ln in open(sys.argv[3], encoding='utf-8'):
    x = LINE.match(ln.rstrip('\n'))
    if not x or int(x.group(3)) not in src:
        continue
    ref, out, n = int(x.group(3)), x.group(2), n + 1
    if out.startswith(m.PARA_MARK):
        kept += 1
        print(f'KEPT #{ref}: {out}')
        continue
    bad = (m.para_problems(src[ref], out) + m.role_problems(m.num_roles(src[ref]), out)
           + (['drops a negation'] if m.negations(out) < m.negations(src[ref], item=True) else [])
           + (['translated to English'] if m.text_lang(out) == 'en' else []))
    need, never = EXPECT.get(ref, ([], []))
    bad += [f'missing {rx}' for rx in need if not re.search(rx, out)]
    bad += [f'has {rx}' for rx in never if re.search(rx, out)]
    fails += bool(bad)
    print(f"{'BAD ' if bad else 'OK  '}#{ref}: {out}" + (f'  <- {sorted(set(bad))}' if bad else ''))
print(f'SWISS-EVAL lines={n} ok={n - kept - fails} kept_as_written={kept} failed={fails}')
sys.exit(1 if fails or n != len(src) else 0)
