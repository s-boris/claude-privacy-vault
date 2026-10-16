#!/usr/bin/env python3
"""public-gate: fail when a tracked file contains private data. Prints file:line + check id, never the value.

  python3 -I tools/public-gate.py [--root DIR] [--denylist FILE] [--allowlist FILE] [--ignore TERM]...
                                  [--no-substring] [--no-syntax] [--context] [--list-pii]

Checks
  1. denylist: one rule per line, `lit:TEXT` (case-sensitive), `i:TEXT` (any case) or `re:REGEX`; `allow:WORD`
     lines name harmless longer words that merely contain a term (for check 1b). Read from --denylist FILE or the
     PUBLIC_DENYLIST environment variable (a CI secret: the list is private and never committed). --ignore TERM
     blanks TERM first (e.g. the repo owner's public GitHub handle).
     Every file is checked twice: as is, and de-escaped (`\\n`, `\\b`, `\\t` -> space, `\\.` -> `.`, `[.]`, %2E,
     \\uXXXX and HTML entities decoded), so `"\\nTerm"` and `term\\.example` are caught too.
     1a. whole word (lit/i) or the regex as written; re: rules are also tried without their `\\b` anchors.
     1b. whole substring: lit/i terms also match inside longer words, any case (terms of 4 characters or less
         only at the start of a word or at a camelCase hump). A longer word that is listed as `allow:` is
         skipped (a short, reviewed list of harmless words).
  2. PII detectors: e-mail addresses, Swiss/Serbian/German mobile numbers, IBANs (mod-97 valid), AHV numbers
     (EAN-13 valid), RFC 1918 / CGNAT IPv4 addresses (also in regex form, `192\\.168\\.1\\.5`). Documentation
     domains, example values and the values in --allowlist (default tools/pii-allowlist.txt) are allowed.
  3. prose: the word owner followed by a date (a dated personal decision) in docs, comments and docstrings
     (and owner + comma + date, or a parenthesized owner OK + date, on any line), and owner + colon + quoted text in comments and docs. Personal quotes and decision logs don't belong in the public tree.
  4. syntax: every Python file (py_compile, in memory), shell script (bash -n / sh -n) and JavaScript file
     (node --check) must parse. Missing interpreters are reported on stderr and skipped.
.gz files are decompressed, PDFs go through pdftotext (missing pdftotext = a hit); other binaries are skipped.
--context adds the matched word with the private term masked as <#N> (for local review; never in CI logs).
Exit 0 clean, 1 hits, 2 usage error.
"""
import argparse
import gzip
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

EMAIL = re.compile(r"(?<![\w.+%\\-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[a-z]{2,24}\b")
EMAIL_OK_DOMAIN = re.compile(r"(?:^|\.)(?:example(?:\.(?:com|org|net|ch|de))?|test|invalid|localhost|local|"
                             r"users\.noreply\.github\.com|anthropic\.com)$")
PHONE = re.compile(r"(?<![\d.,])(?:(?:\+|00)41[ ]?(?:\(0\)[ ]?)?7[5-9]|07[5-9]|(?:\+|00)381[ ]?6\d|(?:\+|00)49[ ]?1[5-7]\d)"
                   r"(?:[ ]?\d){6,8}(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
AHV = re.compile(r"(?<![\d.])756\.?\d{4}\.?\d{4}\.?\d{2}(?!\d)")
IPV4 = re.compile(r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))"
                  r"\.\d{1,3}\.\d{1,3}(?![\d.])")
IP_OK = re.compile(r"^172\.17\.")                      # Docker's default bridge: the same on every host
DATE = r"(?:\d{4}-\d{2}-\d{2}|(?<![\w.])(?:[12]\d|3[01]|0?[1-9])\.(?:1[0-2]|0?[1-9])\.(?:\d{4}(?!\d)|\d{2}(?![\d.])|(?!\d))|(?<![\w.])(?:[12]\d|3[01]|0?[1-9])\.(?:1[0-2]|0?[1-9])(?![.\d]))"
DATED = re.compile(r"(?i)(?<![-\w])owner(?:'s)?\b[^\n\"“]{0,40}?" + DATE)
DATED_TIGHT = re.compile(r"(?i)(?<![-\w'\"])owner(?:'s)?,? (?:on )?" + DATE)      # owner + comma + date: any line
DATED_PAREN = re.compile(r"(?i)\((?:the )?owner(?:'s)?(?: OK| choice| decision| request)?,? (?:on )?" + DATE)
QUOTE = re.compile(r"(?i)\bowner(?:'s)?\b[^\"“\n]{0,25}?\s*:\s*[\"“][^\"”\n]{4,}[\"”]")
HASH_EXT = {".py", ".sh", ".yml", ".yaml", ".toml", ".in", ".example", ".conf", ".cfg", ".env", ""}
SLASH_EXT = {".js", ".mjs", ".cjs", ".ts", ".css"}
WORDCH = r"[^\W_]"


def norm(v):
    s = re.sub(r"[\s.\-()/]", "", v).lower()
    if s.startswith("+"):
        s = "00" + s[1:]
    for cc in ("0041", "00381", "0049"):
        if s.startswith(cc) and s[len(cc):].isdigit():
            s = "0" + s[len(cc):]
    return s


def iban_ok(v):
    s = v.replace(" ", "")
    if not 15 <= len(s) <= 34 or s.startswith("RF"):
        return False
    try:
        return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1
    except ValueError:
        return False


def ean13_ok(v):
    d = [int(c) for c in v if c.isdigit()]
    return len(d) == 13 and (10 - sum(x * (3 if i % 2 else 1) for i, x in enumerate(d[:12])) % 10) % 10 == d[12]


class Rule:
    def __init__(self, n, line):
        self.n, self.term, self.alt = n, None, None
        if line.startswith("re:"):
            self.rx = re.compile(line[3:])
            loose = line[3:].replace(r"\b", "")
            if loose != line[3:]:
                try:
                    self.alt = re.compile(loose)
                except re.error:
                    self.alt = None
            return
        ci = line.startswith("i:")
        lit = line[2:] if ci else (line[4:] if line.startswith("lit:") else line)
        self.rx = re.compile(r"(?<!" + WORDCH + ")" + re.escape(lit) + r"(?!" + WORDCH + ")", re.I if ci else 0)
        self.term = lit.lower()


def load_denylist(raw):
    rules, allow = [], set()
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("allow:"):
            allow.add(s[6:].strip().lower())
            continue
        rules.append(Rule(len(rules) + 1, s))
    return rules, allow


ESC = [(re.compile(r"\\u([0-9a-fA-F]{4})"), lambda m: chr(int(m.group(1), 16))),
       (re.compile(r"\\[nrtbfv0]"), lambda m: " "),
       (re.compile(r"\\([.\-/:@_ #&?=+])"), lambda m: m.group(1)),
       (re.compile(r"\[\.\]"), lambda m: "."),
       (re.compile(r"%2[eE]"), lambda m: "."),
       (re.compile(r"%20"), lambda m: " ")]


def de_escape(t):
    """Undo escapes. Offsets may shift, line breaks never do (line numbers stay valid)."""
    for rx, fn in ESC:
        t = rx.sub(fn, t)
    if "&" in t:
        t = "\n".join(html.unescape(l).replace("\n", " ").replace("\r", " ") for l in t.split("\n"))
    return t


def split_comment(line, marker):
    sq = dq = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\":
            i += 2
            continue
        if c == "'" and not dq:
            sq = not sq
        elif c == '"' and not sq:
            dq = not dq
        elif not sq and not dq and line.startswith(marker, i) and (i == 0 or line[i - 1] in " \t"):
            return line[i:]
        i += 1
    return ""


def tracked(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
        return [f for f in out.decode().split("\0") if f]
    except (OSError, subprocess.CalledProcessError):
        return [os.path.relpath(os.path.join(d, f), root) for d, _, fs in os.walk(root) if "/.git" not in d + "/"
                for f in fs]


def text_of(path):
    """(text, kind): kind = text | gz | pdf | None (other binary) | 'pdf-missing'."""
    b = open(path, "rb").read()
    if path.endswith(".gz"):
        try:
            b = gzip.decompress(b)
        except OSError:
            return None, None
        if b"\0" in b[:65536]:
            return None, None
        return b.decode("utf-8", "replace"), "gz"
    if b[:5] == b"%PDF-":
        exe = shutil.which("pdftotext")
        if not exe:
            return None, "pdf-missing"
        r = subprocess.run([exe, "-q", path, "-"], capture_output=True)
        return r.stdout.decode("utf-8", "replace"), "pdf"
    if b"\0" in b[:65536]:
        return None, None
    return b.decode("utf-8", "replace"), "text"


def lineno(t, pos):
    return t.count("\n", 0, pos) + 1


def word_at(t, s, e):
    a, b = s, e
    while a > 0 and re.match(WORDCH, t[a - 1]):
        a -= 1
    while b < len(t) and re.match(WORDCH, t[b]):
        b += 1
    return t[a:b], a


def deny_hits(f, t, rules, allow, substring, ctx):
    out = {}
    for variant in (t, de_escape(t)):
        low = variant.lower()
        for r in rules:
            for rx in filter(None, (r.rx, r.alt)):
                for m in rx.finditer(variant):
                    out.setdefault((lineno(variant, m.start()), r.n), ("denylist#%d" % r.n, ""))
            if substring and r.term and len(r.term) >= 3:
                i = low.find(r.term)
                while i >= 0:
                    w, ws = word_at(variant, i, i + len(r.term))
                    # short terms (<= 4 chars) inside a word only count at its start or at a camelCase hump
                    edge = len(r.term) > 4 or i == ws or (variant[i].isupper() and variant[i - 1].islower())
                    if edge and w.lower() != r.term and w.lower() not in allow:
                        key = (lineno(variant, i), r.n)
                        masked = re.sub(re.escape(r.term), "<#%d>" % r.n, w, flags=re.I)
                        if key not in out or not out[key][1]:
                            out[key] = ("substring#%d" % r.n, masked if ctx else "")
                    i = low.find(r.term, i + 1)
    return ["%s:%d %s%s" % (f, ln, kind, (" " + c) if c else "") for (ln, _), (kind, c) in sorted(out.items())]


def syntax_hits(root, files):
    hits, missing = [], {}
    py, sh, js = [], [], []
    for f in files:
        p = os.path.join(root, f)
        if not os.path.isfile(p) or os.path.islink(p):
            continue
        try:
            head = open(p, "rb").read(200).split(b"\n", 1)[0].decode("utf-8", "replace")
        except OSError:
            continue
        ext = os.path.splitext(f)[1]
        if ext == ".py" or (head.startswith("#!") and "python" in head):
            py.append(f)
        elif ext in (".sh", ".bash") or (head.startswith("#!") and re.search(r"\b(bash|sh|dash)\b", head)):
            sh.append((f, "sh" if re.search(r"/(?:env )?(?:da)?sh\b", head) and "bash" not in head else "bash"))
        elif ext in (".js", ".mjs", ".cjs") or (head.startswith("#!") and "node" in head):
            js.append(f)
    for f in py:
        try:
            compile(open(os.path.join(root, f), encoding="utf-8").read(), f, "exec", dont_inherit=True)
        except (SyntaxError, ValueError, UnicodeDecodeError) as e:
            hits.append("%s:%s syntax:python" % (f, getattr(e, "lineno", 0) or 0))
    for f, shell in sh:
        exe = shutil.which(shell) or shutil.which("bash")
        if not exe:
            missing["bash"] = missing.get("bash", 0) + 1
            continue
        r = subprocess.run([exe, "-n", os.path.join(root, f)], capture_output=True, text=True)
        if r.returncode:
            m = re.search(r"line (\d+)", r.stderr)
            hits.append("%s:%s syntax:%s" % (f, m.group(1) if m else 0, shell))
    node = shutil.which("node")
    with tempfile.TemporaryDirectory() as td:
        for f in js:
            if not node:
                missing["node"] = missing.get("node", 0) + 1
                continue
            p = os.path.join(root, f)
            if not f.endswith((".js", ".mjs", ".cjs")):      # extensionless node script: check a .js copy
                src = open(p, encoding="utf-8", errors="replace").read()
                p = os.path.join(td, "x%d.mjs" % len(hits))
                open(p, "w", encoding="utf-8").write(re.sub(r"^#![^\n]*", "", src))
            r = subprocess.run([node, "--check", p], capture_output=True, text=True)
            if r.returncode:
                m = re.search(r":(\d+)\n", r.stderr)
                hits.append("%s:%s syntax:node" % (f, m.group(1) if m else 0))
    for k, n in missing.items():
        print("public-gate: %s not found, %d file(s) not syntax-checked" % (k, n), file=sys.stderr)
    return hits, len(py) + len(sh) + len(js)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--denylist")
    ap.add_argument("--allowlist")
    ap.add_argument("--ignore", action="append", default=[])
    ap.add_argument("--no-substring", action="store_true")
    ap.add_argument("--no-syntax", action="store_true")
    ap.add_argument("--context", action="store_true", help="show the matched word with the term masked")
    ap.add_argument("--list-pii", action="store_true", help="print every PII value found (normalized), for review")
    a = ap.parse_args()
    raw = open(a.denylist, encoding="utf-8").read() if a.denylist else os.environ.get("PUBLIC_DENYLIST", "")
    rules, allow_words = load_denylist(raw)
    allow_path = a.allowlist or os.path.join(a.root, "tools/pii-allowlist.txt")
    allow = set()
    if os.path.exists(allow_path):
        allow = {norm(l.strip()) for l in open(allow_path, encoding="utf-8") if l.strip() and not l.startswith("#")}
    hits, pii_seen, nfiles = [], set(), 0
    files = tracked(a.root)
    for f in files:
        p = os.path.join(a.root, f)
        if not os.path.isfile(p):
            continue
        t, kind = text_of(p)
        if kind == "pdf-missing":
            hits.append("%s:0 pdf:pdftotext-missing" % f)
            continue
        if t is None:
            continue
        nfiles += 1
        ext = os.path.splitext(f)[1]
        masked = t
        for term in a.ignore:
            masked = re.sub(re.escape(term), " " * len(term), masked, flags=re.I)
        hits.extend(deny_hits(f, masked, rules, allow_words, not a.no_substring, a.context))
        in_doc = False
        for n, (line, dline) in enumerate(zip(masked.split("\n"), de_escape(masked).split("\n")), 1):
            seen = set()
            for kind_, rx in (("email", EMAIL), ("phone", PHONE), ("iban", IBAN), ("ahv", AHV), ("ip", IPV4)):
                for src in ((line, dline) if kind_ == "ip" else (line,)):
                    for m in rx.finditer(src):
                        v = m.group(0)
                        if kind_ == "email" and EMAIL_OK_DOMAIN.search(v.rsplit("@", 1)[1].lower()):
                            continue
                        if kind_ == "iban" and not iban_ok(v):
                            continue
                        if kind_ == "ahv" and not ean13_ok(v):
                            continue
                        if kind_ == "ip" and IP_OK.search(v):
                            continue
                        if a.list_pii:
                            pii_seen.add((kind_, norm(v)))
                        if norm(v) not in allow and (kind_, norm(v)) not in seen:
                            seen.add((kind_, norm(v)))
                            hits.append("%s:%d pii:%s" % (f, n, kind_))
            if kind == "pdf":
                continue
            n3 = line.count('"""') + line.count("'''")
            doc = in_doc or n3 > 0
            if n3 % 2 == 1:
                in_doc = not in_doc
            prose = ext in (".md", ".txt", ".html", ".json") or doc or \
                line.lstrip().startswith(("#", "//", "/*", "*", "<!--"))
            seg = line if prose else split_comment(line, "#" if ext in HASH_EXT else "//") if (
                ext in HASH_EXT or ext in SLASH_EXT) else ""
            if (seg and DATED.search(seg)) or DATED_TIGHT.search(line) or DATED_PAREN.search(line):
                hits.append("%s:%d prose:dated-owner-ref" % (f, n))
            if seg and QUOTE.search(seg):
                hits.append("%s:%d prose:owner-quote" % (f, n))
    if a.list_pii:
        for kind_, v in sorted(pii_seen):
            print("%s\t%s" % (kind_, v))
        return 0
    nsyn = 0
    if not a.no_syntax:
        sh, nsyn = syntax_hits(a.root, files)
        hits.extend(sh)
    for h in hits:
        print(h)
    print("public-gate: %d hit(s); %d file(s) scanned, %d denylist rule(s) (+%d allowed words), %d allowlisted "
          "PII value(s), %d script(s) syntax-checked" % (len(hits), nfiles, len(rules), len(allow_words), len(allow),
                                                         nsyn), file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
