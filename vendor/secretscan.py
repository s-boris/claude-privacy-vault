#!/usr/bin/python3 -I
"""secretscan: find secrets in text without ever printing them (module + CLI).

Detects
  * my actual secret values, matched by value: ~/.secrets/* (JSON, KEY=VALUE, bare tokens, card
    numbers), ~/.claude/channels/*/.env, ~/.claude/.credentials.json tokens, ~/.ssh/id_* key bodies;
  * common token formats: Telegram bot token, PEM private key, Anthropic/OpenAI/GitHub/AWS/Slack/
    Google/Stripe/Hugging Face keys, JWTs, Luhn-valid card numbers.
Output is hit NAMES (e.g. "value:secrets/media.json:radarr.key", "pattern:telegram-bot-token") with
file/line, never the matched text. Pattern hits on a line containing "secretscan:allow" are skipped
(value hits never are).

CLI
  secretscan --file F [F ...]   scan files              (exit 0 clean, 1 hits, 2 error)
  secretscan --scan-staged      scan the staged blobs of the current git repo (pre-commit hook)
  secretscan --stdin            scan stdin
  secretscan --redact           stdin -> stdout with every hit replaced by [redacted]
  secretscan --sources          list the loaded secret names (never values)
  -q/--quiet                    exit code only

Module (python3 -I: sys.path.insert(0, "/home/node/bin"); import secretscan)
  load_secrets() -> [(name, value)]   scan(text) -> [names]   find(text) -> [(name, line)]
  redact(text) -> str
Env SECRETSCAN_SOURCES=<dir>: read the sources from <dir> instead of $HOME (same layout; for tests).
"""
import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True

REDACTED = "[redacted]"
ALLOW_MARK = "secretscan:allow"
SECRET_KEY_RE = re.compile(r"key|token|secret|pass|pwd|auth|cookie|session|credential|bearer|private", re.I)
MIN_KEYED = 10          # values under secret-ish keys
MIN_UNKEYED = 20        # other values in ~/.secrets that still look like tokens
MAX_BLOB = 20 * 1024 * 1024

PATTERNS = [
    ("telegram-bot-token", re.compile(r"(?<![\w:])\d{6,12}:[A-Za-z0-9_-]{30,}")),
    ("private-key-pem", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("stripe-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{34,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]
# Card numbers: contiguous 13-19 digits, 4-4-4-x groups, or Amex 4-6-5; IIN 2-6; must pass Luhn.
CARD_RE = re.compile(
    r"(?<![\d.,-])(?:[2-6]\d{12,18}"
    r"|[2-6]\d{3}([ -])\d{4}\1\d{4}\1\d{1,7}"
    r"|3[47]\d{2}([ -])\d{6}\2\d{5})(?![\d])")
DIGIT_RUN_RE = re.compile(r"\d(?:[ -]?\d)+")

_cache = None


def _home():
    return os.environ.get("SECRETSCAN_SOURCES") or os.path.expanduser("~")


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return None


def _digits(v):
    s = re.sub(r"[ -]", "", v)
    return s if s.isdigit() else None


def _tokenish(v):
    if len(v) < MIN_UNKEYED or re.search(r"\s", v):
        return False
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", v) or v.startswith(("/", "~")) or re.fullmatch(r"[^@\s]+@[^@\s]+\.\w+", v):
        return False
    kinds = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return kinds >= 2


def _add(out, name, value, keyed):
    """Record one candidate secret: ('str'|'digits', name, value)."""
    if not isinstance(value, str):
        return
    v = value.strip().strip("'\"")
    d = _digits(v)
    if d and 13 <= len(d) <= 19:
        out.append(("digits", name, d))
    elif d:
        return  # short numbers (CVV, PIN, ports) would match everywhere
    elif (keyed and len(v) >= MIN_KEYED) or _tokenish(v):
        out.append(("str", name, v))


def _walk_json(obj, prefix, out, keyed_only, keyed=False):
    if isinstance(obj, dict):
        # the leaf's own key decides (a parent like "claudeAiOauth" must not make its scopes secret)
        for k, v in obj.items():
            _walk_json(v, f"{prefix}.{k}" if prefix else str(k), out, keyed_only,
                       bool(SECRET_KEY_RE.search(str(k))) or str(k).lower() in ("number", "pan", "card"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_json(v, f"{prefix}[{i}]", out, keyed_only, keyed)
    elif isinstance(obj, str):
        if keyed or not keyed_only:
            _add(out, prefix, obj, keyed)


KV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$")


def _parse_text(text, label, out, keyed_only=False):
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or "-----" in s:
            continue
        m = KV_RE.match(s)
        if m:
            k, v = m.groups()
            keyed = bool(SECRET_KEY_RE.search(k)) or k.lower() in ("number", "pan", "card")
            if keyed or not keyed_only:
                _add(out, f"{label}:{k}", v, keyed)
        elif not keyed_only:
            for run in DIGIT_RUN_RE.findall(s):  # e.g. a card number on a line of its own
                d = _digits(run)
                if d and 13 <= len(d) <= 19:
                    out.append(("digits", f"{label}:line{i}", d))
            if not re.search(r"\s", s) and len(s) >= 16:
                out.append(("str", f"{label}:line{i}", s))


def _load_file(path, label, out, keyed_only=False):
    text = _read(path)
    if text is None:
        return
    try:
        obj = json.loads(text)
    except ValueError:
        _parse_text(text, label, out, keyed_only)
    else:
        if isinstance(obj, (dict, list)):
            mine = []
            _walk_json(obj, "", mine, keyed_only)
            out.extend((kind, f"{label}:{name}", val) for kind, name, val in mine)
        else:
            _parse_text(text, label, out, keyed_only)


def _load_all():
    home = _home()
    out = []
    sec = os.path.join(home, ".secrets")
    for root, dirs, files in os.walk(sec):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            _load_file(p, "secrets/" + os.path.relpath(p, sec), out)
    chan = os.path.join(home, ".claude", "channels")
    if os.path.isdir(chan):
        for d in sorted(os.listdir(chan)):
            p = os.path.join(chan, d, ".env")
            if os.path.isfile(p):
                _load_file(p, f"channels/{d}/.env", out)
    _load_file(os.path.join(home, ".claude", ".credentials.json"), "claude-credentials", out, keyed_only=True)
    ssh = os.path.join(home, ".ssh")
    if os.path.isdir(ssh):
        for f in sorted(os.listdir(ssh)):
            if not f.startswith("id_") or f.endswith(".pub"):
                continue
            text = _read(os.path.join(ssh, f)) or ""
            if "PRIVATE KEY" not in text:
                continue
            body = [l.strip() for l in text.splitlines() if l.strip() and "-----" not in l]
            # line 1 of an OpenSSH key body is the same for every unencrypted key of a type: skip it
            for n, line in enumerate(body[1:], 2):
                if len(line) >= 40:
                    out.append(("str", f"ssh/{f}:line{n}", line))
    seen, uniq = set(), []
    for kind, name, val in out:
        if (kind, val) not in seen:
            seen.add((kind, val))
            uniq.append((kind, name, val))
    return uniq


def _secrets():
    global _cache
    if _cache is None:
        _cache = _load_all()
    return _cache


def load_secrets():
    """[(name, value)] of my secret values. Never print the values."""
    return [(name, val) for _, name, val in _secrets()]


def _luhn(d):
    total, alt = 0, False
    for c in reversed(d):
        n = int(c)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _card_ok(d):
    """Luhn plus issuer prefix/length rules, so timestamps and IDs don't look like cards."""
    n = len(d)
    if not (13 <= n <= 19 and _luhn(d)):
        return False
    p2, p4 = int(d[:2]), int(d[:4])
    return ((d[0] == "4" and n in (13, 16, 19))
            or ((51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16)
            or (p2 in (34, 37) and n == 15)
            or (p2 in (30, 36, 38, 39) and n == 14)
            or (p2 == 35 and 16 <= n <= 19)
            or (d[0] == "6" and 16 <= n <= 19))


def _spans(text, honor_allow=True):
    """[(start, end, name)] for every hit."""
    hits = []
    strs = [(n, v) for k, n, v in _secrets() if k == "str"]
    digs = [(n, v) for k, n, v in _secrets() if k == "digits"]
    for name, val in strs:
        i = text.find(val)
        while i != -1:
            hits.append((i, i + len(val), "value:" + name))
            i = text.find(val, i + 1)
    if digs:
        for m in DIGIT_RUN_RE.finditer(text):
            d = re.sub(r"[ -]", "", m.group())
            if len(d) >= 13:
                for name, val in digs:
                    if val in d:
                        hits.append((m.start(), m.end(), "value:" + name))
    pat = []
    for name, rx in PATTERNS:
        for m in rx.finditer(text):
            pat.append((m.start(), m.end(), "pattern:" + name))
    for m in CARD_RE.finditer(text):
        d = re.sub(r"[ -]", "", m.group())
        if _card_ok(d):
            pat.append((m.start(), m.end(), "pattern:card-number"))
    if honor_allow:
        def allowed(pos):
            a = text.rfind("\n", 0, pos) + 1
            b = text.find("\n", pos)
            return ALLOW_MARK in text[a:b if b != -1 else len(text)]
        pat = [h for h in pat if not allowed(h[0])]
    return hits + pat


def find(text):
    """[(name, line_number)] sorted, de-duplicated. Names only, never values."""
    res = set()
    for start, _, name in _spans(text):
        res.add((name, text.count("\n", 0, start) + 1))
    return sorted(res, key=lambda x: (x[1], x[0]))


def scan(text):
    """Hit names (unique, in order of first appearance). Never values."""
    names = []
    for start, _, name in sorted(_spans(text)):
        if name not in names:
            names.append(name)
    return names


def redact(text):
    """text with every secret value and token-shaped string replaced by [redacted]."""
    spans = sorted((s, e) for s, e, _ in _spans(text, honor_allow=False))
    out, pos = [], 0
    for s, e in spans:
        if e <= pos:
            continue
        s = max(s, pos)
        out.append(text[pos:s])
        out.append(REDACTED)
        pos = e
    out.append(text[pos:])
    return "".join(out)


# ---------------------------------------------------------------- CLI

def _git(*args, input=None):
    return subprocess.run(["git", *args], input=input, capture_output=True, check=True).stdout


def staged_blobs():
    """[(path, bytes)] for every added/changed path in the index of the current git repo."""
    names = [n for n in _git("diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT").decode(
        "utf-8", "surrogateescape").split("\0") if n]
    if not names:
        return []
    want = set(names)
    shas = {}
    for entry in _git("ls-files", "-s", "-z").decode("utf-8", "surrogateescape").split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        if path in want:
            shas[path] = meta.split()[1]
    order = [p for p in names if p in shas]
    if not order:
        return []
    raw = _git("cat-file", "--batch", input="".join(shas[p] + "\n" for p in order).encode())
    out, pos = [], 0
    for p in order:
        nl = raw.index(b"\n", pos)
        header = raw[pos:nl].split()
        size = int(header[2])
        out.append((p, raw[nl + 1:nl + 1 + size]))
        pos = nl + 1 + size + 1
    return out


def _report(label, hits, quiet):
    if not quiet:
        for name, line in hits:
            print(f"{label}:{line}: {name}", file=sys.stderr)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="secretscan", description=__doc__.split("\n\n")[0],
                                 epilog="Exit 0 = clean, 1 = possible secrets (names shown, values never), 2 = error.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", nargs="+", metavar="F")
    g.add_argument("--scan-staged", action="store_true")
    g.add_argument("--stdin", action="store_true")
    g.add_argument("--redact", action="store_true")
    g.add_argument("--sources", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args(argv)
    try:
        if a.sources:
            items = load_secrets()
            for name, _ in items:
                print(name)
            print(f"{len(items)} secret value(s) loaded from {_home()}", file=sys.stderr)
            return 0
        if a.redact:
            sys.stdout.write(redact(sys.stdin.read()))
            return 0
        found = 0
        if a.stdin:
            hits = find(sys.stdin.read())
            _report("<stdin>", hits, a.quiet)
            found += len(hits)
        elif a.file:
            for f in a.file:
                if os.path.isdir(f):
                    continue
                if os.path.getsize(f) > MAX_BLOB:
                    print(f"secretscan: {f}: larger than {MAX_BLOB >> 20} MB, not scanned", file=sys.stderr)
                    return 2
                text = _read(f)
                if text is None:
                    print(f"secretscan: cannot read {f}", file=sys.stderr)
                    return 2
                hits = find(text)
                _report(f, hits, a.quiet)
                found += len(hits)
        else:
            for path, blob in staged_blobs():
                if len(blob) > MAX_BLOB:
                    print(f"secretscan: {path}: larger than {MAX_BLOB >> 20} MB, not scanned", file=sys.stderr)
                    return 2
                hits = find(blob.decode("utf-8", "replace"))
                _report(path, hits, a.quiet)
                found += len(hits)
        if found:
            if not a.quiet:
                print(f"secretscan: {found} possible secret(s) found (names only; values are never shown). "
                      f"Remove them; for a false-positive PATTERN hit add '{ALLOW_MARK}' to that line.",
                      file=sys.stderr)
            return 1
        return 0
    except subprocess.CalledProcessError as e:
        print(f"secretscan: git failed: {(e.stderr or b'').decode(errors='replace').strip()}", file=sys.stderr)
        return 2
    except Exception as e:  # fail closed, but never echo content
        print(f"secretscan: error: {type(e).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
