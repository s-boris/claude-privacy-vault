#!/usr/bin/env bash
# Tests for ~/bin/llm-local (and the llm-server-ctl contract). Exit 0 = all pass.
#   run.sh             mocked tests (mock_server.py stands in for llama-server) + one real smoke test
#   run.sh --real      also the slow real-model checks: anonymize, summary and --strict of the synthetic 165-message
#                      chat (fixtures/chat150.tmpl; planted identifiers, private passages and facts in
#                      fixtures/planted.py), ~15 min on CPU. LLM_LOCAL_REAL_OUT=DIR keeps the outputs.
#   run.sh --real-money  also the real-model check of policy v3 (the owner's money/business, fixtures/money.txt,
#                      ~2 min); LLM_LOCAL_REAL_BACKEND=vault runs the real checks through the privacy vault's deployed
#                      llm-local and model instead of this box's llama-server
#   run.sh --real-swiss  also the real-model Swiss German paraphrase eval (policy v4.1, fixtures/swiss-para.txt checked
#                      by fixtures/swiss_eval.py: times stay times, negations stay, no translation; ~3 min)
#   LLM_LOCAL_SKIP_REAL=1 run.sh   mocked tests only
# Mocked tests never touch the real server: they use a free port and a fake llm-server-ctl.
set -uo pipefail
L=${LLM_LOCAL_BIN:-/home/node/bin/llm-local}          # the vault runs this suite on its own copy
CTLF=${LLM_SERVER_CTL_BIN:-/home/node/bin/llm-server-ctl}
export LLM_LOCAL_BACKEND=local                          # test this llm-local, never the vault backend
HERE=$(cd "$(dirname "$0")" && pwd)
FX=$HERE/fixtures
T=$(mktemp -d "${TMPDIR:-/tmp}/llm-local-tests.XXXXXX")
SRV=
trap 'kill $SRV 2>/dev/null; [ -f "$T/ctl.pid" ] && kill "$(cat "$T/ctl.pid")" 2>/dev/null; rm -rf "$T"' EXIT
REAL=0; [ "${1:-}" = --real ] && REAL=1
REALMONEY=0; [ "${1:-}" = --real-money ] && REALMONEY=1
REALSWISS=0; [ "${1:-}" = --real-swiss ] && REALSWISS=1

pass=0; fail=0
ok() { pass=$((pass + 1)); echo "ok   - $1"; }
no() { fail=$((fail + 1)); echo "FAIL - $1"; [ -n "${2:-}" ] && printf '       got: %s\n' "$2" | head -15; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "$2 (want: $3)"; fi; }
has() { if printf '%s' "$2" | grep -qF -- "$3"; then ok "$1"; else no "$1" "$2"; fi; }
hasnt() { if printf '%s' "$2" | grep -qF -- "$3"; then no "$1" "$2"; else ok "$1"; fi; }
lastreq() { tail -1 "$T/req.log"; }
jq_() { python3 -I -c 'import json,sys; d=json.loads(sys.stdin.read()); print(eval(sys.argv[1]))' "$1"; }
freeport() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
startmock() {   # startmock [port]
  rm -f "$T/port"; MOCK_PORT=${1:-0} python3 -I "$HERE/mock_server.py" "$T/port" "$T/req.log" "$T/mode" 2>"$T/mock.err" &
  SRV=$!; for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
}
mode() { echo "$1" > "$T/mode"; }
python3 -I "$FX/render.py" "$T/chat.txt"

# fake llm-server-ctl: `start` launches the mock on $LLM_LOCAL_PORT (or fails if $T/ctl.fail exists)
cat > "$T/ctl" <<STUB
#!/bin/sh
echo "\$*" >> "$T/ctl.log"
[ -f "$T/ctl.fail" ] && { echo "llm-server-ctl: only 812 MB RAM available (need 9000), not starting" >&2; exit 1; }
MOCK_PORT=\$LLM_LOCAL_PORT python3 -I "$HERE/mock_server.py" "$T/ctlport" "$T/req.log" "$T/mode" 2>&1 &
echo \$! > "$T/ctl.pid"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$T/ctlport" ] && exit 0; sleep 0.1; done
exit 1
STUB
chmod +x "$T/ctl"
export LLM_LOCAL_CTL=$T/ctl

startmock; export LLM_LOCAL_PORT=$(cat "$T/port"); mode ok

echo "# basics"
"$L" --help >/dev/null 2>&1; eq "--help exits 0" "$?" 0
out=$(printf '' | "$L" 2>&1); rc=$?
eq "empty stdin -> exit 2" "$rc" 2; has "empty stdin message" "$out" "empty input"
out=$(echo "Hallo Welt" | "$L" 2>&1); eq "basic prompt exit 0" "$?" 0
has "basic prompt prints the answer" "$out" "MOCK ANSWER (system=-): Hallo Welt"
req=$(lastreq)
eq "thinking disabled per request" "$(echo "$req" | jq_ 'd["body"]["chat_template_kwargs"]["enable_thinking"]')" False
eq "default max_tokens 1024" "$(echo "$req" | jq_ 'd["body"]["max_tokens"]')" 1024
eq "no system message by default" "$(echo "$req" | jq_ 'len(d["body"]["messages"])')" 1
out=$(echo "Frage" | "$L" --system "Du bist knapp." --max-tokens 50)
has "--system is sent" "$out" "system=Du bist knapp."
req=$(lastreq)
eq "--max-tokens is sent" "$(echo "$req" | jq_ 'd["body"]["max_tokens"]')" 50
eq "system message first" "$(echo "$req" | jq_ 'd["body"]["messages"][0]["role"]')" system
out=$("$L" --max-tokens 0 </dev/null 2>&1); eq "--max-tokens 0 -> exit 2" "$?" 2
mode think; out=$(echo "x" | "$L"); hasnt "<think> block stripped" "$out" "<think>"; mode ok

echo "# --json"
out=$(echo "gib json" | "$L" --json); eq "--json exit 0" "$?" 0
eq "--json prints compact valid JSON" "$out" '{"answer": 42, "lang": "de"}'
eq "--json requests json_object" "$(lastreq | jq_ 'd["body"]["response_format"]["type"]')" json_object
mode badjson; out=$(echo "gib json" | "$L" --json 2>&1); rc=$?; mode ok
eq "--json with invalid JSON -> exit 4" "$rc" 4; has "invalid JSON message" "$out" "valid JSON"
out=$(echo x | "$L" --json --anonymize 2>&1); eq "--json + --anonymize -> exit 2" "$?" 2

echo "# errors"
mode http400; out=$(echo "zu lang" | "$L" 2>&1); rc=$?; mode ok
eq "server rejects (too long) -> exit 4" "$rc" 4; has "server error message passed on" "$out" "exceeds the available context size"
mode slow; out=$(echo x | "$L" --timeout 1 2>&1); rc=$?; mode ok
eq "timeout -> exit 5" "$rc" 5; has "timeout message" "$out" "timed out"
out=$(echo x | http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 "$L" 2>&1)
has "proxy env vars are ignored (direct to 127.0.0.1)" "$out" "MOCK ANSWER"

echo "# server down / on-demand start"
DOWN=$(freeport)
out=$(echo x | LLM_LOCAL_PORT=$DOWN "$L" --no-start 2>&1); rc=$?
eq "down + --no-start -> exit 3" "$rc" 3; has "down message names the fix" "$out" "llm-server-ctl start"
touch "$T/ctl.fail"; out=$(echo x | LLM_LOCAL_PORT=$DOWN "$L" 2>&1); rc=$?; rm -f "$T/ctl.fail"
eq "start fails -> exit 3" "$rc" 3; has "start failure reason shown" "$out" "local LLM unavailable: llm-server-ctl: only 812 MB RAM"
: > "$T/ctl.log"; out=$(echo "wach?" | LLM_LOCAL_PORT=$DOWN "$L" 2>&1); rc=$?
eq "on-demand start -> exit 0" "$rc" 0; has "on-demand start answers" "$out" "MOCK ANSWER"
eq "ctl called with start once" "$(cat "$T/ctl.log")" start
kill "$(cat "$T/ctl.pid")" 2>/dev/null; rm -f "$T/ctl.pid"

echo "# local only"
remote=$(python3 -I - "$L" <<'PY'
import ast, re, sys
bad = [n.value for n in ast.walk(ast.parse(open(sys.argv[1]).read()))
       if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.match(r"(?i)https?://[a-z0-9]", n.value)
       and not n.value.startswith("http://127.0.0.1")]
print(" ".join(bad))
PY
)
eq "no URL other than http://127.0.0.1 in llm-local" "$remote" ""
eq "llm-local imports no HTTP client but urllib" "$(grep -cE '^\s*(import|from)\s+(requests|httpx|aiohttp|openai|anthropic)' "$L")" 0
if [ -f "$CTLF" ]; then
  eq "server binds 127.0.0.1 only" "$(grep -c -- '--host 127.0.0.1' "$CTLF")" 1
else
  echo "skip - no llm-server-ctl here (in the vault, vaultd starts llama-server with --host 127.0.0.1; its own tests check that)"
fi

echo "# backend switch (privacy vault)"
cat > "$T/fakevault" <<STUB
#!/bin/sh
printf 'argv:%s\n' "\$*"; printf 'stdin:'; cat; exit 7
STUB
chmod +x "$T/fakevault"
out=$(printf 'hallo' | LLM_LOCAL_BACKEND=vault LLM_LOCAL_VAULT_BIN="$T/fakevault" "$L" --anonymize --owner-name "Nico B"); rc=$?
eq "backend vault: exit code of the vault client" "$rc" 7
has "backend vault: args passed after llm-run --" "$out" "argv:llm-run -- --anonymize --owner-name Nico B"
has "backend vault: stdin passed through" "$out" "stdin:hallo"
mkdir -p "$T/h/.config/llm-local"; echo vault > "$T/h/.config/llm-local/backend"
out=$(printf 'x' | env -u LLM_LOCAL_BACKEND HOME="$T/h" LLM_LOCAL_VAULT_BIN="$T/fakevault" "$L" --max-tokens 5); rc=$?
eq "backend file 'vault' switches too" "$rc" 7
out=$(printf 'x' | env LLM_LOCAL_BACKEND=local HOME="$T/h" LLM_LOCAL_VAULT_BIN="$T/fakevault" LLM_LOCAL_PORT=1 "$L" --no-start 2>&1); rc=$?
eq "LLM_LOCAL_BACKEND=local wins over the file" "$rc" 3
out=$(printf 'x' | LLM_LOCAL_BACKEND=vault LLM_LOCAL_VAULT_BIN="$T/missing" "$L" 2>&1); rc=$?
eq "backend vault, client missing -> exit 3" "$rc" 3

echo "# unit: name matching and guards"
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
p = m.People("Nico"); p.add("Will Turner", ["Will"]); p.add("Max", []); p.add("Dr. Frei", []); p.add("Sophie", [])
out = []
out.append(m.apply_people("Will said he will come, max 5, Max agrees; sophie+SOPHIE; Dr. Frei, frei neh; nico!", p))
out.append(" ".join("%s=%d" % (t, m.plausible(ty, t)) for ty, t in [("location", "Samstig"), ("id", "17:30"),
           ("address", "23.50"), ("location", "Mittwuch Abig"), ("address", "Seefeldstrasse 112"), ("birthdate", "18.10."),
           ("birthdate", "18.10.1996"), ("phone", "078 765 43 21"), ("secret", "4711"), ("secret", "17:30"),
           ("secret", "Samstig"), ("secret", "35.-")]))
out.append(str(m.luhn("4" + "1" * 15)) + " " + str(m.luhn("1001234567890")))
print("\n".join(out))
PY
)
has "unit: common-word first names only capitalised" "$unit" "Person A said he will come, max 5, Person B agrees"
has "unit: first names case-insensitive, surnames capitalised only" "$unit" "Person D+Person D; Dr. Person C, frei neh; You!"
has "unit: guards reject weekday/time/amount/year-less date" "$unit" "Samstig=0 17:30=0 23.50=0 Mittwuch Abig=0 Seefeldstrasse 112=1 18.10.=0 18.10.1996=1 078 765 43 21=1"
has "unit: secret guard keeps digits-only codes, rejects time/weekday/amount" "$unit" "4711=1 17:30=0 Samstig=0 35.-=0"
has "unit: Luhn check" "$unit" "True False"

echo "# unit: private passages (located in the original text, widened to sentences)"
priv=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, json, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
text = ("### Crew (group, chat -1001234567890)\n"
        "[2026-10-10 18:01] Anna Muster: Ich bi bim Dr. Kunz gsi, er meint es isch e Burnout. Morn am 18.10. am 19:00 bin i im Kino! [photo; edited] (#11 reply to #9)\n"
        "[2026-10-10 18:02] Peter Gerber: De Lukas Frei hät sini Freundin betroge und si hät en usegheit, er pennt jetzt bi sim Brüeder.\n"
        "    Sie isch total fertig. Training am Mittwuch 19:30 findet statt (#12)\n"
        "[2026-10-10 18:03] Anna Muster: Lenas Mueter isch schwer chrank. Ich zahl d'Pizza.\n"
        "[2026-10-10 18:04] Nico: The Peter Gerber invoice is paid.\n")
items = [({"text": "es isch e Burnout", "category": "mental_health", "about": ""}, 0, len(text)),      # widened
         ({"text": "De Lukas Frei hät sini Freundin betroge und si hät en usegheit, er pennt jetzt bi sim Brüeder. Sie isch total fertig.",
           "category": "relationship", "about": "Lukas Frei"}, 0, len(text)),                          # crosses a line
         ({"text": "Lenas Mueter isch sehr schwer chrank worde", "category": "health", "about": "Lenas Mueter"}, 0, len(text)),  # reworded
         ({"text": "Ich bi bim Dr Kunz gsi er meint", "category": "health", "about": ""}, 0, len(text)),  # fuzzy, adjacent
         ({"text": "Anna", "category": "gossip", "about": ""}, 0, len(text)),                          # a name: ignored
         ({"text": "xyzzy plugh nothing", "category": "money", "about": ""}, 0, len(text))]                 # not found
out, st, sur = m.apply_private(text, items, m.chat_senders(text), "Nico")
print(out)
print("STATS " + json.dumps(st, sort_keys=True))
print("SURNAMES " + " ".join(sorted(sur)))
print("MASKED " + m.mask_surnames(out, sur).splitlines()[-1])
print("SECRETS " + m.regex_pass("PIN 1234, Türcode: 4711, the code is great, dress code: casual, Passwort isch "
                               "Sommer2026! um 17:30, Konto 80-12345-6, Bestätigungscode 834201, Bstellnummer isch 88412, WLAN-Passwort "
                               "isch übrigens Sonne2026!, promo code: SKI20")[0])
hdr = "### Krebs-Selbsthilfe (group, chat -100777)\n[2026-10-10 18:05] Eva: Hoi\n"
print("HEADER " + m.apply_private(hdr, [({"text": "Krebs-Selbsthilfe", "category": "health", "about": ""}, 0, len(hdr))],
                                   m.chat_senders(hdr), None)[0].splitlines()[0])
PY
)
has "private: key phrase widened to its sentence; the rest of the message, prefix and tgread tail kept" "$priv" \
    "] Anna Muster: [private: health, mental health] Morn am 18.10. am 19:00 bin i im Kino! [photo; edited] (#11 reply to #9)"
has "private: span across a continuation line redacted on both lines, later sentence kept" "$priv" \
    "] Peter Gerber: [private: relationship]"
has "private: continuation line indent and the next sentence kept" "$priv" "    [private: relationship] Training am Mittwuch 19:30 findet statt (#12)"
has "private: reworded quote falls back to the matching sentence of its line" "$priv" "] Anna Muster: [private: health] Ich zahl d'Pizza."
has "private: unlocatable quote counted, a bare name ignored" "$priv" '"private_unmatched": 1'
has "private: surnames of writer and subject collected, not relation words" "$priv" "SURNAMES Frei Gerber Muster"
has "private: attached surname masked everywhere" "$priv" "MASKED [2026-10-10 18:04] Nico: The Peter [surname] invoice is paid."
has "regex: PIN/codes/passwords/accounts masked, dress code/plain words/order numbers kept" "$priv" \
    "SECRETS PIN [secret], Türcode: [secret], the code is great, dress code: casual, Passwort isch [secret]! um 17:30, Konto [account number], Bestätigungscode [secret], Bstellnummer isch 88412, WLAN-Passwort isch übrigens [secret]!, promo code: SKI20"
has "private: tgread block header never redacted" "$priv" "HEADER ### Krebs-Selbsthilfe (group, chat -100777)"
eq "private: line count unchanged" "$(printf '%s\n' "$priv" | grep -c '^\[2026-10-10\|^    \|^###')" 6
chk=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, json, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
text = "[2026-10-10 18:01] Anna Muster: Ich ha e Grippe. Am Sunntig chumi aber! Gruess\n"
seen = []
def check(sent, msg):
    seen.append(sent)
    return "health" if "Grippe" in sent else ("?" if "Gruess" in sent else None)
out, st, sur = m.apply_private(text, [({"text": text.split(": ", 1)[1].strip(), "category": "confidential", "about": ""}, 0, len(text))],
                               m.chat_senders(text), None, check)
print(out.strip()); print(" | ".join(seen)); print(st["private_rejected_by_check"], st["private_by_category"])
PY
)
has "check: each sentence of a flagged message is checked on its own" "$chk" "Ich ha e Grippe. | Am Sunntig chumi aber! | Gruess"
has "check: rejected sentence kept, confirmed one gets the checker's category, unreadable answer keeps the detector's" "$chk" \
    "Anna Muster: [private: health] Am Sunntig chumi aber! [private: confidential]"
has "check: stats" "$chk" "1 {'health': 1, 'confidential': 1}"

echo "# --anonymize, default policy (mocked detector)"
: > "$T/req.log"
out=$("$L" --anonymize --owner-name Nico --stats < "$T/chat.txt" 2>"$T/err"); rc=$?
eq "anonymize exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/anon.txt"
res=$(python3 -I "$FX/planted.py" check-anon "$T/anon.txt"); rc=$?
eq "anonymize: identifiers gone, private passages redacted by category, names/addresses/facts kept" "$rc" 0; [ $rc = 0 ] || echo "$res"
hasnt "anonymize: no extra redactions" "$res" "extra redaction"
has "guard: weekday flagged as secret is kept" "$out" "Party am Samstig 18.10. am 19:00"
has "guard: amount flagged as id is kept" "$out" "no 23.50 vom Pizza"
has "guard: time flagged as id is kept" "$out" "Abholig am Samstig am 17:30"
has "guard: time flagged as private is ignored" "$out" "Party am Samstig 18.10. am 19:00 im Frau Gerolds Garten"
has "address kept verbatim" "$out" "wohnt jo a de Seefeldstrasse 112, 8008 Zürich"
has "owner mention becomes @You" "$out" "@You du hesch"
has "unattached titled surname kept" "$out" "Der Vermieter, Herr Huber, will"
has "writer of a private passage: surname masked, first name kept" "$out" "] Lena [surname]: Morge!"
has "debt passage (fuzzy quote) redacted as money" "$out" "] Marco [surname]: [private: money]"
has "health key phrase widened, rest kept" "$out" "] Lena [surname]: [private: health] Am Samstig bin i aber trotzdem debi!"
nch=$(grep -o '"chunks": [0-9]*' "$T/err" | head -1 | grep -o '[0-9]*$')
eq "one detection request per chunk ($nch)" "$(grep -c '"identifiers"' "$T/req.log")" "$nch"
[ "${nch:-0}" -ge 3 ] && [ "${nch:-0}" -le 9 ] && ok "content-defined chunks: 3..9 for the 150-line chat ($nch)" || no "content-defined chunks: 3..9" "$nch"
has "detection asks for private passages and identifiers" "$(grep json_schema "$T/req.log" | head -1)" '"private"'
hasnt "default detection has no people list" "$(grep json_schema "$T/req.log" | head -1 | jq_ 'list(d["body"]["response_format"]["json_schema"]["schema"]["properties"])')" "people"
has "stats: mode" "$(cat "$T/err")" '"mode": "default"'
has "stats: private passages by category" "$(cat "$T/err")" '"private_redactions": 5'
has "stats: harmless sentences rejected by the per-sentence check" "$(cat "$T/err")" '"private_rejected_by_check": 3'
n=$(grep -c '"category"\]' "$T/req.log"); [ "$n" -ge 7 ] && ok "per-sentence check requests ($n)" || no "per-sentence check requests" "$n"
has "stats: surnames masked" "$(cat "$T/err")" '"surnames_masked": 4'

echo "# chunking"
: > "$T/req.log"
out=$("$L" --anonymize --owner-name Nico --chunk-chars 1500 < "$T/chat.txt"); rc=$?
eq "small chunks exit 0" "$rc" 0
n=$(grep -c json_schema "$T/req.log"); [ "$n" -ge 7 ] && ok "many detection chunks ($n)" || no "many detection chunks" "$n"
printf '%s\n' "$out" > "$T/anon2.txt"
python3 -I "$FX/planted.py" check-anon "$T/anon2.txt" >/dev/null; eq "chunked output passes the planted checks" "$?" 0
eq "chunked output identical to single-pass output" "$(md5sum < "$T/anon2.txt")" "$(md5sum < "$T/anon.txt")"

echo "# --strict (old policy: alias all names, mask addresses; plus private passages)"
: > "$T/req.log"
out=$("$L" --anonymize --strict --owner-name Nico --stats < "$T/chat.txt" 2>"$T/err"); rc=$?
eq "strict exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/strict.txt"
res=$(python3 -I "$FX/planted.py" check-strict "$T/strict.txt"); rc=$?
eq "strict: no names/address/identifiers, private redacted, facts kept, Person aliases" "$rc" 0; [ $rc = 0 ] || echo "$res"
hasnt "strict: venue kept despite detector false positive" "$res" "over-redacted"
has "strict: address replaced" "$out" "wohnt jo a de [address]"
has "strict: titled surname aliased, title kept" "$out" "Herrn Person"
has "strict: lowercase word equal to a surname kept (frei)" "$out" "ich chan im Januar frei neh"
has "strict: private passage redacted too" "$out" "[private: health] Am Samstig bin i aber trotzdem debi!"
has "strict: stats" "$(cat "$T/err")" '"people": 7'
has "strict: pass 1 is the pre-v2 detector (people, pii)" "$(grep json_schema "$T/req.log" | head -1 | jq_ 'sorted(d["body"]["response_format"]["json_schema"]["schema"]["properties"])')" "['people', 'pii']"
nch=$(grep -o '"chunks": [0-9]*' "$T/err" | head -1 | grep -o '[0-9]*$')
eq "strict: pass 2 is the default detector (private, identifiers), one per chunk" "$(grep -c '"identifiers"' "$T/req.log")" "$nch"
a1=$(sed -n 1p "$T/strict.txt" | sed -E 's/^\[[^]]*\] ([^:]+):.*/\1/')
a2=$(grep 'Kopfhörer gmacht' "$T/strict.txt" | sed -E 's/^\[[^]]*\] ([^:]+):.*/\1/')
eq "strict: same person, same alias at start and end" "$a2" "$a1"
: > "$T/req.log"
out=$("$L" --strict --owner-name Nico --chunk-chars 1500 < "$T/chat.txt"); rc=$?
eq "strict implies --anonymize; small chunks exit 0" "$rc" 0
known=$(sed -n 3p "$T/req.log" | jq_ 'd["body"]["messages"][1]["content"].split("\n")[0]')
has "strict: later chunk gets the known-people map" "$known" "Marco Keller"
eq "strict: chunked output identical to single pass" "$(printf '%s\n' "$out" | md5sum)" "$(md5sum < "$T/strict.txt")"

echo "# regex safety pass (detector reports nothing private and no identifiers)"
mode lazy; out=$("$L" --anonymize --owner-name Nico < "$T/chat.txt"); rc=$?; mode ok
eq "lazy detector exit 0" "$rc" 0
for p in "79 123 45 67" "765 43 21" "76 555 12 34" "CH93" "756.1234" "$(python3 -I -c 'import sys; sys.path.insert(0,sys.argv[1]); import render; print(render.VALUES["{{TEST_CARD}}"])' "$FX")" \
         "lena.brunner92" "ZH 123 456" "1Qz8xK3vT9mPa2LwR7bN4cYd6E" "f3a9c2e1" "1996"; do
  hasnt "regex pass removes: ${p:0:6}…" "$out" "$p"
done
has "regex pass keeps a public link's domain" "$out" "[link: airbnb.ch]"
CARD=$(python3 -I -c 'import sys; sys.path.insert(0,sys.argv[1]); import render; print(render.VALUES["{{TEST_CARD}}"])' "$FX")
mode lazy
out=$(printf '### Ski Crew (group, chat -1001234567890)\n[2026-10-10 18:02] Marco Keller: Karte %s, ruf 079 123 45 67, WLAN-Passwort: Alpen-77x (#4521 reply to #4519)\n' "$CARD" | "$L" --anonymize)
outs=$(printf '[2026-10-10 18:02] Marco Keller: ruf 079 123 45 67\n' | "$L" --strict)
mode ok
has "tgread format: chat id kept (not a card number)" "$out" "chat -1001234567890"
has "tgread format: message refs kept" "$out" "(#4521 reply to #4519)"
has "tgread format: sender kept, identifiers masked" "$out" "] Marco Keller: Karte [card number], ruf [phone], WLAN-Passwort: [secret] (#4521"
has "tgread format, --strict: sender aliased" "$outs" "] Person A: ruf [phone]"

echo "# --summary"
: > "$T/req.log"; mode leaky
out=$("$L" --summary --owner-name Nico < "$T/chat.txt"); rc=$?; mode ok
eq "summary exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/sum.txt"
res=$(python3 -I "$FX/planted.py" check-summary "$T/sum.txt"); rc=$?
eq "summary: no identifiers or private details, key facts present" "$rc" 0; [ $rc = 0 ] || echo "$res"
hasnt "summary: leaked phone scrubbed" "$out" "79 123"
has "summary: leaked attached surname masked, first name kept" "$out" "Lena [surname] said call her on [phone]"
sumreq=$(grep -v json_schema "$T/req.log" | grep chat/completions | tail -1)
printf '%s' "$sumreq" > "$T/sumreq.txt"
has "summary step: uses the v2 summary prompt" "$sumreq" "real names"
python3 -I "$FX/planted.py" check-summary "$T/sumreq.txt" 2>/dev/null | grep -qE "PII leaked|private detail|masked surname"
eq "summary step: the model never saw identifiers, private details or masked surnames" "$?" 1
: > "$T/req.log"; mode leaky
out=$("$L" --summary --strict --owner-name Nico < "$T/chat.txt"); rc=$?; mode ok
eq "strict summary exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/sum-strict.txt"
python3 -I "$FX/planted.py" check-summary-strict "$T/sum-strict.txt" >/dev/null; eq "strict summary: no names, PII or private details" "$?" 0
sum3='- Party for Sophie on Saturday 18.10. at 19:00; You bring the speaker and pick up the cake at 17:30.
- Gift: 35.- each for headphones (279.-). Ski weekend Laax 16.-18.1.2027, answer by Friday 17.10. 12:00.
- Football Thursday 16.10. 19:00 Juchhof.'
printf '%s\n' "$sum3" > "$T/sum279.txt"
res=$(python3 -I "$FX/planted.py" check-summary "$T/sum279.txt"); rc=$?
eq "summary check: a bigger purchase's price (279) fails (policy v3)" "$rc" 1
has "summary check: only the purchase price fails" "$res" "(1 fails, 2 warnings)"
has "summary check: names the purchase price" "$res" "headphones price 279"
has "summary check: missing small costs only warn" "$res" "WARN optional small cost missing: festival 89"
printf '%s\n' "${sum3/ (279.-)/}" > "$T/sum-v3.txt"
python3 -I "$FX/planted.py" check-summary "$T/sum-v3.txt" >/dev/null; eq "summary check: without the price and the optional costs it passes" "$?" 0
hasnt "strict summary: leaked name re-aliased" "$out" "Marco"
has "strict summary step: uses the alias prompt" "$(grep -v json_schema "$T/req.log" | grep chat/completions | tail -1)" "aliases (Person A"

echo "# policy v3: the owner's money and business"
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
for c in ["Ich lege 3 Tranchen à €25k in ETFs an",                                   # investment (German)
          "Putting $40,000 into index funds this year",                              # investment (English)
          "Min Lohn isch jetzt 9'500 im Monet",                                      # salary (Swiss German)
          "My salary will be 120k plus bonus",                                       # salary (English)
          "Hab mir ein E-Bike gekauft für 3'200.-",                                  # purchase sum (German)
          "Ich ha 200 Grafikchärtli im Bulk kauft für 48'000.-",                     # bulk purchase (Swiss German)
          "Der Deal mit der Müller AG über 12'000 Franken ist durch",                # business deal (German)
          "The company made $350k revenue last year",                                # business (English)
          "Meeting am Dienstag 21.10. um 14:00 im Büro",                             # kept: meeting time
          "Ski-Wuchenend in Laax 16.–18. Januar 2027, kostet 1450.- total",          # kept: trip, shared cost
          "Die Swisscom-Rechnung über CHF 89.90 ist am 30.10.2026 fällig",           # kept: bill due date
          "Lohn chunnt am Fr. 25.10., d'Steuern sind bis 31.03.2027 fällig",         # kept: dates near cue words
          "[2026-10-10 18:01] Nico: Bitcoin bi 100k, Rendite 7% (#4521 reply to #4519)",
          "Check https://youtube.com/watch?v=abc&t=120 about investing, S&P 500 since 2019",
          "Tickets for 1'200 people sold out",
          "Mir sind 8 Lüt, also öppe 35.- pro Person"]:
    print("NET " + m.money_pass(c)[0])
print("POLICY " + m.POLICY)
enum = lambda sch: " ".join(sch["properties"]["private"]["items"]["properties"]["category"]["enum"])
print("ENUM " + enum(m.DETECT_SCHEMA)); print("ENUM_ADMIN " + enum(m.DETECT_SCHEMA_ADMIN))
print("CHECKENUM " + " ".join(m.CHECK_SCHEMA["properties"]["category"]["enum"]))
print("V3 %d%d%d%d" % ("- business:" in m.CHECK_SYSTEM, "salary" in m.CHECK_SYSTEM, "- business:" in m.DETECT_SYSTEM,
                        "investment plans" in m.DETECT_SYSTEM))
print("ADMIN %d%d%d" % ("- business:" in m.CHECK_SYSTEM_ADMIN, "- business:" in m.DETECT_SYSTEM_ADMIN,
                         "investment" in m.DETECT_SYSTEM_ADMIN))
mp = "Money and business stay private"
print("SUMMARY %d%d%d" % (mp in m.SUMMARY_SYSTEM, mp in m.SUMMARY_SYSTEM_STRICT, mp in m.SUMMARY_SYSTEM_ADMIN))
print("NOMONEY " + m.regex_pass("Lohn 9'500, CHF 48'000", money=False)[0])
PY
)
has "money net: investment (German)" "$unit" "NET Ich lege 3 Tranchen à [amount] in ETFs an"
has "money net: investment (English)" "$unit" "NET Putting [amount] into index funds this year"
has "money net: salary (Swiss German)" "$unit" "NET Min Lohn isch jetzt [amount] im Monet"
has "money net: salary (English)" "$unit" "NET My salary will be [amount] plus bonus"
has "money net: purchase sum (German)" "$unit" "NET Hab mir ein E-Bike gekauft für [amount]"
has "money net: bulk purchase, quantity and sum (Swiss German)" "$unit" "NET Ich ha [amount] Grafikchärtli im Bulk kauft für [amount]"
has "money net: business deal (German)" "$unit" "NET Der Deal mit der Müller AG über [amount] ist durch"
has "money net: business revenue (English)" "$unit" "NET The company made [amount] revenue last year"
has "money net keeps a meeting time" "$unit" "NET Meeting am Dienstag 21.10. um 14:00 im Büro"
has "money net keeps a trip and a small shared cost" "$unit" "NET Ski-Wuchenend in Laax 16.–18. Januar 2027, kostet 1450.- total"
has "money net keeps a bill and its due date" "$unit" "NET Die Swisscom-Rechnung über CHF 89.90 ist am 30.10.2026 fällig"
has "money net keeps dates next to money words" "$unit" "NET Lohn chunnt am Fr. 25.10., d'Steuern sind bis 31.03.2027 fällig"
has "money net keeps tgread refs, timestamps and percentages" "$unit" "NET [2026-10-10 18:01] Nico: Bitcoin bi [amount], Rendite 7% (#4521 reply to #4519)"
has "money net keeps URL parameters, index names and years" "$unit" "NET Check https://youtube.com/watch?v=abc&t=120 about investing, S&P 500 since 2019"
has "money net keeps counts without a money word" "$unit" "NET Tickets for 1'200 people sold out"
has "money net keeps small everyday costs" "$unit" "NET Mir sind 8 Lüt, also öppe 35.- pro Person"
has "policy version" "$unit" "POLICY llm-local-v4.1+regex-2026-10-13"
has "detection schema: business category" "$unit" "ENUM health mental_health sexual dating relationship family money business confidential gossip"
has "detection schema (admin): no business category" "$unit" "ENUM_ADMIN health mental_health sexual dating relationship family money confidential gossip"
has "check schema: business category" "$unit" "CHECKENUM health mental_health sexual dating relationship family money business confidential gossip none"
has "check + detection prompts: v3 money and business rules" "$unit" "V3 1111"
has "admin prompts: v2 money rule only" "$unit" "ADMIN 000"
has "summary prompts: money stays private (default, strict), not in admin" "$unit" "SUMMARY 110"
has "regex pass without the money net" "$unit" "NOMONEY Lohn 9'500, CHF 48'000"
: > "$T/req.log"
out=$("$L" --anonymize --owner-name Nico --stats < "$FX/money.txt" 2>"$T/err"); rc=$?
eq "money: anonymize exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/money-anon.txt"
res=$(python3 -I "$FX/planted.py" check-money "$T/money-anon.txt"); rc=$?
eq "money: owner's investment, salary, bulk purchase and deal redacted; meeting, trip, bill due date kept" "$rc" 0; [ $rc = 0 ] || echo "$res"
has "money: investment plan -> [private: money]" "$out" "] You: [private: money]"
has "money: salary sentence redacted, the rest of the message kept" "$out" "] You: Mittwuch passt. [private: money]"
has "money: bulk purchase -> [private: business]" "$out" "18:04] You: [private: business]"
has "money: business deal -> [private: business], writer's surname masked" "$out" "] Jonas [surname]: [private: business]"
has "money: bill due date kept (false positive rejected by the check)" "$out" "Die Swisscom-Rechnung ist am 30.10. fällig, ich zahle sie am Montag."
has "money: stats policy" "$(cat "$T/err")" '"policy": "llm-local-v4.1+regex-2026-10-13"'
has "money: stats by category" "$(cat "$T/err")" '"private_by_category": {"money": 2, "business": 2}'
has "money: detection asks for the business category" "$(grep json_schema "$T/req.log" | head -1)" '"business"'
has "money: detection prompt has the v3 money rule" "$(grep json_schema "$T/req.log" | head -1)" "the owner included"
mode lazy; out=$("$L" --anonymize --owner-name Nico < "$FX/money.txt"); mode ok
for p in "25'000" "11'200" "6'400" "18'000"; do hasnt "money net (detector found nothing): $p masked" "$out" "$p"; done
has "money net (detector found nothing): cinema debt and meeting kept" "$out" "Du schuldsch mir no 18.- fürs Kino"
: > "$T/req.log"
out=$("$L" --summary --owner-name Nico < "$FX/money.txt"); rc=$?
eq "money summary exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/money-sum.txt"
res=$(python3 -I "$FX/planted.py" check-money-summary "$T/money-sum.txt"); rc=$?
eq "money summary: no figures or details, plans present" "$rc" 0; [ $rc = 0 ] || echo "$res"
hasnt "money summary: a figure leaked by the model is masked" "$out" "11'200"
has "money summary: the investment bullet goes to the money backstop (2026-10-14)" "$out" "- [private: money]"
sumreq=$(grep -v json_schema "$T/req.log" | grep chat/completions | tail -1)
has "money summary step: prompt keeps money private" "$sumreq" "Money and business stay private"
hasnt "money summary step: the model never saw the investment" "$sumreq" "25'000"
: > "$T/req.log"
out=$("$L" --keep-own-money --owner-name Nico --stats < "$FX/money.txt" 2>"$T/err"); rc=$?
eq "--keep-own-money implies --anonymize, exit 0" "$rc" 0
has "--keep-own-money (admin documents): the owner's own figures stay" "$out" "in drei Tranchen à 25'000 Euro"
has "--keep-own-money: no [amount] net" "$out" "for CHF 6'400 to resell"
hasnt "--keep-own-money: no money/business redaction" "$out" "[private: "
has "--keep-own-money: stats" "$(cat "$T/err")" '"own_money": "kept"'
hasnt "--keep-own-money: detection without the business category" "$(grep json_schema "$T/req.log" | head -1 | jq_ 'd["body"]["response_format"]["json_schema"]["schema"]["properties"]["private"]["items"]["properties"]["category"]["enum"]')" "business"
out=$(printf 'x' | "$L" --keep-own-money --json 2>&1); eq "--keep-own-money with --json -> exit 2" "$?" 2

echo "# policy v3.1: the owner's own mail (--all-amounts) and payment words in chats (2026-10-13)"
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
for c in ["$108.34", "USD 12.00", "CHF 1'234.50", "€ 9,99", "Total: 45.00", "Total 45", "Preis: 49",
          "Your order 108.34 has shipped", "Ihre Zahlung von CHF 9.90 ist eingegangen",
          "Termin am 21.10. um 10.30 Uhr", "Termin Mittwoch 10.30 im Büro", "Fr. 25.10. Abholung",
          "Lieferung am 18.10.2026, Bestellung #112-3456789-1234567", "20% Rabatt auf 2 Artikel", "Order 2026 summary"]:
    print("MAIL " + m.money_pass(c, True)[0])
for c in ["Paid $108.34 for the concert tickets", "Hab grad 45.50 per TWINT überwiesen", "Total: 45.00",
          "Rechnungsbetrag CHF 1'234.50", "Betrag: € 9,99", "Das hat mich 120.- gekostet",
          "Mir zahled am Fritig um 19.30 de Tisch", "Treffpunkt 19.00 beim Bahnhof", "Total 12 Teilnehmer",
          "Hab bezahlt, Treffpunkt 19.30 am HB",
          "Wir sind total 12 Leute um 19.30", "$108.34"]:
    print("CHAT " + m.money_pass(c)[0])
print("RP " + m.regex_pass("Total $108.34", all_amounts=True)[0] + " | " + m.regex_pass("Total $108.34")[0])
PY
)
for c in "[amount]" "[amount]" "[amount]" "[amount]" "Total: [amount]" "Total [amount]" "Preis: [amount]" \
         "Your order [amount] has shipped" "Ihre Zahlung von [amount] ist eingegangen"; do
  has "mail amounts: $c" "$unit" "MAIL $c"; done
has "mail amounts: the 4 bare currency fixtures masked whole" "$(printf '%s\n' "$unit" | grep -c '^MAIL \[amount\]$')" "4"
for c in "Termin am 21.10. um 10.30 Uhr" "Termin Mittwoch 10.30 im Büro" "Fr. 25.10. Abholung" \
         "Lieferung am 18.10.2026, Bestellung #112-3456789-1234567" "20% Rabatt auf 2 Artikel" "Order 2026 summary"; do
  has "mail amounts keep dates, times, order numbers, percentages, counts, years: $c" "$unit" "MAIL $c"; done
for c in "Paid [amount] for the concert tickets" "Hab grad [amount] per TWINT überwiesen" "Total: [amount]" \
         "Rechnungsbetrag [amount]" "Betrag: [amount]" "Das hat mich [amount] gekostet"; do
  has "chat money net: payment words and amount labels: $c" "$unit" "CHAT $c"; done
for c in "Mir zahled am Fritig um 19.30 de Tisch" "Treffpunkt 19.00 beim Bahnhof" "Total 12 Teilnehmer" \
         "Hab bezahlt, Treffpunkt 19.30 am HB" \
         "Wir sind total 12 Leute um 19.30" '$108.34'; do
  has "chat money net keeps times, counts and a lone small amount: $c" "$unit" "CHAT $c"; done
has "regex_pass passes all_amounts through" "$unit" 'RP Total [amount] | Total $108.34'
echo "# v3.1 fix (13.10): postcodes and phone numbers are never amounts; mail masks only real amounts"
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
mail = "Your order was paid. Ship to Examplestrasse 1, 1234 Exampletown, Switzerland (+41) 791234567. Total US $12.34"
print("MP " + m.money_pass(mail, True)[0])
print("RP " + m.regex_pass(mail, all_amounts=True)[0])
for c in ["Call (+41) 79 123 45 67 for delivery", "(0041) 791234567", "Tel. 052 672 12 34"]:
    print("PH " + m.regex_pass(c, all_amounts=True)[0])
for c in ["Hab 300 bezahlt, Adresse: Bahnhofstrasse 1, 8001 Zürich", "bezahlt, Lieferung in 1234 Exampletown",
          "Ich hab 2500 Aktien gekauft", "Betrag CHF 1200 Zahlung", "Bezahlt per Twint, ruf an: (+41) 791234567"]:
    print("CHAT " + m.money_pass(c)[0])
for c in ["Sie haben 300 bezahlt", "Depot 50k investiert", "CH-1234 Exampletown, Rechnung bezahlt",
          "Zahlung CHF 1234 Exampletown-Filiale"]:
    print("MAIL " + m.money_pass(c, True)[0])
PY
)
has "mail: postcode kept, amount masked" "$unit" 'MP Your order was paid. Ship to Examplestrasse 1, 1234 Exampletown, Switzerland (+41) 791234567. Total US [amount]'
has "mail regex pass: (+41) phone -> [phone], postcode kept" "$unit" 'RP Your order was paid. Ship to Examplestrasse 1, 1234 Exampletown, Switzerland [phone]. Total US [amount]'
for c in "Call [phone] for delivery" "[phone]" "Tel. [phone]"; do has "phone in brackets / national: $c" "$unit" "PH $c"; done
for c in "Hab [amount] bezahlt, Adresse: Bahnhofstrasse 1, 8001 Zürich" "bezahlt, Lieferung in 1234 Exampletown" \
         "Ich hab [amount] Aktien gekauft" "Betrag [amount] Zahlung" "Bezahlt per Twint, ruf an: (+41) 791234567"; do
  has "chat money net: amounts go, postcodes and phone digits stay: $c" "$unit" "CHAT $c"; done
for c in "Sie haben 300 bezahlt" "Depot [amount] investiert" "CH-1234 Exampletown, Rechnung bezahlt" \
         "Zahlung [amount] Exampletown-Filiale"; do
  has "mail money net: only currency/label/cents/k-Mio amounts: $c" "$unit" "MAIL $c"; done
mode lazy; out=$("$L" --anonymize --all-amounts --owner-name Nico --stats < "$FX/receipts.txt" 2>"$T/err"); rc=$?; mode ok
eq "--all-amounts (detector found nothing): exit 0" "$rc" 0
for p in '108.34' '12.00' "1'234.50" '9,99' '45.00'; do hasnt "--all-amounts: $p masked" "$out" "$p"; done
has "--all-amounts: receipt lines keep their words" "$out" "Total [amount] Billed to Visa"
has "--all-amounts: due date, appointment and order number kept" "$out" "zahlbar bis 30.10.2026. Termin am 21.10. um 10.30 Uhr."
has "--all-amounts: delivery date, discount and count kept" "$out" "geliefert. 20% Rabatt auf 2 Artikel."
has "--all-amounts: stats" "$(cat "$T/err")" '"amounts": "all"'
mode lazy; out=$("$L" --anonymize --owner-name Nico < "$FX/receipts.txt"); mode ok
has "default (chat) money net on the same receipts: labelled and payment amounts masked" "$out" "Betrag [amount] wurde am 12.10.2026 belastet."
out=$(printf 'x' | "$L" --all-amounts --keep-own-money 2>&1); eq "--all-amounts with --keep-own-money -> exit 2" "$?" 2
out=$(printf 'x' | "$L" --all-amounts --json 2>&1); eq "--all-amounts with --json -> exit 2" "$?" 2

echo "# policy v4: --paraphrase"
mode ok
"$L" --anonymize --owner-name Nico < "$T/chat.txt" > "$T/v4-anon.txt" 2>/dev/null
: > "$T/req.log"
out=$("$L" --paraphrase --owner-name Nico --stats < "$T/chat.txt" 2>"$T/err"); rc=$?
eq "paraphrase: exit 0" "$rc" 0
printf '%s\n' "$out" > "$T/v4.txt"
cat > "$T/v4check.py" <<'PY'
import re, sys
P = re.compile(r'^(\[[^\]\n]{4,40}\]\s*[^:\n]{1,80}?:\s)(.*)$')
TL = re.compile(r'(?:\s\[[^\[\]\n]*\])?\s\(#M?\d+(?: reply to #M?\d+)?\)(?:\s+<== match)?\s*$')
PH = re.compile(r'\[(?:private:[^\]]*|surname|phone|amount|email|IBAN|AHV number|card number|link[^\]]*|secret)\]')
def msgs(path):
    out = []
    for ln in open(path, encoding='utf-8').read().rstrip('\n').split('\n'):
        if ln.startswith('    ') and out and out[-1][0]:
            out[-1][1] += ' ' + ln.strip()
            continue
        m = P.match(ln)
        out.append([m.group(1), m.group(2)] if m else ['', ln])
    return out
A, B = msgs(sys.argv[1]), msgs(sys.argv[2])
errs, rewritten = [], 0
if len(A) != len(B):
    errs.append('message count %d vs %d' % (len(A), len(B)))
for (pa, ta), (pb, tb) in zip(A, B):
    if pa != pb:
        errs.append('prefix changed: %r -> %r' % (pa, pb))
    a_t, b_t = TL.search(ta), TL.search(tb)
    if (a_t.group(0) if a_t else '') != (b_t.group(0) if b_t else ''):
        errs.append('tail changed: %r -> %r' % (ta[-40:], tb[-40:]))
    ba, bb = TL.sub('', ta), TL.sub('', tb)
    na, nb = set(re.findall(r'\d+', ba)), set(re.findall(r'\d+', bb))
    if not nb <= na:
        errs.append('number added: %r' % tb)
    if not na <= nb:
        errs.append('number lost: %r' % tb)
    if set(PH.findall(ba)) != set(PH.findall(bb).__iter__()) - {'[not paraphrased]'}:
        errs.append('placeholders changed: %r -> %r' % (ba, bb))
    if not pa and ta.startswith('### '):
        if ta != tb:
            errs.append('header changed: %r' % tb)
    elif pa and ba != bb:
        rewritten += 1
print('\n'.join(errs) if errs else 'OK %d messages, %d rewritten' % (len(A), rewritten))
PY
res=$(python3 -I "$T/v4check.py" "$T/v4-anon.txt" "$T/v4.txt")
has "paraphrase: same messages, senders, times, refs and headers; every number and placeholder kept" "$res" "OK "
nre=$(echo "$res" | grep -o '[0-9]* rewritten' | grep -o '[0-9]*')
[ "${nre:-0}" -ge 120 ] && ok "paraphrase: the message bodies are rewritten ($nre)" || no "paraphrase: bodies rewritten" "$res"
for w in Diabetes Insulin Schluss Tinder Schulde Betreibig therapy Herzschmerz; do
  if grep '"p"' "$T/req.log" | grep -qi "$w"; then no "paraphrase: the model never sees removed text ($w)"; else ok "paraphrase: the model never sees removed text ($w)"; fi
  hasnt "paraphrase: removed text stays removed ($w)" "$out" "$w"; done
has "paraphrase: redactions still there" "$out" "[private: health]"
has "paraphrase: surname mask still there" "$out" "] Lena [surname]: "
np=$(grep -c '"p"' "$T/req.log"); nb=$(grep -o '"calls": [0-9]*' "$T/err" | grep -o '[0-9]*$')
eq "paraphrase: one call per batch ($np)" "$np" "$nb"
[ "${np:-0}" -ge 3 ] && [ "${np:-0}" -le 8 ] && ok "paraphrase: batched (165 messages in $np calls)" || no "paraphrase: batched" "$np"
has "paraphrase: stats" "$(cat "$T/err")" '"not_paraphrased": 0'
eq "paraphrase: temperature 0" "$(grep '"p"' "$T/req.log" | head -1 | jq_ 'd["body"]["temperature"]')" 0.0
has "paraphrase: schema = exactly one string per item" "$(grep '"p"' "$T/req.log" | head -1)" '"minItems": '
has "paraphrase: same language, facts and placeholders kept (prompt, v4.1)" "$(grep '"p"' "$T/req.log" | head -1 | jq_ 'd["body"]["messages"][0]["content"]')" "paraphrase in the SAME language as the item"
has "paraphrase: policy v4.1" "$(cat "$T/err")" '"policy": "llm-local-v4.1+regex-2026-10-13"'
# a hallucinated number or weekday: one retry, then the anonymized text, marked
mode hallucinate; : > "$T/req.log"
out=$(printf '[2026-10-12 18:02] Lena: Mir träffed eus am Samstig am 07:30 am Bahnhof Zürich (#12)\n[2026-10-12 18:03] Marco: Super, ich bringe zwei Kafi mit für alli (#13 reply to #12)\n' \
      | "$L" --paraphrase --stats 2>"$T/err"); rc=$?; mode ok
eq "hallucination: exit 0" "$rc" 0
has "hallucination: the line falls back to the anonymized text, marked" "$out" "[2026-10-12 18:02] Lena: [not paraphrased] Mir träffed eus am Samstig am 07:30 am Bahnhof Zürich (#12)"
hasnt "hallucination: the invented time never leaves" "$out" "08:30"
hasnt "hallucination: the invented weekday never leaves" "$out" "Monday"
has "hallucination: counted" "$(cat "$T/err")" '"retried": 2, "not_paraphrased": 2'
eq "hallucination: one batch call + one retry call" "$(grep -c '"p"' "$T/req.log")" 2
has "hallucination: the retry says what was wrong" "$(grep '"p"' "$T/req.log" | tail -1)" "the number 08:30 is not in it"
mode hallucinate-once; out=$(printf '[2026-10-12 18:02] Lena: Mir träffed eus am Samstig am 07:30 am Bahnhof Zürich (#12)\n' | "$L" --paraphrase --stats 2>"$T/err"); mode ok
has "hallucination fixed by the retry: paraphrased" "$out" "Lena: Says: Mir Samstig 07:30 Bahnhof Zürich (#12)"
has "hallucination fixed by the retry: counted" "$(cat "$T/err")" '"retried": 1, "not_paraphrased": 0'
mode dropph; out=$(printf '[2026-10-12 18:02] Lena: Ich chume nöd [private: health] aber am Samstig scho (#12)\n' | "$L" --paraphrase 2>/dev/null); mode ok
has "dropped placeholder: falls back, the redaction stays visible" "$out" "Lena: [not paraphrased] Ich chume nöd [private: health] aber am Samstig scho (#12)"
mode leakemail; out=$("$L" --paraphrase --owner-name Nico < "$FX/money.txt" 2>/dev/null); mode ok
hasnt "regex net after the paraphrase: an address the model adds is masked" "$out" "lena.brunner@example.org"
has "regex net after the paraphrase: [email]" "$out" "[email]"
# policy v3/v3.1 redactions still hold after the paraphrase: the owner's money (and health above)
: > "$T/req.log"
out=$("$L" --paraphrase --owner-name Nico < "$FX/money.txt" 2>/dev/null); rc=$?
eq "money + paraphrase: exit 0" "$rc" 0
for w in "25'000" "11'200" "6'400" "18'000" Tranchen Lohn booster; do
  hasnt "money + paraphrase: $w stays out" "$out" "$w"
  if grep '"p"' "$T/req.log" | grep -qF "$w"; then no "money + paraphrase: the model never sees $w"; else ok "money + paraphrase: the model never sees $w"; fi; done
has "money + paraphrase: [private: money] kept" "$out" "[private: money]"
has "money + paraphrase: times and dates kept" "$out" "21.10. 14:00"
has "money + paraphrase: train time kept" "$out" "08:32"
# --summary --paraphrase: summary lines with numbers that are not in the anonymized text are left out
: > "$T/req.log"
out=$("$L" --summary --paraphrase --owner-name Nico --stats < "$FX/money.txt" 2>"$T/err"); rc=$?
eq "summary + paraphrase: exit 0" "$rc" 0
hasnt "summary + paraphrase: a redacted figure in the summary never leaves" "$out" "11'200"
has "summary + paraphrase: the lines left out are counted" "$out" "[not paraphrased] "
has "summary + paraphrase: checked lines kept" "$out" "Bouldering Wednesday 19:00 at Minimum"
eq "summary + paraphrase: one retry" "$(grep -o '"step": "summary"' "$T/err" | wc -l | tr -d ' ')" 2
has "summary + paraphrase: the retry names the values" "$(grep 'IMPORTANT: your previous summary' "$T/req.log" | tail -1)" "11'200"
has "summary + paraphrase: stats" "$(cat "$T/err")" '"summary_check": {"retried": 1, "lines_left_out": '
# --keep-own-money (paperless) never paraphrases
: > "$T/req.log"; "$L" --keep-own-money --owner-name Nico < "$FX/money.txt" >/dev/null 2>&1
eq "paperless (--keep-own-money): no paraphrase call" "$(grep -c '"p"' "$T/req.log")" 0
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
pb = m.para_problems
cases = [("Mir träffed eus am Samstig am 07:30", "Meeting on Saturday at 07:30.", []),
         ("Mir träffed eus am Samstig am 07:30", "Meeting on Saturday at 08:30.", ["08:30"]),
         ("Mir träffed eus am Samstig", "Meeting on Monday.", ["Monday"]),
         ("Chunsch morn?", "Are you coming tomorrow?", []),
         ("Chunsch morn?", "Are you coming today?", ["today"]),
         ("Am 12.10. um halb acht", "On 12.10. at 7:30.", []),
         ("Mir sind zwei Lüt", "We are 2 people.", []),
         ("Mir sind zwei Lüt", "We are three people.", ["three"]),
         ("Tickets für 1'000 Lüt", "Tickets for 1,000 people.", []),
         ("Am 19:00 im Kino", "At 7 pm at the cinema.", []),
         ("Sie hät [private: health], chunt aber", "She has [private: health] but comes.", []),
         ("Sie hät [private: health], chunt aber", "She is ill but comes.", ["drops"]),
         ("Zahlt [amount]", "Pays [amount] [phone].", ["adds"]),
         ("Konzert im Oktober", "Concert in October.", []),
         ("Konzert am 3.", "Concert on 3 May.", ["May"]),
         ("We sat down at the bar", "They sat down at the bar.", [])]
for src, out, want in cases:
    got = pb(src, out)
    ok = all(any(w in g for g in got) for w in want) and (bool(got) == bool(want))
    print("CASE %s %s -> %s" % ("ok" if ok else "BAD", out, got))
units = m.para_units("### item 1\n[2026-10-12 18:02] Lena: Hallo zäme, wie gahts? [photo] (#M1 reply to #M2)\n### item 2\n"
                     "Subject: Ihre Bestellung | [bulk mail] | Ihr Paket kommt morgen | Attachments: a.pdf (1 page)")
print("UNITS", [u if u[0] == "keep" else (u[1], u[2], u[3]) for u in units])
print("HEADER", bool(m.BLOCK_HEADER.match("### Grouptrip (group, chat C1)")), bool(m.LINE_TAIL.search("x (#M3 reply to #M1)")))
PY
)
eq "v4 checks: numbers, weekdays, months, relative days, number words, placeholders" "$(echo "$unit" | grep -c '^CASE ok')" 16
echo "$unit" | grep '^CASE BAD' | head -5
has "v4 units: chat prefix and the shielded ref tail stay" "$unit" "('[2026-10-12 18:02] Lena: ', 'Hallo zäme, wie gahts?', ' [photo] (#M1 reply to #M2)')"
has "v4 units: mail subject and ' | ' parts" "$unit" "('Subject: ', 'Ihre Bestellung', ''), (' | ', '', '[bulk mail]'), (' | ', 'Ihr Paket kommt morgen', ''), (' | ', '', 'Attachments: a.pdf (1 page)')"
has "v4: tgread's shielded headers and refs are recognized" "$unit" "HEADER True True"
out=$(printf '### item 1\nSubject: Ihre Bestellung ist unterwegs | [bulk mail] | Ihr Paket kommt am 14.10. zwischen 08:00 und 12:00 | Attachments: a.pdf (1 page)\n' | "$L" --paraphrase 2>/dev/null)
has "v4 mail event line: parts kept in place" "$out" "Subject: Says: Ihre Bestellung | [bulk mail] | Says: Ihr Paket 14.10. 08:00 12:00 | Attachments: a.pdf (1 page)"
echo "# anonymization cache (--cache-dir, plan v2 #3, 2026-10-13)"
C="$T/anon-cache"; rm -rf "$C"
: > "$T/req.log"
"$L" --anonymize --owner-name Nico < "$T/chat.txt" > "$T/nc.txt"; n_nc=$(grep -c chat/completions "$T/req.log")
: > "$T/req.log"
"$L" --anonymize --owner-name Nico --cache-dir "$C" < "$T/chat.txt" > "$T/c1.txt"; rc=$?
eq "cache: cold run exit 0" "$rc" 0
eq "cache: cold run = no-cache output (same bytes)" "$(md5sum < "$T/c1.txt")" "$(md5sum < "$T/nc.txt")"
eq "cache: cold run sends the same requests" "$(grep -c chat/completions "$T/req.log")" "$n_nc"
: > "$T/req.log"
"$L" --anonymize --owner-name Nico --cache-dir "$C" --stats < "$T/chat.txt" > "$T/c2.txt" 2>"$T/err"
eq "cache: identical second call sends 0 LLM requests" "$(grep -c chat/completions "$T/req.log")" 0
eq "cache: identical second call returns the same bytes" "$(md5sum < "$T/c2.txt")" "$(md5sum < "$T/nc.txt")"
has "cache: stats count the hits" "$(cat "$T/err")" '"cache": {"detect": {"hits": '
has "cache: cross-message surname rule still applied" "$(cat "$T/c2.txt")" "] Lena [surname]: Morge!"
eq "cache: key and entries 0600, folders 0700" "$(find "$C" -type f ! -perm 600 | wc -l)$(find "$C" -type d ! -perm 700 | wc -l)" "00"
for w in Herzschmerz Schulde Betreibig; do
  if grep -rqi "$w" "$C"; then no "cache: no plaintext ($w)" "found"; else ok "cache: no plaintext ($w)"; fi; done
{ sed -n '2,$p' "$T/chat.txt"; echo "[2026-10-13 20:00] Lena: Mir träffed eus am Fritig um 19 Uhr am Bahnhof."; } > "$T/chat-slide.txt"
"$L" --anonymize --owner-name Nico < "$T/chat-slide.txt" > "$T/slide-nc.txt"
: > "$T/req.log"
"$L" --anonymize --owner-name Nico --cache-dir "$C" --stats < "$T/chat-slide.txt" > "$T/slide-c.txt" 2>"$T/err"
nch=$(grep -o '"chunks": [0-9]*' "$T/err" | head -1 | grep -o '[0-9]*$'); nd=$(grep -c '"identifiers"' "$T/req.log")
[ "$nd" -le 2 ] && [ "$nch" -ge 3 ] && ok "cache: sliding window (one message out, one in): $nd of $nch chunks to the LLM" \
  || no "cache: sliding window reuses the middle chunks" "$nd of $nch"
eq "cache: sliding window output = fresh run (same bytes)" "$(md5sum < "$T/slide-c.txt")" "$(md5sum < "$T/slide-nc.txt")"
find "$C" -name '*.json' -path '*detect*' | while read -r f; do printf 'garbage' > "$f"; done
: > "$T/req.log"
"$L" --anonymize --owner-name Nico --cache-dir "$C" < "$T/chat.txt" > "$T/c3.txt"; rc=$?
eq "cache: corrupt entries are misses (exit 0)" "$rc" 0
eq "cache: corrupt entries -> the work runs again, same bytes" "$(md5sum < "$T/c3.txt")" "$(md5sum < "$T/nc.txt")"
[ "$(grep -c '"identifiers"' "$T/req.log")" -ge 3 ] && ok "cache: corrupt entries re-ran the detection" || no "cache: corrupt entries re-ran" "$(grep -c '"identifiers"' "$T/req.log")"
printf 'x' > "$T/not-a-dir"
"$L" --anonymize --owner-name Nico --cache-dir "$T/not-a-dir/cache" < "$T/chat.txt" > "$T/c4.txt"; rc=$?
eq "cache: an unusable cache folder -> the work runs without it, same bytes" "$rc $(md5sum < "$T/c4.txt")" "0 $(md5sum < "$T/nc.txt")"
C2="$T/anon-cache-own"; rm -rf "$C2"
out=$(printf 'Mein eigener Text\n' | LLM_LOCAL_CACHE_DIR="$C2" "$L" --max-tokens 5 --cache-dir "$C2"); rc=$?
eq "cache: a plain prompt (the caller's own text) never opens a cache" "$rc$( [ -e "$C2" ] && echo ' created')" 0
: > "$T/req.log"
"$L" --summary --owner-name Nico --cache-dir "$C" < "$FX/money.txt" > "$T/s1.txt"; n1=$(grep -c chat/completions "$T/req.log")
: > "$T/req.log"
"$L" --summary --owner-name Nico --cache-dir "$C" < "$FX/money.txt" > "$T/s2.txt"
eq "cache: a repeated summary sends 0 LLM requests" "$(grep -c chat/completions "$T/req.log")" 0
eq "cache: a repeated summary returns the same bytes" "$(md5sum < "$T/s2.txt")" "$(md5sum < "$T/s1.txt")"
unit=$(python3 -I - "$L" <<'PY'
import importlib.machinery, importlib.util, sys, tempfile
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
m.http = lambda *a, **k: {"model_path": "/m/model-a.gguf"}
c = m.AnonCache(tempfile.mkdtemp())
k1 = c.key_for("detect", {"user": "x"}); c.model = "model-b.gguf"; k2 = c.key_for("detect", {"user": "x"})
m.POLICY = "llm-local-v9"; k3 = c.key_for("detect", {"user": "x"})
print("KEYS", len({k1, k2, k3}))
src = "Lena: Sie hat Herzschmerz."
d = {"private": [{"text": "Sie hat Herzschmerz.", "category": "health", "about": "Lena Muster"}], "identifiers": []}
r = m.to_refs(d, src, enc=c.crypt("e1"))
print("ROUND", m.from_refs(r, src, c.crypt("e1")) == d, "Herzschmerz" in str(r), "Muster" in str(r))
PY
)
has "cache: a model or policy change misses (3 different keys)" "$unit" "KEYS 3"
has "cache: positions + encrypted non-verbatim strings round-trip, no plaintext" "$unit" "ROUND True False False"
mode ok
"$L" --paraphrase --owner-name Nico < "$T/chat.txt" > "$T/p-nc.txt"
: > "$T/req.log"
"$L" --paraphrase --owner-name Nico --cache-dir "$C" < "$T/chat.txt" > "$T/p1.txt"; n1=$(grep -c chat/completions "$T/req.log")
eq "cache: paraphrase cold run = no-cache output (same bytes)" "$(md5sum < "$T/p1.txt")" "$(md5sum < "$T/p-nc.txt")"
: > "$T/req.log"
"$L" --paraphrase --owner-name Nico --cache-dir "$C" --stats < "$T/chat.txt" > "$T/p2.txt" 2>"$T/err"
eq "cache: identical paraphrase retry sends 0 LLM requests (cold: $n1)" "$(grep -c chat/completions "$T/req.log")" 0
eq "cache: identical paraphrase retry returns the same bytes" "$(md5sum < "$T/p2.txt")" "$(md5sum < "$T/p-nc.txt")"
has "cache: stats count paraphrase hits" "$(cat "$T/err")" '"para": {"hits": '
np=$(find "$C" -path '*/para/*' -name '*.json' | wc -l)
[ "$np" -ge 1 ] && ok "cache: paraphrase batches stored ($np)" || no "cache: paraphrase batches stored" "$np"
for w in Bahnhof Samstig Nico; do
  if grep -rq "$w" "$C/para" "$C/summary" 2>/dev/null; then no "cache: paraphrases and summaries sealed ($w)" "found"
  else ok "cache: paraphrases and summaries sealed ($w)"; fi; done
"$L" --paraphrase --owner-name Nico < "$T/chat-slide.txt" > "$T/pslide-nc.txt"
"$L" --paraphrase --owner-name Nico --cache-dir "$C" < "$T/chat.txt" > /dev/null
: > "$T/req.log"
"$L" --paraphrase --owner-name Nico --cache-dir "$C" < "$T/chat-slide.txt" > "$T/pslide-c.txt"
np=$(grep -c "Rewrite these" "$T/req.log")
[ "$np" -le 2 ] && ok "cache: sliding window: $np paraphrase batch call(s) (one message out, one in)" \
  || no "cache: sliding window reuses the paraphrase batches" "$np calls"
eq "cache: sliding window paraphrase = fresh run (same bytes)" "$(md5sum < "$T/pslide-c.txt")" "$(md5sum < "$T/pslide-nc.txt")"
mode hallucinate-once                             # a fresh cache: the one above holds the model's good answers
C3="$T/anon-cache-h"; rm -rf "$C3"
"$L" --paraphrase --owner-name Nico < "$T/chat.txt" > "$T/ph-nc.txt"
"$L" --paraphrase --owner-name Nico --cache-dir "$C3" < "$T/chat.txt" > "$T/ph1.txt"
: > "$T/req.log"
"$L" --paraphrase --owner-name Nico --cache-dir "$C3" < "$T/chat.txt" > "$T/ph2.txt"
eq "cache: hallucination + retry, cached: 0 LLM requests" "$(grep -c chat/completions "$T/req.log")" 0
grep -q 'not paraphrased' "$T/ph-nc.txt" && no "cache: hallucination test needs a fixed retry" "fallback" || ok "cache: hallucination fixed by the retry"
eq "cache: hallucination + retry, cold = no-cache (same bytes)" "$(md5sum < "$T/ph1.txt")" "$(md5sum < "$T/ph-nc.txt")"
eq "cache: hallucination + retry, cached = same bytes, checks run again" "$(md5sum < "$T/ph2.txt")" "$(md5sum < "$T/ph-nc.txt")"
mode ok
find "$C" -path '*/para/*' -name '*.json' | while read -r f; do printf '{"v":1,"data":{"x":"!!"}}' > "$f"; done
: > "$T/req.log"
"$L" --paraphrase --owner-name Nico --cache-dir "$C" < "$T/chat.txt" > "$T/p3.txt"; rc=$?
eq "cache: unreadable paraphrase entries are misses, same bytes" "$rc $(md5sum < "$T/p3.txt")" "0 $(md5sum < "$T/p-nc.txt")"
[ "$(grep -c chat/completions "$T/req.log")" -ge 1 ] && ok "cache: unreadable paraphrase entries re-ran the model" || no "cache: re-ran" 0

echo "# stats file for the vault's health metrics (LLM_LOCAL_STATS_FILE, 2026-10-13)"
rm -f "$T/llm-stats.jsonl"
out=$(printf 'Geheimtext Herzschmerz 4711\n' | LLM_LOCAL_STATS_FILE="$T/llm-stats.jsonl" "$L" --max-tokens 20); rc=$?
eq "stats file: plain run exit 0" "$rc" 0
st=$(cat "$T/llm-stats.jsonl" 2>/dev/null)
has "stats file: one line with calls and tokens" "$st" '"calls": 1, "prompt_tokens": '
has "stats file: reused prompt tokens" "$st" '"cached_tokens": 7'
hasnt "stats file: never any text" "$st" "Herzschmerz"
eq "stats file: mode 0600" "$(stat -c %a "$T/llm-stats.jsonl")" 600
out=$(LLM_LOCAL_STATS_FILE="$T/llm-stats.jsonl" "$L" --anonymize --owner-name Nico < "$FX/money.txt" 2>/dev/null)
eq "stats file: appended per run" "$(wc -l < "$T/llm-stats.jsonl" | tr -d ' ')" 2
hasnt "stats file: no chat text after an anonymize run" "$(cat "$T/llm-stats.jsonl")" "Tranchen"
out=$(printf 'x\n' | "$L" --max-tokens 5); eq "no stats file without the env" "$(wc -l < "$T/llm-stats.jsonl" | tr -d ' ')" 2

echo "# policy v4.1: paraphrases keep the source language; times, negations and number roles checked"
has "v4.1 prompt: never translate, Swiss German stays" "$(grep '"p"' "$T/req.log" | head -1 | jq_ 'd["body"]["messages"][0]["content"]')" "Never translate. Swiss German stays Swiss German"
unit=$(python3 -I - "$L" <<'PY2'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
cases = [("dassmer am 4i scho gnueg lüt sind", "We need enough people by the 4th.", "clock time"),
         ("dassmer am 4i scho gnueg lüt sind", "Am 4i sind mer gnueg Lüt.", None),
         ("Mir gönd am vieri los", "Mir gönd am vieri.", None),
         ("Mir gönd am vieri los", "We leave on the fourth.", "clock time"),
         ("Ich chume am 17i", "I come at 5 pm.", "translates"),
         ("Ich chume am 17i", "Chunt am 5 pm.", None),
         ("Am 4. isch Party bim PersonG", "Party bim PersonG um 4 Uhr.", "is a date"),
         ("Am 24. Oktober isch Party", "Party am 24. Oktober.", None),
         ("Kino um 19.30 im Kosmos", "Kino im Kosmos um 19.30.", None),
         ("Mir träffed eus am 12.10. am 07:30", "Träffe am 12.10. am 07:30.", None),
         ("Da meh nid chan reserviere müendmer scho so früeh gah", "Early booking is required.", "negation"),
         ("Da meh nid chan reserviere müendmer scho so früeh gah", "Will mer nid chönd reserviere, müend mer früeh gah.", None),
         ("Ich ha no nid gässe und mues no schnell is Coop", "Het no nid gässe, mues no in Coop.", None),
         ("Mir chömed morn am 8i ane", "We come tomorrow at 8.", "translates"),
         ("We meet at 8 tomorrow, can't wait", "Meeting at 8 tomorrow, can't wait.", None),
         ("There are no tickets left for Friday", "Tickets for Friday are sold out.", "negation")]
for src, out, want in cases:
    got = m._ok_item(src, out) or []
    ok = (any(want in g for g in got) if want else not got)
    print("CASE41 %s %s -> %s" % ("ok" if ok else "BAD", out, got))
print("SUMLINE", m.para_problems("Mir sind am 4i dete", "- Meeting by the 4th", required=False))
print("ROLES", sorted((k, sorted(v)) for k, v in m.num_roles("am 4i, halbi 5, 17i, am 3.11., 21.11. am 06:15, am vieri, 4th").items()))
PY2
)
eq "v4.1 checks: Swiss times, number roles, negations, no translation" "$(echo "$unit" | grep -c '^CASE41 ok')" 16
echo "$unit" | grep '^CASE41 BAD' | head -5
has "v4.1: summary lines get the role check too" "$unit" "4 is a clock time in the item"
has "v4.1: Swiss time and date forms" "$unit" "ROLES [(3, ['date']), (4, ['date', 'time']), (5, ['time']), (6, ['time']), (11, ['date']), (17, ['time']), (21, ['date'])]"
res=$(python3 -I "$FX/swiss_eval.py" "$L" "$FX/swiss-para.txt" "$FX/swiss-para-good.txt"); rc=$?
eq "swiss eval: faithful Swiss German paraphrases pass (12 lines)" "$rc" 0
sed '1s/.*/[2026-10-12 18:02] Mia: Da mer nümme chan reserviere, müemmer scho früeh gah. (#1)/' "$FX/swiss-para-good.txt" > "$T/nuemme.txt"
res=$(python3 -I "$FX/swiss_eval.py" "$L" "$FX/swiss-para.txt" "$T/nuemme.txt"); rc=$?
eq "swiss eval: 'nümme' (no longer) keeps the negation of #1" "$rc" 0
res=$(printf '[2026-10-12 18:02] Mia: Early booking is required. (#1)\n[2026-10-12 18:03] Mia: We need enough people by the 4th. (#2)\n' > "$T/bad.txt"; python3 -I "$FX/swiss_eval.py" "$L" "$FX/swiss-para.txt" "$T/bad.txt"); rc=$?
eq "swiss eval: the 13.10 translations fail" "$rc" 1
has "swiss eval: dropped negation caught" "$res" "drops a negation"
has "swiss eval: time turned into an ordinal caught" "$res" "4 is a clock time in the item, not a date or ordinal"
: > "$T/req.log"; mode swissbad
out=$("$L" --paraphrase --stats < "$FX/swiss-para.txt" 2>"$T/err"); rc=$?; mode ok
eq "swissbad: exit 0" "$rc" 0
has "swissbad: the dropped negation falls back to the anonymized wording" "$out" "Mia: [not paraphrased] Da meh nid chan reserviere müendmer scho so früeh gah (#1)"
has "swissbad: 'by the 4th' falls back" "$out" "Mia: [not paraphrased] dassmer am 4i scho gnueg lüt sind (#2)"
has "swissbad: retried once, then counted" "$(cat "$T/err")" '"retried": 2, "not_paraphrased": 2'
has "swissbad: the retry asks for the item's own language" "$(grep 'changed facts' "$T/req.log" | tail -1)" "never translate"
hasnt "swissbad: no English leaves" "$out" "booking is required"

echo "# 2026-10-14 LLM bench gaps: Swiss money words, investment/debt backstop, language change"
unit=$(python3 -I - "$L" <<'PY3'
import importlib.machinery, importlib.util, sys
l = importlib.machinery.SourceFileLoader("llm", sys.argv[1]); s = importlib.util.spec_from_loader("llm", l)
m = importlib.util.module_from_spec(s); l.exec_module(m)
chat = [("Ich ha mini Stell verlore und ha jetzt 12'000 Franke Schulde bi de Bank",
         "Ich ha mini Stell verlore und ha jetzt [amount] Schulde bi de Bank"),
        ("Er het 12’000 Fränkli Schulde", "Er het [amount] Schulde"),
        ("Si het 12´000 Stutz übercho", "Si het [amount] übercho"),
        ("Das choschtet 7'500 Chlotz", "Das choschtet [amount]"),
        ("Ha 12k Schulde bi de Bank", "Ha [amount] Schulde bi de Bank"),
        ("Mir händ 12k Franke gspart", "Mir händ [amount] gspart"),
        ("CHF 12 000 uf em Konto", "[amount] uf em Konto"),
        ("12 000 Franke Schulde", "[amount] Schulde"),
        ("chf 6500 für s Auto", "[amount] für s Auto"),
        ("Fr. 6'500.– überwiese", "[amount] überwiese"),
        ("6500 Fr Schulde", "[amount] Schulde"),
        ("Er schuldet 12 000 Franke", "Er schuldet [amount]"),
        ("sfr 9000 Bonus", "[amount] Bonus"),
        ("zwölftausend Franke Schulde", "[amount] Schulde"),
        ("füfzähtuusig Stutz", "[amount]"),
        ("twelve thousand dollars of debt", "[amount] of debt"),
        ("12 Tausend Franke", "[amount]"),
        ("3 Mille Lohn", "[amount] Lohn"),
        ("Rechnig vo 240 isch zahlt, Adresse: Examplestrasse 1, 1234 Exampletown",
         "Rechnig vo [amount] isch zahlt, Adresse: Examplestrasse 1, 1234 Exampletown"),
        ("Mir sind tausend Lüt gsi", None), ("hundert Prozent sicher, dass er zahlt", None),
        ("Du schuldsch mir no 18.- fürs Kino", None), ("Gleis 3a ab 17:42, Schulde hin oder her", None),
        ("Schulde zahle mer am 6i, Treffpunkt 19.30 am 24.10.", None),
        ("bezahlt, Lieferung in 1234 Exampletown", None), ("Zug am 3.11. um 17:42, mir sind 40 Lüt", None)]
for src, want in chat:
    got = m.money_pass(src)[0]
    print("NET14 %s %s -> %s" % ("ok" if got == (want or src) else "BAD", src, got))
mail = [("Total CHF 12 000", "Total [amount]"), ("zwölftausend Franke", "[amount]"),
        ("Mir sind tausend Lüt", None), ("CH-1234 Exampletown, Rechnig bezahlt", None)]
for src, want in mail:
    got = m.money_pass(src, True)[0]
    print("NET14 %s %s -> %s" % ("ok" if got == (want or src) else "BAD", src, got))
P = "[private: money]"
bs = [("[2026-10-12 18:10] Nico: Ich habe gestern 15'000 Franken in den Index-ETF investiert und plane nächsten "
       "Monat nochmals 8000. (#10)", "[2026-10-12 18:10] Nico: %s (#10)" % P),
      ("[2026-10-12 18:06] Luca: Ich ha mini Stell verlore und ha jetzt 12'000 Franke Schulde bi de Bank, bitte säg das "
       "niemertem. (#6)", "[2026-10-12 18:06] Luca: %s (#6)" % P),
      ("Ha gester 15k investiert.", P), ("Kevin het 5 Aktie vo Nestlé gchauft.", P), ("Mis Depot isch im Minus.", P),
      ("I bought more BTC yesterday.", P), ("Sie haben 10 Aktien gekauft.", P), ("Er isch pleite.", P),
      ("Ich bi i de Betreibig.", P), ("My portfolio is down 20% this year.", P),
      ("Mir händ jetzt en ETF-Sparplan, 500 im Monet.", P), ("Subject: Ihr Depotauszug Q3", "Subject: " + P),
      ("- You invested [amount] in an ETF.", "- " + P),
      ("[2026-10-12 18:10] Nico: Kino am Fritig? Ich ha übrigens BTC gchauft. Bis denn! (#10)",
       "[2026-10-12 18:10] Nico: Kino am Fritig? %s Bis denn! (#10)" % P),
      ("Was isch eigentlich en ETF?", None), ("Nvidia investiert in OpenAI.", None),
      ("Ich ha vill Ziit in das Projekt investiert.", None), ("We have a lot of technical debt in this repo.", None),
      ("Die Schulden der USA steigen.", None), ("Ich studier a de ETH.", None), ("Is it in stock?", None),
      ("Ich ha e investigative Artikel gläse.", None), ("Du schuldsch mir no 18.- fürs Kino 😄", None)]
for src, want in bs:
    got = m.regex_pass(src)[0]
    print("BS14 %s %s -> %s" % ("ok" if got == (want or src) else "BAD", src, got))
print("BSADMIN " + m.regex_pass("Ich habe 15'000 in den ETF investiert.", money=False)[0])
lang = [("Mein Lohn wurde auf [amount] im Monat erhöht, endlich!", "My salary increased to [amount] per month, finally!",
         "translates the item into English"),
        ("Mein Lohn wurde auf [amount] im Monat erhöht, endlich!", "Lohn auf [amount] im Monat erhöht, endlich.", None),
        ("Treffen am Samstag um 18 Uhr bei Anna", "Meeting on Saturday at 18 at Anna's.", "translates"),
        ("Wir treffen uns am 24. Oktober um 19:30 im Restaurant Krone", "We meet on 24 October at 19:30 at Restaurant Krone.",
         "translates"),
        ("I won't make it to the gym tomorrow.", "Ich schaffe es morgen nicht ins Gym.", "translates the item into German"),
        ("Haha merci viel mal, isch mega schön gsi geschter!", "Danke, es war gestern sehr schön.",
         "Swiss German into Standard German"),
        ("Haha merci viel mal, isch mega schön gsi geschter!", "Merci, isch geschter mega schön gsi.", None),
        ("Call me after 8, the wifi password is [secret].", "Call after 8; the wifi password is [secret].", None),
        ("Mir gönd am 3.11. uf Züri as Konzert", "Am 3.11. gömmer uf Züri as Konzert.", None),
        ("I am at home on Monday, call me", "At home on Monday, call me.", None),
        ("[private: health] Am Dunschtig chum ich drum nöd as Training.",
         "[private: health] Chunt am Dunschtig nöd as Training.", None),
        ("Die Hochzeit ist nicht am 12. sondern am 19. Dezember, Apéro ab 14 Uhr.",      # Gemma-4 bench, mixed batch
         "D Hochziit isch nöd am 12., sondern am 19. Dezember, Apéro ab 14 Uhr.", "Standard German into Swiss German"),
        ("[private: health] Das Abendessen am Samstag um 18 Uhr findet trotzdem statt, ich bin dabei.",
         "[private: health] S Znacht am Samstig um 18 Uhr findet trotzdem statt.", "Standard German into Swiss German"),
        ("Die Hochzeit ist nicht am 12. sondern am 19. Dezember.", "Die Hochzeit ist nicht am 12., sondern am 19. Dezember.",
         None),
        ("Kannst du mir das Geld bis Freitag schicken?", "Kannst du mir das Geld bis am Fritig schicken?", None)]
for src, out, want in lang:
    got = m._ok_item(src, out) or []
    ok = any(want in g for g in got) if want else not got
    print("LANG14 %s %s -> %s" % ("ok" if ok else "BAD", out, got))
PY3
)
eq "money net: Swiss currency words, separators, k/Tausend/tuusig/Mille, amounts in words; postcodes, times, dates kept" "$(echo "$unit" | grep -c '^NET14 ok')" 30
echo "$unit" | grep '^NET14 BAD' | head -5
eq "money backstop: investments and debts -> [private: money]; questions, news, time, tech debt, ETH, cinema kept" "$(echo "$unit" | grep -c '^BS14 ok')" 23
echo "$unit" | grep '^BS14 BAD' | head -5
has "money backstop: not with --keep-own-money (admin documents)" "$unit" "BSADMIN Ich habe 15'000 in den ETF investiert."
eq "language check: a German item that only leans German, English items, Swiss <-> Standard German" "$(echo "$unit" | grep -c '^LANG14 ok')" 15
echo "$unit" | grep '^LANG14 BAD' | head -5
mode lazy; out=$("$L" --anonymize --owner-name "Nico Keller" --stats < "$FX/bench-2026-10-14.txt" 2>"$T/err"); rc=$?; mode ok
eq "bench set, detector found nothing: exit 0" "$rc" 0
has "bench #6 (debts, Swiss German) -> [private: money]" "$out" "Luca: [private: money] (#6)"
has "bench #10 (owner's ETF investment) -> [private: money]" "$out" "You: [private: money] (#10)"
for w in "12'000" "Franke" "Schulde" "MSCI" "ETF" "15'000" "8000" "9'500" "079 412" "CH93" "756.1234" "5168"; do
  hasnt "bench set (no detector): $w gone" "$out" "$w"; done
for k in "am 24. Oktober um 19:30 im Restaurant Krone in Examplecity, nicht erst um 20 Uhr" "Mir gönd am 3.11. uf Züri" \
  "de Zug fahrt am 17:42 ab Winti" "bis am Fritig am 6i" "Iigang ab 22i, mir sind öppe 40 Lüt" \
  "Die Hochzeit ist nicht am 12. sondern am 19. Dezember, Apéro ab 14 Uhr" "My flight lands at 07:05 on Nov 21" \
  "Mini neui Nummer isch [phone]" "Call me on [phone] after 8"; do has "bench set: kept $k" "$out" "$k"; done
has "bench set: stats count the backstop" "$(cat "$T/err")" '"private_money": 2'
out=$(printf '[2026-10-12 18:06] Luca Brunner: Ich ha 12k Franke Schulde bi de Bank.\n[2026-10-12 18:07] Luca Brunner: Kino am Fritig?\n' \
  | { mode lazy; "$L" --anonymize --owner-name Nico; }); mode ok
has "backstop: the writer's surname is masked like for the model's passages" "$out" "Luca [surname]: [private: money]"
has "backstop: the surname goes on his other lines too" "$out" "Luca [surname]: Kino am Fritig?"
hasnt "backstop: no surname left" "$out" "Brunner"
: > "$T/req.log"; mode translate-once
out=$(printf '[2026-10-12 18:15] Kevin: Mein Lohn wurde auf 9500 Franken im Monat erhöht, endlich! (#15)\n' \
  | "$L" --anonymize --paraphrase --owner-name Nico --stats 2>"$T/err"); rc=$?; mode ok
eq "translated paraphrase: exit 0" "$rc" 0
hasnt "translated paraphrase (bench #15) is caught" "$out" "My salary"
has "translated paraphrase: retried in German" "$out" "Kevin: Says: Mein Lohn"
has "translated paraphrase: the retry names both languages" "$(grep 'changed facts' "$T/req.log" | tail -1)" "translates the item into English; write it in German like the item"
has "translated paraphrase: retried once, no fallback" "$(cat "$T/err")" '"retried": 1, "not_paraphrased": 0'
mode translate
out=$(printf '[2026-10-12 18:15] Kevin: Mein Lohn wurde auf 9500 Franken im Monat erhöht, endlich! (#15)\n' \
  | "$L" --anonymize --paraphrase --owner-name Nico --stats 2>"$T/err"); mode ok
has "still translated after the retry: the anonymized German original, marked" "$out" "Kevin: [not paraphrased] Mein Lohn wurde auf [amount] im Monat erhöht, endlich! (#15)"
hasnt "still translated: no English leaves" "$out" "My salary"
out=$("$L" --anonymize --paraphrase --owner-name "Nico Keller" < "$FX/bench-2026-10-14.txt")
has "bench set paraphrased: #6 stays [private: money]" "$out" "Luca: [private: money] (#6)"
has "bench set paraphrased: #10 stays [private: money]" "$out" "You: [private: money] (#10)"
hasnt "bench set paraphrased: no ETF" "$out" "ETF"
hasnt "bench set paraphrased: no Schulde" "$out" "Schulde"

echo "# real model (${LLM_LOCAL_REAL_BACKEND:-local}: llama-server on 127.0.0.1:8179, or the privacy vault's)"
unset LLM_LOCAL_PORT LLM_LOCAL_CTL
export LLM_LOCAL_BACKEND=${LLM_LOCAL_REAL_BACKEND:-local}
real_model=$("$CTLF" info 2>/dev/null | sed -n 's/^model=\([^ ]*\) .*/\1/p')
if [ "${LLM_LOCAL_SKIP_REAL:-0}" = 1 ]; then
  echo "skip - real smoke test (LLM_LOCAL_SKIP_REAL=1)"
elif [ "$LLM_LOCAL_BACKEND" = local ] && [ ! -e "$real_model" ] && ! "$CTLF" status >/dev/null 2>&1; then
  echo "skip - real smoke test (no local model set up: ${real_model:-model} missing, no llama-server running; see llm-server-ctl install)"
  if [ $REAL = 1 ] || [ $REALMONEY = 1 ] || [ $REALSWISS = 1 ]; then no "real-model checks need a model"; fi
else
  out=$(echo "Antworte nur mit dem Wort OK." | "$L" --max-tokens 10 --stats 2>"$T/err"); rc=$?
  eq "real smoke test exit 0" "$rc" 0
  if printf '%s' "$out" | grep -qi '\bok\b'; then ok "real model answers OK"; else no "real model answers OK" "$out"; fi
  grep -o '"gen_tps": [0-9.]*' "$T/err" | head -1 | sed 's/^/       /'
  if [ $REAL = 1 ] || [ $REALMONEY = 1 ]; then
    OUTDIR=${LLM_LOCAL_REAL_OUT:-$T}
    t0=$(date +%s)
    "$L" --anonymize --owner-name Nico --stats < "$FX/money.txt" > "$OUTDIR/real-money.txt" 2>"$T/err"; eq "real money anonymize exit 0" "$?" 0
    echo "       ($(( $(date +%s) - t0 )) s)"; grep -o '"private_by_category": {[^}]*}\|"regex_pass_hits": {[^}]*}' "$T/err" | sed 's/^/       /'
    res=$(python3 -I "$FX/planted.py" check-money "$OUTDIR/real-money.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real money: owner's investment, salary, purchase, deal redacted; meeting, trip, bill due date kept" "$rc" 0
    "$L" --summary --owner-name Nico < "$FX/money.txt" > "$OUTDIR/real-money-sum.txt" 2>"$T/err"; eq "real money summary exit 0" "$?" 0
    res=$(python3 -I "$FX/planted.py" check-money-summary "$OUTDIR/real-money-sum.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real money summary: no figures or details, plans present" "$rc" 0
  fi
  if [ $REALSWISS = 1 ]; then
    OUTDIR=${LLM_LOCAL_REAL_OUT:-$T}
    t0=$(date +%s)
    "$L" --paraphrase --stats < "$FX/swiss-para.txt" > "$OUTDIR/real-swiss.txt" 2>"$T/err"; eq "real swiss paraphrase exit 0" "$?" 0
    echo "       ($(( $(date +%s) - t0 )) s)"; grep -o '"paraphrase": {[^}]*}' "$T/err" | sed 's/^/       /'
    res=$(python3 -I "$FX/swiss_eval.py" "$L" "$FX/swiss-para.txt" "$OUTDIR/real-swiss.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real swiss: times stay times, negations kept, no translation (or the safe fallback)" "$rc" 0
  fi
  if [ $REAL = 1 ]; then
    OUTDIR=${LLM_LOCAL_REAL_OUT:-$T}
    t0=$(date +%s)
    "$L" --anonymize --owner-name Nico --stats < "$T/chat.txt" > "$OUTDIR/real-anon.txt" 2>"$T/err"; eq "real anonymize exit 0" "$?" 0
    echo "       ($(( $(date +%s) - t0 )) s)"; sed 's/^/       /' "$T/err"
    res=$(python3 -I "$FX/planted.py" check-anon "$OUTDIR/real-anon.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real anonymize: identifiers gone, private redacted by category, names/addresses/facts kept" "$rc" 0
    t0=$(date +%s)
    "$L" --summary --owner-name Nico --stats < "$T/chat.txt" > "$OUTDIR/real-sum.txt" 2>"$T/err"; eq "real summary exit 0" "$?" 0
    echo "       ($(( $(date +%s) - t0 )) s)"
    res=$(python3 -I "$FX/planted.py" check-summary "$OUTDIR/real-sum.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real summary: no identifiers or private details, key facts present" "$rc" 0
    t0=$(date +%s)
    "$L" --anonymize --strict --owner-name Nico --stats < "$T/chat.txt" > "$OUTDIR/real-strict.txt" 2>"$T/err"; eq "real strict exit 0" "$?" 0
    echo "       ($(( $(date +%s) - t0 )) s)"
    res=$(python3 -I "$FX/planted.py" check-strict "$OUTDIR/real-strict.txt"); rc=$?; echo "$res" | sed 's/^/       /'
    eq "real strict: no names/address/identifiers, private redacted, facts kept" "$rc" 0
  fi
fi

echo "# $pass passed, $fail failed"
[ $fail = 0 ]
