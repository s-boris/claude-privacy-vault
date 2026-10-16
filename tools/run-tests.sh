#!/usr/bin/env bash
# Offline vault tests with the system python3 (no image needed). tests/test_index.py needs sqlite-vec
# (VAULT_VEC_PATH=.../vec0) and tests/tgread a Telethon venv (TGREAD_PY=.../python3): they run only when set.
# Inside the built image: `vault admin test` (= tests/run-all.sh).
set -u
cd "$(dirname "$0")/.."
LOG=$(mktemp -d); fail=0
for t in test_vault test_deploys test_gmail test_media test_photos test_facts test_sessions test_people test_people_v2 test_answer eval_answers \
         test_intake test_ha test_ha_live; do
  if timeout 900 python3 -I tests/$t.py >"$LOG/$t.log" 2>&1 </dev/null; then echo "ok   $t"; else echo "FAIL $t ($LOG/$t.log)"; fail=1; fi
done
if [ -n "${VAULT_VEC_PATH:-}" ]; then python3 -I tests/test_index.py >"$LOG/index.log" 2>&1 && echo "ok   test_index" || { echo "FAIL test_index"; fail=1; }; fi
if LLM_LOCAL_BIN=$PWD/vendor/llm-local LLM_LOCAL_SKIP_REAL=1 bash tests/llm-local/run.sh >"$LOG/llm-local.log" 2>&1 </dev/null; then
  echo "ok   llm-local (mocked)"; else echo "FAIL llm-local ($LOG/llm-local.log)"; fail=1; fi
if [ -n "${TGREAD_PY:-}" ]; then TGREAD_BIN=$PWD/vendor/tgread SECRETSCAN_BIN=$PWD/vendor/secretscan.py bash tests/tgread/run.sh \
  >"$LOG/tgread.log" 2>&1 && echo "ok   tgread" || { echo "FAIL tgread"; fail=1; }; fi
exit $fail
