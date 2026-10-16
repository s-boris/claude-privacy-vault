#!/bin/sh
# All test suites inside the vault image: `vault admin test` runs this in a throwaway container
# (no network, read-only root, /tmp tmpfs). Real-model checks need the running vault (see the vault skill).
set -u
fail=0
echo "# vault unit tests"
/usr/bin/python3 -I /opt/vault/tests/test_vault.py || fail=1
echo "# Telegram-approved deploys (request file, card from the runner's review, the owner's tap, results, expiry)"
/usr/bin/python3 -I /opt/vault/tests/test_deploys.py || fail=1
echo "# media requests (list, approval bundle, facts only, type checks, extraction, acks)"
/usr/bin/python3 -I /opt/vault/tests/test_media.py || fail=1
echo "# photos (16.10): OCR in the vault, photo facts, poisoned image text, event feed photo text + floor, no text out"
/usr/bin/python3 -I /opt/vault/tests/test_photos.py || fail=1
echo "# facts, find, calendar suggestions (plan v2 #6, #10, #11)"
/usr/bin/python3 -I /opt/vault/tests/test_facts.py || fail=1
echo "# answers, not text (privacy plan A: /answer, digest, hits, text only on the owner's ✅)"
/usr/bin/python3 -I /opt/vault/tests/test_answer.py || fail=1
echo "# answer eval fixtures consistent (the scored run needs the model: eval_answers.py --real)"
/usr/bin/python3 -I /opt/vault/tests/eval_answers.py || fail=1
echo "# follow-up ask sessions (memory plan C1: TTL, turns, scope lock, purge, same messages, switch)"
/usr/bin/python3 -I /opt/vault/tests/test_sessions.py || fail=1
echo "# person cards (memory plan C2: metadata cards, relation only from the owner, forget, purge, switches)"
/usr/bin/python3 -I /opt/vault/tests/test_people.py || fail=1
echo "# person cards v2 (memory plan C5: open asks, topics, poisoning suite, switch VAULT_PEOPLE_ASKS)"
/usr/bin/python3 -I /opt/vault/tests/test_people_v2.py || fail=1
echo "# semantic index C3 (chunker, sampling, RRF, metrics, sqlite-vec load + KNN, embed server, bake-off with fakes)"
VAULT_VEC_REQUIRED=1 VAULT_VEC_PATH=/opt/vault/lib/vec0 /usr/bin/python3 -I /opt/vault/tests/test_index.py || fail=1
echo "# gmail source tests (fake IMAP: read-only guarantee, IDLE, triage, API)"
/usr/bin/python3 -I /opt/vault/tests/test_gmail.py || fail=1
echo "# tgread tests (vendored copy, venv python)"
TGREAD_BIN=/opt/vault/vendor/tgread TGREAD_PY=/opt/vault/venv/bin/python3 SECRETSCAN_BIN=/opt/vault/vendor/secretscan.py \
  /opt/vault/venv/bin/python3 -I -W ignore::DeprecationWarning /opt/vault/tests/tgread/test_tgread.py || fail=1
if [ -f /opt/vault/tests/test_finance.py ]; then   # the bank-export intake is not in the public tree
  echo "# finance intake tests (Firefly sync; fake Telegram + Firefly)"
  /usr/bin/python3 -I /opt/vault/tests/test_finance.py || fail=1
  echo "# Firefly sync rules config (loader, importer on fixtures with the example, no personal data in code)"
  VAULT_FINANCE_TEST_PY=/opt/vault/venv/bin/python3 /usr/bin/python3 -I /opt/vault/tests/test_firefly_rules.py || fail=1
fi
echo "# document intake tests (photos/PDFs via the vault bot -> paperless; fake Telegram + paperless)"
/usr/bin/python3 -I /opt/vault/tests/test_intake.py || fail=1
echo "# mail import (Gmail -> paperless backfill: scan, rules, model batches, duplicates, import; aggregates only)"
/usr/bin/python3 -I /opt/vault/tests/test_mailimport.py || fail=1
echo "# Home Assistant inventory (metadata only: no values, coordinates, SSIDs; other people excluded)"
/usr/bin/python3 -I /opt/vault/tests/test_ha.py || fail=1
echo "# Home Assistant status feed (read-only websocket guard, coarsening, debounce/rate, fake HA end to end)"
/usr/bin/python3 -I /opt/vault/tests/test_ha_live.py || fail=1
echo "# llm-local tests (mocked)"
LLM_LOCAL_BIN=/opt/vault/vendor/llm-local LLM_LOCAL_SKIP_REAL=1 bash /opt/vault/tests/llm-local/run.sh || fail=1
[ $fail = 0 ] && echo "ALL SUITES PASSED" || echo "SOME SUITES FAILED"
exit $fail
