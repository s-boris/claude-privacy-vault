#!/bin/bash
# Offline tests for tgread (~/opt/claude-vault/vendor/tgread; env TGREAD_BIN, TGREAD_PY, SECRETSCAN_BIN) (fake Telegram inside the real Telethon client; sockets disabled).
# Usage: ~/opt/tgread-tests/run.sh [-v] [TestClass[.test_name] ...]
set -euo pipefail
cd "$(dirname "$0")"
exec "${TGREAD_PY:-/home/node/opt/tgread-venv/bin/python3}" -I -W ignore::DeprecationWarning ./test_tgread.py "$@"
