# Contributing

Thanks for your interest. The vault is a personal project published as a reference. Fixes, hardening, tests and
documentation are the most welcome; open an issue first for anything larger, such as a new source or a change to
the privacy pipeline.

Security problems: do not open an issue or pull request. See [SECURITY.md](SECURITY.md).

## Pull requests

- **Small and focused.** One change per pull request, with a short description of what and why. Changes to the
  privacy pipeline, the approval flow, `Dockerfile` or `docker-compose.yml` should say what they do to the
  [threat model](docs/DESIGN.md#threat-model).
- **Run the tests.** `tools/run-tests.sh` runs the offline suites with the system Python. `tests/test_index.py`
  needs sqlite-vec (`VAULT_VEC_PATH`) and `tests/tgread` a Telethon virtualenv (`TGREAD_PY`); they run when those
  are set. `tests/run-all.sh` runs everything inside the built image without network.
- **Add tests** for behaviour you change. Tests must stay offline: use the fake Telegram, IMAP, paperless,
  Firefly and Home Assistant servers and the mock LLM that the suites already provide.
- **Keep the design doc current.** Update [docs/DESIGN.md](docs/DESIGN.md) when you change routes, limits,
  switches or guarantees.
- **Pin dependencies.** New Python dependencies go into `requirements/*.txt` with `--require-hashes`; new
  downloads in the `Dockerfile` need a version and a checksum.
- `vendor/llm-local`, `vendor/secretscan.py`, `vendor/bills`, `tests/tgread/` and `tests/llm-local/` are copies of
  tools from [claude-assistant](https://github.com/s-boris/claude-assistant). Changes there are best made in that
  repository.

## Never commit personal data or secrets

- No tokens, session files, `.env` files, app passwords, model outputs from real data, or exported chats, mails
  or documents.
- Test data must be synthetic: invented names, `example.com` / `example.net` addresses, documentation IP ranges
  (`198.51.100.x`, `203.0.113.x`), fake ids.
- Anonymizer test cases with realistic-looking private content must be invented, not taken from real
  conversations.

CI runs the tests, [gitleaks](https://github.com/gitleaks/gitleaks) and a privacy gate (PII patterns, prose
checks and a private denylist) on pushes to `main` and on pull requests. A hit blocks the merge. Pull requests
from forks don't get the denylist secret, so the maintainer re-runs the full check before merging.

## Licensing

No sign-off, DCO or CLA is required. By submitting a contribution you agree that it is licensed under the
[Apache License 2.0](LICENSE), the same license as the project ("inbound = outbound", as in section 5 of the
license).
