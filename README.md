# claude-privacy-vault

A privacy vault for a personal AI assistant. It keeps your raw private data (Telegram chats, Gmail, paperless-ngx
documents, Firefly III finances, Home Assistant location) and the credentials for it in its own hardened
container, and answers the assistant's questions with a **local** LLM. The assistant gets answers, not text.

It is built for [claude-assistant](https://github.com/s-boris/claude-assistant), an always-on Claude Code
session. Everything that session reads is sent to a cloud API, so private data must not reach it in the first
place.

> Personal project, published as a reference. Read [Security](#security-model) and [Limitations](#limitations)
> before trusting it with your data. The full technical design is in [docs/DESIGN.md](docs/DESIGN.md).

## What it does

- **Answers, not text.** `POST /answer` ("did anyone ask me to call back?", "when is the dentist?") is answered
  inside the vault by the local model and checked in code. What comes back is a yes/no, a date or time, a first
  name, a category, a count or a short card, never the underlying messages.
- **Approval for anything raw.** Message text (anonymized), exact wording, original files or exact location
  leave only after you tap ✅ in the vault's **own** Telegram bot. The assistant cannot approve, requests expire,
  and each release can be picked up once.
- **Privacy pipeline on every outbound text.** Regex net → local LLM anonymizer → regex net, plus a checked
  paraphrase for message text. It **fails closed**: if the local model fails, the caller gets an error, never raw
  text.
- **Read-only sources.** Gmail over IMAP with EXAMINE and `BODY.PEEK` only (no SMTP code at all); Firefly III
  queries are read-only; Home Assistant over a websocket that can only authenticate, read states and subscribe;
  paperless metadata writes are allowlisted and nothing is ever deleted.
- **Live feed.** New Telegram messages and mails are triaged inside the vault into flags (category, first name,
  wants a reply, urgency, calendar suggestions) that the assistant polls as events.
- **Document and bank-export intake.** You send bills and letters to the vault's bot, which files them into
  paperless and replies with a card. Bank exports can be fed to your own Firefly importer (see below).
- **Audit log** of every call, request and decision; a daily summary when anything raw or security-related
  happened; `vault-console` for you at the server terminal.

## How it fits together

```
 assistant container                     claude-vault container (no published ports)
 ┌──────────────────────┐   HTTP + token   ┌───────────────────────────────────────────┐
 │ Claude Code session  │ ───────────────► │ vaultd.py :8300                           │
 │  `vault ask …`       │ ◄─────────────── │  policy · audit · rate limits             │
 │  vault-guard hook    │  answers, flags, │  local LLM (llama.cpp, Gemma) · embeddings│
 └──────────────────────┘  cards           │  Telegram archive (Telethon user session) │
            internal Docker network only   │  Gmail IMAP · paperless · Firefly · HA    │
                                           └─────────────────────┬─────────────────────┘
                                                                 │ approval requests
                                           You ◄── vault's own Telegram bot ── ✅ / ❌
```

## Requirements

- Docker with Compose, on a host with enough memory for the local model: the defaults reserve 8 CPUs and 22 GB
  of RAM (`VAULT_CPUS`, `VAULT_CPUSET`, `VAULT_MEM_LIMIT`), and the model files need about 15 GB of disk.
- A Docker network shared with the assistant's container (the compose file expects an external network named
  `src_default`; rename it to yours).
- The assistant side: the `vault` client from claude-assistant (`bin/vault`), or your own HTTP client.
- A **second** Telegram bot (from @BotFather) for approvals, separate from the assistant's bot.
- For each source you want: Telegram `api_id`/`api_hash` from my.telegram.org; a Gmail app password; paperless and
  Firefly III API tokens; a Home Assistant long-lived token.

## Setup

By hand, on the Docker host. In the original setup the owner deploys reviewed commits from the host and the
assistant only pushes the source; see [DESIGN.md → Deploy](docs/DESIGN.md#deploy).

1. **Token.** Generate a random API token. Put its SHA-256 in `.env` as `VAULT_TOKEN_SHA256` (copy
   `.env.example`, `chmod 600 .env`) and the token itself in the assistant's `~/.secrets/vault-token`.
2. **Models.** Put the GGUF files the vault expects (Gemma-4-26B-A4B with its MTP drafter, and EmbeddingGemma-300M
   for the semantic index; file names and checksums in `app/vaultd.py`) in `VAULT_MODELS_DIR`. They are mounted
   read-only and sha256-checked before llama-server loads them.
3. **Build and start.** `docker compose up -d --build`, then wait for `GET /health`.
4. **Secrets, at the server terminal** (`docker exec -it claude-vault vault-console …`; hidden values are typed
   without echo and never pass through the assistant):
   - `secret telegram`: the approval bot's token and your chat id (send the bot `/start` first);
   - `tg-credentials`: Telegram `api_id` and `api_hash`;
   - `secret paperless`, `secret firefly`, `secret gmail [LABEL]` as needed.
5. **Telegram login.** From the assistant: `vault tg login-qr`, scan the QR code with your phone, and enter a 2FA
   password with `vault-console 2fa` if asked.
6. **Home Assistant (optional).** Store the `homeassistant` secret (URL, token, your person entity) and set
   `VAULT_HA_DEVICE` to your phone's entity prefix.
7. **Test.** `tools/run-tests.sh` runs the offline suites with the system Python; `tests/run-all.sh` runs
   everything inside the built image without network.

Details for each step, the API and all switches: [docs/DESIGN.md](docs/DESIGN.md).

## Configuration

- `.env` (from `.env.example`): `VAULT_TOKEN_SHA256` (required), `VAULT_HA_DEVICE`, `VAULT_MODELS_DIR`,
  `VAULT_CPUS`, `VAULT_CPUSET`, `VAULT_MEM_LIMIT`, `VAULT_DEPLOY_DIR`, optionally `VAULT_FIREFLY_SYNC`.
- Feature switches in `vault.env` (`"0"` = off; a value in `.env` wins): `VAULT_ASK_SESSIONS`, `VAULT_PEOPLE`,
  `VAULT_PEOPLE_ASK`, `VAULT_PEOPLE_ASKS`, `VAULT_EMBED`, `VAULT_INDEX`, `VAULT_PHOTOS`, `VAULT_VISION`,
  `VAULT_HA_FEED`.
- Test and debug switches (`VAULT_TEST_MODE`, `VAULT_NO_LLAMA`, `VAULT_NO_SYNC`, …): see
  [DESIGN.md → Repo layout](docs/DESIGN.md#repo-layout).
- Source credentials live only in the vault's data volume, entered through `vault-console`.

### Bring your own Firefly importer

The bank-export importer used in the original setup is personal and **not included**. `app/finance.py` runs your
own importer from the directory in `VAULT_FIREFLY_SYNC` (default `vendor/firefly_sync`). The directory must
contain `vault_runner.py`, which the vault starts as `python3 -I vault_runner.py MODE` with `MODE` one of `plan`,
`import` or `report`. It receives a JSON object on stdin (`url`, `token`, `data` directory, optional `state`
file), prints a JSON object on its last stdout line (at least `ok`, plus `error` or `log`), and exits 0 or 1.
Without an importer the rest of the vault works; bank-export intake then answers with an error.

## Security model

- **Isolation.** No published ports: only containers on the shared Docker network reach `:8300`. Read-only root
  filesystem, `cap_drop: ALL`, `no-new-privileges`, an unprivileged user, PID, CPU and memory limits, `/tmp` as
  tmpfs. Data, sessions and tokens live in one volume mounted nowhere else.
- **Authentication.** Every call except `/health` needs the bearer token; the vault stores only its hash.
- **Fail closed.** Every outbound text passes the privacy pipeline; on failure the caller gets an error.
- **Human approval.** Raw access goes through a separate bot, single-use nonces, short lifetimes and rate
  limits; a fallback code mode and `vault-console approve|deny` cover a bot outage.
- **Pinned build.** Base image by digest, llama.cpp by tag and commit, Python dependencies by hash.
- **Out of scope:** root on the Docker host, or anyone who can `docker exec` into the vault. Whoever controls the
  host controls the vault. In the original setup a server-side lockdown keeps the assistant away from the host's
  Docker: every deploy is the owner's (a reviewed commit, by a button on the host or his ✅ in the vault bot); see
  [DESIGN.md → Deploy](docs/DESIGN.md#deploy).

The local LLM anonymizer reduces what leaves; it is not a guarantee. Treat anything released after approval as
having reached the cloud model. More in [SECURITY.md](SECURITY.md).

## Telegram terms of service

The Telegram source logs in as **your own user account** through Telethon (the MTProto API), not as a bot.
Automating a user account may violate Telegram's Terms of Service or API terms for some uses and can get an
account limited or banned. The vault only reads (a receive-only listener plus periodic syncs) and never sends
from your account, but you are responsible for how you use it. Check Telegram's current terms first.

## Limitations

- Built for one owner and one assistant. Several defaults are personal: the Europe/Zurich time zone, German and
  Swiss German handling in prompts and money rules, CPU pinning for one host.
- Needs a capable machine: the default model needs about 19 GB of RAM at peak, and answers take seconds to
  minutes on CPU.
- Anonymization by an LLM can miss things; the regex nets catch common identifiers, not everything.
- The Firefly importer and the server-side deploy lockdown are not included.
- Tests that depend on the personal importer are not included.

## Disclaimer

A personal project, **not affiliated with, endorsed by or supported by Anthropic or Telegram**. Provided **as is,
without warranty of any kind**. You run it at your own risk, including the risk of data loss, data exposure or
account restrictions.

## License

[Apache-2.0](LICENSE); see also [NOTICE](NOTICE). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
