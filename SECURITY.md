# Security

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, pull request or
discussion for a security problem, and do not include real personal data in a report.

Describe what you found, how to reproduce it (ideally against the offline test setup), and what an attacker
gains. This is a personal project maintained in spare time: reports are handled on a best-effort basis, with no
guaranteed response time and no bug bounty. Only the `main` branch is maintained.

## What the vault is meant to guarantee

The vault's caller is an AI assistant whose entire context goes to a cloud API. The vault exists so that the
owner's raw private data and the credentials for it never reach that caller without the owner's explicit
approval. In particular:

1. Raw message text, mail bodies, document content, original files and exact location are released only after
   the owner taps ✅ in the vault's own bot (or approves at the console), once per request.
2. Every text that leaves goes through the privacy pipeline, and a pipeline failure returns an error, never the
   unfiltered text.
3. Source credentials (Telegram session, Gmail app passwords, paperless, Firefly and Home Assistant tokens, the
   approval bot's token) can be written but never read back through the API.
4. Gmail is never modified and never used to send; Home Assistant is only read; paperless is never deleted from.
5. The assistant's API token cannot approve requests or use console-only routes.

The full threat model is in [docs/DESIGN.md](docs/DESIGN.md#threat-model).

## Scope

In scope:

- Any way for an API-token holder to obtain raw text, files, credentials or exact location without the owner's
  approval: routes, parameters, job results, error messages, logs, the event feed, caches, timing of the approval
  flow, replayed or forged approval callbacks.
- Bypasses of the regex nets or the anonymizer **that come from a code bug** (for example a path that skips the
  pipeline, or a fallback that returns input unchanged).
- Write paths that go beyond the documented allowlists (IMAP commands other than read-only ones, paperless
  deletions, Home Assistant service calls).
- Container hardening regressions in `Dockerfile` or `docker-compose.yml`, and supply-chain issues in the pinned
  build (unpinned downloads, missing checksum checks).
- Injection through untrusted content the vault processes (messages, mails, documents, file names, Home
  Assistant attributes) that changes what the vault releases or does.

Out of scope:

- The local LLM missing an identifier or a private passage in otherwise correctly processed text. That is a known
  limit of LLM-based anonymization; improvements to prompts or regex nets are welcome as normal issues or pull
  requests, without real data.
- Attacks that need root on the Docker host, `docker exec` into the vault, access to its data volume, or control
  of the owner's Telegram account.
- Content the owner approved for release.
- Vulnerabilities in Telegram, Telethon, Gmail, paperless-ngx, Firefly III, Home Assistant or llama.cpp themselves
  (report those upstream), and outdated software in your own deployment.

## Deployment advice

- Keep the vault on an internal Docker network with no published ports, as in `docker-compose.yml`.
- Use a dedicated bot for approvals, never the assistant's bot, and keep its token only in the vault.
- Give each source the narrowest credentials it accepts (read-only tokens where possible, a Gmail app password
  for one account, a Home Assistant user limited to what it needs).
- Restrict who can run `docker` on the host: anyone who can enter the container can read everything in it.
- Back up the data volume with the same care as the sources themselves: it holds a copy of your chats and the
  credentials to your accounts.
- Using Telegram through a user session (Telethon) may violate Telegram's terms for some uses; see the README.
