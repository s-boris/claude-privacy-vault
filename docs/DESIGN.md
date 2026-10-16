# claude-vault

A privacy vault for a personal AI assistant. The assistant is a Claude Code session in its own container, and
everything it reads goes to a cloud API. So the owner's raw private data and the credentials for it live **only**
in this separate container, `claude-vault`, on the Unraid server. Over a small HTTP API the assistant gets answers,
not text: short values checked in code, cards, counts and coarse flags. Message text (anonymized) and raw files
leave only after the owner taps ✅ in the vault's own Telegram bot.

- Server: `app/vaultd.py` (stdlib `http.server`, no web framework), port 8300
- Local LLM: llama.cpp `llama-server` + Gemma-4-26B-A4B (UD-IQ4_XS + its MTP drafter, sha256-checked), inside the
  container on 127.0.0.1; a second llama-server with EmbeddingGemma-300M for the semantic index (idle CPU only)
- Client: `vault …` in the assistant's container (not in this repo)

## Threat model

**Protects against:** private content (chats, mails, documents, finances) and the source credentials reaching the
assistant's context, and so the cloud model.

- The raw data, sessions and tokens live in the Docker volume `claude-vault_data` (`/data`). It is never mounted
  anywhere else.
- No port is published to the LAN. Only containers on the Docker network `src_default` can reach
  `http://claude-vault:8300`.
- Every call except `GET /health` needs `Authorization: Bearer <token>`. The vault stores only the token's sha256
  (`VAULT_TOKEN_SHA256` in `.env`).
- Every text that leaves goes through the privacy pipeline (below). **It fails closed:** if the local LLM fails,
  the caller gets an error, never raw text.
- Raw text and original files need the owner's tap in the vault's own bot. The assistant cannot approve.
- Hardened container: read-only root, `cap_drop: ALL`, `no-new-privileges`, uid 10001, 512 pids, 12 CPUs pinned to
  the host's free P-cores (`cpuset`), 22 GB, `/tmp` tmpfs. HTTP proxies from the
  environment are ignored.
- Pinned build: base image by digest, llama.cpp by tag + commit, Python deps by sha256 (`--require-hashes`).
- On the assistant's side, a fail-closed PreToolUse hook (`vault-guard`) blocks shell or file access around the
  API. It is a tripwire, not a sandbox.

**Out of scope:** root on the Unraid host. The assistant can't change the vault on its own: its SSH key on the host
runs only a fixed list of commands, none of which builds, starts, enters or writes to the vault, and every deploy
needs the owner, by his User Scripts button or his ✅ in the vault bot (see [Deploy](#deploy)).

## Sources

| Source | What the vault does | What the assistant gets |
|---|---|---|
| **Telegram** (owner's own account) | `vendor/tgread` (Telethon, pinned). QR login, 7-day initial sync, then `tgread live`: a receive-only listener plus a sync every 15 min. The vault bots' chats and Telegram's login-code chat (777000) are never stored. | Anonymized search, recent, unread data and summaries. The live event feed. The chat directory (`alias`, `find-chat`, `who`: labels and counts only). Chat ids and message refs are hidden from the anonymizer and restored afterwards. |
| **paperless-ngx** | Uses the vault's own token. Metadata writes are allowlisted (title, date, type, correspondent, tags, matching rules). Nothing is ever deleted. Plus the owner's document intake (`app/intake.py`): photos and PDFs he sends the vault bot are filed with tags Inbox + via-bot (albums merged into one PDF, type from the bytes, 30 files/h), and he gets "📄 Filed as #N …" with the tier-1 fields. | Metadata and a card (`get`: no content). Tier-1 fields free; tier-2 fields (IBAN, reference, numbers, addresses, dates) only after his ✅ (raw source `paperless-fields`), else null + `_withheld`. Content only as raw source `paperless-anon` (anonymized, `--keep-own-money`). `suggest` and `rule-test` read content inside the vault and answer with names/ids only. Intake: a feed event (source `paperless`, label `filed`, doc id/type/correspondent/bill_likely) and `GET /intake/status` counts. |
| **Firefly III** | Read-only queries. Plus the owner's bank-export intake: he sends bank and card exports (CSV / XLSX) to the vault bot, gets a dry run with ✅ Import / ❌ Cancel, and can use `/fsync` and `/freport`. Code: `vendor/firefly_sync` (his sync logic) via `vault_runner.py`, `app/finance.py`. | Category totals, merchants as stable HMAC pseudonyms, intake status (counts, masked account names). It can't upload or import. |
| **Gmail** (one or more accounts) | **Read-only IMAP** (`app/gmail.py`): EXAMINE and `BODY.PEEK` only. STORE, COPY, MOVE, EXPUNGE, SELECT, APPEND etc. are refused before sending. There is no SMTP code. Per account: IDLE on INBOX plus a 15-min poll, own positions, folders, login backoff and alerts. | Anonymized search (all accounts or one) and mails. Senders as "Name (domain)", the account as its label (`main`, `work`), never an address. Attachments as metadata, or filed into paperless. |
| **Home Assistant** | Read-only (`app/ha.py`, `app/ha_live.py`): a stdlib websocket that can only send auth, get_states, subscribe_trigger and ping (REST GET fallback). Only the owner's phone entities (`VAULT_HA_DEVICE` prefix); other people's trackers are excluded. Secret `homeassistant` {url, token, person}. | Coarse flags only (`/ha/now`): zone name or away + distance band + town, driving, activity, sleep, alarm, battery, Bluetooth category, Wi-Fi class. `homeassistant` events in the live feed. The inventory as entity metadata. Coordinates only as raw source `location` on his ✅. |

## Privacy pipeline

Every outbound text: **regex net → local LLM anonymizer → regex net.** Telegram and Gmail message text then gets
a fourth step: **→ checked paraphrase of the anonymized text → regex net.**

- **Regex net:** `tgread.mask_text`. It masks phones, emails, IBAN / account / card / AHV numbers, links that
  carry secrets, passwords and codes, coordinates, and the vault's own secret values.
- **Anonymizer:** `vendor/llm-local --anonymize`. The model only *detects*: it returns grammar-constrained JSON
  quoting private sentences and identifiers. The replacement is done in code on the original text, followed by
  a regex safety pass. The prompts are `DETECT_SYSTEM`, `CHECK_SYSTEM`, `SUMMARY_SYSTEM` and their `_ADMIN` /
  `_STRICT` variants.
- **Policy version:** `llm-local-v4.1+regex-2026-10-13` (`POLICY_VERSION` in `app/vaultlib.py`, `POLICY` in
  `vendor/llm-local`).
  - **Kept:** names, addresses, places, and non-financial facts (plans, meetings, trips, dates, decisions).
  - **Redacted:** intimate passages, which become `[private: health | mental health | sexual | dating |
    relationship | family | money | business | confidential | gossip]`.
  - **Masked:** identifiers, e.g. `[phone]`, `[email]`, `[IBAN]`, `[secret]`, `[link: domain]`. A surname is
    masked when its person is attached to a redacted passage.
- **Money and business:** anyone's finances, the owner's included, are redacted: salary, investments,
  portfolio and trading plans, holdings, debts, purchases, negotiated prices, deals, side business. A money net
  then turns amounts into `[amount]`: every amount from 5'000 up, any amount on a line with a money, business or
  payment word (paid, bezahlt, TWINT, receipt, …), and a number right after an amount label (`Total:`, `Betrag`,
  `amount due`). Times, dates, percentages and counts stay.
- **Mail:** mail is the owner's own money (receipts, orders, bank notices), so every Gmail output
  (search, get, events, attachment and media names) masks **every** amount, any size: `--all-amounts`, and the same
  money net again in code (`Policy.money_net`), so a figure the model keeps still can't leave.
- **Money backstop:** the money net knows Swiss German money words (Franke, Fränkli, Stutz,
  Chlotz, "Fr" without a dot, any case), 12'000 / 12’000 / 12´000 / "12 000 Franke", k/Tausend/tuusig/Mille and
  amounts in words ("zwölftausend Franke"). After it, in code, a sentence about someone's investments (ETF, Aktien,
  Depot, Portfolio, Krypto/BTC, investiert…) or debts (Schulde(n), Betreibig, pleite, debt) with a personal sign
  (I/you/my…, an `[amount]`, a buy/sell verb) becomes `[private: money]`, and its writer's surname is masked
  (not with `--keep-own-money`). Paraphrases fail the language check when the item only leans German/English and the
  rewrite is clearly the other language, or Swiss German turns into Standard German (retry once, then
  `[not paraphrased]` + the anonymized original).
- **Paraphrase:** message text leaves paraphrased, every meaning, number and fact kept and every redaction above
  still applied. `llm-local --anonymize --paraphrase` first anonymizes
  as above, then rewrites each message of the **anonymized** text as a short, neutral paraphrase **in the message's
  own language** (Swiss German stays Swiss German, with light normalization: a translation can change the meaning,
  e.g. "am 4i" means "at four", not "by the 4th"). The model never sees what was removed. Kept as they are, outside the model's
  reach: `###` headers, sender, date/time and `(#ref)` tails, `Subject:` prefixes, attachment lists and every
  placeholder. Kept by the paraphrase and checked in code: every fact, name, place, address, date, time and number.
  The check: every number and date word in a paraphrase must occur in that message's anonymized input, no
  placeholder may be added or dropped, and the length is capped. Also: a number keeps its role (a clock time,
  also Swiss "am 4i", "um 4", "am vieri", "halbi 5", "17i", never becomes a date or ordinal, and the other way round:
  `num_roles`), a sentence with a negation (nid, nöd, nicht, kein, nie, not, never; Swiss "no" = "still") keeps one,
  and German/Swiss German doesn't come back in English or vice versa. A failing message is retried once (with the
  reasons), then falls back to its anonymized wording marked `[not paraphrased]`. Never to raw text. One model call
  per batch (≤ 3'000 chars / 30 messages). The regex net runs again on the result. Summaries (`--summary
  --paraphrase`) get the same number/date check: a line with an unknown figure is retried once, then dropped and
  counted. Where: `tg search/recent/unread-summary-data/summarize` (tgread's `local_llm_anonymize_args` /
  `local_llm_summary_args`, enforced by the vault), `gmail search` (subject and snippet) and `gmail get`, and the
  events feed. Not paraphrased: paperless content, `paperless fields`, the media extractors (names, facts) and `facts`,
  which read the anonymized wording; only their validated outputs leave. The watch's "Claude got" shows the paraphrase.
- **Anonymization cache:** private jobs (`Policy.anonymize`: Gmail, events, paperless, media;
  tgread's llm-local runs) set `LLM_LOCAL_CACHE_DIR=/data/state/llm-cache`; `llm-run` (Claude's own text) never
  does, and `--cache-dir` is not an allowed llm-run flag. llm-local keys every entry by an HMAC (key file in that
  folder, 0600) of policy, model and the full request. Detections are stored as positions and enum categories,
  quotes it can't place are encrypted; check verdicts as a category; summaries and paraphrase batches sealed
  (HMAC keystream). Every code step still runs, so the output is the same bytes as a fresh run; a bad entry is a
  miss, never a fallback. Chunks and paraphrase batches are cut where the content says (hash of a line/item, with a
  minimum segment), so a window that moves by one message re-sends only its first and last chunk. 30 days,
  200 MB. `tg purge`, `tg exclude add` and `tg wipe` delete the whole folder (audit `llm_cache_cleared`). Cached
  tgread work runs to the end when its caller leaves, so the retry is instant.
- **Paperless content** uses `--keep-own-money` (the owner's own bills, payslips and tax papers: only debts and
  money troubles count as private, no business category, no amount net). `paperless fields` returns whitelisted structured fields raw.

## Firefly sync rules (private config)

`vendor/firefly_sync` is generic bank-export -> Firefly III logic. Everything personal (payee and people
mappings, categories, trips, subscriptions, budgets, piggy banks, the pillar-3a account, card numbers, IBANs, his
own name) is one JSON file that is never in git or the image:

- **Where:** `/data/finance/firefly_rules.json` in the data volume (0600). The sync finds it through env
  `FIREFLY_SYNC_RULES`, else `<FIREFLY_SYNC_DATA>/firefly_rules.json` (standalone: next to the script).
- **Format:** `vendor/firefly_sync/firefly_rules.example.json` (every key, fake values, a `_doc` line per key);
  the checks are in `rules_config.py` (types, regexes, dates; errors name the key, never a value). Keys starting
  with `_` are comments.
- **Set / replace:** like a secret: `vault firefly rules-set < firefly_rules.json` (`POST /finance/rules`) works
  once; replacing it needs the owner's code (`vault firefly rules-replace --reason ...`, his ✅, then `rules-set
  --request-id ID`). An invalid file is refused before his code is used. The API never returns the values:
  `vault firefly rules` shows set/valid, sha256 and entries per key.
- **Check:** `vault firefly check` (`POST /finance/check`) runs the preview's dry run against Firefly read-only and
  answers numbers only (transactions, known, new, would-be updates, kept edits, accounts; same account counts as
  the last preview?). No message to the owner, no plan, log in `/data/finance/last-check.log`.
- Without the file the sync stops with "no Firefly rules config" (rules_missing). `.gitignore`/`.dockerignore`
  and `vault admin stage` keep any `firefly_rules.json` out of git and the image. Tests: `tests/test_firefly_rules.py`.

## HTTP API

Bearer token on everything except `/health`. Full list with parameters: the docstring at the top of
`app/vaultd.py`.

| Area | Routes |
|---|---|
| State | `GET /health`, `/status`, `/metrics?days=N`, `/audit?days=N`, `/alerts`, `POST /alerts/ack` |
| Telegram | `POST /tg/<search\|recent\|unread-summary-data\|summarize\|window\|chats\|status\|exclude\|purge\|sync\|wipe\|allowlist\|selfcheck>`, `POST /tg/credentials`, `/tg/login-qr`, `GET /tg/login`, `POST /tg/login-cancel`, `/tg/2fa` |
| Paperless | `POST /paperless/search`, `/recent`, `/get` (card), `/fields` (tiers), `/suggest`, `/rule-test`, `/upload`, `/task`, `/update`, `/taxonomy`; `GET /paperless/meta`, `GET /intake/status` |
| Firefly | `GET /firefly/status`, `POST /firefly/summary`, `/firefly/merchants`, `GET /finance/status`, `GET\|POST /finance/rules` (write-only rules config), `POST /finance/check` (read-only dry run, numbers only) |
| Gmail | `GET /gmail/status`, `POST /gmail/search`, `/gmail/get`, `GET\|POST /gmail/config`, `POST /gmail/to-paperless`. All take an optional `account` (search: default all; get, to-paperless, raw: the REF's account or the only one) |
| LLM | `POST /llm/run` (llm-local on the caller's own text; the KV cache is flushed first) |
| Jobs | `POST /jobs {op, params}`, `GET /jobs/<id>?wait=N`, `GET /jobs`, `POST /jobs/<id>/cancel` (below) |
| Raw | `POST /raw/request`, `/raw/release`, `GET /raw/pending` |
| Media | `POST /media/list`, `/media/request`, `/media/release`, `/media/ack`, `/media/extract` (below) |
| Facts, find, plans | `POST /tg/facts`, `/gmail/facts`, `/find`, `GET /plans?days=14` (below) |
| Answers | `POST /answer` (`vault ask`, follow-up sessions), `POST /tg/digest` (below) |
| Memory | `GET /people`, `POST /people/show\|relation\|forget\|rebuild\|refresh`; `GET /index/status`, `POST /index/rebuild\|eval` |
| Home Assistant | `GET /ha/now` (coarse flags), `GET /ha/inventory` (metadata) |
| Events | `GET /events?since=CURSOR\|latest&max=N&source=telegram\|gmail\|paperless\|homeassistant`, `GET /tg/events`, `GET\|POST /events/rules`, `POST /events/retriage` |
| Secrets | `GET /secrets` (names only), `POST /secrets/<telegram\|paperless\|firefly\|gmail\|gmail:LABEL>` (write-only; replacing one needs the owner's approval) |
| Deploys | `POST /deploy/request {commit}`, `GET /deploy/status[?id=ID]` (see Deploy) |
| Console only | `POST /raw/approve`, `GET /console/events`. These return 404 for the API token. |

## `vault` client (assistant side)

| Command | Does |
|---|---|
| `vault status` | Vault, LLM, sources, Telegram login and live listener, approval mode, event feed, alerts. No data. |
| `vault tg …` (= `tgread …`) | tgread through the vault. `--raw` is refused. |
| `vault paperless search\|recent\|get\|meta\|fields\|upload\|task\|set\|rule set\|rules` | Paperless through the vault |
| `vault firefly status\|summary START END\|merchants START END\|sync-status` | Firefly |
| `vault firefly rules\|rules-set < rules.json\|rules-replace --reason R\|check` | the sync's private rules (counts + sha256 back) and a numbers-only dry run |
| `vault gmail status\|search Q\|get REF\|to-paperless REF [N]\|config` (+ `--account L`) | Gmail, read-only. REF = `main:1234` or `work:1234@Folder` |
| `vault llm-run -- ARGS < text` | llm-local in the vault |
| `vault raw request --source S --reason R …` / `vault raw release ID [CODE]` / `vault raw pending` | Raw access (below) |
| `vault media list\|request\|release\|facts\|gc\|status` | Files: metadata, owner-approved bundles, facts (below) |
| `vault tg alias\|find-chat\|who` | Chat directory: my chat names, which chat is it, a person's chats (metadata only) |
| `vault facts tg CHAT [--since 60d]` / `vault facts gmail REF` | Events, to-dos, places, decisions, open questions as JSON (below) |
| `vault find "QUERY" [--since 30d] [--sources tg,gmail,paperless]` | One ranked list across the three, with Swiss German / German / English variants (below); `vault tg search Q --expand` = the variants in Telegram |
| `vault plans [--days 14]` | Dated facts of the event feed: calendar suggestions (below) |
| `vault ask tg (--chat C \| --search Q) [--kind K] "question"` / `vault ask gmail REF` / `--session`, `--session ID "…"`, `--end` | An answer, not text; hybrid retrieval; follow-up sessions (below) |
| `vault people [--active 90d] [--relation R] [--asks]` / `people show\|relation\|forget\|refresh\|calibrate` | Person cards: metadata, open asks, topics (below) |
| `vault index status\|rebuild [--reconcile]\|eval` | Embedding server, semantic index, bake-off (numbers only) |
| `vault ha now\|inventory` | Home Assistant: coarse status flags; phone entities as metadata |
| `vault events [--since C] [--source S]` / `vault events rules\|mute\|priority\|normal …` | Live feed and its rules |
| `vault audit [--days N]` / `vault alerts [--to-inbox]` | Metadata audit, problem alerts |
| `vault metrics [--days N]` | Health numbers (below): per route, LLM, caches, source delays |
| `vault --async …` / `vault job wait ID [--max 230] [--partial]\|list\|cancel ID` | A long read as a job (below) |
| `vault secret list\|set NAME\|rotate NAME --reason R` | Write-only secrets |
| `vault deploy request [COMMIT] [--wait S]` / `vault deploy status [ID]` | Telegram-approved deploys (see Deploy); exit 0 deployed, 10 under way, 1 not deployed |
| `vault admin deploy\|logs\|ps` | `deploy` pushes the source to GitHub for the owner's deploy; `logs` and `ps` are read-only (see Deploy) |

Exit codes: 0 ok, 1 error, 2 usage, 3 unavailable or not configured, 10 waiting for the owner, 12 job still running,
75 busy, 77 auth.

## Async jobs and chunked summaries

`app/jobs.py`. A cold read can take minutes (the paraphrase runs at ~10 tokens/s); the
assistant's agents must not wait more than 4 min per call. So a long read runs as a job and is polled.

- **Ops (allowlist):** `tg.search`, `tg.recent`, `tg.unread-summary-data`, `tg.summarize`, `gmail.search`,
  `gmail.get`, `paperless.get`, `media.extract`, `llm.run`; `params` = that route's body. Raw, secret, console and
  write routes can never be jobs (checked at import and in the tests).
- **Same handlers, same filters:** a job runs its route's handler under the same token, audited like the route
  (plus `job_submit` / `job_done`: id, op, state, seconds, bytes). Cancel = a caller that left (the LLM queue drops
  its queued step).
- **Memory only:** results 30 min after the job ends, 20 MB in all (oldest dropped first: state `expired`), only for
  the token that started it; random 16-hex ids; a restart drops every job. Identical requests (op + params) join the
  running job, or one that ended less than 2 min ago. At most 8 jobs at a time (429).
- **`GET /jobs/<id>?wait=25`:** long poll; state, progress (`part 3/7`), the LLM queue position and an ETA, partial
  results, then the route's answer. The client: `vault --async …` prints the id; `vault job wait ID --max 230` prints
  the answer like the command would (its exit code), or exits 12 while it runs.
- **Chunked `tg summarize` (jobs only):** `tgread window` gives messages and characters per chat and day (ids and
  counts, no text, no names). The window start is rounded to 10 min. A busy chat (> 12'000 chars over more than one
  day) is cut at day borders (Zurich) into parts of whole days up to 12'000 chars, small chats (< 2'500 chars) share a
  part (≤ 8'000 chars, ≤ 8 chats), the rest one part per chat, newest activity first. Each part is a normal `tgread summarize --chats … --since @… [--until @…]
  --no-counts` (stable text for the anonymization cache) at bulk priority. Each model request of a part takes the LLM
  gate on its own (LLM scheduler), so a live read waits for one request, not a 10-minute part.
  Then ONE `llm-local --summary --paraphrase` call merges the part summaries (already anonymized; anonymized again,
  every number and date checked against them) → regex net. If only the merge fails, the part summaries are the answer.
- **Live view:** the submit shows as `… → ⏳ job queued (#1, ETA ~3 min)`, the job's answer once, as the call it ran
  (`… (job)`); its polls are one progress line in the bot's /watch, edited in place.

## Facts, find and calendar suggestions

All three are built from text that is already anonymized in the vault.

- **`vault facts`** (`app/facts.py`; `POST /tg/facts {chat, since=60d, n<=500}`, `/gmail/facts {uid, account?,
  chars?}`; jobs `tg.facts` / `gmail.facts` for `--async`): events (what, date, start, end, venue, address, who,
  status), to-dos (what, who, due), places, decisions and open questions as JSON, each with `refs` (`#msg` or the
  mail REF).
  - Input: the chat's messages anonymized **without** the paraphrase (tgread's `recent` with `--no-paraphrase`, a
    flag the API can't pass: it is not in `TG_SPECS`; mail: `Gmail.anon_doc`, every amount masked).
    That text never leaves the vault.
  - One structured llm-local call (`--json --temp 0`) per part of up to 5'000 characters (whole days where it fits).
  - Checks in code: fields from fixed lists; names, dates, times, venues and addresses must be written in the text
    (token by token); `what` is a short description whose every word (glue words like "at", "mit", "zum" aside) is in
    the messages; a wrong citation is replaced by the messages that hold the words; dates are worked out from the
    message's own time (Europe/Zurich): "Samstag", "17.10.", "morgen", "next Friday", "3.1." written in late
    December = next January (`date` ISO + `date_text` as written; times `start` "HH:MM" + `start_text`); 25 items per
    kind and part, 40/30 per answer, 120 characters per value. Then the regex net (mail: + the money net), and again
    on the way out. `dropped_fields` counts refused values by field.
  - An LLM failure or an answer that isn't JSON is an error with nothing partial. Results are cached per part in
    `/data/state/facts-cache` (0600; key = facts version, policy, model, the part's text and refs; 30 days);
    `tg purge|exclude|wipe` clear it with the anonymization cache.
- **`vault find "QUERY"`** (`app/find.py`; `POST /find {q, since=30d, sources, n=15}`, job `find`): one ranked list.
  - Word variants (`expand_query` in vendor/tgread, one table for `find` and `tg search --expand`): Hochzeit =
    Hochziit = wedding, Freitag = Fritig, Samstag = Samschtig, JGA = Junggesellenabschied, Geburtstag = Geburi,
    Znacht = Abendessen, …; ue = ü (ae = ä, oe = ö); word starts (FTS prefix).
  - Telegram: tgread's full-text search with the variants, read inside the vault as JSON hits (the JSON form exists
    only for the vault's own unfiltered reads and is not in `TG_SPECS`). Gmail: X-GM-RAW `{a b c}` per word on every
    account (read-only IMAP). Paperless: full-text query, **metadata only**.
  - Ranked in code: the query's own words before variants, then newest first. The chosen Telegram and Gmail
    snippets are anonymized and paraphrased in **one** llm-local call (cached; with mail in the batch every amount
    is masked), then the regex net. A failing source gives a partial result with `errors`.
- **Calendar suggestions** (`EventFeed` + `Facts.for_events`; `GET /plans?days=14`, `vault plans`):
  - Surfaced feed items labelled `plan_datetime`, `deadline`, `location` (Telegram) or `appointment`, `deadline`
    (Gmail), and other surfaced items whose body names a day or a time, get facts: the batch is anonymized once
    without the paraphrase first (the paraphrase call then reuses its detections from the cache), then ONE
    background facts call per batch. The facts are stored on the event (`facts` column, up to 6 per event); a
    failure stores the event without them (`facts_state` counts it). Chatter never triggers extraction.
  - `/events` carries `facts`; `/plans` collects the dated ones (events by date, to-dos by due date) of the last 7
    days of messages in [today, today + days], without cancelled ones, duplicates merged (`mentions`).
  - `vault-events` notes add lines like `Suggest: Sat 17.10 16:00 Concert, Town Hall · Choir`; the
    assistant then applies the owner's calendar rule (add what is obviously needed, ask when unsure, no duplicates).

## Answers, not text

`app/answer.py`: the vault answers questions about chats and mail with short, checked values instead of text.
- **Input** (never leaves the vault): `TG.anon_messages` (anonymized, not paraphrased), tgread search hits (anonymized
  in one call), `Gmail.anon_doc` (every amount masked). One `llm-local --json --schema` call per part of <= 5,000 chars
  (grammar-constrained per kind), cached in `/data/state/answer-cache` (0600, 30 days; `tg purge|exclude|wipe` clear it).
- **Kinds**: `yesno`, `when`, `who` (first names + flagged nicknames, single checked words; who/wer questions always
  run as `who`, also over an explicit `short`), `deadline`, `actionable`, `requests`, `count`, `short`
  (<= 12 words from the text),
  `interests` (<= 5 phrases of <= 4 words, gift radar), `mail_card` (gmail get default), `digest` (tg summarize/recent/
  unread default: needs_you, plans, signals, topics).
- **Checks in code**: fixed fields; enums; first names only (the first word of a name in the text); `*` values found in
  the text; dates resolved in code (`facts.resolve_date`); a `[placeholder]` never inside a value (topic `private`);
  then the regex net (mail: + money net) drops any value it would mask. An LLM failure is an error, never partial.
- **Today and the asked days**: the prompt starts
  with today's date and the question's time words resolved in code against today (`ask_window`: this/next/last
  weekend, week, month, heute/morgen/gestern, weekdays, written dates; a follow-up without its own uses the earlier
  turn's); a message's own relative dates still count from that message (`facts.resolve_date`, "am
  Wochenende" included). Each dated answer gets `timing: past`, `relative` (last weekend, tomorrow ...) and, when days were
  asked, `in_window` (false: a yes becomes no); the result shows `today` and `asked {label, from, to}`.
- **Routes**: `POST /answer {source: tg|gmail, kind, question, chat|query|ref, since, n}`, `POST /tg/digest`; job ops
  `answer`, `tg.digest`. Audit `answer` {source, kind, parts, chars_in, dropped_fields}.
- **Follow-up sessions** (`app/sessions.py`, switch env `VAULT_ASK_SESSIONS=1`, off =
  409 `sessions_off`): `session: true` on an ask opens one (`session: {id, expires, turns_left}` in the answer);
  `{session: ID, question, kind?}` asks a follow-up over the SAME messages (by ref; a chat window is pinned to the
  first ask's oldest message), its question composed in code from the earlier turns' checked values (≤ 300 chars),
  kind from a keyword map unless given; `{session: ID, end: true}` ends it. The scope is fixed (another chat, query,
  mail or since -> 400 `scope_locked`). Memory only: scope, refs and checked turns; 15 min idle, 60 min cap, 6 turns,
  20 sessions (LRU), bound to the caller's token hash, dropped on restart and by `tg purge|exclude|wipe`. Audit
  `answer` + {session (sha8), turn}, `answer_session` {action: open|followup|end|expired|purged, session, turns}.
- **Times carry their date**: an
  undated `when` gets its date in code from the cited messages when they name exactly one day (`date_from: message`),
  else a session's earlier checked date (`date_from: earlier`), else it is flagged `date_unknown` (never guessed).
- **Person cards** (`app/people.py`, switch env `VAULT_PEOPLE=1`, off = 409
  `people_off`, nothing stored): one card per Telegram DM contact with >= 10 messages in 12 months, not a bot, not
  him: person (his chat alias, else the first name; honorific + surname -> "someone"), key (p- + HMAC of
  the user id; the id is never stored or shown), relation (enum, set only by the owner), dm_since (month),
  groups_shared, last_contact {from_them, from_owner} (dates), messages {30d, 90d, 365d: {in, out}}. Derived from
  tgread's vault-internal `people-stats` (SQL counts, no text; not in TG_SPECS) every night at 03:00 and after
  `tg purge|exclude add` (cards dropped at once, rebuilt on the next read); `tg wipe --data|--all` deletes
  /data/state/people.db (0600, secure_delete). Only relations and forget entries persist. No notes, no LLM, no text;
  cards are never fed into a prompt. Routes `GET /people?active=&n=<=20&relation=`, `POST /people/show|relation|
  forget|rebuild`. Relation: `{person}` -> the vault bot asks him with `p:` buttons (owner chat only, nonce + message
  checked, <= 20 a day (env VAULT_PEOPLE_ASKS_PER_DAY), 7 days valid); `{person, relation}` = my relay of his words, confirmed to him silently with
  Undo. Both only with `VAULT_PEOPLE_ASK=1` (default off: 409 `relation_ask_off`). Audit `people_build|list|show|
  relation|relation_ask|forget|purge|callback_refused` (pseudonym keys, counts, enums; no names). No Gmail.
- **Embedding runtime + bake-off** (`app/index.py`, switch env `VAULT_EMBED=<model>`
  (embeddinggemma | qwen3-0.6b | bge-m3; "0" = off)): a second llama-server from the same pinned binary,
  `--embeddings`, 127.0.0.1:8191 only, under a SCHED_IDLE + nice 19 wrapper (it only gets CPU the main LLM leaves
  idle; idle itself it uses no CPU), 6 threads, inside the same cpuset. Weights sha256-pinned in vaultd.py
  (`EMBED_*_FILE/_SHA256/_URL`, official Qwen and ggml-org GGUFs), seeded into /models by the deploy
  (it reads every EMBED_* pin), verified before load (/data/state/embed-verified.json). sqlite-vec 0.1.9
  compiled in its own build stage from the sha256-pinned amalgamation tarball, load-tested at build, in run-all.sh
  and live (GET /index/status). Bake-off `POST /index/eval` (async job op `index.eval`):
  2,000 chunks from tgread's vault-internal `index-rows` (DMs and groups; 45-min gap / ~800 chars, one message of
  overlap), 400 Gemma-written questions + search words (half cross-lingual, language tagged de/gsw/en/bcs/other) at
  background priority, then per model a temporary embed server (port 8192), sqlite-vec KNN, keyword (`fts-query` =
  the FTS5 expression of `search --expand`, newest first) and hybrid (RRF k=60, <= 3 chunks per chat). Output and
  /data/state/index-eval.json: recall@5/@10, MRR per model, language and same/cross-lingual bucket, tok/s, query
  p50/p95 ms, peak RSS, the public smoke set (tests/embed_smoke.json): numbers only; text, questions and vectors stay
  in memory. Every embedding batch takes the LLM gate at background priority. Audit `index_eval` (numbers).
- **Telegram semantic index + hybrid retrieval** (`app/index.py` + `app/answer.py`):
  `/data/state/index.db` (0600, WAL, secure_delete): chunk ids, chat ids, times, counts, sender ids, a keyed HMAC per
  chunk (derived from the vault key; change detection) and the vectors (sqlite-vec vec0, cosine, partition `source`,
  metadata chat_id/ts): never message text. Kept by the `index` thread while VAULT_EMBED is on: first build and
  model/chunker changes into a shadow file `index.db.new` (resumable: kept chunks match by HMAC), swapped atomically;
  incremental updates 60 s after the live listener's LIVE_QUEUED/SYNC_DONE (else every 15 min): rows after the cursor,
  each touched chat's open tail re-chunked; 02:30 reconcile of the whole archive (edits re-embed, deleted messages and
  purged chats drop). Embedding batches of 4 at background priority on the LLM gate (live asks go first). Purge hook:
  `tg purge` / `exclude add` delete every chat the index must drop, at once (tgread `index-rows --chats`, ids
  only; if unreadable, the whole index goes: fail closed), `wipe --data|--all` deletes the files; a running build
  aborts before its next insert. `vault ask tg --search Q` with retrieval hybrid: FTS hits (n 50) mapped to chunks +
  the question's KNN (top 50, since filter), weighted RRF (vector 1.0, keyword 0.7), <= 3 chunks per chat, chunks
  until 2,000 chars (`chars` 500-4500), their messages via tgread's vault-internal `index-lines` (search-style lines)
  -> the same one --anonymize call -> one answer part. `--chat` over a window needing > 1 part, for yesno, when,
  short, deadline, actionable: the chat's best chunks (KNN + a recency leg) fill one part. Default retrieval =
  env VAULT_INDEX ("1" hybrid, the default in `vault.env`; else keyword); `retrieval: hybrid|keyword` per call; any problem
  (embed server down, not built, chat/from/until filters) falls back to keyword per call with a reason enum. The
  answer carries `retrieval {mode, keyword_hits, vector_hits, chunks, chars, fallback}` (numbers); audit `answer`
  + retrieval/chunks, `index_rebuild`/`index_update`/`index_purge` (numbers). Semantic hit lists are never exposed
  (`tg search`/`find` stay keyword). `GET /index/status` (index part), `POST /index/rebuild {mode}`.
- **Open asks + topics** (`app/asks.py` + `app/topics.py`, switch env `VAULT_PEOPLE_ASKS=1`
  with VAULT_PEOPLE; "0" = cards without asks and topics): a card adds open asks {dir, wants, urgency, due, since, status, refs, src,
  expires} (enums, dates and refs, never text). `from_them` = the event feed's triage rows matched by Telegram user id
  (DMs only, never by name); `from_owner` = a nightly owner-perspective triage of his own DM messages (tgread's
  vault-internal `out-items`, <= 30 a call, grammar-constrained, background priority, 01:00-06:30). open -> replied
  when the other side writes after; expiry 21 days or due + 7 (cap 90); <= 5 shown, <= 50 new a day, contacts with < 3
  earlier messages kept off. Topics: one enum per DM chunk of index.db by prototype cosine; calibration = Gemma labels
  ~300 chunks inside the vault, only numbers leave; shown only when precision >= 0.55 and coverage >= 0.25;
  `private`/`other` never shown. `POST /people/refresh {what: asks|topics|calibrate}` (job op `people.refresh`);
  forget drops asks, purge drops centroids. `tests/test_people_v2.py` includes a poisoning suite (injected
  instructions, fake relations and asks, spoofed names, floods).
- **Defaults without text** (`text: false` by default, `TEXT_DEFAULT = False`): tg search = hits {ref,
  ts, chat (alias | first name | "group"), from} (+ `ask` answers over them); tg recent/summarize/unread-summary-data =
  digest; gmail search = {ref, date, account, from ("Company (domain)" or a freemail sender's first name), category
  (one triage call per page), attachment counts}; gmail get = mail card (a bill: no due date, no amount); find = hits
  without text.
- **Text only on the owner's ✅**: `text: true` + `reason` (3..300 chars) on those routes makes a
  raw request (source `text`): the owner reads the reason in the vault bot and taps ✅; the caller picks it up with
  `/raw/release`. Audit `text_release` {route, reason, bytes}; board "📝 text releases today: N"; more than 10 a day
  raise an alert. Never on /events.
- **Location**: raw source `location` (Home Assistant secret `homeassistant` {url, token, person}): zone, coordinates
  and a map link, released only on his ✅.
- **Event feed**: triage adds `wants` and `urgency` (enums); no paraphrase call (events carry no text); columns
  who, wants, urgency, att (counts); a group shows as its alias, else "group".

## Raw access: approval bot

1. `POST /raw/request {source, query, reason}`. The payload is computed now and held **in memory only**.
2. The vault's **own** bot (never the assistant's chat bot) sends the owner: "🔐 Claude asks for raw text:
   *reason* (source, query, ~size)" with **✅ Allow once / ❌ Deny** buttons.
3. A tap counts only if it comes from the configured owner chat, on that request's message, with its single-use
   nonce. Anything else is ignored and audited.
4. `POST /raw/release` returns the payload **once** after ✅. Otherwise it returns `pending` (it can wait up to
   30 s), or 410 if denied or expired.

| Limit | Value |
|---|---|
| Request lifetime | 15 min |
| Pickup window after ✅ | 5 min |
| Pending requests at once | max 3 |
| Requests per hour / per day | max 10 / max 20 |
| Alert to the owner | more than 6 requests in an hour |
| Vault restart | drops all pending requests |

- **Fallback "code" mode**, while the vault bot can't poll (it is shared with another poller, or answered 409):
  the message carries a 6-digit code instead of buttons. The code is stored only as an HMAC. 3 wrong codes kill
  the request.
- **Always available:** `vault-console approve|deny RID` at the Unraid terminal.
- **Daily summary:** once a day after 20:00 Europe/Zurich, the owner gets one line, but only if there was raw
  activity or a security event in the last 24 h (refused callbacks or decisions, failed auth, console refusals,
  wrong codes, rate limits, refused finance senders). Quiet days stay silent.

## Media requests

`app/media.py`. Files from Telegram chats, Gmail attachments and paperless originals.

| Step | What happens |
|---|---|
| `POST /media/list` | Metadata only, no approval: date, chat/sender label, type, size, pages/duration. File names go through the privacy filter in one batched llm-local call (generic camera names skip it; on failure `[name hidden]`); codes in names (booking references, letter+digit ids, digit runs of 7+ that are no date) become `[code]` in code, before and after the model, and `grep` matches the masked names. Telegram: `tgread media` reads the archive (it stores size, MIME and duration); excluded chats are refused. |
| `POST /media/request {keys, reason, keep_minutes}` | Up to 5 files, 50 MB, fetched read-only at once (tgread download profile, IMAP BODY.PEEK, paperless GET). The real type comes from the bytes: PDF, images, audio, video, text, .ics, docx/xlsx; executables, scripts, archives, HTML and macro documents are refused. Held in memory by the raw-request state machine (kind `media`: same 15 min / 5 min pickup / 3 pending / 10 per hour / 20 per day, plus 200 MB per day). |
| Owner | The vault bot shows the preview (name, type, size, pages, chat, sender, date, keep time) with ✅ Allow once / ❌ Deny, plus 📋 Facts only when every file is a PDF or .ics. The API response never carries file names. |
| `POST /media/release` | After Allow: the files once (base64, sha256, cleaned name). After Facts only: the extracted fields instead, the bytes never leave. |
| `POST /media/ack` | The client reports `saved` and `deleted` (sha256 only). Released files stay at most 2 h on the assistant's side. No `deleted` 15 min after that: audit `media_delete_overdue` + alert. A promise of the client, made auditable. |
| `POST /media/extract {key, kind}` | No approval. Text: `pdftotext -layout`, paperless OCR text for scans, .ics parsed in code (attendee addresses dropped) → anonymizer (paperless: `--keep-own-money`) → code patterns + one structured llm-local call on the anonymized text with a fixed field list (travel / event / booking). Every value must appear in the anonymized text (dates, times and flight numbers by meaning: "Fri, 20 Nov" = 2026-11-20, carrier "QR" + number "096" = "QR 096" as written; a date without a year ("20 Nov", "03.06.") takes the document's year, else the next such day from the file's date; a date range gives its first day and a time range its start, the end going into the kind's end field (check_in → check_out, dep_time → arr_time); check_in/check_out are grounded as date and time apart and come back as `YYYY-MM-DD HH:MM`, `YYYY-MM-DD` or `HH:MM`), lengths are capped, the regex net must not change it. Photos: tesseract OCR in the vault picks the kind (airport codes beside times or flight numbers = travel; hotel words or a count before "nights" = booking; event, appointment, invitation and reservation words = event; a photo with none of these but a date goes to the model as event, or as travel with travel words and two times), then the local model reads the image (vision; OCR text is the fallback); the phone's status-bar clock (a lone time on the first line, or in the top 5 % of the image) is no `times` entry. Legs whose dates contradict their times (overnight, out of order) keep only the times; legs the model missed come from code patterns (`segments_from`); `dropped_fields` counts refused values by field. Booking references, ticket numbers, barcode/QR contents and prices are never returned. |

The audit holds keys, types, sizes and sha256 prefixes, never file names. On the assistant's side, vault-guard blocks
network tools on `~/.cache/vault/media`.

## Live feed, status board, live view

- **`/events` feed** (`EventFeed` in `app/vaultlib.py`): new *incoming* Telegram messages and mails.
  - Steps: mute/priority rules → stale cut (> 6 h) → per-chat cap (10/h) → one local-LLM triage call → one
    anonymization call for what is surfaced → regex net → store.
  - Telegram labels: `question_to_owner`, `plan_datetime`, `request`, `deadline`, `money`, `location`, `chatter`.
  - Gmail labels: `bill`, `deadline`, `appointment`, `reply_needed`, `delivery`, `account_security`, and
    `newsletter` / `other` (counted only).
  - Chatter keeps no text. If the LLM fails, nothing is stored and the batch is retried later.
  - Gmail events carry `account` (the label) and a REF with it (`work:1234`), for `vault gmail get REF`.
  - It is cursor-based. The assistant polls it every minute from cron.
  - Also carries `paperless` (document intake, label `filed`) and `homeassistant` events (coarse flags, see
    [Home Assistant](#home-assistant-status-feed)); the assistant turns those into `vault-events-ha` inbox notes.
- **Pinned status board** (`app/board.py`): one silent, protected message in the vault bot's chat, edited in
  place.
  - Updates: at most every 30 s on a change, every 10 min for the clock, and at once on `/status`.
  - Shows activity, today's counts (the assistant's requests by kind, raw asks and decisions, redactions, new
    messages and mails vs. surfaced, Firefly imports) and health.
  - **Counts and states only, never content.** It is re-sent or re-pinned if deleted or unpinned.
  - Off in test mode, with `VAULT_NO_STATUS_BOARD=1`, or while the bot is shared.
- **Live view:**
  - Every API call writes one stderr line (Unraid → Docker → claude-vault → **Logs**): caller, method + path,
    allowlisted parameters (hidden on secret routes), status, size, duration and redaction counts. Never a
    response body.
  - `vault-console watch` follows the same calls live from an in-memory ring buffer (2000 calls / 5 MB, gone at
    restart). It shows the last 10 first.
  - `--full` shows each call as a block: **REQUEST** (the route in plain words + the parameters, e.g.
    `Telegram search 'Oktoberfest', n=3`), **RAW** (the source text that went in, see below), **RESPONSE**
    (exactly what the assistant got) and the redaction counts; each part cut at 8 KB with `…(N more chars)`.
  - **`/watch` in the vault bot** (`app/watch.py`, owner's chat only):
    `/watch on [full] [30m|2h]` (or `/watch full [30m|2h]`) streams the assistant's API calls (never the
    console's) to his chat; `/watch off`. `/watch`, `/watch state` and anything it doesn't know answer with the
    state and buttons (Watch 30 min · Watch full 30 min · Full 2 h · Off); colons after the command or a word are
    ignored (`/watch: full`). Default 30 min, at most 12 h, auto-off, and off after every restart.
    - Layout: HTML, one message per call. Header: emoji per source (💬 Telegram · 📧 Gmail ·
      📄 Paperless · 🖼 media · 🔑 raw request), the action, the query, time · duration · size. Without `full`: the
      other parameters and an italic line with what was hidden by category ("hidden: 1 AHV · 2 links" / "nothing
      hidden"). With `full`: bold **Request**, **Original** and **Claude got**, the last two as expandable quotes
      (~1200 characters each) in a readable form (one line per message "Sender · time: text", no `###` headers,
      refs or policy footers; the console keeps the exact bytes), placeholders in bold, then the hidden line.
    - More than 3 calls within 5 s: the rest go out together, one message per 5 s; no notification sound. Routine
      polls with nothing new (`/events` empty, `/status`, `/alerts`, `/metrics`) are only counted.
    - Same ring buffer, same scrubbing (once more right before sending). The audit gets `watch_on` / `watch_off`;
      `/status` shows `watch` (on, full, until, `raw_kept` count).
  - **RAW** (owner only): Telegram messages with sender, time and chat (re-read by the archive reader the raw
    release uses, no LLM; for a summary the messages of its window), the Gmail snippet or body with the sender,
    the Paperless content excerpt.
    - Captured only while a full watch runs (`/watch on full`, or a `vault-console watch --full` that polled in
      the last 35 s). Otherwise nothing is captured and the buffer drops what it held within a second.
    - Memory only: never in a response, the log, the audit, the events feed, on disk or on any route the
      assistant's token can call (`/console/events` is console-only).
    - Scrubbed: the vault's secret values and live raw codes, tokens (bot tokens, JWTs, bearer, long keys), links
      with tokens and one-time codes.

## LLM scheduler

`LLMGate` in `app/vaultlib.py`. The model runs one job at a time, from a priority queue:

- **Classes:** `live` (my small reads: search, recent, gmail, paperless, llm-run on short text) before `bulk`
  (summaries, `--full`, more than 60 messages or 72 h, long llm-run) before `background` (event and Gmail triage).
  First come, first served within a class; a background job that waited 10 min moves up to bulk.
- **Caller gone:** every API call carries a check of its socket. A queued job whose caller closed the connection is
  dropped before it starts; a running tgread or llm-local process is stopped (`run_proc`). Both are counted in the
  metrics (`dropped`, `stopped`).
- **Reset rule:** the model's prompt cache is flushed once before my own text runs after private work.
- **Per-request gating:** `app/llmproxy.py`, a thin proxy on 127.0.0.1:8180 between llm-local and llama-server,
  gates **each model request**, so a long summary run can't keep a live read waiting for minutes:
  - LLM work in a subprocess runs in a `lease()`: env `LLM_LOCAL_PORT` = the proxy, `LLM_LOCAL_TICKET` = a random
    ticket (llm-local sends it as `X-LLM-Ticket`); the lease carries the class, private or caller text, the job, the
    caller. The flush rule holds per request.
  - A lease keeps its turn for 3 s between its requests against the same or a lower class (warm prompt cache; no
    background or bulk request slips into a live read's gaps). A live request goes first at the next request
    boundary; a bulk/background request that kept it waiting 20 s (`VAULT_LLM_PREEMPT_S`, 0 = off) is aborted
    upstream (llama-server cancels a task whose connection closed) and re-sent after it, at most twice; llm-local sees
    one answer. Answers are relayed byte for byte, so outputs don't change.
  - Fail closed: no or unknown ticket 403 (any subprocess outside a lease gets the proxy's port and no ticket), gate
    timeout or failed flush 503, the lease's caller gone before its first request 499, llama-server down 502; llm-local
    exits with an error. `GET /health` needs no ticket; `/props`, `/tokenize` need one but aren't gated.
  - `/status` → `llm.gating` (`per request` / `per run`) and `llm.proxy` (counts). `VAULT_LLM_PROXY=0` or a proxy that
    can't listen (alert `llm-proxy`): each run holds the gate as a whole. The metrics' LLM "jobs" are model
    requests; `preempted` counts aborted-and-re-run requests.
- **Visibility:** `/status` → `llm.queue` (running job: kind, class, elapsed, ETA from its kind's typical time;
  queued jobs: kind, class, waited). Kinds only, never text. The client prints
  `vault: LLM busy with tgread summarize for 2m10s (ETA ~1m), 1 queued` to stderr after 10 s of a long call
  (`VAULT_QUIET=1` turns it off), and `vault status` shows the queue.

## Health metrics

`app/metrics.py`: hourly totals for 30 days in `/data/state/metrics.json` (0600). **Numbers
only**, summed per hour: no queries, payloads, chat or file names.

- **Per route** (method + first two path parts; unknown paths count as `other`): calls, errors (5xx), timeouts,
  callers that left before the answer, median / 95th percentile / maximum duration (from a fixed histogram).
- **LLM:** busy share, jobs, wait per class (`live`, `bulk`, `background`), longest queue, jobs dropped or stopped
  because their caller left. llm-local appends one line of numbers per run to `/data/state/llm-stats.jsonl`
  (`LLM_LOCAL_STATS_FILE`): prompt tokens processed vs reused from llama.cpp's prompt cache, generated tokens,
  prompt and generation speed. The vault reads it every minute.
- **Caches:** hits and misses (paperless content, the anonymization caches). **Source delay:** message or mail time
  to event stored. **Backlog:** the largest event-feed backlog.
- Shown by `GET /metrics?days=N` / `vault metrics [--days 7]`, one line in `vault status`, and `⏱ wait p95 · LLM
  busy` on the pinned status. A vault alert fires when the LLM's 95th-percentile wait was over 15 min for a whole
  hour.

## Owner console: `vault-console`

Run at the Unraid terminal (Docker tab → claude-vault → Console, or `docker exec -it claude-vault vault-console …`).
Hidden values are typed without echo and go straight into the vault, so the assistant never sees them.

| Command | Does |
|---|---|
| `vault-console secret telegram` | The vault's **own** bot token (create a NEW bot with @BotFather and send it `/start` first) + the owner's chat id. This turns the ✅/❌ buttons on. |
| `vault-console secret paperless` / `firefly` | Server URL + API token (hidden) |
| `vault-console secret gmail [LABEL]` | One Gmail account: the label (asked if not given; Enter = `main`, the first account), the address and the Google app password (hidden). Asks y/N before replacing a stored label, then tests the IMAP login at once. A new label (e.g. `work`) adds a further account (secret `gmail:work`, at most 5). |
| `vault-console tg-credentials` | Telegram `api_id` + `api_hash` from my.telegram.org. Asks y/N before replacing. Refused while a session exists. |
| `vault-console 2fa` | The Telegram 2FA password during a QR login. Never stored. |
| `vault-console pending` / `approve RID` / `deny RID` | Decide a raw request |
| `vault-console watch [--full]` | Live view (above): `--full` = REQUEST / RAW / RESPONSE per call |

A console secret may replace a stored one without a code, because the owner is present. Console auth: the
`X-Vault-Console` key (`/data/state/console.key`, new at every start), from 127.0.0.1 only, limited to
`CONSOLE_ROUTES`.

**First-time setup:**
1. The API token: the assistant creates and keeps it; the owner stores its sha256 in the server's `.env`
   (`vault-deploy token-hash <sha256>`).
2. The first deploy, by the owner's button (see [Deploy](#deploy)).
3. On the console: `secret telegram`, then `tg-credentials`.
4. `vault tg login-qr`, then `vault-console 2fa` if the account asks for it.
5. On the console: `secret paperless` / `firefly` / `gmail` (and `secret gmail work` for a second Gmail account).

## Several Gmail accounts

- Secret `gmail` is the account labelled `main` (unchanged). Every further account is its own secret `gmail:LABEL`
  (label: a letter, then up to 15 letters, digits, `-` or `_`; not `all`) with the same write-only rules.
- Each account has its own IDLE + poll threads, state (`gmail.json` / `gmail.LABEL.json`: UID positions), folder
  config (`gmail-config.json` / `gmail-config.LABEL.json`), 30-min login block and alerts (`gmail-auth-LABEL`). An
  account added while the vault runs starts at once.
- Mail REFs carry the account: `main:1234`, `work:1234@Folder`. A bare `1234` works only while there is one account;
  otherwise give `account` (the API answers 400 `account_needed`).
- Search covers every account unless `account` is given; results are merged newest first, and an account that fails
  is listed under `errors`. Events, results and status show the label and the domain, never the address.
- The pinned board and `/status` show the worst account state; with several accounts the board adds one line per
  label.

## Home Assistant status feed

`app/ha.py` (inventory) and `app/ha_live.py` (live feed). Read-only toward Home
Assistant, the owner's phone only (entity prefix `VAULT_HA_DEVICE`); switch env `VAULT_HA_FEED=1` ("0" = off, `/ha/now`
409 `ha_off`).

- **Inventory** (`GET /ha/inventory`, `vault ha inventory`): entity_id, domain, device_class, unit, netted friendly
  name and the *kind* of state. Never a state or attribute value, coordinates, SSID, address or Bluetooth device name.
- **Connection:** a stdlib websocket client whose send path allows only auth, get_states, subscribe_trigger (`state`,
  allowlisted entities) and ping (tested). While it is down: REST GET poll every 60 s, reconnect backoff 5 s-5 min;
  the allowlist refreshes every 6 h.
- **Coarse flags** (`GET /ha/now`, `vault ha now`): zone name, or away + distance band (< 5 / 5-50 / > 50 km) + town
  (locality only); drive start/end (Android Auto); activity, sleep, alarm, battery, phone/DND; Bluetooth as categories,
  Wi-Fi as HMAC classes. Each with its age. No coordinates: those stay raw source `location` (owner's ✅).
- **Events:** changes go into the feed as source `homeassistant` (column `ha`), debounced per signal, at most 12 an hour
  and 4 per signal (folded). `/status` → `ha` (on/off, websocket|polling, counts). Audit `ha_now`, `ha_inventory`.

## Deploy

Deploys are the owner's. The assistant's SSH key on the host runs only a fixed list of commands through a
dispatcher (the server-side lockdown, not included here): none of them builds, starts, stops or enters the vault
or touches its folder or volume. The host's deploy script (`vault-deploy`, an Unraid User Script, not included)
fetches the commit from GitHub with a read-only deploy key.

**Preparing a deploy (assistant):** `vault admin deploy` runs `vault-git-sync`, which commits and pushes this tree
to GitHub after a `secretscan` of the diff. It prints `ready for your deploy: <commit>` with the commits since the
last deploy, and flags privacy-relevant files (`vendor/llm-local`, `app/`, `Dockerfile`, `docker-compose.yml`,
`requirements/`).

**The button:** Unraid → Settings → **User Scripts** → **claude-vault deploy** → Run Script with `<commit>` shows
the review: commits, changed files, and full diffs of the privacy filter and container settings. Run again with
`<commit> confirm`: it builds the image, runs `tests/run-all.sh` inside it without network, adds missing model
files (sha256-pinned in `app/vaultd.py`), switches to the new container and checks `/health`. If the build, the
tests or the model files fail, the old vault keeps running. A rollback is a deploy of an earlier commit.

**Telegram-approved deploys** (`app/deploys.py`; on the host: the lockdown's deploy runner, not included here). The
owner approves a deploy in the vault bot, and a root runner on the host checks the approval and runs the same deploy
script as the button.
1. `vault deploy request <commit>` (on GitHub `main`): the vault writes a review request into the deploy mailbox,
   `/deploy/requests` (the vault's folder).
2. The runner (every minute) reviews the commit with the deploy script and writes the facts to `/deploy/results`
   (read-only in the vault): kind (update, ROLLBACK, rebuild), commits, changed files, flags (weights, privacy
   filter, image build) and whether Telegram may deploy it.
3. If it may, the vault bot sends a card with ✅ Deploy / ❌ Cancel. A ✅ from the owner's chat and user, on that card,
   with its single-use nonce, writes the approval: request id, commit, the sha256 of the facts on the card, an expiry
   of 30 min. No API route writes an approval.
4. The runner checks the approval (format, single use, expiry, the facts' sha256, a fresh review with the same facts,
   at most 6 a day), runs `<commit> confirm` and writes the outcome; the vault tells the owner.

Only the button deploys the first version, a change of `docker-compose.yml` (privileges, mounts, user), another
compose file, a symlink, submodule or `.gitattributes`, `vault.env` lines other than `VAULT_NAME=value` (or the API
token's hash), and odd model pins. The vault's settings live in `vault.env` so that a Telegram deploy can change them;
the server's `.env` wins over it. A compromised vault could approve its own deploys: commits on `main` only, never a
change of container privileges, at most 6 a day, each one in the host's notifications. The file formats: the docstring
of `app/deploys.py`.

**Operations:** the assistant has `vault admin logs` and `ps` (read-only commands on the host). Restarting or
stopping the vault (Unraid's Docker tab), the API token's hash (`vault-deploy token-hash`) and the server's `.env`
are the owner's.

## Repo layout

```
app/vaultd.py         HTTP API, routes, owner console (vault-console), live view
app/vaultlib.py       config, secret store, audit, notifier + approval bot, raw state machine, LLM gate,
                      policy layer, event feed (store, rules, triage)
app/sources.py        Telegram (tgread subprocess + live job), paperless, Firefly
app/gmail.py          read-only IMAP source + IDLE watcher
app/finance.py        bank-export intake via the vault bot → Firefly sync
app/board.py          pinned status message
app/watch.py          /watch in the vault bot (live view of the assistant's calls in the owner's chat)
app/metrics.py        health metrics (hourly numbers, 30 days)
app/llmproxy.py       per-request LLM gate: priority proxy between llm-local and llama-server (127.0.0.1:8180)
app/jobs.py           async jobs (memory only; chunked Telegram summaries run in sources.TG.summarize_chunked)
app/facts.py          vault facts: structured extraction from anonymized text, grounded in code; /plans
app/find.py           vault find: Telegram + Gmail + paperless in one ranked list, word variants, one anonymize call
app/answer.py         answers, not text: kinds, checks in code, cache, digest, mail card, hybrid retrieval
app/sessions.py       follow-up ask sessions (memory only)
app/people.py         person cards: metadata, relations from the owner, night worker
app/index.py          embed server, sqlite-vec semantic index of Telegram, bake-off
app/asks.py           open asks on person cards
app/topics.py         topic enums per chunk by prototype cosine, calibration
app/ha.py             Home Assistant inventory (metadata only)
app/ha_live.py        Home Assistant read-only websocket feed, coarse flags
app/intake.py         document intake via the vault bot (photos/PDFs -> paperless)
app/deploys.py        Telegram-approved deploys: request files, the card from the host's review, the approval
app/media.py          media: file metadata, owner-approved bundles, extraction
app/llm-ctl           llm-local's server control inside the vault (vaultd supervises llama-server)
vendor/               tgread, llm-local (anonymizer prompts), secretscan.py, bills, firefly_sync/
requirements/         hash-pinned Python deps (tgread, finance, build)
tests/                unit tests and suites (below)
Dockerfile            3 stages: llama.cpp build, Python venv, runtime
docker-compose.yml    network, volume, hardening, deploy mailbox
vault.env             the vault's settings: feature switches, model path (VAULT_NAME=value lines only)
.env.example          VAULT_TOKEN_SHA256= (the real .env is never committed)
```

`vendor/llm-local`, `vendor/secretscan.py`, `vendor/bills`, `tests/tgread/` and `tests/llm-local/` are mirrored from
the assistant's home by `vault-git-sync`. Edit them at the source, not here.

Env switches: `VAULT_TEST_MODE`, `VAULT_NO_LLAMA`, `VAULT_NO_SYNC`, `VAULT_NO_LIVE`, `VAULT_NO_APPROVAL_BOT`,
`VAULT_NO_STATUS_BOARD`, `VAULT_NO_GMAIL` (`=1`); `VAULT_LLM_PROXY=0`, `VAULT_LLM_PROXY_PORT`, `VAULT_LLM_PREEMPT_S`.
Feature switches in `vault.env` (all on, `0` = off): `VAULT_ASK_SESSIONS`, `VAULT_PEOPLE`, `VAULT_PEOPLE_ASK`,
`VAULT_PEOPLE_ASKS`, `VAULT_EMBED=embeddinggemma`, `VAULT_INDEX`, `VAULT_PHOTOS`, `VAULT_VISION`, `VAULT_HA_FEED`
(+ `VAULT_PEOPLE_ASKS_PER_DAY` 1..100, default 20). This server's values (`.env`): `VAULT_HA_DEVICE`,
`VAULT_MODELS_DIR`, `VAULT_CPUS`, `VAULT_CPUSET`, `VAULT_MEM_LIMIT`, `VAULT_DEPLOY_DIR`.

## Tests

All offline: fake Telegram, IMAP, paperless, Firefly and Home Assistant servers, and a mock LLM.

```sh
# from the repo root, system python3
python3 -I tests/test_vault.py      # secrets, audit, raw state machine, approval bot, policy, API, events, board
python3 -I tests/test_deploys.py    # Telegram-approved deploys: request, card from the host's review, tap, expiry
python3 -I tests/test_gmail.py      # read-only IMAP guarantee, IDLE, triage, API, two accounts
python3 -I tests/test_media.py      # media: list, approval bundle, facts only, type checks, extraction, acks
python3 -I tests/test_facts.py      # facts (grounding, dates, refs, nets, cache), find (variants, rank, one call), plans
python3 -I tests/test_sessions.py   # follow-up ask sessions + times always dated
python3 -I tests/test_people.py     # person cards: metadata cards, relation only from the owner, forget, purge
python3 -I tests/test_people_v2.py  # open asks, statuses, expiry, caps, topics, poisoning suite
python3 -I tests/test_answer.py     # answers: kinds, checks, time words, digest, mail card
python3 -I tests/eval_answers.py    # answer-eval fixtures consistent (--real: scored on the model, ~4 min)
VAULT_VEC_PATH=.../vec0 python3 -I tests/test_index.py   # chunker, RRF, sqlite-vec, embed server, eval, index.db, hybrid
python3 -I tests/test_finance.py    # bank-export intake, Firefly sync (fake Telegram + Firefly)
python3 -I tests/test_intake.py     # document intake via the vault bot
python3 -I tests/test_ha.py         # HA inventory: metadata only, other people excluded
python3 -I tests/test_ha_live.py    # HA feed: fake websocket + REST, send allowlist, coarsening, rate limits

# tgread needs a venv with requirements/tgread.txt (Telethon); absolute paths (run.sh cds into its dir)
TGREAD_BIN=$PWD/vendor/tgread SECRETSCAN_BIN=$PWD/vendor/secretscan.py \
  TGREAD_PY=<tgread-venv>/bin/python3 tests/tgread/run.sh
LLM_LOCAL_BIN=$PWD/vendor/llm-local LLM_LOCAL_SKIP_REAL=1 bash tests/llm-local/run.sh   # mocked LLM

# everything, inside the built image (no network, read-only root); every deploy runs it before the switch
docker run --rm --network none --read-only --tmpfs /tmp:rw,exec --cap-drop ALL \
  --entrypoint /bin/sh IMAGE /opt/vault/tests/run-all.sh
```

`tests/llm-local/run.sh --real` / `--real-money` / `--real-swiss` (the Swiss German paraphrase eval) add the slow
checks against the real model. Set
`LLM_LOCAL_REAL_BACKEND=vault` to run them through the deployed vault.
