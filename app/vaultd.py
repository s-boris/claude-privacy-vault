#!/usr/bin/python3 -I
"""vaultd: HTTP API of the privacy vault (container claude-vault, http://claude-vault:8300 on the Docker network
src_default only; no port is published to the LAN).

Every call except GET /health needs `Authorization: Bearer <token>`; the vault only knows the token's sha256
(VAULT_TOKEN_SHA256). Responses are policy-filtered (vaultlib.Policy) unless stated otherwise:
  GET  /status                      vault, LLM, Telegram, paperless, Firefly, raw-request state (no data)
  POST /tg/<cmd>                    tgread search|recent|unread-summary-data|summarize|chats|status|exclude|purge|
                                    sync|wipe|allowlist|selfcheck; body = tgread options as JSON (see sources.TG_SPECS)
  POST /tg/credentials {api_id, api_hash}       set once (tgread set-credentials); GET: {credentials, logged_in}
  POST /tg/login-qr {timeout}  GET /tg/login    QR login: PNG as base64, refreshed; POST /tg/login-cancel
  POST /tg/2fa {password}                        to the waiting login's stdin; never stored or logged
  POST /paperless/search {q, n} | /recent {n} | GET /paperless/meta      metadata only
  POST /paperless/get {id}                       a CARD: metadata + amount/currency/due date, never content (plan B,
                                    2026-10-14; content: raw source paperless-anon, the owner's ✅)
  POST /paperless/fields {id, fields}            whitelisted structured fields: tier 1 free; tier 2 (IBAN, reference,
                                    numbers, addresses, dates) null + _withheld (raw source paperless-fields: his ✅)
  POST /paperless/suggest {id, chars?}           type/correspondent/tags from the existing names, picked by the local
                                    model on the content inside the vault (no content leaves)
  POST /paperless/rule-test {kind, match, matching_algorithm, is_insensitive?, name?}   which documents a matching
                                    rule would hit: ids + their current value only
  GET  /intake/status                            the vault bot's document intake (photos/PDFs -> paperless): counts
  POST /paperless/upload {...} | /paperless/task {task_id}
  POST /paperless/update {id, title?, created?, document_type?, correspondent?, tags_add[], tags_remove[], create?}
                                    metadata only (no content/notes/owner/permissions, no delete); answers metadata
  POST /paperless/taxonomy {kind, name, match?, matching_algorithm 0-6?, is_insensitive?, is_inbox_tag?, create?}
                                    create/update the matching rule of a tag/type/correspondent (no delete);
                                    GET /paperless/meta shows the rules
  GET  /firefly/status | POST /firefly/summary {start, end} | /firefly/merchants {start, end, limit}
  GET  /finance/status | GET /finance/rules   the bank-export sync: counts; its private rules: set?, sha256, counts
  POST /finance/rules {rules[, request_id, code]}   the sync rules (firefly_rules.json), write-only: set once;
                                    replacing needs the owner's code (raw request with source "finance-rules")
  POST /finance/check                read-only dry run of the sync against Firefly: numbers only, no message
  GET  /gmail/status                READ-ONLY Gmail (app/gmail.py), per account (label main = secret gmail, others
                                    gmail:<label>): watcher (IDLE + 15-min poll), positions, folders
  POST /gmail/search {q, n, folder, account, triage?}   Gmail search syntax in one account or all (default); default:
                                    ref/date/from/category (the feed's triage or the label cache, "?" = not triaged;
                                    triage=true: ONE local-LLM call for those); text=true: the owner's ✅ first
  POST /gmail/get {uid, folder, chars, account, deep?}  default: a quick card from the triage (feed, cache or ONE
                                    call); deep=true: the full card (anonymized mail + one answer call, with dates).
                                    uid = a REF (work:1234@Folder); account: from the REF, the param or the only one
  POST /events/retriage {since, max}   re-triage stored Gmail events (max 20, one call); counts + cursors only
  GET|POST /gmail/config {account, folders, owner_name}   per account: extra folders/labels (INBOX always), name
  POST /gmail/to-paperless {uid, attachment, folder, account, title?, tags?, ...}   an attachment into paperless
  GET  /gmail/import?plan=ID | POST /gmail/import/scan {accounts?, since?, max?, download?, llm?, resume?} |
       /gmail/import/run {plan, categories, limit?, office?, likely?, pause?, dry?} | /gmail/import/cancel {plan?} |
       /gmail/import/drop {plan}    mail backfill into paperless (app/mailimport.py): plan rows stay in the vault;
                                    answers are counts, categories, years, sender domains / first names
  POST /llm/run {args, text}        llm-local on the caller's own text (the KV cache is flushed first)
  POST /jobs {op, params}           async job (app/jobs.py, plan v2 #4): op = tg.search|tg.recent|tg.unread-summary-data|
                                    tg.summarize (chunked: per chat/day, then a merge)|gmail.search|gmail.get|
                                    paperless.get|media.extract|llm.run, params = that route's body -> {id, state,
                                    position, eta_s, coalesced}; never raw, secret, console or write routes
  GET  /jobs/<id>?wait=N (<= 30)    state, progress, partial results, then the route's answer (kept 30 min, 20 MB)
  GET  /jobs | POST /jobs/<id>/cancel           the caller's jobs (no results) | stop one
  POST /raw/request {source, query, reason} -> the owner gets the request from the vault's own bot with
                                    ✅ Allow once / ❌ Deny buttons (fallback while the bot can't poll: a 6-digit code)
  POST /raw/release {request_id, wait?, code?} -> the raw text/file once the owner allowed it ({status: released});
                                    else {status: pending} after waiting up to `wait` s (<= 30); denied/expired: 410.
                                    code: only for fallback-code requests (3 wrong codes kill it)
  GET  /raw/pending | GET /audit?days=7 | GET /alerts | POST /alerts/ack {names}
  POST /deploy/request {commit} -> the host runner reviews the commit (on GitHub main), then the owner gets a card
                                    with ✅ Deploy / ❌ Cancel in the vault's bot; on ✅ the runner deploys it (app/deploys.py)
  GET  /deploy/status?id=ID         the runner (alive, busy, deployed commit) and the deploy requests (no data)
  POST /media/list {source: tg|gmail|paperless, chat | ref | id, type?, since?, grep?, n?}   files as metadata only
                                    (date, labels, type, size, pages/duration, privacy-filtered names); app/media.py
  POST /media/request {keys[1..5], reason, keep_minutes?<=120} -> the owner's ✅ Allow once / 📋 Facts only / ❌ Deny
                                    with the preview; the files are fetched read-only and type-checked from the bytes
  POST /media/release {request_id, wait?, code?} -> files once (base64, sha256) | facts (after Facts only)
  POST /media/ack {request_id, event: saved|deleted, files: [sha256]}   the client's deletion promise, audited
  POST /media/extract {key, kind?}  facts from a PDF/.ics without approval (anonymized, grounded, no PNR/prices)
  POST /tg/facts {chat, since?, n?} | /gmail/facts {uid, folder?, account?, chars?}   events, to-dos, places,
                                    decisions, open questions as JSON from the anonymized (not paraphrased) text; every
                                    value grounded in it, dates from the message times (app/facts.py, plan v2 #6)
  POST /find {q, since?, sources?, n?}   one ranked list across Telegram, Gmail and paperless with Swiss German /
                                    German / English word variants; one anonymize call; paperless metadata only (#10)
  GET  /plans?days=14               dated facts of the event feed (calendar suggestions, plan v2 #11)
  GET  /events?since=CURSOR|latest&max=N&source=telegram|gmail   the live event feed: new incoming messages and
                                    mails, triaged and anonymized by the local LLM (actionable/priority ones with
                                    text; chatter/newsletters only counted); GET /tg/events = source telegram
  GET  /events/rules | POST /events/rules {source, mode: mute|priority|normal, chat | sender}
  GET  /secrets | POST /secrets/<telegram|paperless|firefly|gmail|gmail:LABEL> {...}   write-only; replacing needs
                                    the owner's code (raw request source "secret-rotate"); raw sources include gmail
                                    {uid, folder?, account?, attachment? | eml?}

Owner console (the owner at the Unraid terminal, never the assistant): `docker exec -it claude-vault vault-console
2fa | secret NAME | tg-credentials` types the Telegram 2FA password, a secret or the Telegram API credentials straight
into the vault. It authenticates with X-Vault-Console (a random key in /data/state/console.key, new at every start),
from 127.0.0.1 only, and reaches only CONSOLE_ROUTES; a console secret may replace a stored one without a code (the
owner is present; tg-credentials asks y/N first). `vault-console pending | approve RID | deny RID` decides a raw
request (POST /raw/approve: console only, never the API token; with GET /raw/pending).

Pinned status for the owner (app/board.py): one silent, pinned message in the vault bot's chat, edited in place
(at most every 30 s on a change, every 10 min for the clock, at once on his /status): current activity, today's
counts (Claude's requests by kind, raw asks + his decisions, redactions, new Telegram messages / mails and how many
were surfaced to Claude, Firefly imports) and health. Counts and states only. GET /status -> board.

Live view for the owner: every API call writes one line to stderr (docker logs; Unraid > Docker > claude-vault >
Logs): caller, method + path, allowlisted parameters (none on secret routes), status, response size, duration and
the redaction counts of filtered results; never a response body. `vault-console watch [--full]` follows the same
calls from an in-memory ring buffer (GET /console/events, console key only); --full adds each response body as
the assistant got it, cut to 4 KB, with the vault's secret values and live raw codes scrubbed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
os.umask(0o077)

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import secrets
import select
import socket
import shutil
import signal
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import answer as AN
import board as B
import deploys as DP
import facts as FX
import find as FD
import gmail as G
import ha_live as HL
import index as IX
import intake as IN
import jobs as J
import llmproxy as LP
import mailimport as MI
import media as M
import people as PP
import metrics as MX
import sources as S
import vaultlib as V
import watch as W
from vaultlib import NotConfigured, VaultError

try:
    import finance as F                        # the bank-export intake: private-only (plan D2), absent in public
except ImportError:
    F = None

# Local LLM (Gemma-4-26B-A4B replaces Qwen3.5-9B; bench in the assistant's
# ~/reports/research/llm-bench-2026-10-14.md, switch + rollback in ~/reports/vault/gemma-switch-2026-10-14.md).
# The weights live in cfg.weights (VAULT_WEIGHTS=/models: a read-only bind of the data pool, seeded by `vault admin
# deploy`); each file is sha256-checked before llama-server may load it. The old Qwen file stays in /data/models.
MODEL_FILE = 'gemma-4-26B-A4B-it-UD-IQ4_XS.gguf'
MODEL_SHA256 = 'babd1e389d386352f71600765d37390f7dc993fbfad6725caccf996ffe34aecf'
MODEL_URL = 'https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF/resolve/main/gemma-4-26B-A4B-it-UD-IQ4_XS.gguf'
DRAFT_FILE = 'mtp-gemma-4-26B-A4B-it.gguf'        # its MTP drafter for speculative decoding (-md); '' = none
DRAFT_SHA256 = '6326fb9f5e487aa8dcdd313a091e3c67724cb2a666ec3b7d2895b5b26d93ed1b'
DRAFT_URL = 'https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF/resolve/main/mtp-gemma-4-26B-A4B-it.gguf'
WEIGHTS = [(MODEL_FILE, MODEL_SHA256, MODEL_URL)] + ([(DRAFT_FILE, DRAFT_SHA256, DRAFT_URL)] if DRAFT_FILE else [])
# The model's vision projector (16.10, vault-photos round 4): `vault media facts` on a photo lets the model read the
# image itself (llama-server --mmproj; +1.2 GB, ~30-45 s of the slot per image); OCR stays the fallback and the event
# feed's reader. Optional on purpose: missing (seeded by `vault admin deploy`, never downloaded here), failing its
# sha256, VAULT_VISION=0 or llama-server failing twice with it -> llama-server runs without it, photos fall back to OCR.
MMPROJ_FILE = 'mmproj-gemma-4-26B-A4B-it-F16.gguf'   # unsloth's mmproj-F16.gguf of this model, renamed in /models
MMPROJ_SHA256 = '418a6d8723067cd712235facbbc5cba6c8fbbd413fc1292d2aace5a027d5a42f'
MMPROJ_URL = 'https://huggingface.co/unsloth/gemma-4-26B-A4B-it-GGUF/resolve/main/mmproj-F16.gguf'
# Embedding models (vault memory plan C3, 15.10): GGUFs from the official repos (Qwen; ggml-org = llama.cpp's own org for
# EmbeddingGemma and bge-m3), sha256 = the files' Hugging Face LFS ids; seeded by `vault admin deploy` (~/bin/vault
# weight_pins reads every EMBED_*_FILE/_SHA256/_URL here) and verified by app/index.py before load. VAULT_EMBED picks
# the one the embed server runs; `vault index eval` (the bake-off) runs each in turn.
EMBED_GEMMA_FILE = 'embeddinggemma-300M-Q8_0.gguf'
EMBED_GEMMA_SHA256 = 'b5ce9d77a3fc4b3b39ccb5643c36777911cc4eb46a66962eadfa3f5f60490d63'
EMBED_GEMMA_URL = 'https://huggingface.co/ggml-org/embeddinggemma-300M-GGUF/resolve/main/embeddinggemma-300M-Q8_0.gguf'
EMBED_QWEN_FILE = 'Qwen3-Embedding-0.6B-Q8_0.gguf'
EMBED_QWEN_SHA256 = '06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439'
EMBED_QWEN_URL = 'https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/main/Qwen3-Embedding-0.6B-Q8_0.gguf'
EMBED_BGE_FILE = 'bge-m3-q8_0.gguf'
EMBED_BGE_SHA256 = 'aa473d51f451a22f0fcf39ba3330c14bed38a385712b1113440f69df4047a173'
EMBED_BGE_URL = 'https://huggingface.co/ggml-org/bge-m3-Q8_0-GGUF/resolve/main/bge-m3-q8_0.gguf'
EMBED_FILES = {'embeddinggemma': (EMBED_GEMMA_FILE, EMBED_GEMMA_SHA256, EMBED_GEMMA_URL),
               'qwen3-0.6b': (EMBED_QWEN_FILE, EMBED_QWEN_SHA256, EMBED_QWEN_URL),
               'bge-m3': (EMBED_BGE_FILE, EMBED_BGE_SHA256, EMBED_BGE_URL)}
LLAMA_ARGS = ['-c', '32768', '-np', '1', '-t', '6', '-tb', '12', '--no-webui', '--no-slots', '--reasoning', 'off',
              '--cache-ram', '0', '--spec-type', 'draft-mtp', '--spec-draft-n-max', '3']
MAX_TEXT_PAYLOAD = 5_000_000
# Privacy plan A (2026-10-14): routes answer with structured, checked values; their text only with text=true + a
# reason, released after the owner's ✅. TEXT_DEFAULT = False since chunk 4: calls without
# the flag get the structured default (hits, digest, cards); True would bring back the old text output.
TEXT_DEFAULT = False
TEXT_ROUTES = ('/tg/search', '/tg/recent', '/tg/unread-summary-data', '/tg/summarize', '/gmail/search', '/gmail/get',
               '/find')
TEXT_TG = ('search', 'recent', 'unread-summary-data', 'summarize')
TEXT_ALERT_PER_DAY = 10
# quick mail card: the triage's `wants` -> the card's `action` (answer.ACTIONS)
WANT_ACTION = {'reply': 'reply', 'decision': 'decide', 'meeting': 'attend', 'document': 'send', 'payment': 'pay',
               'pickup': 'pick_up', 'call': 'call', 'info': 'reply', 'favour': 'none', 'none': 'none'}
MAX_FILE_PAYLOAD = 50 << 20
ALERT_RE = re.compile(r'(?:tgread|vault)-[\w.-]{1,120}\.md')


def log(msg):
    print(f'{V.now_iso()} {msg}', file=sys.stderr, flush=True)


def where(e):
    """Exception type + innermost frames, never the message (it could quote private data)."""
    tb = traceback.extract_tb(e.__traceback__)[-3:]
    return f'{type(e).__name__} at ' + ' < '.join(f'{os.path.basename(f.filename)}:{f.lineno}' for f in reversed(tb))


# ============================================================================================ llama-server

class Llama:
    """Supervises llama-server (127.0.0.1 inside the vault only): verifies the sha256 of every weight file (model +
    drafter) once (marker keyed by name + size + mtime), downloads a missing one if its dir is writable, restarts the
    server with backoff."""

    def __init__(self, cfg, alert):
        self.cfg, self.alert = cfg, alert
        self.state, self.detail, self.proc, self.started, self.restarts = 'stopped', '', None, None, 0
        self.verified = False
        self.vision, self.vision_detail, self.vision_fails = False, 'not checked yet', 0
        self.stop_ev = threading.Event()

    @property
    def model(self):
        return self.cfg.weights / MODEL_FILE

    @property
    def draft(self):
        return self.cfg.weights / DRAFT_FILE if DRAFT_FILE else None

    @property
    def mmproj(self):
        return self.cfg.weights / MMPROJ_FILE if MMPROJ_FILE else None

    def vision_ready(self):
        """Media: may a photo go to the model's vision now? (projector verified and loaded, server running)"""
        return self.vision and self.state == 'running'

    def http(self, path, body=None, timeout=5):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{self.cfg.llama_port}{path}', data=data,
                                     headers={'Content-Type': 'application/json'})
        with V.OPENER.open(req, timeout=timeout) as r:
            return json.loads(r.read() or b'{}')

    def healthy(self):
        try:
            return self.http('/health', timeout=3).get('status') == 'ok'
        except Exception:
            return False

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def verify(self):
        marker = self.cfg.state / 'model-verified.json'
        try:
            done = json.loads(marker.read_text())
            done = done if isinstance(done, list) else [done]     # before 2026-10-14: one dict (one file)
        except (OSError, ValueError):
            done = []
        keys = []
        for name, sha, url in WEIGHTS:
            p = self.cfg.weights / name
            if not p.is_file():
                self.download(p, sha, url)
            st = p.stat()
            key = {'file': name, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'sha256': sha}
            if key not in done:
                self.state = 'verifying'
                h = hashlib.sha256()
                with open(p, 'rb') as f:
                    for chunk in iter(lambda: f.read(8 << 20), b''):
                        h.update(chunk)
                if h.hexdigest() != sha:
                    raise RuntimeError(f'{name}: sha256 mismatch, refusing to load it')
            keys.append(key)
        self.vision, self.vision_detail = False, 'off (VAULT_VISION=0)' if not self.cfg.vision else 'off (none pinned)'
        p = self.mmproj
        if self.cfg.vision and p is not None:      # optional: never downloaded here, never fatal (photos -> OCR)
            try:
                st = p.stat()
                key = {'file': MMPROJ_FILE, 'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'sha256': MMPROJ_SHA256}
                if key not in done:
                    h = hashlib.sha256()
                    with open(p, 'rb') as f:
                        for chunk in iter(lambda: f.read(8 << 20), b''):
                            h.update(chunk)
                    if h.hexdigest() != MMPROJ_SHA256:
                        raise RuntimeError('sha256 mismatch')
                keys.append(key)
                self.vision, self.vision_detail = True, 'on'
            except FileNotFoundError:
                self.vision_detail = f'off ({MMPROJ_FILE} is missing; `vault admin deploy` seeds it)'
            except (OSError, RuntimeError) as e:
                self.vision_detail = f'off ({MMPROJ_FILE}: {e.strerror if isinstance(e, OSError) else e})'[:200]
            if not self.vision:
                log(f'llama: vision projector {self.vision_detail}')
        if keys != done:
            V.write_private(marker, json.dumps(keys))
        self.verified = True

    def argv(self):
        return ['nice', '-n', '19', self.cfg.llama_bin, '--host', '127.0.0.1', '--port', str(self.cfg.llama_port),
                '-m', str(self.model)] + LLAMA_ARGS + (['-md', str(self.draft)] if self.draft else []) \
            + (['--mmproj', str(self.mmproj)] if self.vision else [])

    def download(self, p, sha, url):
        if not os.access(p.parent, os.W_OK):      # the read-only weights bind: `vault admin deploy` seeds it
            raise RuntimeError(f'{p.name} is missing in {p.parent} (read-only); `vault admin deploy` seeds it')
        self.state = 'downloading'
        part = p.with_name(p.name + '.part')
        V.ensure_dir(p.parent)
        h = hashlib.sha256()
        req = urllib.request.Request(url, headers={'User-Agent': 'claude-vault'})
        with V.OPENER.open(req, timeout=60) as r, open(part, 'wb') as f:
            for chunk in iter(lambda: r.read(8 << 20), b''):
                h.update(chunk)
                f.write(chunk)
        if h.hexdigest() != sha:
            part.unlink()
            raise RuntimeError(f'the downloaded {p.name} failed the sha256 check')
        os.replace(part, p)

    def run(self):
        backoff = 5
        while not self.stop_ev.is_set():
            try:
                if not self.verified:
                    self.verify()
            except Exception as e:
                self.state, self.detail = 'failed', f'{type(e).__name__}: {e}'[:300]
                log(f'llama: {self.detail}')
                self.alert('llm-model', 'local LLM model problem', self.detail)
                self.stop_ev.wait(3600)
                continue
            logf = self.cfg.logs / 'llama-server.log'
            try:
                if logf.stat().st_size > 20_000_000:
                    os.replace(logf, logf.with_name('llama-server.log.1'))
            except FileNotFoundError:
                pass
            cmd = self.argv()
            self.state, self.started, self.detail = 'starting', time.time(), ''
            fd = os.open(logf, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.STDOUT,
                                             env={'PATH': '/usr/bin:/bin', 'HOME': str(self.cfg.home), 'LANG': 'C.UTF-8'})
            except OSError as e:
                self.state, self.detail = 'failed', f'cannot start llama-server: {e.strerror}'
                log(f'llama: {self.detail}')
                self.stop_ev.wait(600)
                continue
            finally:
                os.close(fd)
            while self.running() and not self.stop_ev.is_set():
                if self.state == 'starting' and self.healthy():
                    self.state = 'running'
                    log(f'llama: running (pid {self.proc.pid}, {MODEL_FILE})')
                if self.state == 'running' and time.time() - self.started > 600:
                    backoff = 5
                self.stop_ev.wait(2)
            if self.stop_ev.is_set():
                break
            rc = self.proc.poll()
            self.restarts += 1
            if self.vision and self.state == 'starting':       # it never came up with the projector
                self.vision_fails += 1
                if self.vision_fails >= 2:
                    self.vision, self.vision_detail = False, 'off (llama-server did not start with it twice)'
                    log(f'llama: vision projector {self.vision_detail}')
            elif self.state == 'running':
                self.vision_fails = 0
            self.state, self.detail = 'restarting', f'llama-server exited (code {rc}); restart in {backoff} s'
            log(f'llama: {self.detail}')
            if self.restarts in (3, 10):
                self.alert('llm-restarts', 'local LLM keeps crashing', f'{self.restarts} restarts; last exit code {rc}. '
                           'See `vault admin logs` and /data/logs/llama-server.log in the vault.')
            self.stop_ev.wait(backoff)
            backoff = min(backoff * 2, 300)
        self.stop()

    def stop(self):
        self.stop_ev.set()
        p = self.proc
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        self.state = 'stopped'

    def flush(self):
        """Replace the slot's KV cache with a random prompt (before an external job runs after a private one)."""
        if not self.running():
            return                                     # no server process, no cache
        try:
            self.http('/completion', {'prompt': 'flush ' + secrets.token_hex(48), 'n_predict': 1,
                                      'cache_prompt': True, 'temperature': 0}, timeout=180)
        except urllib.error.URLError as e:
            if isinstance(getattr(e, 'reason', None), ConnectionRefusedError):
                return
            raise


# ============================================================================================ application

def _obj(v, what='query'):
    if not isinstance(v, dict):
        raise VaultError(f'{what} must be a JSON object', 400, 'bad_param')
    return dict(v)


def _doc_id(v):
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v.strip())
    if not (isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= 10 ** 9):
        raise VaultError('id must be a paperless document number', 400, 'bad_param')
    return v


def _int(v, lo, hi, name, default):
    if v is None:
        return default
    if isinstance(v, str) and re.fullmatch(r'\d{1,9}', v.strip()):
        v = int(v)
    if not (isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi):
        raise VaultError(f'{name} must be an integer {lo}..{hi}', 400, 'bad_param')
    return v


def _net_obj(v, net):
    """The regex net on every string of a JSON value (facts, plan v2 #11)."""
    if isinstance(v, str):
        return net(v)
    if isinstance(v, list):
        return [_net_obj(x, net) for x in v]
    if isinstance(v, dict):
        return {k: _net_obj(x, net) for k, x in v.items()}
    return v


def dt_ts(iso):
    return dt.datetime.fromisoformat(str(iso)).timestamp()


def tg_summary(q):
    parts = [str(q.get('cmd'))]
    if q.get('query'):
        parts.append(f"'{q['query']}'")
    for k in ('chat', 'from', 'since', 'until', 'hours', 'n'):
        if q.get(k) is not None:
            parts.append(f'{k}={q[k]}')
    return ' '.join(parts)


LLM_FLAGS = {'--anonymize': None, '--summary': None, '--strict': None, '--json': None, '--stats': None,
             '--keep-own-money': None, '--all-amounts': None, '--paraphrase': None,
             '--owner-name': ('str', 100), '--system': ('text', 20000), '--max-tokens': ('int', 1, 8192),
             '--temp': ('float', 0.0, 2.0), '--schema': ('text', 20000), '--chunk-chars': ('int', 500, 30000), '--timeout': ('int', 10, 7200)}


def llm_argv(args):
    """llm-local options from the caller, allowlisted and normalized to --flag=value."""
    if not (isinstance(args, list) and len(args) <= 30 and all(isinstance(a, str) for a in args)):
        raise VaultError('args must be a list of strings', 400, 'bad_param')
    out, i = [], 0
    while i < len(args):
        a = args[i]
        flag, _, val = a.partition('=') if a.startswith('--') and '=' in a else (a, '', None)
        spec = LLM_FLAGS.get(flag, 'x')
        if spec == 'x':
            raise VaultError(f'llm-local option {flag!r} is not allowed through the vault', 400, 'bad_param')
        if spec is None:
            if val is not None:
                raise VaultError(f'{flag} takes no value', 400, 'bad_param')
            out.append(flag)
            i += 1
            continue
        if val is None:
            if i + 1 >= len(args):
                raise VaultError(f'{flag} needs a value', 400, 'bad_param')
            val, i = args[i + 1], i + 2
        else:
            i += 1
        kind = spec[0]
        try:
            if kind == 'int':
                n = int(val)
                ok = spec[1] <= n <= spec[2]
            elif kind == 'float':
                n = float(val)
                ok = spec[1] <= n <= spec[2]
            elif kind == 'str':
                ok = 0 < len(val) <= spec[1] and '\n' not in val and '\x00' not in val
            else:
                ok = 0 < len(val) <= spec[1] and '\x00' not in val
        except ValueError:
            ok = False
        if not ok:
            raise VaultError(f'bad value for {flag}', 400, 'bad_param')
        out.append(f'{flag}={val}')
    return out


class NullFinance:
    """The bank-export intake when app/finance.py is absent (private-only, plan D2): nothing runs, the bot ignores
    bank exports and their buttons, /finance/* answers 404 (App._fin)."""
    busy = False
    rules_file = None

    def run(self, stop_ev):
        return None

    def on_message(self, msg):
        return None

    def on_callback(self, cq):
        return None

    def status(self):
        return {'installed': False, 'status': 'not installed'}


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.started = time.time()
        self.store = V.SecretStore(cfg)
        self.audit = V.Audit(cfg.audit_path)
        self.notifier = V.Notifier(self.store, cfg.telegram_api, cfg.test_mode, log=log)
        self.llama = Llama(cfg, self.alert)
        self.llm_proxy = None
        self.metrics = MX.Metrics(cfg.state / 'metrics.json', alert=self.alert,          # numbers only (G7)
                                  stats_file=cfg.state / 'llm-stats.jsonl')
        self.gate = V.LLMGate(flush=self.llama.flush, metrics=self.metrics)
        self.policy = V.Policy(cfg, self.gate)
        key = self.store.hmac_key()
        self.approval = V.ApprovalBot(cfg, self.store, self.notifier, self.audit, log=log, alert=self.alert)
        self.raw = V.RawRequests(self.notifier, self.audit, key, net=self.policy.regex_net, approver=self.approval,
                                 on_volume=self.raw_volume_alert)
        self.approval.raw = self.raw
        self.policy.nets.append(self.raw.scrub_codes)
        self.tg = S.TG(cfg, self.policy, self.gate, self.audit, self.notifier, bot_ids=self.approval.known_bot_ids,
                       alert=self.alert)
        self.tg.login.on_success = self.after_login
        self.events = V.EventStore(cfg.state / 'events.db')
        self.rules = V.EventRules(cfg.state / 'events-rules.json')
        self.feed = V.EventFeed(self.events, self.rules, self.policy, self.gate)
        # HA status feed: websocket listener, coarse flags only; VAULT_HA_FEED=1 turns it on
        self.ha = HL.HALive(cfg, self.store, self.events, net=lambda s: self.policy.regex_net(s, addresses=True),
                            key=key, audit=self.audit, alert=self.alert, log=log)
        self.feed.metrics = self.metrics
        self.events_error = ''
        self._vol_alert = 0.0
        self.paperless = S.Paperless(cfg, self.store, self.policy, self.gate, self.audit)
        self.paperless.metrics = self.metrics
        self.firefly = S.Firefly(cfg, self.store, self.policy, self.audit, key)
        self.gmail = G.GmailAccounts(cfg, self.store, self.policy, self.audit, key, alert=self.alert, log=log)
        self.media = M.Media(cfg, self.tg, self.paperless, self.gmail, self.policy, self.gate, self.audit, self.raw,
                             alert=self.alert)
        self.facts = FX.Facts(cfg, self.policy, self.gate, self.audit, model=MODEL_FILE, tg=self.tg,
                              gmail=self.gmail)    # plan v2 #6
        self.feed.facts = self.facts                   # plan v2 #11: calendar facts in the event feed
        self.feed.photo_text = self.media.feed_photo_text   # photos: OCR text into the triage + facts (16.10)
        self.media.vision_ready = self.llama.vision_ready    # media facts on photos: the model's vision (round 4)
        self.find = FD.Find(cfg, self.policy, self.audit, self.tg, self.gmail, self.paperless)   # plan v2 #10
        self.answer = AN.Answer(cfg, self.policy, self.gate, self.audit, tg=self.tg, gmail=self.gmail,
                                model=MODEL_FILE)     # privacy plan A: answers, not text
        self.tg.cache_hooks = [self.answer.clear_cache, self.answer.sessions.drop_all]   # plan C1: sessions too
        # memory plan C2: person cards (metadata only; VAULT_PEOPLE), relation buttons `p:` in the vault bot
        self.people = PP.People(cfg, self.tg, self.notifier, self.audit, key, net=self.policy.regex_net,
                                aliases=self.tg.alias_map, log=log)
        self.tg.purge_hooks = [self.people.on_purge]
        # memory plan C3: embedding server (VAULT_EMBED, SCHED_IDLE) + sqlite-vec + the bake-off (numbers only)
        self.index = IX.Index(cfg, self.tg, self.policy, self.gate, self.audit, EMBED_FILES, alert=self.alert, log=log,
                              key=key)
        # memory plan C4: index.db (kept while VAULT_EMBED is on) + hybrid retrieval for `vault ask` (VAULT_INDEX)
        self.answer.index = self.index
        self.tg.purge_hooks.append(self.index.on_purge)
        # memory plan C5: open asks (feed triage rows + nightly triage of his DM messages) and topics (VAULT_PEOPLE_ASKS)
        self.people.wire_v2(events=self.events, index=self.index, policy=self.policy, gate=self.gate, model=MODEL_FILE)
        self.tg.live.listeners.append(self.index.poke)
        self.approval.people = self.people
        self.feed.aliases = self.tg.alias_map
        self.finance = F.Finance(cfg, self.store, self.notifier, self.audit, log=log,     # bank exports via the bot
                                 bot_state=lambda: self.approval.state) if F is not None else NullFinance()
        self.approval.finance = self.finance
        self.intake = IN.Intake(cfg, self.store, self.notifier, self.audit, self.paperless,     # photos/PDFs via the bot
                                events=self.events, log=log)
        self.approval.intake = self.intake
        self.mailimport = MI.MailImport(cfg, self.gmail, self.paperless, self.policy, self.gate, self.audit, log=log)
        self._llm_ok = (0.0, False)
        self.board = B.StatusBoard(cfg, self.notifier, self.board_snapshot, events=self.events,  # pinned status
                                   enabled=self.board_enabled, log=log)
        self.approval.board = self.board
        self.audit.listeners.append(self.board.note_audit)
        self.stop_ev = threading.Event()
        self.sync_failures = 0
        self._auth_fail = [0, 0.0]
        self._alert_lock = threading.Lock()
        self._tl = threading.local()
        self.console_key = secrets.token_hex(32)       # owner console (vault-console), new at every start
        self.tap = V.LiveTap()                         # live view of the API calls (vault-console watch)
        self.jobs = J.Jobs(self.run_job, self.audit, outlook=self.gate.outlook)    # async jobs (plan v2 #4)
        self.watch = W.WatchBot(self.tap, self.notifier, self.audit, scrub=self.scrub, log=log)   # /watch in the bot
        self.approval.watch = self.watch
        # Telegram-approved deploys: the owner's ✅ on a card, the host runner deploys (app/deploys.py)
        self.deploys = DP.Deploys(cfg, self.notifier, self.audit, approver=self.approval, log=log)
        self.approval.deploys = self.deploys
        self._secret_vals = None
        V.ensure_dir(cfg.state)
        V.write_private(cfg.state / 'console.key', self.console_key)

    # ---------------------------------------------------------------- lifecycle
    def start_llm_proxy(self):
        """Per-request LLM gating (plan v2 #2b, app/llmproxy.py). VAULT_LLM_PROXY=0 turns it off;
        VAULT_LLM_PROXY_PORT (8180), VAULT_LLM_PREEMPT_S (20; 0 = never stop a running request). If it can't listen,
        each LLM run holds the gate as a whole (the old behaviour) and an alert says so."""
        env = self.cfg.env
        if env.get('VAULT_LLM_PROXY', '1') == '0':
            return
        try:
            self.gate.preempt_after = max(0.0, float(env.get('VAULT_LLM_PREEMPT_S', self.gate.PREEMPT_AFTER)))
        except ValueError:
            pass
        try:
            self.llm_proxy = LP.LLMProxy(self.gate, self.cfg.llama_port,
                                         port=int(env.get('VAULT_LLM_PROXY_PORT', '8180'))).start()
        except OSError as e:
            log(f'llm proxy: cannot listen ({e.strerror}); each LLM run holds the gate as a whole')
            self.alert('llm-proxy', 'LLM proxy not running', 'per-request LLM gating is off: live reads can wait '
                       'behind a whole bulk run. See `vault admin logs`.')
            return
        self.cfg.tool_llm_port = self.llm_proxy.port
        self.gate.proxy = self.llm_proxy
        log(f'llm proxy: per-request gating on 127.0.0.1:{self.llm_proxy.port} '
            f'(preempt after {self.gate.preempt_after:g} s)')

    def start(self):
        if not self.cfg.no_llama:
            threading.Thread(target=self.llama.run, name='llama', daemon=True).start()
            self.start_llm_proxy()
            threading.Thread(target=self.index.server.run, name='embed', daemon=True).start()   # no-op when off
            threading.Thread(target=self.index.run, args=(self.stop_ev,), name='index', daemon=True).start()
        else:
            self.llama.state = 'disabled'
        try:
            self.tg.ensure_config()
        except Exception as e:
            log(f'tgread config: {where(e)}')
        if not self.cfg.no_sync:
            threading.Thread(target=self.sync_loop, name='sync', daemon=True).start()
        threading.Thread(target=self.approval.run, args=(self.stop_ev,), name='approval-bot', daemon=True).start()
        threading.Thread(target=self.finance.run, args=(self.stop_ev,), name='finance', daemon=True).start()
        threading.Thread(target=self.intake.run, args=(self.stop_ev,), name='intake', daemon=True).start()
        threading.Thread(target=self.mailimport.run, args=(self.stop_ev,), name='mailimport', daemon=True).start()
        threading.Thread(target=self.watch.run, args=(self.stop_ev,), name='watch', daemon=True).start()
        threading.Thread(target=self.deploys.run, args=(self.stop_ev,), name='deploys', daemon=True).start()
        if self.tg.live.enabled:
            threading.Thread(target=self.tg.live.run, args=(self.stop_ev,), name='tg-live', daemon=True).start()
            threading.Thread(target=self.events_loop, name='events', daemon=True).start()
        self.gmail.start(self.stop_ev, self.feed)      # IDLE + poll per Gmail account; VAULT_NO_GMAIL=1: none
        if self.ha.enabled:                            # HA status feed (read-only websocket + REST fallback)
            threading.Thread(target=self.ha.run, args=(self.stop_ev,), name='ha-live', daemon=True).start()
        threading.Thread(target=self.ticker, name='ticker', daemon=True).start()
        threading.Thread(target=self.board.run, args=(self.stop_ev,), name='status-board', daemon=True).start()

    def stop(self):
        self.stop_ev.set()
        try:
            self.metrics.flush()
        except Exception as e:
            log(f'metrics flush: {where(e)}')
        self.tg.login.cancel()
        self.tg.live.stop(timeout=10)
        self.llama.stop()
        self.index.server.stop()

    def ticker(self):
        """Once a minute: the owner's daily raw-release summary (20:00 Zurich, only on days with activity) and
        event-feed retention."""
        while not self.stop_ev.wait(60):
            try:
                self.approval.daily_summary()
                self.events.prune()
                self.media.check_acks()
            except Exception as e:
                log(f'ticker: {where(e)}')
            try:
                self.people.tick()                     # memory plan C2: person cards at 03:00 (+ first, after purge)
            except Exception as e:
                log(f'people: {where(e)}')
            try:
                self.metrics.tick()                    # llm-local's numbers in, the slow-queue alert, flush
            except Exception as e:
                log(f'metrics: {where(e)}')

    def raw_volume_alert(self, n):
        """More raw requests in an hour than usual: tell the OWNER directly (the assistant could ignore its own
        inbox), at most once an hour, plus a vault alert note."""
        self.audit.log('raw_volume_alert', per_hour=n)
        if time.time() - self._vol_alert < 3600:
            return
        self._vol_alert = time.time()
        try:
            self.notifier.send(f'⚠️ Vault: unusual volume\n{n} raw requests in the last hour\n'
                               f'(the hourly limit is {V.RawRequests.MAX_PER_HOUR})\n'
                               f'Only allow what you asked for.\n`vault audit` lists them.')
        except V.NotifyError as e:
            log(f'volume alert not sent: {e}')
        self.alert('raw-volume', 'unusual raw-request volume', f'{n} raw requests in the last hour; the owner was '
                   f'told on Telegram.', hours=1)

    # ---------------------------------------------------------------- pinned status (app/board.py)
    def board_enabled(self):
        if self.cfg.test_mode or self.cfg.no_status_board:
            return False, 'test mode / VAULT_NO_STATUS_BOARD=1'
        if self.approval.state != 'polling':
            return False, f'only with the vault\'s own bot (vault bot: {self.approval.state})'
        return True, ''

    def board_snapshot(self):
        """States for the pinned status: flags, counts and the LLM gate's job label (no content)."""
        now = time.time()
        pend = []
        for r in self.raw.pending():
            try:
                exp = dt_ts(r.get('expires_at'))
            except ValueError:
                exp = now
            pend.append({'state': r.get('state'), 'approval': r.get('approval'), 'kind': r.get('kind'),
                         'source': r.get('source'), 'expires': exp})
        if self.cfg.no_llama:
            llm = 'off'
        elif self.gate.busy:
            llm = 'ok'                                 # working on a job right now
        elif self.llama.state == 'running':
            if now - self._llm_ok[0] > 60:
                self._llm_ok = (now, self.llama.healthy())
            llm = 'ok' if self._llm_ok[1] else 'down'
        else:
            llm = 'down' if self.llama.state in ('failed', 'stopped') else 'starting'
        alerts = 0
        if self.cfg.inbox.is_dir():
            alerts = sum(1 for f in self.cfg.inbox.iterdir() if ALERT_RE.fullmatch(f.name))
        try:
            perf = self.metrics.board_line()
        except Exception:
            perf = None
        return {'pending': pend, 'llm_busy': self.gate.busy, 'llm': llm, 'perf': perf,
                'finance_busy': self.finance.busy, 'tg_sync': bool(self.tg.sync_state['running']),
                'gmail_check': self.gmail.checking(), 'tg_logged_in': self.tg.logged_in(),
                'tg_live': self.tg.live.state if self.tg.live.enabled else 'disabled',
                'gmail_configured': self.gmail.configured(), 'gmail_watch': self.gmail.watch_state(),
                'gmail_error': self.gmail.has_error(), 'gmail_accounts': self.gmail.board(),
                'paperless': self.paperless.configured(),
                'firefly': self.firefly.configured(), 'events_error': bool(self.events_error), 'alerts': alerts,
                'policy': V.POLICY_VERSION}

    # ---------------------------------------------------------------- event feed (lockdown plan E)
    def _events_state(self):
        try:
            d = json.loads((self.cfg.state / 'events-sources.json').read_text())
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def events_once(self):
        """One batch of tgread's queue through the feed (rules, triage, anonymize, store). -> True if more waits.
        The queue position only moves after the batch is stored (an LLM failure retries the same batch)."""
        if not self.tg.logged_in():
            return False
        st = self._events_state()
        after = int(st.get('telegram', 0))
        peek = self.tg.live_peek(after)
        if int(peek.get('last_qid', 0)) < after:      # tgread's queue was reset (wipe): start over
            after = 0
            peek = self.tg.live_peek(0)
        try:
            self.metrics.backlog(int(peek.get('pending') or 0))             # numbers only (app/metrics.py)
        except (TypeError, ValueError):
            pass
        if not peek.get('pending'):
            return False
        batch = self.tg.live_items(after, V.EventFeed.MAX_BATCH)
        if batch.get('owner_name'):
            self.gmail.tg_owner = V.clean_text(batch['owner_name'], 100)    # gmail triage: the owner's name
        self.feed.process('telegram', batch)
        st['telegram'] = int(batch.get('last_qid', after))
        V.write_private(self.cfg.state / 'events-sources.json', json.dumps(st))
        self.events_error = ''
        return bool(batch.get('pending'))

    def events_loop(self):
        self.stop_ev.wait(20)
        while not self.stop_ev.is_set():
            more = False
            try:
                more = self.events_once()
            except VaultError as e:                    # LLM busy/unavailable, tgread failed: retry later
                self.events_error = str(e)[:200]
            except Exception as e:
                self.events_error = type(e).__name__
                log(f'events: {where(e)}')
            if not more:
                self.tg.live.wake.wait(60)
            self.tg.live.wake.clear()
            self.stop_ev.wait(5)

    def after_login(self):
        self.audit.log('tg_login_ok')
        try:
            self.tg.ensure_config()
        except Exception as e:
            log(f'tgread config after login: {where(e)}')
        if not self.cfg.no_sync:
            threading.Thread(target=self.tg.sync_once, kwargs={'initial': True}, name='initial-sync',
                             daemon=True).start()

    def sync_loop(self):
        self.stop_ev.wait(90)
        while not self.stop_ev.is_set():
            try:
                if self.tg.logged_in() and not self.tg.login.running():
                    self.tg.ensure_config()
                    res = self.tg.sync_once(initial=not self.tg.sync_state['initial_done'])
                    if res is not None:
                        if res['exit_code'] in (0, 75):
                            self.sync_failures = 0
                        else:
                            self.sync_failures += 1
                            if self.sync_failures == 3:
                                self.alert('sync', 'Telegram sync keeps failing',
                                           f'3 syncs in a row failed in the vault (last exit code {res["exit_code"]}: '
                                           f'{res.get("error") or "no message"}). Check `vault tg status`.')
            except Exception as e:
                log(f'sync loop: {where(e)}')
            self.stop_ev.wait(max(1, self.cfg.sync_minutes) * 60)

    # ---------------------------------------------------------------- alerts (notes the client copies to ~/inbox)
    def alert(self, kind, title, body, hours=6):
        with self._alert_lock:
            st_path = self.cfg.state / 'alerts.json'
            try:
                st = json.loads(st_path.read_text())
            except (OSError, ValueError):
                st = {}
            if time.time() - float(st.get(kind, 0)) < hours * 3600:
                return
            st[kind] = time.time()
            V.write_private(st_path, json.dumps(st))
            V.write_private(self.cfg.inbox / f'vault-{kind}-{int(time.time())}.md',
                            f'# claude-vault: {title}\n\n{body}\n\nFrom the privacy vault (container claude-vault).\n')

    def list_alerts(self):
        out = []
        if self.cfg.inbox.is_dir():
            for f in sorted(self.cfg.inbox.iterdir()):
                if f.is_file() and ALERT_RE.fullmatch(f.name):
                    try:
                        out.append({'name': f.name, 'text': self.policy.regex_net(f.read_text('utf-8'))[:3000]})
                    except OSError:
                        pass
        return out

    # ---------------------------------------------------------------- live view (one log line per call)
    def secret_values(self):
        """The vault's own secret values (tokens, api_hash, keys), longest first: scrubbed from the live view."""
        vals = self._secret_vals
        if vals is None:
            found = {self.console_key, self.store.hmac_key().hex()}
            for n in self.store.names():               # every Gmail account too
                try:
                    d = self.store.get(n) if self.store.is_set(n) else {}
                except VaultError:
                    d = {}
                found.update(v for k, v in d.items() if k not in ('url', 'chat_id') and isinstance(v, str))
            try:
                found.add(json.loads(self.tg.creds_path.read_text()).get('api_hash'))
            except (OSError, ValueError, AttributeError):
                pass
            vals = self._secret_vals = sorted((v for v in found if isinstance(v, str) and len(v) >= 8),
                                              key=len, reverse=True)
        return vals

    def scrub(self, text):
        for v in self.secret_values():
            if v in text:
                text = text.replace(v, '[secret]')
        return self.raw.scrub_codes(text)

    def record_call(self, ip, via, method, path, q, payload, status, body, nbytes, ms, raw_in=None, job=None):
        """One stderr line per call (Unraid > Docker > claude-vault > Logs) + the event for vault-console watch.
        Parameters only from the allowlist, never on secret routes; response bodies never go to the log."""
        path = '/' + '/'.join(p for p in path.split('/') if p)
        if method == 'POST' and (path.startswith('/secrets/') or path == '/tg/credentials'):
            self._secret_vals = None                   # a secret may have changed
        if via == 'console' and path == '/console/events' and status == 200:
            return                                     # the watch itself
        if path == '/jobs' and method == 'POST' and status == 200 and isinstance(body, dict) and job is None:
            op = (payload or {}).get('op')             # a submit: the route it will run and that route's parameters
            job = {'id': str(body.get('id') or '')[:8], 'phase': 'submit', 'op': op, 'route': J.OPS[op][1],
                   'state': body.get('state'), 'position': body.get('position'), 'eta_s': body.get('eta_s'),
                   'coalesced': bool(body.get('coalesced'))}
            inner = (payload or {}).get('params')
            payload = dict(inner) if isinstance(inner, dict) else {}
        elif path.startswith('/jobs'):                 # polls: state + progress; the answer shows once, at its end
            body = J.tap_view(body)
        ev = self.tap.event(ip, via, method, path, q, payload, status, body, nbytes, ms, scrub=self.scrub, raw_in=raw_in,
                            job=job)
        log(ev['line'])
        self.tap.add(ev)
        self.board.note_call(ev)                       # counts for the pinned status (kind + redactions)

    # ---------------------------------------------------------------- auth + dispatch
    def auth(self, header):
        tok = header[7:].strip() if header and header.startswith('Bearer ') else ''
        if tok and hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), self.cfg.token_sha256):
            self._tl.owner = self.cfg.token_sha256     # jobs are readable only with the token that started them
            return
        self._auth_fail[0] += 1
        if time.time() - self._auth_fail[1] > 60:
            self.audit.log('auth_failed', count=self._auth_fail[0])
            self._auth_fail = [0, time.time()]
        time.sleep(0.5)
        raise VaultError('missing or wrong bearer token', 401, 'unauthorized')

    CONSOLE_ROUTES = frozenset({('POST', '/tg/2fa'), ('GET', '/tg/login'), ('GET', '/secrets'),
                                ('GET', '/tg/credentials'), ('POST', '/tg/credentials'), ('GET', '/console/events'),
                                ('GET', '/raw/pending'), ('POST', '/raw/approve')}
                               | {('POST', f'/secrets/{n}') for n in V.SECRET_SPECS})

    def console_route(self, route):
        """CONSOLE_ROUTES, plus POST /secrets/gmail:<label> (a further Gmail account)."""
        return route in self.CONSOLE_ROUTES or (route[0] == 'POST' and route[1].startswith('/secrets/gmail:')
                                                and V.secret_name(route[1][len('/secrets/'):]) is not None)

    def console_auth(self, key, method, path, client_ip):
        """vault-console: the owner typing at the Unraid terminal (docker exec), so loopback only, a few routes."""
        route = (method, '/' + '/'.join(p for p in path.split('/') if p))
        if (client_ip in ('127.0.0.1', '::1') and self.console_route(route) and isinstance(key, str)
                and hmac.compare_digest(key.strip().encode(), self.console_key.encode())):
            return
        self.audit.log('console_refused', route=' '.join(route)[:120])
        time.sleep(0.5)
        raise VaultError('console access refused', 401, 'unauthorized')

    def via(self):
        return getattr(self._tl, 'via', 'api')

    def dispatch(self, method, path, q, b, via='api'):
        self._tl.via = via
        parts = [p for p in path.split('/') if p]
        key = (method, '/' + '/'.join(parts))
        h = self.ROUTES.get(key)
        if h:
            return h(self, q, b)
        if method == 'POST' and len(parts) == 2 and parts[0] == 'tg' and parts[1] in S.TG_SPECS:
            return self.h_tg_cmd(parts[1], b)
        if method == 'POST' and len(parts) == 2 and parts[0] == 'secrets':
            return self.h_secret_set(parts[1], b)
        if parts[:1] == ['jobs'] and via == 'api':
            if method == 'GET' and len(parts) == 2:
                return self.h_job(parts[1], q)
            if method == 'POST' and len(parts) == 3 and parts[2] == 'cancel':
                return self.jobs.cancel(parts[1], self.job_owner())
        raise VaultError(f'no such endpoint: {method} {path}', 404, 'not_found')

    # ---------------------------------------------------------------- handlers
    def h_status(self, q, b):
        st = self.tg.sync_state
        last = dict(st['last'] or {})
        if last.get('at'):
            last['at'] = V.now_iso(last['at'])
        return {
            'vault': {'version': V.VERSION, 'policy': V.POLICY_VERSION, 'test_mode': self.cfg.test_mode,
                      'started_at': V.now_iso(self.started), 'uptime_seconds': int(time.time() - self.started)},
            'secrets': self.store.names(),
            'llm': {'state': self.llama.state, 'detail': self.llama.detail, 'model': MODEL_FILE,
                    'vision': self.llama.vision_detail,
                    'healthy': (not self.cfg.no_llama) and self.llama.healthy(), 'restarts': self.llama.restarts,
                    'busy_with': self.gate.busy[0] if self.gate.busy else None, 'waiting': self.gate.waiting,
                    'queue': self.gate.queue_view(),
                    'gating': 'per request' if self.gate.per_request else 'per run',
                    'proxy': dict(self.llm_proxy.counts) if self.gate.per_request else None},
            'metrics': self.metrics.status_line(),
            'tg': {'credentials': self.tg.creds_path.is_file(), 'logged_in': self.tg.logged_in(),
                   'login': self.tg.login.state, 'bot_chat_excluded': self.notifier.bot_id() is not None,
                   'sync': {'enabled': not self.cfg.no_sync, 'every_minutes': self.cfg.sync_minutes,
                            'running': st['running'], 'initial_done': st['initial_done'], 'last': last or None},
                   'live': self.tg.live.snapshot()},
            'paperless': {'configured': self.paperless.configured()},
            'firefly': {'configured': self.firefly.configured()},
            'gmail': self.gmail.summary(),             # {configured, watcher, last_poll, error, accounts: [...]}
            'ha': self.ha.status(),                    # HA status feed: on/off, websocket|polling|..., counts
            'people': self.people.status(),            # person cards (plan C2): on/off, counts, last build
            'embed': self.index.server.status(),       # embedding server (plan C3): on/off, model, state, RSS
            'raw': {'pending': sum(r['state'] == 'pending' for r in self.raw.pending()),
                    'approval': self.approval.status()},
            'watch': self.watch.status(),              # the owner's /watch: on, full, until, RAW count (no content)
            'jobs': {'active': self.jobs.active()},    # async jobs (plan v2 #4): a count only
            'events': {'head': self.events.head(), 'error': self.events_error or None,
                       'rules': len(self.rules.list()),
                       'sources': ['telegram'] + (['gmail'] if self.gmail.configured() else [])
                       + (['homeassistant'] if self.ha.enabled else [])},
            'alerts': len(self.list_alerts()),
            'board': self.board.status(),
        }

    def h_metrics(self, q, b):
        try:
            days = float(q.get('days', 1))
        except ValueError:
            raise VaultError('days must be a number', 400, 'bad_param')
        return self.metrics.summary(min(max(days, 1 / 24), 30))

    def h_audit(self, q, b):
        try:
            days = float(q.get('days', 7))
        except ValueError:
            raise VaultError('days must be a number', 400, 'bad_param')
        days = min(max(days, 0.01), 365)
        return {'days': days, 'events': self.audit.read(days=days)}

    def h_alerts(self, q, b):
        return {'alerts': self.list_alerts()}

    def h_alerts_ack(self, q, b):
        n = 0
        for name in b.get('names') or []:
            if isinstance(name, str) and ALERT_RE.fullmatch(name):
                try:
                    (self.cfg.inbox / name).unlink()
                    n += 1
                except FileNotFoundError:
                    pass
        return {'acknowledged': n}

    def h_secrets(self, q, b):
        return {'secrets': self.store.names()}

    def h_secret_set(self, name, b):
        name = self.store.canonical(name)              # 404 for an unknown name; gmail:main = gmail
        b = dict(b)
        rid, code = b.pop('request_id', None), b.pop('code', None)
        clean = self.store.validate(name, b)
        replaced = False
        if self.store.is_set(name):
            if self.via() == 'console':
                pass                                   # the owner himself at the Unraid console
            elif not rid:
                raise VaultError(f'secret {name!r} is already set; replacing it needs the owner\'s code: '
                                 f'raw request with source "secret-rotate", then send request_id + code here', 409,
                                 'already_set')
            else:
                self.raw.release(rid, code, expect_kind='secret', expect_meta={'name': name})
            replaced = True
        self.store.set(name, clean, replace_ok=replaced)
        self.policy.refresh_secrets()
        self.audit.log('secret_set', name=name, replaced=replaced, via=self.via())
        res = {'ok': True, 'name': name, 'replaced': replaced}
        if name == 'paperless':
            try:
                self.paperless.req('GET', '/api/documents/?page_size=1')
                res['check'] = 'paperless reachable, token accepted'
            except VaultError as e:
                res['check'] = f'stored, but the check failed: {e}'
        elif name == 'firefly':
            try:
                res['check'] = f"Firefly reachable (version {self.firefly.status().get('version')})"
            except VaultError as e:
                res['check'] = f'stored, but the check failed: {e}'
        elif name == 'gmail' or name.startswith('gmail:'):
            label = name.partition(':')[2] or 'main'
            res['account'] = label
            self.gmail.credentials_changed(label)      # clears a login block, (re)starts the watcher, polls now
            try:
                res['check'] = self.gmail.check(label)
            except VaultError as e:
                res['check'] = f'stored, but the check failed: {e}'
        return res

    def h_tg_cmd(self, cmd, b):
        if cmd in TEXT_TG:
            return self.h_tg_text(cmd, b)
        return self.tg.run(cmd, b)

    # ---------------------------------------------------------------- privacy plan A: text only on the owner's ✅
    def text_mode(self, route, b):
        """-> (body without text/reason, mode, reason). mode: 'legacy' (no flag while TEXT_DEFAULT), 'text' (text=true:
        released only after the owner's ✅), 'default' (structured, no text)."""
        b = dict(b or {})
        t, reason = b.pop('text', None), b.pop('reason', None)
        if t is None:
            return b, ('legacy' if TEXT_DEFAULT else 'default'), None
        if not isinstance(t, bool):
            raise VaultError('text must be true or false', 400, 'bad_param')
        if not t:
            return b, 'default', None
        r = V.clean_text(reason, 400) if isinstance(reason, str) else ''
        if not 3 <= len(r) <= 300:
            raise VaultError('text needs a reason of 3..300 characters (the owner reads it before he allows it)', 400,
                             'reason_required')
        return b, 'text', r

    def release_text(self, route, summary, reason, payload):
        """A route's text output -> a raw request (source 'text'): the owner sees the reason and taps ✅; the caller
        picks the text up with /raw/release. payload: the text, or (a Telegram text search hung 120 s
        before any request existed) a function that computes it: the request goes out FIRST and the text is made in
        a background thread while the owner decides (release answers 'preparing' until it is ready). Audited as
        text_release {route, reason, bytes} when the text exists."""
        if callable(payload):
            res = self.raw.create('text', summary, reason, None, kind='text', deferred=True)
            rid = res['request_id']
            threading.Thread(target=self._prepare_text, args=(rid, route, reason, payload), daemon=True,
                             name=f'text-{rid}').start()
        else:
            payload = self._text_payload(payload)
            self.audit.log('text_release', route=route, reason=self.policy.regex_net(reason), bytes=len(payload))
            res = self.raw.create('text', summary, reason, payload, kind='text')
        res.update(text_release=True, route=route)
        if self.cfg.test_mode:
            res['test_mode'] = True
        try:
            n = int(self.board.counts().get('text_rel') or 0)
        except Exception:
            n = 0
        if n > TEXT_ALERT_PER_DAY:
            self.alert('text_releases', 'Many text releases today',
                       f'{n} text releases were requested today (more than {TEXT_ALERT_PER_DAY}). Check `vault audit '
                       f'--days 1`.', hours=12)
        return res

    @staticmethod
    def _text_payload(payload):
        payload = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=1)
        if len(payload) > MAX_TEXT_PAYLOAD:
            payload = payload[:MAX_TEXT_PAYLOAD] + '\n[...truncated by the vault]\n'
        return payload

    def _prepare_text(self, rid, route, reason, compute):
        """Background half of a deferred text release: compute, then hand the text to the waiting request (dropped
        if the owner denied it or it expired meanwhile). Errors: the request fails (no text, the reason only)."""
        try:
            res = compute()
            if isinstance(res, dict) and res.get('exit_code'):
                raise VaultError(f"tgread exit {res.get('exit_code')}: "
                                 f"{self.policy.regex_net(V.clean_text(res.get('stderr') or '', 200))}", 502,
                                 'source_failed')
            if isinstance(res, dict) and 'stdout' in res:
                res = res.get('stdout') or ''
            payload = self._text_payload(res)
        except Exception as e:
            why = str(e)[:200] if isinstance(e, VaultError) else type(e).__name__
            self.audit.log('text_release_failed', request_id=rid, route=route, error=self.policy.regex_net(why))
            self.raw.fail(rid, why)
            return
        self.audit.log('text_release', request_id=rid, route=route, reason=self.policy.regex_net(reason),
                       bytes=len(payload))
        self.raw.fill(rid, payload)

    def h_tg_text(self, cmd, b):
        b, mode, reason = self.text_mode(f'/tg/{cmd}', b)
        ask, kind = b.pop('ask', None), b.pop('kind', None)
        report = getattr(V.CALLER, 'report', None)
        if mode == 'default':
            if cmd == 'search':
                return self.answer.tg_hits(b, ask=ask, kind=kind, report=report)
            return self.answer.digest(self.answer.digest_params(cmd, b), report=report)
        if ask is not None or kind is not None:
            raise VaultError('ask/kind work with the default output only (text=false)', 400, 'bad_param')
        if mode == 'legacy':
            if cmd == 'summarize' and getattr(V.CALLER, 'job', None):
                return self.tg.summarize_chunked(b, report=report)   # the async job: chunked (plan v2 #4)
            return self.tg.run(cmd, b)
        # text=true: the ✅ request goes out at once; tgread (search + anonymizer) runs meanwhile
        return self.release_text(f'/tg/{cmd}', f'tg {tg_summary(dict(b, cmd=cmd))}', reason,
                                 (lambda: self.tg.summarize_chunked(b)) if cmd == 'summarize'
                                 else (lambda: self.tg.run(cmd, b)))

    def h_answer(self, q, b):
        # plan C1: a follow-up session is bound to the caller's token hash (jobs carry the token that started them)
        owner = getattr(self._tl, 'owner', None) or f'via:{self.via()}'
        return self.answer.run(b, report=getattr(V.CALLER, 'report', None), owner=owner)

    def h_tg_digest(self, q, b):
        return self.answer.digest(b, report=getattr(V.CALLER, 'report', None))

    def location_text(self):
        """The raw source `location`: his exact place from Home Assistant, only on his ✅."""
        if not self.store.is_set('homeassistant'):
            raise VaultError('location: Home Assistant is not set up in the vault (vault secret set homeassistant)',
                             409, 'not_configured')
        sec = self.store.get('homeassistant')
        req = urllib.request.Request(sec['url'].rstrip('/') + '/api/states/' + sec['person'],
                                     headers={'Authorization': 'Bearer ' + sec['token']})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                st = json.loads(r.read(1 << 20).decode('utf-8'))
        except (OSError, ValueError) as e:
            raise VaultError(f'location: Home Assistant did not answer ({type(e).__name__})', 502, 'source_failed')
        a = st.get('attributes') or {}
        lat, lon = a.get('latitude'), a.get('longitude')
        lines = [f"zone/state: {st.get('state')}", f"since: {st.get('last_changed')}"]
        if lat is not None and lon is not None:
            lines += [f'coordinates: {lat}, {lon} (accuracy {a.get("gps_accuracy")} m)',
                      f'map: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}']
        return '\n'.join(lines) + '\n'

    def h_ha_inventory(self, q, b):
        """Phase 1 of the HA status feed: the owner's phone entities as METADATA only (app/ha.py:
        kinds and attribute key names, never a state or attribute value, coordinates, SSIDs or device names)."""
        import ha
        if not self.store.is_set('homeassistant'):
            raise VaultError('Home Assistant is not set up in the vault (vault secret set homeassistant)', 409,
                             'not_configured')
        sec = self.store.get('homeassistant')
        req = urllib.request.Request(sec['url'].rstrip('/') + '/api/states',
                                     headers={'Authorization': 'Bearer ' + sec['token']})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                states = json.loads(r.read(16 << 20).decode('utf-8'))
        except (OSError, ValueError) as e:
            raise VaultError(f'Home Assistant did not answer ({type(e).__name__})', 502, 'source_failed')
        out = ha.inventory(states if isinstance(states, list) else [], sec.get('person') or '',
                           net=lambda s: self.policy.regex_net(s, addresses=True))
        self.audit.log('ha_inventory', count=len(out['entities']))
        return out

    def h_ha_now(self, q, b):
        """Phase 2 of the HA status feed: the owner's current COARSE flags (zone name or away + distance band +
        town, drive, activity, Bluetooth categories, Wi-Fi class, sleep, alarm, battery) + their age. Never
        coordinates, addresses, SSIDs or device names (app/ha_live.py)."""
        if not self.ha.enabled:
            raise VaultError('the HA status feed is off (VAULT_HA_FEED=0 in docker-compose.yml)', 409, 'ha_off')
        if not self.store.is_set('homeassistant'):
            raise VaultError('Home Assistant is not set up in the vault (vault secret set homeassistant)', 409,
                             'not_configured')
        out = self.ha.now()
        self.audit.log('ha_now', state=out['connection']['state'])
        return out

    # ---------------------------------------------------------------- person cards (memory plan C2)
    def h_people(self, q, b):
        """GET /people?active=90d&n=20&relation=friend|set|unset: at most 20 compact cards (fields only)."""
        return self.people.list(active=q.get('active') or None, n=_int(q.get('n'), 1, PP.MAX_SHOW, 'n', PP.MAX_SHOW),
                                relation=q.get('relation') or None, asks=q.get('asks') in ('1', 'true', 'yes'))

    def h_people_show(self, q, b):
        return self.people.show(b.get('person'))

    def h_people_relation(self, q, b):
        """{person} -> the vault bot asks him (buttons); {person, relation} -> my relay of his words (D1), confirmed
        to him with Undo. Both only with VAULT_PEOPLE_ASK=1."""
        return self.people.relation(b.get('person'), b.get('relation'))

    def h_people_forget(self, q, b):
        return self.people.forget(b.get('person'), undo=bool(b.get('undo')))

    def h_people_refresh(self, q, b):
        """POST /people/refresh {what: asks|topics|calibrate, sample, dry, force}: memory plan C5 (numbers only);
        meant as async job people.refresh (the calibration and a dry triage run use the local model)."""
        return self.people.refresh(b, report=getattr(V.CALLER, 'report', None))

    def h_people_rebuild(self, q, b):
        self.people.check_on()
        return self.people.build('manual')

    # ---------------------------------------------------------------- semantic index (memory plan C3)
    def h_index_status(self, q, b):
        """GET /index/status: embed server, sqlite-vec, the last bake-off's numbers (no text, no vectors)."""
        return self.index.status(full=q.get('full') == '1')

    def h_index_rebuild(self, q, b):
        """POST /index/rebuild {mode: rebuild|reconcile}: queued for the index thread (memory plan C4)."""
        return self.index.request_rebuild(b)

    def h_index_eval(self, q, b):
        """POST /index/eval {sample, queries, models, seed}: the in-vault bake-off; meant as async job index.eval."""
        return self.index.eval(b, report=getattr(V.CALLER, 'report', None))

    def h_tg_credentials(self, q, b):
        return self.tg.set_credentials(b.get('api_id'), b.get('api_hash'), via=self.via())

    def h_tg_credentials_state(self, q, b):
        return self.tg.credentials_state()

    def h_tg_login_start(self, q, b):
        self.audit.log('tg_login_start')
        self.tg.live.stop()                            # it holds the one Telegram connection; restarts after login
        return self.tg.login.start(_int(b.get('timeout'), 30, 900, 'timeout', 180))

    def h_tg_login(self, q, b):
        return self.tg.login.snapshot()

    def h_tg_login_cancel(self, q, b):
        return {'cancelled': self.tg.login.cancel()}

    def h_tg_2fa(self, q, b):
        self.audit.log('tg_2fa_submitted', via=self.via())
        return self.tg.login.password(b.get('password'))

    def h_pl_search(self, q, b):
        r = self.paperless.search(b.get('q') if b.get('q') is not None else b.get('query'),
                                  _int(b.get('n'), 1, 100, 'n', 5))
        self.audit.log('paperless_search', q=b.get('q') or b.get('query'), count=r['count'])
        return r

    def h_pl_recent(self, q, b):
        n = _int(b.get('n'), 1, 5000, 'n', 5)
        r = self.paperless.recent(n)
        self.audit.log('paperless_recent', n=n)
        return r

    def h_pl_meta(self, q, b):
        self.audit.log('paperless_meta')
        return self.paperless.meta()

    def h_pl_get(self, q, b):
        if b.get('content'):
            raise VaultError('paperless get answers with a card, never content. The content (anonymized) needs the '
                             'owner\'s ✅: POST /raw/request {source: paperless-anon, query: {id}, reason} '
                             '(vault paperless get ID --content --reason R)', 400, 'content_needs_approval')
        _int(b.get('chars'), 1, 100_000, 'chars', 1500)       # older clients still send chars: checked, unused
        return self.paperless.card(_doc_id(b.get('id')))

    @staticmethod
    def _field_list(b):
        f = b.get('fields')
        if f is not None and not (isinstance(f, list) and all(isinstance(x, str) for x in f)):
            raise VaultError('fields must be a list of field names', 400, 'bad_field')
        return f

    def h_pl_fields(self, q, b):
        return self.paperless.fields(_doc_id(b.get('id')), self._field_list(b))

    def h_pl_suggest(self, q, b):
        return self.paperless.suggest(_doc_id(b.get('id')), _int(b.get('chars'), 200, 20_000, 'chars', S.SUGGEST_CHARS))

    def h_pl_rule_test(self, q, b):
        return self.paperless.rule_test(b)

    def h_intake_status(self, q, b):
        return self.intake.status()

    def h_pl_upload(self, q, b):
        return self.paperless.upload(b)

    def h_pl_task(self, q, b):
        self.audit.log('paperless_task')
        return self.paperless.task(b.get('task_id'), _int(b.get('timeout'), 1, 900, 'timeout', 180))

    def h_pl_update(self, q, b):
        return self.paperless.update(_doc_id(b.get('id')), b)

    def h_pl_taxonomy(self, q, b):
        return self.paperless.rule_set(b)

    def h_ff_status(self, q, b):
        return self.firefly.status()

    def h_ff_summary(self, q, b):
        return self.firefly.summary(b.get('start'), b.get('end'))

    def h_ff_merchants(self, q, b):
        return self.firefly.merchants(b.get('start'), b.get('end'), _int(b.get('limit'), 1, 200, 'limit', 30))

    def h_gmail_status(self, q, b):
        return self.gmail.status()

    def mail_labels(self, refs, items=None, compute=False):
        """Fast path (a default `gmail search` took 200 s on one triage call per page): {ref: {label, actionable,
        wants, urgency, via}} from the live feed's triage or the label cache, no LLM. compute: ONE triage call (class
        live) for the rest (their feed items: `items` {ref: item} or fetched), stored in the label cache. Enums only."""
        known = self.events.labels('gmail', refs)
        missing = [r for r in dict.fromkeys(refs) if r not in known]
        if compute and missing:
            items = dict(items or {})
            need = [r for r in missing if r not in items]
            if need:
                items.update(self.gmail.triage_items(need))
            todo = [r for r in missing if r in items]
            if todo:
                extra = []
                labs = self.feed.triage([items[r] for r in todo], self.gmail.fallback_owner() or '', 'gmail',
                                        extra=extra, cls='live')
                new = {r: {'label': lab, 'actionable': act, **x}
                       for r, (lab, act), x in zip(todo, labs, extra) if lab in V.GMAIL_LABELS}
                self.events.put_labels('gmail', new)
                known.update({r: dict(d, via='triage') for r, d in new.items()})
        return known

    def h_gmail_search(self, q, b):
        b, mode, reason = self.text_mode('/gmail/search', b)
        triage = b.pop('triage', False)
        if not isinstance(triage, bool):
            raise VaultError('triage must be true or false', 400, 'bad_param')
        qs = b.get('q') if b.get('q') is not None else b.get('query')
        if not isinstance(qs, str) or not 0 < len(qs.strip()) <= 300 or V._CTRL.search(qs):
            raise VaultError('q must be a search text of 1-300 characters (Gmail search syntax works)', 400,
                             'bad_param')
        args = (qs, _int(b.get('n'), 1, G.MAX_SEARCH, 'n', 10), b.get('folder') or 'INBOX', b.get('account'))
        if mode == 'text':                             # the ✅ request first, the search + anonymizer after it
            return self.release_text('/gmail/search', f"gmail search: {V.clean_text(str(qs), 60)}", reason,
                                     lambda: self.gmail.search(*args, text=True))

        def classify(refs, items):                     # feed/cache labels; --triage: ONE call for the rest
            got = self.mail_labels(refs, dict(zip(refs, items)), compute=triage)
            return [(got.get(r) or {}).get('label') for r in refs]
        return self.gmail.search(*args, text=mode != 'default', classify=classify)

    def h_gmail_get(self, q, b):
        b, mode, reason = self.text_mode('/gmail/get', b)
        deep = b.pop('deep', False)
        if not isinstance(deep, bool):
            raise VaultError('deep must be true or false', 400, 'bad_param')
        if mode == 'default':
            card = None if deep else self.quick_card(b)
            if card is not None:
                return card
            return self.answer.mail_card(dict(b, ref=b.get('uid') or b.get('ref')),
                                         report=getattr(V.CALLER, 'report', None))
        ref = b.get('uid') or b.get('ref')
        args = (ref, b.get('folder'), _int(b.get('chars'), 1, 100_000, 'chars', 4000), b.get('account'))
        if mode == 'text':                             # the ✅ request first, the anonymizer after it
            label = self.gmail.norm_ref(ref, b.get('folder'), b.get('account'))
            return self.release_text('/gmail/get', f'mail {label}', reason, lambda: self.gmail.get(*args))
        return self.gmail.get(*args)

    def quick_card(self, b):
        """Fast path (the default card took 200 s: anonymize the whole mail + one answer call): the card from the
        live feed's triage, the label cache or ONE triage call (class live) -> category, actionable, action, wants,
        urgency, reply_needed. No dates: deep=true (vault gmail get --deep) reads the mail for deadline/appointment.
        None if the mail can't be found that way (the caller falls back to the deep card)."""
        ref = self.gmail.norm_ref(b.get('uid') or b.get('ref'), b.get('folder'), b.get('account'))
        lab = self.events.labels('gmail', [ref]).get(ref)
        item = None
        if lab is None:
            items = self.gmail.triage_items([ref])
            item = items.get(ref)
            if item is None:
                return None
            lab = self.mail_labels([ref], items, compute=True).get(ref)
            if lab is None:
                return None
        if item is not None:
            who, ts, att = self.feed.show('gmail', item)[1], item.get('ts'), item.get('att')
        elif lab.get('via') == 'feed':
            who, ts = lab.get('who'), lab.get('ts')
            try:
                att = json.loads(lab.get('att') or 'null')
            except ValueError:
                att = None
        else:                                          # cached label: date/sender/attachments from the mail
            item = self.gmail.triage_items([ref]).get(ref) or {}
            who, ts, att = (self.feed.show('gmail', item)[1] if item else None), item.get('ts'), item.get('att')
        cat = lab['label']
        wants = lab.get('wants') if lab.get('wants') in V.WANTS else None
        act = bool(lab.get('actionable')) and cat not in ('newsletter', 'other')
        card = {'kind': 'mail_card', 'ref': ref, 'account': ref.partition(':')[0] if ':' in ref else None,
                'date': V.now_iso(ts) if ts else None, 'from': self.gmail.mail_net(who) if who else None,
                'category': cat, 'actionable': act,
                'action': WANT_ACTION.get(wants, 'none') if act else 'none', 'wants': wants if act else None,
                'urgency': lab.get('urgency') if lab.get('urgency') in V.URGENCY else 'none',
                'reply_needed': cat == 'reply_needed' or (act and wants == 'reply'),
                'attachments': att if isinstance(att, dict) else {'n': 0, 'pdf': 0, 'image': 0},
                'via': lab.get('via'), 'cached': lab.get('via') != 'triage',
                'note': 'a quick card from the triage (no subject, no text, no dates); --deep reads the mail for '
                        'deadline/appointment; text needs --text + the owner\'s OK'}
        if cat == 'bill':
            card['hint'] = f"file the bill: vault gmail to-paperless {ref} N"
        self.audit.log('answer', source='gmail', kind='mail_card', quick=lab.get('via'))
        return card

    def h_gmail_config(self, q, b):
        return self.gmail.config(q.get('account'))

    def h_gmail_config_set(self, q, b):
        return self.gmail.set_config(b)

    def h_gmail_to_paperless(self, q, b):
        return self.gmail.to_paperless(b, self.paperless)

    def h_mailimport_status(self, q, b):
        return self.mailimport.status(q.get('plan'))

    def h_mailimport_scan(self, q, b):
        return self.mailimport.start_scan(b)

    def h_mailimport_run(self, q, b):
        return self.mailimport.start_run(b)

    def h_mailimport_cancel(self, q, b):
        return self.mailimport.cancel(b)

    def h_mailimport_drop(self, q, b):
        return self.mailimport.drop(b)

    def _fin(self):
        """The bank-export intake, or 404 when this vault has none (NullFinance)."""
        if isinstance(self.finance, NullFinance):
            raise VaultError('no bank-export intake in this vault (app/finance.py is not installed)', 404, 'not_found')
        return self.finance

    def h_finance_rules(self, q, b):
        """The sync rules: set?, valid?, sha256, entries per key. Never the values."""
        return self._fin().rules_status()

    def h_finance_rules_set(self, q, b):
        """Write-only like a secret: set once; replacing needs his code (raw request "finance-rules")."""
        b = dict(b)
        rid, code, rules = b.pop('request_id', None), b.pop('code', None), b.get('rules')
        self._fin().parse_rules(rules)               # a bad file never uses up his code
        replace = False
        if self._fin().rules_file.is_file():
            if not rid:
                raise VaultError('the Firefly rules are already set; replacing them needs the owner\'s code: raw request '
                                 'with source "finance-rules" (vault firefly rules-replace --reason ...), then send '
                                 'request_id + code here', 409, 'already_set')
            self.raw.release(rid, code, expect_kind='secret', expect_meta={'name': 'finance-rules'})
            replace = True
        return self._fin().set_rules(rules, replace_ok=replace)

    def h_finance_check(self, q, b):
        return self._fin().check()

    def h_finance_status(self, q, b):
        """Read-only for Claude: counts, times, masked account names. Uploads and imports only come from the owner's
        own messages and taps in the vault bot chat; there is no endpoint for them."""
        return self._fin().status()

    def h_llm_run(self, q, b):
        args = llm_argv(b.get('args') or [])
        text = b.get('text') or ''
        if not isinstance(text, str) or len(text) > 4_000_000:
            raise VaultError('text must be a string of at most 4,000,000 characters', 400, 'bad_param')
        self.audit.log('llm_run', flags=[a.split('=', 1)[0] for a in args], chars=len(text))
        cls = 'bulk' if len(text) > 8000 or '--summary' in args else 'live'
        with self.gate.lease(private=False, what='llm-run (caller text)', timeout=3600, cls=cls):
            try:
                rc, out, err = V.run_proc([self.cfg.llm_local] + args, stdin=text, timeout=7300,
                                          env=self.cfg.tool_env(), alive=V.caller_alive_fn())
            except subprocess.TimeoutExpired:
                return {'exit_code': 5, 'stdout': '', 'stderr': 'llm-local: timed out in the vault'}
        return {'exit_code': rc, 'stdout': out, 'stderr': (err or '')[-4000:]}

    # ---------------------------------------------------------------- async jobs (plan v2 #4, app/jobs.py)
    def job_owner(self):
        owner = getattr(self._tl, 'owner', None)
        if not owner:
            raise VaultError('jobs need the API token', 401, 'unauthorized')
        return owner

    def h_job_submit(self, q, b):
        if self.via() != 'api':
            raise VaultError('jobs are for the API token only', 403, 'forbidden')
        return self.jobs.submit(b.get('op'), b.get('params'), self.job_owner(), ip=getattr(self._tl, 'ip', ''))

    def h_jobs(self, q, b):
        if self.via() != 'api':
            raise VaultError('jobs are for the API token only', 403, 'forbidden')
        return {'jobs': self.jobs.list(self.job_owner())}

    def h_job(self, jid, q):
        try:
            wait = float(q.get('wait') or 0)
        except ValueError:
            raise VaultError('wait must be a number of seconds (at most 30)', 400, 'bad_param')
        return self.jobs.get(jid, self.job_owner(), wait=max(0.0, min(wait, J.Jobs.MAX_WAIT)))

    def run_job(self, job):
        """A job's work, in its own thread: the route's handler with the job as the caller (cancel = a caller that
        left), its RAW captured for the owner's full watch as on a direct call; then the live view gets the call it
        ran with its answer (once) and the metrics count it under its route. -> (status, body)."""
        method, route = J.OPS[job.op]
        t0 = time.time()
        self._tl.via, self._tl.owner, self._tl.ip = 'api', job.owner, job.ip
        V.CALLER.alive, V.CALLER.job, V.CALLER.report = job.alive, job.id, job.report
        V.CAPTURE.buf, V.CAPTURE.total = ([], 0) if self.tap.raw_ok() else (None, 0)
        try:
            body = self.dispatch(method, route, {}, dict(job.params), via='api')   # tg summarize: h_tg_text
            status = 200
        except VaultError as e:
            status, body = e.status, {'error': str(e), 'code': e.code, **e.extra}
        except Exception as e:
            log(f'internal error in job {job.op}: {where(e)}')
            status, body = 500, {'error': 'internal error in the vault (type and line in its log)', 'code': 'internal'}
        finally:
            V.CALLER.alive, V.CALLER.job, V.CALLER.report = None, None, None
            buf, V.CAPTURE.buf = getattr(V.CAPTURE, 'buf', None), None
            raw_in = {'parts': buf, 'total': getattr(V.CAPTURE, 'total', 0)} if buf is not None else None
        secs = time.time() - t0
        try:
            data = json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.record_call(job.ip or 'job', 'api', method, route, {}, job.params, status, body, len(data),
                             int(secs * 1000), raw_in=raw_in,
                             job={'id': job.id[:8], 'phase': 'done', 'op': job.op, 'route': route,
                                  'state': 'done' if status == 200 else 'failed'})
        except Exception as e:
            log(f'live view: {where(e)} on job {job.op}')
        try:
            code = body.get('code') if isinstance(body, dict) else None
            self.metrics.call(MX.route_key(method, route, status), status, secs, code=code)
        except Exception as e:
            log(f'metrics: {where(e)} on job {job.op}')
        return status, body

    def h_media_list(self, q, b):
        return self.media.list(b)

    def h_media_request(self, q, b):
        res = self.media.request(b)
        if self.cfg.test_mode:
            res['test_mode'] = True
        return res

    def h_media_release(self, q, b):
        return self.media.release(b)

    def h_media_ack(self, q, b):
        return self.media.ack(b)

    def h_media_extract(self, q, b):
        return self.media.extract(b)

    # ---------------------------------------------------------------- facts, find, plans (plan v2 #6, #10, #11)
    def h_tg_facts(self, q, b):
        return self.facts.tg_facts(b, report=getattr(V.CALLER, 'report', None))

    def h_gmail_facts(self, q, b):
        return self.facts.gmail_facts(b, report=getattr(V.CALLER, 'report', None))

    def h_find(self, q, b):
        b, mode, reason = self.text_mode('/find', b)
        if mode == 'text':                             # the ✅ request first, the search after it
            return self.release_text('/find', f"find: {V.clean_text(str(b.get('q') or b.get('query')), 60)}", reason,
                                     lambda: self.find.run(b, text=True))
        return self.find.run(b, report=getattr(V.CALLER, 'report', None), text=mode != 'default')

    def h_plans(self, q, b):
        return self.facts.plans(self.events, _int(q.get('days'), 1, 60, 'days', 14))

    def h_raw_request(self, q, b):
        source, query, reason = b.get('source'), b.get('query'), b.get('reason')
        if source not in V.RAW_SOURCES:
            raise VaultError(f'source must be one of {", ".join(V.RAW_SOURCES)}', 400, 'bad_source')
        if not isinstance(reason, str) or len(V.clean_text(reason)) < 3:
            raise VaultError('a reason is required (it is shown to the owner)', 400, 'reason_required')
        kind, meta = 'text', {}
        if source == 'test':
            summary, payload = 'no data', 'raw-release test OK'
        elif source == 'tg':
            qq = _obj(query)
            summary, payload = tg_summary(qq), self.tg.raw(qq)
        elif source == 'tg-file':
            qq = _obj(query)
            kind = 'file'
            payload = self.tg.raw_file(qq.get('chat'), qq.get('msg'))
            summary = f"file from message {qq.get('msg')} in chat {qq.get('chat')}"        # no file names in the audit
        elif source == 'paperless':
            qq = _obj(query)
            i = _doc_id(qq.get('id'))
            payload = self.paperless.raw_text(i, _int(qq.get('chars'), 1, 500_000, 'chars', 20000))
            summary = payload.split('\n', 1)[0].lstrip('# ')
        elif source == 'paperless-anon':
            qq = _obj(query)
            i = _doc_id(qq.get('id'))
            payload = self.paperless.anon_text(i, _int(qq.get('chars'), 1, 100_000, 'chars', 20000))
            summary = payload.split('\n', 1)[0].lstrip('# ')
        elif source == 'paperless-fields':
            qq = _obj(query)
            i = _doc_id(qq.get('id'))
            res = self.paperless.fields(i, self._field_list(qq), tier2=True)
            payload = json.dumps(res, indent=1, ensure_ascii=False)
            summary = f"paperless #{i}, fields {', '.join(k for k in res if not k.startswith('_'))}"
        elif source == 'paperless-file':
            qq = _obj(query)
            i = _doc_id(qq.get('id'))
            kind = 'file'
            payload = self.paperless.download(i, archived=bool(qq.get('archived')))
            summary = f'paperless #{i}, original file'
        elif source == 'firefly':
            qq = _obj(query)
            summary = f"merchant names {qq.get('start')}..{qq.get('end')}"
            payload = self.firefly.raw_merchants(qq.get('start'), qq.get('end'))
        elif source == 'gmail':
            kind, summary, payload = self.gmail.raw(_obj(query))
        elif source == 'location':
            summary, payload = 'exact place and coordinates (Home Assistant)', self.location_text()
        elif source == 'finance-rules':                # replace the Firefly sync rules
            if not self._fin().rules_file.is_file():
                raise VaultError('the Firefly rules are not set yet; just set them (no code needed)', 409, 'not_set')
            kind, meta, summary, payload = 'secret', {'name': 'finance-rules'}, 'Firefly sync rules (full replace)', None
        else:                                          # secret-rotate
            qq = _obj(query)
            name = V.secret_name(qq.get('name'))
            if name is None:
                raise VaultError(f'name must be one of {", ".join(V.SECRET_SPECS)} or gmail:LABEL', 400, 'bad_param')
            if not self.store.is_set(name):
                raise VaultError(f'secret {name!r} is not set yet; just set it (no code needed)', 409, 'not_set')
            kind, meta, summary, payload = 'secret', {'name': name}, name, None
        if kind == 'text' and len(payload) > MAX_TEXT_PAYLOAD:
            payload = payload[:MAX_TEXT_PAYLOAD] + '\n[...truncated by the vault]\n'
        if kind == 'file' and len(payload[1]) > MAX_FILE_PAYLOAD:
            raise VaultError(f'file too large for a raw release ({len(payload[1])} bytes)', 413, 'too_large')
        res = self.raw.create(source, summary, reason, payload, kind=kind, meta=meta)
        if self.cfg.test_mode:
            res['test_mode'] = True                    # the code went to this test vault's log, not Telegram
        return res

    def h_raw_release(self, q, b):
        try:
            payload = self.raw.release(b.get('request_id'), b.get('code'), expect_kind=('text', 'file'),
                                       wait=b.get('wait', 0))
        except V.RawPending as p:
            return dict(p.extra)                       # {status: pending, approval, expires_at}: poll again
        if isinstance(payload, tuple):
            fn, data = payload
            return {'status': 'released', 'kind': 'file', 'filename': fn, 'bytes': len(data),
                    'content_b64': base64.b64encode(data).decode()}
        return {'status': 'released', 'kind': 'text', 'text': payload}

    def h_raw_approve(self, q, b):
        """vault-console approve|deny RID: the owner at the Unraid terminal (console key, loopback only). Not an API
        route: with the API token this answers 404, so the assistant can never approve its own request."""
        if self.via() != 'console':
            raise VaultError('no such endpoint: POST /raw/approve', 404, 'not_found')
        decision = b.get('decision')
        if decision not in ('approve', 'deny'):
            raise VaultError('decision must be approve or deny', 400, 'bad_param')
        outcome, info = self.raw.decide(b.get('request_id'), decision == 'approve', via='console')
        if info and outcome in ('approved', 'denied'):
            self.approval.finish(info, outcome)        # the Telegram message shows it too (buttons removed)
        return {'outcome': outcome}

    RETRIAGE_MAX = 20

    def h_events_retriage(self, q, b):
        """Re-triage stored Gmail events (cursor > since, at most `max`, default and cap RETRIAGE_MAX)
        with today's triage (label, actionable, wants, urgency), in ONE call (class live), so an older mail shows in
        the flag-only note format. Same cursors: the cron feed never sees them twice. -> counts and cursors only."""
        try:
            since, n = int(b.get('since')), int(b.get('max') or self.RETRIAGE_MAX)
        except (TypeError, ValueError):
            raise VaultError('since must be a cursor (integer); max an integer', 400, 'bad_param')
        if since < 0 or not 1 <= n <= self.RETRIAGE_MAX:
            raise VaultError(f'since must be >= 0 and max 1..{self.RETRIAGE_MAX}', 400, 'bad_param')
        rows, _, more, _ = self.events.since(since, 500, 'gmail')
        allrows = [r for r in rows if r['label'] != 'collapsed' and r['ref']]
        rows, more = allrows[:n], more or len(allrows) > n
        if not rows:
            return {'retriaged': 0, 'changed': 0, 'missing': 0, 'cursors': []}
        items = self.gmail.triage_items([r['ref'] for r in rows])
        todo = [r for r in rows if r['ref'] in items]
        changed, done = 0, []
        if todo:
            extra = []
            labs = self.feed.triage([items[r['ref']] for r in todo], self.gmail.fallback_owner() or '', 'gmail',
                                    extra=extra, cls='live')
            for r, (lab, act), x in zip(todo, labs, extra):
                if lab not in V.GMAIL_LABELS:
                    continue
                d = {'label': lab, 'actionable': act, 'wants': x.get('wants'), 'urgency': x.get('urgency')}
                if (r['label'], bool(r['actionable']), r['wants'], r['urgency']) != (
                        lab, bool(act), d['wants'], d['urgency']):
                    changed += 1
                self.events.retriaged(r['cursor'], d)
                done.append(r['cursor'])
        self.audit.log('events_retriage', since=since, count=len(done), changed=changed,
                       missing=len(rows) - len(todo))
        return {'retriaged': len(done), 'changed': changed, 'missing': len(rows) - len(todo), 'cursors': done,
                'more': more}

    def h_events(self, q, b, source=None):
        source = source or q.get('source') or None
        if source is not None and source not in V.FEED_SOURCES:
            raise VaultError(f'source must be one of {", ".join(V.FEED_SOURCES)}', 400, 'bad_param')
        try:
            n = int(q.get('max', 100))
            since = q.get('since', '0')
            cur = None if since == 'latest' else int(since)
        except ValueError:
            raise VaultError('since must be a cursor (integer) or "latest"; max an integer', 400, 'bad_param')
        if not 1 <= n <= 500 or (cur is not None and cur < 0):
            raise VaultError('max must be 1..500 and since >= 0', 400, 'bad_param')
        live = {'telegram': self.tg.live.snapshot()['state'], 'gmail': self.gmail.watch_state(),
                'homeassistant': self.ha.state}
        if cur is None:
            return {'events': [], 'next_cursor': self.events.head(), 'more': False, 'dropped_counts': {},
                    'live': live}
        rows, nxt, more, reset = self.events.since(cur, n, source)
        net = self.policy.regex_net
        out, dropped = [], {}
        for e in rows:
            d = {'cursor': e['cursor'], 'source': e['source'], 'ts': V.now_iso(e['ts']) if e['ts'] else None,
                 'chat_key': e['chat_key'], 'chat': net(e['chat'] or ''), 'chat_type': e['chat_type'],
                 'label': e['label']}
            if e['label'] == 'collapsed':
                d.update(count=e['count'], why=e['why'], actionable=False)
                k = f"{e['source']}:{d['chat']}"
                dropped[k] = dropped.get(k, 0) + e['count']
            else:
                who = e.get('who') or (e['sender'] or '').split(' ')[0]
                d.update(sender=net(who), who=net(who), sender_key=e['sender_key'],
                         actionable=bool(e['actionable']), priority=bool(e['priority']), ref=e['ref'],
                         wants=e.get('wants'), urgency=e.get('urgency'))
                if e.get('att'):                       # privacy plan A: never text, only counts
                    try:
                        d['att'] = json.loads(e['att'])
                    except ValueError:
                        pass
                if e.get('facts'):                     # plan v2 #11: checked facts (anonymized, grounded)
                    try:
                        d['facts'] = _net_obj(json.loads(e['facts']), net)
                    except ValueError:
                        pass
            if e.get('doc'):                           # intake: {doc_id, type, correspondent, bill_likely}
                try:
                    d['doc'] = _net_obj(json.loads(e['doc']), net)
                except ValueError:
                    pass
            if e.get('account'):
                d['account'] = e['account']            # the Gmail account's label (never its address)
            if e.get('ha'):                            # HA status feed: coarse flags (zone/band/town, drive, ...)
                try:
                    d['ha'] = _net_obj(json.loads(e['ha']), net)
                except ValueError:
                    pass
            out.append(d)
        res = {'events': out, 'next_cursor': nxt, 'more': more, 'dropped_counts': dropped, 'live': live}
        if reset:
            res['reset'] = True
        return res

    def h_tg_events(self, q, b):
        return self.h_events(q, b, source='telegram')

    def h_event_rules(self, q, b):
        return {'rules': self.rules.list()}

    def h_event_rules_set(self, q, b):
        rules = self.rules.set(b.get('source'), b.get('mode'), chat=b.get('chat'), sender=b.get('sender'))
        self.audit.log('event_rule', source=b.get('source'), mode=b.get('mode'), chat=b.get('chat'),
                       sender=b.get('sender'))
        return {'rules': rules}

    def h_raw_pending(self, q, b):
        return {'requests': self.raw.pending()}

    def h_deploy_request(self, q, b):
        """Ask the owner (vault bot card, ✅ Deploy / ❌ Cancel) to deploy a commit; the host runner reviews it first."""
        return self.deploys.request(b.get('commit'))

    def h_deploy_status(self, q, b):
        return self.deploys.status(q.get('id'))

    def h_console_events(self, q, b):
        """vault-console watch only (never the API token): ?after=SEQ&wait=S (long poll) | ?last=N, &full=1."""
        if self.via() != 'console':
            raise VaultError('no such endpoint: GET /console/events', 404, 'not_found')
        full = q.get('full') == '1'
        try:
            after = int(q['after']) if 'after' in q else None
            wait, last = float(q.get('wait', 0)), int(q.get('last', 10))
        except ValueError:
            raise VaultError('after, wait and last must be numbers', 400, 'bad_param')
        if after is None:
            self.audit.log('console_watch', full=full)
        if full:
            self.tap.console_full()                    # attached: RAW is captured while it polls (LiveTap.raw_ok)
        return self.tap.since(after=after, last=last, wait=wait, full=full)

    def h_index(self, q, b):
        return {'vault': 'claude-vault', 'version': V.VERSION,
                'endpoints': sorted(' '.join(k) for k in self.ROUTES if k[1] not in ('/console/events', '/raw/approve'))
                + ['POST /tg/<command>', 'POST /secrets/<name>', 'GET /jobs/<id>', 'POST /jobs/<id>/cancel']}

    ROUTES = {
        ('GET', '/'): h_index,
        ('GET', '/status'): h_status,
        ('GET', '/audit'): h_audit,
        ('GET', '/metrics'): h_metrics,
        ('GET', '/alerts'): h_alerts,
        ('POST', '/alerts/ack'): h_alerts_ack,
        ('GET', '/secrets'): h_secrets,
        ('POST', '/tg/credentials'): h_tg_credentials,
        ('GET', '/tg/credentials'): h_tg_credentials_state,
        ('POST', '/tg/login-qr'): h_tg_login_start,
        ('GET', '/tg/login'): h_tg_login,
        ('POST', '/tg/login-cancel'): h_tg_login_cancel,
        ('POST', '/tg/2fa'): h_tg_2fa,
        ('POST', '/paperless/search'): h_pl_search,
        ('POST', '/paperless/recent'): h_pl_recent,
        ('GET', '/paperless/meta'): h_pl_meta,
        ('POST', '/paperless/get'): h_pl_get,
        ('POST', '/paperless/fields'): h_pl_fields,
        ('POST', '/paperless/suggest'): h_pl_suggest,
        ('POST', '/paperless/rule-test'): h_pl_rule_test,
        ('GET', '/intake/status'): h_intake_status,
        ('GET', '/ha/inventory'): h_ha_inventory,
        ('GET', '/ha/now'): h_ha_now,
        ('GET', '/people'): h_people,
        ('POST', '/people/show'): h_people_show,
        ('POST', '/people/relation'): h_people_relation,
        ('POST', '/people/forget'): h_people_forget,
        ('POST', '/people/rebuild'): h_people_rebuild,
        ('POST', '/people/refresh'): h_people_refresh,
        ('GET', '/index/status'): h_index_status,
        ('POST', '/index/eval'): h_index_eval,
        ('POST', '/index/rebuild'): h_index_rebuild,
        ('POST', '/paperless/upload'): h_pl_upload,
        ('POST', '/paperless/task'): h_pl_task,
        ('POST', '/paperless/update'): h_pl_update,
        ('POST', '/paperless/taxonomy'): h_pl_taxonomy,
        ('GET', '/firefly/status'): h_ff_status,
        ('POST', '/firefly/summary'): h_ff_summary,
        ('POST', '/firefly/merchants'): h_ff_merchants,
        ('GET', '/finance/status'): h_finance_status,
        ('GET', '/finance/rules'): h_finance_rules,
        ('POST', '/finance/rules'): h_finance_rules_set,
        ('POST', '/finance/check'): h_finance_check,
        ('GET', '/gmail/status'): h_gmail_status,
        ('POST', '/gmail/search'): h_gmail_search,
        ('POST', '/gmail/get'): h_gmail_get,
        ('GET', '/gmail/config'): h_gmail_config,
        ('POST', '/gmail/config'): h_gmail_config_set,
        ('POST', '/gmail/to-paperless'): h_gmail_to_paperless,
        ('GET', '/gmail/import'): h_mailimport_status,
        ('POST', '/gmail/import/scan'): h_mailimport_scan,
        ('POST', '/gmail/import/run'): h_mailimport_run,
        ('POST', '/gmail/import/cancel'): h_mailimport_cancel,
        ('POST', '/gmail/import/drop'): h_mailimport_drop,
        ('POST', '/llm/run'): h_llm_run,
        ('POST', '/raw/request'): h_raw_request,
        ('POST', '/raw/release'): h_raw_release,
        ('GET', '/raw/pending'): h_raw_pending,
        ('POST', '/deploy/request'): h_deploy_request,
        ('GET', '/deploy/status'): h_deploy_status,
        ('POST', '/media/list'): h_media_list,
        ('POST', '/media/request'): h_media_request,
        ('POST', '/media/release'): h_media_release,
        ('POST', '/media/ack'): h_media_ack,
        ('POST', '/media/extract'): h_media_extract,
        ('POST', '/tg/facts'): h_tg_facts,
        ('POST', '/gmail/facts'): h_gmail_facts,
        ('POST', '/find'): h_find,
        ('POST', '/answer'): h_answer,
        ('POST', '/tg/digest'): h_tg_digest,
        ('GET', '/plans'): h_plans,
        ('POST', '/raw/approve'): h_raw_approve,
        ('GET', '/events'): h_events,
        ('GET', '/tg/events'): h_tg_events,
        ('GET', '/events/rules'): h_event_rules,
        ('POST', '/events/rules'): h_event_rules_set,
        ('POST', '/events/retriage'): h_events_retriage,
        ('GET', '/console/events'): h_console_events,
        ('POST', '/jobs'): h_job_submit,
        ('GET', '/jobs'): h_jobs,
    }


# ============================================================================================ HTTP

APP = None
MAX_BODY = {'/paperless/upload': 80 << 20, '/llm/run': 20 << 20, '/jobs': 20 << 20}


class Handler(BaseHTTPRequestHandler):
    server_version = 'claude-vault'
    sys_version = ''
    timeout = 300                                      # socket reads (request + body)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.api('GET')

    def do_POST(self):
        self.api('POST')

    def do_PUT(self):
        self.api('PUT')

    def do_DELETE(self):
        self.api('DELETE')

    def read_json(self, path):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            raise VaultError('bad Content-Length', 400, 'bad_request')
        limit = MAX_BODY.get(path.rstrip('/'), 1 << 20)
        if n < 0 or n > limit:
            raise VaultError(f'request body too large (max {limit} bytes)', 413, 'too_large')
        raw = self.rfile.read(n) if n else b''
        if not raw.strip():
            return {}
        try:
            d = json.loads(raw)
        except ValueError:
            raise VaultError('the body must be JSON', 400, 'bad_json')
        if not isinstance(d, dict):
            raise VaultError('the body must be a JSON object', 400, 'bad_json')
        return d

    def caller_alive(self):
        """False once the client closed its connection (EOF/reset on the request socket; it sends nothing more)."""
        try:
            r, _, _ = select.select([self.connection], [], [], 0)
            if not r:
                return True
            return bool(self.connection.recv(1, socket.MSG_PEEK))
        except (OSError, ValueError):
            return False

    def api(self, method):
        t0 = time.time()
        u = urllib.parse.urlsplit(self.path)
        path = u.path or '/'
        q, payload, via = {}, {}, 'api'
        try:
            if method == 'GET' and path == '/health':
                status, body = 200, {'ok': True}
            else:
                console = self.headers.get('X-Vault-Console')
                via = 'console' if console is not None else 'api'
                if console is not None:
                    APP.console_auth(console, method, path, self.client_address[0])
                else:
                    APP.auth(self.headers.get('Authorization'))
                if method not in ('GET', 'POST'):
                    raise VaultError('method not allowed', 405, 'method_not_allowed')
                payload = self.read_json(path) if method == 'POST' else {}
                q = dict(urllib.parse.parse_qsl(u.query))
                V.CALLER.alive = self.caller_alive         # the LLM queue drops / stops work of a caller that left
                APP._tl.ip = self.client_address[0]
                if via == 'api' and APP.tap.raw_ok():      # the owner's full watch: RAW in memory (V.capture_raw)
                    V.CAPTURE.buf, V.CAPTURE.total = [], 0
                status, body = 200, APP.dispatch(method, path, q, payload, via=via)
        except VaultError as e:
            status, body = e.status, {'error': str(e), 'code': e.code, **e.extra}
        except Exception as e:
            log(f'internal error on {method} {path}: {where(e)}')
            status, body = 500, {'error': 'internal error in the vault (type and line in its log)', 'code': 'internal'}
        finally:
            V.CALLER.alive = None
            buf, V.CAPTURE.buf = getattr(V.CAPTURE, 'buf', None), None
            raw_in = {'parts': buf, 'total': getattr(V.CAPTURE, 'total', 0)} if buf is not None else None
        data = json.dumps(body, ensure_ascii=False).encode('utf-8')
        if path != '/health':
            try:
                APP.record_call(self.client_address[0], via, method, path, q, payload, status, body, len(data),
                                int((time.time() - t0) * 1000), raw_in=raw_in)
            except Exception as e:
                log(f'live view: {where(e)} on {method} {path}')
        gone = False
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            gone = True
            log(f'client went away before the answer to {method} {path}')
        if path != '/health':
            code = body.get('code') if isinstance(body, dict) else None
            try:                                       # numbers only: route, status, duration (app/metrics.py)
                APP.metrics.call(MX.route_key(method, path, status), status, time.time() - t0, code=code, gone=gone,
                                 timed_out=code == 'llm_unavailable' and 'timed out' in str(body.get('error')))
            except Exception as e:
                log(f'metrics: {where(e)} on {method} {path}')


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


# vault-console secret NAME: what the owner reads per field, and whether it's typed without echo (every token is).
CONSOLE_FIELDS = {
    ('telegram', 'bot_token'): ('Token of a NEW bot from @BotFather used ONLY by the vault, never Claude\'s chat bot '
                                 '(like 123456789:AA...)', True),
    ('telegram', 'chat_id'): ('Your Telegram chat id (a number; Claude can tell you)', False),
    ('paperless', 'url'): ('paperless address (like http://198.51.100.5:PORT)', False),
    ('paperless', 'token'): ('paperless API token', True),
    ('firefly', 'url'): ('Firefly III address (like http://198.51.100.5:PORT)', False),
    ('firefly', 'token'): ('Firefly III personal access token', True),
    ('homeassistant', 'url'): ('Home Assistant address (like http://198.51.100.7:8123)', False),
    ('homeassistant', 'token'): ('Home Assistant long-lived access token', True),
    ('homeassistant', 'person'): ('Your person entity in Home Assistant (like person.name)', False),
    ('gmail', 'address'): ('Your Gmail address (like name@gmail.com)', False),
    ('gmail', 'app_password'): ('Gmail app password: the 16 letters Google shows once (spaces are fine)', True),
}
# printed once before the fields of `vault-console secret NAME`
CONSOLE_INTRO = {
    'gmail': ('Gmail for the vault (READ-ONLY: it never marks, moves, deletes or sends mail).\n'
              'First create an app password: Google account > Security > 2-Step Verification (must be on) >\n'
              'App passwords (https://myaccount.google.com/apppasswords), name it "claude-vault", copy the 16 letters.'),
}


def console_field(name, key):
    """(prompt, hidden) for one secret field; unknown fields: the raw name, hidden if it looks like a token."""
    label, hidden = CONSOLE_FIELDS.get((name, key), (f'{name} {key}', 'token' in key or 'hash' in key))
    return f"{label}{' (not shown)' if hidden else ''}: ", hidden


def console_secret_gmail(call, label, ask, ask_secret, out):
    """vault-console secret gmail [LABEL]: one Gmail account. LABEL main (the default) = secret gmail, the first
    account as before; any other label adds a further account (secret gmail:LABEL). Asks y/N before replacing."""
    out(CONSOLE_INTRO['gmail'])
    have = ['main' if n == 'gmail' else n.partition(':')[2]
            for n, on in (call('GET', '/secrets').get('secrets') or {}).items()
            if on and n.partition(':')[0] == 'gmail']
    if have:
        out(f"Gmail accounts in the vault: {', '.join(have)}. A new label adds another account.")
    if label is None:
        label = ask('Account label (like main or work; Enter = main): ').strip() or 'main'
    lab = V.gmail_label(label)
    if lab is None:
        out('vault-console: the label must be 1-16 letters, digits, - or _, start with a letter and not be "all"; '
            'nothing stored')
        return 1
    if lab in have and ask(f"Gmail account {lab!r} is already set. Replace it? [y/N] ").strip().lower() not in (
            'y', 'yes'):
        out(f'gmail account {lab}: unchanged')
        return 1
    vals = {}
    for k in V.SECRET_SPECS['gmail']:
        prompt, hidden = console_field('gmail', k)
        vals[k] = (ask_secret(prompt) if hidden else ask(prompt)).strip()
    name = V.gmail_secret(lab)
    r = call('POST', f'/secrets/{name}', vals)
    vals = None
    out(f"secret {name}: {'replaced' if r.get('replaced') else 'stored'}" + (f"; {r['check']}" if r.get('check') else ''))
    return 0


def console_watch(call, full=False, out=print, max_polls=None):
    """vault-console watch [--full]: follow the live view until Ctrl-C (the last 10 calls first)."""
    flag = '&full=1' if full else ''
    polls = 0
    try:
        out('vault-console watch: every API call to the vault, live' + (': REQUEST, RAW (what went in) and RESPONSE '
            '(what Claude got)' if full else '') + ' (Ctrl-C to stop)')
        r = call('GET', f'/console/events?last=10{flag}')
        while True:
            if r.get('skipped'):
                out(f"[{r['skipped']} older calls dropped from the buffer]")
            for ev in r.get('events') or []:
                if full and 'request' in ev:
                    if ev.get('via') == 'console':
                        out(V.display_text(ev['line']))       # the owner's own console calls: one line
                        continue
                    out(V.display_text(V.watch_block(ev, V.RAW_MAX, indent='    ')))
                    out('')
                else:
                    out(V.display_text(ev['line']))
            polls += 1
            if max_polls is not None and polls >= max_polls:
                return 0
            r = call('GET', f"/console/events?after={int(r['seq'])}&wait=20{flag}")
    except KeyboardInterrupt:
        out('vault-console: watch stopped')
        return 0
    except OSError:                                    # URLError, reset: the vault restarted (new console key)
        out('vault-console: lost the connection to the vault (restarted?): run the command again')
        return 1


def console_main(argv, ask=None, ask_secret=None, out=print, cfg=None):
    """vault-console 2fa | secret NAME | tg-credentials: for the OWNER at the Unraid terminal (docker exec -it
    claude-vault vault-console ...). Hidden values are read without echo and go straight to the running vault;
    nothing typed is ever printed back."""
    import getpass
    ask = ask or input
    ask_secret = ask_secret or getpass.getpass
    cfg = cfg or V.Config()
    try:
        key = (cfg.state / 'console.key').read_text().strip()
    except OSError:
        out('vault-console: the vault is not running here (no console key)')
        return 1
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(method, path, body=None):
        req = urllib.request.Request(f'http://127.0.0.1:{cfg.port}{path}', method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'X-Vault-Console': key, 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=120) as r:
                return json.loads(r.read() or b'{}')
        except urllib.error.HTTPError as e:
            try:
                d = json.loads(e.read() or b'{}')
            except ValueError:
                d = {}
            raise VaultError(d.get('error') or f'HTTP {e.code}', e.code, d.get('code') or 'error')

    try:
        if argv[:1] == ['watch'] and set(argv[1:]) <= {'--full'} and len(argv) <= 2:
            return console_watch(call, full='--full' in argv, out=out)
        if argv == ['pending']:
            reqs = call('GET', '/raw/pending').get('requests') or []
            for r in reqs:
                out(V.display_text(f"{r['request_id']}  {r['state']:<9} {r['source']:<14} {r['query']} | reason: "
                                   f"{r['reason']} | expires {r['expires_at'][11:16]} ({r['approval']})"))
            if not reqs:
                out('no raw requests')
            return 0
        if argv[:1] in (['approve'], ['deny']) and len(argv) == 2:
            reqs = {r['request_id']: r for r in call('GET', '/raw/pending').get('requests') or []}
            r = reqs.get(argv[1])
            if r is None or r['state'] != 'pending':
                out(f'vault-console: no pending request {argv[1]!r} (vault-console pending lists them)')
                return 1
            out(V.display_text(f"Claude asks for {r['source']}: {r['query']}\nreason: {r['reason']}"))
            if ask(f"{'Allow this ONCE' if argv[0] == 'approve' else 'Deny it'}? [y/N] ").strip().lower() not in (
                    'y', 'yes'):
                out('vault-console: nothing changed')
                return 1
            res = call('POST', '/raw/approve', {'request_id': argv[1], 'decision': argv[0]})
            out(f"vault-console: {res.get('outcome')}")
            return 0 if res.get('outcome') in ('approved', 'denied') else 1
        if argv[:1] == ['2fa'] and len(argv) == 1:
            st = call('GET', '/tg/login').get('state')
            if st not in ('PASSWORD_NEEDED', 'PASSWORD_INVALID'):
                out(f'vault-console: no Telegram login is waiting for a 2FA password (state: {st})')
                return 1
            pw = ask_secret('Telegram 2FA password (not shown): ')
            call('POST', '/tg/2fa', {'password': pw})
            pw = None
            for _ in range(60):
                time.sleep(1)
                st = call('GET', '/tg/login').get('state')
                if st not in ('PASSWORD_SENT', 'PASSWORD_NEEDED'):
                    break
            out({'LOGIN_OK': 'Telegram login OK: the vault syncs the last 7 days now, then every 15 min.',
                 'PASSWORD_INVALID': 'wrong password: run `vault-console 2fa` again.'}.get(st, f'login state: {st}'))
            return 0 if st == 'LOGIN_OK' else 1
        if argv == ['tg-credentials']:
            st = call('GET', '/tg/credentials')
            if st.get('logged_in'):
                out('vault-console: Telegram is already logged in, so the API credentials stay as they are '
                    '(changing them needs the session wiped first: ask Claude)')
                return 1
            if st.get('credentials'):
                out('telegram credentials: already set')
                if ask('Replace them? [y/N] ').strip().lower() not in ('y', 'yes'):
                    out('telegram credentials: unchanged')
                    return 1
            api_id = ask('Telegram api_id (a number, from my.telegram.org > API development tools): ').strip()
            if not S.TG_API_ID_RE.fullmatch(api_id):
                out('vault-console: api_id must be a number (3-12 digits); nothing stored')
                return 1
            api_hash = ask_secret('Telegram api_hash (32 characters, not shown): ').strip()
            api_id, api_hash = S.check_tg_credentials(api_id, api_hash)
            r = call('POST', '/tg/credentials', {'api_id': api_id, 'api_hash': api_hash})
            api_hash = None
            if r.get('exit_code') != 0:
                out(f"vault-console: telegram credentials NOT stored (tgread exit {r.get('exit_code')})")
                return 1
            out('telegram credentials: stored')
            return 0
        if (argv[:1] == ['secret'] and argv[1:2] and argv[1].partition(':')[0] == 'gmail'
                and len(argv) <= (2 if ':' in argv[1] else 3)):   # secret gmail [LABEL] | secret gmail:LABEL
            label = argv[1].partition(':')[2] or (argv[2] if len(argv) == 3 else None)
            return console_secret_gmail(call, label, ask, ask_secret, out)
        if argv[:1] == ['secret'] and len(argv) == 2 and argv[1] in V.SECRET_SPECS:
            if argv[1] in CONSOLE_INTRO:
                out(CONSOLE_INTRO[argv[1]])
            vals = {}
            for k in V.SECRET_SPECS[argv[1]]:
                prompt, hidden = console_field(argv[1], k)
                vals[k] = (ask_secret(prompt) if hidden else ask(prompt)).strip()
            r = call('POST', f'/secrets/{argv[1]}', vals)
            vals = None
            out(f"secret {argv[1]}: {'replaced' if r.get('replaced') else 'stored'}"
                + (f"; {r['check']}" if r.get('check') else ''))
            return 0
    except VaultError as e:
        out(f'vault-console: {e}')
        return 1
    except (EOFError, KeyboardInterrupt):
        out('vault-console: cancelled')
        return 1
    out('usage: vault-console tg-credentials (type the Telegram api_id + api_hash from my.telegram.org)\n'
        '       vault-console 2fa            (type the Telegram 2FA password during a login)\n'
        f'       vault-console secret NAME    (store/replace a secret: {", ".join(V.SECRET_SPECS)})\n'
        '       vault-console secret gmail [LABEL]   (a Gmail account: main = the first; a new label adds one)\n'
        '       vault-console watch [--full]  (live: every API call; --full adds the response bodies)\n'
        '       vault-console pending | approve RID | deny RID   (decide a raw request of Claude\'s here)')
    return 2


def main():
    global APP
    if sys.argv[1:2] == ['console']:
        return console_main(sys.argv[2:], out=lambda s: print(s, flush=True))   # live even without a tty
    cfg = V.Config()
    os.environ['HOME'] = str(cfg.home)                 # secretscan (regex net) reads the vault's own secrets
    if not re.fullmatch(r'[0-9a-f]{64}', cfg.token_sha256):
        log('refusing to start: VAULT_TOKEN_SHA256 must be the sha256 (hex) of the API token')
        return 2
    for d in (cfg.data, cfg.home, cfg.secrets, cfg.models, cfg.cache, cfg.state, cfg.logs, cfg.inbox):
        V.ensure_dir(d)
    shutil.rmtree(cfg.tmp, ignore_errors=True)
    V.ensure_dir(cfg.tmp)
    store = V.SecretStore(cfg)
    if cfg.test_mode and (any(store.names().values()) or (cfg.secrets / 'tgread.session').exists()):
        log('refusing to start: VAULT_TEST_MODE=1 on a data volume with real secrets or a Telegram session')
        return 2
    APP = App(cfg)
    APP.start()
    srv = Server((cfg.listen, cfg.port), Handler)

    def on_term(signum, frame):
        log(f'signal {signum}: shutting down')
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    log(f'claude-vault {V.VERSION} listening on {cfg.listen}:{cfg.port}' + (' (TEST MODE: codes go to this log, '
                                                                            'nothing to Telegram)' if cfg.test_mode else ''))
    try:
        srv.serve_forever(poll_interval=1)
    finally:
        APP.stop()
        srv.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
