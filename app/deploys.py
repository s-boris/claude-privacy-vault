"""Telegram-approved deploys of the vault itself: the owner taps ✅ in the vault bot, a runner on the host deploys.

The assistant cannot deploy the vault. It asks: POST /deploy/request {commit} (a commit on GitHub main). The deploy
mailbox is two host folders bind-mounted into the vault (docker-compose.yml):
  /deploy/requests  written only by this process (the vault's user); the host runner reads it and never writes it
  /deploy/results   written by the host runner (root, every minute); read-only here
One request id, two steps:
  1. review  requests/ID.review -> the runner reviews the commit with the owner's deploy script and writes
             results/ID.review: kind (update / ROLLBACK / rebuild), files (!! privacy or container first), WEIGHTS
             CHANGED, privacy filter, image build, the vault.env settings it changes, and whether Telegram may deploy
             it at all (container settings unchanged, ...). The vault sends the owner a card made from exactly those
             facts, with ✅ Deploy / ❌ Cancel.
  2. deploy  his ✅ (his chat, this card's message, its single-use nonce) -> requests/ID.deploy with the sha256 of the
             facts he saw and a 30-min expiry. The runner checks everything again on its own and deploys;
             results/ID.result -> the card shows the outcome and a new message tells him.
No API route approves anything. State: /data/state/deploys.json (it survives the restart a deploy causes)."""
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from pathlib import Path

import vaultlib as V
from vaultlib import VaultError

ID_RE = re.compile(r'[0-9a-f]{32}')
SHA_RE = re.compile(r'[0-9a-f]{40}')
CALLBACK = re.compile(r'D:([ad]):([0-9a-f]{32}):([A-Za-z0-9_-]{16})')
ACTIVE = ('reviewing', 'awaiting', 'approved', 'deploying')
KINDS = ('update', 'rollback', 'redeploy', 'sideways', 'first')
REVIEW_KEYS = ('id', 'commit', 'running', 'kind', 'commits', 'weights', 'privacy', 'build', 'settings', 'telegram',
               'allowed', 'why', 'date', 'subject', 'stat', 'files', 'flagged', 'code')
SETTINGS = re.compile(r'-|VAULT_[A-Z0-9_]{1,34}(,VAULT_[A-Z0-9_]{1,34}){0,7}(,\+[0-9]{1,4})?')
MARK_ORDER = {'!!': 0, '!': 1, '-': 2}
FILE_LINE = re.compile(r'file (!!|!|-) ([A-Z]) (.{1,200})')
RESULT_KEYS = ('id', 'commit', 'step', 'outcome', 'reason', 'finished', 'running')
OUTCOME_LINE = {'approved': '✅ Approved: your server deploys it within a minute (a build takes a few minutes)',
                'deploying': '⏳ Deploying', 'deployed': '✅ Deployed', 'failed': '⚠️ Failed',
                'refused': '⛔ Not deployed', 'denied': '❌ Cancelled', 'expired': '⌛ Expired',
                'cancelled': '↩️ Replaced by a newer request'}


def clean(s, maxlen):
    """Server text for the owner's card: printable, no bidi/format characters, bounded."""
    s = ''.join(ch for ch in str(s) if unicodedata.category(ch) not in ('Cc', 'Cf', 'Co', 'Cs'))
    return V.clean_text(s, maxlen)


def parse_review(data):
    """results/ID.review (the runner's facts) -> dict. Strict: fixed keys in a fixed order, else ValueError."""
    lines = data.decode('utf-8', 'replace').split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    if len(lines) < len(REVIEW_KEYS) + 2 or lines[0] != 'claude-vault-deploy-review 1' or lines[-1] != 'end':
        raise ValueError('not a review')
    rv = {}
    for k, line in zip(REVIEW_KEYS, lines[1:]):
        if not line.startswith(k + ' '):
            raise ValueError(f'expected {k}')
        rv[k] = line[len(k) + 1:]
    files = []
    for line in lines[1 + len(REVIEW_KEYS):-1]:
        m = FILE_LINE.fullmatch(line)
        if not m or len(files) >= 25:
            raise ValueError('bad file line')
        files.append({'mark': m.group(1), 'status': m.group(2), 'path': clean(m.group(3), 120)})
    ok = (ID_RE.fullmatch(rv['id']) and SHA_RE.fullmatch(rv['commit'])
          and (rv['running'] == 'none' or SHA_RE.fullmatch(rv['running'])) and rv['kind'] in KINDS
          and rv['commits'].isdigit() and rv['files'].isdigit() and rv['weights'] in ('changed', 'same')
          and rv['privacy'] in ('changed', 'same') and rv['build'] in ('changed', 'same')
          and SETTINGS.fullmatch(rv['settings']) and rv['flagged'].isdigit() and rv['code'].isdigit()
          and rv['telegram'] in ('yes', 'no') and rv['allowed'] in ('yes', 'no'))
    if not ok:
        raise ValueError('bad value')
    for k in ('commits', 'files', 'flagged', 'code'):
        rv[k] = int(rv[k])
    if rv['flagged'] + rv['code'] > rv['files'] or len(files) > rv['files']:
        raise ValueError('bad counts')
    for k, n in (('why', 200), ('date', 20), ('subject', 150), ('stat', 120)):
        rv[k] = clean(rv[k], n)
    rv['file_list'] = sorted(files, key=lambda f: MARK_ORDER[f['mark']])     # !! first (the runner sends them so)
    return rv


def parse_result(data):
    """results/ID.result -> dict (strict), else ValueError."""
    lines = data.decode('utf-8', 'replace').split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    if len(lines) != len(RESULT_KEYS) + 1 or lines[0] != 'claude-vault-deploy-result 1':
        raise ValueError('not a result')
    res = {}
    for k, line in zip(RESULT_KEYS, lines[1:]):
        if not line.startswith(k + ' '):
            raise ValueError(f'expected {k}')
        res[k] = line[len(k) + 1:]
    if not (ID_RE.fullmatch(res['id']) and SHA_RE.fullmatch(res['commit']) and res['step'] in ('review', 'deploy')
            and res['outcome'] in ('deployed', 'failed', 'refused') and res['finished'].isdigit()):
        raise ValueError('bad value')
    res['reason'] = clean(res['reason'], 200)
    return res


def card_text(rv):
    """The owner's deploy card: only the runner's facts (the commit subject is the assistant's words, quoted)."""
    short, run, n, kind = rv['commit'][:7], rv['running'][:7], rv['commits'], rv['kind']
    title = {'update': '🚀 Deploy the vault update', 'rollback': '⏪ ROLLBACK the vault to',
             'redeploy': '🔁 Rebuild the running vault', 'sideways': '⚠️ Deploy the vault (not a newer version)'}
    lines = [f"{title.get(kind, 'Deploy the vault')} {short}?", f"“{rv['subject']}” ({rv['date']})"]
    if kind == 'update':
        lines.append(f"{n} new commit{'s' if n != 1 else ''} since {run} (running now)")
    elif kind == 'rollback':
        lines.append(f"ROLLBACK: {n} commit{'s' if n != 1 else ''} back from {run} (running now)")
    elif kind == 'redeploy':
        lines.append('The same version as now: a rebuild only')
    else:
        lines.append(f'Not a newer version of {run} (running now)')
    if rv['stat'] != '-':
        lines.append(rv['stat'])
    flags = []
    if rv['weights'] == 'changed':
        flags.append('⚠️ WEIGHTS CHANGED: the local model reads your private data')
    if rv['privacy'] == 'changed':
        flags.append('⚠️ Privacy filter changed (vendor/llm-local)')
    if rv['build'] == 'changed':
        flags.append('ℹ️ Image build changed (Dockerfile)')
    if rv['settings'] != '-':
        flags.append('⚙️ Settings changed (vault.env): ' + rv['settings'].replace(',', ', '))
    if rv['telegram'] != 'yes':
        flags.append('⚠️ That version has no Telegram deploys: the next deploy needs the User Scripts button')
    if flags:
        lines += [''] + flags
    if rv['file_list']:
        shown = rv['file_list'][:12]
        lines += [''] + [f"{f['mark'] if f['mark'] != '-' else '  '} {f['status']} {f['path']}" for f in shown]
        more = rv['files'] - len(shown)
        if more > 0:
            hidden = [f'{n} {mark}' for n, mark in ((rv['flagged'] - sum(f['mark'] == '!!' for f in shown), '!!'),
                                                    (rv['code'] - sum(f['mark'] == '!' for f in shown), '!')) if n > 0]
            lines.append(f'… and {more} more' + (f" (of them {', '.join(hidden)})" if hidden else ''))
        if rv['flagged'] or rv['code']:
            lines.append('!! privacy filter or container · ! vault code')
    lines += ['', 'Checked by your server: on GitHub main, container settings unchanged. The tests run before the '
                  'switch; if anything fails, the old vault keeps running.']
    return '\n'.join(lines)


def result_text(r):
    short = r['commit'][:7]
    if r['state'] == 'deployed':
        return f"✅ Vault {short} is deployed{' (rollback)' if (r.get('review') or {}).get('kind') == 'rollback' else ''}."
    if r['state'] == 'failed':
        return f"⚠️ Vault deploy {short} failed: {r.get('reason')}"
    if r['state'] == 'expired':
        return f"⌛ Vault deploy {short} did not happen: {r.get('reason')}"
    return f"⛔ Vault {short} was not deployed: {r.get('reason')}"


class Deploys:
    REVIEW_WAIT = 1200          # s for the runner's review (it runs every minute; a running deploy delays it)
    CARD_TTL = 12 * 3600        # s the owner has to decide
    APPROVAL_TTL = 1800         # s the runner has to start after his ✅ (it checks the expiry itself)
    DEPLOY_WAIT = 3 * 3600      # s after his ✅ without a result: lost
    RUNNER_FRESH = 300          # s: the runner's 'alive' stamp is older -> not running
    MAX_PER_DAY = 10
    KEEP = 30
    TICK = 5

    def __init__(self, cfg, notifier, audit, approver=None, clock=time.time, log=print):
        env = cfg.env
        self.req = Path(env.get('VAULT_DEPLOY_REQUESTS') or '/deploy/requests')
        self.res = Path(env.get('VAULT_DEPLOY_RESULTS') or '/deploy/results')
        self.path = cfg.state / 'deploys.json'
        self.notifier, self.audit, self.approver, self.clock, self.log = notifier, audit, approver, clock, log
        self._lock = threading.RLock()
        self._out = []                                 # ('edit', message_id, text) | ('send', text): after the lock
        self._dirty = False
        try:
            self.st = json.loads(self.path.read_text())
            if not isinstance(self.st, dict) or not isinstance(self.st.get('requests'), dict):
                raise ValueError
        except (OSError, ValueError):
            self.st = {'requests': {}, 'per_day': {}}
        self.st.setdefault('per_day', {})

    # ------------------------------------------------------------------ files
    def _write(self, name, text):
        """requests/NAME, atomically, 0600, never through a symlink."""
        tmp = self.req / f'.{name}.{secrets.token_hex(4)}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='ascii') as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.req / name)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _read(self, name, limit=16384):
        """results/NAME as bytes, or None (missing, not a plain file, too big)."""
        try:
            fd = os.open(self.res / name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        except OSError:
            return None
        with os.fdopen(fd, 'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            data = f.read(limit + 1)
        return data if len(data) <= limit else None

    def _unlink_requests(self, rid):
        for step in ('review', 'deploy'):
            try:
                (self.req / f'{rid}.{step}').unlink()
            except OSError:
                pass

    def cleanup(self):
        """At start: request files of requests that are no longer active go (the vault owns requests/)."""
        try:
            names = os.listdir(self.req)
        except OSError:
            return
        with self._lock:
            live = {rid for rid, r in self.st['requests'].items() if r['state'] in ACTIVE}
        for n in names:
            m = re.fullmatch(r'([0-9a-f]{32})\.(review|deploy)', n)
            if (m and m.group(1) not in live) or (n.startswith('.') and n.endswith('.tmp')):
                try:
                    (self.req / n).unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------ the runner
    def runner(self):
        """The host runner as it reports itself: alive (stamp <= 5 min), state, current job, deployed commit."""
        now = self.clock()
        out = {'alive': False, 'seen': None, 'state': None, 'job': None, 'deployed': None}
        a = self._read('alive', 512)
        m = re.search(rb'^seen (\d{10})$', a or b'', re.M)
        if m:
            seen = int(m.group(1))
            out['seen'] = V.now_iso(seen)
            out['alive'] = -120 <= now - seen <= self.RUNNER_FRESH
        s = (self._read('runner', 1024) or b'').decode('ascii', 'replace')
        m = re.search(r'^state (idle|busy|paused)$', s, re.M)
        out['state'] = m.group(1) if m else None
        m = re.search(r'^job ([0-9a-f]{32}) (review|deploy) (\d{10})$', s, re.M)
        out['job'] = (m.group(1), m.group(2), int(m.group(3))) if m and out['state'] == 'busy' else None
        m = re.search(r'^deployed ([0-9a-f]{40})$', s, re.M)
        out['deployed'] = m.group(1) if m else None
        return out

    def _result(self, rid):
        data = self._read(f'{rid}.result', 4096)
        if data is None:
            return None
        try:
            res = parse_result(data)
        except ValueError:
            return None
        return res if res['id'] == rid else None

    # ------------------------------------------------------------------ state
    def _recs(self):
        return list(self.st['requests'].values())

    def _find(self, rid):
        rid = str(rid or '').strip().lower()
        if not re.fullmatch(r'[0-9a-f]{6,32}', rid):
            raise VaultError('request id: 6-32 hex characters', 400, 'bad_param')
        hits = [r for r in self._recs() if r['id'].startswith(rid)]
        if len(hits) != 1:
            raise VaultError('no such deploy request' if not hits else 'ambiguous request id', 404, 'not_found')
        return hits[0]

    def _stamp(self):
        return dt.datetime.fromtimestamp(self.clock(), V.TZ).strftime('%H:%M')

    def _card_edit(self, r, state, reason=None):
        if r.get('message_id') and r.get('card'):
            line = OUTCOME_LINE.get(state, state) + (f': {reason}' if reason else '')
            self._out.append(('edit', r['message_id'], f"{r['card']}\n\n{line} · {self._stamp()}"))

    def _finish(self, r, state, reason, notify):
        """A final state: request files go, the card shows it, and (notify) a new message tells the owner."""
        r['state'], r['reason'], r['finished'], r['nonce'] = state, clean(reason, 200), self.clock(), None
        self._unlink_requests(r['id'])
        self._card_edit(r, state, r['reason'] if state not in ('deployed', 'denied', 'cancelled') else None)
        if notify:
            self._out.append(('send', result_text(r)))
        self.audit.log(f'deploy_{state}', request_id=r['id'], commit=r['commit'][:12], reason=r['reason'])
        self._dirty = True

    def _sweep(self, now):
        for r in self._recs():
            if r['state'] == 'awaiting' and now > r.get('card_at', r['created']) + self.CARD_TTL:
                self._finish(r, 'expired', 'not decided within 12 h', notify=False)
        done = sorted((r for r in self._recs() if r['state'] not in ACTIVE), key=lambda r: r['created'])
        for r in done[:max(0, len(done) - self.KEEP)]:
            del self.st['requests'][r['id']]
            self._dirty = True
        day = dt.datetime.fromtimestamp(now, V.TZ).date().isoformat()
        if set(self.st['per_day']) - {day}:
            self.st['per_day'] = {day: self.st['per_day'].get(day, 0)}
            self._dirty = True
        return day

    def _save(self):
        if self._dirty:
            V.write_private(self.path, json.dumps(self.st, indent=1, ensure_ascii=False))
            self._dirty = False

    def _flush(self):
        with self._lock:
            out, self._out = self._out, []
        for item in out:
            try:
                if item[0] == 'edit':
                    self.notifier.edit(item[1], item[2])
                else:
                    self.notifier.send(item[1])
            except V.NotifyError as e:
                self.log(f'deploys: telegram {item[0]} failed: {e}')

    # ------------------------------------------------------------------ API
    def _view(self, r):
        out = {'request_id': r['id'], 'commit': r['commit'], 'state': r['state'], 'created_at': V.now_iso(r['created'])}
        for k in ('approved', 'finished'):
            if r.get(k):
                out[f'{k}_at'] = V.now_iso(r[k])
        if r['state'] == 'approved':
            out['expires_at'] = V.now_iso(r['expires'])
        if r.get('reason'):
            out['reason'] = r['reason']
        rv = r.get('review')
        if rv:
            out['review'] = {k: rv[k] for k in ('kind', 'running', 'commits', 'files', 'weights', 'privacy', 'build',
                                                'telegram', 'allowed', 'why', 'subject')}
        return out

    def request(self, commit):
        """The assistant asks for a deploy of COMMIT (full sha). -> the request's view ('reviewing')."""
        commit = str(commit or '').strip().lower()
        if not SHA_RE.fullmatch(commit):
            raise VaultError('commit must be a full 40-character commit id', 400, 'bad_param')
        if self.approver is not None and not self.approver.healthy():
            raise VaultError('the vault bot is not polling (no buttons), so the owner cannot approve here: '
                             'use the User Scripts button', 409, 'no_buttons')
        run = self.runner()
        if not run['alive']:
            raise VaultError('the deploy runner on the server has not been seen for 5 min (not installed or not '
                             'scheduled): use the User Scripts button', 409, 'runner_down')
        if run['state'] == 'paused':
            raise VaultError('the deploy runner is paused on the server (runner.off)', 409, 'runner_paused')
        now = self.clock()
        with self._lock:
            day = self._sweep(now)
            busy = [r for r in self._recs() if r['state'] in ('approved', 'deploying')]
            if busy:
                raise VaultError(f"deploy {busy[0]['id'][:8]} ({busy[0]['commit'][:7]}) is under way: wait for its "
                                 'result', 409, 'busy')
            if self.st['per_day'].get(day, 0) >= self.MAX_PER_DAY:
                raise VaultError(f'{self.MAX_PER_DAY} deploy requests today already', 429, 'daily_limit')
            rid = secrets.token_hex(16)
            try:
                self._write(f'{rid}.review', f'claude-vault-deploy-request 1\nid {rid}\nstep review\n'
                                             f'commit {commit}\ncreated {int(now)}\n')
            except OSError as e:
                raise VaultError(f'the deploy mailbox is not writable ({type(e).__name__}): the runner prepares it '
                                 'on its first run', 503, 'mailbox')
            for r in self._recs():
                if r['state'] in ('reviewing', 'awaiting'):
                    self._finish(r, 'cancelled', 'replaced by a newer request', notify=False)
            rec = {'id': rid, 'commit': commit, 'state': 'reviewing', 'created': now}
            self.st['requests'][rid] = rec
            self.st['per_day'][day] = self.st['per_day'].get(day, 0) + 1
            self._dirty = True
            self._save()
            view = self._view(rec)
        self._flush()
        self.audit.log('deploy_request', request_id=rid, commit=commit[:12])
        return view

    def status(self, rid=None):
        run = self.runner()
        job = run.pop('job')
        run['job'] = {'request_id': job[0], 'step': job[1], 'since': V.now_iso(job[2])} if job else None
        with self._lock:
            if rid:
                return {'runner': run, 'request': self._view(self._find(rid))}
            recs = sorted(self._recs(), key=lambda r: r['created'], reverse=True)[:10]
            return {'runner': run, 'requests': [self._view(r) for r in recs]}

    # ------------------------------------------------------------------ the bot
    def on_callback(self, cq):
        """✅ Deploy / ❌ Cancel on a card. The ApprovalBot already checked the owner's chat and user id."""
        m = CALLBACK.fullmatch(str(cq.get('data') or ''))
        if not m:
            self.audit.log('deploy_callback_refused', why='bad_data')
            return 'Unknown button'
        act, rid, nonce = m.groups()
        msg = cq.get('message') if isinstance(cq.get('message'), dict) else {}
        now = self.clock()
        with self._lock:
            self._sweep(now)
            r = self.st['requests'].get(rid)
            if r is None:
                outcome = 'unknown'
            elif not (r.get('message_id') and msg.get('message_id') == r['message_id'] and isinstance(r.get('nonce'), str)
                      and hmac.compare_digest(nonce.encode(), r['nonce'].encode())):
                outcome = 'mismatch' if r['state'] == 'awaiting' else 'already'
            elif r['state'] != 'awaiting':
                outcome = 'already'
            elif act == 'd':
                self._finish(r, 'denied', 'cancelled by the owner', notify=False)
                outcome = 'denied'
            else:
                exp = int(now) + self.APPROVAL_TTL
                try:
                    self._write(f'{rid}.deploy', f"claude-vault-deploy-request 1\nid {rid}\nstep deploy\n"
                                                 f"commit {r['commit']}\nreview {r['review_sha256']}\n"
                                                 f"approved {int(now)}\nexpires {exp}\n")
                except OSError as e:
                    self._finish(r, 'failed', f'the deploy mailbox is not writable ({type(e).__name__})', notify=True)
                    outcome = 'failed'
                else:
                    r['state'], r['approved'], r['expires'], r['nonce'] = 'approved', now, exp, None
                    self._card_edit(r, 'approved')
                    self._dirty = True
                    outcome = 'approved'
            state = r['state'] if r else None
            self._save()
        self._flush()
        if outcome == 'approved':
            self.audit.log('deploy_approved', request_id=rid, commit=r['commit'][:12], via='telegram')
        elif outcome in ('unknown', 'mismatch'):
            self.audit.log('deploy_callback_refused', request_id=rid, why=outcome)
        return {'approved': 'Approved ✓ Your server deploys it within a minute', 'denied': 'Cancelled ✓',
                'failed': 'Could not hand it to your server', 'unknown': 'This deploy request is gone',
                'mismatch': 'This button is not valid'}.get(outcome, f'Already {state}')

    # ------------------------------------------------------------------ the loop
    def tick(self):
        now = self.clock()
        cards = []
        with self._lock:
            self._sweep(now)
            run = None
            for r in self._recs():
                if r['state'] == 'reviewing':
                    res = self._result(r['id'])
                    if res and res['step'] == 'review':
                        self._finish(r, 'refused', res['reason'], notify=False)
                        continue
                    data = self._read(f"{r['id']}.review")
                    if data is None:
                        if now > r['created'] + self.REVIEW_WAIT:
                            self._finish(r, 'expired', 'the server did not review it in time (is the runner '
                                                       'scheduled?)', notify=False)
                        continue
                    try:
                        rv = parse_review(data)
                    except ValueError as e:
                        self._finish(r, 'failed', f'unreadable review from the server ({e})', notify=False)
                        continue
                    if rv['id'] != r['id'] or rv['commit'] != r['commit']:
                        self._finish(r, 'failed', 'the server reviewed another request', notify=False)
                        continue
                    r['review'], r['review_sha256'] = rv, hashlib.sha256(data).hexdigest()
                    if rv['allowed'] != 'yes':
                        self._finish(r, 'refused', f"needs the User Scripts button: {rv['why']}", notify=False)
                        continue
                    r['state'], r['nonce'], r['card_at'] = 'awaiting', secrets.token_urlsafe(12), now
                    self._dirty = True
                    cards.append(r['id'])
                elif r['state'] in ('approved', 'deploying'):
                    res = self._result(r['id'])
                    if res and res['step'] == 'deploy':
                        self._finish(r, res['outcome'], res['reason'], notify=True)
                        continue
                    run = run or self.runner()
                    job = run['job']
                    if job and job[0] == r['id'] and job[1] == 'deploy':
                        if r['state'] != 'deploying':
                            r['state'], r['started'] = 'deploying', job[2]
                            self._dirty = True
                    elif r['state'] == 'approved' and now > r['expires'] + 120:
                        self._finish(r, 'expired', 'your server did not start it within 30 min (is the runner '
                                                   'scheduled?)', notify=True)
                        continue
                    if now > r['approved'] + self.DEPLOY_WAIT:
                        self._finish(r, 'failed', 'no result from your server after 3 h (User Scripts: the log of '
                                                  '"claude-vault deploy runner")', notify=True)
            self._save()
        for rid in cards:
            self._send_card(rid)
        self._flush()

    def _send_card(self, rid):
        with self._lock:
            r = self.st['requests'].get(rid)
            if not r or r['state'] != 'awaiting' or r.get('message_id'):
                return
            text, nonce = card_text(r['review']), r['nonce']
        buttons = [[('✅ Deploy', f'D:a:{rid}:{nonce}'), ('❌ Cancel', f'D:d:{rid}:{nonce}')]]
        try:
            mid = self.notifier.send(text, buttons=buttons)
        except V.NotifyError as e:
            with self._lock:
                self._finish(r, 'failed', f'could not text the owner: {e}', notify=False)
                self._save()
            return
        with self._lock:
            r['message_id'], r['card'] = mid, text
            self._dirty = True
            self._save()
        self.audit.log('deploy_card', request_id=rid, commit=r['commit'][:12], kind=r['review']['kind'],
                       weights=r['review']['weights'], privacy=r['review']['privacy'])

    def run(self, stop_ev):
        self.cleanup()
        while not stop_ev.wait(self.TICK):
            try:
                self.tick()
            except Exception as e:                     # never let the loop die
                self.log(f'deploys: {type(e).__name__}: {e}')
