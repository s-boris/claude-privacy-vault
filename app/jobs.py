"""Async jobs (plan v2 #4, 2026-10-13): a long read runs inside the vault while the assistant polls for it, so no
single API call has to outlast an agent's 4-minute limit.

  POST /jobs {op, params}           -> {id, op, state, position, eta_s, coalesced}; op from OPS only (never raw,
                                       secret, console, media request/release or any write route)
  GET  /jobs/<id>?wait=N (N <= 30)  -> {id, op, state, progress, partial, elapsed_s, result | error}; waits up to N s
                                       for the job to end (long poll)
  GET  /jobs                        -> the caller's jobs, without results
  POST /jobs/<id>/cancel            -> a queued job never runs; a running one stops at its next LLM step

Privacy: a job runs the same handler as its route (same filters, same audit lines) under the same token; its result
is that route's anonymized answer, kept in memory only (never on disk, never in the log), for TTL s after the job
ended and at most MAX_BYTES in all (the oldest results go first), readable only with the token that started it. Ids
are random. A restart drops every job. Identical requests (same op and params) share one job while it runs and for
COALESCE_ENDED s after it ended. The audit gets job_submit / job_done with ids, the op, state, seconds and bytes only.
"""
import hashlib
import json
import secrets
import threading
import time

from vaultlib import VaultError, now_iso

OPS = {                                                # op -> (method, route): the reads that may take minutes
    'tg.search': ('POST', '/tg/search'),
    'tg.recent': ('POST', '/tg/recent'),
    'tg.unread-summary-data': ('POST', '/tg/unread-summary-data'),
    'tg.summarize': ('POST', '/tg/summarize'),         # chunked: per chat / day, then one merge (sources.TG)
    'gmail.search': ('POST', '/gmail/search'),
    'gmail.get': ('POST', '/gmail/get'),
    'paperless.get': ('POST', '/paperless/get'),
    'paperless.suggest': ('POST', '/paperless/suggest'),   # plan B: the local model reads it inside
    'media.extract': ('POST', '/media/extract'),       # `vault media facts`
    'llm.run': ('POST', '/llm/run'),
    'tg.facts': ('POST', '/tg/facts'),
    'answer': ('POST', '/answer'),                     # privacy plan A: answers, not text
    'tg.digest': ('POST', '/tg/digest'),               # privacy plan A: the default of tg summarize/recent/unread                 # plan v2 #6: `vault facts tg CHAT` over a long window
    'gmail.facts': ('POST', '/gmail/facts'),
    'find': ('POST', '/find'),                         # plan v2 #10
    'index.eval': ('POST', '/index/eval'),             # memory plan C3: the embedding bake-off (numbers only)
    'people.refresh': ('POST', '/people/refresh'),     # memory plan C5: asks dry run / topic calibration (numbers)
}
# the LLM gate's label of each op's first step (for the ETA before the job reaches the queue)
OP_WHAT = {'tg.search': 'tgread search', 'tg.recent': 'tgread recent',
           'tg.unread-summary-data': 'tgread unread-summary-data', 'tg.summarize': 'tgread summarize',
           'llm.run': 'llm-run (caller text)', 'tg.facts': 'tgread recent', 'find': 'tgread search',
           'answer': 'answer (anonymized text)', 'tg.digest': 'tgread recent (digest)',
           'index.eval': 'index eval (queries)', 'people.refresh': 'people topics calibration'}
NEVER = ('/raw', '/secrets', '/console', '/tg/2fa', '/tg/credentials', '/tg/login', '/media/request',
         '/media/release', '/media/ack', '/paperless/fields', '/paperless/upload', '/paperless/update',
         '/paperless/taxonomy', '/gmail/to-paperless', '/gmail/config', '/events/rules', '/alerts/ack')
assert not any(r.startswith(NEVER) for _, r in OPS.values()), 'a job op may never be a raw, secret or write route'
FINAL = ('done', 'failed', 'cancelled', 'expired')


class Job:
    def __init__(self, op, params, key, owner, ip, clock):
        self.id = secrets.token_hex(8)                 # random, 16 hex characters
        self.op, self.params, self.key, self.owner, self.ip = op, params, key, owner, ip
        self.state = 'queued'
        self.created, self.started, self.ended = clock(), None, None
        self.progress = None                           # {done, total, step}
        self.partial = []                              # filtered part results (chunked summaries)
        self.status, self.result, self.size = None, None, 0
        self.cancel_ev, self.done_ev = threading.Event(), threading.Event()

    def alive(self):
        """The LLM gate's caller check: a cancelled job is a caller that left."""
        return not self.cancel_ev.is_set()

    def report(self, kind, **kw):
        """From the work in progress: 'progress' (done, total, step) or 'partial' (item: a filtered part result)."""
        if kind == 'progress':
            self.progress = {'done': kw.get('done'), 'total': kw.get('total'), 'step': str(kw.get('step') or '')[:40]}
        elif kind == 'partial' and isinstance(kw.get('item'), dict):
            self.partial.append(kw['item'])


class Jobs:
    TTL = 1800                                         # results kept 30 min after the job ended
    MAX_BYTES = 20 << 20                               # all kept results together
    MAX_ACTIVE = 8                                     # queued + running
    MAX_KEPT = 200
    MAX_WAIT = 30.0
    COALESCE_ENDED = 120

    def __init__(self, run, audit=None, clock=time.time, outlook=None):
        self.run = run                                 # run(job) -> (status, body), in the job's own thread
        self.audit, self.clock = audit, clock
        self.outlook = outlook                         # LLMGate.outlook(job=, what=) -> (position, eta_s)
        self._jobs = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------------------------------ submit / run
    def submit(self, op, params, owner, ip=''):
        if op not in OPS:
            raise VaultError(f'op must be one of: {", ".join(sorted(OPS))} (raw, secret, console and write routes '
                             f'can never be jobs)', 400, 'bad_op')
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise VaultError('params must be a JSON object', 400, 'bad_param')
        canon = json.dumps([op, params], sort_keys=True, ensure_ascii=False)
        key = hashlib.sha256(canon.encode('utf-8')).hexdigest()
        with self._lock:
            self._sweep()
            now = self.clock()
            for j in self._jobs.values():
                if j.key == key and j.owner == owner and (
                        j.state in ('queued', 'running')
                        or (j.state == 'done' and now - j.ended <= self.COALESCE_ENDED)):
                    return self.ticket(j, coalesced=True)
            active = sum(j.state in ('queued', 'running') for j in self._jobs.values())
            if active >= self.MAX_ACTIVE:
                raise VaultError(f'{active} jobs are still running; wait for one to end (vault job list)', 429,
                                 'too_many_jobs')
            j = Job(op, params, key, owner, ip, self.clock)
            self._jobs[j.id] = j
        if self.audit:
            self.audit.log('job_submit', job=j.id, op=op)
        threading.Thread(target=self._work, args=(j,), name=f'job-{j.id[:6]}', daemon=True).start()
        return self.ticket(j)

    def _work(self, j):
        with self._lock:
            if j.cancel_ev.is_set():
                j.state = 'cancelled'
            else:
                j.state, j.started = 'running', self.clock()
        if j.state == 'running':
            try:
                status, body = self.run(j)
            except Exception:                          # run() maps errors itself; this is the last resort
                status, body = 500, {'error': 'internal error in the vault (type and line in its log)',
                                     'code': 'internal'}
        else:
            status, body = 499, {'error': 'cancelled before it started', 'code': 'cancelled'}
        self._finish(j, status, body)

    def _finish(self, j, status, body):
        try:
            size = len(json.dumps([body, j.partial], ensure_ascii=False).encode('utf-8'))
        except (TypeError, ValueError):
            status, body, size = 500, {'error': 'the job result is not JSON', 'code': 'internal'}, 0
        if size > self.MAX_BYTES:
            status, body, j.partial = 413, {'error': f'the result is larger than the {self.MAX_BYTES >> 20} MB the '
                                                     f'vault keeps for jobs: narrow it', 'code': 'too_large'}, []
            size = 200
        with self._lock:
            j.status, j.result, j.size, j.ended = status, body, size, self.clock()
            j.state = 'done' if status == 200 else 'cancelled' if j.cancel_ev.is_set() else 'failed'
            self._sweep()
        if self.audit:
            self.audit.log('job_done', job=j.id, op=j.op, state=j.state, status=status,
                           seconds=round(j.ended - (j.started or j.created), 1), bytes=size)
        j.done_ev.set()

    def _sweep(self):
        """(lock held) Drop jobs TTL s after they ended; keep the results under MAX_BYTES and MAX_KEPT jobs."""
        now = self.clock()
        for jid in [k for k, j in self._jobs.items() if j.ended is not None and now - j.ended > self.TTL]:
            del self._jobs[jid]
        ended = sorted((j for j in self._jobs.values() if j.ended is not None and j.result is not None),
                       key=lambda x: x.ended)
        total = sum(j.size for j in ended)
        while ended and total > self.MAX_BYTES:
            old = ended.pop(0)
            total -= old.size
            old.result, old.partial, old.size, old.state = None, [], 0, 'expired'
        while len(self._jobs) > self.MAX_KEPT:
            old = min((j for j in self._jobs.values() if j.ended is not None), key=lambda x: x.ended, default=None)
            if old is None:
                break
            del self._jobs[old.id]

    # ------------------------------------------------------------------------------------------ read
    def _find(self, jid, owner):
        with self._lock:
            self._sweep()
            j = self._jobs.get(jid) if isinstance(jid, str) else None
        if j is None or j.owner != owner:
            raise VaultError('no such job: results are kept 30 min after a job ends, and a vault restart drops every '
                             'job; run it again', 404, 'no_such_job')
        return j

    def get(self, jid, owner, wait=0.0):
        j = self._find(jid, owner)
        if wait and j.state in ('queued', 'running'):
            j.done_ev.wait(max(0.0, min(float(wait), self.MAX_WAIT)))
        return self.view(j, full=True)

    def list(self, owner):
        with self._lock:
            self._sweep()
            js = sorted((j for j in self._jobs.values() if j.owner == owner), key=lambda x: x.created)
        return [self.view(j) for j in js]

    def cancel(self, jid, owner):
        j = self._find(jid, owner)
        if j.state in ('queued', 'running'):
            j.cancel_ev.set()
            if self.audit:
                self.audit.log('job_cancel', job=j.id, op=j.op)
        return self.view(j)

    def active(self):
        with self._lock:
            return sum(j.state in ('queued', 'running') for j in self._jobs.values())

    def ticket(self, j, coalesced=False):
        d = self.view(j)
        d['coalesced'] = coalesced
        return d

    def view(self, j, full=False):
        now = self.clock()
        d = {'id': j.id, 'op': j.op, 'state': j.state, 'created_at': now_iso(j.created),
             'elapsed_s': int((j.ended or now) - (j.started or j.created)), 'progress': j.progress,
             'parts_done': len(j.partial)}
        if j.state in ('queued', 'running') and self.outlook:
            try:
                pos, eta = self.outlook(job=j.id, what=OP_WHAT.get(j.op))
            except Exception:
                pos, eta = None, None
            d['position'], d['eta_s'] = pos, eta
        if j.ended is not None:
            d['ended_at'] = now_iso(j.ended)
            d['expires_at'] = now_iso(j.ended + self.TTL)
            d['status'], d['bytes'] = j.status, j.size
        if full:
            if j.partial:
                d['partial'] = list(j.partial)
            if j.state == 'done':
                d['result'] = j.result
            elif j.state == 'expired':
                d['error'] = {'error': 'the result was dropped: the vault keeps at most 20 MB of job results; run it '
                                       'again', 'code': 'result_dropped'}
            elif j.state in ('failed', 'cancelled'):
                d['error'] = j.result
        return d


def tap_view(body):
    """GET /jobs/<id> as the live view keeps it: state and progress only. The result itself is shown once, as the
    call it ran, when the job ends (vaultd.run_job), so it is neither counted nor stored twice."""
    if not isinstance(body, dict):
        return body
    if isinstance(body.get('jobs'), list):
        return {'jobs': len(body['jobs'])}
    keep = ('id', 'op', 'state', 'progress', 'parts_done', 'elapsed_s', 'position', 'eta_s', 'status', 'bytes')
    return {k: body[k] for k in keep if k in body}
