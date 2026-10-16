"""Health metrics of the privacy vault (plan v2 #8, 2026-10-13).

Hourly totals for 30 days in /data/state/metrics.json (0600). Numbers only, summed per hour (G7): no payload text,
no chat, sender or file names, so nothing reveals the timing of a single private message.

Per hour:
  routes   per route (method + first two path parts): calls, errors (5xx), timeouts, callers that left before the
           answer, and a duration histogram (median, 95th percentile, maximum)
  llm      busy seconds and jobs; wait histogram per class (live | bulk | background); longest queue; jobs dropped
           (caller gone while queued) or stopped (caller gone while running); llm-local's own numbers (it appends one
           JSON line per run to llm-stats.jsonl, LLM_LOCAL_STATS_FILE): prompt tokens processed vs reused from the
           model's prompt cache, generated tokens, prompt and generation seconds
  cache    hits and misses per cache (paperless content; llm-local's anonymization caches)
  delay    source delay per source: message or mail time -> event stored
  backlog  the largest event-feed backlog seen
Shown by GET /metrics?days=N (`vault metrics`), one line in /status (`vault status`) and in the pinned status.
Alert (vault alert note) when the LLM's 95th-percentile wait was over 15 min for a whole hour.
"""
import calendar
import json
import math
import os
import threading
import time
from pathlib import Path

import vaultlib as V

BOUNDS = (0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 45, 60, 90, 120, 180, 240, 300, 450, 600, 900, 1200, 1800, 2700,
          3600, 7200)
KEEP_HOURS = 30 * 24
MAX_ROUTES = 120                     # per hour; more distinct routes are counted as 'other'
WAIT_ALERT_S = 900                   # p95 wait over 15 min for a whole hour -> alert
CLASSES = ('live', 'bulk', 'background')
TIMEOUT_CODES = ('llm_busy', 'timeout', 'llm_timeout')
TOKEN_KEYS = ('prompt_tokens', 'cached_tokens', 'gen_tokens')
SECOND_KEYS = ('prompt_s', 'gen_s')


def hist_new():
    return {'n': 0, 'sum': 0.0, 'max': 0.0, 'b': [0] * (len(BOUNDS) + 1)}


def hist_add(h, v):
    v = max(0.0, float(v))
    h['n'] += 1
    h['sum'] += v
    h['max'] = max(h['max'], v)
    i = 0
    while i < len(BOUNDS) and v > BOUNDS[i]:
        i += 1
    h['b'][i] += 1


def hist_merge(a, b):
    if not b:
        return a
    a['n'] += b.get('n', 0)
    a['sum'] += b.get('sum', 0.0)
    a['max'] = max(a['max'], b.get('max', 0.0))
    a['b'] = [x + y for x, y in zip(a['b'], b.get('b') or [0] * len(a['b']))]
    return a


def hist_pct(h, p):
    """The upper bound of the bucket holding the p-th percentile, capped at the real maximum; None when empty."""
    if not h or not h.get('n'):
        return None
    rank = max(1, math.ceil(p / 100 * h['n']))
    c = 0
    for i, k in enumerate(h['b']):
        c += k
        if c >= rank:
            return round(min(BOUNDS[i], h['max']) if i < len(BOUNDS) else h['max'], 2)
    return round(h['max'], 2)


def hist_view(h):
    return {'n': h['n'], 'p50_s': hist_pct(h, 50), 'p95_s': hist_pct(h, 95), 'max_s': round(h['max'], 2)}


def route_key(method, path, status=200):
    """'POST /tg/recent'; variable parts (secret names, job ids) become '*'; unknown paths count as 'other'."""
    if status == 404:
        return 'other'
    parts = [p for p in path.split('/') if p][:2]
    if parts and parts[0] in ('secrets', 'jobs') and len(parts) > 1:
        parts[1] = '*'
    return f"{method} /{'/'.join(parts)}"


def job_class(what):
    """LLM job class from the gate label (the scheduler passes it explicitly; this is the fallback)."""
    w = (what or '').lower()
    if any(k in w for k in ('triage', 'event anonymize', 'prefetch', 'background')):
        return 'background'
    if any(k in w for k in ('summar', 'job', 'bulk', '--full')):
        return 'bulk'
    return 'live'


def hour_key(ts):
    return time.strftime('%Y-%m-%dT%H', time.gmtime(ts))


def hour_ts(key):
    return calendar.timegm(time.strptime(key, '%Y-%m-%dT%H'))


def fmt_s(s):
    if s is None:
        return '-'
    return f'{s:.1f} s' if s < 10 else f'{int(round(s))} s' if s < 90 else f'{s / 60:.1f} min'


class Metrics:
    def __init__(self, path, clock=time.time, alert=None, stats_file=None):
        self.path, self.clock, self.alert = Path(path), clock, alert
        self.stats_file = Path(stats_file) if stats_file else None
        self._lock = threading.Lock()
        self.hours = {}
        self.queue_len = 0
        self._alerted = None
        try:
            d = json.loads(self.path.read_text())
            if isinstance(d.get('hours'), dict):
                self.hours = d['hours']
            self._alerted = d.get('alerted')
        except (OSError, ValueError, AttributeError):
            pass

    # ---------------------------------------------------------------- recording (numbers only)
    def _hour(self):
        k = hour_key(self.clock())
        h = self.hours.get(k)
        if h is None:
            h = self.hours[k] = {'routes': {}, 'llm': {'busy_s': 0.0, 'jobs': 0, 'wait': {}, 'queue_max': 0,
                                                       'dropped': 0, 'stopped': 0, 'runs': 0,
                                                       **{t: 0 for t in TOKEN_KEYS}, **{t: 0.0 for t in SECOND_KEYS}},
                                 'cache': {}, 'delay': {}, 'backlog': 0}
        return h

    def call(self, route, status, seconds, code=None, gone=False, timed_out=False):
        with self._lock:
            routes = self._hour()['routes']
            if route not in routes and len(routes) >= MAX_ROUTES:
                route = 'other'
            r = routes.setdefault(route, {'n': 0, 'err': 0, 'timeout': 0, 'gone': 0, 'h': hist_new()})
            r['n'] += 1
            r['err'] += int(status >= 500)
            r['timeout'] += int(bool(timed_out or code in TIMEOUT_CODES or status == 504))
            r['gone'] += int(bool(gone))
            hist_add(r['h'], seconds)

    def llm_wait(self, cls, seconds):
        with self._lock:
            hist_add(self._hour()['llm']['wait'].setdefault(cls if cls in CLASSES else 'live', hist_new()), seconds)

    def llm_job(self, seconds):
        with self._lock:
            llm = self._hour()['llm']
            llm['busy_s'] += max(0.0, float(seconds))
            llm['jobs'] += 1

    def llm_queue(self, n):
        with self._lock:
            self.queue_len = n
            llm = self._hour()['llm']
            llm['queue_max'] = max(llm['queue_max'], int(n))

    def llm_event(self, kind):
        """'dropped' (caller gone while queued) or 'stopped' (caller gone while running)."""
        with self._lock:
            llm = self._hour()['llm']
            llm[kind] = llm.get(kind, 0) + 1

    def cache(self, name, hits=0, misses=0):
        with self._lock:
            c = self._hour()['cache'].setdefault(str(name)[:40], {'hit': 0, 'miss': 0})
            c['hit'] += int(hits)
            c['miss'] += int(misses)

    def delay(self, source, seconds):
        with self._lock:
            hist_add(self._hour()['delay'].setdefault(str(source)[:20], hist_new()), seconds)

    def backlog(self, n):
        with self._lock:
            h = self._hour()
            h['backlog'] = max(h.get('backlog', 0), int(n))

    def ingest(self):
        """llm-local's per-run lines (numbers only) -> this hour. The file is renamed first, so a run that appends
        meanwhile starts a new file instead of being lost."""
        if not self.stats_file or not self.stats_file.exists():
            return 0
        tmp = self.stats_file.with_name(self.stats_file.name + '.ingest')
        try:
            os.replace(self.stats_file, tmp)
            lines = tmp.read_text('utf-8', errors='replace').splitlines()[-5000:]
            tmp.unlink()
        except OSError:
            return 0
        n = 0
        with self._lock:
            h = self._hour()
            llm = h['llm']
            for ln in lines:
                try:
                    d = json.loads(ln)
                except ValueError:
                    continue
                if not isinstance(d, dict):
                    continue
                llm['runs'] += 1
                for k in TOKEN_KEYS:
                    llm[k] += int(d.get(k) or 0) if isinstance(d.get(k), (int, float)) else 0
                for k in SECOND_KEYS:
                    llm[k] += float(d.get(k) or 0) if isinstance(d.get(k), (int, float)) else 0.0
                for name, hm in (d.get('cache') or {}).items():
                    if isinstance(hm, list) and len(hm) == 2 and all(isinstance(x, int) for x in hm):
                        c = h['cache'].setdefault(str(name)[:40], {'hit': 0, 'miss': 0})
                        c['hit'] += hm[0]
                        c['miss'] += hm[1]
                n += 1
        return n

    # ---------------------------------------------------------------- persistence, alert
    def flush(self):
        with self._lock:
            for k in sorted(self.hours)[:-KEEP_HOURS]:
                del self.hours[k]
            data = json.dumps({'hours': self.hours, 'alerted': self._alerted}, separators=(',', ':'))
        V.write_private(self.path, data)

    def check_alert(self):
        """The last complete hour: p95 wait over all classes > WAIT_ALERT_S -> one alert per hour."""
        prev = hour_key(self.clock() - 3600)
        if self._alerted == prev:
            return False
        with self._lock:
            w = hist_new()
            for hh in ((self.hours.get(prev) or {}).get('llm') or {}).get('wait', {}).values():
                hist_merge(w, hh)
        p95 = hist_pct(w, 95)
        if p95 is None or p95 <= WAIT_ALERT_S:
            return False
        self._alerted = prev
        if self.alert:
            self.alert('llm-wait', 'the local LLM queue is slow',
                       f'In the hour {prev}:00 UTC, 95% of LLM jobs waited up to {fmt_s(p95)} before they could '
                       f'start ({w["n"]} jobs). `vault metrics` shows the routes and classes; `vault status` the '
                       f'current queue.', hours=1)
        return True

    def tick(self):
        self.ingest()
        self.check_alert()
        self.flush()

    # ---------------------------------------------------------------- views
    def summary(self, days=1.0):
        now = self.clock()
        cutoff = now - float(days) * 86400
        with self._lock:
            keys = [k for k in self.hours if hour_ts(k) + 3600 > cutoff]
            hours = [json.loads(json.dumps(self.hours[k])) for k in sorted(keys)]
        routes, waits, delays, cache = {}, {}, {}, {}
        llm = {'busy_s': 0.0, 'jobs': 0, 'queue_max': 0, 'dropped': 0, 'stopped': 0, 'runs': 0,
               **{t: 0 for t in TOKEN_KEYS}, **{t: 0.0 for t in SECOND_KEYS}}
        backlog = 0
        for h in hours:
            for name, r in h.get('routes', {}).items():
                a = routes.setdefault(name, {'n': 0, 'err': 0, 'timeout': 0, 'gone': 0, 'h': hist_new()})
                for k in ('n', 'err', 'timeout', 'gone'):
                    a[k] += r.get(k, 0)
                hist_merge(a['h'], r.get('h'))
            hl = h.get('llm') or {}
            for k in llm:
                if k == 'queue_max':
                    llm[k] = max(llm[k], hl.get(k, 0))
                else:
                    llm[k] += hl.get(k, 0)
            for cls, w in (hl.get('wait') or {}).items():
                hist_merge(waits.setdefault(cls, hist_new()), w)
            for src, d in (h.get('delay') or {}).items():
                hist_merge(delays.setdefault(src, hist_new()), d)
            for name, c in (h.get('cache') or {}).items():
                a = cache.setdefault(name, {'hit': 0, 'miss': 0})
                a['hit'] += c.get('hit', 0)
                a['miss'] += c.get('miss', 0)
            backlog = max(backlog, h.get('backlog', 0))
        span = 0.0
        if hours:
            first = hour_ts(sorted(keys)[0])
            span = max(60.0, min(now, hour_ts(sorted(keys)[-1]) + 3600) - first)
        proc, reused = llm['prompt_tokens'], llm['cached_tokens']
        return {
            'days': float(days), 'hours': len(hours),
            'routes': sorted(({'route': k, 'calls': r['n'], 'errors': r['err'], 'timeouts': r['timeout'],
                               'gone': r['gone'], **{k2: v for k2, v in hist_view(r['h']).items() if k2 != 'n'}}
                              for k, r in routes.items()), key=lambda x: -x['calls']),
            'llm': {'busy_share': round(min(1.0, llm['busy_s'] / span), 3) if span else 0.0, 'jobs': llm['jobs'],
                    'wait': {c: hist_view(w) for c, w in sorted(waits.items())},
                    'queue_max': llm['queue_max'], 'dropped': llm['dropped'], 'stopped': llm['stopped'],
                    'queue_now': self.queue_len,
                    'runs': llm['runs'], 'prompt_tokens_processed': proc, 'prompt_tokens_reused': reused,
                    'reused_share': round(reused / (proc + reused), 3) if proc + reused else None,
                    'gen_tokens': llm['gen_tokens'],
                    'prompt_tps': round(proc / llm['prompt_s'], 1) if llm['prompt_s'] else None,
                    'gen_tps': round(llm['gen_tokens'] / llm['gen_s'], 2) if llm['gen_s'] else None},
            'cache': {k: {'hits': c['hit'], 'misses': c['miss'],
                          'hit_rate': round(c['hit'] / (c['hit'] + c['miss']), 3) if c['hit'] + c['miss'] else None}
                      for k, c in sorted(cache.items())},
            'delay': {k: hist_view(d) for k, d in sorted(delays.items())},
            'backlog_max': backlog,
        }

    def status_line(self, s=None):
        """One line for /status: the last 24 h."""
        s = s or self.summary(1)
        calls = sum(r['calls'] for r in s['routes'])
        if not calls and not s['llm']['jobs']:
            return 'no calls in the last 24 h'
        err = sum(r['errors'] for r in s['routes'])
        gone = sum(r['gone'] for r in s['routes'])
        slow = max(s['routes'], key=lambda r: r['p95_s'] or 0, default=None)
        w95 = max((w['p95_s'] or 0 for w in s['llm']['wait'].values()), default=None)
        hits = sum(c['hits'] for c in s['cache'].values())
        tot = hits + sum(c['misses'] for c in s['cache'].values())
        parts = [f'24 h: {calls} calls, {err} errors' + (f', {gone} callers left early' if gone else '')]
        if slow and slow['p95_s']:
            parts.append(f"slowest p95 {slow['route']} {fmt_s(slow['p95_s'])}")
        parts.append(f"LLM {round(100 * s['llm']['busy_share'])}% busy, {s['llm']['jobs']} jobs, wait p95 "
                     f"{fmt_s(w95)}")
        if tot:
            parts.append(f'cache hits {round(100 * hits / tot)}%')
        return '; '.join(parts)

    def board_line(self):
        """A short health item for the pinned status (24 h)."""
        s = self.summary(1)
        w95 = max((w['p95_s'] or 0 for w in s['llm']['wait'].values()), default=0)
        err = sum(r['errors'] for r in s['routes'])
        return f"⏱ wait {fmt_s(w95)} · LLM {round(100 * s['llm']['busy_share'])}%" + (f' · ⚠ {err} err' if err else '')
