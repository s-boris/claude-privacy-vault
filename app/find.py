"""Find (plan v2 #10, 2026-10-13): one ranked list across Telegram, Gmail and paperless, with word variants.

`POST /find {q, since?, sources?, n?}` (job op `find`; client `vault find "query"`):
- The query's words are expanded (tgread.expand_query, the same table as `tg search --expand`): Swiss German, German
  and English (Hochzeit = Hochziit = wedding, Freitag = Fritig, JGA = Junggesellenabschied, Geburtstag = Geburi, ...),
  ue = ü (ae = ä, oe = ö), word starts.
- Telegram: `tgread search --expand --raw --json` (vault-internal raw hits); Gmail: X-GM-RAW `{a b c}` groups per
  word (read-only IMAP, every account); paperless: full-text search, METADATA ONLY (title, date, type,
  correspondent, tags; never content).
- Ranked in code on the raw text (inside the vault): the query's own words before variants, then newest first.
- The Telegram and Gmail snippets of the result are anonymized together in ONE llm-local call (policy v4 paraphrase;
  with mail in the batch: every amount masked, policy v3.1), cached; regex net after. Nothing raw leaves.
- A source that fails gives a partial result with `errors: {source: why}`; all failing is an error."""
import datetime as dt
import re
import time

import vaultlib as V
from vaultlib import VaultError

SOURCES = ('tg', 'gmail', 'paperless')
SNIPPET = 360
REF_TAIL = re.compile(r'\s*\(#(\d+)(?: reply to #(\d+))?\)(?:\s+<== match)?\s*$')
LINE_HEAD = re.compile(r'^(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}\] [^\n:]{1,120}?: ?)')
PL_MAX = 300


def _key(s):
    """ü/ue-insensitive, casefolded word keys of a text."""
    out = []
    for w in re.findall(r'[^\W_]+', str(s or '').casefold()):
        for a, b, c in (('ü', 'ue', 'u'), ('ä', 'ae', 'a'), ('ö', 'oe', 'o')):
            w = w.replace(b, c).replace(a, c)
        out.append(w)
    return out


def score(text, groups):
    """2 per query word found as written (word start), 1 per word found only as a variant."""
    ks = _key(text)
    s = 0
    for g in groups:
        own = _key(g[0].strip('"'))
        if own and _has(ks, own):
            s += 2
        elif any(_has(ks, _key(v.strip('"'))) for v in g[1:]):
            s += 1
    return s


def _has(ks, want):
    if not want:
        return False
    n = len(want)
    for i in range(len(ks) - n + 1):
        if all(ks[i + j] == want[j] for j in range(n - 1)) and ks[i + n - 1].startswith(want[-1]):
            return True
    return False


def since_days(since):
    m = re.fullmatch(r'(\d{1,4})([mhdw])', since)
    if m:
        n = int(m[1]) * {'m': 1 / 1440, 'h': 1 / 24, 'd': 1, 'w': 7}[m[2]]
        return max(1, int(n + 0.999))
    return None


def gmail_query(groups, since):
    """X-GM-RAW: one {a b c} OR-group per query word, newer_than / after for the window."""
    parts = []
    for g in groups:
        alts = []
        for v in g:
            v = v.strip('"')
            t = f'"{v}"' if ' ' in v else v
            if t not in alts:
                alts.append(t)
        parts.append(alts[0] if len(alts) == 1 else '{' + ' '.join(alts[:12]) + '}')
    q = ' '.join(parts)
    d = since_days(since)
    if d:
        q += f' newer_than:{d}d'
    elif re.fullmatch(r'\d{4}-\d{2}-\d{2}', since):
        q += ' after:' + since.replace('-', '/')
    return q


def paperless_query(groups):
    """Whoosh full-text query: (a OR b OR c*) per word, cut to fit paperless' 300 characters."""
    for per in (8, 5, 3, 1):
        parts = []
        for g in groups:
            alts = []
            for v in g[:per]:
                v = v.strip('"')
                t = f'"{v}"' if ' ' in v else (v + '*' if len(v) >= 4 else v)
                if t not in alts:
                    alts.append(t)
            parts.append(alts[0] if len(alts) == 1 else '(' + ' OR '.join(alts) + ')')
        q = ' '.join(parts)
        if len(q) <= PL_MAX:
            return q
    return None


def cut_around(text, groups, n=SNIPPET):
    """A long message -> about n characters around the first word that matched."""
    text = ' '.join(str(text or '').split())
    if len(text) <= n:
        return text
    low = text.casefold()
    pos = -1
    for g in groups:
        for v in g:
            i = low.find(v.strip('"')[:6])
            if i >= 0 and (pos < 0 or i < pos):
                pos = i
    start = max(0, pos - n // 3) if pos > 0 else 0
    return ('…' if start else '') + text[start:start + n].strip() + ('…' if start + n < len(text) else '')


class Find:
    def __init__(self, cfg, policy, audit, tg, gmail, paperless, clock=time.time):
        self.cfg, self.policy, self.audit, self.tg, self.gmail, self.paperless = cfg, policy, audit, tg, gmail, paperless
        self.clock = clock

    def params(self, b):
        q = b.get('q', b.get('query'))
        if not (isinstance(q, str) and 0 < len(q.strip()) <= 200 and not V._CTRL.search(q)):
            raise VaultError('q must be a search text of 1..200 characters', 400, 'bad_param')
        since = b.get('since') or '30d'
        if not (isinstance(since, str) and re.fullmatch(r'\d{1,4}[mhdw]|\d{4}-\d{2}-\d{2}', since.strip())):
            raise VaultError('since: e.g. 30d, 12w or 2026-09-01', 400, 'bad_param')
        n = b.get('n', 15)
        if not (isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= 50):
            raise VaultError('n must be 1..50', 400, 'bad_param')
        src = b.get('sources') or list(SOURCES)
        if isinstance(src, str):
            src = [s.strip() for s in src.split(',') if s.strip()]
        src = ['tg' if s in ('telegram', 'tg') else s for s in src] if isinstance(src, list) else None
        if not src or any(s not in SOURCES for s in src):
            raise VaultError(f'sources: a list of {", ".join(SOURCES)}', 400, 'bad_param')
        return q.strip(), since.strip(), n, list(dict.fromkeys(src))

    def run(self, b, report=None, text=True):
        """text=False (privacy plan A): hits without text, subject or snippet (no LLM call at all)."""
        q, since, n, sources = self.params(b or {})
        groups = self.policy.tg().expand_query(q)
        if not groups:
            raise VaultError('q has no words to search for', 400, 'bad_param')
        hits, errors = [], {}
        for s in sources:
            if report:
                report('progress', done=sources.index(s), total=len(sources) + 1, step=f'searching {s}')
            try:
                hits += getattr(self, f'_{s}')(q, since, n, groups, errors)
            except V.NotConfigured:
                errors[s] = 'not configured in the vault'
            except VaultError as e:
                errors[s] = V.clean_text(self.policy.regex_net(str(e)), 200)
        if errors and not hits and all(s in errors for s in sources):
            raise VaultError('find: every source failed: ' + '; '.join(f'{k}: {v}' for k, v in errors.items()), 502,
                             'source_failed', errors=errors)
        hits.sort(key=lambda h: (-h['_score'], -(h['_ts'] or 0)))
        hits = hits[:n]
        texts = [h for h in hits if h['source'] in ('tg', 'gmail')] if text else []
        if not text:
            import answer
            aliases = self.tg.alias_map() if any(h['source'] == 'tg' for h in hits) else {}
            for h in hits:
                if h['source'] == 'tg':
                    h['chat'] = answer.chat_display(h.get('chat_key'), h.get('chat_type'), h.get('_chat'), aliases)
                    h['from'] = answer.first_name(h.get('_sender')) if h.get('_sender') else None
                elif h['source'] == 'gmail':
                    h['from'] = self.gmail.mail_net(answer.display_from(h.get('_name'), h.get('_domain')))
        if report:
            report('progress', done=len(sources), total=len(sources) + 1, step='anonymizing the snippets')
        if texts:
            anon = self.anonymize([h['_text'] for h in texts], mail=any(h['source'] == 'gmail' for h in texts))
            for h, a in zip(texts, anon):
                if h['source'] == 'gmail':
                    subj, _, snip = a.partition('\n')
                    h['subject'] = subj.removeprefix('Subject:').strip()
                    h['snippet'] = ' '.join(snip.split())
                else:
                    h['text'] = ' '.join(a.split())
        out = []
        for i, h in enumerate(hits, 1):
            out.append({'rank': i, **{k: v for k, v in h.items() if not k.startswith('_')}, 'score': h['_score']})
        self.audit.log('find', q=q, since=since, sources=','.join(sources), count=len(out),
                       per_source=','.join(f"{s}:{sum(1 for h in out if h['source'] == s)}" for s in sources),
                       failed=','.join(sorted(errors)))
        res = {'query': q, 'since': since, 'sources': sources, 'count': len(out),
               'variants': [g[:8] for g in groups], 'results': out,
               'note': ('one ranked list (the query\'s own words first, then newest); Telegram and mail text anonymized '
                        'and paraphrased in the vault; paperless as metadata only') if text else
                       'one ranked list; hits without text (privacy plan A); paperless as metadata only'}
        if errors:
            res['errors'] = errors
        return res

    def anonymize(self, texts, mail=False):
        """ONE --anonymize --paraphrase call for every snippet ('### item N' blocks); per item only if the split
        fails. mail: every amount masked (policy v3.1) for the whole batch."""
        owner = (self.gmail.fallback_owner() if self.gmail is not None else '') or None
        joined = '\n\n'.join(f'### item {k}\n{t}' for k, t in enumerate(texts, 1))
        out = self.policy.anonymize(joined, owner_name=owner, what=f'find anonymize ({len(texts)})', timeout=1800,
                                    all_amounts=mail, cls='live', paraphrase=True)
        parts = V.split_items(out, len(texts))
        if parts is None:
            parts = [self.policy.anonymize(t, owner_name=owner, what='find anonymize', timeout=900, all_amounts=mail,
                                           cls='live', paraphrase=True) for t in texts]
        net = self.policy.regex_net
        return [net(p.strip()) for p in parts]

    # ------------------------------------------------------------------------------------------------ sources
    def _tg(self, q, since, n, groups, errors):
        out = []
        for h in self.tg.find_hits(q, since=since, n=n):
            line = str(h.get('line') or '')
            line = REF_TAIL.sub('', line)
            m = LINE_HEAD.match(line)
            head, body = (m.group(1), line[m.end():]) if m else ('', line)
            ts = h.get('ts') if isinstance(h.get('ts'), (int, float)) else None
            sm = re.match(r'^\[[^\]]+\] ([^\n:]{1,120}?):', head)
            out.append({'source': 'tg', 'date': V.now_iso(ts) if ts else None, '_chat': h.get('chat'),
                        '_sender': sm.group(1) if sm else None,
                        'chat': self.policy.regex_net(V.clean_text(h.get('chat') or '?', 100)),
                        'chat_key': str(h.get('chat_id') or ''), 'chat_type': V.clean_text(h.get('chat_type') or '', 20),
                        'ref': f"#{h.get('msg_id')}", '_ts': ts, '_score': score(body, groups),
                        '_text': head + cut_around(body, groups)})
        return out

    def _gmail(self, q, since, n, groups, errors):
        rows, errs = self.gmail.find_rows(gmail_query(groups, since), q, n)
        V.capture_raw('Gmail find', '\n\n'.join(r.pop('_raw', '') for r in rows))
        out = []
        for r in rows:
            out.append({'source': 'gmail', 'date': V.now_iso(r['ts']) if r.get('ts') else None,
                        'ref': f"{r['account']}:{r['uid']}" + (f"@{r['folder']}" if r.get('folder') not in
                                                               (None, 'INBOX') else ''),
                        'account': r['account'], 'from': self.gmail.mail_net(r['from']), '_ts': r.get('ts'),
                        '_name': r.get('_name'), '_domain': r.get('_domain'),
                        '_score': score(f"{r['subject']} {r['snippet']}", groups),
                        '_text': f"Subject: {r['subject']}\n{cut_around(r['snippet'], groups, 240)}"})
        for label, why in (errs or {}).items():          # one account failed, the others answered
            errors[f'gmail:{label}'] = V.clean_text(self.policy.regex_net(why), 200)
        return out

    def _paperless(self, q, since, n, groups, errors):
        pq = paperless_query(groups) or q[:PL_MAX]
        res = self.paperless.search(pq, n)
        out = []
        for d in res.get('results') or []:
            ts = None
            try:
                ts = dt.datetime.fromisoformat(d.get('created') or d.get('added')).timestamp()
            except (TypeError, ValueError, AttributeError):
                pass
            out.append({'source': 'paperless', 'date': d.get('created') or None, 'id': d.get('id'),
                        'title': d.get('title'), 'document_type': d.get('document_type'),
                        'correspondent': d.get('correspondent'), 'tags': d.get('tags'), 'url': d.get('url'),
                        '_ts': ts, '_score': max(1, score(d.get('title') or '', groups))})
        return out
