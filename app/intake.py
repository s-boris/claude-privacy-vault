"""Document intake (privacy plan D): the owner sends photos and PDFs (bills, letters,
contracts, payslips) to the vault's OWN bot, and the vault files them into paperless. Claude never sees the file.

Routing (ApprovalBot.step): a photo, or a document that is a PDF or an image (MIME type or name), comes here; CSV,
XLSX, ZIP and everything else still go to the finance intake (app/finance.py).
- Owner only: from.id == chat.id == his configured chat; anyone else is ignored and audited (intake_refused).
- The real type comes from the bytes (media.sniff): PDF, JPEG, PNG, WebP. HEIC is refused with a hint (paperless
  and the image's Pillow can't read it); so is anything else.
- Albums: items with the same media_group_id within ALBUM_WAIT s are merged; their images become ONE PDF (Pillow),
  a PDF in an album is filed on its own.
- Filing: Paperless.upload with tags Inbox + via-bot (created if missing), the caption as the title, wait for the
  task, then the tier-1 fields; the owner gets "📄 Filed as #N "title" · type · correspondent · CHF x · due …".
- Claude gets: an event in the feed (source paperless, label filed, doc {doc_id, type, correspondent, bill_likely}),
  and GET /intake/status (counts only).
- Limits and audit: MAX_PER_HOUR files per rolling hour; 20 MB per file (the bot API's own limit). The audit
  holds doc ids, sizes and sha256 prefixes only, never names, captions or titles.
Work runs in one worker thread (the poll thread only checks the sender and queues)."""
import base64
import hashlib
import io
import json
import queue
import re
import threading
import time

import vaultlib as V
from media import sniff

MAX_FILE = 20 * 1024 * 1024              # what a bot can download from Telegram anyway
MAX_PER_HOUR = 30
ALBUM_WAIT = 3.0                         # seconds after an album's last item before it is filed
MAX_ALBUM = 30
TASK_TIMEOUT = 300
TAGS = ('Inbox', 'via-bot')
FILE_TYPES = {'pdf': '.pdf', 'jpeg': '.jpg', 'png': '.png', 'webp': '.webp'}
IMAGE_TYPES = ('jpeg', 'png', 'webp')
WANT_EXT = ('.pdf', '.jpg', '.jpeg', '.png', '.webp', '.heic', '.heif', '.tif', '.tiff', '.gif')
BILL_TYPES = re.compile(r'(?i)rechnung|faktura|invoice|bill|mahnung|facture|zahlungs')
WEEKDAYS = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')
TOLD_EVERY = 600                         # the "limit reached" hint at most every 10 min


def wants(msg):
    """True for a message the document intake takes: a photo, or a document that is a PDF or an image."""
    if not isinstance(msg, dict):
        return False
    if isinstance(msg.get('photo'), list) and msg['photo']:
        return True
    doc = msg.get('document')
    if not isinstance(doc, dict):
        return False
    mime = str(doc.get('mime_type') or '').lower()
    name = str(doc.get('file_name') or '').lower()
    return mime == 'application/pdf' or mime.startswith('image/') or name.endswith(WANT_EXT)


def sha12(data):
    return hashlib.sha256(data).hexdigest()[:12]


def due_text(iso):
    try:
        d = time.strptime(str(iso)[:10], '%Y-%m-%d')
    except (TypeError, ValueError):
        return None
    return f'{WEEKDAYS[d.tm_wday]} {d.tm_mday:02d}.{d.tm_mon:02d}'


def images_to_pdf(blobs):
    """Album images -> one PDF (Pillow; python3-pil in the image)."""
    from PIL import Image                                # the vault's /usr/bin/python3 has python3-pil
    pages = []
    for b in blobs:
        im = Image.open(io.BytesIO(b))
        im.load()
        pages.append(im.convert('RGB'))
    out = io.BytesIO()
    pages[0].save(out, format='PDF', save_all=True, append_images=pages[1:], resolution=150.0)
    return out.getvalue()


class Intake:
    def __init__(self, cfg, store, notifier, audit, paperless, events=None, log=print, clock=time.time):
        self.cfg, self.store, self.notifier, self.audit, self.log, self.clock = cfg, store, notifier, audit, log, clock
        self.paperless, self.events = paperless, events
        self.q = queue.Queue()
        self.albums = {}                                 # media_group_id -> {'items': [...], 'last': ts}
        self.lock = threading.RLock()
        self.path = cfg.state / 'intake.json'
        try:
            self.st = json.loads(self.path.read_text())
            if not isinstance(self.st, dict):
                raise ValueError
        except (OSError, ValueError):
            self.st = {}
        for k in ('filed', 'duplicates', 'rejected', 'refused', 'failed', 'rate_limited'):
            self.st.setdefault(k, 0)
        self.st.setdefault('recent', [])                 # timestamps of accepted files (rolling hour)
        self.told_at = 0.0
        self.busy = None

    wants = staticmethod(wants)

    # ---------------------------------------------------------------- helpers
    def _save(self):
        with self.lock:
            V.write_private(self.path, json.dumps(self.st, indent=1))

    def say(self, text):
        try:
            return self.notifier.send(text[:4000])
        except (V.NotifyError, V.VaultError) as e:
            self.log(f'intake: message not sent ({type(e).__name__})')
            return None

    def owner(self):
        try:
            return self.notifier.chat_id()
        except (V.VaultError, KeyError, TypeError):
            return None

    def _count(self, key, n=1):
        with self.lock:
            self.st[key] = int(self.st.get(key, 0)) + n
            self._save()

    # ---------------------------------------------------------------- entry point (poll thread: check + queue)
    def on_message(self, msg):
        owner = self.owner()
        frm, chat = str((msg.get('from') or {}).get('id', '')), str((msg.get('chat') or {}).get('id', ''))
        if not owner or frm != owner or chat != owner:
            self.audit.log('intake_refused', why='wrong_chat')
            self._count('refused')
            return
        now = self.clock()
        with self.lock:
            recent = [t for t in self.st['recent'] if now - t < 3600]
            if len(recent) >= MAX_PER_HOUR:
                self.st['recent'] = recent
                self.st['rate_limited'] = int(self.st.get('rate_limited', 0)) + 1
                self._save()
                tell = now - self.told_at > TOLD_EVERY
                if tell:
                    self.told_at = now
            else:
                recent.append(now)
                self.st['recent'] = recent
                self._save()
                tell = None
        if tell is not None:
            self.audit.log('intake_rate_limited', limit=MAX_PER_HOUR)
            if tell:
                self.say(f'⏳ Document limit reached ({MAX_PER_HOUR} files per hour)\nNothing filed.\n'
                         f'Please send the rest a bit later.')
            return
        self.q.put(('msg', msg))

    # ---------------------------------------------------------------- worker
    def run(self, stop_ev):
        while not stop_ev.is_set():
            try:
                task = self.q.get(timeout=0.5)
            except queue.Empty:
                task = None
            try:
                if task:
                    self.take(task[1])
                self.flush_albums()
            except Exception as e:                       # details could carry document data: type only
                self.log(f'intake: {type(e).__name__}')
                self._count('failed')
                self.say(f'⚠️ Could not file that document ({type(e).__name__}); please send it again.')
            finally:
                self.busy = None

    def drain(self):
        """Tests: everything queued, then every album, right now."""
        while True:
            try:
                task = self.q.get_nowait()
            except queue.Empty:
                break
            self.take(task[1])
        self.flush_albums(force=True)

    def take(self, msg):
        gid = msg.get('media_group_id')
        if gid:
            with self.lock:
                al = self.albums.setdefault(str(gid), {'items': [], 'last': 0.0})
                al['items'].append(msg)
                al['last'] = time.time()
            return
        self.file_messages([msg])

    def flush_albums(self, force=False):
        with self.lock:
            due = [g for g, al in self.albums.items() if force or time.time() - al['last'] >= ALBUM_WAIT]
            ready = [self.albums.pop(g)['items'] for g in due]
        for items in ready:
            self.file_messages(items)

    # ---------------------------------------------------------------- one message or one album
    def _file_ref(self, msg):
        """-> (file_id, size, kind_hint) of a message's photo (largest size) or document."""
        if isinstance(msg.get('photo'), list) and msg['photo']:
            p = max((x for x in msg['photo'] if isinstance(x, dict)),
                    key=lambda x: (int(x.get('file_size') or 0), int(x.get('width') or 0)), default={})
            return p.get('file_id'), int(p.get('file_size') or 0), 'photo'
        doc = msg.get('document') or {}
        return doc.get('file_id'), int(doc.get('file_size') or 0), 'document'

    def _caption(self, msgs):
        for m in msgs:
            c = V.clean_text(str(m.get('caption') or ''), 128).strip()
            if c:
                return c
        return None

    def fetch(self, msg):
        """-> (type, bytes) or (None, why) for one message's file."""
        fid, size, _ = self._file_ref(msg)
        if not fid:
            return None, 'no file in that message'
        if size > MAX_FILE:
            return None, 'over 20 MB (the bot limit)'
        self.busy = 'download'
        try:
            data = self.notifier.download(fid, MAX_FILE)
        except (V.NotifyError, V.VaultError) as e:
            self.log(f'intake: download failed ({type(e).__name__})')
            return None, 'Telegram download failed; please send it again'
        kind, why = sniff(data)
        if kind == 'heic':
            return None, 'HEIC photos can\'t be filed; send it as a photo (not as a file) or as PDF'
        if kind not in FILE_TYPES:
            return None, (f'that is {why}' if why else f'a {kind} file') + '; I file PDFs and photos (JPEG/PNG/WebP)'
        return kind, data

    def file_messages(self, msgs):
        caption = self._caption(msgs)
        got, problems = [], []
        for m in msgs[:MAX_ALBUM]:
            kind, data = self.fetch(m)
            if kind is None:
                problems.append(data)
                self.audit.log('intake_rejected', why=data.split(';')[0][:60])
                self._count('rejected')
            else:
                got.append((kind, data))
        if len(msgs) > MAX_ALBUM:
            problems.append(f'only the first {MAX_ALBUM} items of an album are filed')
        images = [d for k, d in got if k in IMAGE_TYPES]
        pdfs = [d for k, d in got if k == 'pdf']
        uploads = []
        if len(images) > 1:
            try:
                uploads.append(('pdf', images_to_pdf(images), len(images)))
            except Exception as e:                       # a broken image: file them one by one instead
                self.log(f'intake: album merge failed ({type(e).__name__})')
                uploads += [(k, d, 1) for k, d in got if k in IMAGE_TYPES]
        else:
            uploads += [(k, d, 1) for k, d in got if k in IMAGE_TYPES]
        uploads += [('pdf', d, 1) for d in pdfs]
        for kind, data, pages in uploads:
            self.file_one(kind, data, caption, pages)
        for why in dict.fromkeys(problems):
            self.say(f'⚠️ Not filed: {why}.')

    def file_one(self, kind, data, caption, merged=1):
        h = sha12(data)
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(self.clock()))
        body = {'filename': f'via-bot-{stamp}{FILE_TYPES[kind]}', 'content_b64': base64.b64encode(data).decode(),
                'tags': list(TAGS), 'create': True, 'wait': True, 'timeout': TASK_TIMEOUT}
        if caption:
            body['title'] = caption
        self.busy = 'filing'
        try:
            r = self.paperless.upload(body, quiet=True)
        except V.VaultError as e:
            if e.code == 'no_document' or 'duplicate' in str(e).lower():
                self.audit.log('intake_duplicate', size=len(data), sha12=h)
                self._count('duplicates')
                return self.say('📄 Already in paperless (same file), nothing new filed.')
            self.audit.log('intake_failed', why=e.code, size=len(data), sha12=h)
            self._count('failed')
            return self.say(f'⚠️ paperless did not take it ({e.code}); please try again later.')
        if 'document_id' not in r:
            self.audit.log('intake_pending', size=len(data), sha12=h)
            return self.say('📄 Received; paperless is still processing it. It will show up in the Inbox.')
        doc_id = int(r['document_id'])
        try:
            f = self.paperless.fields(doc_id, ['title', 'document_type', 'correspondent', 'amount', 'currency',
                                               'due_date', 'qr_bill', 'has_payment_ref'], audit=False)
        except V.VaultError as e:
            self.log(f'intake: fields failed ({e.code})')
            f = {}
        bill = bool(f.get('qr_bill') or (f.get('amount') and (f.get('due_date') or f.get('has_payment_ref')))
                    or BILL_TYPES.search(str(f.get('document_type') or '')))
        self.audit.log('intake_filed', doc_id=doc_id, size=len(data), sha12=h, pages=merged, bill_likely=bill)
        with self.lock:
            self.st['filed'] = int(self.st.get('filed', 0)) + 1
            self.st['last_filed'] = int(self.clock())
            self._save()
        self.say(self.reply(doc_id, f, bill, merged, r.get('url')))
        self.event(doc_id, f, bill)

    def reply(self, doc_id, f, bill, merged, url):
        """Short lines for a phone: what was filed, its type and sender, then amount and due date."""
        lines = [f'📄 Filed as #{doc_id}' + (f' "{V.clean_text(str(f["title"]), 80)}"' if f.get('title') else '')]
        who = [V.clean_text(str(f[k]), 60) for k in ('document_type', 'correspondent') if f.get(k)]
        if who:
            lines.append(' · '.join(who))
        pay = [f"{f.get('currency') or 'CHF'} {f['amount']}"] if f.get('amount') else []
        if f.get('due_date') and due_text(f['due_date']):
            pay.append(f"due {due_text(f['due_date'])}")
        elif bill:
            pay.append('due date not found')
        if pay:
            lines.append('💰 ' + ' · '.join(pay))
        if merged > 1:
            lines.append(f'({merged} photos merged into one PDF)')
        if url:
            lines.append(url)
        return '\n'.join(lines)

    def event(self, doc_id, f, bill):
        """One row in the event feed: Claude learns that a document was filed and whether it looks like a bill;
        never its title or content."""
        if self.events is None:
            return
        net = self.paperless.policy.regex_net
        doc = {'doc_id': doc_id, 'type': net(str(f.get('document_type') or '')) or None,
               'correspondent': net(str(f.get('correspondent') or '')) or None, 'bill_likely': bill}
        try:
            self.events.add([{'source': 'paperless', 'ts': int(self.clock()), 'chat_key': 'intake',
                              'chat': 'paperless', 'chat_type': 'document', 'label': 'filed',
                              'actionable': int(bill), 'ref': f'paperless:{doc_id}',
                              'doc': json.dumps(doc, ensure_ascii=False)}])
        except Exception as e:                           # never lose the filing over its event
            self.log(f'intake: event not stored ({type(e).__name__})')

    def status(self):
        now = self.clock()
        with self.lock:
            st = dict(self.st)
        return {'intake': 'on', 'filed': st['filed'], 'duplicates': st['duplicates'], 'rejected': st['rejected'],
                'refused': st['refused'], 'failed': st['failed'], 'rate_limited': st['rate_limited'],
                'last_hour': sum(1 for t in st['recent'] if now - t < 3600), 'limit_per_hour': MAX_PER_HOUR,
                'last_filed': V.now_iso(st['last_filed']) if st.get('last_filed') else None,
                'queued': self.q.qsize(), 'albums_waiting': len(self.albums), 'busy': self.busy}
