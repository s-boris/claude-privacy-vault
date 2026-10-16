"""Home Assistant status feed, phase 2 (the vault tells the assistant about status changes in HA:
location, Android Auto, activity, ... coarse enough to place him roughly and tell what he is doing).

Runs INSIDE the vault, READ-ONLY toward Home Assistant:
- a stdlib websocket client that only ever sends the HA message types auth, get_states, subscribe_trigger (a `state`
  trigger on the allowlisted entities) and ping (HAConn.send refuses everything else: no call_service, no
  fire_event, no config writes); REST fallback = GET /api/states[/<allowlisted entity>] every 60 s while the
  websocket is down; reconnect backoff 5 s .. 5 min.
- allowlist by pattern on the owner's phone (VAULT_HA_DEVICE, like `alex_phone`; default: the person's GPS
  tracker updated last): person + device_tracker.<dev> + <dev>_{android_auto, detected_activity, sleep_confidence,
  sleep_segment, bluetooth_connection, wifi_connection, battery_level, battery_state, charger_type, next_alarm,
  phone_state, do_not_disturb_sensor, geocoded_location}; zones by name. A sensor the owner enables later in the
  Companion app is picked up at the next allowlist refresh (6 h, or a reconnect). Other people are never selected.
- coarsening in memory, nothing raw leaves this module: zone NAME or away + distance band from
  zone.home (near < 5 km, region 5-50 km, far > 50 km) + town (geocoded_location's Locality attribute only, owner OK
  15.10; never street, number or postcode; no geocoded sensor -> no town); drive start/end (+ minutes) from Android
  Auto; activity category; Bluetooth device CATEGORY (car, headphones, watch, speaker, other: never a name or MAC);
  Wi-Fi home/work/other/none (SSIDs only as HMACs, learned while in the Home/Work zone); likely asleep; next alarm
  (local minute); battery band + charging; on a call; do-not-disturb. No coordinates, SSIDs, names or addresses.
- debounce (zone 2 min, activity 5, Android Auto off 2, Bluetooth 2, Wi-Fi 3, sleep 5, alarm 1, battery 2) and a
  rate limit (<= 12 events/h, <= 4 per signal; the overflow is folded into the next allowed event: `collapsed`: N)
  before an event goes to the EventStore (source 'homeassistant', label = the signal; actionable = significant:
  a zone change, a drive start/end, going far or coming back from far).
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Europe/Zurich')
ALLOWED_TYPES = frozenset({'auth', 'get_states', 'subscribe_trigger', 'ping'})
SUFFIXES = {                                     # '<dev>_<suffix>' -> signal (sensor or binary_sensor)
    'android_auto': 'aa', 'detected_activity': 'activity', 'sleep_confidence': 'sleep',
    'sleep_segment': 'sleep_segment', 'bluetooth_connection': 'bt', 'wifi_connection': 'wifi',
    'battery_level': 'battery_level', 'battery_state': 'battery_state', 'charger_type': 'charger',
    'next_alarm': 'alarm', 'phone_state': 'phone', 'do_not_disturb_sensor': 'dnd', 'geocoded_location': 'geo'}
SIGNAL_DOMAINS = {'aa': 'binary_sensor'}         # all others: sensor
DEBOUNCE = {'zone': 120, 'drive_end': 120, 'activity': 300, 'bt': 120, 'wifi': 180, 'sleep': 300, 'alarm': 60,
            'battery': 120}
SIGNIFICANT = ('zone', 'drive')
RATE_TOTAL, RATE_SIGNAL, RATE_WINDOW = 12, 4, 3600
NEAR_KM, FAR_KM = 5, 50
BATTERY_LOW = 15
POLL_S, PING_S, PONG_WAIT_S, REFRESH_S = 60, 30, 20, 6 * 3600
BACKOFF_MIN, BACKOFF_MAX = 5, 300
MAX_MSG = 32 << 20
REST_PATH_RE = re.compile(r'/api/states(/[a-z_]+\.[a-z0-9_]+)?')
TOWN_RE = re.compile(r"[^\W\d_]+(?:[ .'\-]{1,2}[^\W\d_]+){0,5}")
WORK_ZONE_RE = re.compile(r'work|office|b(ü|ue)ro|arbeit|job', re.I)
ACTIVITY = {'in_vehicle': 'vehicle', 'on_bicycle': 'bicycle', 'on_foot': 'walking', 'walking': 'walking',
            'running': 'running', 'still': 'still'}
BT_CATEGORIES = (                                # first match wins; only the category ever leaves this module
    ('headphones', re.compile(r'buds|pods|headphone|headset|earbud|earphone|\bwh-|\bwf-|jabra|beats|momentum|'
                              r'\bqc ?\d|\bliberty|\bear ?\(|\bnothing ear\b|\bhd ?\d{3}\b', re.I)),
    ('watch', re.compile(r'watch|garmin|fitbit|forerunner|fenix|amazfit|\bband\b|whoop|\bpolar\b', re.I)),
    ('speaker', re.compile(r'speaker|soundlink|sonos|\becho\b|homepod|boombox|\bflip ?\d|\bcharge ?\d|\bboom\b|'
                           r'xtreme|marshall|soundbar|soundcore motion', re.I)),
    ('car', re.compile(r'\bcar\b|carkit|car ?kit|\bauto\b|\bvw\b|volkswagen|\bbmw\b|audi|mercedes|mbux|tesla|'
                       r'[sš]koda|\bseat\b|cupra|toyota|\bford\b|volvo|\bopel\b|renault|peugeot|hyundai|\bkia\b|'
                       r'mazda|nissan|honda|\bfiat\b|porsche|\bmini\b|uconnect|\bsync\b|hands-?free|polestar|'
                       r'\bbyd\b|lexus|subaru|suzuki|dacia|citro|\bjeep\b|land rover|jaguar|my ?car', re.I)),
)


class Forbidden(Exception):
    """A message or request this read-only client must never send."""


class AuthFailed(Exception):
    pass


class WSClosed(OSError):
    pass


# ============================================================================================ allowlist

def _obj(eid):
    return eid.split('.', 1)[1] if '.' in eid else eid


def _ts(v):
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return dt.datetime.fromisoformat(str(v).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None


def select(states, person_id, device=None):
    """-> {person, device, entities: {entity_id: signal}, zones: {entity_id: {name, lat, lon, radius}}} from a
    get_states list. Only the owner's person and ONE phone (device prefix); never another person's tracker."""
    by_id = {s.get('entity_id'): s for s in states if isinstance(s, dict) and isinstance(s.get('entity_id'), str)}
    me = by_id.get(person_id)
    if not me:
        return {'person': person_id, 'device': None, 'entities': {}, 'zones': {}}
    mine = [t for t in (me.get('attributes') or {}).get('device_trackers') or [] if isinstance(t, str)]
    others = set()
    for eid, s in by_id.items():
        if eid.startswith('person.') and eid != person_id:
            others.update(t for t in (s.get('attributes') or {}).get('device_trackers') or [] if isinstance(t, str))
    if device:
        dev = device if f'device_tracker.{device}' not in others else None
    else:                                        # the GPS tracker of his updated last (old phones go stale)
        cands = [t for t in mine if t not in others and t in by_id and (by_id[t].get('attributes') or {})
                 .get('source_type') in (None, 'gps') and by_id[t].get('state') not in ('unknown', 'unavailable')]
        cands.sort(key=lambda t: _ts(by_id[t].get('last_updated')) or 0)
        dev = _obj(cands[-1]) if cands else None
    ents = {person_id: 'person'}
    if dev:
        if f'device_tracker.{dev}' in by_id:
            ents[f'device_tracker.{dev}'] = 'tracker'
        for suffix, sig in SUFFIXES.items():
            eid = f"{SIGNAL_DOMAINS.get(sig, 'sensor')}.{dev}_{suffix}"
            if eid in by_id:
                ents[eid] = sig
    zones = {}
    for eid, s in by_id.items():
        if eid.startswith('zone.'):
            a = s.get('attributes') or {}
            if a.get('passive'):
                continue
            zones[eid] = {'name': str(a.get('friendly_name') or _obj(eid)), 'lat': a.get('latitude'),
                          'lon': a.get('longitude'), 'radius': a.get('radius') or 100}
    return {'person': person_id, 'device': dev, 'entities': ents, 'zones': zones}


# ============================================================================================ coarsening

def km_between(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(min(1.0, h)))


def band(km):
    return None if km is None else 'near' if km < NEAR_KM else 'region' if km <= FAR_KM else 'far'


def _coords(a):
    lat, lon = a.get('latitude'), a.get('longitude')
    return (lat, lon) if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) else None


def town(geo_attrs, net=lambda s: s):
    """geocoded_location's Locality (the town) only: never the state (a full address), street, number or postcode."""
    a = geo_attrs or {}
    v = a.get('Locality') if 'Locality' in a else a.get('locality')
    if not isinstance(v, str):
        return None
    v = ' '.join(v.split())
    if not v or len(v) > 40 or not TOWN_RE.fullmatch(v):
        return None
    return v if net(v) == v else None


def bt_categories(attrs):
    """Connected paired Bluetooth devices -> sorted categories; names and MACs never leave."""
    out = set()
    for d in (attrs or {}).get('connected_paired_devices') or []:
        if not isinstance(d, str):
            continue
        m = re.search(r'\((.*)\)\s*$', d)
        name = m.group(1) if m else re.sub(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\s*', '', d)
        out.add(next((c for c, rx in BT_CATEGORIES if rx.search(name)), 'other'))
    return sorted(out)


def local_minute(ts):
    return dt.datetime.fromtimestamp(ts, TZ).strftime('%Y-%m-%dT%H:%M') if ts is not None else None


class Feed:
    """The coarse state machine: observe(entity_id, state) as HA reports it, tick(now) commits debounced changes
    and writes events. Raw values stay in self.cur (memory only); snapshot() and events carry coarse values."""

    def __init__(self, events=None, net=lambda s: s, key=b'', wifi_path=None, clock=time.time, log=lambda m: None):
        self.events, self.net, self.key, self.clock, self.log = events, net, key or b'ha', clock, log
        self.wifi_path = Path(wifi_path) if wifi_path else None
        self.lock = threading.RLock()
        self.sel = {'entities': {}, 'zones': {}, 'device': None, 'person': None}
        self.cur = {}                             # signal -> HA state dict (raw, memory only)
        self.committed, self.pending = {}, {}     # signal -> value / (value, since)
        self.since = {}                           # signal -> epoch of the committed value
        self.drive_start = None
        self.sent = []                            # (ts, signal) of stored events, for the rate limit
        self.overflow = {}                        # signal -> {count, event, significant}
        self.counts = {'events': 0, 'collapsed': 0, 'observed': 0}
        self.last_msg = None
        self.wifi = self._load_wifi()
        self._wifi_seen = None                    # (hash, zone kind, since) for learning

    # ------------------------------------------------------------------ input
    def set_selection(self, sel):
        with self.lock:
            self.sel = sel
            for sig in list(self.cur):
                if sig not in sel['entities'].values():
                    self.cur.pop(sig, None)

    def observe_all(self, states, now=None):
        ents = self.sel['entities']
        with self.lock:
            for s in states:
                if isinstance(s, dict) and s.get('entity_id') in ents:
                    self._store(s)
            self._derive(now if now is not None else self.clock())

    def observe(self, eid, st, now=None):
        with self.lock:
            if eid not in self.sel['entities'] or not isinstance(st, dict):
                return
            self._store(dict(st, entity_id=eid))
            self._derive(now if now is not None else self.clock())

    def _store(self, s):
        self.cur[self.sel['entities'][s['entity_id']]] = {'state': str(s.get('state') or ''),
                                                           'attributes': s.get('attributes') or {},
                                                           'last_changed': _ts(s.get('last_changed')),
                                                           'last_updated': _ts(s.get('last_updated'))}
        self.counts['observed'] += 1
        self.last_msg = self.clock()

    def _val(self, sig):
        s = self.cur.get(sig)
        return None if s is None or s['state'] in ('unknown', 'unavailable', '') else s['state']

    # ------------------------------------------------------------------ derived (coarse) values
    def home_zone(self):
        return self.sel['zones'].get('zone.home')

    def place(self):
        """{kind: home|zone|away, zone, band, km_band_from: 'Home', town, flag: home|away|far, fix_age_min} or None."""
        tr = self.cur.get('tracker')
        src = tr if tr and tr['state'] not in ('unknown', 'unavailable', '') else self.cur.get('person')
        if not src or src['state'] in ('unknown', 'unavailable', ''):
            return None
        st, a = src['state'], src['attributes']
        names = {z['name']: z for z in self.sel['zones'].values()}
        home = self.home_zone()
        c = _coords(a)
        km = None
        if c and home and isinstance(home.get('lat'), (int, float)) and isinstance(home.get('lon'), (int, float)):
            km = km_between(c, (home['lat'], home['lon']))
        if st == 'home' or (st == 'not_home' and km is not None and km * 1000 <= float(home.get('radius') or 100)):
            kind, zone, b = 'home', self.net(home['name']) if home else 'Home', None
        elif st in names and st != 'not_home':
            kind, zone, b = 'zone', self.net(st), band(km)
        else:
            kind, zone, b = 'away', None, band(km)
        tw = None
        if kind == 'away' and 'geo' in self.cur and self.cur['geo']['state'] not in ('unknown', 'unavailable'):
            tw = town(self.cur['geo']['attributes'], self.net)
        upd = src.get('last_updated') or src.get('last_changed')
        return {'kind': kind, 'zone': zone, 'band': b, 'town': tw,
                'flag': 'home' if kind == 'home' else 'far' if b == 'far' else 'away',
                'fix_at': upd}

    def battery(self):
        lv = self._val('battery_level')
        try:
            level = int(round(float(lv) / 5.0) * 5) if lv is not None else None
        except ValueError:
            level = None
        bs, ch = self._val('battery_state'), self._val('charger')
        charging = None if bs is None and ch is None else (bs in ('charging', 'full') or ch not in (None, 'none'))
        if level is None and charging is None:
            return None
        return {'level': level, 'band': None if level is None else 'low' if level <= BATTERY_LOW else
                'mid' if level <= 50 else 'high', 'charging': charging,
                'charger': ch if ch in ('ac', 'usb', 'wireless', 'dock', 'none') else None}

    def wifi_class(self):
        w = self.cur.get('wifi')
        if w is None or w['state'] in ('unknown', 'unavailable'):
            return None
        ssid = w['state']
        if ssid in ('', '<not connected>') or 'not connected' in ssid.lower():
            return 'none'
        h = self._wifi_hash(ssid)
        return 'home' if h in self.wifi.get('home', []) else 'work' if h in self.wifi.get('work', []) else 'other'

    def sleep(self):
        v = self._val('sleep')
        try:
            c = float(v) if v is not None else None
        except ValueError:
            c = None
        if c is None:
            return None
        prev = self.committed.get('sleep')
        if c >= 85:
            return 'asleep'
        if c <= 50:
            return 'awake'
        return prev or 'awake'

    def last_sleep(self):
        s = self.cur.get('sleep_segment')
        if not s or s['state'] in ('unknown', 'unavailable', ''):
            return None
        try:
            hours = round(float(s['state']) / 3.6e6 * 2) / 2
        except ValueError:
            return None
        a = s['attributes']
        end = a.get('end') if 'end' in a else a.get('end_time')
        end_ts = (end / 1000.0 if isinstance(end, (int, float)) and end > 1e11 else _ts(end)) if end is not None \
            else s.get('last_changed')
        return {'hours': hours, 'ended': local_minute(end_ts) if end_ts else None}

    def activity(self):
        """still | walking | running | bicycle | vehicle; 'tilting' (and other odd values) keep the last one."""
        v = self._val('activity')
        if v is None:
            return None
        return ACTIVITY.get(v, self.committed.get('activity'))

    def alarm(self):
        v = self._val('alarm')
        t = _ts(v) if v else None
        return local_minute(t) if t else None

    def values(self, now):
        """signal -> the value whose changes make events (coarse)."""
        p = self.place()
        bat = self.battery()
        out = {'zone': (p['kind'], p['zone'], p['band']) if p else None,
               'drive': None if self._val('aa') is None else self._val('aa') == 'on',
               'activity': self.activity(),
               'bt': tuple(bt_categories(self.cur['bt']['attributes'])) if self._val('bt') is not None else None,
               'wifi': self.wifi_class(),
               'sleep': self.sleep(),
               'alarm': self.alarm(),
               'battery': None if not bat or bat['level'] is None or not p else
               'low' if bat['level'] <= BATTERY_LOW and not bat['charging'] and p['kind'] != 'home' else 'ok'}
        return out

    def _derive(self, now):
        vals = self.values(now)
        self._learn_wifi(now)
        for sig, v in vals.items():
            if v is None:
                continue
            if sig not in self.committed:        # baseline after start: no event
                self.committed[sig] = v
                self.since[sig] = self._baseline_since(sig, now)
                if sig == 'drive' and v:
                    self.drive_start = self.since[sig]
                continue
            if v == self.committed[sig]:
                self.pending.pop(sig, None)
                continue
            pv = self.pending.get(sig)
            if not pv or pv[0] != v:
                self.pending[sig] = (v, now)
        self.tick(now)

    def _baseline_since(self, sig, now):
        src = {'zone': 'tracker', 'drive': 'aa', 'activity': 'activity', 'bt': 'bt', 'wifi': 'wifi',
               'sleep': 'sleep', 'alarm': 'alarm', 'battery': 'battery_level'}.get(sig)
        s = self.cur.get(src) or (self.cur.get('person') if sig == 'zone' else None)
        return (s or {}).get('last_changed') or now

    def _delay(self, sig, v):
        if sig == 'drive':
            return 0 if v else DEBOUNCE['drive_end']
        return DEBOUNCE.get(sig, 120)

    # ------------------------------------------------------------------ commit, events, rate limit
    def tick(self, now=None):
        now = self.clock() if now is None else now
        with self.lock:
            for sig, (v, t0) in list(self.pending.items()):
                if now - t0 >= self._delay(sig, v):
                    self.pending.pop(sig, None)
                    old = self.committed.get(sig)
                    self.committed[sig], self.since[sig] = v, t0
                    ev = self._event(sig, old, v, t0)
                    if ev:
                        self._emit(sig, ev, now)
            for sig in list(self.overflow):
                self._flush(sig, now)

    def _event(self, sig, old, v, t0):
        """-> {label, ts, significant, data} with coarse values only, or None (no event for this change)."""
        if sig == 'zone':
            p = self.place() or {}
            ok, oz, ob = old if isinstance(old, tuple) else (None, None, None)
            k, z, b = v
            sig_change = (ok, oz) != (k, z) or ((ob == 'far') != (b == 'far'))
            data = {'place': k, 'zone': z, 'band': b, 'town': p.get('town') if k == 'away' else None,
                    'flag': 'home' if k == 'home' else 'far' if b == 'far' else 'away',
                    'from': {'place': ok, 'zone': oz, 'band': ob}}
            return {'label': 'zone', 'ts': t0, 'significant': sig_change, 'data': data}
        if sig == 'drive':
            if v:
                self.drive_start = t0
                return {'label': 'drive', 'ts': t0, 'significant': True, 'data': {'state': 'start'}}
            mins = round((t0 - self.drive_start) / 60) if self.drive_start else None
            self.drive_start = None
            return {'label': 'drive', 'ts': t0, 'significant': True, 'data': {'state': 'end', 'minutes': mins}}
        if sig == 'battery':
            if v != 'low':
                return None                       # only the "low while away" moment is news
            return {'label': 'battery', 'ts': t0, 'significant': False,
                    'data': {'low': True, 'level': (self.battery() or {}).get('level')}}
        if sig == 'bt':
            return {'label': 'bt', 'ts': t0, 'significant': False, 'data': {'connected': list(v)}}
        if sig == 'sleep':
            return {'label': 'sleep', 'ts': t0, 'significant': False, 'data': {'asleep': v == 'asleep'}}
        if sig == 'alarm':
            return {'label': 'alarm', 'ts': t0, 'significant': False, 'data': {'next': v}}
        return {'label': sig, 'ts': t0, 'significant': False, 'data': {'value': v}}

    def _allowed(self, sig, now):
        self.sent = [(t, s) for t, s in self.sent if now - t < RATE_WINDOW]
        return len(self.sent) < RATE_TOTAL and sum(1 for _, s in self.sent if s == sig) < RATE_SIGNAL

    def _emit(self, sig, ev, now):
        o = self.overflow.get(sig)
        if o:                                     # fold into the waiting overflow, keep the newest
            o['count'] += 1
            o['significant'] = o['significant'] or ev['significant']
            o['event'] = ev
            self.counts['collapsed'] += 1
            return
        if self._allowed(sig, now):
            self._store_event(sig, ev, now, 1)
        else:
            self.overflow[sig] = {'count': 1, 'significant': ev['significant'], 'event': ev}
            self.counts['collapsed'] += 1

    def _flush(self, sig, now):
        o = self.overflow.get(sig)
        if o and self._allowed(sig, now):
            ev = dict(o['event'], significant=o['significant'])
            self.overflow.pop(sig)
            self._store_event(sig, ev, now, o['count'])

    def _store_event(self, sig, ev, now, count):
        self.sent.append((now, sig))
        self.counts['events'] += 1
        data = dict(ev['data'], significant=bool(ev['significant']))
        if count > 1:
            data['collapsed'] = count
        if self.events is None:
            return
        try:
            self.events.add([{'source': 'homeassistant', 'ts': int(ev['ts']), 'chat_key': ev['label'],
                              'chat': 'Home Assistant', 'chat_type': 'status', 'label': ev['label'],
                              'actionable': int(bool(ev['significant'])), 'ref': f"ha:{ev['label']}",
                              'ha': json.dumps(data, ensure_ascii=False)}])
        except Exception as e:                    # never crash the listener over the store
            self.log(f'ha: event not stored ({type(e).__name__})')

    # ------------------------------------------------------------------ Wi-Fi classes (HMACs only)
    def _wifi_hash(self, ssid):
        return hmac.new(self.key, b'ha-wifi:' + ssid.encode('utf-8', 'replace'), hashlib.sha256).hexdigest()[:32]

    def _load_wifi(self):
        try:
            d = json.loads(self.wifi_path.read_text()) if self.wifi_path else {}
            return {k: [h for h in d.get(k, []) if isinstance(h, str)][:5] for k in ('home', 'work')}
        except (OSError, ValueError, AttributeError):
            return {'home': [], 'work': []}

    def _learn_wifi(self, now):
        """An SSID seen for 10 min while in the Home zone (or a zone named like work) is learned as home (work)."""
        w = self.cur.get('wifi')
        p = self.place()
        if not w or not p or w['state'] in ('unknown', 'unavailable', '', '<not connected>'):
            self._wifi_seen = None
            return
        cls = 'home' if p['kind'] == 'home' else 'work' if p['kind'] == 'zone' and WORK_ZONE_RE.search(
            p['zone'] or '') else None
        if not cls:
            self._wifi_seen = None
            return
        h = self._wifi_hash(w['state'])
        if h in self.wifi.get(cls, []):
            return
        if not self._wifi_seen or self._wifi_seen[:2] != (h, cls):
            self._wifi_seen = (h, cls, now)
            return
        if now - self._wifi_seen[2] >= 600:
            self.wifi[cls] = (self.wifi.get(cls, []) + [h])[-5:]
            self._wifi_seen = None
            if self.wifi_path:
                try:
                    tmp = self.wifi_path.with_suffix('.tmp')
                    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, 'w') as f:
                        json.dump(self.wifi, f)
                    os.replace(tmp, self.wifi_path)
                except OSError as e:
                    self.log(f'ha: wifi classes not saved ({type(e).__name__})')

    # ------------------------------------------------------------------ output
    def snapshot(self, now=None):
        now = self.clock() if now is None else now
        with self.lock:
            p = self.place()
            vals = self.values(now)
            fix = p.pop('fix_at') if p else None
            if p:
                p['since'] = _iso(self.since.get('zone')) if 'zone' in self.committed else None
                p['fix_age_min'] = round((now - fix) / 60) if fix else None
            drive = None
            if vals['drive'] is not None:
                st = self.drive_start if self.committed.get('drive') else None
                drive = {'active': bool(vals['drive']), 'since': _iso(st),
                         'minutes': round((now - st) / 60) if st else None}
            ph, dnd = self._val('phone'), self._val('dnd')
            return {
                'device': self.sel.get('device'), 'place': p, 'drive': drive, 'activity': vals['activity'],
                'bluetooth': list(vals['bt']) if vals['bt'] is not None else None, 'wifi': vals['wifi'],
                'sleep': vals['sleep'], 'last_sleep': self.last_sleep(), 'alarm': vals['alarm'],
                'battery': self.battery(), 'on_call': None if ph is None else ph == 'offhook',
                'dnd': None if dnd is None else dnd != 'off',
                'signals': sorted(set(self.sel['entities'].values()) - {'person'}),
                'pending': sorted(self.pending), 'last_update': _iso(self.last_msg),
                'age_min': round((now - self.last_msg) / 60) if self.last_msg else None,
                'counts': dict(self.counts),
            }


def _iso(ts):
    return dt.datetime.fromtimestamp(ts, TZ).isoformat(timespec='seconds') if ts else None


# ============================================================================================ websocket (stdlib)

class WS:
    """A minimal RFC 6455 client: text frames out (masked), text/continuation/ping/pong/close in."""
    GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    def __init__(self, sock, buf=b''):
        self.sock, self.buf, self.parts, self.closed = sock, buf, [], False
        self.lock = threading.Lock()

    @classmethod
    def connect(cls, url, timeout=10):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ('ws', 'wss'):
            raise ValueError('websocket url must be ws:// or wss://')
        port = u.port or (443 if u.scheme == 'wss' else 80)
        sock = socket.create_connection((u.hostname, port), timeout=timeout)
        try:
            if u.scheme == 'wss':
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
            key = base64.b64encode(os.urandom(16))
            host = u.hostname + (f':{u.port}' if u.port else '')
            req = (f'GET {u.path or "/"} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key.decode()}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode()
            sock.sendall(req)
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    raise WSClosed('closed during the handshake')
                data += chunk
                if len(data) > 16384:
                    raise ValueError('handshake response too large')
            head, rest = data.split(b'\r\n\r\n', 1)
            lines = head.decode('latin-1').split('\r\n')
            if not re.match(r'HTTP/1\.1 101\b', lines[0]):
                raise WSClosed(f'handshake refused ({lines[0][:40]})')
            hdr = {k.strip().lower(): v.strip() for k, v in (ln.split(':', 1) for ln in lines[1:] if ':' in ln)}
            want = base64.b64encode(hashlib.sha1(key + cls.GUID).digest()).decode()
            if hdr.get('sec-websocket-accept') != want:
                raise WSClosed('bad Sec-WebSocket-Accept')
            return cls(sock, rest)
        except BaseException:
            sock.close()
            raise

    def _frame(self, opcode, payload):
        n = len(payload)
        head = bytes([0x80 | opcode])
        head += bytes([0x80 | n]) if n < 126 else (bytes([0x80 | 126]) + struct.pack('>H', n) if n < 65536 else
                                                   bytes([0x80 | 127]) + struct.pack('>Q', n))
        mask = os.urandom(4)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self.lock:
            self.sock.sendall(head + mask + body)

    def _send_text(self, text):                  # only HAConn.send calls this (test-enforced)
        self._frame(0x1, text.encode('utf-8'))

    def _read(self, n, timeout):
        self.sock.settimeout(timeout)
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise WSClosed('connection closed')
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self, timeout=1.0):
        """-> one text message, or None when nothing arrived within `timeout`."""
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            if not self.buf:
                try:
                    self.sock.settimeout(left)
                    chunk = self.sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    return None
                if not chunk:
                    raise WSClosed('connection closed')
                self.buf += chunk
            b0, b1 = self._read(2, 15)
            op, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack('>H', self._read(2, 15))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._read(8, 15))[0]
            if n > MAX_MSG:
                raise WSClosed('message too large')
            mask = self._read(4, 15) if b1 & 0x80 else None
            data = self._read(n, 60) if n else b''
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x9:                         # ping -> pong (a websocket control frame, not an HA message)
                self._frame(0xA, data[:125])
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                self.closed = True
                raise WSClosed('closed by Home Assistant')
            if op in (0x1, 0x0, 0x2):
                self.parts.append(data)
                if sum(len(p) for p in self.parts) > MAX_MSG:
                    raise WSClosed('message too large')
                if b0 & 0x80:
                    msg, self.parts = b''.join(self.parts), []
                    return msg.decode('utf-8', 'replace')

    def close(self):
        try:
            if not self.closed:
                self._frame(0x8, b'\x03\xe8')
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class HAConn:
    """The only way a message reaches Home Assistant. Read-only by construction: ALLOWED_TYPES, a `state` trigger on
    allowlisted entities only, auth with nothing but the token."""

    def __init__(self, ws, allow=lambda eid: False):
        self.ws, self.allow, self.next_id = ws, allow, 1
        self.sent_types = []

    @staticmethod
    def check(msg, allow):
        if not isinstance(msg, dict):
            raise Forbidden('not a message object')
        t = msg.get('type')
        if t not in ALLOWED_TYPES:
            raise Forbidden(f'message type {t!r} is not allowed (read-only client)')
        keys = set(msg) - {'type', 'id'}
        if t == 'auth':
            if keys != {'access_token'}:
                raise Forbidden('auth carries only the token')
        elif t in ('get_states', 'ping'):
            if keys:
                raise Forbidden(f'{t} takes no parameters')
        else:
            if keys != {'trigger'} or not isinstance(msg['trigger'], dict):
                raise Forbidden('subscribe_trigger takes one trigger')
            trig = msg['trigger']
            if set(trig) != {'platform', 'entity_id'} and set(trig) != {'trigger', 'entity_id'}:
                raise Forbidden('only a plain state trigger')
            if trig.get('platform', trig.get('trigger')) != 'state':
                raise Forbidden('only a state trigger')
            ids = trig['entity_id'] if isinstance(trig['entity_id'], list) else [trig['entity_id']]
            if not ids or not all(isinstance(e, str) and allow(e) for e in ids):
                raise Forbidden('trigger on an entity outside the allowlist')

    def send(self, msg):
        msg = dict(msg)
        if msg.get('type') != 'auth':
            msg['id'] = self.next_id
            self.next_id += 1
        self.check(msg, self.allow)
        self.sent_types.append(msg['type'])
        self.ws._send_text(json.dumps(msg))
        return msg.get('id')


# ============================================================================================ the listener

class HALive:
    """Thread: websocket subscription (REST poll fallback), feeding a Feed. VAULT_HA_FEED=1 turns it on."""

    def __init__(self, cfg, store, events, net=lambda s: s, key=b'', audit=None, alert=None, log=lambda m: None,
                 clock=time.time):
        env = cfg.env
        self.enabled = env.get('VAULT_HA_FEED') == '1'
        self.device = (env.get('VAULT_HA_DEVICE') or '').strip() or None
        self.store, self.audit, self.alert, self.log, self.clock = store, audit, alert, log, clock
        self.feed = Feed(events, net=net, key=key, wifi_path=cfg.state / 'ha-wifi.json', clock=clock, log=log)
        self.state = 'off' if not self.enabled else 'starting'
        self.error = None
        self.connected_since = None
        self.last_poll = None
        self.reconnects = 0
        self.sub_count = 0
        self.wake = threading.Event()

    # ------------------------------------------------------------------ helpers
    def secret(self):
        if not self.store.is_set('homeassistant'):
            return None
        return self.store.get('homeassistant')

    def allow(self, eid):
        return eid in self.feed.sel['entities']

    def rest_get(self, sec, path, timeout=15):
        """GET only, and only /api/states or /api/states/<allowlisted entity>."""
        if not REST_PATH_RE.fullmatch(path):
            raise Forbidden(f'REST path not allowed: {path}')
        if path != '/api/states' and not self.allow(path.rsplit('/', 1)[1]):
            raise Forbidden('REST entity outside the allowlist')
        req = urllib.request.Request(sec['url'].rstrip('/') + path, method='GET',
                                     headers={'Authorization': 'Bearer ' + sec['token']})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as r:
            return json.loads(r.read(32 << 20).decode('utf-8'))

    def apply_states(self, sec, states):
        sel = select(states if isinstance(states, list) else [], sec.get('person') or '', self.device)
        changed = set(sel['entities']) != set(self.feed.sel['entities'])
        self.feed.set_selection(sel)
        self.feed.observe_all(states)
        return sel, changed

    def ws_url(self, sec):
        u = urllib.parse.urlsplit(sec['url'].rstrip('/'))
        return urllib.parse.urlunsplit(('wss' if u.scheme == 'https' else 'ws', u.netloc,
                                        u.path.rstrip('/') + '/api/websocket', '', ''))

    # ------------------------------------------------------------------ websocket session
    def session(self, sec, stop):
        ws = WS.connect(self.ws_url(sec), timeout=10)
        try:
            conn = HAConn(ws, self.allow)
            first = self._wait(ws, lambda m: m.get('type') in ('auth_required', 'auth_ok'), 15)
            if first.get('type') == 'auth_required':
                conn.send({'type': 'auth', 'access_token': sec['token']})
                r = self._wait(ws, lambda m: m.get('type') in ('auth_ok', 'auth_invalid'), 15)
                if r.get('type') != 'auth_ok':
                    raise AuthFailed('token refused')
            i = conn.send({'type': 'get_states'})
            res = self._wait(ws, lambda m: m.get('id') == i and m.get('type') == 'result', 60)
            if not res.get('success'):
                raise WSClosed('get_states failed')
            sel, _ = self.apply_states(sec, res.get('result'))
            ids = sorted(sel['entities'])
            sub = None
            for key in ('platform', 'trigger'):  # HA >= 2024.10 also takes "trigger"
                sub = conn.send({'type': 'subscribe_trigger', 'trigger': {key: 'state', 'entity_id': ids}})
                r = self._wait(ws, lambda m, s=sub: m.get('id') == s and m.get('type') == 'result', 30)
                if r.get('success'):
                    break
                sub = None
            if sub is None:
                raise WSClosed('subscribe_trigger refused')
            self.sub_count = len(ids)
            self.state, self.error, self.connected_since = 'websocket', None, self.clock()
            self.log(f'ha: websocket connected, {len(ids)} entities subscribed (device {sel["device"] or "none"})')
            if self.audit:
                self.audit.log('ha_connected', entities=len(ids))
            last_ping, ping_id, ping_at, refresh_at = time.monotonic(), None, None, time.monotonic() + REFRESH_S
            while not stop.is_set():
                raw = ws.recv(1.0)
                if raw is not None:
                    for m in self._decode(raw):
                        if m.get('type') == 'event' and m.get('id') == sub:
                            trig = ((m.get('event') or {}).get('variables') or {}).get('trigger') or {}
                            eid, to = trig.get('entity_id'), trig.get('to_state')
                            if isinstance(eid, str) and isinstance(to, dict):
                                self.feed.observe(eid, to)
                        elif m.get('type') == 'pong' and m.get('id') == ping_id:
                            ping_id = ping_at = None
                self.feed.tick()
                mono = time.monotonic()
                if ping_id is not None and mono - ping_at > PONG_WAIT_S:
                    raise WSClosed('no pong from Home Assistant')
                if ping_id is None and mono - last_ping >= PING_S:
                    ping_id, ping_at, last_ping = conn.send({'type': 'ping'}), mono, mono
                if mono >= refresh_at or self.wake.is_set():
                    self.wake.clear()
                    i = conn.send({'type': 'get_states'})
                    res = self._wait(ws, lambda m: m.get('id') == i and m.get('type') == 'result', 60,
                                     on_other=lambda m: self._side(m, sub))
                    refresh_at = mono + REFRESH_S
                    if res.get('success'):
                        _, changed = self.apply_states(sec, res.get('result'))
                        if changed:
                            self.log('ha: allowlist changed, resubscribing')
                            return
        finally:
            ws.close()

    def _side(self, m, sub):
        if m.get('type') == 'event' and m.get('id') == sub:
            trig = ((m.get('event') or {}).get('variables') or {}).get('trigger') or {}
            if isinstance(trig.get('entity_id'), str) and isinstance(trig.get('to_state'), dict):
                self.feed.observe(trig['entity_id'], trig['to_state'])

    @staticmethod
    def _decode(raw):
        try:
            m = json.loads(raw)
        except ValueError:
            return []
        return [x for x in (m if isinstance(m, list) else [m]) if isinstance(x, dict)]

    def _wait(self, ws, pred, timeout, on_other=None):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            raw = ws.recv(min(1.0, max(0.05, end - time.monotonic())))
            if raw is None:
                continue
            for m in self._decode(raw):
                if pred(m):
                    return m
                if on_other:
                    on_other(m)
        raise WSClosed('Home Assistant did not answer in time')

    # ------------------------------------------------------------------ REST fallback
    def poll(self, sec):
        if not self.feed.sel['entities'] or self.last_poll is None or self.clock() - self.last_poll > REFRESH_S:
            self.apply_states(sec, self.rest_get(sec, '/api/states', timeout=30))
        else:
            for eid in sorted(self.feed.sel['entities']):
                st = self.rest_get(sec, '/api/states/' + eid)
                self.feed.observe(eid, st)
        self.last_poll = self.clock()

    # ------------------------------------------------------------------ main loop
    def run(self, stop):
        if not self.enabled:
            return
        backoff, next_poll, auth_fail = BACKOFF_MIN, 0.0, 0
        while not stop.is_set():
            sec = self.secret()
            if not sec:
                self.state = 'not_configured'
                stop.wait(300)
                continue
            try:
                self.state = 'connecting'
                self.session(sec, stop)
                backoff, auth_fail = BACKOFF_MIN, 0
                continue
            except AuthFailed:
                auth_fail += 1
                self.state, self.error = 'auth_failed', 'Home Assistant refused the token'
                if self.alert and auth_fail == 1:
                    self.alert('ha-auth', 'Home Assistant refused the vault\'s token',
                               'The HA status feed is paused; the owner may need to renew the long-lived token '
                               '(vault secret rotate homeassistant).')
                stop.wait(1800)
                continue
            except Forbidden as e:               # a bug, never an HA problem: stop rather than send it
                self.state, self.error = 'stopped', f'refused to send: {e}'
                self.log(f'ha: {self.error}')
                return
            except (OSError, ValueError, KeyError, TypeError) as e:
                self.error = type(e).__name__ + (f': {e}' if isinstance(e, (WSClosed, ValueError)) else '')
                self.reconnects += 1
                self.connected_since = None
                self.log(f'ha: websocket down ({self.error[:120]}); retry in {backoff} s, REST poll meanwhile')
            self.state = 'polling'
            end = time.monotonic() + backoff
            while not stop.is_set() and time.monotonic() < end:
                if time.monotonic() >= next_poll:
                    try:
                        self.poll(sec)
                        self.state = 'polling'
                    except Forbidden as e:
                        self.state, self.error = 'stopped', f'refused to send: {e}'
                        return
                    except (OSError, ValueError, KeyError, TypeError) as e:
                        self.state = 'unreachable'
                        self.error = f'REST: {type(e).__name__}'
                    next_poll = time.monotonic() + POLL_S
                self.feed.tick()
                stop.wait(1.0)
            backoff = min(backoff * 2, BACKOFF_MAX)

    def status(self):
        return {'feed': 'on' if self.enabled else 'off', 'state': self.state, 'error': self.error,
                'connected_since': _iso(self.connected_since), 'subscribed': self.sub_count,
                'reconnects': self.reconnects, 'last_poll': _iso(self.last_poll), 'device': self.feed.sel.get('device')}

    def now(self):
        out = self.feed.snapshot()
        out['connection'] = self.status()
        return out
