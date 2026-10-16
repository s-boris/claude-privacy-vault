"""Home Assistant inventory, metadata only (phase 1 of the owner's HA status-change feed).

Runs INSIDE the vault on GET /api/states and returns, for the owner's phone only: entity_id, domain, device_class,
unit, friendly name (regex-netted) and the KIND of state (on/off, number, timestamp, zone, slug, text, ...).
Never a state value, an attribute value, coordinates, an SSID, an address or a Bluetooth device name: attributes come
out as key names only. Other people's person.* entities and their trackers are excluded. Zones: names only.
"""
import re

ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}')
NUM_RE = re.compile(r'-?\d+(\.\d+)?')
SLUG_RE = re.compile(r'[a-z0-9_]{1,30}')
# states whose VALUE is private even as a kind hint ("slug" could be an SSID or an app name): kind says so instead
SENSITIVE = (('wifi_connection', 'SSID'), ('wifi_bssid', 'BSSID'), ('ip_address', 'IP'), ('ip6_addresses', 'IP'),
             ('public_ip', 'IP'), ('geocoded_location', 'address'), ('last_notification', 'notification text'),
             ('last_removed_notification', 'notification text'), ('media_session', 'media title'),
             ('last_used_app', 'app name'), ('car_name', 'car name'), ('sim_', 'carrier'), ('beacon', 'beacon ids'))
CANDIDATES = re.compile(r'android_auto|detected_activity|activity|charger_type|is_charging|battery_state|wifi_connection|'
                        r'bluetooth_connection|next_alarm|sleep|steps|interactive|do_not_disturb|ringer_mode|'
                        r'headphones|music_active|phone_state|geocoded_location|car_|network_type|power_save')
COORD_KEYS = {'latitude', 'longitude', 'gps_accuracy', 'altitude', 'course', 'speed', 'vertical_accuracy'}
MAX = 400


def _obj(eid):
    return eid.split('.', 1)[1] if '.' in eid else eid


def state_kind(eid, state, attrs, zones):
    """The kind of value this entity holds, computed from the value without returning it."""
    obj = _obj(eid)
    for frag, what in SENSITIVE:
        if frag in obj:
            return f'masked text ({what})'
    if state in ('unavailable', 'unknown'):
        return state
    dom = eid.split('.', 1)[0]
    if dom in ('person', 'device_tracker'):
        return 'zone name | home | not_home'
    if dom == 'zone':
        return 'count of persons in zone'
    if dom == 'binary_sensor' or state in ('on', 'off'):
        return 'on/off'
    if NUM_RE.fullmatch(state or ''):
        return 'number'
    if ISO_RE.match(state or ''):
        return 'timestamp'
    if attrs.get('device_class') == 'enum' and isinstance(attrs.get('options'), list):
        opts = [o for o in attrs['options'] if isinstance(o, str) and SLUG_RE.fullmatch(o)]
        return f"enum ({', '.join(opts[:12])})" if len(opts) == len(attrs['options']) else f"enum ({len(attrs['options'])} options)"
    if state in zones:
        return 'zone name'
    return 'slug' if SLUG_RE.fullmatch(state or '') else 'text'


def attr_keys(attrs):
    keys = sorted(k for k in attrs if k not in ('friendly_name', 'device_class', 'unit_of_measurement', 'icon'))
    out = [('coordinates' if k in COORD_KEYS else k) for k in keys]
    return sorted(set(out))[:30]


def inventory(states, person_id, net=lambda s: s):
    """states = HA GET /api/states (list). -> {owner_trackers, zones, entities, excluded_people, counts}."""
    by_id = {s.get('entity_id'): s for s in states if isinstance(s, dict) and isinstance(s.get('entity_id'), str)}
    me = by_id.get(person_id) or {}
    mine = [t for t in (me.get('attributes') or {}).get('device_trackers') or [] if isinstance(t, str)]
    others = set()
    for eid, s in by_id.items():
        if eid.startswith('person.') and eid != person_id:
            others.update(t for t in (s.get('attributes') or {}).get('device_trackers') or [] if isinstance(t, str))
    my_prefixes = {_obj(t) + '_' for t in mine}
    my_names = {str((by_id.get(t) or {}).get('attributes', {}).get('friendly_name') or '') for t in mine} - {''}
    other_prefixes = {_obj(t) + '_' for t in others}
    zones = {}
    for eid, s in by_id.items():
        if eid.startswith('zone.'):
            zones[eid] = str((s.get('attributes') or {}).get('friendly_name') or _obj(eid))
    zone_states = set(zones.values()) | {'home', 'not_home'}

    def owner_of(eid, attrs):
        obj, fn = _obj(eid), str(attrs.get('friendly_name') or '')
        if eid == person_id or eid in mine or any(obj.startswith(p) for p in my_prefixes) \
                or any(n and fn.startswith(n + ' ') for n in my_names):
            return 'owner'
        if eid.startswith('person.') or eid in others or any(obj.startswith(p) for p in other_prefixes):
            return 'other'
        return 'unattributed' if CANDIDATES.search(obj) and eid.split('.', 1)[0] in ('sensor', 'binary_sensor') else None

    ents, excluded = [], 0
    for eid in sorted(by_id):
        s = by_id[eid]
        attrs = s.get('attributes') or {}
        who = owner_of(eid, attrs)
        if who == 'other':
            excluded += 1
            continue
        if who is None or eid.startswith('zone.'):
            continue
        ents.append({'entity_id': eid, 'domain': eid.split('.', 1)[0], 'device_class': attrs.get('device_class'),
                     'unit': attrs.get('unit_of_measurement'), 'friendly_name': net(str(attrs.get('friendly_name') or '')),
                     'kind': state_kind(eid, str(s.get('state') or ''), attrs, zone_states),
                     'attr_keys': attr_keys(attrs), 'owner': who})
        if len(ents) >= MAX:
            break
    return {'person': person_id, 'owner_trackers': mine, 'zones': sorted(net(z) for z in zones.values()),
            'entities': ents, 'excluded_other_people': excluded,
            'counts': {'states': len(by_id), 'owner': sum(e['owner'] == 'owner' for e in ents),
                       'unattributed': sum(e['owner'] == 'unattributed' for e in ents)}}
