"""app/ha_live.py: the HA status feed (phase 2). Invented fixtures only (no real coordinates, SSIDs,
device names or addresses). Covers: allowlist by device prefix, coarsening (zone/band/town, BT categories, Wi-Fi
classes), debounce + rate limit, events, the read-only message guard (call_service etc. can never be sent), and an
end-to-end run against a fake HA websocket server with the REST fallback and reconnect."""
import ast
import base64
import hashlib
import http.server
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'app'))
import ha_live as H  # noqa: E402
import vaultlib as V  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix='ha-live-test-'))
HOME = (12.5, 33.25)                                  # invented
SECRET_VALUES = ['12.5', '33.25', '12.51', '12.7', '13.6', 'FakeNet-Home', 'FakeNet-Cafe', 'Pixel Buds Fake',
                 'AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02', 'AA:BB:CC:DD:EE:03', 'Testgasse', '9999', 'TestCar 3000',
                 'Watchy Fake', 'Hi from Testperson', 'com.fake.clock', 'Partner']


def st(eid, state, ts=None, **attrs):
    t = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(ts or 1_760_000_000))
    return {'entity_id': eid, 'state': state, 'attributes': attrs, 'last_changed': t, 'last_updated': t}


def states(person='home', lat=HOME[0], lon=HOME[1], extra=()):
    out = [
        st('person.owner', person, device_trackers=['device_tracker.owner_phone_new', 'device_tracker.owner_old'],
           latitude=lat, longitude=lon, friendly_name='Owner'),
        st('person.partner', 'home', device_trackers=['device_tracker.partner_phone'], friendly_name='Partner'),
        st('device_tracker.owner_phone_new', person, latitude=lat, longitude=lon, gps_accuracy=10, source_type='gps',
           friendly_name='Owner Phone New', ts=1_760_000_100),
        st('device_tracker.owner_old', 'not_home', latitude=13.6, longitude=33.25, source_type='gps', ts=1_700_000_000),
        st('device_tracker.partner_phone', 'home', latitude=HOME[0], longitude=HOME[1], source_type='gps',
           ts=1_760_000_200),
        st('zone.home', '1', latitude=HOME[0], longitude=HOME[1], radius=100, friendly_name='Home'),
        st('zone.work', '0', latitude=12.7, longitude=33.25, radius=200, friendly_name='Work'),
        st('binary_sensor.owner_phone_new_android_auto', 'off', connection_type='none'),
        st('sensor.owner_phone_new_battery_level', '83', unit_of_measurement='%'),
        st('sensor.owner_phone_new_battery_state', 'discharging'),
        st('sensor.owner_phone_new_charger_type', 'none'),
        st('sensor.owner_phone_new_next_alarm', '2026-10-16T04:30:00+00:00', Package='com.fake.clock'),
        st('sensor.owner_phone_new_detected_activity', 'still'),
        st('sensor.owner_phone_new_sleep_confidence', '10'),
        st('sensor.owner_phone_new_bluetooth_connection', '0', connected_paired_devices=[],
           paired_devices=['AA:BB:CC:DD:EE:01 (Pixel Buds Fake)', 'AA:BB:CC:DD:EE:02 (TestCar 3000)']),
        st('sensor.owner_old_battery_level', '5'),
        st('binary_sensor.partner_phone_android_auto', 'on'),
        st('sensor.partner_phone_wifi_connection', 'FakeNet-Home'),
        st('sensor.owner_phone_new_last_notification', 'Hi from Testperson'),
        st('light.kitchen', 'on'),
    ]
    return out + list(extra)


class Clock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeStore:
    def __init__(self):
        self.added = []

    def add(self, rows):
        self.added.extend(rows)


def make_feed(sts=None, device='owner_phone_new', clock=None, store=None, net=lambda s: s):
    clock = clock or Clock()
    f = H.Feed(store if store is not None else FakeStore(), net=net, key=b'k', clock=clock)
    sts = sts or states()
    f.set_selection(H.select(sts, 'person.owner', device))
    f.observe_all(sts)
    return f, clock


def obs(f, eid, state, clock, **attrs):
    f.observe(eid, {'state': state, 'attributes': attrs, 'last_changed': None, 'last_updated': None})


class SelectTests(unittest.TestCase):
    def test_prefix_allowlist_and_others_excluded(self):
        s = H.select(states(), 'person.owner', 'owner_phone_new')
        self.assertEqual(s['device'], 'owner_phone_new')
        ents = s['entities']
        self.assertEqual(ents['person.owner'], 'person')
        self.assertEqual(ents['device_tracker.owner_phone_new'], 'tracker')
        self.assertEqual(ents['binary_sensor.owner_phone_new_android_auto'], 'aa')
        self.assertEqual(ents['sensor.owner_phone_new_bluetooth_connection'], 'bt')
        for eid in ents:
            self.assertNotIn('partner', eid)
            self.assertNotIn('owner_old', eid)
            self.assertNotIn('last_notification', eid)
            self.assertNotEqual(eid, 'light.kitchen')
        self.assertEqual(sorted(z['name'] for z in s['zones'].values()), ['Home', 'Work'])

    def test_sensors_enabled_later_are_picked_up(self):
        more = [st('sensor.owner_phone_new_wifi_connection', 'FakeNet-Home'),
                st('sensor.owner_phone_new_sleep_segment', '27000000'),
                st('sensor.owner_phone_new_geocoded_location', 'Testgasse 7, 9999 Testdorf', Locality='Testdorf'),
                st('sensor.owner_phone_new_phone_state', 'idle'),
                st('sensor.owner_phone_new_do_not_disturb_sensor', 'off')]
        ents = H.select(states(extra=more), 'person.owner', 'owner_phone_new')['entities']
        for sig in ('wifi', 'sleep_segment', 'geo', 'phone', 'dnd'):
            self.assertIn(sig, ents.values())

    def test_another_persons_device_is_refused(self):
        s = H.select(states(), 'person.owner', 'partner_phone')
        self.assertIsNone(s['device'])
        self.assertEqual(s['entities'], {'person.owner': 'person'})

    def test_default_device_is_the_newest_gps_tracker(self):
        self.assertEqual(H.select(states(), 'person.owner')['device'], 'owner_phone_new')

    def test_unknown_person(self):
        self.assertEqual(H.select(states(), 'person.nobody')['entities'], {})

    def test_missing_device_setting_never_widens(self):
        # S9: VAULT_HA_DEVICE comes from the server's .env; unset or blank -> no device, so select() takes the
        # person's own newest GPS tracker: never another person's, never more than the explicit phone gives
        for env in ({'VAULT_HA_FEED': '1'}, {'VAULT_HA_FEED': '1', 'VAULT_HA_DEVICE': '  '}):
            cfg = type('C', (), {'env': env, 'state': TMP})()
            live = H.HALive(cfg, Secrets('http://127.0.0.1:9', 'good'), FakeStore(), key=b'k', alert=lambda *a, **k: None)
            self.assertIsNone(live.device)
        dflt = H.select(states(), 'person.owner', None)['entities']
        explicit = H.select(states(), 'person.owner', 'owner_phone_new')['entities']
        self.assertLessEqual(set(dflt), set(explicit))
        self.assertFalse(any('partner' in e or 'owner_old' in e for e in dflt))


class CoarseTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(H.band(1.2), 'near')
        self.assertEqual(H.band(22), 'region')
        self.assertEqual(H.band(111), 'far')
        self.assertIsNone(H.band(None))

    def test_town_only_from_locality(self):
        self.assertEqual(H.town({'Locality': 'Testdorf', 'Thoroughfare': 'Testgasse', 'Postal Code': '9999'}), 'Testdorf')
        self.assertEqual(H.town({'Locality': 'Saint-Test am See'}), 'Saint-Test am See')
        for bad in ('Testgasse 7', '9999 Testdorf', '', 'x' * 41, None, 42):
            self.assertIsNone(H.town({'Locality': bad}), bad)
        self.assertIsNone(H.town({'Thoroughfare': 'Testgasse'}))
        self.assertIsNone(H.town({'Locality': 'Testdorf'}, net=lambda s: '[masked]'))

    def test_bt_categories_never_names(self):
        cats = H.bt_categories({'connected_paired_devices': [
            'AA:BB:CC:DD:EE:01 (Pixel Buds Fake)', 'AA:BB:CC:DD:EE:02 (TestCar 3000)', 'AA:BB:CC:DD:EE:03 (Watchy Fake)',
            'AA:BB:CC:DD:EE:04 (JBL Flip 6)', 'AA:BB:CC:DD:EE:05 (VW Golf)', 'AA:BB:CC:DD:EE:06 (Thing 42)']})
        self.assertEqual(cats, ['car', 'headphones', 'other', 'speaker', 'watch'])
        self.assertEqual(H.bt_categories({'connected_paired_devices': ['AA:BB:CC:DD:EE:07 (Galaxy Buds3 Pro)']}),
                         ['headphones'])
        self.assertEqual(H.bt_categories({}), [])

    def test_place_home_zone_away(self):
        f, _ = make_feed()
        self.assertEqual(f.place()['kind'], 'home')
        f, _ = make_feed(states('Work', 12.7, 33.25))
        p = f.place()
        self.assertEqual((p['kind'], p['zone'], p['band'], p['flag']), ('zone', 'Work', 'region', 'away'))
        f, _ = make_feed(states('not_home', 12.51, 33.25))
        p = f.place()
        self.assertEqual((p['kind'], p['zone'], p['band'], p['town'], p['flag']), ('away', None, 'near', None, 'away'))
        f, _ = make_feed(states('not_home', 13.6, 33.25))
        self.assertEqual(f.place()['flag'], 'far')
        f, _ = make_feed(states('not_home', 12.5001, 33.25))   # inside the home radius, HA not caught up yet
        self.assertEqual(f.place()['kind'], 'home')

    def test_town_only_outside_zones(self):
        geo = st('sensor.owner_phone_new_geocoded_location', 'Testgasse 7, 9999 Testdorf', Locality='Testdorf',
                 Thoroughfare='Testgasse')
        f, _ = make_feed(states('not_home', 12.7, 33.5, extra=[geo]))
        self.assertEqual(f.place()['town'], 'Testdorf')
        f, _ = make_feed(states('home', extra=[geo]))
        self.assertIsNone(f.place()['town'])
        f, _ = make_feed(states('not_home', 12.7, 33.5))       # no geocoded sensor: distance band only
        self.assertIsNone(f.place()['town'])
        self.assertEqual(f.place()['band'], 'region')

    def test_snapshot_never_leaks(self):
        more = [st('sensor.owner_phone_new_wifi_connection', 'FakeNet-Cafe'),
                st('sensor.owner_phone_new_geocoded_location', 'Testgasse 7, 9999 Testdorf', Locality='Testdorf',
                   Thoroughfare='Testgasse', **{'Postal Code': '9999'}),
                st('sensor.owner_phone_new_phone_state', 'offhook'),
                st('sensor.owner_phone_new_do_not_disturb_sensor', 'priority_only')]
        f, c = make_feed(states('not_home', 12.7, 33.5, extra=more))
        obs(f, 'sensor.owner_phone_new_bluetooth_connection', '3', c, connected_paired_devices=[
            'AA:BB:CC:DD:EE:01 (Pixel Buds Fake)', 'AA:BB:CC:DD:EE:02 (TestCar 3000)',
            'AA:BB:CC:DD:EE:03 (Watchy Fake)'])
        snap = f.snapshot()
        blob = json.dumps(snap)
        for v in SECRET_VALUES:
            self.assertNotIn(v, blob, v)
        self.assertEqual(snap['bluetooth'], ['headphones', 'other', 'watch'])     # 'TestCar 3000': no car word
        self.assertEqual(snap['wifi'], 'other')
        self.assertEqual((snap['on_call'], snap['dnd']), (True, True))
        self.assertEqual(snap['place']['town'], 'Testdorf')
        self.assertEqual(snap['alarm'], '2026-10-16T06:30')                      # local minute (Zurich, CEST)
        self.assertEqual(snap['battery'], {'level': 85, 'band': 'high', 'charging': False, 'charger': 'none'})
        self.assertNotIn('latitude', blob)
        self.assertNotIn('gps_accuracy', blob)


class FeedEventTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.f, self.c = make_feed(store=self.store)

    def go(self, s):
        self.c.t += s
        self.f.tick()

    def tracker(self, state, lat, lon):
        obs(self.f, 'device_tracker.owner_phone_new', state, self.c, latitude=lat, longitude=lon, gps_accuracy=10)

    def rows(self, label=None):
        return [r for r in self.store.added if label is None or r['label'] == label]

    def test_baseline_makes_no_event(self):
        self.go(600)
        self.assertEqual(self.rows(), [])

    def test_zone_debounce_and_significance(self):
        self.tracker('not_home', 12.51, 33.25)
        self.go(60)
        self.tracker('home', *HOME)                    # back within 2 min: a flap, no event
        self.go(300)
        self.assertEqual(self.rows(), [])
        self.tracker('not_home', 12.51, 33.25)
        self.go(119)
        self.assertEqual(self.rows(), [])
        self.go(2)
        r = self.rows('zone')
        self.assertEqual(len(r), 1)
        d = json.loads(r[0]['ha'])
        self.assertEqual((d['place'], d['band'], d['flag'], d['from']['place'], d['significant']),
                         ('away', 'near', 'away', 'home', True))
        self.assertEqual((r[0]['source'], r[0]['actionable'], r[0]['chat_type']), ('homeassistant', 1, 'status'))
        self.tracker('not_home', 12.7, 33.25)          # near -> region: recorded, not significant
        self.go(130)
        d = json.loads(self.rows('zone')[-1]['ha'])
        self.assertEqual((d['band'], d['significant']), ('region', False))
        self.tracker('not_home', 13.6, 33.25)          # -> far: significant
        self.go(130)
        d = json.loads(self.rows('zone')[-1]['ha'])
        self.assertEqual((d['band'], d['flag'], d['significant']), ('far', 'far', True))
        self.assertEqual(self.rows('zone')[-1]['actionable'], 1)
        for r in self.rows():
            for v in SECRET_VALUES:
                self.assertNotIn(v, json.dumps(r), v)

    def test_drive_start_end(self):
        obs(self.f, 'binary_sensor.owner_phone_new_android_auto', 'on', self.c)
        self.go(1)
        r = self.rows('drive')
        self.assertEqual((len(r), json.loads(r[0]['ha'])['state'], r[0]['actionable']), (1, 'start', 1))
        self.go(25 * 60)
        obs(self.f, 'binary_sensor.owner_phone_new_android_auto', 'off', self.c)
        self.go(60)
        obs(self.f, 'binary_sensor.owner_phone_new_android_auto', 'on', self.c)   # a short drop: still driving
        self.go(300)
        self.assertEqual(len(self.rows('drive')), 1)
        self.assertTrue(self.f.snapshot()['drive']['active'])
        obs(self.f, 'binary_sensor.owner_phone_new_android_auto', 'off', self.c)
        self.go(121)
        d = json.loads(self.rows('drive')[-1]['ha'])
        self.assertEqual((d['state'], d['minutes'], d['significant']), ('end', 31, True))
        self.assertFalse(self.f.snapshot()['drive']['active'])

    def test_activity_bt_sleep_alarm_battery(self):
        obs(self.f, 'sensor.owner_phone_new_detected_activity', 'walking', self.c)
        self.go(299)
        self.assertEqual(self.rows('activity'), [])
        self.go(2)
        self.assertEqual(json.loads(self.rows('activity')[0]['ha'])['value'], 'walking')
        obs(self.f, 'sensor.owner_phone_new_detected_activity', 'tilting', self.c)   # keeps walking
        self.go(400)
        self.assertEqual(len(self.rows('activity')), 1)
        obs(self.f, 'sensor.owner_phone_new_bluetooth_connection', '1', self.c,
            connected_paired_devices=['AA:BB:CC:DD:EE:01 (Pixel Buds Fake)'])
        self.go(121)
        self.assertEqual(json.loads(self.rows('bt')[0]['ha'])['connected'], ['headphones'])
        obs(self.f, 'sensor.owner_phone_new_sleep_confidence', '95', self.c)
        self.go(301)
        self.assertTrue(json.loads(self.rows('sleep')[0]['ha'])['asleep'])
        obs(self.f, 'sensor.owner_phone_new_sleep_confidence', '70', self.c)         # hysteresis: still asleep
        self.go(301)
        self.assertEqual(len(self.rows('sleep')), 1)
        obs(self.f, 'sensor.owner_phone_new_next_alarm', '2026-10-17T05:00:00+00:00', self.c)
        self.go(61)
        self.assertEqual(json.loads(self.rows('alarm')[0]['ha'])['next'], '2026-10-17T07:00')
        obs(self.f, 'sensor.owner_phone_new_battery_level', '12', self.c)            # low, but at home: nothing
        self.go(200)
        self.assertEqual(self.rows('battery'), [])
        self.tracker('not_home', 12.7, 33.5)
        self.go(200)
        r = self.rows('battery')
        self.assertEqual((len(r), json.loads(r[0]['ha'])['low'], r[0]['actionable']), (1, True, 0))
        for lab in ('activity', 'bt', 'sleep', 'alarm', 'battery'):
            self.assertTrue(all(x['actionable'] == 0 for x in self.rows(lab)), lab)

    def test_rate_limit_per_signal_and_fold(self):
        for i in range(8):                             # 8 committed activity changes inside an hour
            obs(self.f, 'sensor.owner_phone_new_detected_activity', 'walking' if i % 2 == 0 else 'still', self.c)
            self.go(301)
        self.assertEqual(len(self.rows('activity')), 4)
        self.assertEqual(self.f.counts['collapsed'], 4)
        self.go(3600)                                  # the window frees up: one folded row
        r = self.rows('activity')
        self.assertEqual(len(r), 5)
        d = json.loads(r[-1]['ha'])
        self.assertEqual((d['collapsed'], d['value']), (4, 'still'))

    def test_rate_limit_total(self):
        sigs = [('sensor.owner_phone_new_detected_activity', ('walking', 'still'), 301),
                ('sensor.owner_phone_new_sleep_confidence', ('95', '10'), 301),
                ('sensor.owner_phone_new_next_alarm', ('2026-10-17T05:00:00+00:00', '2026-10-18T05:00:00+00:00'), 61),
                ('sensor.owner_phone_new_bluetooth_connection', ('1', '0'), 121)]
        for i in range(4):
            for eid, vals, wait in sigs:
                attrs = {'connected_paired_devices': ['AA:BB:CC:DD:EE:01 (Pixel Buds Fake)']} if \
                    'bluetooth' in eid and i % 2 == 0 else {'connected_paired_devices': []}
                obs(self.f, eid, vals[i % 2], self.c, **attrs)
                self.go(wait)
        self.assertEqual(len(self.rows()), 12)
        self.assertGreaterEqual(self.f.counts['collapsed'], 4)

    def test_wifi_classes_learned_as_hmacs(self):
        path = TMP / 'wifi.json'
        f = H.Feed(FakeStore(), key=b'k', clock=self.c, wifi_path=path)
        sts = states(extra=[st('sensor.owner_phone_new_wifi_connection', 'FakeNet-Home')])
        f.set_selection(H.select(sts, 'person.owner', 'owner_phone_new'))
        f.observe_all(sts)
        self.assertEqual(f.wifi_class(), 'other')
        self.c.t += 601
        obs(f, 'sensor.owner_phone_new_wifi_connection', 'FakeNet-Home', self.c)
        self.assertEqual(f.wifi_class(), 'home')
        self.assertNotIn('FakeNet', path.read_text())
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')
        g = H.Feed(FakeStore(), key=b'k', clock=self.c, wifi_path=path)              # survives a restart
        g.set_selection(H.select(sts, 'person.owner', 'owner_phone_new'))
        g.observe_all(sts)
        self.assertEqual(g.wifi_class(), 'home')
        obs(g, 'sensor.owner_phone_new_wifi_connection', '<not connected>', self.c)
        self.assertEqual(g.wifi_class(), 'none')

    def test_eventstore_roundtrip(self):
        es = V.EventStore(TMP / 'events.db')
        f, c = make_feed(store=es)
        obs(f, 'binary_sensor.owner_phone_new_android_auto', 'on', c)
        c.t += 1
        f.tick()
        rows, _, _, _ = es.since(0, 10, 'homeassistant')
        self.assertEqual([(r['label'], json.loads(r['ha'])['state']) for r in rows], [('drive', 'start')])
        self.assertIn('homeassistant', V.FEED_SOURCES)


class GuardTests(unittest.TestCase):
    """Read-only by construction: nothing but auth/get_states/subscribe_trigger(state, allowlist)/ping."""

    class Rec:
        def __init__(self):
            self.sent = []

        def _send_text(self, t):
            self.sent.append(t)

    def conn(self):
        return H.HAConn(self.Rec(), allow=lambda e: e in ('person.owner', 'sensor.owner_phone_new_battery_level'))

    def test_forbidden_types(self):
        c = self.conn()
        for msg in ({'type': 'call_service', 'domain': 'light', 'service': 'turn_on'},
                    {'type': 'execute_script', 'sequence': []}, {'type': 'fire_event', 'event_type': 'x'},
                    {'type': 'subscribe_events'}, {'type': 'config/entity_registry/update'},
                    {'type': 'render_template', 'template': '{{ 1 }}'}, {'type': 'conversation/process'},
                    {'type': 'auth/long_lived_access_token', 'client_name': 'x', 'lifespan': 1},
                    {'type': 'validate_config'}, {'type': 'get_config'}, {'type': 'get_services'}, {},
                    {'type': 'auth', 'access_token': 't', 'extra': 1}, {'type': 'get_states', 'entity_id': 'x'},
                    {'type': 'ping', 'service': 'x'},
                    {'type': 'subscribe_trigger', 'trigger': {'platform': 'state', 'entity_id': ['light.kitchen']}},
                    {'type': 'subscribe_trigger', 'trigger': {'platform': 'template', 'value_template': '1'}},
                    {'type': 'subscribe_trigger', 'trigger': {'platform': 'state', 'entity_id': ['person.owner'],
                                                              'action': {'service': 'light.turn_on'}}},
                    {'type': 'subscribe_trigger', 'trigger': [{'platform': 'state', 'entity_id': 'person.owner'}]},
                    {'type': 'subscribe_trigger', 'trigger': {'platform': 'state', 'entity_id': []}},
                    {'type': 'subscribe_trigger', 'trigger': {'platform': 'state', 'entity_id': ['person.owner']},
                     'variables': {}}):
            with self.assertRaises(H.Forbidden, msg=str(msg)):
                c.send(msg)
        self.assertEqual(c.ws.sent, [])

    def test_allowed(self):
        c = self.conn()
        c.send({'type': 'auth', 'access_token': 't'})
        c.send({'type': 'get_states'})
        c.send({'type': 'subscribe_trigger', 'trigger': {'platform': 'state', 'entity_id': ['person.owner']}})
        c.send({'type': 'subscribe_trigger', 'trigger': {'trigger': 'state', 'entity_id': ['person.owner']}})
        c.send({'type': 'ping'})
        types = [json.loads(m)['type'] for m in c.ws.sent]
        self.assertEqual(types, ['auth', 'get_states', 'subscribe_trigger', 'subscribe_trigger', 'ping'])
        self.assertEqual([json.loads(m).get('id') for m in c.ws.sent], [None, 1, 2, 3, 4])

    def test_rest_guard(self):
        live = H.HALive(type('C', (), {'env': {'VAULT_HA_FEED': '1'}, 'state': TMP})(), None, None)
        live.feed.sel = {'entities': {'person.owner': 'person'}, 'zones': {}}
        sec = {'url': 'http://127.0.0.1:9', 'token': 't'}
        for p in ('/api/services/light/turn_on', '/api/states/light.kitchen', '/api/config', '/api/states/../x',
                  '/api/template', '/api/events/x'):
            with self.assertRaises(H.Forbidden, msg=p):
                live.rest_get(sec, p)

    def test_static_only_one_send_path(self):
        """Only HAConn.send writes text frames; only rest_get opens URLs, with GET; no write-ish HA words in code."""
        src = (ROOT / 'app' / 'ha_live.py').read_text()
        tree = ast.parse(src)
        callers = {}
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        callers.setdefault(node.func.attr, set()).add(f'{cls.name}.{fn.name}')
                        if node.func.attr == '_frame' and node.args and isinstance(node.args[0], ast.Constant):
                            callers.setdefault(f'_frame:{node.args[0].value}', set()).add(f'{cls.name}.{fn.name}')
        self.assertEqual(callers['_send_text'], {'HAConn.send'})
        self.assertEqual(callers['_frame:1'], {'WS._send_text'})
        self.assertEqual(callers.get('_frame:2'), None)
        self.assertEqual({c for c in callers['open'] if not c.startswith('Feed.')}, {'HALive.rest_get'})
        self.assertNotIn('urlopen', src)
        self.assertIn("method='GET'", src)
        code = '\n'.join(ln for ln in src.splitlines() if not ln.strip().startswith('#'))
        body = code.split('class Forbidden')[1]
        for word in ("'call_service'", '"call_service"', 'fire_event', 'execute_script', '/api/services',
                     'method=\'POST\'', "'POST'", 'set_state'):
            self.assertNotIn(word, body, word)


# ============================================================================================ fake Home Assistant

class FakeHA:
    """A websocket + REST server like HA's: records every message type it receives."""

    def __init__(self, sts, token='good', refuse_platform=False):
        self.sts, self.token, self.refuse_platform = sts, token, refuse_platform
        self.received, self.rest_paths, self.clients, self.sub_ids = [], [], [], []
        self.lock = threading.Lock()
        self.ws_up = True
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    @staticmethod
    def send(c, obj):
        data = json.dumps(obj).encode()
        n = len(data)
        head = bytes([0x81]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack('>H', n) if n < 65536 else
                                bytes([127]) + struct.pack('>Q', n))
        c.sendall(head + data)

    @staticmethod
    def recv_exact(c, n):
        b = b''
        while len(b) < n:
            x = c.recv(n - len(b))
            if not x:
                raise OSError('closed')
            b += x
        return b

    def recv(self, c):
        b0, b1 = self.recv_exact(c, 2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack('>H', self.recv_exact(c, 2))[0]
        elif n == 127:
            n = struct.unpack('>Q', self.recv_exact(c, 8))[0]
        assert b1 & 0x80, 'client frames must be masked'
        mask = self.recv_exact(c, 4)
        data = bytes(x ^ mask[i % 4] for i, x in enumerate(self.recv_exact(c, n)))
        return b0 & 0x0F, data

    def handle(self, c):
        req = b''
        while b'\r\n\r\n' not in req:
            x = c.recv(4096)
            if not x:
                return
            req += x
        head = req.decode('latin-1')
        line = head.split('\r\n')[0]
        if line.startswith('GET /api/websocket'):
            if not self.ws_up:
                c.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n')
                c.close()
                return
            key = [ln.split(':', 1)[1].strip() for ln in head.split('\r\n') if ln.lower().startswith('sec-websocket-key')][0]
            acc = base64.b64encode(hashlib.sha1(key.encode() + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()).decode()
            c.sendall(f'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                      f'Sec-WebSocket-Accept: {acc}\r\n\r\n'.encode())
            self.ws(c)
        else:
            self.rest(c, line, head)

    def ws(self, c):
        with self.lock:
            self.clients.append(c)
        try:
            self.send(c, {'type': 'auth_required', 'ha_version': '2026.10.0'})
            while True:
                op, data = self.recv(c)
                if op == 0x8:
                    return
                if op != 0x1:
                    continue
                m = json.loads(data)
                with self.lock:
                    self.received.append(m)
                t = m.get('type')
                if t == 'auth':
                    if m.get('access_token') == self.token:
                        self.send(c, {'type': 'auth_ok'})
                    else:
                        self.send(c, {'type': 'auth_invalid', 'message': 'bad'})
                        c.close()
                        return
                elif t == 'get_states':
                    self.send(c, {'id': m['id'], 'type': 'result', 'success': True, 'result': self.sts})
                elif t == 'subscribe_trigger':
                    if self.refuse_platform and 'platform' in m['trigger']:
                        self.send(c, {'id': m['id'], 'type': 'result', 'success': False,
                                      'error': {'code': 'invalid_format', 'message': 'x'}})
                    else:
                        with self.lock:
                            self.sub_ids.append((c, m['id']))
                        self.send(c, {'id': m['id'], 'type': 'result', 'success': True, 'result': None})
                elif t == 'ping':
                    self.send(c, {'id': m['id'], 'type': 'pong'})
                else:
                    self.send(c, {'id': m.get('id'), 'type': 'result', 'success': True})   # a real HA would act
        except (OSError, ValueError, AssertionError):
            return

    def push(self, eid, state, **attrs):
        """A state change, delivered to every subscribed client and kept for REST."""
        new = st(eid, state, **attrs)
        for i, s in enumerate(self.sts):
            if s['entity_id'] == eid:
                self.sts[i] = new
        with self.lock:
            subs = list(self.sub_ids)
        for c, sid in subs:
            try:
                self.send(c, {'id': sid, 'type': 'event', 'event': {'variables': {'trigger': {
                    'platform': 'state', 'entity_id': eid, 'from_state': None, 'to_state': new}}}})
            except OSError:
                pass

    def drop_ws(self):
        self.ws_up = False
        with self.lock:
            cs, self.clients, self.sub_ids = list(self.clients), [], []
        for c in cs:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except OSError:
                pass

    def rest(self, c, line, head):
        method, path = line.split(' ')[:2]
        with self.lock:
            self.rest_paths.append((method, path))
        ok = f'Authorization: Bearer {self.token}' in head
        if not ok:
            body, code = b'{}', '401 Unauthorized'
        elif path == '/api/states':
            body, code = json.dumps(self.sts).encode(), '200 OK'
        else:
            eid = path.rsplit('/', 1)[1]
            s = [x for x in self.sts if x['entity_id'] == eid]
            body, code = (json.dumps(s[0]).encode(), '200 OK') if s else (b'{}', '404 Not Found')
        c.sendall(f'HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n'
                  f'Connection: close\r\n\r\n'.encode() + body)
        c.close()

    def close(self):
        self.sock.close()
        self.drop_ws()


class Secrets:
    def __init__(self, url, token='good'):
        self.v = {'url': url, 'token': token, 'person': 'person.owner'}

    def is_set(self, name):
        return name == 'homeassistant'

    def get(self, name):
        return dict(self.v)


def wait_for(pred, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.saved = (H.BACKOFF_MIN, H.POLL_S, H.DEBOUNCE.copy())
        H.BACKOFF_MIN, H.POLL_S = 0.3, 0.3
        for k in H.DEBOUNCE:
            H.DEBOUNCE[k] = 0
        self.alerts = []

    def tearDown(self):
        H.BACKOFF_MIN, H.POLL_S = self.saved[:2]
        H.DEBOUNCE.clear()
        H.DEBOUNCE.update(self.saved[2])
        self.stop.set()
        self.ha.close()

    def start(self, token='good', refuse_platform=False, device='owner_phone_new'):
        self.ha = FakeHA(states(), refuse_platform=refuse_platform)
        cfg = type('C', (), {'env': {'VAULT_HA_FEED': '1', 'VAULT_HA_DEVICE': device}, 'state': TMP})()
        self.store = FakeStore()
        self.live = H.HALive(cfg, Secrets(f'http://127.0.0.1:{self.ha.port}', token), self.store, key=b'k',
                             alert=lambda *a, **k: self.alerts.append(a[0]))
        self.stop = threading.Event()
        threading.Thread(target=self.live.run, args=(self.stop,), daemon=True).start()

    def test_subscribe_events_fallback_reconnect(self):
        self.start()
        self.assertTrue(wait_for(lambda: self.live.state == 'websocket'), self.live.status())
        self.assertEqual(self.live.feed.place()['kind'], 'home')
        sub = [m for m in self.ha.received if m['type'] == 'subscribe_trigger'][0]
        self.assertEqual(sub['trigger']['platform'], 'state')
        self.assertIn('binary_sensor.owner_phone_new_android_auto', sub['trigger']['entity_id'])
        self.assertFalse(any('partner' in e or 'owner_old' in e for e in sub['trigger']['entity_id']))
        self.ha.push('binary_sensor.owner_phone_new_android_auto', 'on', connection_type='wired')
        self.assertTrue(wait_for(lambda: any(r['label'] == 'drive' for r in self.store.added)))
        self.ha.push('device_tracker.owner_phone_new', 'not_home', latitude=13.6, longitude=33.25, gps_accuracy=9)
        self.assertTrue(wait_for(lambda: (self.live.feed.place() or {}).get('flag') == 'far'))
        self.assertTrue(wait_for(lambda: any(r['label'] == 'zone' for r in self.store.added)))
        now = self.live.now()
        self.assertEqual(now['connection']['state'], 'websocket')
        self.assertTrue(now['drive']['active'])
        for v in SECRET_VALUES:
            self.assertNotIn(v, json.dumps(now), v)
        # websocket goes away -> REST poll (GET only, allowlisted entities), then reconnect
        self.ha.drop_ws()
        self.assertTrue(wait_for(lambda: self.live.state in ('polling', 'connecting')
                                 and any(p[1] != '/api/states' for p in self.ha.rest_paths)), self.live.status())
        self.ha.push('binary_sensor.owner_phone_new_android_auto', 'off')
        self.assertTrue(wait_for(lambda: self.live.feed.snapshot()['drive']['active'] is False))
        self.assertTrue(all(m == 'GET' for m, _ in self.ha.rest_paths))
        for _, p in self.ha.rest_paths:
            self.assertTrue(p == '/api/states' or 'owner_phone_new' in p or p.endswith('person.owner'), p)
        self.ha.ws_up = True
        self.assertTrue(wait_for(lambda: self.live.state == 'websocket', 15), self.live.status())
        self.assertGreaterEqual(self.live.reconnects, 1)
        types = {m['type'] for m in self.ha.received}
        self.assertLessEqual(types, H.ALLOWED_TYPES)

    def test_trigger_key_fallback(self):
        self.start(refuse_platform=True)
        self.assertTrue(wait_for(lambda: self.live.state == 'websocket'), self.live.status())
        subs = [m for m in self.ha.received if m['type'] == 'subscribe_trigger']
        self.assertEqual([('platform' in s['trigger'], 'trigger' in s['trigger']) for s in subs],
                         [(True, False), (False, True)])

    def test_auth_failed_stops_and_alerts(self):
        self.start(token='wrong')
        self.assertTrue(wait_for(lambda: self.live.state == 'auth_failed'), self.live.status())
        time.sleep(0.5)
        self.assertEqual([m['type'] for m in self.ha.received], ['auth'])
        self.assertEqual(self.alerts, ['ha-auth'])

    def test_ping_keepalive(self):
        saved = H.PING_S
        H.PING_S = 0.2
        try:
            self.start()
            self.assertTrue(wait_for(lambda: any(m['type'] == 'ping' for m in self.ha.received)))
            time.sleep(0.6)
            self.assertEqual(self.live.state, 'websocket')
        finally:
            H.PING_S = saved

    def test_off_switch(self):
        cfg = type('C', (), {'env': {}, 'state': TMP})()
        live = H.HALive(cfg, Secrets('http://127.0.0.1:9'), FakeStore())
        self.assertFalse(live.enabled)
        self.stop = threading.Event()
        self.ha = FakeHA(states())
        live.run(self.stop)                               # returns at once, never connects
        self.assertEqual((live.state, self.ha.received), ('off', []))


if __name__ == '__main__':
    unittest.main(verbosity=1)
