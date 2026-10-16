"""app/ha.py: the Home Assistant inventory is metadata only. Invented fixtures only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app'))
import ha  # noqa: E402

SECRET_VALUES = ['47.1234', '8.5678', 'FakeNet-5G', 'Musterweg 9, 9999 Testdorf', 'Pixel Buds Fake',
                 'AA:BB:CC:DD:EE:FF', 'Hi from Testperson', 'TestCar 3000', '203.0.113.42', '4321']


def st(eid, state, **attrs):
    return {'entity_id': eid, 'state': state, 'attributes': attrs}


STATES = [
    st('person.owner', 'Work', device_trackers=['device_tracker.phone_a'], latitude=47.1234, longitude=8.5678,
       gps_accuracy=12, friendly_name='Owner'),
    st('person.partner', 'home', device_trackers=['device_tracker.phone_b'], friendly_name='Partner'),
    st('device_tracker.phone_a', 'Work', latitude=47.1234, longitude=8.5678, source_type='gps', friendly_name='Phone A'),
    st('device_tracker.phone_b', 'home', latitude=47.1234, longitude=8.5678, friendly_name='Phone B'),
    st('zone.home', '1', latitude=47.1234, longitude=8.5678, radius=100, friendly_name='Home'),
    st('zone.work', '1', latitude=47.1234, longitude=8.5678, radius=200, friendly_name='Work'),
    st('binary_sensor.phone_a_android_auto', 'off', friendly_name='Phone A Android Auto'),
    st('sensor.phone_a_detected_activity', 'still', confidence=90, friendly_name='Phone A Detected activity'),
    st('sensor.phone_a_wifi_connection', 'FakeNet-5G', friendly_name='Phone A Wifi connection'),
    st('sensor.phone_a_geocoded_location', 'Musterweg 9, 9999 Testdorf', Locality='Testdorf',
       friendly_name='Phone A Geocoded location'),
    st('sensor.phone_a_bluetooth_connection', '1', connected_paired_devices=['AA:BB:CC:DD:EE:FF (Pixel Buds Fake)'],
       unit_of_measurement='connection(s)', friendly_name='Phone A Bluetooth connection'),
    st('sensor.phone_a_last_notification', 'Hi from Testperson', friendly_name='Phone A Last notification'),
    st('sensor.phone_a_car_name', 'TestCar 3000', friendly_name='Phone A Car name'),
    st('sensor.phone_a_public_ip_address', '203.0.113.42', friendly_name='Phone A Public IP address'),
    st('sensor.phone_a_next_alarm', '2026-10-16T05:30:00+00:00', device_class='timestamp', friendly_name='Phone A Next alarm'),
    st('sensor.phone_a_steps_sensor', '4321', unit_of_measurement='steps', friendly_name='Phone A Steps sensor'),
    st('sensor.phone_a_charger_type', 'none', device_class='enum', options=['ac', 'usb', 'wireless', 'dock', 'none'],
       friendly_name='Phone A Charger type'),
    st('sensor.phone_b_battery_level', '55', friendly_name='Phone B Battery level'),
    st('binary_sensor.phone_b_android_auto', 'on', friendly_name='Phone B Android Auto'),
    st('light.kitchen', 'on', friendly_name='Kitchen'),
    st('sensor.car_x_android_auto_status', 'on', friendly_name='Some car thing'),
]


class T(unittest.TestCase):
    def setUp(self):
        self.r = ha.inventory(STATES, 'person.owner')
        self.ids = {e['entity_id']: e for e in self.r['entities']}

    def test_no_values_leak(self):
        blob = json.dumps(self.r)
        for v in SECRET_VALUES:
            self.assertNotIn(v, blob, v)

    def test_others_excluded(self):
        for eid in self.ids:
            self.assertNotIn('phone_b', eid)
            self.assertNotEqual(eid, 'person.partner')
        self.assertEqual(self.r['excluded_other_people'], 4)
        self.assertNotIn('light.kitchen', self.ids)

    def test_kinds(self):
        k = {e: v['kind'] for e, v in self.ids.items()}
        self.assertEqual(k['binary_sensor.phone_a_android_auto'], 'on/off')
        self.assertEqual(k['sensor.phone_a_detected_activity'], 'slug')
        self.assertEqual(k['sensor.phone_a_wifi_connection'], 'masked text (SSID)')
        self.assertEqual(k['sensor.phone_a_geocoded_location'], 'masked text (address)')
        self.assertEqual(k['sensor.phone_a_next_alarm'], 'timestamp')
        self.assertEqual(k['sensor.phone_a_steps_sensor'], 'number')
        self.assertEqual(k['sensor.phone_a_charger_type'], 'enum (ac, usb, wireless, dock, none)')
        self.assertEqual(k['person.owner'], 'zone name | home | not_home')
        self.assertIn('coordinates', self.ids['device_tracker.phone_a']['attr_keys'])
        self.assertNotIn('latitude', self.ids['device_tracker.phone_a']['attr_keys'])

    def test_zones_and_unattributed(self):
        self.assertEqual(self.r['zones'], ['Home', 'Work'])
        self.assertEqual(self.ids['sensor.car_x_android_auto_status']['owner'], 'unattributed')


if __name__ == '__main__':
    unittest.main(verbosity=1)
