import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from client import network_quarantine as q


INSTANCE_ID = 'c7a35d5c-e17c-4e25-8479-123456789abc'
PODMAN_ID = 'a'*64
EVIDENCE = [{'kind': 'identity_enumeration', 'confidence': 'high', 'pid': 20,
             'source_sha256': 'b'*64, 'source': 'private-source-must-not-persist',
             'argv': ['--password', 'private-password-must-not-persist']}]


class FakeIncus:
    def __init__(self):
        self.profile = {'eth0': {'type': 'nic', 'name': 'eth0', 'network': 'incusbr0'}}
        self.item = {'config': {'volatile.uuid': INSTANCE_ID, 'user.note': 'preserved',
                                'volatile.eth0.hwaddr':'10:66:6a:00:00:11','volatile.eth0.name':'eth0'},
                     'devices': {'root': {'type': 'disk', 'path': '/', 'pool': 'default'},
                                 'ssh': {'type': 'proxy', 'listen': 'tcp:0.0.0.0:12345', 'connect': 'tcp:127.0.0.1:22'}},
                     'profiles': ['default'], 'description': 'customer data', 'ephemeral': False}
        self.revision = 0
        self.calls = []
        self.fail_update = False

    def request(self, method, path, data=None, etag=None):
        self.calls.append((method, path, copy.deepcopy(data), etag))
        if path.endswith('/state'):
            expanded = {**self.profile, **self.item['devices']}
            return {'network': {v.get('name') or self.item['config'].get('volatile.'+key+'.name'):
                    {'state': 'up', 'hwaddr':v.get('hwaddr') or self.item['config'].get('volatile.'+key+'.hwaddr')}
                    for key,v in expanded.items() if v.get('type') == 'nic'}}, None
        if method == 'PUT':
            if self.fail_update or etag != str(self.revision):
                raise q.QuarantineError('conditional update failed')
            before = {**self.profile, **self.item['devices']}
            self.item = copy.deepcopy(data)
            after = {**self.profile, **self.item['devices']}
            for key in set(before) | set(after):
                if before.get(key,{}).get('type') != after.get(key,{}).get('type'):
                    for field in ('hwaddr', 'name', 'host_name'):
                        self.item['config'].pop('volatile.'+key+'.'+field, None)
                    if after.get(key,{}).get('type') == 'nic':
                        if not after[key].get('hwaddr'):
                            self.item['config']['volatile.'+key+'.hwaddr'] = '10:66:6a:00:00:99'
                        if not after[key].get('name'):
                            self.item['config']['volatile.'+key+'.name'] = 'eth0'
            self.revision += 1
            return {}, None
        result = copy.deepcopy(self.item)
        result['expanded_devices'] = {**self.profile, **result['devices']}
        return result, str(self.revision)


class FakePodman:
    def __init__(self):
        self.item = {'Id': PODMAN_ID, 'Pod': '', 'HostConfig': {'NetworkMode': 'bridge'},
                     'NetworkSettings': {'Networks': {'one': {'IPAddress': '10.90.0.2', 'Aliases': ['customer']},
                                                     'two': {'GlobalIPv6Address': 'fd00::2', 'MacAddress': '02:00:00:00:00:02'}}}}
        self.calls = []
        self.fail_network = None

    def __call__(self, command):
        self.calls.append(command)
        if command[1] == 'inspect':
            return True, json.dumps([self.item])
        network, identity = command[-2:]
        if identity != PODMAN_ID or network == self.fail_network:
            return False, 'not returned to caller'
        networks = self.item['NetworkSettings']['Networks']
        if command[2] == 'disconnect':
            networks.pop(network, None)
        else:
            options = command[3:-2]
            restored = {}
            for flag, field in (('--ip', 'IPAddress'), ('--ip6', 'GlobalIPv6Address'), ('--mac-address', 'MacAddress')):
                if flag in options:
                    restored[field] = options[options.index(flag)+1]
            restored['Aliases'] = [options[i+1] for i, flag in enumerate(options) if flag == '--alias']
            networks[network] = restored
        return True, ''


class NetworkQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)/'quarantine.json'
        self.journal = q.Journal(str(self.path))

    def tearDown(self):
        self.directory.cleanup()

    def test_incUS_masks_all_nics_and_proxy_and_restores_inheritance(self):
        api = FakeIncus()
        original = copy.deepcopy(api.item)
        driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        key = q.target('incus', 'default', 'customer', INSTANCE_ID)
        result = q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertTrue(result['ingress_blocked'] and result['egress_blocked'])
        self.assertEqual(api.item['devices']['eth0'], {'type': 'none'})
        self.assertEqual(api.item['devices']['ssh'], {'type': 'none'})
        self.assertEqual(api.item['devices']['root'], original['devices']['root'])
        self.assertEqual({k:v for k,v in api.item['config'].items() if not k.startswith('volatile.eth0.')},
                         {k:v for k,v in original['config'].items() if not k.startswith('volatile.eth0.')})
        self.assertEqual(api.item['profiles'], ['default'])
        self.assertNotIn('private-source', self.path.read_text())
        self.assertNotIn('private-password', self.path.read_text())
        q.release(self.journal, key, driver)
        self.assertEqual(api.item, original)
        self.assertEqual(self.journal.read(), {})
        self.assertFalse(any(call[0] in {'PATCH', 'DELETE'} for call in api.calls))

    def test_recovery_record_exists_before_first_mutation(self):
        api = FakeIncus()
        driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        original = driver.isolate
        def check(backup):
            self.assertTrue(self.path.is_file())
            self.assertEqual(next(iter(self.journal.read().values()))['status'], 'applying')
            return original(backup)
        driver.isolate = check
        q.quarantine(self.journal, q.target('incus', '', 'customer', INSTANCE_ID), driver, EVIDENCE)

    def test_auto_named_incUS_nic_resolved_before_mutation(self):
        api = FakeIncus()
        api.profile['eth0'].pop('name')
        api.item['config']['volatile.eth0.name'] = 'ens3'
        driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        key = q.target('incus', '', 'customer', INSTANCE_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertEqual(self.journal.read()[key]['backup']['guest_names'], {'eth0': 'ens3'})
        q.release(self.journal, key, driver)

    def test_unknown_incUS_nic_name_refused_before_mutation(self):
        api = FakeIncus(); api.profile['eth0'].pop('name')
        api.item['config'].pop('volatile.eth0.name')
        api.item['config'].pop('volatile.eth0.hwaddr')
        with self.assertRaises(q.QuarantineError):
            q.IncusIsolation(api, 'customer', INSTANCE_ID).snapshot()
        self.assertFalse(any(c[0] == 'PUT' for c in api.calls))

    def test_incUS_restores_volatile_mac_and_name_without_stale_host_veth(self):
        api = FakeIncus()
        api.item['config'].update({'volatile.eth0.hwaddr':'10:66:6a:00:00:11',
                                  'volatile.eth0.name':'eth0','volatile.eth0.host_name':'old-veth'})
        driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        key = q.target('incus', '', 'customer', INSTANCE_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertNotIn('volatile.eth0.hwaddr', api.item['config'])
        q.release(self.journal, key, driver)
        self.assertEqual(api.item['config']['volatile.eth0.hwaddr'], '10:66:6a:00:00:11')
        self.assertEqual(api.item['config']['volatile.eth0.name'], 'eth0')
        self.assertNotIn('volatile.eth0.host_name', api.item['config'])

    def test_restored_podman_address_mismatch_rolls_back(self):
        runner = FakePodman(); driver = q.PodmanIsolation(runner, 'podman', 'customer', PODMAN_ID)
        key = q.target('podman', '', 'customer', PODMAN_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        original = driver.command
        def mismatch(args):
            output = original(args)
            if args[:2] == ['network', 'connect']:
                runner.item['NetworkSettings']['Networks'][args[-2]]['IPAddress'] = '10.0.0.99'
            return output
        driver.command = mismatch
        with self.assertRaises(q.QuarantineError):
            q.release(self.journal, key, driver)
        self.assertEqual(runner.item['NetworkSettings']['Networks'], {})
        self.assertIn(key, self.journal.read())

    def test_incUS_identity_change_no_mutation(self):
        api = FakeIncus()
        api.item['config']['volatile.uuid'] = 'other-container'
        with self.assertRaises(q.QuarantineError):
            q.quarantine(self.journal, q.target('incus', '', 'customer', INSTANCE_ID), q.IncusIsolation(api, 'customer', INSTANCE_ID), EVIDENCE)
        self.assertFalse(self.path.exists())
        self.assertFalse(any(c[0] == 'PUT' for c in api.calls))

    def test_incUS_unmanaged_network_passthrough_and_etag_failures_visible(self):
        for config in ({'raw.lxc': 'lxc.net.0.type = phys'},):
            api = FakeIncus(); api.item['config'].update(config)
            with self.assertRaises(q.QuarantineError):
                q.IncusIsolation(api, 'customer', INSTANCE_ID).snapshot()
        api = FakeIncus(); api.item['devices']['passthrough'] = {'type': 'pci'}
        with self.assertRaises(q.QuarantineError):
            q.IncusIsolation(api, 'customer', INSTANCE_ID).snapshot()
        api = FakeIncus(); api.fail_update = True
        key = q.target('incus', '', 'customer', INSTANCE_ID)
        with self.assertRaises(q.QuarantineError):
            q.quarantine(self.journal, key, q.IncusIsolation(api, 'customer', INSTANCE_ID), EVIDENCE)
        self.assertEqual(self.journal.read()[key]['status'], 'failed')
        self.assertNotIn('eth0', api.item['devices'])

    def test_new_incUS_nic_cannot_silently_bypass_persistent_quarantine(self):
        api = FakeIncus(); driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        key = q.target('incus', '', 'customer', INSTANCE_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        api.item['devices']['eth1'] = {'type': 'nic', 'name': 'eth1', 'network': 'new-bridge'}
        q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertEqual(api.item['devices']['eth1'], {'type': 'none'})
        self.assertIn('eth1', self.journal.read()[key]['backup']['original'])

    def test_later_passthrough_cannot_be_reported_as_complete_isolation(self):
        api=FakeIncus();driver=q.IncusIsolation(api,'customer',INSTANCE_ID)
        key=q.target('incus','','customer',INSTANCE_ID)
        q.quarantine(self.journal,key,driver,EVIDENCE)
        api.item['devices']['new-device']={'type':'pci'}
        with self.assertRaises(q.QuarantineError):q.quarantine(self.journal,key,driver,EVIDENCE)
        self.assertEqual(self.journal.read()[key]['status'],'failed')

    def test_restore_refuses_to_overwrite_operator_device_changes(self):
        api = FakeIncus(); driver = q.IncusIsolation(api, 'customer', INSTANCE_ID)
        key = q.target('incus', '', 'customer', INSTANCE_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        api.item['devices']['ssh'] = {'type': 'disk', 'path': '/new-disk', 'pool': 'default'}
        with self.assertRaises(q.QuarantineError):
            q.release(self.journal, key, driver)
        self.assertEqual(api.item['devices']['ssh']['type'], 'disk')
        self.assertIn(key, self.journal.read())

    def test_podman_disconnect_all_networks_and_restore_options(self):
        runner = FakePodman(); driver = q.PodmanIsolation(runner, 'podman', 'customer', PODMAN_ID)
        key = q.target('podman', '', 'customer', PODMAN_ID)
        q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertEqual(runner.item['NetworkSettings']['Networks'], {})
        q.release(self.journal, key, driver)
        self.assertEqual(set(runner.item['NetworkSettings']['Networks']), {'one', 'two'})
        connects = [c for c in runner.calls if c[1:3] == ['network', 'connect']]
        self.assertIn('--ip', connects[0]); self.assertIn('--alias', connects[0])
        self.assertIn('--ip6', connects[1]); self.assertIn('--mac-address', connects[1])
        self.assertFalse(any('stop' in c or 'rm' in c or 'network rm' in c for c in runner.calls))

    def test_podman_shared_and_host_network_never_touched(self):
        for mode, pod in (('host', ''), ('container:other', ''), ('bridge', 'pod-id'), ('pasta', ''), ('slirp4netns', '')):
            runner = FakePodman(); runner.item['HostConfig']['NetworkMode'] = mode; runner.item['Pod'] = pod
            with self.assertRaises(q.QuarantineError):
                q.PodmanIsolation(runner, 'podman', 'customer', PODMAN_ID).snapshot()
            self.assertEqual(len(runner.calls), 1)
        runner=FakePodman();runner.item['HostConfig']['PidMode']='host'
        with self.assertRaises(q.QuarantineError):q.PodmanIsolation(runner,'podman','customer',PODMAN_ID).snapshot()
        self.assertNotIn('.Env',q.PODMAN_INSPECT_FORMAT)
        self.assertNotIn('.Labels',q.PODMAN_INSPECT_FORMAT)

    def test_podman_partial_disconnect_is_not_reported_as_success(self):
        runner = FakePodman(); runner.fail_network = 'two'
        driver = q.PodmanIsolation(runner, 'podman', 'customer', PODMAN_ID)
        key = q.target('podman', '', 'customer', PODMAN_ID)
        with self.assertRaises(q.QuarantineError):
            q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertEqual(self.journal.read()[key]['status'], 'failed')
        self.assertEqual(set(runner.item['NetworkSettings']['Networks']), {'two'})
        runner.fail_network = None
        q.quarantine(self.journal, key, driver, EVIDENCE)
        self.assertEqual(runner.item['NetworkSettings']['Networks'], {})

    def test_invalid_target_protected_management_and_unsafe_evidence_rejected(self):
        for runtime, name, identity in (('docker', 'customer', PODMAN_ID), ('incus', 'x;evil', INSTANCE_ID),
                                        ('podman', 'narwhal-monitor-server', PODMAN_ID), ('incus', 'customer', 'short')):
            with self.assertRaises(q.QuarantineError):
                q.target(runtime, '', name, identity)
        with self.assertRaises(q.QuarantineError):
            q.safe_evidence([{'source': 'do not persist'}])
        with self.assertRaises(q.QuarantineError):
            q.Journal('relative.json')
        if os.name == 'posix':
            self.journal.write({})
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()

