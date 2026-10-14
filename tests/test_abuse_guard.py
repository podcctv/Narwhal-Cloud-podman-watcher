import tempfile
import unittest
from pathlib import Path
from unittest import mock
from client import abuse_guard as guard, network_quarantine as q


class Driver:
    def __init__(self):
        self.changed = 0
    def snapshot(self):
        return {'original_network': 'kept'}
    def isolate(self, backup):
        self.changed += 1


class AbuseGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.engine = guard.Engine(q.Journal(str(Path(self.directory.name)/'state.json')))
        self.container = {'runtime': 'podman', 'project': '', 'name': 'customer', 'id': 'a'*64}
        self.processes = [{'pid': 22, 'start_ticks': '12345', 'executable': '/usr/bin/nmap', 'argv': ['nmap', '8.8.8.8']}]
        self.driver = Driver()
    def tearDown(self):
        self.directory.cleanup()
    def test_two_fresh_corroborating_samples_before_isolation(self):
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)['state'], 'suspected')
        self.assertEqual(self.driver.changed, 0)
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 110)['state'], 'suspected')
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 121)
        self.assertEqual(result['state'], 'isolated')
        self.assertEqual(result['alert']['severity'], 'critical')
        self.assertTrue(result['alert']['network_quarantine']['egress_blocked'])
        self.assertTrue(result['alert']['network_quarantine']['ingress_blocked'])
        self.assertEqual(self.driver.changed, 1)
    def test_process_incarnation_change_does_not_confirm_old_evidence(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        self.processes[0]['start_ticks'] = 'other-process'
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)['state'], 'suspected')
        self.assertEqual(self.driver.changed, 0)
    def test_stale_discontinuous_and_missing_samples_not_confirmation(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 500)['state'], 'suspected')
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, [], [], 510)['state'], 'not_observed')
        self.assertEqual(self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 530)['state'], 'suspected')
        self.assertEqual(self.driver.changed, 0)
    def test_quarantine_persists_after_network_activity_disappears_and_restart(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        restarted = guard.Engine(self.engine.journal)
        result = restarted.check(self.container, 'a'*64, self.driver, [], [], 180)
        self.assertEqual(result['state'], 'isolated')
        self.assertIn('等待管理员复核', result['alert']['message'])
        self.assertEqual(self.driver.changed, 2)
    def test_isolation_failure_remains_critical_not_success(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        def fail(backup):
            raise q.QuarantineError('verification failed')
        self.driver.isolate = fail
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        self.assertEqual(result['state'], 'failed')
        self.assertFalse(result['alert']['network_quarantine']['ingress_blocked'])
        self.assertEqual(result['alert']['severity'], 'critical')
    def test_notification_failure_retries_without_releasing_networks(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        def fail(alert):
            raise OSError('offline')
        self.engine.notify(result, fail, 130)
        self.assertTrue(result['notification_pending'])
        self.assertEqual(result['state'], 'isolated')
        sent = []
        def delivered(alert):
            sent.append(alert)
            return {'telegram_delivery': {'state': 'delivered'}}
        self.engine.notify(result, delivered, 140)
        self.assertFalse(result['notification_pending'])
        self.engine.notify(result, delivered, 150)
        self.assertEqual(len(sent), 1)

    def test_server_ack_is_not_telegram_delivery_and_retries(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        calls = []
        def pending(alert):
            calls.append(alert)
            return {'ok': True, 'telegram_delivery': {'state': 'unconfigured'}}
        self.engine.notify(result, pending, 130)
        self.assertTrue(result['event_relayed'])
        self.assertTrue(result['notification_pending'])
        self.engine.notify(result, pending, 140)
        self.engine.notify(result, pending, 161)
        self.assertEqual(len(calls), 2)

    def test_stale_quarantine_never_becomes_a_clean_observation(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        self.engine.results[('podman', '', 'customer')] = result
        status = self.engine.status(self.container, 1100)
        self.assertEqual(status['state'], 'stale')
        self.assertEqual(status['alert']['network_quarantine']['status'], 'unverified')
        self.assertIn('不表示风险已恢复', status['alert']['message'])
        self.assertTrue(self.engine.journal.read())

    def test_collection_failure_retains_pending_review(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        result = self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        self.engine.results[('podman', '', 'customer')] = result
        def unavailable(container):
            raise OSError('synthetic-unavailable')
        self.engine.schedule([self.container], unavailable, lambda value: None)
        self.engine.worker.join(timeout=3)
        status = self.engine.results[('podman', '', 'customer')]
        self.assertEqual(status['state'], 'unverified')
        self.assertEqual(status['alert']['severity'], 'critical')
        self.assertFalse(status['alert']['network_quarantine']['ingress_blocked'])

    def test_missing_none_and_empty_podman_project_share_one_status_identity(self):
        container = {key:value for key,value in self.container.items() if key != 'project'}
        def provider(c):
            return 'a'*64, self.driver, [], []
        self.engine.schedule([container], provider, lambda value: {})
        self.engine.worker.join(timeout=3)
        for project in (None,''):
            report = {**container,'project':project}
            self.assertEqual(self.engine.status(report)['state'],'not_observed')
        self.engine.forget(container,'a'*64)
        self.assertNotIn(('podman','','customer'),self.engine.results)

    def test_native_provider_refuses_restart_between_sampling_and_new_isolation(self):
        import json
        from client import agent
        item={'Id':'a'*64,'Pod':'','HostConfig':{'NetworkMode':'bridge','PidMode':'private'},'State':{'Pid':101}}
        fresh={**item,'State':{'Pid':202}}
        process={'pid':1,'host_pid':101,'start_ticks':'40'}
        with mock.patch.object(agent,'get_runtime_bins',return_value={'podman':'podman'}), \
             mock.patch.object(agent,'_run_action_command',side_effect=[(True,json.dumps([item])),(True,json.dumps([fresh]))]), \
             mock.patch.object(agent.os.path,'isdir',return_value=True), \
             mock.patch.object(agent.os,'stat',side_effect=lambda path:mock.Mock(st_ino=1 if path=='/proc/1/ns/pid' else 2)), \
             mock.patch.object(agent.os,'access',return_value=True), \
             mock.patch.object(agent.abuse_collection,'host_metadata',return_value=process), \
             mock.patch.object(agent.abuse_collection,'scoped_host_processes',return_value=[process]), \
             mock.patch.object(agent,'_collect_socket_security',return_value={'listening_ports':[]}), \
             mock.patch.object(agent,'_collect_host_proc_socket_details',return_value={'communication_sockets':[]}), \
             mock.patch.object(agent.abuse_collection,'collect_host',return_value=[process]):
            _,driver,_,_=agent._abuse_provider({'runtime':'podman','name':'customer','id':'a'*64})
            with self.assertRaises(q.QuarantineError):driver.check_evidence([{'pid':1,'start_ticks':'40'}])
    def test_renamed_instance_retains_quarantine_not_new_tenant(self):
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 100)
        self.engine.check(self.container, 'a'*64, self.driver, self.processes, [], 130)
        renamed = {**self.container, 'name': 'renamed-customer'}
        self.assertEqual(self.engine.check(renamed, 'a'*64, self.driver, [], [], 180)['state'], 'isolated')
        replacement = {**self.container, 'id': 'c'*64}
        self.assertEqual(self.engine.check(replacement, 'c'*64, self.driver, [], [], 190)['state'], 'not_observed')


if __name__ == '__main__':
    unittest.main()

