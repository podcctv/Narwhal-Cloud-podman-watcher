import copy
import json
import sqlite3
import unittest
from unittest import mock

from client import agent
from server import connection_policy as policy


READY_INCUS_HEALTH = {
    'scan_status': 'complete',
    'alerts': [],
    'error_instances': [],
    'active_lifecycle_operations': [],
}


class ConnectionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript('''CREATE TABLE connection_overloads(host_id,runtime,project,container_name,first_seen,last_seen,sample_count,stop_action_id);
            CREATE TABLE security_actions(id INTEGER PRIMARY KEY,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at,attempts DEFAULT 0);''')
        policy.initialize(self.conn)

    def tearDown(self):
        self.conn.close()

    def sample(self, stamp, count=1600, epoch='boot:net:pid'):
        return {'name':'a','runtime':'incus','project':'default','conn_count':count,
            'security':{'connection_metrics':{'schema':1,'valid':True,'source':'container_proc_net','epoch':epoch,
                'sampled_at':stamp,'total':count,'tcp_total':40,'tcp_established':30,'tcp_pending':0,'tcp_time_wait':5,'udp_sockets':count-40}}}

    def runman_sample(self, stamp, generation='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', count=1600):
        vm_id = '11111111-2222-3333-4444-555555555555'
        return {'name':vm_id,'runtime':'runman','project':'default','instance_id':generation,'conn_count':count,
            'security':{'connection_metrics':{'schema':1,'valid':True,'source':'runman_local_proc_net','epoch':generation,
                'sampled_at':stamp,'total':count,'tcp_total':40,'tcp_established':30,'tcp_pending':0,'tcp_time_wait':5,'udp_sockets':count-40}}}

    def observe(self, stamp, count=1600, epoch='boot:net:pid', sample=None, runtime_health=READY_INCUS_HEALTH):
        c = sample or self.sample(stamp,count,epoch)
        result = policy.observe(self.conn,'h',stamp,[c],1000,1500,900,600,now=stamp,
                                runtime_health=runtime_health)
        return result,c['connection_policy']

    def test_incus_stop_fails_closed_without_a_complete_runtime_scan(self):
        self.assertEqual(self.observe(1000)[0],0)
        self.assertEqual(self.observe(1450)[0],0)
        queued, result = self.observe(1900, runtime_health=None)
        self.assertEqual(queued,0)
        self.assertEqual(result['status'],'unverified')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM security_actions').fetchone()[0],0)

    def test_continuous_stop_requires_three_fresh_samples_and_only_queues_once(self):
        self.assertEqual(self.observe(1000)[0],0)
        self.assertEqual(self.observe(1450)[0],0)
        n,p = self.observe(1900)
        self.assertEqual(n,1)
        self.assertEqual(p['stop_duration_seconds'],900)
        self.assertEqual(p['stop_sample_count'],3)
        self.assertTrue(p['stop_duration_verified'])
        self.assertIn('3 次有效采样',policy.text(p))
        self.assertEqual(self.observe(2000)[0],0)
        params=json.loads(self.conn.execute('SELECT params_json FROM security_actions').fetchone()[0])
        self.assertEqual(params['metric_schema'],1)
        self.assertEqual(params['sample_count'],3)
        self.assertTrue(params['duration_verified'])
        self.assertEqual(params['max_gap_seconds'],600)
        self.assertEqual(params['expires_at'],2500)

    def test_critical_window_does_not_inherit_warning_episode_age(self):
        self.observe(1000,600)
        self.observe(1450,1001)
        _,p=self.observe(1900,1001)
        self.assertEqual(p['critical_duration_seconds'],450)
        self.assertFalse(p.get('escalated',False))
        _,p=self.observe(2350,1001)
        self.assertTrue(p['escalated'])
        self.assertEqual(p['stop_duration_seconds'],0)
        self.assertFalse(p['stop_duration_verified'])
        self.assertEqual(self.conn.execute('SELECT count(*) FROM security_actions').fetchone()[0],0)

    def test_gap_restart_recovery_and_missing_metric_reset_windows(self):
        for change in ('gap','restart','recovery','missing'):
            with self.subTest(change=change):
                self.conn.execute('DELETE FROM connection_windows')
                self.observe(1000)
                if change=='gap': self.observe(1601)
                if change=='restart': self.observe(1450,epoch='new')
                if change=='recovery': self.observe(1450,50)
                if change=='missing': self.observe(1450,sample={'name':'a','runtime':'incus','project':'default','conn_count':9999})
                n,p=self.observe(1900)
                self.assertEqual(n,0)
                self.assertLess(p['stop_duration_seconds'],900)

    def test_stale_future_inconsistent_and_shared_namespace_metrics_are_rejected(self):
        for change in ('legacy','stale','future','total','epoch','source','bool','states'):
            c=self.sample(1000)
            m=c['security']['connection_metrics']
            if change=='legacy': c['security']={}
            if change=='stale': m['sampled_at']=1
            if change=='future': m['sampled_at']=1031
            if change=='total': m['total']+=1
            if change=='epoch': m['epoch']=''
            if change=='source': m['source']='host'
            if change=='bool': m['tcp_pending']=False
            if change=='states': m['tcp_established']=41
            with self.subTest(change=change): self.assertIsNone(policy.metrics(c,1000))

    def test_replayed_sample_cannot_extend_or_destroy_window(self):
        self.observe(1000)
        self.observe(1450)
        self.observe(1450)
        self.observe(1200,50)
        n,p=self.observe(1900)
        self.assertEqual(n,1)
        self.assertEqual(p['stop_duration_seconds'],900)

    def test_pending_action_prevents_duplicate_after_restart(self):
        for stamp in (1000,1450,1900): self.observe(stamp)
        for stamp in (2000,2450,2900): self.observe(stamp,epoch='new')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM security_actions').fetchone()[0],1)

    def test_runman_overload_queues_generation_bound_stop_and_requeues_replacement(self):
        generation1 = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        generation2 = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
        for stamp in (1000,1450,1900):
            sample = self.runman_sample(stamp, generation1)
            queued = policy.observe(self.conn, 'h', stamp, [sample], 1000, 1500, 900, 600, now=stamp)
            self.assertEqual(queued, 1 if stamp == 1900 else 0)
        for stamp in (2000,2450,2900):
            sample = self.runman_sample(stamp, generation2)
            queued = policy.observe(self.conn, 'h', stamp, [sample], 1000, 1500, 900, 600, now=stamp)
            self.assertEqual(queued, 1 if stamp == 2900 else 0)
        rows = self.conn.execute('SELECT params_json FROM security_actions ORDER BY id').fetchall()
        self.assertEqual([json.loads(row[0])['instance_id'] for row in rows], [generation1, generation2])

    def test_runman_policy_rejects_missing_or_mismatched_generation(self):
        sample = self.runman_sample(1000)
        self.assertIsNotNone(policy.metrics(sample, 1000))
        sample['instance_id'] = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff'
        self.assertIsNone(policy.metrics(sample, 1000))
        sample = self.runman_sample(1000)
        sample['project'] = 'other'
        self.assertIsNone(policy.metrics(sample, 1000))

    def test_retries_are_bounded_and_failure_is_visible(self):
        for stamp in (1000,1450,1900): self.observe(stamp)
        for stamp in (2000,2450,2900,3000,3450,3900,4000,4450,4900):
            self.conn.execute("UPDATE security_actions SET status='failed'")
            _,p=self.observe(stamp)
        self.assertEqual(self.conn.execute('SELECT count(*) FROM security_actions').fetchone()[0],3)
        self.assertEqual(p['status'],'failed')

    def test_success_receipt_restarts_protection_window(self):
        for stamp in (1000,1450,1900): self.observe(stamp)
        self.conn.execute("UPDATE security_actions SET status='succeeded',updated_at=1950")
        n,p=self.observe(2000)
        self.assertEqual(n,0)
        self.assertEqual(p['stop_duration_seconds'],0)

    def test_dedup_keeps_independent_http_or_bandwidth_signals(self):
        a={'runtime':'incus','project':'default','container_name':'a','type':'container_connection_count'}
        b={**a,'type':'ops_policy_signal','observation':{'signals':{'connections':True,'rx_bps':False,'http_rps':False}}}
        self.assertEqual(len(policy.enrich_alerts([a,b],[])),1)
        b['observation']['signals']['http_rps']=True
        self.assertEqual(len(policy.enrich_alerts([a,b],[])),2)

    def test_invalid_metric_text_does_not_claim_verified_zero_duration(self):
        _,p=self.observe(1000,sample={'name':'a','conn_count':9999})
        self.assertIn('仅提醒',policy.text(p))
        self.assertIn('尚未验证',policy.text(None))

    def test_kill_switch_keeps_alerting_without_enforcement(self):
        for stamp in (1000,1450,1900):
            c=self.sample(stamp)
            self.assertEqual(policy.observe(self.conn,'h',stamp,[c],1000,1500,900,600,now=stamp,auto_stop=False),0)
        self.assertEqual(c['connection_policy']['status'],'disabled')
        self.assertEqual(self.conn.execute('SELECT count(*) FROM security_actions').fetchone()[0],0)

    def test_socket_metric_separates_tcp_states_from_udp(self):
        tcp='header\n0: 0100007F:0016 0100007F:1234 01 rest\n1: 0100007F:0016 0100007F:1234 06 rest\n'
        udp='header\n0: 0100007F:0016 0100007F:1234 01 rest\n'
        def read_file(path,*args,**kwargs):
            import io
            return io.StringIO(tcp if path.endswith('/tcp') else udp if path.endswith('/udp') else 'header\n')
        with mock.patch('builtins.open',side_effect=read_file),mock.patch.object(agent,'_connection_metric_epoch',return_value='epoch'):
            m=agent._collect_socket_security(123)['connection_metrics']
        self.assertTrue(m['valid'])
        self.assertEqual((m['total'],m['tcp_established'],m['tcp_time_wait'],m['udp_sockets']),(3,1,1,1))

    def test_partial_proc_read_is_not_enforcement_evidence(self):
        with mock.patch('builtins.open',side_effect=OSError),mock.patch.object(agent,'_connection_metric_epoch',return_value='epoch'):
            self.assertFalse(agent._collect_socket_security(123)['connection_metrics']['valid'])

    def test_node_cancels_expired_recovered_restarted_and_legacy_stops(self):
        action={'action_type':'stop_container','runtime':'incus','project':'default','container_name':'a',
            'params':{'reason':'sustained_connection_overload','metric_schema':1,'metric_epoch':'epoch',
                'threshold':1500,'duration_seconds':900,'required_duration_seconds':900,'expires_at':2000}}
        for change in ('expired','recovered','restarted','legacy','missing'):
            a=copy.deepcopy(action)
            fresh={'valid':True,'epoch':'epoch','total':1600}
            if change=='expired':a['params']['expires_at']=999
            if change=='recovered':fresh['total']=50
            if change=='restarted':fresh['epoch']='new'
            if change=='legacy':a['params'].pop('metric_schema')
            if change=='missing':fresh['valid']=False
            with self.subTest(change=change), mock.patch.object(agent.time,'time',return_value=1000), mock.patch.object(agent,'get_runtime_bins',return_value={'incus':'incus'}), mock.patch.object(agent,'_incus_instance_pid',return_value=123), mock.patch.object(agent,'_collect_socket_security',return_value={'connection_metrics':fresh}), mock.patch.object(agent,'_run_action_command') as runner:
                self.assertFalse(agent.execute_security_action(a)[0])
                runner.assert_not_called()

    def test_socket_abuse_distinguishes_benign_time_wait_from_socks_and_scan_abuse(self):
        benign_container = {
            'name': 'd56f4a3b-b116-45fb-906f-55cf18600616',
            'runtime': 'incus',
            'project': 'default',
            'conn_count': 2030,
            'net_rx_bps': 250000,
            'net_tx_bps': 480000,
            'security': {
                'connection_metrics': {
                    'schema': 1,
                    'valid': True,
                    'total': 2030,
                    'tcp_total': 1972,
                    'tcp_established': 180,
                    'tcp_pending': 2,
                    'tcp_time_wait': 1790,
                    'udp_sockets': 58,
                },
                'tcp_states': {'established': 180, 'time_wait': 1790, 'syn_recv': 2},
                'incoming_established': 42,
                'inbound_unique_ips': 4,
                'inbound_established_unique_ips': 2,
                'inbound_syn_recv_unique_ips': 2,
                'outbound_established': 138,
                'outbound_unique_ips': 24,
                'outbound_unique_ports': 3,
                'suspicious_outbound_connections': 0,
                'net_rx_pps': 95,
                'net_tx_pps': 120,
                'communication_processes': [{'process': 'xray', 'pid': 321, 'inbound_connections': 42, 'outbound_connections': 138}],
            },
        }
        benign_eval = agent._evaluate_socket_abuse(
            benign_container,
            benign_container['security'],
            rx_bps=250000,
            tx_bps=480000,
            rx_pps=95,
            tx_pps=120,
        )
        self.assertFalse(benign_eval['suspected'])
        self.assertEqual(benign_eval['verdict'], 'benign_high_sockets')
        self.assertIn('倾向非滥用', benign_eval['compact_basis_text'])
        self.assertEqual(len(benign_eval['dimensions']), 4)

        benign_container['security']['socket_abuse'] = benign_eval
        ops_alert = {
            'runtime': 'incus',
            'project': 'default',
            'container_name': benign_container['name'],
            'type': 'ops_policy_signal',
            'message': 'socket 总数 2030，提醒门槛 500。此策略用于提醒，自动停机由独立的连续超标保护规则决定。',
            'observation': {'signals': {'connections': True}},
        }
        enriched = policy.enrich_alerts([ops_alert], [benign_container])[0]
        self.assertIn('【四维判断依据】', enriched['message'])
        self.assertEqual(enriched['socket_abuse']['verdict'], 'benign_high_sockets')

        socks_container = {
            'name': 'socks-shared-node',
            'runtime': 'incus',
            'project': 'default',
            'conn_count': 860,
            'net_rx_bps': 1200000,
            'net_tx_bps': 1500000,
            'security': {
                'connection_metrics': {
                    'schema': 1,
                    'valid': True,
                    'total': 860,
                    'tcp_total': 820,
                    'tcp_established': 620,
                    'tcp_pending': 10,
                    'tcp_time_wait': 190,
                    'udp_sockets': 40,
                },
                'tcp_states': {'established': 620, 'time_wait': 190, 'syn_sent': 38, 'syn_recv': 6},
                'syn_sent_count': 38,
                'outbound_syn_sent_unique_ips': 22,
                'incoming_established': 310,
                'inbound_unique_ips': 20,
                'inbound_established_unique_ips': 16,
                'inbound_syn_recv_unique_ips': 4,
                'outbound_established': 310,
                'outbound_unique_ips': 95,
                'outbound_unique_ports': 18,
                'suspicious_outbound_connections': 9,
                'sensitive_outbound_ports': [
                    {'port': 22, 'service': 'SSH', 'connections': 14, 'established': 2, 'syn_sent': 12, 'unique_ips': 9},
                    {'port': 3389, 'service': 'RDP', 'connections': 7, 'established': 1, 'syn_sent': 6, 'unique_ips': 6},
                ],
                'socks_proxy': {'detected': True, 'auth_mode': 'no_auth'},
                'net_rx_pps': 580,
                'net_tx_pps': 640,
            },
        }
        with mock.patch.dict(agent.os.environ, {'SECURITY_MONITOR_ENABLED': 'true', 'SECURITY_ACCESS_LOG_PATHS': ''}, clear=False):
            summary = agent.collect_security_summary([socks_container], 60)
        abuse_alerts = [a for a in summary['alerts'] if a['type'] == 'socket_abuse_suspected']
        self.assertEqual(len(abuse_alerts), 1)
        self.assertTrue(abuse_alerts[0]['protection_only'])
        self.assertFalse(abuse_alerts[0]['auto_stop_eligible'])
        codes = {c['code'] for c in abuse_alerts[0]['socket_abuse']['categories']}
        self.assertIn('shared_proxy_socks_abuse', codes)
        self.assertIn('outbound_scan_bruteforce', codes)
        self.assertIn('【四维判断依据】', abuse_alerts[0]['message'])
