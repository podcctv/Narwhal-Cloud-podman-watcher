import json
import os
import subprocess
import unittest
from unittest import mock
import test_operations as existing
from client import agent
from server import buyer_content as content
from server import buyer_mapping as mapping
from server import buyer_notifications as buyer
from server import operations as ops


class NotificationEvidenceTests(unittest.TestCase):
    def alert(self, kind='socks_weak_auth', **extra):
        return dict(alert_type=kind, host_id='香港', container_name='A1B2',
                    last_seen=1700000000, value=12500000, threshold=10000000,
                    details_json='{}', **extra)

    def test_metric_conversion_and_observed_threshold(self):
        _, text = content.render(self.alert('ddos_bandwidth'), 'active')
        self.assertIn('100 Mbps', text)
        self.assertIn('80 Mbps', text)
        self.assertNotIn('已关闭', text)

    def test_policy_values_and_thresholds_are_event_evidence(self):
        alert = self.alert('ops_policy_signal')
        alert['details_json'] = json.dumps({'observation': {'signals': {'connections':True},
            'values': {'connections':1234}, 'thresholds': {'connections':500}}})
        _, text = content.render(alert, 'active')
        self.assertIn('1,234 个，阈值 500 个', text)

    def test_partial_cleanup_has_actual_names_not_instance_deletion(self):
        details = {'automatic_remediation': {'attempted':True, 'succeeded':False,
            'message':'killed_processes=1 removed_configs=1 cleanup_errors=1',
            'items':[{'kind':'config','target':'/etc/xrayr/config.yml','status':'ok'},
                     {'kind':'service','target':'/etc/init.d/xrayr','status':'failed'}]}}
        text = content.execution_text(details)
        self.assertIn('未能全部完成', text)
        self.assertIn('/etc/xrayr/config.yml：完成', text)
        self.assertIn('/etc/init.d/xrayr：失败', text)
        self.assertNotIn('删除实例', text)

    def test_stop_instance_is_distinguished_from_service_cleanup(self):
        text = content.execution_text({}, {'status':'succeeded','action_type':'stop_container',
            'result_message':'stopped','params_json':'{}'})
        self.assertIn('停止该实例，未删除实例', text)

    def test_unknown_auth_never_claims_empty_password_or_cleanup(self):
        _, text = content.render(self.alert(), 'active')
        self.assertIn('认证设置尚未确认', text)
        self.assertNotIn('没有密码', text)
        self.assertNotIn('执行处理', text)

    def test_service_listeners_do_not_use_instance_all_ports(self):
        details = {'listening_ports':[22,80,1080], 'service_listeners':[
            {'process':'danted','pid':21,'local':'0.0.0.0:1080','port':1080}]}
        self.assertIn('1080', content.listener_text(details))
        self.assertNotIn(':22', content.listener_text(details))
        self.assertNotIn(':80', content.listener_text(details))

    def test_failed_action_overrides_earlier_success(self):
        details = {'automatic_remediation': {'attempted':True,'succeeded':True,'message':'killed_processes=1'}}
        text = content.execution_text(details, {'status':'failed','action_type':'enforce_socks_auth','result_message':'remaining_processes=1'})
        self.assertIn('未能全部完成', text)
        self.assertNotIn('停止进程 1', text)

    def test_sensitive_text_and_untrusted_receipts_are_sanitized(self):
        self.assertNotIn('example-secret', content.clean('token=example-secret\x1b[31m'))
        self.assertEqual(content.receipt_items([{'kind':'config','target':'password=example-secret','status':'ok'}]), [])
        text = content.execution_text({'automatic_remediation': {'attempted':True,'succeeded':True,
            'message':'@@NW_ACTION\tconfig\tpassword=example-secret\tok'}})
        self.assertNotIn('example-secret', text)

    def test_help_footer_survives_long_content_and_invalid_time(self):
        a = self.alert('unknown', message='x'*10000)
        a['last_seen'] = 1e300
        _, text = content.render(a, 'resolved', node='N'*10000)
        self.assertLessEqual(len(text),1800)
        self.assertTrue(text.endswith('如有其他疑问，请发工单。'))
        self.assertIn('尚未验证', text)


class BandwidthEvidenceTests(unittest.TestCase):
    setUp = existing.OperationsTests.setUp
    tearDown = existing.OperationsTests.tearDown
    data = existing.OperationsTests.data
    ingest = existing.OperationsTests.ingest

    def configure(self):
        self.conn.execute('INSERT INTO ops_policies VALUES(?,?,?,?)',
            (self.entity,'general',json.dumps({'bandwidth_mbps':100}),self.now))

    def sample(self, offset, rate=95, epoch='a', available=True):
        amount = 100 + offset*rate*1e6/8
        return self.ingest(self.now+offset,self.data(amount,amount,epoch=epoch,available=available))

    def test_sustained_capacity_requires_counter_evidence_and_ten_minutes(self):
        self.configure()
        self.sample(0)
        self.assertNotIn('ops_bandwidth_saturation',[a['type'] for a in self.sample(300)])
        alerts = self.sample(600)
        alert = next(a for a in alerts if a['type']=='ops_bandwidth_saturation')
        self.assertEqual(alert['observation']['covered_seconds'],600)
        self.assertAlmostEqual(alert['observation']['rate_mbps'],95)
        self.assertEqual(alert['severity'],'warning')
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM security_actions').fetchone()[0],0)
        for offset in (900,1200,1500,1800): alerts = self.sample(offset)
        self.assertEqual(next(a for a in alerts if a['type']=='ops_bandwidth_saturation')['severity'],'critical')

    def test_unknown_capacity_and_host_capacity_do_not_guess(self):
        self.conn.execute('INSERT INTO ops_policies VALUES(?,?,?,?)',
            (ops.identity('node'),'general',json.dumps({'bandwidth_mbps':100}),self.now))
        for offset in (0,300,600,900):
            self.assertNotIn('ops_bandwidth_saturation',[a['type'] for a in self.sample(offset)])

    def test_gap_reset_and_estimate_restart_duration(self):
        self.configure()
        for offset in (0,300,600): self.sample(offset)
        alerts = self.sample(1800)
        self.assertTrue(next(a for a in alerts if a['type']=='ops_bandwidth_saturation')['data_stale'])
        self.sample(2100,epoch='b')
        self.sample(2400,available=False)
        self.sample(2700)
        state = json.loads(self.conn.execute('SELECT payload FROM ops_meter').fetchone()[0])
        self.assertEqual(state['bandwidth']['covered_seconds'],0)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_incidents WHERE kind='bandwidth_saturation'").fetchone()[0],'open')

    def test_full_duplex_directions_are_not_added(self):
        self.configure()
        for offset in (0,300,600,900):
            self.assertNotIn('ops_bandwidth_saturation',[a['type'] for a in self.sample(offset,rate=60)])

    def test_low_rate_proves_recovery_and_duplicates_do_not_extend(self):
        self.configure()
        for offset in (0,300,600): self.sample(offset)
        self.sample(600)
        state = json.loads(self.conn.execute('SELECT payload FROM ops_meter').fetchone()[0])
        self.assertEqual(state['bandwidth']['covered_seconds'],600)
        amount = 100 + 600*95*1e6/8
        self.ingest(self.now+900,self.data(amount,amount))
        self.assertEqual(self.conn.execute("SELECT status FROM ops_incidents WHERE kind='bandwidth_saturation'").fetchone()[0],'resolved')

    def test_policy_saves_values_and_effective_thresholds(self):
        alerts = self.ingest(self.now,self.data(connections=1234))
        obs = next(a for a in alerts if a['type']=='ops_policy_signal')['observation']
        self.assertEqual(obs['values']['connections'],1234)
        self.assertEqual(obs['thresholds']['connections'],500)

    def test_actual_connection_stop_has_deduplicated_receipt(self):
        params = json.dumps({'reason':'sustained_connection_overload','connection_count':1800,'threshold':1500,'duration_seconds':3600})
        self.conn.execute("INSERT INTO security_actions(id,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at,result_message) VALUES(1,0,'h','incus','default','c','stop_container',?,'succeeded','system:connection-guard',?,?,'stopped')",(params,self.now,self.now))
        ops.record_connection_guard(self.conn,1,self.now)
        ops.record_connection_guard(self.conn,1,self.now)
        rows = self.conn.execute("SELECT * FROM security_alerts WHERE alert_type='ops_connection_guard'").fetchall()
        self.assertEqual(len(rows),1)
        _, text = buyer.render(rows[0], 'awaiting_report', conn=self.conn)
        self.assertIn('停止该实例，未删除实例',text)
        self.assertIn('1,800 个',text)
        self.assertIn('60 分钟',text)


class BuyerMappingEvidenceTests(unittest.TestCase):
    setUp = existing.OperationsTests.setUp
    tearDown = existing.OperationsTests.tearDown
    VM = '00000000-0000-0000-0000-000000000010'
    MACHINE = '00000000-0000-0000-0000-000000000020'

    def report(self, host='h', project='default', name=None):
        self.conn.execute('INSERT INTO reports(host_id,runtime,project,container_name,cpu_percent,mem_bytes,net_rx_bps,net_tx_bps,conn_count,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json) VALUES(?,?,?,?,0,0,0,0,0,1,1,?,?)',
            (host,'incus',project,name or self.VM,self.now,'{}'))

    def vm(self, **extra):
        return {'id':self.VM,'machine_id':self.MACHINE,'runtime':'incus','user_id':'buyer1','status':'running','node_name':'香港','bandwidth_mbps':100,**extra}

    def test_exact_uuid_mapping_has_server_name_capacity_and_no_broadcast(self):
        self.report()
        result = mapping.apply(self.conn,[self.vm()],self.now)
        self.assertEqual(result['matched'],1)
        row = self.conn.execute('SELECT * FROM buyer_targets').fetchone()
        self.assertEqual(row['scope'],'user')
        self.assertEqual(row['node_name'],'香港')
        self.assertEqual(row['bandwidth_mbps'],100)
        self.assertIsNone(buyer.target(self.conn,row,self.now+901))

    def test_duplicate_local_uuid_is_not_guessed(self):
        self.report()
        self.report(host='h2')
        result = mapping.apply(self.conn,[self.vm()],self.now)
        self.assertEqual(result['unmatched'],2)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM buyer_targets').fetchone()[0],0)

    def test_duplicate_upstream_uuid_and_runtime_mismatch_reject(self):
        self.report()
        self.assertEqual(mapping.apply(self.conn,[self.vm(),self.vm()],self.now)['unmatched'],1)
        self.assertEqual(mapping.apply(self.conn,[self.vm(runtime='podman')],self.now)['unmatched'],1)

    def test_disabled_manual_target_is_preserved(self):
        self.report()
        buyer.save_target(self.conn,dict(host_id='h',runtime='incus',project='default',container_name=self.VM,
            machine_id=self.MACHINE,user_id='manual-buyer',scope='user',enabled=False))
        self.assertEqual(mapping.apply(self.conn,[self.vm()],self.now)['manual'],1)
        row = self.conn.execute('SELECT * FROM buyer_targets').fetchone()
        self.assertEqual(row['user_id'],'manual-buyer')
        self.assertEqual(row['enabled'],0)

    def test_deleted_vm_disables_previous_mapping(self):
        self.report()
        mapping.apply(self.conn,[self.vm()],self.now)
        mapping.apply(self.conn,[],self.now+1)
        self.assertEqual(self.conn.execute('SELECT enabled FROM buyer_targets').fetchone()[0],0)

    def test_incomplete_and_failed_catalog_never_applies(self):
        cfg = {'api_url':'https://api.example.com/v1','api_key':'fake-only'}
        response = mock.MagicMock()
        opener = mock.Mock()
        opener.open.return_value = response
        for raw in (b'{"success":false,"data":{}}',b'{"data":{"machines":[],"total":1}}'):
            response.__enter__.return_value.read.return_value = raw
            with self.assertRaises(ValueError):
                mapping.fetch_catalog(cfg,lambda value,**kw:value,lambda:opener)


class AgentEvidenceTests(unittest.TestCase):
    def test_socket_listener_has_actual_process_owner(self):
        snapshot = '@@SS_AVAILABLE@@\ntcp LISTEN 0 4096 0.0.0.0:1080 0.0.0.0:* users:(("danted",pid=42,fd=8))\ntcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=88,fd=9))\n'
        with mock.patch.object(agent,'run',return_value=snapshot):
            result = agent._collect_socket_process_details('incus','c','default',[1080,80])
        self.assertEqual([(i['process'],i['port']) for i in result['service_listeners']],[('danted',1080),('nginx',80)])

    def test_http_host_observation_contains_count_and_actual_source(self):
        alerts = agent._http_security_alerts({'requests':80,'top_ip':'192.0.2.1','top_ip_requests_per_second':40})
        alert = next(a for a in alerts if a['type']=='cc_single_ip')
        self.assertEqual(alert['observation']['http_requests'],80)
        self.assertEqual(alert['observation']['source_ip'],'192.0.2.1')

    def test_receipt_parser_preserves_per_item_outcomes(self):
        items = agent._cleanup_items('@@NW_ACTION\tconfig\t/etc/xrayr/config.yml\tok\n@@NW_ACTION\tservice\t/etc/init.d/xrayr\tfailed')
        self.assertEqual(len(items),2)
        self.assertEqual(items[-1]['status'],'failed')

    def test_release_failure_keeps_real_throttle_state(self):
        state = {'is_throttled':True,'consecutive_violation_count':3,'reason':'test'}
        with mock.patch.dict(agent._hy2_throttle_states,{'podman::c':state},clear=True), mock.patch.object(agent,'release_udp_throttle',return_value=(False,'failed')):
            ok,_ = agent.execute_security_action({'action_type':'release_udp_throttle','runtime':'podman','container_name':'c'})
            self.assertFalse(ok)
            self.assertTrue(state['is_throttled'])

    @unittest.skipUnless(os.name=='posix','POSIX shell validation')
    def test_receipt_shell_has_portable_syntax(self):
        result = subprocess.run(['sh','-n','-c',agent._cleanup_receipt_shell()+' nw_receipt config /etc/example ok'],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
