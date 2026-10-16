"""Synthetic credentials only. No network, real notices, or service stops."""
import asyncio
import json
import time
import unittest
import shutil
import subprocess
from pathlib import Path
from unittest import mock
from starlette.requests import Request
from client import agent, socks_detector as detector, security_banner as banner
from server import buyer_notifications as buyer
from tests import test_buyer_notifications as fixtures
server = fixtures.server


class PasswordFactsTests(unittest.TestCase):
    def test_counts_without_characters_or_order(self):
        result = detector.password_profile('Aa1112!!')
        self.assertEqual(result, {'available': True, 'length': 8, 'lowercase': 1, 'uppercase': 1,
            'digits': 4, 'symbols': 2, 'other': 0, 'repeated_digits': 2,
            'max_digit_frequency': 3, 'longest_identical_run': 3})
        self.assertNotIn('Aa1112!!', json.dumps(result))
        self.assertEqual(detector.password_profile('')['length'], 0)
        self.assertFalse(detector.password_profile('${SECRET}')['available'])
        self.assertFalse(detector.password_profile('x'*4097)['available'])

    def test_gost_json_and_yaml_are_inbound_only(self):
        for raw in [json.dumps({'services':[{'addr':':6987','handler':{'type':'socks5','auth':{'username':'private-user','password':'Aa1112!!'}}}],
                               'chains':[{'password':'outbound-secret'}]}),
                    'services:\n- addr: ":6987"\n  handler:\n    type: socks5\n    auth:\n      username: private-user\n      password: "Aa1112!!"\n']:
            result = detector.parse_config(raw, 'gost')
            self.assertTrue(result['single_purpose'])
            self.assertEqual(result['endpoints'][0]['auth_state'], 'unknown')
            self.assertEqual(result['endpoints'][0]['password_profiles'][0]['length'], 8)
            for secret in ['Aa1112!!','private-user','outbound-secret']:
                self.assertNotIn(secret, json.dumps(result))

    def test_gost_cli_ignores_forward_chain(self):
        result = detector.gost_cli('27 S gost /usr/bin/gost -L socks5://fixture:Aa1112%21%21@:6987 -F socks5://fixture:OUTBOUND@127.0.0.1:1080', 27)
        self.assertEqual(result['endpoints'][0]['password_profiles'][0]['symbols'], 2)
        self.assertNotIn('OUTBOUND', json.dumps(result))
        self.assertIsNone(detector.gost_cli('27 S gost /usr/bin/gost -F socks5://fixture:OUTBOUND@:1080',27))

    def test_hashes_external_and_aliases_remain_unavailable(self):
        for process in ['danted', 'sockd']:
            self.assertFalse(detector.legacy_profiles('socksmethod: pam',process)[0]['available'])
        self.assertFalse(detector.legacy_profiles('users fixture:CR:hashed-secret','3proxy')[0]['available'])
        result = detector.parse_config('services: &a [*a]', 'gost')
        self.assertFalse(result['parsed'])
        self.assertEqual(detector.process_configs('27 S gost /usr/bin/gost -C /etc/gost/config.yaml')[0]['paths'],['/etc/gost/config.yaml'])

    def test_live_review_separate_from_probe_failure_and_no_automatic_stop(self):
        socks = {'process_matches':[{'pid':27,'process':'gost','config_scoped':True}],
            'inbound_endpoints':[{'pid':27,'port':6987,'listen':'*','auth_state':'unknown','action_safe':True,
                                 'password_profiles':[detector.password_profile('Aa1112!!')]}],
            'review_processes':[{'pid':27,'start_ticks':'123','sources':[]}]}
        listeners = [{'pid':27,'port':6987,'local':'*:6987','proto':'tcp'}]
        with mock.patch.object(agent,'_probe_socks_listener',return_value={'mode':'auth_required','reason':'fixture'}):
            agent._refine_socks_listener_evidence(socks,listeners,[],'/usr/bin/podman','fixture','',222)
        self.assertTrue(socks['password_review'][0]['action_safe'])
        self.assertEqual(socks['auth_mode'],'unknown')
        with mock.patch.object(agent,'stop_unauthenticated_socks') as stop:
            agent.enforce_socks_auth_policy({'runtime':'podman','name':'fixture','security':{'socks_proxy':socks}},[])
        stop.assert_not_called()
        with mock.patch.object(agent,'_probe_socks_listener',return_value={'mode':'unknown','reason':'timeout'}):
            agent._refine_socks_listener_evidence(socks,listeners,[],'/usr/bin/podman','fixture','',222)
        self.assertEqual(socks['password_review'], [])

    def test_manual_stop_revalidates_and_does_not_forge_weak_auth(self):
        action = {'runtime':'podman','container_name':'fixture','project':'','params':{
            'manual_review':True,'review_token':'a'*64,'review_observed_at':int(time.time())}}
        facts={'review_token':'a'*64,'password_review':[{'pid':27,'process':'gost','action_safe':True,'start_ticks':'123'}]}
        with mock.patch.object(agent,'get_runtime_bins',return_value={'podman':'/usr/bin/podman'}), \
             mock.patch.object(agent,'run',return_value='222'), \
             mock.patch.object(agent,'collect_panel_pairing_indicators',return_value={'socks_proxy':facts}), \
             mock.patch.object(agent,'_collect_socket_security',return_value={}), \
             mock.patch.object(agent,'_collect_socket_process_details',return_value={}), \
             mock.patch.object(agent,'_refine_socks_listener_evidence'), \
             mock.patch.object(agent,'_stop_scoped_socks',return_value=(True,'fixture stopped')) as stop:
            self.assertTrue(agent.stop_reviewed_socks(action)[0])
            self.assertNotIn('auth_mode', stop.call_args[0][0]['params'])
            self.assertEqual(stop.call_args[0][0]['params']['process_pids'],[27])
            stop.reset_mock(); facts['review_token']='b'*64
            self.assertFalse(agent.stop_reviewed_socks(action)[0]); stop.assert_not_called()
            facts['review_token']='a'*64; facts['password_review'][0]['action_safe']=False
            self.assertFalse(agent.stop_reviewed_socks(action)[0]); stop.assert_not_called()
            action['params']['review_observed_at']=0
            self.assertFalse(agent.stop_reviewed_socks(action)[0]); stop.assert_not_called()

    def test_reviewed_stop_script_generation_guard_and_no_unsafe_fallback(self):
        action={'runtime':'incus','container_name':'fixture','project':'default','params':{
            'process_names':['gost'],'process_pids':[27],'process_starts':{'27':'12345'}}}
        with mock.patch.object(agent,'get_runtime_bins',return_value={'incus':'incus'}), \
             mock.patch.object(agent,'_run_action_command',return_value=(False,'generation mismatch')) as execute, \
             mock.patch.object(agent,'_incus_host_namespace_kill') as fallback:
            self.assertFalse(agent._stop_scoped_socks(action)[0]); fallback.assert_not_called()
            script=execute.call_args[0][0][-1]
        self.assertIn('/proc/27/stat',script)
        self.assertIn('12345',script)
        shell=shutil.which('sh') or ('C:/Program Files/Git/bin/bash.exe' if Path('C:/Program Files/Git/bin/bash.exe').is_file() else '')
        if shell:
            result=subprocess.run([shell,'-n'],input=script,text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)


class UserNoticeTests(unittest.TestCase):
    setUp = fixtures.BuyerTests.setUp
    tearDown = fixtures.BuyerTests.tearDown
    ingest = fixtures.BuyerTests.ingest
    mapping = fixtures.BuyerTests.mapping

    def queue(self, mapped=True, request_id='a'*32):
        self.alert.update(type='socks_password_review',socks_processes=['gost'],
            password_review=[{'password_profiles':[detector.password_profile('Aa1112!!')]}])
        if mapped:
            self.mapping()
        self.ingest()
        with server.db() as conn:
            a=conn.execute('SELECT id FROM security_alerts').fetchone()[0]
            preview=buyer.notice_preview(conn,a)
            self.assertIn(preview['telegram'], {'ready','blocked'})
            self.assertEqual(preview['banner'],'ready')
            self.assertNotIn('Aa1112!!',preview['message'])
            self.assertNotIn('password_profiles',preview['message'])
            payload={'confirm':True,'request_id':request_id,'preview_token':preview['preview_token']}
            result=buyer.queue_user_notice(conn,a,payload,'admin')
            return a, payload, result

    def test_queue_no_send_idempotent_and_channel_receipts(self):
        with mock.patch.object(buyer,'deliver') as send:
            a,payload,result=self.queue()
            send.assert_not_called()
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM buyer_outbox').fetchone()[0],0)
        with server.db() as conn:
            self.assertTrue(buyer.queue_user_notice(conn,a,payload,'admin')['duplicate'])
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM buyer_user_notices').fetchone()[0],1)
            states=buyer.banner_states(conn,'host')
            manual=next(s for s in states if s['type']=='user_notice')
            self.assertEqual(manual['event_id'],'NOTICE-'+result['id'])
        sender=mock.Mock(return_value=('succeeded',200))
        buyer.work_user_notices(server.db,self.now,sender)
        self.assertEqual(sender.call_args[0][3],'user')
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT telegram_status,banner_status FROM buyer_user_notices').fetchone()[:],('succeeded','queued'))
            c={**self.c,'security':{'motd_delivery':{'status':'written','notice_ids':['NOTICE-'+result['id']]}}}
            buyer.observe(conn,'host',self.now,[c],[self.alert])
            self.assertEqual(conn.execute('SELECT banner_status FROM buyer_user_notices').fetchone()[0],'written')

    def test_missing_mapping_never_becomes_broadcast_or_new_recipient(self):
        self.queue(False)
        self.mapping(user='new-user')
        sender=mock.Mock()
        buyer.work_user_notices(server.db,self.now,sender)
        sender.assert_not_called()
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT telegram_status,banner_status FROM buyer_user_notices').fetchone()[:],('blocked','queued'))

    def test_changed_recipient_rejects_preview_and_blocks_queued_delivery(self):
        a,payload,_=self.queue()
        self.mapping(user='changed-user')
        with server.db() as conn:
            with self.assertRaises(ValueError):
                buyer.queue_user_notice(conn,a,{**payload,'request_id':'b'*32},'admin')
        sender=mock.Mock()
        buyer.work_user_notices(server.db,self.now,sender); sender.assert_not_called()
        with server.db() as conn:
            self.assertFalse(any(n['type']=='user_notice' for n in buyer.banner_states(conn,'host')))

    def test_container_recreation_cancels_both_pending_channels(self):
        self.mapping(); self.ingest()
        with server.db() as conn:
            conn.execute("INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,ts,payload_json,podman_network_ok_v4,podman_network_ok_v6) VALUES('host','c1','incus','default',0,0,0,0,0,0,?,?,1,1)",(self.now,json.dumps({'id':'original-instance'})))
        self.queue()
        with server.db() as conn:
            conn.execute("UPDATE reports SET payload_json=?",(json.dumps({'id':'new-instance'}),))
            self.assertFalse(any(n['type']=='user_notice' for n in buyer.banner_states(conn,'host')))
        sender=mock.Mock()
        buyer.work_user_notices(server.db,self.now,sender); sender.assert_not_called()
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT telegram_status,banner_status FROM buyer_user_notices').fetchone()[:],('cancelled','cancelled'))

    def test_machine_broadcast_mapping_does_not_authorize_user_notice(self):
        self.mapping(scope='machine',confirm_broadcast=True)
        self.queue(False)
        sender=mock.Mock()
        buyer.work_user_notices(server.db,self.now,sender); sender.assert_not_called()
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT user_id,telegram_status FROM buyer_user_notices').fetchone()[:],('','blocked'))

    def test_uncertain_is_not_retried_and_banner_independent(self):
        self.queue()
        sender=mock.Mock(side_effect=TimeoutError())
        buyer.work_user_notices(server.db,self.now,sender)
        buyer.work_user_notices(server.db,self.now+300,sender)
        self.assertEqual(sender.call_count,1)
        with server.db() as conn:
            self.assertEqual(conn.execute('SELECT telegram_status,banner_status FROM buyer_user_notices').fetchone()[:],('uncertain','queued'))

    def test_role_and_manual_review_endpoint(self):
        self.assertTrue(server.operations.permitted('operator','POST','/api/v1/security/alerts/1/notify-user'))
        self.assertFalse(server.operations.permitted('viewer','POST','/api/v1/security/alerts/1/notify-user'))
        self.alert.update(type='socks_password_review', review_observed_at=self.now,review_token='a'*64,
            password_review=[{'pid':27,'process':'gost','action_safe':True}])
        self.ingest()
        with server.db() as conn:
            a=conn.execute('SELECT id FROM security_alerts').fetchone()[0]
        async def call(token):
            async def receive(): return {'type':'http.request','body':json.dumps({'decision':'stop_reviewed_socks','review_token':token}).encode()}
            request=Request({'type':'http','method':'POST','headers':[],'state':{'dashboard_user':'admin'}},receive)
            return await server.set_security_alert_disposition(a,request)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException): asyncio.run(call('b'*64))
        result=asyncio.run(call('a'*64))
        self.assertEqual(result.status_code,202)
        with server.db() as conn:
            action=conn.execute("SELECT action_type,params_json FROM security_actions WHERE action_type='stop_reviewed_socks'").fetchone()
            self.assertTrue(json.loads(action['params_json'])['manual_review'])


class UserBannerTests(unittest.TestCase):
    setUp=fixtures.BannerTests.setUp
    tearDown=fixtures.BannerTests.tearDown

    def test_manual_message_written_without_local_alert_then_expires(self):
        now=int(time.time())
        notice={'type':'user_notice','runtime':'incus','project':'default','name':'c1',
            'event_id':'NOTICE-'+'a'*32,'created_at':now,'updated_at':now,'expires_at':now+86400,
            'title':'服务器安全提醒','message':'请检查代理设置。\n如有疑问，请发工单。'}
        with mock.patch.object(banner,'install_shell',return_value=(True,True)) as install, \
             mock.patch.object(banner,'write_proc',return_value=True):
            banner.update(self.c,[],set(),lambda *_:(True,''),[notice],'test')
            self.assertIn('NOTICE-'+'a'*32,self.c['security']['motd_delivery']['notice_ids'])
            rendered=banner.render('c1',install.call_args[0][1])
            self.assertIn('请检查代理设置',rendered)
            banner.update(self.c,[],set(),lambda *_:(True,''),[notice],'test')
            self.assertEqual(len(banner.select_entries(install.call_args[0][1])),1)
            notice['expires_at']=now-1
            banner.update(self.c,[],set(),lambda *_:(True,''),[notice],'test')
            self.assertEqual(self.c['security']['motd_delivery']['notice_ids'],[])

    def test_old_container_notice_is_not_rendered_on_replacement(self):
        now=int(time.time())
        notice={'type':'user_notice','runtime':'incus','project':'default','name':'c1',
            'event_id':'NOTICE-'+'a'*32,'expected_container_id':'different-instance',
            'updated_at':now,'expires_at':now+100,'message':'old owner notice'}
        with mock.patch.object(banner,'install_shell',return_value=(True,True)),mock.patch.object(banner,'write_proc',return_value=True):
            banner.update(self.c,[],set(),lambda *_:(True,''),[notice],'test')
            self.assertEqual(self.c['security']['motd_delivery']['notice_ids'],[])


if __name__ == '__main__': unittest.main()
