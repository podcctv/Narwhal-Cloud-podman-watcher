import asyncio
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
from server import buyer_notifications as buyer
from client import security_banner as banner

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("buyer_test_server",ROOT/"server/app.py")
server=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)
MACHINE="00000000-0000-0000-0000-000000000001"


class BuyerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.connections=[]
        original_db=server.db
        def tracked_db():
            conn=original_db()
            self.connections.append(conn)
            return conn
        self.db_patch=mock.patch.object(server,"db",side_effect=tracked_db)
        self.db_patch.start()
        server.DB_PATH=str(Path(self.tmp.name)/"monitor.db")
        server.init_db()
        self.now=int(time.time())
        self.alert={"type":"socks_weak_auth","severity":"critical","runtime":"incus","project":"default","container_name":"c1","title":"SOCKS 认证风险","message":"Detected, password=secret-value"}
        self.c={"runtime":"incus","project":"default","name":"c1","id":"container-id-1","security":{"socks_proxy":{"detected":False}}}
        with server.db() as conn:
            server._set_system_setting(conn,"narwhal_api_key","fake-key")
            server._set_system_setting(conn,"narwhal_api_url","https://api.example.com/v1")

    def tearDown(self):
        for conn in self.connections: conn.close()
        self.db_patch.stop()
        self.tmp.cleanup()

    def ingest(self, alerts=None, when=None, container=None):
        alerts=[self.alert] if alerts is None else alerts
        ts=when or self.now
        observed=container or self.c
        with server.db() as conn:
            conn.execute("INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("host",observed.get("name","c1"),observed.get("runtime","incus"),observed.get("project","default"),0,0,0,0,0,0,0,0,ts,json.dumps(observed)))
            server.process_security_alerts(conn,"host",ts,alerts)
            buyer.observe(conn,"host",ts,[observed],alerts)
            buyer.reconcile(conn,"host",ts)

    def mapping(self,name="c1",user="user-1",scope="user",**kw):
        with server.db() as conn:
            buyer.save_target(conn,{"host_id":"host","runtime":"incus","project":"default","container_name":name,"machine_id":MACHINE,"user_id":user,"node_name":kw.pop('node_name','Node'),"scope":scope,**kw})

    def rows(self):
        with server.db() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM buyer_outbox ORDER BY id")]

    def test_records_exposes_telegram_banner_backlog_and_recent_events(self):
        with server.db() as conn:
            conn.execute(
                "INSERT INTO buyer_user_notices(id,alert_id,host_id,runtime,project,container_name,subject,created_at,expires_at,telegram_status,banner_status) VALUES('live',7,'host','incus','default','c1','Notice',?,?, 'failed','written')",
                (self.now, self.now + 3600),
            )
            conn.execute(
                "INSERT INTO buyer_user_notices(id,alert_id,host_id,runtime,project,container_name,subject,created_at,expires_at,telegram_status,banner_status) VALUES('expired',8,'host','incus','default','c1','Expired',?,?, 'queued','queued')",
                (self.now - 7200, self.now - 1),
            )
            conn.execute(
                "INSERT INTO buyer_user_notice_events(notice_id,channel,status,attempt,ts,detail) VALUES('live','telegram','failed',2,?,'timeout')",
                (self.now,),
            )
            conn.execute(
                "INSERT INTO buyer_user_notice_events(notice_id,channel,status,attempt,ts,detail) VALUES('expired','banner','queued',0,?,'old')",
                (self.now - 7200,),
            )
            conn.commit()

        endpoint = next(route.endpoint for route in server.app.routes if getattr(route, "path", "") == "/api/v1/buyer/records")
        data = endpoint()
        self.assertEqual(data["notice_channel_counts"]["telegram"], {"failed": 1})
        self.assertEqual(data["notice_channel_counts"]["banner"], {"written": 1})
        self.assertEqual(len(data["notice_events"]), 1)
        self.assertEqual(data["notice_events"][0]["notice_id"], "live")

    def test_report_enqueues_only_and_missing_mapping_blocks(self):
        with mock.patch.object(buyer,"deliver") as send:
            self.ingest()
            self.ingest(when=self.now+10)
            self.assertEqual(len(self.rows()),1)
            self.assertEqual(self.rows()[0]["status"],"blocked")
            send.assert_not_called()
        self.assertNotIn("secret-value",self.rows()[0]["message"])

    def test_unattributed_connection_signal_is_protection_only(self):
        self.mapping()
        self.alert.update(type='container_connection_count', title='连接过多', value=1061, threshold=1000,
            connection_policy={'metric':'TCP 各状态 + UDP socket 总数','critical_duration_seconds':900,
                'stop_threshold':2000,'required_duration_seconds':300,'valid':True,'reason':'未达到停机门槛'})
        self.ingest()
        self.assertEqual(self.rows(), [])
        with server.db() as conn:
            alert_id=conn.execute("SELECT id FROM security_alerts WHERE alert_type='container_connection_count'").fetchone()[0]
            preview=buyer.notice_preview(conn,alert_id)
            self.assertTrue(preview['protection_only'])
            self.assertFalse(preview['can_submit'])
            with self.assertRaisesRegex(ValueError, '未通过应用或代理认证日志'):
                buyer.queue_user_notice(conn,alert_id,{
                    'request_id':'a'*32,'confirm':True,'preview_token':preview['preview_token']
                },'dashboard')

    def test_client_supplied_user_attribution_cannot_unlock_customer_notice(self):
        self.mapping()
        self.alert.update(type='container_connection_count', title='连接过多', value=1061, threshold=1000,
            user_attribution={'verified':True,'source':'application_auth_log','user_id':'user-1'})
        self.ingest()
        self.assertEqual(self.rows(), [])
        with server.db() as conn:
            alert_id=conn.execute("SELECT id FROM security_alerts WHERE alert_type='container_connection_count'").fetchone()[0]
            preview=buyer.notice_preview(conn,alert_id)
            self.assertTrue(preview['protection_only'])
            self.assertFalse(preview['can_submit'])

    def test_confirmed_vmess_block_sends_scoped_policy_advice_not_abuse_notice(self):
        self.mapping()
        self.alert.update(type='vmess_port_blocked', title='VMess 入站端口已自动阻断',
            message='仅阻断 TCP/443，未停止其他服务', value=1, threshold=0,
            instance_id='container-id-1',
            vmess_guard={'state':'blocked','blocked_endpoints':[
                {'proto':'tcp','port':443,'process':'xray','pid':120}], 'pending_endpoints':[]},
            automatic_remediation={'attempted':True,'succeeded':True})
        self.ingest()
        row=self.rows()[0]
        self.assertEqual(row['status'],'queued')
        self.assertEqual(row['scope'],'user')
        self.assertEqual(row['user_id'],'user-1')
        self.assertIn('incus/default/c1',row['message'])
        self.assertIn('实例 ID container-id',row['message'])
        self.assertIn('xray（容器内 PID 120）监听 TCP/443',row['message'])
        self.assertIn('VLESS + Reality + Vision',row['message'])
        self.assertIn('不是对您进行滥用定性',row['message'])
        with server.db() as conn:
            alert_id=conn.execute("SELECT id FROM security_alerts WHERE alert_type='vmess_port_blocked'").fetchone()[0]
            preview=buyer.notice_preview(conn,alert_id)
            self.assertTrue(preview['protection_only'])
            self.assertFalse(preview['can_submit'])
            with self.assertRaisesRegex(ValueError, '未通过应用或代理认证日志'):
                buyer.queue_user_notice(conn,alert_id,{
                    'request_id':'b'*32,'confirm':True,'preview_token':preview['preview_token']
                },'dashboard')

    def test_vmess_unverified_or_machine_scope_never_queues_customer_notice(self):
        self.mapping(scope='machine',confirm_broadcast=True)
        self.alert.update(type='vmess_port_blocked',title='VMess pending',message='pending',
            instance_id='container-id-1',
            vmess_guard={'state':'partial','blocked_endpoints':[
                {'proto':'tcp','port':443,'process':'xray','pid':120}], 'pending_endpoints':[{'port':8443}]},
            automatic_remediation={'attempted':True,'succeeded':False})
        self.ingest()
        self.assertEqual(self.rows(), [])

        self.alert.update(type='vmess_block_unverified', title='VMess unverified',
            vmess_guard={'state':'unverified','blocked_endpoints':[], 'pending_endpoints':[{'port':8443}]})
        self.ingest(when=self.now+1)
        self.assertEqual(self.rows(), [])

    def test_vmess_policy_notice_expires_before_customer_delivery(self):
        self.mapping()
        self.alert.update(type='vmess_port_blocked',title='VMess blocked',message='blocked',
            instance_id='container-id-1',
            vmess_guard={'state':'blocked','blocked_endpoints':[
                {'proto':'udp','port':443,'process':'sing-box','pid':122}], 'pending_endpoints':[]},
            automatic_remediation={'attempted':True,'succeeded':True})
        self.ingest()
        sender=mock.Mock(return_value=('succeeded',200))
        buyer.work_once(server.db,self.now+901,sender)
        sender.assert_not_called()
        self.assertEqual(self.rows()[0]['status'],'cancelled')

    def test_vmess_policy_notice_is_cancelled_if_container_identity_changes(self):
        self.mapping()
        self.alert.update(type='vmess_port_blocked',title='VMess blocked',message='blocked',
            instance_id='container-id-1',
            vmess_guard={'state':'blocked','blocked_endpoints':[
                {'proto':'tcp','port':443,'process':'xray','pid':120}], 'pending_endpoints':[]},
            automatic_remediation={'attempted':True,'succeeded':True})
        self.ingest()
        self.ingest([self.alert],self.now+10,{**self.c,'id':'replacement-id'})
        sender=mock.Mock(return_value=('succeeded',200))
        buyer.work_once(server.db,self.now+10,sender)
        sender.assert_not_called()
        self.assertEqual(self.rows()[0]['status'],'cancelled')

    def test_connection_guard_notice_is_neutral_and_not_cancelled_as_abuse(self):
        self.mapping()
        self.alert.update(type='container_connection_count', title='连接过多', value=2100, threshold=1000)
        self.ingest()
        identity=('host','incus','default','c1')
        params={'metric_epoch':'epoch-1','threshold':2000,'required_duration_seconds':300,
                'stop_since':self.now-300,'connection_count':2100,'duration_seconds':300,
                'sample_count':2,'max_gap_seconds':360,'duration_verified':True}
        with server.db() as conn:
            result=buyer.connection_stop_gate(conn,identity,params,self.now)
            self.assertEqual(result['status'],'queued')
            buyer.reconcile(conn,'host',self.now+1)
            notice=conn.execute('SELECT * FROM buyer_user_notices WHERE id=?',(result['notice_id'],)).fetchone()
            self.assertEqual(notice['telegram_status'],'queued')
            self.assertIn('不代表认定用户滥用',notice['message'])
            self.assertNotIn('检查代理账号',notice['message'])
            self.assertIn('2 次有效采样核验',notice['message'])
            self.assertIn('单次间隔不超过 360 秒',notice['message'])

    def test_persistent_dedup_and_machine_cooldown(self):
        self.mapping()
        self.mapping("c2")
        self.ingest()
        sender=mock.Mock(return_value=("succeeded",200))
        buyer.work_once(server.db,self.now,sender)
        self.assertEqual(sender.call_count,1)
        self.alert["container_name"]="c2"
        self.ingest(when=self.now+10,container={**self.c,"name":"c2"})
        buyer.work_once(server.db,self.now+10,sender)
        self.assertEqual(sender.call_count,1)
        with server.db() as conn:
            self.assertEqual(conn.execute("SELECT next_at FROM buyer_cooldowns").fetchone()[0],self.now+86400)

    def test_severity_change_cancels_old_snapshot(self):
        self.mapping()
        self.alert["severity"]="warning"
        self.ingest()
        self.alert["severity"]="critical"
        self.ingest(when=self.now+10)
        self.assertEqual(self.rows()[0]["status"],"cancelled")
        sender=mock.Mock(return_value=("succeeded",200))
        buyer.work_once(server.db,self.now+10,sender)
        self.assertEqual(sender.call_count,1)
        self.assertIn("服务器",sender.call_args.args[5])
        self.assertEqual(self.rows()[-1]['severity'], 'critical')

    def test_closed_alert_is_not_claimed_verified(self):
        self.assertNotIn("消失",buyer.STATES["resolved"])
        self.assertIn("未验证",buyer.STATES["resolved"])

    def test_client_image_copies_imported_modules(self):
        dockerfile=(ROOT/"client/Dockerfile").read_text()
        for module in ("agent.py","operations.py","security_banner.py"):
            self.assertIn(f"COPY {module} .",dockerfile)

    def test_transient_5xx_retries_unchanged_alert_with_bound(self):
        self.mapping()
        self.ingest()
        sender=mock.Mock(side_effect=urllib.error.HTTPError("https://api.example.com",503,"unavailable",{},None))
        ts=self.now
        for _ in range(5):
            buyer.work_once(server.db,ts,sender)
            ts=self.rows()[0]["due_at"]
        self.assertEqual(sender.call_count,5)
        self.assertEqual(self.rows()[0]["status"],"failed")

    def test_429_respects_retry_after(self):
        self.mapping(); self.ingest()
        sender=mock.Mock(side_effect=urllib.error.HTTPError("https://api.example.com",429,"limited",{"Retry-After":"1200"},None))
        buyer.work_once(server.db,self.now,sender)
        self.assertEqual(self.rows()[0]["due_at"],self.now+1200)
        self.assertEqual(self.rows()[0]["status"],"retrying")

    def test_401_not_retried_and_error_is_redacted(self):
        self.mapping(); self.ingest()
        sender=mock.Mock(side_effect=urllib.error.HTTPError("https://key.example.com",401,"secret-key",{},io.BytesIO(b"secret-body")))
        buyer.work_once(server.db,self.now,sender)
        self.assertEqual(self.rows()[0]["status"],"failed")
        self.assertEqual(self.rows()[0]["last_error"],"上游 HTTP 401")

    def test_timeout_is_uncertain_never_blindly_retried(self):
        self.mapping(); self.ingest()
        sender=mock.Mock(side_effect=TimeoutError())
        buyer.work_once(server.db,self.now,sender)
        buyer.work_once(server.db,self.now+90000,sender)
        self.assertEqual(sender.call_count,1)
        self.assertEqual(self.rows()[0]["status"],"uncertain")

    def test_crashed_sending_lease_is_uncertain(self):
        self.mapping(); self.ingest()
        with server.db() as conn: conn.execute("UPDATE buyer_outbox SET status='sending',updated_at=?",(self.now-200,))
        sender=mock.Mock()
        buyer.work_once(server.db,self.now,sender)
        sender.assert_not_called()
        self.assertEqual(self.rows()[0]["status"],"uncertain")

    def test_recovery_cancels_stale_active_and_requires_two_fresh_samples(self):
        self.mapping(); self.ingest()
        self.ingest([],self.now+10)
        self.assertEqual(self.rows()[0]["status"],"cancelled")
        self.assertEqual(self.rows()[-1]["state"],"awaiting_report")
        self.ingest([],self.now+10)
        self.assertEqual(self.rows()[-1]["state"],"awaiting_report")
        self.ingest([],self.now+20)
        self.assertEqual(self.rows()[-1]["state"],"verified")

    def test_unknown_auth_does_not_verify(self):
        self.mapping(); self.ingest()
        c={**self.c,"security":{"socks_proxy":{"detected":True,"auth_mode":"unknown"}}}
        self.ingest([],self.now+10,c); self.ingest([],self.now+20,c)
        self.assertEqual(self.rows()[-1]["state"],"unverified")

    def test_successful_execution_does_not_claim_verified(self):
        self.alert["automatic_remediation"]={"attempted":True,"succeeded":True}
        self.mapping(); self.ingest()
        first=self.rows()[0]["event_key"]
        self.ingest(when=self.now+10)
        self.assertEqual(len(self.rows()),1)
        self.assertEqual(self.rows()[0]["event_key"],first)
        self.assertEqual(self.rows()[0]["state"],"awaiting_report")

    def test_scope_requires_explicit_broadcast_confirmation(self):
        with self.assertRaises(ValueError): self.mapping(scope="machine")
        with self.assertRaises(ValueError): self.mapping(user="")
        self.mapping(scope="machine",confirm_broadcast=True)

    def test_mapping_change_before_delivery_uses_new_recipient(self):
        self.mapping(); self.ingest(); self.mapping(user="user-2")
        sender=mock.Mock(return_value=("succeeded",200))
        buyer.work_once(server.db,self.now,sender)
        self.assertEqual(sender.call_args.args[2],"user-2")

    def test_runtime_and_project_do_not_share_mapping(self):
        self.mapping(); self.alert["project"]="other"; self.ingest(container={**self.c,"project":"other"})
        self.assertEqual(self.rows()[0]["status"],"blocked")

    def test_digest_acknowledges_only_included_events(self):
        self.alert['type'] = 'unclassified_service_attention'
        for n in range(5):
            self.mapping(f"c{n}", node_name='香港服务器'*16)
            self.alert["container_name"]=f"c{n}"
            self.alert["message"]="x"*1000
            self.ingest(container={**self.c,"name":f"c{n}"})
        sender=mock.Mock(return_value=("succeeded",200))
        buyer.work_once(server.db,self.now,sender)
        self.assertLessEqual(len(sender.call_args.args[5]),2000)
        self.assertLess(sum(r["status"]=="succeeded" for r in self.rows()),5)

    def test_preview_never_calls_upstream(self):
        sender=mock.Mock()
        p=buyer.test_notification(server.db,{},sender)
        self.assertTrue(p["preview"]); sender.assert_not_called()
        self.assertEqual(self.rows(),[])

    def test_delivery_identifies_application_and_preserves_scoped_payload(self):
        response=mock.MagicMock()
        response.__enter__.return_value.status=200
        response.__enter__.return_value.read.return_value=b'{"data":{"notified":1}}'
        opener=mock.Mock()
        opener.open.return_value=response
        with mock.patch.object(buyer,"validate_url",return_value="https://api.example.com/v1"), mock.patch.object(buyer.urllib.request,"build_opener",return_value=opener), mock.patch.dict(os.environ,{"NARWHAL_VERSION":"test-version"}):
            self.assertEqual(buyer.deliver({"api_url":"https://api.example.com/v1","api_key":"fake-key"},MACHINE,"user-1","user","subject","message","batch"),("succeeded",200))
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"),"Narwhal-Monitor/test-version")
        self.assertEqual(request.get_header("Accept"),"application/json")
        self.assertEqual(json.loads(request.data)["user_id"],"user-1")

    def test_real_test_requires_audience_and_is_persisted(self):
        payload={"narwhal_machine_id":MACHINE,"user_id":"user-1","send":True}
        with self.assertRaises(ValueError): buyer.test_notification(server.db,payload,mock.Mock())
        payload["confirm_audience"]=f"机器 {MACHINE} / 用户 user-1"
        sender=mock.Mock(return_value=("succeeded",200))
        self.assertTrue(buyer.test_notification(server.db,payload,sender)["ok"])
        self.assertEqual(self.rows()[0]["state"],"test")
        self.assertEqual(buyer.test_notification(server.db,payload,sender)["status_code"],429)
        self.assertEqual(sender.call_count,1)

    def test_url_and_rbac(self):
        for url in ("http://api.example.com","https://localhost","https://127.0.0.1","https://[::1]","https://user:secret@api.example.com","https://api.example.com/?token=secret"):
            with self.assertRaises(ValueError): buyer.validate_url(url)
        self.assertFalse(server.operations.permitted("viewer","GET","/api/v1/buyer/records"))
        self.assertFalse(server.operations.permitted("operator","POST","/api/v1/buyer/targets"))

    def test_retention_and_expiry(self):
        self.ingest()
        with server.db() as conn:
            conn.execute("UPDATE buyer_outbox SET created_at=?",(self.now-8*86400,))
        buyer.work_once(server.db,self.now,mock.Mock())
        self.assertEqual(self.rows()[0]["status"],"expired")
        with server.db() as conn: conn.execute("UPDATE buyer_outbox SET updated_at=?",(self.now-91*86400,))
        buyer.work_once(server.db,self.now,mock.Mock())
        self.assertEqual(self.rows(),[])


class BannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.env=mock.patch.dict(os.environ,{"SECURITY_MOTD_STATE_FILE":str(Path(self.tmp.name)/"state.json"),"SECURITY_MOTD_COLOR":"false"})
        self.env.start(); banner.incidents.clear(); banner._checks.clear(); banner._loaded_path=""
        self.c={"runtime":"incus","project":"default","name":"c1","id":"container-1","pid":10000,"security":{"socks_proxy":{"detected":False}}}
        self.a=[{"type":"socks_weak_auth","severity":"warning","message":"no auth"}]

    def tearDown(self): banner.incidents.clear(); self.env.stop(); self.tmp.cleanup()

    def test_warning_not_compromised_and_verified_color(self):
        entry={"state":"awaiting_report","severity":"warning","detail":"x","type":"SOCKS"}
        text=banner.render("name",[entry],version="1.7.1")
        self.assertNotIn("COMPROMISED",text); self.assertNotIn("CRITICAL",text)
        self.assertIn("已执行处理，等待复查确认",text); self.assertNotIn("1.7.1",text)
        with mock.patch.dict(os.environ,{"TERM":"xterm","NO_COLOR":""}):
            entry["state"]="verified"
            self.assertIn("\033[32m",banner.render("name",[entry],color=True))

    def test_escape_sanitization_and_exact_original_preservation(self):
        text=banner.render("\x1b[31mname\x1b[0m",[{"detail":"\x1b]0;evil\x07token=secret-value\u202e","severity":"warning"}])
        self.assertNotIn("\x1b",text); self.assertNotIn("secret-value",text); self.assertNotIn("\u202e",text)
        original="\nWelcome\n\n  custom\t\n"
        self.assertEqual(banner.merge(banner.merge(original,"first"),""),original)
        with self.assertRaises(ValueError): banner.merge(banner.START+"broken","new")

    def test_narrow_terminal_chinese_width_and_english(self):
        text=banner.render("长名称"*30,[{"detail":"中文"*40}],width=40,language="en")
        self.assertIn("Status",text)
        self.assertNotIn("Target",text)
        for line in text.splitlines():
            import unicodedata
            self.assertLessEqual(sum(2 if unicodedata.east_asian_width(c) in {'W','F'} else 1 for c in line),40)

    def test_proc_failure_uses_checked_exec_and_reports_failure(self):
        execute=mock.Mock(return_value=(False,""))
        with mock.patch.object(banner,"write_proc",side_effect=PermissionError):
            self.assertFalse(banner.update(self.c,self.a,{"socks_weak_auth"},execute,[],"1.7.1"))
        self.assertEqual(self.c["security"]["motd_delivery"]["status"],"failed")
        self.assertTrue(Path(banner.state_path()).exists())

    def test_state_survives_restart_and_two_samples(self):
        execute=mock.Mock(return_value=(True,"printmotd yes"))
        with mock.patch.object(banner,"write_proc",return_value=True):
            banner.update(self.c,self.a,{"socks_weak_auth"},execute,[],"1.7.1")
            saved=json.loads(Path(banner.state_path()).read_text())
            ref=list(saved.values())[0][0]["event_id"]
            banner.incidents.clear(); banner._loaded_path=""
            banner.update(self.c,[],{"socks_weak_auth"},execute,[],"1.7.1")
            self.assertEqual(next(iter(banner.incidents.values()))[0]["event_id"],ref)
            banner.update(self.c,[],{"socks_weak_auth"},execute,[],"1.7.1")
            self.assertEqual(next(iter(banner.incidents.values()))[0]["state"],"verified")

    @unittest.skipUnless(os.name=='posix',"POSIX dirfd required")
    def test_linux_atomic_writer_rejects_symlinks_and_preserves_mode(self):
        root=Path(self.tmp.name)/"root"; (root/"etc").mkdir(parents=True)
        motd=root/"etc/motd"; motd.write_text("custom\n"); motd.chmod(0o640)
        actual_open=os.open
        def local_open(path,*args,**kw):
            return actual_open(str(root) if path=='/proc/10000/root' else path,*args,**kw)
        with mock.patch.object(banner.os,"open",side_effect=local_open):
            self.assertTrue(banner.write_proc(10000,"notice"))
            self.assertEqual(motd.stat().st_mode&0o777,0o640)
            self.assertTrue(banner.write_proc(10000,""))
            self.assertEqual(motd.read_text(),"custom\n")
            protected=root/"secret"; protected.write_text("untouched")
            motd.unlink(); motd.symlink_to(protected)
            with self.assertRaises(OSError): banner.write_proc(10000,"notice")
            self.assertEqual(protected.read_text(),"untouched")
