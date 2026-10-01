import asyncio
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock
from server import app as server
from server import operations as ops
from client import operations as agent_ops


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.patch=mock.patch.multiple(server,DB_PATH=str(Path(self.temp.name)/"monitor.db"),DASHBOARD_USERNAME="test-admin",DASHBOARD_PASSWORD="test-password-only",APP_VERSION="1.7.0")
        self.patch.start()
        server.init_db()
        self.conn=server.db()
        self.now=int(time.time())
        self.conn.execute("INSERT INTO hosts VALUES('h',?,'1.6.74','node','{}')",(self.now,))
        self.conn.commit()
        self.entity=ops.identity("node","incus","default","c")

    def tearDown(self):
        self.conn.close()
        self.patch.stop()
        self.temp.cleanup()

    def data(self,rx=100,tx=100,rate=100,connections=10,epoch="a",available=True):
        return {"agent_version":"1.6.74","client_config":{"report_interval":300},"security":{"enabled":True,"alerts":[]},"containers":[{"name":"c","runtime":"incus","project":"default","cpu_percent":12,"mem_percent":20,"net_rx_bps":rate,"net_tx_bps":rate,"conn_count":connections,"traffic_counters":{"available":available,"rx":rx,"tx":tx,"epoch":epoch},"security":{"process_count":2}}],"operations":{"health":[],"managed_upgrade":True}}

    def ingest(self,ts,data=None):
        result=ops.ingest(self.conn,"h","node",ts,data or self.data())
        self.conn.commit()
        return result

    def usage(self,period="day"):
        return self.conn.execute("SELECT SUM(rx),SUM(tx),SUM(covered),SUM(gaps) FROM ops_rollups WHERE period=?",(period,)).fetchone()

    def test_counter_deltas_and_duplicates(self):
        self.ingest(self.now)
        self.ingest(self.now+300,self.data(1100,2100))
        self.ingest(self.now+300,self.data(999999,999999))
        self.ingest(self.now+200,self.data(999999,999999))
        self.assertEqual(tuple(self.usage()),(1000,2000,300,0))
        self.assertEqual(tuple(self.usage("hour")),(1000,2000,300,0))

    def test_gap_and_reset_are_not_billed(self):
        self.ingest(self.now)
        self.ingest(self.now+1200,self.data(100000,100000))
        self.ingest(self.now+1500,self.data(10,10,epoch="b"))
        self.assertEqual(tuple(self.usage()),(0,0,0,2))
        self.ingest(self.now+1800,self.data(110,210,epoch="b"))
        self.assertEqual(tuple(self.usage())[:2],(100,200))

    def test_estimation_is_explicit(self):
        self.ingest(self.now,self.data(available=False))
        self.ingest(self.now+300,self.data(rate=10,available=False))
        self.assertEqual(self.usage()[0],3000)
        self.assertEqual(self.conn.execute("SELECT SUM(estimated) FROM ops_rollups WHERE period='day'").fetchone()[0],1)

    def test_midnight_split(self):
        midnight=int((self.now+28800)//86400)*86400-28800
        self.ingest(midnight-150)
        self.ingest(midnight+150,self.data(1100,2100))
        days=self.conn.execute("SELECT rx,tx,covered FROM ops_rollups WHERE period='day' ORDER BY bucket").fetchall()
        self.assertEqual([tuple(x) for x in days],[(500,1000,150),(500,1000,150)])

    def test_host_rename_preserves_meter_identity(self):
        self.ingest(self.now)
        ops.ingest(self.conn,"renamed","node",self.now+300,self.data(1100,2100))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ops_meter").fetchone()[0],1)
        self.assertEqual(self.usage()[0],1000)

    def test_profile_inheritance_override_and_quota(self):
        self.conn.execute("INSERT INTO ops_policies VALUES(?,?,?,?)",(ops.identity("node"),"web",json.dumps({"monthly_quota_bytes":1000,"quota_warning":.8}),self.now))
        self.assertEqual(ops.policy(self.conn,self.entity)["connections"],2000)
        self.ingest(self.now)
        alerts=self.ingest(self.now+300,self.data(1100,2100))
        self.assertIn("ops_traffic_quota",[a["type"] for a in alerts])
        self.conn.execute("INSERT INTO ops_policies VALUES(?,?,?,?)",(self.entity,"hy2","{}",self.now))
        self.assertEqual(ops.policy(self.conn,self.entity)["connections"],1500)

    def test_baseline_requires_sustained_two_signals(self):
        for i in range(24):
            self.ingest(self.now+i*300,self.data(rx=i*100,tx=i*100))
        first=self.ingest(self.now+24*300,self.data(2500,2500,rate=100_000_000,connections=2000))
        second=self.ingest(self.now+25*300,self.data(2600,2600,rate=100_000_000,connections=2000))
        self.assertNotIn("ops_baseline_anomaly",[a["type"] for a in first+second])
        third=self.ingest(self.now+26*300,self.data(2700,2700,rate=100_000_000,connections=2000))
        self.assertIn("ops_baseline_anomaly",[a["type"] for a in third])
        self.ingest(self.now+27*300,self.data(2800,2800))
        self.assertEqual(self.conn.execute("SELECT status FROM ops_incidents WHERE kind='baseline_anomaly'").fetchone()[0],"resolved")

    def make_recheck(self):
        self.conn.execute("INSERT INTO security_alerts(fingerprint,host_id,runtime,project,container_name,alert_type,severity,title,message,first_seen,last_seen,status) VALUES('test','h','incus','default','c','socks_weak_auth','critical','t','m',?,?,'active')",(self.now,self.now))
        self.conn.execute("INSERT INTO security_actions(id,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(1,1,'h','incus','default','c','enforce_socks_auth','{}','succeeded','test',?,?)",(self.now,self.now))
        ops.track_recheck(self.conn,1,self.now)
        self.conn.commit()

    def test_recheck_two_fresh_complete_samples(self):
        self.make_recheck()
        self.ingest(self.now+300)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_rechecks").fetchone()[0],"awaiting_report")
        self.ingest(self.now+600)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_rechecks").fetchone()[0],"verified")

    def test_disabled_or_missing_process_sample_is_not_verification(self):
        self.make_recheck()
        data=self.data()
        data["security"]["enabled"]=False
        self.ingest(self.now+300,data)
        data["security"]["enabled"]=True
        data["containers"][0]["security"]["process_count"]=0
        self.ingest(self.now+600,data)
        self.assertEqual(self.conn.execute("SELECT clean_samples FROM ops_rechecks").fetchone()[0],0)
        ops.maintain(self.conn,self.now+4000)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_rechecks").fetchone()[0],"unverified")

    def test_unknown_socks_auth_is_not_clean(self):
        self.make_recheck()
        data=self.data()
        data["containers"][0]["security"]["socks_proxy"]={"detected":True,"auth_mode":"unknown"}
        self.ingest(self.now+300,data)
        self.ingest(self.now+600,data)
        self.assertEqual(self.conn.execute("SELECT clean_samples FROM ops_rechecks").fetchone()[0],0)

    def test_recurring_has_two_retry_ceiling(self):
        self.make_recheck()
        data=self.data()
        data["security"]["alerts"]=[{"type":"socks_weak_auth","runtime":"incus","project":"default","container_name":"c"}]
        for i in range(1,4):
            self.conn.execute("UPDATE security_actions SET status='succeeded' WHERE id=1")
            self.ingest(self.now+300*i,data)
        row=self.conn.execute("SELECT status,attempts FROM ops_rechecks").fetchone()
        self.assertEqual(row["status"],"recurring")
        self.assertEqual(row["attempts"],2)
        self.assertEqual(self.conn.execute("SELECT status FROM security_actions").fetchone()[0],"succeeded")

    def test_maintenance_preserves_day_rollup_not_old_hours(self):
        self.ingest(self.now-40*86400)
        ops.maintain(self.conn,self.now)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ops_rollups WHERE period='hour'").fetchone()[0],0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ops_rollups WHERE period='day'").fetchone()[0],1)

    def test_backup_integrity_retention_and_secrets_not_in_filename(self):
        self.conn.execute("INSERT INTO ops_settings VALUES('example','secret-config')")
        self.conn.commit()
        for _ in range(3):
            result=ops.backup(server.DB_PATH,2)
        files=list((Path(self.temp.name)/"backups").glob("*.db"))
        self.assertEqual(len(files),2)
        with closing(sqlite3.connect(Path(self.temp.name)/"backups"/result["name"])) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0],"ok")
            self.assertEqual(db.execute("SELECT payload FROM ops_settings WHERE key='example'").fetchone()[0],"secret-config")
        self.assertEqual(len(result["sha256"]),64)

    def test_password_and_role_guards(self):
        hashed=ops.password_hash("test-only-password")
        self.conn.execute("INSERT INTO ops_users VALUES('reader',?,'viewer',1,?)",(hashed,self.now))
        header="Basic "+base64.b64encode(b"reader:test-only-password").decode()
        self.assertEqual(ops.authenticate(self.conn,header),("reader","viewer"))
        self.assertIsNone(ops.authenticate(self.conn,"Basic !!!"))
        for path in ("/api/v1/containers/disposition","/api/v1/security/alerts/1/actions","/api/v1/hosts/h/delete","/api/v1/ops/users","/api/v1/ops/upgrades"):
            self.assertFalse(ops.permitted("viewer","POST",path))
        self.assertFalse(ops.permitted("viewer","GET","/api/v1/settings/push"))
        self.assertTrue(ops.permitted("operator","POST","/api/v1/containers/disposition"))
        self.assertFalse(ops.permitted("operator","POST","/api/v1/ops/upgrades"))
        self.assertTrue(ops.permitted("operator","POST","/api/v1/security/alerts/1/disposition"))

    def request(self,path,method="GET",body=None,username="test-admin",password="test-password-only",signed=False):
        content=json.dumps(body or {}).encode()
        headers=[(b"content-type",b"application/json")]
        if signed:
            ts=str(int(time.time()))
            signature=hmac.new(server.SHARED_SECRET.encode(),content+ts.encode(),hashlib.sha256).hexdigest()
            headers.extend([(b"x-timestamp",ts.encode()),(b"x-signature",signature.encode())])
        else:
            headers.append((b"authorization",b"Basic "+base64.b64encode(f"{username}:{password}".encode())))
        async def run():
            sent=[]
            received=False
            async def receive():
                nonlocal received
                if not received:
                    received=True
                    return {"type":"http.request","body":content,"more_body":False}
                await asyncio.Event().wait()
            async def send(message):
                sent.append(message)
            scope={"type":"http","asgi":{"version":"3.0","spec_version":"2.4"},"http_version":"1.1","method":method,"scheme":"http","path":path,"raw_path":path.encode(),"query_string":b"","root_path":"","headers":headers,"server":("localhost",80),"client":("127.0.0.1",1234)}
            await server.app(scope,receive,send)
            status=next(x["status"] for x in sent if x["type"]=="http.response.start")
            data=b"".join(x.get("body",b"") for x in sent if x["type"]=="http.response.body")
            return status,json.loads(data) if data else {}
        return asyncio.run(run())

    def test_api_rbac_protects_old_routes_and_audits_failures(self):
        self.conn.execute("INSERT INTO ops_users VALUES('reader',?,'viewer',1,?)",(ops.password_hash("test-only-password"),self.now))
        self.conn.commit()
        status,_=self.request("/api/v1/containers/disposition","POST",{},"reader","test-only-password")
        self.assertEqual(status,403)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_audit").fetchone()[0],403)
        self.assertEqual(self.request("/api/v1/ops/session",username="reader",password="test-only-password")[1]["role"],"viewer")
        self.assertEqual(self.request("/api/v1/notifications/bots",username="reader",password="test-only-password")[0],403)

    def test_api_overview_storage_traffic_and_policy_preview(self):
        self.ingest(self.now)
        for path in ("overview","storage","traffic","policies","services","upgrades","backups","users","audit"):
            self.assertEqual(self.request("/api/v1/ops/"+path)[0],200,path)
        payload={"entity":self.entity,"profile":"web","rules":{"monthly_quota_bytes":10000}}
        self.assertEqual(self.request("/api/v1/ops/policies/preview","POST",payload)[1]["after"]["connections"],2000)
        self.assertEqual(self.request("/api/v1/ops/policies","POST",payload)[0],200)
        payload["rules"]["silent_until"]=self.now+172800
        self.assertEqual(self.request("/api/v1/ops/policies","POST",payload)[0],400)

    def test_operator_cannot_persistently_allow_panel_domains(self):
        self.conn.execute("INSERT INTO ops_users VALUES('operator',?,'operator',1,?)",(ops.password_hash("test-only-password"),self.now))
        self.conn.commit()
        self.assertEqual(self.request("/api/v1/security/alerts/1/actions","POST",{"action":"allow"},"operator","test-only-password")[0],403)
        self.assertEqual(self.request("/api/v1/security/alerts/1/disposition","POST",{"decision":"allow_silent"},"operator","test-only-password")[0],403)

    def test_host_purge_clears_operational_state_without_other_nodes(self):
        self.ingest(self.now)
        ops.ingest(self.conn,"other","other-node",self.now,self.data())
        server._purge_host(self.conn,"h")
        self.assertEqual(self.conn.execute("SELECT host_id FROM ops_hosts").fetchone()[0],"other")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM ops_meter").fetchone()[0],1)

    def test_api_service_targets_and_signed_delivery(self):
        self.ingest(self.now)
        for target in ("file:///etc/passwd","http://user:pass@example.com","tcp://localhost:0","https://x:99999"):
            self.assertEqual(self.request("/api/v1/ops/services","POST",{"host_id":"h","target":target})[0],400)
        self.assertEqual(self.request("/api/v1/ops/services","POST",{"host_id":"h","target":"https://example.com/health","name":"test"})[0],200)
        status,payload=self.request("/api/v1/actions/poll","POST",{"host_id":"h","node_id":"node"},signed=True)
        self.assertEqual(status,200)
        self.assertEqual(len(payload["operations"]["services"]),1)

    def test_logs_connect_requires_discovery_and_safe_path(self):
        self.ingest(self.now)
        self.assertEqual(self.request("/api/v1/ops/logs/connect","POST",{"host_id":"h","paths":["/var/log/nginx/access.log"]})[0],409)
        data=self.data()
        data["operations"]["log_discovery"]=[{"path":"/var/log/nginx/access.log","status":"healthy"}]
        self.ingest(self.now+1,data)
        status,payload=self.request("/api/v1/ops/logs/connect","POST",{"host_id":"h","paths":["/var/log/nginx/access.log"]})
        self.assertEqual(status,200)
        row=self.conn.execute("SELECT params_json FROM security_actions WHERE id=?",(payload["action_id"],)).fetchone()
        self.assertEqual(json.loads(row[0])["expected_node_id"],"node")
        self.assertEqual(self.request("/api/v1/ops/logs/connect","POST",{"host_id":"h","paths":["/var/log/../../etc/shadow"]})[0],400)

    def test_upgrade_promotion_gate(self):
        self.ingest(self.now)
        self.conn.execute("INSERT INTO ops_upgrades VALUES(1,'1.7.0',?,'canary',?,'{}')",("a"*40,self.now))
        self.conn.execute("INSERT INTO ops_upgrade_nodes VALUES(1,'h',NULL,'dispatched','1.6.74')")
        self.conn.commit()
        self.assertEqual(self.request("/api/v1/ops/upgrades/1/promote","POST")[0],409)
        self.conn.execute("UPDATE ops_upgrade_nodes SET status='verified'")
        self.conn.commit()
        self.assertEqual(self.request("/api/v1/ops/upgrades/1/promote","POST")[0],200)

    def test_upgrade_worker_failure_is_visible(self):
        self.conn.execute("INSERT INTO security_actions(id,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(9,0,'h','host','','__host__','managed_upgrade',?,'running','test',?,?)",(json.dumps({"expected_node_id":"node"}),self.now,self.now))
        data=self.data()
        data["operations"]["upgrade_result"]={"action_id":9,"status":"failed"}
        self.ingest(self.now,data)
        self.assertEqual(self.conn.execute("SELECT status FROM security_actions WHERE id=9").fetchone()[0],"failed")

    def test_rollback_to_legacy_agent_is_confirmed_by_signed_report_version(self):
        self.conn.execute("INSERT INTO security_actions(id,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(9,0,'h','host','','__host__','managed_rollback',?,'running','test',?,?)",(json.dumps({"expected_node_id":"node","version":"1.6.74"}),self.now,self.now))
        data=self.data()
        data.pop("operations")
        self.ingest(self.now,data)
        self.assertEqual(self.conn.execute("SELECT status FROM security_actions WHERE id=9").fetchone()[0],"succeeded")

    def test_canary_requires_core_collection_and_service_health(self):
        self.conn.execute("INSERT INTO ops_upgrades VALUES(1,'1.7.0',?,'canary',?,'{}')",("a"*40,self.now))
        self.conn.execute("INSERT INTO ops_upgrade_nodes VALUES(1,'h',9,'dispatched','1.6.74')")
        self.conn.execute("INSERT INTO security_actions(id,alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(9,0,'h','host','','__host__','managed_upgrade','{}','running','test',?,?)",(self.now,self.now))
        data=self.data()
        data["agent_version"]="1.7.0"
        data["operations"]["health"]=[{"source":"network_counters","status":"partial"}]
        self.ingest(self.now,data)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_upgrade_nodes").fetchone()[0],"dispatched")
        data["operations"]["health"][0]["status"]="healthy"
        self.ingest(self.now+300,data)
        self.assertEqual(self.conn.execute("SELECT status FROM ops_upgrade_nodes").fetchone()[0],"verified")

    def test_signed_report_integrates_quota_into_existing_alert_pipeline(self):
        self.conn.execute("INSERT INTO ops_policies VALUES(?,?,?,?)",(self.entity,"general",json.dumps({"monthly_quota_bytes":1000}),self.now))
        self.conn.commit()
        with mock.patch.object(server,"send_alert_webhook"),mock.patch.object(server,"sync_configured_bot_alert_messages"),mock.patch.object(server,"dispatch_buyer_notifications_for_alerts"):
            first=self.data()
            first.update(host_id="h",node_id="node",timestamp=self.now)
            self.assertEqual(self.request("/api/v1/report","POST",first,signed=True)[0],200)
            second=self.data(2100,2100)
            second.update(host_id="h",node_id="node",timestamp=self.now+300)
            self.assertEqual(self.request("/api/v1/report","POST",second,signed=True)[0],200)
        self.assertEqual(self.conn.execute("SELECT alert_type FROM security_alerts WHERE alert_type='ops_traffic_quota'").fetchone()[0],"ops_traffic_quota")

    def test_service_failure_creates_alert_and_recovers(self):
        self.conn.execute("INSERT INTO ops_services VALUES(1,'h','service','{}',1)")
        data=self.data()
        data["operations"]["services"]=[{"id":1,"status":"failed","error":"Timeout"}]
        alerts=self.ingest(self.now,data)
        self.assertEqual(alerts[0]["severity"],"critical")
        data["operations"]["services"][0]["status"]="healthy"
        self.assertEqual(self.ingest(self.now+300,data),[])
        self.assertEqual(self.conn.execute("SELECT status FROM ops_incidents WHERE kind='service:1'").fetchone()[0],"resolved")


class NodeOperationsTests(unittest.TestCase):
    def test_probe_tcp_and_failure(self):
        with mock.patch.object(agent_ops.socket,"create_connection") as connect:
            result=agent_ops.probe({"id":1,"kind":"tcp","target":"tcp://127.0.0.1:8080"})
            self.assertEqual(result["status"],"healthy")
            connect.assert_called_once_with(("127.0.0.1",8080),timeout=3)
        with mock.patch.object(agent_ops.socket,"create_connection",side_effect=OSError("do not leak secret")):
            result=agent_ops.probe({"id":1,"kind":"tcp","target":"tcp://127.0.0.1:8080"})
            self.assertEqual(result["error"],"OSError")

    def test_http_does_not_follow_redirects_or_read_body(self):
        with mock.patch.object(agent_ops.requests,"get") as get:
            get.return_value.__enter__.return_value.status_code=503
            result=agent_ops.probe({"id":2,"kind":"http","target":"http://localhost/health"})
            self.assertEqual(result["status"],"failed")
            self.assertFalse(get.call_args.kwargs["allow_redirects"])
            self.assertTrue(get.call_args.kwargs["stream"])

    def test_health_distinguishes_no_logs_and_real_zero(self):
        with mock.patch.object(agent_ops,"_config",{"services":[]}):
            out=agent_ops.collect({"enabled":True,"access_log":{"enabled":True,"readable_files":1,"requests":0}},[],300)
            self.assertEqual(out["health"][0]["status"],"idle")
            out=agent_ops.collect({"enabled":True,"access_log":{"enabled":True,"unreadable_files":1}},[],300)
            self.assertEqual(out["health"][0]["status"],"permission_denied")

    def test_log_preview_does_not_upload_raw_content(self):
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/"access.log"
            file.write_text('127.0.0.1 GET /?password=secret 200\n')
            with mock.patch.object(agent_ops.glob,"glob",return_value=[]),mock.patch.dict(os.environ,{"SECURITY_ACCESS_LOG_PATHS":str(file)}):
                result=agent_ops.discover_logs(lambda s:{"ip":"127.0.0.1","uri":"/?password=secret","method":"GET","status":200})
                self.assertEqual(result[0]["parsed"],1)
                self.assertNotIn("secret",json.dumps(result))
                self.assertNotIn("127.0.0.1",json.dumps(result))

    def test_managed_upgrade_rejects_mismatched_identity_and_commands(self):
        self.assertFalse(agent_ops.schedule_upgrade({"params":{"expected_node_id":"other"}},"node")[0])
        self.assertFalse(agent_ops.schedule_upgrade({"params":{"expected_node_id":"node","revision":"a; curl evil","version":"1.7.0"}},"node")[0])

    def test_managed_upgrade_uses_fixed_independent_worker_arguments(self):
        action={"id":17,"action_type":"managed_upgrade","params":{"expected_node_id":"node","revision":"a"*40,"version":"1.7.0"}}
        with mock.patch.object(agent_ops.os.path,"isfile",return_value=True),mock.patch.object(agent_ops.shutil,"which",return_value="/bin/systemd-run"),mock.patch.object(agent_ops.subprocess,"run") as run:
            run.return_value.returncode=0
            self.assertTrue(agent_ops.schedule_upgrade(action,"node")[0])
            args=run.call_args.args[0]
            self.assertIn("narwhal-managed-17",args)
            self.assertEqual(args[-5:],["/opt/narwhal-monitor/managed-client-update.sh","upgrade","a"*40,"1.7.0","17"])
            self.assertNotIn("shell",run.call_args.kwargs)
