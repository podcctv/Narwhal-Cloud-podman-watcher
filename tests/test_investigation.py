import asyncio
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from server import investigation, buyer_notifications

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("investigation_test_app", ROOT / "server/app.py")
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.tmp.name) / "monitor.db")
        self.connections = []
        original = server.db
        def tracked():
            c = original()
            self.connections.append(c)
            return c
        self.patch = mock.patch.object(server, "db", side_effect=tracked)
        self.patch.start()
        server.init_db()
        self.conn = server.db()
        self.now = int(time.time()) - 1000
        self.container = {"name": "c1", "runtime": "incus", "project": "default", "id": "generation-1",
                          "security": {"socks_proxy": {"detected": False}}}
        self.alert = {"type": "socks_weak_auth", "runtime": "incus", "project": "default", "container_name": "c1",
                      "title": "无密码 SOCKS代理", "severity": "critical", "value": 40, "threshold": 20,
                      "password": "must-not-copy", "service_listeners": [{"process": "danted", "local": "0.0.0.0:1080", "pid": 123}]}

    def tearDown(self):
        for conn in self.connections:
            conn.close()
        self.patch.stop()
        self.tmp.cleanup()

    def mapping(self, user="user-1", name="c1", runtime="incus", host="h1"):
        buyer_notifications.save_target(self.conn, {"host_id": host, "runtime": runtime, "project": "default",
            "container_name": name, "machine_id": "00000000-0000-0000-0000-000000000001", "user_id": user})

    def ingest(self, delta=0, alerts=None, containers=None, host="h1", node="node-1"):
        ts = self.now + delta
        alerts = [self.alert] if alerts is None else alerts
        containers = [self.container] if containers is None else containers
        server.process_security_alerts(self.conn, host, ts, alerts)
        buyer_notifications.observe(self.conn, host, ts, containers, alerts)
        present = {r[0] for r in self.conn.execute("SELECT fingerprint FROM security_alerts WHERE host_id=? AND last_seen=? AND status<>'resolved'", (host, ts))}
        investigation.observe(self.conn, host, node, ts, containers, present)

    def result(self, **kwargs):
        return investigation.overview(self.conn, kwargs.pop("host", "h1"), self.now - 10, self.now + 10000, **kwargs)

    def test_poll_hits_are_one_episode_and_evidence_is_allowlisted(self):
        self.mapping()
        for i in range(20): self.ingest(i * 10)
        result = self.result()
        self.assertEqual(result["users"][0]["episodes"], 1)
        self.assertEqual(result["users"][0]["observed"], 1)
        self.assertEqual(len(result["items"][0]["transitions"]), 1)
        self.assertNotIn("must-not-copy", json.dumps(result))
        self.assertEqual(result["items"][0]["evidence"]["service_listeners"][0]["process"], "danted")

    def test_production_socks_auth_field_is_preserved_without_credentials(self):
        for mode in ('no_auth', 'weak_password', 'unknown'):
            self.assertEqual(json.loads(investigation._evidence({'details_json': json.dumps({'socks_auth_mode': mode, 'password': 'never-copy'})}))['auth_mode'], mode)
        evidence = investigation._evidence({'details_json': json.dumps({'socks_auth_mode': 'invalid-secret-value'})})
        self.assertNotIn('auth_mode', json.loads(evidence))
        self.assertNotIn('invalid-secret-value', evidence)

    def test_recurrence_keeps_old_episode_and_threshold(self):
        self.mapping()
        self.ingest()
        self.ingest(10, alerts=[])
        self.ingest(20, alerts=[])
        self.alert["threshold"] = 99
        self.ingest(30)
        rows = self.result()["items"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["initial_threshold"], 99)
        self.assertEqual(rows[1]["initial_threshold"], 20)
        self.assertEqual(rows[1]["state"], "verified")
        self.assertEqual(rows[1]["last_anomaly"], self.now)
        self.assertEqual(self.result()["users"][0]["affected"], 1)

    def test_owner_transfer_does_not_reassign_history(self):
        self.mapping("old-buyer")
        self.ingest()
        self.mapping("new-buyer")
        self.ingest(10, alerts=[])
        self.ingest(20, alerts=[])
        self.ingest(30)
        self.assertEqual([i["user_id"] for i in self.result()["items"]], ["new-buyer", "old-buyer"])
        self.assertEqual(len(self.result(user="old-buyer")["items"]), 1)
        self.assertEqual(self.result()["summary"]["observed"], 1)

    def test_stale_upstream_and_broadcast_are_unknown(self):
        self.mapping()
        self.conn.execute("UPDATE buyer_targets SET source='upstream',verified_at=?", (self.now - 1000,))
        self.ingest()
        self.assertEqual(self.result()["items"][0]["user_id"], "")
        self.assertIsNone(self.result()["users"][0]["rate"])
        self.conn.execute("UPDATE buyer_targets SET source='manual',scope='machine'")
        self.ingest(10, alerts=[])
        self.ingest(20)
        self.assertTrue(all(not i["user_id"] for i in self.result()["items"]))

    def test_legacy_does_not_guess_historical_owner_or_episode_count(self):
        self.mapping()
        server.process_security_alerts(self.conn, "h1", self.now - 100, [self.alert])
        self.ingest()
        rows = self.result()["items"]
        self.assertEqual(rows[0]["user_id"], "")
        self.assertEqual(rows[0]["legacy"], 1)
        self.assertEqual(sum(u["episodes"] for u in self.result()["users"]), 0)

    def test_runtime_project_and_generation_are_not_mixed(self):
        self.mapping()
        self.ingest()
        old_key = self.result()["items"][0]["identity_key"]
        self.container["id"] = "generation-2"
        self.ingest(10)
        self.assertEqual(self.result()["summary"]["affected"], 2)
        self.assertEqual(len(self.result(identity_key=old_key)["items"]), 1)
        self.assertEqual(self.result()["items"][0]["user_id"], "")  # old detector episode cannot prove the recreated VM's owner

    def test_host_public_alerts_are_not_user_incidents(self):
        self.mapping()
        host_alert = {"type": "ddos_syn", "severity": "warning", "title": "母鸡外部攻击信号"}
        self.ingest(alerts=[host_alert])
        r = self.result()
        self.assertEqual(r["public_total"], 1)
        self.assertEqual(r["summary"]["affected"], 0)
        self.assertEqual(r["users"][0]["episodes"], 0)

    def test_allow_policy_history_visible_but_not_counted(self):
        self.mapping()
        self.ingest()
        self.conn.execute("UPDATE security_alerts SET status='suppressed'")
        investigation.sync_states(self.conn, "h1", self.now + 10, host_key="node-1")
        r = self.result()
        self.assertEqual(r["summary"]["affected"], 0)
        self.assertEqual(len(r["items"]), 1)

    def test_host_and_owner_scopes_pagination_search(self):
        self.mapping()
        self.ingest()
        self.mapping("other", host="h2")
        self.ingest(10, host="h2", node="node-2")
        self.assertEqual(self.result()["summary"]["users"], 1)
        self.assertEqual(self.result()["summary"]["affected"], 1)
        self.assertFalse(self.result(user="other")["items"])
        self.assertFalse(self.result(query="missing")["users"])
        self.assertEqual(len(self.result(limit=1)["items"]), 1)
        self.assertFalse(self.result(offset=1)["items"])

    def test_action_receipt_and_transitions_survive_raw_cleanup(self):
        self.mapping()
        self.ingest()
        a = self.conn.execute("SELECT * FROM security_alerts").fetchone()
        self.conn.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'succeeded','test',?,?)",
                          (a['id'], 'h1', 'incus', 'default', 'c1', 'enforce_socks_auth', '{}', self.now, self.now + 1))
        aid = self.conn.execute("SELECT id FROM security_actions").fetchone()[0]
        self.conn.execute("INSERT INTO security_action_receipts VALUES(?,?,?)", (aid, json.dumps([{"kind": "stop_service", "target": "danted", "status": "ok"}]), self.now + 1))
        investigation.sync_states(self.conn, "h1", self.now + 1, host_key="node-1")
        # Delayed action results still update the exact incident after the live
        # sampling cutoff, without fabricating a new anomalous sample.
        self.conn.execute("UPDATE security_actions SET status='failed',updated_at=?", (self.now + 2 * 86400,))
        investigation.sync_states(self.conn, "h1", self.now + 2 * 86400, host_key="node-1", alert_id=a['id'])
        self.assertEqual(self.result()["items"][0]["action"]["status"], "failed")
        self.assertEqual(self.result()["items"][0]["last_anomaly"], self.now)
        self.conn.execute("DELETE FROM security_actions")
        self.conn.execute("DELETE FROM security_alerts")
        r = self.result()["items"][0]
        self.assertEqual(r["action"]["items"][0]["target"], "danted")
        self.assertEqual(len(r["transitions"]), 3)

    def test_out_of_order_disabled_and_caps(self):
        self.mapping()
        self.ingest()
        investigation.observe(self.conn, "h1", "node-1", self.now - 10, [self.container], set())
        self.assertEqual(self.result()["items"][0]["last_anomaly"], self.now)
        investigation.observe(self.conn, "h1", "node-1", self.now + 5, [self.container], None)
        self.assertEqual(self.result()["items"][0]["updated_at"], self.now)
        for i in range(50):
            self.conn.execute("UPDATE security_alerts SET severity=?", ("warning" if i % 2 else "critical",))
            investigation.sync_states(self.conn, "h1", self.now + 20 + i, host_key="node-1")
        self.assertLessEqual(len(self.result()["items"][0]["transitions"]), 20)
        investigation.maintain(self.conn, self.now + 91 * 86400)
        self.assertFalse(self.result()["items"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM investigation_transitions").fetchone()[0], 0)

    def test_api_validation_and_host_rename(self):
        self.mapping()
        self.ingest()
        with self.assertRaises(server.HTTPException): server.user_investigation(days=365)
        investigation.rename_host(self.conn, "h1", "renamed")
        self.assertEqual(self.result(host="renamed")["summary"]["affected"], 1)

    def test_admission_caps_do_not_depend_on_cleanup_speed(self):
        self.mapping()
        self.ingest()
        with mock.patch.object(investigation, 'INCIDENT_CAP', 1), mock.patch.object(investigation, 'OBSERVATION_CAP', 1), mock.patch.object(investigation, 'TRANSITION_CAP', 1):
            self.ingest(10, alerts=[])
            self.ingest(20)
            self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM investigation_incidents").fetchone()[0], 1)
            self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM investigation_transitions").fetchone()[0], 1)
            other = {**self.container, 'name': 'c2', 'id': 'gen-2'}
            investigation.observe(self.conn, 'h1', 'node-1', self.now + 30, [other], None)
            self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM investigation_observations").fetchone()[0], 1)
            self.assertFalse(self.result()["coverage"]["complete_window"])

    def test_disabled_security_does_not_claim_zero_risk_rate(self):
        self.mapping()
        investigation.observe(self.conn, 'h1', 'node-1', self.now, [self.container], None)
        user = self.result()['users'][0]
        self.assertEqual(user['unassessed'], 1)
        self.assertIsNone(user['rate'])

    def test_report_endpoint_records_exposure_and_incident(self):
        self.mapping()
        self.conn.commit()
        payload = {"host_id": "h1", "node_id": "node-1", "timestamp": self.now,
                   "containers": [self.container], "security": {"enabled": True, "alerts": [self.alert]}}
        class Request:
            async def body(self): return json.dumps(payload).encode()
        with mock.patch.object(server, "verify_signature"), mock.patch.object(server, "send_alert_webhook"), mock.patch.object(server, "sync_configured_bot_alert_messages"), mock.patch.object(server, "dispatch_buyer_notifications_for_alerts"):
            asyncio.run(server.report(Request(), "", ""))
        self.assertEqual(self.result()["summary"]["affected"], 1)
        self.conn.commit()
        self.assertEqual(json.loads(server.user_investigation(host_id="h1").body)["summary"]["users"], 1)


if __name__ == "__main__": unittest.main()
