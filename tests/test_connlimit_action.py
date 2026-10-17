import asyncio
import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import HTTPException

from client import agent

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("connlimit_test_server", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class Request:
    def __init__(self, payload, role="admin"):
        self.payload = payload
        self.state = SimpleNamespace(dashboard_role=role, dashboard_user="test-admin")

    async def json(self):
        return self.payload


class ConnectionLimitActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.temp.name) / "monitor.db")
        server._next_cleanup_monotonic = 0.0
        server.init_db()
        self.now = int(time.time())
        self.instance_id = "8b81822b-4779-4f12-9a12-6ea4cd777d10"
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,node_id) VALUES('host-a',?,'watcher-node-a')",
            (self.now,),
        )
        report = {
            "id": "vm-a",
            "stable_id": self.instance_id,
            "conn_count": 1200,
            "security": {
                "connection_metrics": {
                    "schema": 1,
                    "valid": True,
                    "source": "container_proc_net",
                    "epoch": "boot:network:pid",
                    "sampled_at": self.now,
                    "total": 1200,
                    "tcp_total": 700,
                    "tcp_established": 650,
                    "tcp_pending": 10,
                    "tcp_time_wait": 40,
                    "udp_sockets": 500,
                }
            },
        }
        conn.execute(
            """INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,
                net_rx_bps,net_tx_bps,conn_count,disk_file,disk_size_bytes,disk_used_percent,
                podman_network_ok_v4,podman_network_ok_v6,ts,payload_json)
                VALUES('host-a','vm-a','incus','default',0,0,0,0,0,1200,'',0,0,1,1,?,?)""",
            (self.now, json.dumps(report)),
        )
        self.alert_id = conn.execute(
            """INSERT INTO security_alerts(fingerprint,host_id,runtime,project,container_name,alert_type,
                severity,title,message,value,threshold,first_seen,last_seen,occurrence_count,status,details_json)
                VALUES('fp-a','host-a','incus','default','vm-a','container_connection_count','critical',
                '连接数过高','持续超限',1200,1000,?,?,1,'active','{}')""",
            (self.now, self.now),
        ).lastrowid
        conn.commit()
        conn.close()

    def tearDown(self):
        self.temp.cleanup()

    def apply(self, role="admin", limit=500, duration=1800):
        return asyncio.run(server.set_security_alert_disposition(
            int(self.alert_id), Request({
                "decision": "apply_container_connlimit",
                "max_connections": limit,
                "duration_seconds": duration,
            }, role),
        ))

    def test_admin_can_queue_only_fresh_verified_incus_tcp_limit(self):
        response = self.apply()
        self.assertEqual(response.status_code, 202)
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["action_type"], "apply_container_connlimit")
        params = body["action"]["params"]
        self.assertEqual(params["max_connections"], 500)
        conn = server.db()
        row = conn.execute("SELECT * FROM security_actions WHERE action_type='apply_container_connlimit'").fetchone()
        stored = json.loads(row["params_json"])
        public = server._action_item(row)
        conn.close()
        self.assertEqual(stored["expected_node_id"], "watcher-node-a")
        self.assertEqual(stored["instance_id"], self.instance_id)
        self.assertRegex(stored["policy_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(stored["observed_tcp_connections"], 660)
        self.assertEqual(public["params"], {"max_connections": 500, "lease_expires_at": params["lease_expires_at"]})

    def test_non_admin_cannot_change_firewall_policy(self):
        with self.assertRaises(HTTPException) as raised:
            self.apply(role="viewer")
        self.assertEqual(raised.exception.status_code, 403)
        conn = server.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_actions").fetchone()[0], 0)
        conn.close()

    def test_corrupt_existing_lease_fails_closed_instead_of_returning_500(self):
        self.apply()
        conn = server.db()
        row = conn.execute("SELECT id,params_json FROM security_actions WHERE action_type='apply_container_connlimit'").fetchone()
        params = json.loads(row["params_json"])
        params["lease_expires_at"] = "corrupt"
        conn.execute("UPDATE security_actions SET status='succeeded',params_json=? WHERE id=?", (json.dumps(params), row["id"]))
        conn.commit()
        conn.close()
        with self.assertRaises(HTTPException) as raised:
            self.apply()
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("无法核实", raised.exception.detail)

    def test_aggregate_udp_sockets_do_not_authorize_tcp_limit(self):
        conn = server.db()
        row = conn.execute("SELECT payload_json FROM reports WHERE host_id='host-a'").fetchone()
        payload = json.loads(row[0])
        metrics = payload["security"]["connection_metrics"]
        metrics.update({"total": 1200, "tcp_total": 400, "tcp_established": 350, "tcp_pending": 10,
                        "tcp_time_wait": 40, "udp_sockets": 800})
        conn.execute("UPDATE reports SET payload_json=? WHERE host_id='host-a'", (json.dumps(payload),))
        conn.commit()
        conn.close()
        with self.assertRaises(HTTPException) as raised:
            self.apply()
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("不限制 UDP", raised.exception.detail)

    def test_client_rechecks_epoch_and_live_tcp_count_before_apply(self):
        action = {
            "action_type": "apply_container_connlimit",
            "runtime": "incus",
            "project": "default",
            "container_name": "vm-a",
            "params": {
                "action_expires_at": 1100,
                "lease_expires_at": 2800,
                "policy_id": "a" * 32,
                "instance_id": self.instance_id,
                "max_connections": 500,
                "metric_epoch": "boot:network:pid",
                "observed_tcp_connections": 660,
                "observed_at": 1000,
            },
        }
        fresh = {"valid": True, "epoch": "boot:network:pid", "tcp_established": 650, "tcp_pending": 10}
        with mock.patch.object(agent.time, "time", return_value=1000), \
             mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), \
             mock.patch.object(agent, "_incus_instance_pid", return_value=123), \
             mock.patch.object(agent, "_collect_socket_security", return_value={"connection_metrics": fresh}), \
             mock.patch.object(agent, "_runman_connlimit_request", return_value=(True, "applied")) as send:
            self.assertEqual(agent.execute_security_action(action), (True, "applied"))
        self.assertEqual(send.call_args.args[0]["action"], "apply")
        self.assertEqual(send.call_args.args[0]["max_connections"], 500)

        fresh["epoch"] = "new-instance-epoch"
        with mock.patch.object(agent.time, "time", return_value=1000), \
             mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), \
             mock.patch.object(agent, "_incus_instance_pid", return_value=123), \
             mock.patch.object(agent, "_collect_socket_security", return_value={"connection_metrics": fresh}), \
             mock.patch.object(agent, "_runman_connlimit_request") as send:
            self.assertFalse(agent.execute_security_action(action)[0])
            send.assert_not_called()

    def test_client_releases_only_policy_id_and_expired_actions_are_noops(self):
        action = {
            "action_type": "release_container_connlimit",
            "runtime": "incus",
            "project": "default",
            "container_name": "vm-a",
            "params": {"action_expires_at": 1100, "policy_id": "b" * 32, "instance_id": self.instance_id},
        }
        with mock.patch.object(agent.time, "time", return_value=1000), \
             mock.patch.object(agent, "_runman_connlimit_request", return_value=(True, "released")) as send:
            self.assertEqual(agent.execute_security_action(action), (True, "released"))
        self.assertEqual(send.call_args.args[0]["action"], "release")
        self.assertNotIn("max_connections", send.call_args.args[0])
        action["params"]["action_expires_at"] = 999
        with mock.patch.object(agent.time, "time", return_value=1000), \
             mock.patch.object(agent, "_runman_connlimit_request") as send:
            self.assertFalse(agent.execute_security_action(action)[0])
            send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
