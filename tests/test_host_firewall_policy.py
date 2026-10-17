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
SPEC = importlib.util.spec_from_file_location("host_firewall_test_server", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class Request:
    def __init__(self, payload, role="admin"):
        self.raw = json.dumps(payload).encode()
        self.state = SimpleNamespace(dashboard_role=role, dashboard_user="test-admin")

    async def body(self):
        return self.raw


class HostFirewallPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.temp.name) / "monitor.db")
        server.init_db()
        self.now = int(time.time())
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,node_id) VALUES('host-a',?,'watcher-node-a')",
            (self.now,),
        )
        conn.commit()
        conn.close()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def policy():
        return {
            "rules": [{
                "key": "policy-rule-1", "priority": 100, "direction": "in", "protocol": "quic",
                "action": "block", "enabled": True, "port_start": 443, "ip_type": "geoip", "countries": ["cn", "US"],
            }],
            "abuse": {"speedtest": True, "mining": False, "bt": True, "interfaces": ["incusbr0"]},
        }

    def save(self, payload=None, role="admin"):
        return asyncio.run(server.update_host_firewall_policy("host-a", Request(payload or self.policy(), role)))

    def test_save_persists_revision_and_queues_node_identity_bound_action(self):
        response = self.save()
        self.assertEqual(response.status_code, 202)
        result = json.loads(response.body)
        self.assertEqual(result["revision"], 1)
        conn = server.db()
        policy_row = conn.execute("SELECT * FROM host_firewall_policies WHERE host_id='host-a'").fetchone()
        action = conn.execute("SELECT * FROM security_actions WHERE action_type='apply_host_firewall_policy'").fetchone()
        params = json.loads(action["params_json"])
        conn.close()
        self.assertEqual(policy_row["revision"], 1)
        self.assertEqual(params["expected_node_id"], "watcher-node-a")
        self.assertEqual(params["policy"]["revision"], 1)
        self.assertEqual(params["policy"]["rules"][0]["countries"], ["CN", "US"])
        self.assertEqual(server._action_item(action)["params"], {"revision": 1, "rule_count": 1})
        state = json.loads(server.get_host_firewall_policy("host-a").body)
        self.assertEqual(state["latest_action"]["status"], "queued")
        self.assertTrue(state["agent_ready"])

    def test_new_revision_supersedes_old_queued_configuration(self):
        self.save()
        second = self.policy()
        second["rules"] = []
        second["abuse"]["mining"] = True
        response = self.save(second)
        self.assertEqual(json.loads(response.body)["revision"], 2)
        conn = server.db()
        rows = conn.execute("SELECT status,params_json FROM security_actions WHERE action_type='apply_host_firewall_policy' ORDER BY id").fetchall()
        conn.close()
        self.assertEqual([row["status"] for row in rows], ["cancelled", "queued"])
        self.assertEqual(json.loads(rows[1]["params_json"])["policy"]["revision"], 2)

    def test_invalid_rules_categories_and_viewer_cannot_queue(self):
        invalid = self.policy()
        invalid["rules"][0]["protocol"] = "quic"
        invalid["rules"][0]["direction"] = "out"
        with self.assertRaises(HTTPException) as raised:
            self.save(invalid)
        self.assertEqual(raised.exception.status_code, 400)

        invalid = self.policy()
        invalid["rules"][0]["ip_type"] = "cidr"
        invalid["rules"][0]["ip"] = "not-a-cidr"
        with self.assertRaises(HTTPException) as raised:
            self.save(invalid)
        self.assertEqual(raised.exception.status_code, 400)

        invalid = self.policy()
        invalid["abuse"]["kill_processes"] = True
        with self.assertRaises(HTTPException) as raised:
            self.save(invalid)
        self.assertEqual(raised.exception.status_code, 400)

        with self.assertRaises(HTTPException) as raised:
            self.save(role="viewer")
        self.assertEqual(raised.exception.status_code, 403)
        conn = server.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM security_actions").fetchone()[0], 0)
        conn.close()

    def test_enabled_abuse_policy_requires_explicit_container_bridge(self):
        invalid = self.policy()
        invalid["abuse"]["interfaces"] = []
        with self.assertRaises(HTTPException) as raised:
            self.save(invalid)
        self.assertEqual(raised.exception.status_code, 400)

        invalid = self.policy()
        invalid["abuse"]["interfaces"] = ["eth0;iptables"]
        with self.assertRaises(HTTPException) as raised:
            self.save(invalid)
        self.assertEqual(raised.exception.status_code, 400)

    def test_host_without_registered_agent_cannot_queue(self):
        conn = server.db()
        conn.execute("UPDATE hosts SET node_id='' WHERE host_id='host-a'")
        conn.commit()
        conn.close()
        with self.assertRaises(HTTPException) as raised:
            self.save()
        self.assertEqual(raised.exception.status_code, 409)

    def test_client_sends_only_host_scoped_policy_to_matching_runman_node(self):
        action = {
            "runtime": "host",
            "container_name": "__host__",
            "params": {
                "expected_node_id": "watcher-node-a",
                "policy": {"revision": 4, "rules": [], "abuse": {"speedtest": False, "mining": False, "bt": False}},
            },
        }
        with mock.patch.object(agent, "_runman_host_firewall_request", return_value=(True, "applied")) as send:
            self.assertEqual(agent._execute_host_firewall_policy(action, "watcher-node-a"), (True, "applied"))
            send.assert_called_once_with(action["params"]["policy"])

        with mock.patch.object(agent, "_runman_host_firewall_request") as send:
            self.assertFalse(agent._execute_host_firewall_policy(action, "different-node")[0])
            send.assert_not_called()
            action["runtime"] = "incus"
            self.assertFalse(agent._execute_host_firewall_policy(action, "watcher-node-a")[0])
            send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
