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

    def set_host_interface_inventory(self, host_id="host-a", interfaces=None, observed_at=None):
        observed_at = self.now if observed_at is None else observed_at
        interfaces = interfaces if interfaces is not None else [{
            "name": "incusbr0", "kind": "bridge", "state": "up", "mtu": 1500,
            "addresses": ["10.90.0.1/24"], "runtimes": ["incus"],
            "network_names": ["default"], "firewall_eligible": True,
        }]
        payload = {"host_firewall": {
            "control_api": "ready", "observed_at": observed_at,
            "interface_inventory": {
                "status": "ready", "observed_at": observed_at, "interfaces": interfaces,
            },
        }}
        conn = server.db()
        conn.execute("DELETE FROM host_security WHERE host_id=?", (host_id,))
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            (host_id, observed_at, json.dumps(payload)),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def policy():
        return {
            "rules": [{
                "key": "policy-rule-1", "priority": 100, "direction": "in", "protocol": "tcp",
                "action": "block", "enabled": True, "port_start": 443, "ip_type": "geoip", "countries": ["cn", "US"],
            }],
            "abuse": {"speedtest": True, "mining": False, "bt": True, "interfaces": ["incusbr0"]},
        }

    def save(self, payload=None, role="admin"):
        candidate = payload or self.policy()
        abuse = candidate.get("abuse") if isinstance(candidate, dict) else None
        if isinstance(abuse, dict) and any(abuse.get(key) is True for key in ("speedtest", "mining", "bt")):
            self.set_host_interface_inventory()
        return asyncio.run(server.update_host_firewall_policy("host-a", Request(payload or self.policy(), role)))

    def install_rfw_capabilities(self, host_id, protocols, observed_at=None):
        observed_at = self.now if observed_at is None else observed_at
        snapshot = {
            "status": "in_sync", "observed_at": observed_at, "policy_revision": 1,
            "rule_count": 0, "managed_rule_count": 0, "drift_count": 0, "missing_count": 0,
            "rfw_api_version": "0.1.0", "capabilities_known": True,
            "supported_protocols": list(protocols), "rules": [], "expected_rules": [],
        }
        conn = server.db()
        server._store_host_firewall_readback(
            conn, host_id,
            {"host_firewall": {"readback": {"status": "ready", "observed_at": observed_at, "snapshot": snapshot}}},
            observed_at,
        )
        conn.commit()
        conn.close()

    @staticmethod
    def mtproto_policy():
        return {
            "rules": [{
                "key": "mtproto-test", "priority": 100, "direction": "out", "protocol": "mtproto",
                "action": "block", "enabled": True, "port_start": 0,
                "ip_type": "geoip", "countries": ["CN"],
            }],
            "abuse": {"speedtest": False, "mining": False, "bt": False, "interfaces": []},
        }

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

    def test_host_firewall_api_includes_sanitized_interface_inventory(self):
        payload = {
            "host_firewall": {
                "interface_inventory": {
                    "status": "ready",
                    "observed_at": self.now,
                    "interfaces": [
                        {
                            "name": "incusbr0", "kind": "bridge", "state": "up", "mtu": 1500,
                            "addresses": ["10.90.0.1/24", "not-an-ip"],
                            "is_default_route": False, "runtimes": ["incus", "unknown"],
                            "network_names": ["incusbr0"], "firewall_eligible": True,
                        },
                        {
                            "name": "eth0;drop", "kind": "bridge", "state": "up",
                            "runtimes": ["incus"], "firewall_eligible": True,
                        },
                    ],
                },
            },
        }
        conn = server.db()
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host-a',?,?)",
            (self.now, json.dumps(payload)),
        )
        inventory = server._host_firewall_interface_inventory(conn, "host-a", self.now)
        conn.close()

        self.assertEqual(inventory["status"], "ready")
        self.assertFalse(inventory["stale"])
        self.assertEqual([item["name"] for item in inventory["interfaces"]], ["incusbr0"])
        self.assertEqual(inventory["interfaces"][0]["addresses"], ["10.90.0.1/24"])
        self.assertEqual(inventory["interfaces"][0]["runtimes"], ["incus"])
        self.assertTrue(inventory["interfaces"][0]["firewall_eligible"])

    def test_live_rfw_readback_is_latest_only_and_preserves_last_good_snapshot(self):
        rule = {
            "id": 7, "priority": 100, "direction": "out", "protocol": "wireguard",
            "action": "block", "enabled": True, "port_start": 0, "port_end": 0,
            "ip_type": "geoip", "countries": ["CN"], "origin": "platform",
            "managed_key": "wg-cn-out", "sync_state": "in_sync",
        }
        payload = {
            "status": "ready", "observed_at": self.now,
            "snapshot": {
                "status": "in_sync", "observed_at": self.now, "policy_revision": 3,
                "rule_count": 1, "managed_rule_count": 1, "drift_count": 0, "missing_count": 0,
                "rules": [rule], "expected_rules": [{"key": "wg-cn-out", "id": 7, "sync_state": "in_sync"}],
            },
        }
        conn = server.db()
        server._store_host_firewall_readback(conn, "host-a", {"host_firewall": {"readback": payload}}, self.now)
        live = server._host_firewall_live_readback(conn, "host-a", self.now)
        self.assertEqual((live["status"], live["sync_status"], live["rule_count"]), ("ready", "in_sync", 1))
        self.assertFalse(live["stale"])

        unavailable = {"status": "unavailable", "observed_at": self.now + 60, "snapshot": None}
        server._store_host_firewall_readback(conn, "host-a", {"host_firewall": {"readback": unavailable}}, self.now + 60)
        live = server._host_firewall_live_readback(conn, "host-a", self.now + 60)
        self.assertEqual(live["status"], "unavailable")
        self.assertTrue(live["stale"])
        self.assertEqual(live["snapshot"]["rules"][0]["managed_key"], "wg-cn-out")
        self.assertEqual(live["last_success_at"], self.now)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_firewall_readbacks WHERE host_id='host-a'").fetchone()[0], 1)
        conn.commit()
        conn.close()

        host_state = json.loads(server.get_host_firewall_policy("host-a").body)
        self.assertEqual(host_state["live_readback"]["status"], "unavailable")
        self.assertEqual(host_state["live_readback"]["snapshot"]["rule_count"], 1)
        fleet_state = json.loads(server.get_fleet_firewall_policy().body)
        host = next(item for item in fleet_state["hosts"] if item["host_id"] == "host-a")
        self.assertEqual(host["live_readback"]["status"], "unavailable")
        self.assertNotIn("snapshot", host["live_readback"])

    def test_live_rfw_readback_rejects_malformed_rule_data(self):
        invalid = {
            "status": "ready", "snapshot": {
                "status": "in_sync", "policy_revision": 1, "rule_count": 1,
                "managed_rule_count": 1, "drift_count": 0, "missing_count": 0,
                "rules": [{"id": 1, "protocol": "shell"}], "expected_rules": [],
            },
        }
        checked = server._validate_host_firewall_readback(invalid, self.now)
        self.assertEqual(checked["status"], "unavailable")
        self.assertIsNone(checked["snapshot"])

    def test_readback_capabilities_are_validated_and_legacy_nodes_remain_unknown(self):
        legacy = {"status": "ready", "snapshot": {
            "status": "in_sync", "policy_revision": 1, "rule_count": 0,
            "managed_rule_count": 0, "drift_count": 0, "missing_count": 0,
            "rules": [], "expected_rules": [],
        }}
        checked = server._validate_host_firewall_readback(legacy, self.now)
        self.assertEqual(checked["status"], "ready")
        self.assertFalse(checked["snapshot"]["capabilities_known"])
        self.assertEqual(checked["snapshot"]["supported_protocols"], [])

        malformed = json.loads(json.dumps(legacy))
        malformed["snapshot"].update({"capabilities_known": True, "supported_protocols": []})
        checked = server._validate_host_firewall_readback(malformed, self.now)
        self.assertEqual(checked["status"], "unavailable")
        self.assertIsNone(checked["snapshot"])

    def test_live_readback_reports_supported_unsupported_and_unknown_protocols(self):
        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "socks", "wireguard"])
        conn = server.db()
        live = server._host_firewall_live_readback(conn, "host-a", self.now)
        conn.close()
        self.assertEqual(live["protocol_capabilities"]["wireguard"], "supported")
        self.assertEqual(live["protocol_capabilities"]["fet"], "unsupported")

        conn = server.db()
        conn.execute("DELETE FROM host_firewall_readbacks WHERE host_id='host-a'")
        conn.commit()
        live = server._host_firewall_live_readback(conn, "host-a", self.now)
        conn.close()
        self.assertEqual(live["protocol_capabilities"]["wireguard"], "unknown")

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

    def test_outbound_wireguard_geoip_rule_is_supported(self):
        payload = self.policy()
        payload["rules"] = [{
            "key": "wg-cn-out", "priority": 100, "direction": "out", "protocol": "wireguard",
            "action": "block", "enabled": True, "port_start": 0,
            "ip_type": "geoip", "countries": ["cn"],
        }]
        normalized = server._validate_host_firewall_policy(payload)
        self.assertEqual(normalized["rules"][0]["direction"], "out")
        self.assertEqual(normalized["rules"][0]["protocol"], "wireguard")
        self.assertEqual(normalized["rules"][0]["countries"], ["CN"])

    def test_single_host_application_protocol_requires_fresh_confirmed_rfw_support(self):
        payload = self.policy()
        payload["rules"][0].update({"direction": "out", "protocol": "wireguard", "countries": ["CN"], "ip_type": "geoip"})
        with self.assertRaises(HTTPException) as raised:
            self.save(payload)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("wireguard", raised.exception.detail)

        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "socks"])
        with self.assertRaises(HTTPException) as raised:
            self.save(payload)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("不支持", raised.exception.detail)

        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "wireguard"])
        response = self.save(payload)
        self.assertEqual(response.status_code, 202)

    def test_fleet_wireguard_policy_defers_unknown_and_unsupported_nodes(self):
        conn = server.db()
        for host_id in ("host-unsupported", "host-unknown"):
            conn.execute(
                "INSERT INTO hosts(host_id,last_seen,node_id) VALUES(?,?,?)",
                (host_id, self.now, f"watcher-{host_id}"),
            )
            conn.execute(
                "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
                (host_id, self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
            )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host-a',?,?)",
            (self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory()
        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "wireguard"])
        self.install_rfw_capabilities("host-unsupported", ["all", "tcp", "udp", "socks"])

        payload = self.policy()
        payload["rules"][0].update({"direction": "out", "protocol": "wireguard", "countries": ["CN"], "ip_type": "geoip"})
        response = asyncio.run(server.update_fleet_firewall_policy(Request(payload)))
        result = json.loads(response.body)
        self.assertEqual((result["queued_hosts"], result["deferred_hosts"], result["total_hosts"]), (1, 2, 3))

        state = json.loads(server.get_fleet_firewall_policy().body)
        by_host = {item["host_id"]: item for item in state["hosts"]}
        self.assertEqual(by_host["host-unsupported"]["state"], "rfw_protocol_update_required")
        self.assertEqual(by_host["host-unsupported"]["unsupported_protocols"], ["wireguard"])
        self.assertEqual(by_host["host-unknown"]["state"], "awaiting_rfw_capability")
        self.assertEqual(by_host["host-unknown"]["unknown_protocols"], ["wireguard"])
        self.assertEqual(state["counts"]["required_protocols_supported_hosts"], 1)
        self.assertEqual(state["counts"]["required_protocols_unsupported_hosts"], 1)
        self.assertEqual(state["counts"]["required_protocols_unknown_hosts"], 1)

    def test_outbound_mtproto_geoip_rule_is_supported(self):
        payload = self.policy()
        payload["rules"] = [{
            "key": "mtproto-cn-out", "priority": 100, "direction": "out", "protocol": "mtproto",
            "action": "block", "enabled": True, "port_start": 0,
            "ip_type": "geoip", "countries": ["cn"],
        }]
        normalized = server._validate_host_firewall_policy(payload)
        self.assertEqual(normalized["rules"][0]["direction"], "out")
        self.assertEqual(normalized["rules"][0]["protocol"], "mtproto")
        self.assertEqual(normalized["rules"][0]["countries"], ["CN"])

    def test_single_host_mtproto_policy_requires_fresh_confirmed_rfw_capability(self):
        payload = self.mtproto_policy()
        with self.assertRaises(HTTPException) as raised:
            self.save(payload)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("尚无所选应用协议的新鲜 RFW 能力读回", raised.exception.detail)

        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "socks"])
        with self.assertRaises(HTTPException) as raised:
            self.save(payload)
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("mtproto", raised.exception.detail)
        self.assertIn("不支持", raised.exception.detail)

        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "socks", "mtproto"])
        response = self.save(payload)
        self.assertEqual(response.status_code, 202)

    def test_stale_rfw_capability_is_unknown_not_supported(self):
        self.install_rfw_capabilities(
            "host-a", ["all", "tcp", "mtproto"], self.now - server.STALE_SECONDS - 1
        )
        conn = server.db()
        live = server._host_firewall_live_readback(conn, "host-a", self.now)
        conn.close()
        self.assertEqual(server._protocol_capability_state(live, "mtproto"), "unknown")

    def test_policy_rejects_more_rules_than_the_rfw_ebpf_table(self):
        payload = self.policy()
        payload["rules"] = [{
            "key": f"rule-{index}", "priority": 1000 - index, "direction": "in",
            "protocol": "wireguard", "action": "block", "enabled": True,
            "port_start": 51820, "ip_type": "any",
        } for index in range(65)]
        with self.assertRaises(HTTPException) as raised:
            server._validate_host_firewall_policy(payload)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("64", raised.exception.detail)

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

    def test_fleet_policy_queues_only_nodes_that_report_runman_control_support(self):
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,node_id) VALUES('host-old',?,'watcher-node-old')",
            (self.now,),
        )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host-a',?,?)",
            (self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
        )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host-old',?,?)",
            (self.now, json.dumps({"host_firewall": {"control_api": "unsupported", "observed_at": self.now}})),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory()

        response = asyncio.run(server.update_fleet_firewall_policy(Request(self.policy())))
        result = json.loads(response.body)
        self.assertEqual(response.status_code, 202)
        self.assertEqual((result["queued_hosts"], result["deferred_hosts"], result["total_hosts"]), (1, 1, 2))

        conn = server.db()
        action = conn.execute(
            "SELECT * FROM security_actions WHERE host_id='host-a' AND action_type='apply_host_firewall_policy'"
        ).fetchone()
        self.assertIsNone(conn.execute(
            "SELECT id FROM security_actions WHERE host_id='host-old' AND action_type='apply_host_firewall_policy'"
        ).fetchone())
        params = json.loads(action["params_json"])
        self.assertEqual(params["fleet_revision"], 1)
        self.assertEqual(params["expected_node_id"], "watcher-node-a")
        host_policy = conn.execute("SELECT source_fleet_revision FROM host_firewall_policies WHERE host_id='host-a'").fetchone()
        conn.close()
        self.assertEqual(host_policy["source_fleet_revision"], 1)

        state = json.loads(server.get_fleet_firewall_policy().body)
        self.assertTrue(state["live_rule_readback_supported"])
        self.assertEqual(state["revision"], 1)
        self.assertEqual({item["host_id"]: item["state"] for item in state["hosts"]}["host-old"], "runman_update_required")

    def test_fleet_runtime_selection_maps_to_each_hosts_discovered_bridges(self):
        self.set_host_interface_inventory()
        podman_interface = {
            "name": "podman-lab", "kind": "bridge", "state": "up", "mtu": 1500,
            "addresses": ["10.89.0.1/24"], "runtimes": ["podman"],
            "network_names": ["lab"], "firewall_eligible": True,
        }
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,node_id) VALUES('host-b',?,'watcher-node-b')",
            (self.now,),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory("host-b", [podman_interface])

        policy = self.policy()
        policy["abuse"]["interfaces"] = []
        policy["abuse"]["runtimes"] = ["incus", "podman"]
        response = asyncio.run(server.update_fleet_firewall_policy(Request(policy)))
        result = json.loads(response.body)
        self.assertEqual((result["queued_hosts"], result["network_deferred_hosts"]), (2, 0))

        conn = server.db()
        actions = conn.execute(
            "SELECT host_id,params_json FROM security_actions WHERE action_type='apply_host_firewall_policy' ORDER BY host_id"
        ).fetchall()
        fleet_policy = json.loads(conn.execute("SELECT policy_json FROM fleet_firewall_policy WHERE id=1").fetchone()[0])
        conn.close()
        self.assertEqual(fleet_policy["abuse"]["runtimes"], ["incus", "podman"])
        self.assertEqual(fleet_policy["abuse"]["interfaces"], [])
        mapped = {row["host_id"]: json.loads(row["params_json"])["policy"]["abuse"] for row in actions}
        self.assertEqual(mapped["host-a"]["interfaces"], ["incusbr0"])
        self.assertEqual(mapped["host-b"]["interfaces"], ["podman-lab"])
        self.assertNotIn("runtimes", mapped["host-a"])
        self.assertNotIn("runtimes", mapped["host-b"])

        state = json.loads(server.get_fleet_firewall_policy().body)
        by_host = {item["host_id"]: item for item in state["hosts"]}
        self.assertEqual(by_host["host-b"]["container_interfaces"]["by_runtime"]["podman"], ["podman-lab"])

    def test_fleet_policy_defers_nodes_without_a_matching_discovered_runtime(self):
        self.set_host_interface_inventory()
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,node_id) VALUES('host-c',?,'watcher-node-c')",
            (self.now,),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory("host-c", [{
            "name": "eth0", "kind": "ether", "state": "up", "mtu": 1500,
            "addresses": ["192.0.2.10/24"], "runtimes": [],
            "network_names": [], "firewall_eligible": False,
        }])

        policy = self.policy()
        policy["abuse"]["interfaces"] = []
        policy["abuse"]["runtimes"] = ["podman"]
        response = asyncio.run(server.update_fleet_firewall_policy(Request(policy)))
        result = json.loads(response.body)
        self.assertEqual((result["queued_hosts"], result["deferred_hosts"], result["network_deferred_hosts"]), (0, 2, 2))
        state = json.loads(server.get_fleet_firewall_policy().body)
        by_host = {item["host_id"]: item for item in state["hosts"]}
        self.assertEqual(by_host["host-a"]["state"], "interfaces_not_found")
        self.assertEqual(by_host["host-c"]["state"], "interfaces_not_found")
        self.assertEqual(state["counts"]["network_deferred"], 2)

    def test_fleet_policy_waits_for_fresh_inventory_before_mapping_runtime(self):
        self.set_host_interface_inventory(observed_at=self.now - server.STALE_SECONDS - 1)
        policy = self.policy()
        policy["abuse"]["interfaces"] = []
        policy["abuse"]["runtimes"] = ["incus"]

        response = asyncio.run(server.update_fleet_firewall_policy(Request(policy)))
        result = json.loads(response.body)
        self.assertEqual((result["queued_hosts"], result["network_deferred_hosts"]), (0, 1))

        state = json.loads(server.get_fleet_firewall_policy().body)
        self.assertEqual(state["hosts"][0]["state"], "awaiting_interfaces")
        self.assertEqual(state["counts"]["network_deferred"], 1)

    def test_single_host_runtime_selector_is_resolved_before_agent_dispatch(self):
        policy = self.policy()
        policy["abuse"]["interfaces"] = []
        policy["abuse"]["runtimes"] = ["incus"]
        self.save(policy)
        conn = server.db()
        action = conn.execute(
            "SELECT params_json FROM security_actions WHERE action_type='apply_host_firewall_policy'"
        ).fetchone()
        conn.close()
        dispatched_policy = json.loads(action["params_json"])["policy"]
        self.assertEqual(dispatched_policy["abuse"]["interfaces"], ["incusbr0"])
        self.assertNotIn("runtimes", dispatched_policy["abuse"])

    def test_single_host_rejects_unverified_or_stale_bridge_selection(self):
        self.set_host_interface_inventory()
        policy = self.policy()
        policy["abuse"]["interfaces"] = ["not-a-bridge"]
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(server.update_host_firewall_policy("host-a", Request(policy)))
        self.assertEqual(raised.exception.status_code, 409)

        self.set_host_interface_inventory(observed_at=self.now - server.STALE_SECONDS - 1)
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(server.update_host_firewall_policy("host-a", Request(self.policy())))
        self.assertEqual(raised.exception.status_code, 409)

    def test_fleet_mtproto_policy_defers_nodes_until_fresh_rfw_support_is_confirmed(self):
        conn = server.db()
        for host_id in ("host-unsupported", "host-unknown"):
            conn.execute(
                "INSERT INTO hosts(host_id,last_seen,node_id) VALUES(?,?,?)",
                (host_id, self.now, f"watcher-{host_id}"),
            )
            conn.execute(
                "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
                (host_id, self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
            )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host-a',?,?)",
            (self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
        )
        conn.commit()
        conn.close()
        self.install_rfw_capabilities("host-a", ["all", "tcp", "udp", "mtproto"])
        self.install_rfw_capabilities("host-unsupported", ["all", "tcp", "udp", "socks"])

        response = asyncio.run(server.update_fleet_firewall_policy(Request(self.mtproto_policy())))
        result = json.loads(response.body)
        self.assertEqual((result["queued_hosts"], result["deferred_hosts"], result["total_hosts"]), (1, 2, 3))

        state = json.loads(server.get_fleet_firewall_policy().body)
        by_host = {item["host_id"]: item for item in state["hosts"]}
        self.assertEqual(by_host["host-unsupported"]["state"], "rfw_protocol_update_required")
        self.assertEqual(by_host["host-unknown"]["state"], "awaiting_rfw_capability")
        self.assertEqual(state["counts"]["mtproto_supported_hosts"], 1)
        self.assertEqual(state["counts"]["mtproto_unsupported_hosts"], 1)
        self.assertEqual(state["counts"]["mtproto_capability_unknown_hosts"], 1)
        conn = server.db()
        self.assertEqual(conn.execute(
            "SELECT COUNT(*) FROM security_actions WHERE action_type='apply_host_firewall_policy'"
        ).fetchone()[0], 1)
        conn.close()

    def test_fleet_reconcile_waits_for_next_fresh_mtproto_capability(self):
        conn = server.db()
        conn.execute(
            "INSERT INTO fleet_firewall_policy(id,revision,policy_json,updated_by,updated_at) VALUES(1,1,?,?,?)",
            (json.dumps(self.mtproto_policy()), "test", self.now),
        )
        conn.commit()
        queued = server._maybe_queue_fleet_firewall_policy(
            conn, "host-a", "watcher-node-a", self.now,
            {"host_firewall": {"control_api": "ready", "observed_at": self.now}},
        )
        self.assertFalse(queued)
        conn.close()

        self.install_rfw_capabilities("host-a", ["all", "tcp", "mtproto"])
        conn = server.db()
        queued = server._maybe_queue_fleet_firewall_policy(
            conn, "host-a", "watcher-node-a", self.now + 1,
            {"host_firewall": {"control_api": "ready", "observed_at": self.now + 1}},
        )
        conn.commit()
        self.assertTrue(queued)
        conn.close()

    def test_fleet_policy_repairs_only_fresh_post_apply_drift_and_surfaces_state(self):
        policy = self.policy()
        conn = server.db()
        conn.execute(
            "INSERT INTO fleet_firewall_policy(id,revision,policy_json,updated_by,updated_at) VALUES(1,1,?,?,?)",
            (json.dumps(policy), "test", self.now - 30),
        )
        conn.execute(
            "INSERT INTO host_firewall_policies(host_id,revision,policy_json,updated_by,updated_at,source_fleet_revision) VALUES(?,?,?,?,?,1)",
            ("host-a", 1, json.dumps(policy), "test", self.now - 20),
        )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            ("host-a", self.now, json.dumps({"host_firewall": {"control_api": "ready", "observed_at": self.now}})),
        )
        conn.execute(
            "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
            "VALUES(0,'host-a','host','','__host__','apply_host_firewall_policy',?,'succeeded','test',?,?)",
            (json.dumps({"fleet_revision": 1, "expected_node_id": "watcher-node-a", "policy": {"revision": 1, **policy}}), self.now - 10, self.now - 5),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory()

        snapshot = {
            "status": "drifted", "policy_revision": 1, "rule_count": 1,
            "managed_rule_count": 1, "drift_count": 1, "missing_count": 0,
            "rfw_api_version": "0.1.0", "capabilities_known": True,
            "supported_protocols": ["all", "tcp", "udp", "wireguard"],
            "rules": [{
                "id": 88, "priority": 100, "direction": "in", "protocol": "tcp",
                "action": "block", "enabled": True, "port_start": 443, "port_end": 443,
                "ip_type": "geoip", "countries": ["CN", "US"], "origin": "platform",
                "managed_key": "policy-rule-1", "sync_state": "drifted",
            }],
            "expected_rules": [{"key": "policy-rule-1", "id": 88, "sync_state": "drifted"}],
        }
        conn = server.db()
        server._store_host_firewall_readback(
            conn, "host-a", {"host_firewall": {"readback": {"status": "ready", "snapshot": snapshot}}}, self.now,
        )
        conn.commit()

        fleet_state = json.loads(server.get_fleet_firewall_policy().body)
        self.assertEqual(fleet_state["counts"]["drifted_hosts"], 1)
        self.assertEqual(fleet_state["hosts"][0]["state"], "drifted")

        security = {"host_firewall": {"control_api": "ready", "observed_at": self.now}}
        self.assertTrue(server._maybe_queue_fleet_firewall_policy(conn, "host-a", "watcher-node-a", self.now, security))
        self.assertFalse(server._maybe_queue_fleet_firewall_policy(conn, "host-a", "watcher-node-a", self.now + 1, security))

        conn.execute(
            "UPDATE security_actions SET status='succeeded',updated_at=? WHERE id=(SELECT MAX(id) FROM security_actions WHERE host_id='host-a' AND action_type='apply_host_firewall_policy')",
            (self.now + 2,),
        )
        conn.commit()
        self.assertFalse(server._maybe_queue_fleet_firewall_policy(conn, "host-a", "watcher-node-a", self.now + 3, security))

        server._store_host_firewall_readback(
            conn, "host-a", {"host_firewall": {"readback": {"status": "ready", "snapshot": snapshot}}}, self.now + 4,
        )
        conn.commit()
        self.assertTrue(server._maybe_queue_fleet_firewall_policy(conn, "host-a", "watcher-node-a", self.now + 4, security))
        conn.close()

    def test_enabled_fleet_template_rejects_conflicting_single_host_policy(self):
        asyncio.run(server.update_fleet_firewall_policy(Request(self.policy())))

        with self.assertRaises(HTTPException) as raised:
            self.save()
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("全局防火墙模板已启用", raised.exception.detail)

        conn = server.db()
        self.assertIsNone(conn.execute(
            "SELECT host_id FROM host_firewall_policies WHERE host_id='host-a'"
        ).fetchone())
        conn.close()

    def test_capable_node_receives_saved_fleet_policy_on_its_next_report(self):
        fleet_payload = self.policy()
        conn = server.db()
        conn.execute(
            "INSERT INTO fleet_firewall_policy(id,revision,policy_json,updated_by,updated_at) VALUES(1,1,?,?,?)",
            (json.dumps(fleet_payload), "test", self.now),
        )
        conn.commit()
        conn.close()
        self.set_host_interface_inventory()

        conn = server.db()
        queued = server._maybe_queue_fleet_firewall_policy(
            conn, "host-a", "watcher-node-a", self.now,
            {"host_firewall": {"control_api": "ready", "observed_at": self.now}},
        )
        conn.commit()
        conn.close()
        self.assertTrue(queued)
        conn = server.db()
        action = conn.execute("SELECT params_json FROM security_actions WHERE action_type='apply_host_firewall_policy'").fetchone()
        conn.close()
        self.assertEqual(json.loads(action["params_json"])["fleet_revision"], 1)

    def test_rfw_event_ingestion_groups_deduplicates_and_reports_direction(self):
        def event(sequence, action="block", countries=None):
            return {
                "sequence": sequence,
                "cursor": f"rfw-a:{sequence}",
                "observed_at": self.now,
                "source_ip": "10.0.0.4" if sequence == 1 else "8.8.8.8",
                "source_port": 51820,
                "destination_ip": "1.1.1.1",
                "destination_port": 51820 if sequence == 1 else 443,
                "transport": "udp" if sequence == 1 else "tcp",
                "app_protocol": "wireguard" if sequence == 1 else "socks",
                "direction": "out" if sequence == 1 else "in",
                "action": action,
                "rule_id": 4,
                "rule_countries": countries or ["CN"],
            }

        security = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-a", "next_cursor": "rfw-a:2",
            "cursor_reset": False, "dropped": 0, "events": [event(1), event(2)],
        }}
        conn = server.db()
        alerts, cursor = server._ingest_host_firewall_events(conn, "host-a", security, self.now)
        self.assertEqual(cursor, "rfw-a:2")
        self.assertEqual(len(alerts), 2)
        outbound = next(item for item in alerts if item["type"] == "rfw_cn_wireguard_out_block")
        self.assertEqual(outbound["severity"], "warning")
        self.assertIn("出站到 CN", outbound["message"])
        passed = security["host_firewall"]["events"][1].copy()
        passed.update({"sequence": 3, "cursor": "rfw-a:3", "app_protocol": "wireguard", "action": "pass", "direction": "out"})
        repeated = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-a", "next_cursor": "rfw-a:2",
            "cursor_reset": False, "dropped": 0, "events": [event(1), event(2)],
        }}
        deduplicated, _ = server._ingest_host_firewall_events(conn, "host-a", repeated, self.now + 1)
        self.assertEqual(deduplicated, [])

        followup = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-a", "next_cursor": "rfw-a:3",
            "cursor_reset": False, "dropped": 0, "events": [passed],
        }}
        passed_alerts, _ = server._ingest_host_firewall_events(conn, "host-a", followup, self.now + 2)
        self.assertEqual(len(passed_alerts), 1)
        self.assertEqual(passed_alerts[0]["severity"], "critical")
        self.assertIn("被放行", passed_alerts[0]["title"])
        state = conn.execute("SELECT instance_id,sequence FROM host_firewall_event_state WHERE host_id='host-a'").fetchone()
        self.assertEqual((state["instance_id"], state["sequence"]), ("rfw-a", 3))
        conn.close()

    def test_rfw_gap_and_mixed_country_scope_are_not_overstated(self):
        conn = server.db()
        conn.execute(
            "INSERT INTO host_firewall_event_state(host_id,instance_id,sequence,cursor,updated_at) VALUES(?,?,?,?,?)",
            ("host-a", "rfw-b", 1, "rfw-b:1", self.now - 1),
        )
        conn.commit()
        conn.close()
        security = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-b", "next_cursor": "rfw-b:3",
            "cursor_reset": False, "dropped": 0, "events": [{
                "sequence": 3, "cursor": "rfw-b:3", "observed_at": self.now,
                "source_ip": "8.8.8.8", "source_port": 443,
                "destination_ip": "1.1.1.1", "destination_port": 51820,
                "transport": "udp", "app_protocol": "wireguard", "direction": "out", "action": "block",
                "rule_id": 5, "rule_countries": ["CN", "US"],
            }],
        }}
        conn = server.db()
        alerts, _ = server._ingest_host_firewall_events(conn, "host-a", security, self.now)
        scoped = next(item for item in alerts if item["type"].startswith("rfw_cn_"))
        gap = next(item for item in alerts if item["type"] == "rfw_event_gap")
        self.assertEqual(scoped["rfw_evidence"]["country_confidence"], "rule_scope_includes_cn")
        self.assertIn("实际国家未知", scoped["message"])
        self.assertNotIn("出站到 CN", scoped["message"])
        self.assertIn("实际命中国家", scoped["message"])
        self.assertIn("序号", gap["message"])
        conn.close()

    def test_rfw_mtproto_cn_event_creates_specific_alert(self):
        security = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-mtproto", "next_cursor": "rfw-mtproto:1",
            "cursor_reset": False, "dropped": 0, "events": [{
                "sequence": 1, "cursor": "rfw-mtproto:1", "observed_at": self.now,
                "source_ip": "192.0.2.10", "source_port": 41000,
                "destination_ip": "203.0.113.20", "destination_port": 443,
                "transport": "tcp", "app_protocol": "mtproto", "direction": "out", "action": "block",
                "rule_id": 3, "rule_countries": ["CN"],
            }],
        }}
        conn = server.db()
        alerts, _ = server._ingest_host_firewall_events(conn, "host-a", security, self.now)
        conn.close()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "rfw_cn_mtproto_out_block")
        self.assertIn("MTProto", alerts[0]["title"])
        self.assertIn("已阻断", alerts[0]["message"])

    def test_rfw_openvpn_cn_event_creates_alert_with_non_accusatory_context(self):
        security = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-openvpn", "next_cursor": "rfw-openvpn:1",
            "cursor_reset": False, "dropped": 0, "events": [{
                "sequence": 1, "cursor": "rfw-openvpn:1", "observed_at": self.now,
                "source_ip": "198.51.100.10", "source_port": 41000,
                "destination_ip": "203.0.113.20", "destination_port": 1194,
                "transport": "udp", "app_protocol": "openvpn", "direction": "in", "action": "pass",
                "rule_id": 3, "rule_countries": ["CN"],
            }],
        }}
        conn = server.db()
        alerts, _ = server._ingest_host_firewall_events(conn, "host-a", security, self.now)
        conn.close()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "rfw_cn_openvpn_in_pass")
        self.assertIn("OpenVPN", alerts[0]["title"])
        self.assertIn("来自 CN 的入站", alerts[0]["message"])
        self.assertIn("不代表服务未授权", alerts[0]["message"])

    def test_rfw_fet_cn_alert_discloses_ss_detection_is_heuristic(self):
        security = {"host_firewall": {
            "events_api": "ready", "instance_id": "rfw-fet", "next_cursor": "rfw-fet:1",
            "cursor_reset": False, "dropped": 0, "events": [{
                "sequence": 1, "cursor": "rfw-fet:1", "observed_at": self.now,
                "source_ip": "192.0.2.10", "source_port": 53000,
                "destination_ip": "203.0.113.20", "destination_port": 443,
                "transport": "tcp", "app_protocol": "fet", "direction": "out", "action": "block",
                "rule_id": 3, "rule_countries": ["CN"],
            }],
        }}
        conn = server.db()
        alerts, _ = server._ingest_host_firewall_events(conn, "host-a", security, self.now)
        conn.close()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "rfw_cn_fet_out_block")
        self.assertIn("可能含 SS 类", alerts[0]["title"])
        self.assertIn("不能确证 Shadowsocks", alerts[0]["message"])

    def test_agent_advances_rfw_event_cursor_only_after_matching_server_ack(self):
        class Response:
            def __init__(self, cursor):
                self.cursor = cursor
            def raise_for_status(self):
                return None
            def json(self):
                return {"firewall_event_cursor": self.cursor}

        with mock.patch.object(agent, "_firewall_event_cursor", "rfw-a:1"), \
             mock.patch.object(agent, "_pending_firewall_event_cursor", "rfw-a:2"), \
             mock.patch.object(agent.requests, "post", return_value=Response("rfw-a:2")):
            result = agent.push("https://watcher.invalid", "secret", {})
            self.assertEqual(result["firewall_event_cursor"], "rfw-a:2")
            self.assertEqual(agent._firewall_event_cursor, "rfw-a:2")

        with mock.patch.object(agent, "_firewall_event_cursor", "rfw-a:1"), \
             mock.patch.object(agent, "_pending_firewall_event_cursor", "rfw-a:2"), \
             mock.patch.object(agent.requests, "post", return_value=Response("rfw-a:1")):
            agent.push("https://watcher.invalid", "secret", {})
            self.assertEqual(agent._firewall_event_cursor, "rfw-a:1")

    def test_viewer_cannot_update_fleet_firewall_policy(self):
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(server.update_fleet_firewall_policy(Request(self.policy(), role="viewer")))
        self.assertEqual(raised.exception.status_code, 403)
        conn = server.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM fleet_firewall_policy").fetchone()[0], 0)
        conn.close()

    def test_runman_firewall_capability_probe_distinguishes_supported_and_old_agent(self):
        class Response:
            def __init__(self, status):
                self.status = status
            def read(self, _limit):
                return b""

        class Connection:
            def __init__(self, status):
                self.status = status
                self.timeout = 0
            def request(self, method, path, headers=None):
                self.requested = (method, path, headers)
            def getresponse(self):
                return Response(self.status)
            def close(self):
                pass

        for status, expected in ((405, "ready"), (404, "unsupported"), (503, "unavailable")):
            connection = Connection(status)
            with mock.patch.object(agent.os, "name", "posix"), mock.patch.object(
                agent.network_quarantine, "_UnixHTTP", return_value=connection
            ):
                result = agent._runman_firewall_control_status()
            self.assertEqual(result["control_api"], expected)
            self.assertEqual(connection.requested[:2], ("GET", "/v1/firewall/policy"))

    def test_runman_live_rfw_readback_is_bounded_and_validated(self):
        snapshot = {
            "status": "drifted", "observed_at": self.now, "policy_revision": 3,
            "rule_count": 1, "managed_rule_count": 1, "drift_count": 1, "missing_count": 0,
            "rfw_api_version": "0.1.0", "capabilities_known": True,
            "supported_protocols": ["all", "tcp", "udp", "mtproto"],
            "rules": [{
                "id": 9, "priority": 100, "direction": "out", "protocol": "mtproto",
                "action": "pass", "enabled": True, "port_start": 51820, "port_end": 51820,
                "ip_type": "geoip", "countries": ["CN"], "origin": "platform",
                "managed_key": "mtproto-cn-out", "sync_state": "drifted",
            }],
            "expected_rules": [{"key": "mtproto-cn-out", "id": 9, "sync_state": "drifted"}],
        }

        class Response:
            def __init__(self, status, body):
                self.status = status
                self.body = body
            def read(self, _limit):
                return self.body

        class Connection:
            def __init__(self, status, body):
                self.status = status
                self.body = body
                self.timeout = 0
            def request(self, method, path, headers=None):
                self.requested = (method, path, headers)
            def getresponse(self):
                return Response(self.status, self.body)
            def close(self):
                pass

        response_body = json.dumps(snapshot).encode()
        for status, body, expected in (
            (200, response_body, "ready"), (404, b"", "unsupported"), (503, b"", "unavailable"),
            (200, b"not-json", "unavailable"),
        ):
            connection = Connection(status, body)
            with mock.patch.object(agent.os, "name", "posix"), mock.patch.object(
                agent.network_quarantine, "_UnixHTTP", return_value=connection
            ):
                result = agent._runman_firewall_readback()
            self.assertEqual(result["status"], expected)
            self.assertEqual(connection.requested[:2], ("GET", "/v1/firewall/readback"))
            if expected == "ready":
                self.assertEqual(result["snapshot"]["status"], "drifted")
                self.assertEqual(result["snapshot"]["rules"][0]["managed_key"], "mtproto-cn-out")
                self.assertTrue(result["snapshot"]["capabilities_known"])
                self.assertIn("mtproto", result["snapshot"]["supported_protocols"])

        legacy_snapshot = {key: value for key, value in snapshot.items() if key not in {
            "rfw_api_version", "capabilities_known", "supported_protocols",
        }}
        legacy_connection = Connection(200, json.dumps(legacy_snapshot).encode())
        with mock.patch.object(agent.os, "name", "posix"), mock.patch.object(
            agent.network_quarantine, "_UnixHTTP", return_value=legacy_connection
        ):
            legacy_result = agent._runman_firewall_readback()
        self.assertEqual(legacy_result["status"], "ready")
        self.assertFalse(legacy_result["snapshot"]["capabilities_known"])
        self.assertEqual(legacy_result["snapshot"]["supported_protocols"], [])

    def test_runman_firewall_event_parser_accepts_mtproto(self):
        page = {
            "instance_id": "rfw-a", "next_cursor": "rfw-a:1", "cursor_reset": False,
            "dropped": 0, "dropped_total": 0, "events": [{
                "sequence": 1, "cursor": "rfw-a:1", "observed_at": self.now,
                "source_ip": "192.0.2.10", "source_port": 41000,
                "destination_ip": "203.0.113.20", "destination_port": 443,
                "transport": "tcp", "app_protocol": "mtproto", "direction": "out", "action": "block",
                "rule_id": 3, "rule_countries": ["CN"],
            }],
        }

        class Response:
            status = 200
            def read(self, _limit):
                return json.dumps(page).encode()

        class Connection:
            timeout = 0
            def request(self, *_args, **_kwargs):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass

        with mock.patch.object(agent.os, "name", "posix"), mock.patch.object(
            agent.network_quarantine, "_UnixHTTP", return_value=Connection()
        ):
            result = agent._runman_firewall_events()
        self.assertEqual(result["events_api"], "ready")
        self.assertEqual(result["events"][0]["app_protocol"], "mtproto")

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
