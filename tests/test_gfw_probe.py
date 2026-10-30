import json
import errno
import io
import sqlite3
import time
import unittest
import uuid
from unittest import mock

from client import gfw_probe
from server import gfw_monitor


class GfwProbeWorkerTests(unittest.TestCase):
    def make_job(self):
        target_host_id = "[5Gbps] Bero DE 原生IP 移动联通可用小钢炮"
        target_node_id = "8b1d4f90ec7f41c88563f770f8ce7ba0"
        target = {"ip": "8.8.8.8", "port": 443, "interface": "ens3"}
        target["id"] = gfw_probe._digest({"host_id": target_host_id, **target})[:24]
        targets = [target]
        return {
            "id": str(uuid.uuid4()),
            "cycle_id": str(uuid.uuid4()),
            "source_host_id": "ZaoZhuang-BGP-NAT",
            "source_node_id": "ad086f17ebda490bb057af9e6bf1a970",
            "target_host_id": target_host_id,
            "target_node_id": target_node_id,
            "role": "mainland",
            "lease": "a" * 48,
            "deadline_at": int(time.time()) + 300,
            "targets": targets,
            "targets_hash": gfw_probe._digest(targets),
        }

    def test_server_host_name_and_32_character_node_id_are_valid_targets(self):
        job = self.make_job()
        gfw_probe._validate(job, job["source_host_id"], job["source_node_id"])

    def test_control_characters_in_target_identity_are_rejected(self):
        job = self.make_job()
        job["target_host_id"] = "server\nforged"
        with self.assertRaisesRegex(ValueError, "invalid_probe_identity"):
            gfw_probe._validate(job, job["source_host_id"], job["source_node_id"])

    def test_unavailable_runtime_reports_failure_instead_of_silently_expiring(self):
        job = self.make_job()
        posts = []
        with mock.patch.object(gfw_probe, "available", return_value=False):
            gfw_probe.handle(
                {"job": job}, job["source_host_id"], job["source_node_id"],
                lambda path, payload: posts.append((path, payload)),
            )
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][0], "/api/v1/gfw-probe/failure")
        self.assertEqual(posts[0][1]["failure_code"], "probe_runtime_unavailable")
        self.assertNotIn("targets", posts[0][1])

    def test_network_errors_keep_the_kernel_reason(self):
        cases = {
            errno.EAFNOSUPPORT: "family_unsupported",
            errno.ENETUNREACH: "no_route",
            errno.EHOSTUNREACH: "host_unreachable",
            errno.EACCES: "local_policy_block",
            errno.EIO: "network_error",
        }
        for error_number, expected in cases.items():
            with self.subTest(error_number=error_number):
                self.assertEqual(gfw_probe._network_error_code(OSError(error_number, "test")), expected)

    def test_route_capabilities_detect_default_routes_per_family(self):
        ipv4 = io.StringIO(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "ens3 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n"
        )
        ipv6 = io.StringIO(
            "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32
            + " 00000000 00000000 00000000 00000001 ens3\n"
        )
        with mock.patch("builtins.open", side_effect=[ipv4, ipv6]):
            self.assertEqual(gfw_probe.route_capabilities(), {
                "ipv4_default_route": True,
                "ipv6_default_route": True,
            })

    def test_route_capabilities_report_ipv4_only_probe(self):
        ipv4 = io.StringIO(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "ens3 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n"
        )
        with mock.patch("builtins.open", side_effect=[ipv4, io.StringIO("")]):
            self.assertEqual(gfw_probe.route_capabilities(), {
                "ipv4_default_route": True,
                "ipv6_default_route": False,
            })


class GfwProbeFailurePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        gfw_monitor.initialize(self.conn)
        self.now = int(time.time())
        self.host_id = "[5Gbps] Bero DE 原生IP 移动联通可用小钢炮"
        self.node_id = "8b1d4f90ec7f41c88563f770f8ce7ba0"
        self.source_host_id = "ZaoZhuang-BGP-NAT"
        self.source_node_id = "ad086f17ebda490bb057af9e6bf1a970"
        self.cycle_id = str(uuid.uuid4())
        self.job_id = str(uuid.uuid4())
        self.lease = "b" * 48
        targets = [{"id": "target-1", "ip": "8.8.8.8", "port": 443, "interface": "ens3"}]
        self.targets_hash = gfw_monitor._digest(targets)
        self.conn.execute(
            "INSERT INTO gfw_probe_roles(node_id,host_id,role,updated_at) VALUES(?,?,?,?)",
            (self.source_node_id, self.source_host_id, "mainland", self.now),
        )
        self.conn.execute(
            "INSERT INTO gfw_cycles(id,host_id,node_id,targets_json,status,created_at,deadline_at) VALUES(?,?,?,?,?,?,?)",
            (self.cycle_id, self.host_id, self.node_id, gfw_monitor._json(targets), "running", self.now, self.now + 600),
        )
        self.conn.execute(
            "INSERT INTO gfw_probe_jobs(id,cycle_id,source_host_id,source_node_id,role,targets_json,targets_hash,lease,status,created_at,deadline_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (self.job_id, self.cycle_id, self.source_host_id, self.source_node_id, "mainland",
             gfw_monitor._json(targets), self.targets_hash, self.lease, "running", self.now, self.now + 600),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_signed_failure_receipt_closes_job_and_explains_unknown_cycle(self):
        payload = {
            "job_id": self.job_id,
            "cycle_id": self.cycle_id,
            "source_host_id": self.source_host_id,
            "source_node_id": self.source_node_id,
            "lease": self.lease,
            "targets_hash": self.targets_hash,
            "failure_code": "invalid_probe_identity",
        }
        self.assertEqual(gfw_monitor.report_failure(self.conn, payload, self.now + 1), {"ok": True})
        job = self.conn.execute("SELECT status,error FROM gfw_probe_jobs WHERE id=?", (self.job_id,)).fetchone()
        self.assertEqual((job["status"], job["error"]), ("failed", "invalid_probe_identity"))
        state = self.conn.execute("SELECT evidence_json FROM gfw_states WHERE host_id=?", (self.host_id,)).fetchone()
        evidence = json.loads(state["evidence_json"])
        self.assertIn("探针任务身份校验失败", evidence["reason"])
        self.assertEqual(evidence["probe_failures"][0]["code"], "invalid_probe_identity")

    def test_failure_receipt_requires_matching_lease(self):
        payload = {
            "job_id": self.job_id,
            "cycle_id": self.cycle_id,
            "source_host_id": self.source_host_id,
            "source_node_id": self.source_node_id,
            "lease": "c" * 48,
            "targets_hash": self.targets_hash,
            "failure_code": "invalid_probe_identity",
        }
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as raised:
            gfw_monitor.report_failure(self.conn, payload, self.now + 1)
        self.assertEqual(raised.exception.status_code, 403)

    def test_latest_role_result_includes_endpoint_and_source_evidence(self):
        self.conn.execute(
            "UPDATE gfw_probe_jobs SET status='complete',finished_at=? WHERE id=?",
            (self.now + 2, self.job_id),
        )
        self.conn.execute(
            "INSERT INTO gfw_probe_results(job_id,target_id,success,latency_ms,error,attempts) VALUES(?,?,?,?,?,?)",
            (self.job_id, "target-1", 1, 41.5, "", 1),
        )
        result = gfw_monitor._latest_role_result(self.conn, "mainland")
        self.assertEqual(result["target_host_id"], self.host_id)
        self.assertEqual(result["source_region"], "")
        self.assertEqual(result["endpoints"][0]["ip"], "8.8.8.8")
        self.assertEqual(result["endpoints"][0]["port"], 443)
        self.assertTrue(result["endpoints"][0]["success"])


class GfwCoverageDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.now = int(time.time())
        self.conn.executescript("""
          CREATE TABLE hosts(host_id TEXT PRIMARY KEY,last_seen INTEGER NOT NULL,agent_version TEXT NOT NULL DEFAULT 'unknown',node_id TEXT NOT NULL DEFAULT '',config_json TEXT NOT NULL DEFAULT '{}');
          CREATE TABLE ops_hosts(node TEXT PRIMARY KEY,payload TEXT NOT NULL DEFAULT '{}');
          CREATE TABLE host_security(id INTEGER PRIMARY KEY AUTOINCREMENT,host_id TEXT NOT NULL,ts INTEGER NOT NULL,payload_json TEXT NOT NULL);
          CREATE TABLE reports(id INTEGER PRIMARY KEY AUTOINCREMENT,host_id TEXT NOT NULL,container_name TEXT NOT NULL,runtime TEXT NOT NULL,project TEXT NOT NULL DEFAULT '',ts INTEGER NOT NULL,payload_json TEXT NOT NULL);
        """)
        gfw_monitor.initialize(self.conn)
        self.target_host = "target-vps"
        self.target_node = "target-node"
        self.conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES(?,?,?)", (self.target_host, self.now, self.target_node))
        probes = [
            ("mainland-a", "probe-cn-a", "mainland", "Zaozhuang", "Telecom", self.now - 10),
            ("mainland-b", "probe-cn-b", "mainland", "Shanghai", "Unicom", self.now - 20),
            ("overseas-a", "probe-us-a", "overseas", "US", "", self.now - 30),
        ]
        for host_id, node_id, role, region, carrier, last_seen in probes:
            self.conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES(?,?,?)", (host_id, last_seen, node_id))
            self.conn.execute("INSERT INTO ops_hosts(node,payload) VALUES(?,?)", (node_id, json.dumps({"report_interval": 300})))
            self.conn.execute("INSERT INTO gfw_probe_roles(node_id,host_id,role,region,carrier,updated_at) VALUES(?,?,?,?,?,?)",
                              (node_id, host_id, role, region, carrier, self.now))
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_probe_health_reports_online_offline_and_network_labels(self):
        self.conn.execute("UPDATE hosts SET last_seen=? WHERE node_id='probe-cn-b'", (self.now - 4000,))
        self.conn.commit()
        health = gfw_monitor._probe_health_snapshot(self.conn, self.now)
        self.assertEqual(health["roles"]["mainland"]["configured"], 2)
        self.assertEqual(health["roles"]["mainland"]["online"], 1)
        self.assertEqual(health["roles"]["mainland"]["offline"], 1)
        self.assertEqual(health["roles"]["mainland"]["distinct_carriers"], 1)
        self.assertEqual(health["roles"]["overseas"]["online_missing_region"], 0)

    def test_status_map_explains_missing_public_tcp_listener(self):
        self.conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            (self.target_host, self.now, json.dumps({"host_firewall": {"interface_inventory": {
                "status": "ready", "interfaces": [{"name": "ens3", "addresses": ["8.8.8.8/24"]}],
            }}})),
        )
        self.conn.execute(
            "INSERT INTO reports(host_id,container_name,runtime,project,ts,payload_json) VALUES(?,?,?,?,?,?)",
            (self.target_host, "container-a", "incus", "default", self.now,
             json.dumps({"id": "container-id", "network_addresses": ["10.0.0.2"],
                         "security": {"listening_ports": [], "network_exposure": []}})),
        )
        self.conn.commit()
        gfw_monitor._schedule(self.conn, self.now)
        self.conn.commit()
        status = gfw_monitor.status_map(self.conn, self.now)[self.target_host]
        self.assertEqual(status["target_readiness"]["status"], "public_tcp_endpoint_missing")
        self.assertIn("实际监听端口", status["target_readiness"]["reason"])
        self.assertIn("检查容器监听端口", status["target_readiness"]["next_step"])

    def test_status_map_reports_expired_host_heartbeat_before_waiting_for_a_probe(self):
        self.conn.execute("UPDATE hosts SET last_seen=? WHERE host_id=?", (self.now - gfw_monitor.STALE_SECONDS - 1, self.target_host))
        self.conn.commit()
        status = gfw_monitor.status_map(self.conn, self.now)[self.target_host]
        self.assertEqual(status["target_readiness"]["status"], "host_offline")
        self.assertIn("心跳已过期", status["reason"])

    def test_scheduler_records_endpoint_diagnosis_even_when_probe_roles_are_missing(self):
        self.conn.execute("DELETE FROM gfw_probe_roles")
        self.conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            (self.target_host, self.now, json.dumps({"host_firewall": {"interface_inventory": {
                "status": "ready", "interfaces": [{"name": "ens3", "addresses": ["8.8.8.8/24"]}],
            }}})),
        )
        self.conn.execute(
            "INSERT INTO reports(host_id,container_name,runtime,project,ts,payload_json) VALUES(?,?,?,?,?,?)",
            (self.target_host, "container-a", "incus", "default", self.now,
             json.dumps({"id": "container-id", "network_addresses": ["10.0.0.2"],
                         "security": {"listening_ports": [], "network_exposure": []}})),
        )
        self.conn.commit()
        gfw_monitor._schedule(self.conn, self.now)
        self.conn.commit()
        stored = self.conn.execute("SELECT evidence_json FROM gfw_states WHERE host_id=?", (self.target_host,)).fetchone()
        self.assertIsNotNone(stored)
        readiness = json.loads(stored["evidence_json"])["target_readiness"]
        self.assertEqual(readiness["status"], "public_tcp_endpoint_missing")
        self.assertIn("实际监听端口", readiness["reason"])

    def test_partial_probe_results_are_visible_but_never_confirm_a_state(self):
        self.conn.execute("DELETE FROM gfw_probe_roles")
        source_node = "probe-cn-a"
        self.conn.execute(
            "INSERT INTO gfw_probe_roles(node_id,host_id,role,updated_at,source_network_id,source_network_updated_at) VALUES(?,?,?,?,?,?)",
            (source_node, "mainland-a", "mainland", self.now, "cn-net-a", self.now),
        )
        self.conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            (self.target_host, self.now, json.dumps({"host_firewall": {"interface_inventory": {
                "status": "ready", "interfaces": [],
            }}})),
        )
        self.conn.execute(
            "INSERT INTO reports(host_id,container_name,runtime,project,ts,payload_json) VALUES(?,?,?,?,?,?)",
            (self.target_host, "container-a", "incus", "default", self.now,
             json.dumps({"id": "container-id", "network_addresses": ["8.8.8.8"],
                         "security": {"listening_ports": [443], "listening_endpoints": ["0.0.0.0:443"], "network_exposure": []}})),
        )
        self.conn.commit()

        gfw_monitor._schedule(self.conn, self.now)
        cycle = self.conn.execute("SELECT * FROM gfw_cycles WHERE host_id=?", (self.target_host,)).fetchone()
        self.assertIsNotNone(cycle)
        jobs = self.conn.execute("SELECT * FROM gfw_probe_jobs WHERE cycle_id=?", (cycle["id"],)).fetchall()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["role"], "mainland")
        self.assertEqual(jobs[0]["source_node_id"], source_node)

        targets = json.loads(jobs[0]["targets_json"])
        self.conn.execute("UPDATE gfw_probe_jobs SET status='complete',finished_at=? WHERE id=?", (self.now + 1, jobs[0]["id"]))
        self.conn.execute(
            "INSERT INTO gfw_probe_results(job_id,target_id,success,latency_ms,error,attempts) VALUES(?,?,?,?,?,?)",
            (jobs[0]["id"], targets[0]["id"], 1, 10.0, "", 1),
        )
        self.assertTrue(gfw_monitor._apply_cycle(
            self.conn,
            self.conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (cycle["id"],)).fetchone(),
            self.now + 1,
        ))
        state = self.conn.execute("SELECT state,last_classification,evidence_json FROM gfw_states WHERE host_id=?", (self.target_host,)).fetchone()
        self.assertEqual(state["state"], "unassessed")
        self.assertEqual(state["last_classification"], "unknown")
        evidence = json.loads(state["evidence_json"])
        self.assertEqual(evidence["targets"][0]["mainland"]["success"], 1)
        self.assertTrue(evidence["reason"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM gfw_events WHERE host_id=?", (self.target_host,)).fetchone()[0], 0)


class GfwFamilyProbePlanTests(unittest.TestCase):
    @staticmethod
    def source(node_id, role, network_id, ipv4, ipv6):
        return {
            "node_id": node_id,
            "role": role,
            "network_id": network_id,
            "ipv4_default_route": ipv4,
            "ipv6_default_route": ipv6,
        }

    def test_sources_are_selected_per_target_family_and_independent_network(self):
        roles = {
            "mainland": [
                self.source("cn-v4-a", "mainland", "cn-net-a", True, False),
                self.source("cn-v4-b", "mainland", "cn-net-b", True, False),
                self.source("cn-v6-a", "mainland", "cn-net-c", False, True),
                self.source("cn-v6-b", "mainland", "cn-net-d", False, True),
            ],
            "overseas": [
                self.source("overseas-v4", "overseas", "us-net-a", True, False),
                self.source("overseas-v6", "overseas", "us-net-b", False, True),
            ],
        }
        plan, coverage = gfw_monitor._family_probe_plan(roles)
        self.assertTrue(coverage["ipv4"]["ready"])
        self.assertTrue(coverage["ipv6"]["ready"])
        self.assertEqual({source["node_id"] for source in plan["ipv4"]["mainland"]}, {"cn-v4-a", "cn-v4-b"})
        self.assertEqual({source["node_id"] for source in plan["ipv6"]["mainland"]}, {"cn-v6-a", "cn-v6-b"})
        self.assertEqual(plan["ipv4"]["overseas"][0]["node_id"], "overseas-v4")
        self.assertEqual(plan["ipv6"]["overseas"][0]["node_id"], "overseas-v6")

    def test_missing_default_route_does_not_hide_target_specific_ipv6_routes(self):
        roles = {
            "mainland": [
                self.source("cn-a", "mainland", "cn-net-a", True, None),
                self.source("cn-b", "mainland", "cn-net-b", True, False),
            ],
            "overseas": [self.source("overseas-a", "overseas", "us-net-a", True, None)],
        }
        plan, coverage = gfw_monitor._family_probe_plan(roles)
        self.assertTrue(coverage["ipv4"]["ready"])
        self.assertTrue(coverage["ipv6"]["ready"])
        self.assertEqual(gfw_monitor._family_coverage_reason(coverage, {"ipv4"}), "")
        self.assertEqual(gfw_monitor._family_coverage_reason(coverage, {"ipv6"}), "")
        self.assertEqual(len(plan["ipv6"]["mainland"]), 2)
        self.assertEqual(len(plan["ipv6"]["overseas"]), 1)
        self.assertEqual(coverage["ipv6"]["mainland"]["route_present_sources"], 0)
        self.assertEqual(coverage["ipv6"]["mainland"]["route_missing_sources"], 1)
        self.assertEqual(coverage["ipv6"]["mainland"]["route_unknown_sources"], 1)


if __name__ == "__main__":
    unittest.main()
