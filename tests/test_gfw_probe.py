import json
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


if __name__ == "__main__":
    unittest.main()
