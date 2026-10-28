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


if __name__ == "__main__":
    unittest.main()
