import hashlib
import hmac
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_server_res", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class ResourceLimitsApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "monitor.db")
        self.patch = mock.patch.multiple(
            server,
            DB_PATH=self.db_path,
            DASHBOARD_USERNAME="test-admin",
            DASHBOARD_PASSWORD="test-password-only",
            SHARED_SECRET="test-shared-secret",
        )
        self.patch.start()
        server.init_db()
        server.app.state.dashboard_login_limiter.records.clear()

        self.now = int(time.time())
        self.vm_id = "11111111-2222-4333-8444-555555555555"
        self.gen_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,agent_version,node_id,config_json) VALUES(?,?,?,?,?)",
            ("host-1", self.now, "2.2.8", "node-1", "{}"),
        )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES(?,?,?)",
            (
                "host-1",
                self.now,
                json.dumps(
                    {
                        "host_firewall": {
                            "interface_inventory": {
                                "interfaces": [
                                    {"name": "eth0", "kind": "ether", "state": "up", "is_default_route": True}
                                ]
                            }
                        },
                        "manual_resource_limits": {"revision": 1, "state": "applied", "items": []},
                    }
                ),
            ),
        )
        for runtime, project, cname, cid, extra in (
            ("runman", "default", self.vm_id, self.vm_id, {"instance_id": self.gen_id}),
            ("incus", "default", "web-ct", "incus-id-1", {}),
        ):
            payload = {"id": cid, "name": cname, "runtime": runtime, **extra}
            conn.execute(
                """
                INSERT INTO reports(
                    host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent,
                    net_rx_bps, net_tx_bps, conn_count, disk_file, disk_size_bytes,
                    disk_used_percent, podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                ("host-1", cname, runtime, project, 10, 1024, 5, 0, 0, 1, "", 0, 0, 1, 1, self.now, json.dumps(payload)),
            )
        conn.commit()
        conn.close()
        self.client = TestClient(server.app, base_url="https://testserver")
        self.auth = ("test-admin", "test-password-only")

    def tearDown(self):
        self.client.close()
        self.patch.stop()
        self.tmp.cleanup()

    def _signed_headers(self, body_bytes: bytes) -> dict[str, str]:
        ts = str(int(time.time()))
        sig = hmac.new(
            b"test-shared-secret",
            body_bytes + ts.encode(),
            hashlib.sha256,
        ).hexdigest()
        return {"X-Timestamp": ts, "X-Signature": sig}

    def test_container_resource_limit_upsert_clear_and_poll_delivery(self):
        # 1. GET initial context returns both containers and empty policy.
        res = self.client.get("/api/v1/ops/hosts/host-1/resource-limits", auth=self.auth)
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["policy"]["revision"], 0)
        self.assertEqual(len(body["containers"]), 2)

        # 2. Invalid generation for runman must be rejected (409).
        bad = self.client.put(
            "/api/v1/ops/hosts/host-1/resource-limits/container",
            auth=self.auth,
            json={
                "runtime": "runman",
                "project": "default",
                "container_name": self.vm_id,
                "container_id": "99999999-9999-4999-8999-999999999999",
                "mode": "cooperate",
                "cpu_cpus": 0.5,
            },
        )
        self.assertEqual(bad.status_code, 409)

        # 3. Upsert runman + incus rules atomically without clobbering each other.
        r1 = self.client.put(
            "/api/v1/ops/hosts/host-1/resource-limits/container",
            auth=self.auth,
            json={
                "runtime": "runman",
                "project": "default",
                "container_name": self.vm_id,
                "container_id": self.gen_id,
                "mode": "cooperate",
                "cpu_cpus": 0.5,
                "memory_high_mb": 256,
                "io_read_mbps": 20,
                "note": "cap runman",
            },
        )
        self.assertEqual(r1.status_code, 200, r1.text)
        self.assertEqual(r1.json()["revision"], 1)

        r2 = self.client.put(
            "/api/v1/ops/hosts/host-1/resource-limits/container",
            auth=self.auth,
            json={
                "runtime": "incus",
                "project": "default",
                "container_name": "web-ct",
                "container_id": "incus-id-1",
                "mode": "lock",
                "cpu_cpus": 1.0,
            },
        )
        self.assertEqual(r2.status_code, 200, r2.text)
        self.assertEqual(r2.json()["revision"], 2)
        self.assertEqual(len(r2.json()["limits"]), 2)

        # 4. /api/v1/actions/poll delivers resource_limits for matching node_id, and hides for mismatched node_id.
        poll_ok = json.dumps({"host_id": "host-1", "node_id": "node-1"}).encode()
        poll_resp = self.client.post("/api/v1/actions/poll", content=poll_ok, headers=self._signed_headers(poll_ok))
        self.assertEqual(poll_resp.status_code, 200, poll_resp.text)
        delivered = poll_resp.json()["operations"]["resource_limits"]
        self.assertEqual(delivered["revision"], 2)
        self.assertEqual(len(delivered["limits"]), 2)

        poll_wrong = json.dumps({"host_id": "host-1", "node_id": "other-node"}).encode()
        poll_wrong_resp = self.client.post(
            "/api/v1/actions/poll", content=poll_wrong, headers=self._signed_headers(poll_wrong)
        )
        self.assertEqual(poll_wrong_resp.status_code, 200)
        self.assertEqual(poll_wrong_resp.json()["operations"]["resource_limits"]["limits"], [])

        # 5. Clear incus rule keeps runman rule intact.
        clr = self.client.put(
            "/api/v1/ops/hosts/host-1/resource-limits/container",
            auth=self.auth,
            json={
                "runtime": "incus",
                "project": "default",
                "container_name": "web-ct",
                "container_id": "incus-id-1",
                "clear": True,
            },
        )
        self.assertEqual(clr.status_code, 200, clr.text)
        self.assertTrue(clr.json()["cleared"])
        self.assertEqual(len(clr.json()["limits"]), 1)
        self.assertEqual(clr.json()["limits"][0]["container_name"], self.vm_id)

    def test_container_bandwidth_limit_preserves_host_and_auto_throttle(self):
        # Set host bandwidth limit + auto_throttle first.
        host_save = self.client.put(
            "/api/v1/ops/hosts/host-1/bandwidth-limits",
            auth=self.auth,
            json={
                "limits": [{"scope": "host", "interface": "eth0", "upload_mbps": 100, "download_mbps": 100}],
                "auto_throttle": {"enabled": True},
            },
        )
        self.assertEqual(host_save.status_code, 200, host_save.text)

        # Upsert single container bandwidth limit.
        ct_save = self.client.put(
            "/api/v1/ops/hosts/host-1/bandwidth-limits/container",
            auth=self.auth,
            json={
                "runtime": "runman",
                "project": "default",
                "container_name": self.vm_id,
                "container_id": self.gen_id,
                "upload_mbps": 30,
                "download_mbps": 40,
            },
        )
        self.assertEqual(ct_save.status_code, 200, ct_save.text)
        data = ct_save.json()
        self.assertTrue(data["auto_throttle"]["enabled"])
        self.assertEqual(len(data["limits"]), 2)
        self.assertEqual(data["limits"][0]["scope"], "host")
        self.assertEqual(data["limits"][1]["upload_mbps"], 30)

        # Clear single container bandwidth limit keeps host limit & auto_throttle.
        ct_clear = self.client.put(
            "/api/v1/ops/hosts/host-1/bandwidth-limits/container",
            auth=self.auth,
            json={
                "runtime": "runman",
                "project": "default",
                "container_name": self.vm_id,
                "container_id": self.gen_id,
                "clear": True,
            },
        )
        self.assertEqual(ct_clear.status_code, 200, ct_clear.text)
        self.assertTrue(ct_clear.json()["cleared"])
        self.assertTrue(ct_clear.json()["auto_throttle"]["enabled"])
        self.assertEqual(len(ct_clear.json()["limits"]), 1)
        self.assertEqual(ct_clear.json()["limits"][0]["scope"], "host")


if __name__ == "__main__":
    unittest.main()
