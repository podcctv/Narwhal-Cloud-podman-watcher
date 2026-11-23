import asyncio
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from server import app as server
from server import live_events, operations as ops, server_metrics

ROOT = Path(__file__).resolve().parents[1]


class ServerPerfAndModularizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "monitor.db")
        self.ca_path = str(Path(self.tmp.name) / "root.crt")
        self.patch = mock.patch.multiple(
            server,
            DB_PATH=self.db_path,
            SHARED_SECRET="perf-test-secret",
            DASHBOARD_USERNAME="test-admin",
            DASHBOARD_PASSWORD="test-admin-password",
            APP_VERSION="2.0.5",
            TLS_CA_CERT_PATH=self.ca_path,
            PUBLIC_BASE_URL="",
        )
        self.patch.start()
        server._next_cleanup_monotonic = 0.0
        server.init_db()
        server_metrics.metrics.reset()
        live_events.bus.reset()
        self.client = TestClient(server.app)
        self.admin_auth = ("test-admin", "test-admin-password")

    def tearDown(self):
        live_events.bus.reset()
        server_metrics.metrics.reset()
        self.patch.stop()
        self.tmp.cleanup()

    @staticmethod
    def _signed_headers(body: bytes, secret: str = "perf-test-secret", ts: int | None = None) -> dict[str, str]:
        stamp = str(int(time.time()) if ts is None else ts)
        sig = hmac.new(secret.encode("utf-8"), body + stamp.encode("utf-8"), hashlib.sha256).hexdigest()
        return {"X-Timestamp": stamp, "X-Signature": sig, "Content-Type": "application/json"}

    def _post_signed(self, path: str, payload: dict, extra_headers: dict[str, str] | None = None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = self._signed_headers(body)
        if extra_headers:
            headers.update(extra_headers)
        return self.client.post(path, content=body, headers=headers)

    def _seed_host_and_report(self, host_id: str = "host-1", node_id: str = "node-1", ts: int | None = None, cpu: float = 12.5, rx_bps: float = 1000.0):
        now = int(time.time()) if ts is None else ts
        payload = {
            "host_id": host_id,
            "node_id": node_id,
            "agent_version": "2.0.5",
            "timestamp": now,
            "container_network": {"ipv4_ok": True, "ipv6_ok": True},
            "containers": [
                {
                    "id": f"cid-{host_id}",
                    "stable_id": f"cid-{host_id}",
                    "name": f"ctr-{host_id}",
                    "runtime": "podman",
                    "project": "",
                    "cpu_percent": cpu,
                    "mem_bytes": 1024 * 1024,
                    "mem_percent": 10.0,
                    "net_rx_bps": rx_bps,
                    "net_tx_bps": 500.0,
                    "conn_count": 5,
                    "security": {"inbound_unique_ips": 1, "outbound_unique_ips": 1},
                }
            ],
            "security": {
                "enabled": True,
                "total_rx_bps": rx_bps,
                "total_tx_bps": 500.0,
                "alerts": [],
            },
        }
        with mock.patch.object(server, "send_alert_webhook"), mock.patch.object(
            server, "sync_configured_bot_alert_messages"
        ), mock.patch.object(server, "dispatch_buyer_notifications_for_alerts"):
            res = self._post_signed("/api/v1/report", payload)
        self.assertEqual(res.status_code, 200)
        return res.json()

    def test_gfw_history_retention_default_is_7_days(self):
        env = {k: v for k, v in os.environ.items() if k != "GFW_HISTORY_RETENTION_DAYS"}
        spec = importlib.util.spec_from_file_location("gfw_monitor_default_test", ROOT / "server" / "gfw_monitor.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, env, clear=True):
            spec.loader.exec_module(mod)
        self.assertEqual(mod.GFW_HISTORY_RETENTION_SECONDS, 7 * 86400)

    def test_db_maintenance_compacts_aged_oversized_payloads_preserving_newest_and_recent(self):
        now = int(time.time())
        aged_ts = now - 50 * 3600
        recent_ts = now - 10 * 3600
        big_report_payload = json.dumps(
            {
                "_agent_version": "2.0.5",
                "id": "c1-id",
                "name": "c1",
                "runtime": "podman",
                "project": "",
                "disk": {"root_total_bytes": 100000},
                "security": {
                    "inbound_unique_ips": 7,
                    "outbound_unique_ips": 3,
                    "communication_sockets": [{"ip": "1.2.3.4", "port": i} for i in range(120)],
                },
            }
        )
        self.assertGreater(len(big_report_payload), 2048)

        big_hs_payload = json.dumps(
            {
                "enabled": True,
                "interval_seconds": 30,
                "total_rx_bps": 42000.0,
                "total_tx_bps": 12000.0,
                "access_log": {"requests": 500, "qps": 1.2, "nested": [{"p": "/x"} for _ in range(300)]},
                "extra_blob": "z" * 4500,
            }
        )
        self.assertGreater(len(big_hs_payload), 4096)

        conn = server.db()
        try:
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES('h1',?,'n1')", (now,))
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES('h2',?,'n2')", (now,))
            # c1: aged oversized (should be compacted) + recent oversized (untouched)
            conn.execute(
                "INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json) "
                "VALUES('h1','c1','podman','',1,1,1,1,1,1,1,1,?,?)",
                (aged_ts, big_report_payload),
            )
            c1_aged_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute(
                "INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json) "
                "VALUES('h1','c1','podman','',1,1,1,1,1,1,1,1,?,?)",
                (recent_ts, big_report_payload),
            )
            c1_recent_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            # c2: aged oversized AND newest for c2 (must be preserved untouched)
            conn.execute(
                "INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json) "
                "VALUES('h1','c2','podman','',1,1,1,1,1,1,1,1,?,?)",
                (aged_ts, big_report_payload),
            )
            c2_only_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # host_security h1: aged + recent; h2: aged only (newest for h2)
            conn.execute("INSERT INTO host_security(host_id,ts,payload_json) VALUES('h1',?,?)", (aged_ts, big_hs_payload))
            hs1_aged_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute("INSERT INTO host_security(host_id,ts,payload_json) VALUES('h1',?,?)", (recent_ts, big_hs_payload))
            hs1_recent_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.execute("INSERT INTO host_security(host_id,ts,payload_json) VALUES('h2',?,?)", (aged_ts, big_hs_payload))
            hs2_only_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
        finally:
            conn.close()

        server.cleanup_old_reports(now_ts=now, force=True)
        self.assertGreaterEqual(server._cleanup_status.get("compacted_rows", 0), 2)

        conn = server.db()
        try:
            r_aged = json.loads(conn.execute("SELECT payload_json FROM reports WHERE id=?", (c1_aged_id,)).fetchone()[0])
            r_recent = json.loads(conn.execute("SELECT payload_json FROM reports WHERE id=?", (c1_recent_id,)).fetchone()[0])
            r_c2 = json.loads(conn.execute("SELECT payload_json FROM reports WHERE id=?", (c2_only_id,)).fetchone()[0])
            self.assertTrue(r_aged.get("_compacted"))
            self.assertEqual(r_aged["security"]["inbound_unique_ips"], 7)
            self.assertNotIn("communication_sockets", r_aged["security"])
            self.assertNotIn("_compacted", r_recent)
            self.assertIn("communication_sockets", r_recent["security"])
            self.assertNotIn("_compacted", r_c2)
            self.assertIn("communication_sockets", r_c2["security"])

            h_aged = json.loads(conn.execute("SELECT payload_json FROM host_security WHERE id=?", (hs1_aged_id,)).fetchone()[0])
            h_recent = json.loads(conn.execute("SELECT payload_json FROM host_security WHERE id=?", (hs1_recent_id,)).fetchone()[0])
            h_h2 = json.loads(conn.execute("SELECT payload_json FROM host_security WHERE id=?", (hs2_only_id,)).fetchone()[0])
            self.assertTrue(h_aged.get("_compacted"))
            self.assertEqual(h_aged["total_rx_bps"], 42000.0)
            self.assertEqual(h_aged["access_log"]["requests"], 500)
            self.assertNotIn("nested", h_aged["access_log"])
            self.assertNotIn("extra_blob", h_aged)
            self.assertNotIn("_compacted", h_recent)
            self.assertIn("extra_blob", h_recent)
            self.assertNotIn("_compacted", h_h2)
            self.assertIn("extra_blob", h_h2)
        finally:
            conn.close()

    def test_idle_actions_poll_hits_readonly_fast_path_and_wakes_on_queued_action(self):
        now = int(time.time())
        self._seed_host_and_report("host-idle", "node-idle", ts=now)
        server_metrics.metrics.reset()

        # First poll initializes _poll_heartbeat_by_db and GFW schedule throttle via write path
        res1 = self._post_signed("/api/v1/actions/poll", {"host_id": "host-idle", "node_id": "node-idle"})
        self.assertEqual(res1.status_code, 200)
        snap1 = server_metrics.metrics.snapshot()["counters"]
        self.assertEqual(snap1["idle_poll_write_hits"], 1)
        self.assertEqual(snap1["idle_poll_readonly_hits"], 0)

        # Second poll within 25s (and <15s GFW schedule window) must execute zero DB write statements
        executed_sql: list[str] = []
        orig_db = server.db

        class TrackingConn:
            def __init__(self, inner):
                self._inner = inner

            def execute(self, sql, *args, **kwargs):
                executed_sql.append(str(sql).strip().upper())
                return self._inner.execute(sql, *args, **kwargs)

            def __getattr__(self, item):
                return getattr(self._inner, item)

        with mock.patch.object(server, "db", side_effect=lambda: TrackingConn(orig_db())):
            res2 = self._post_signed("/api/v1/actions/poll", {"host_id": "host-idle", "node_id": "node-idle"})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["actions"], [])
        for stmt in executed_sql:
            self.assertFalse(stmt.startswith(("BEGIN", "UPDATE", "INSERT", "DELETE")), f"Unexpected write SQL: {stmt}")
        snap2 = server_metrics.metrics.snapshot()["counters"]
        self.assertEqual(snap2["idle_poll_readonly_hits"], 1)
        self.assertEqual(snap2["idle_poll_write_hits"], 1)

        # Queue a security action -> next poll immediately enters write path and delivers it
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
                "VALUES(0,'host-idle','host','','__host__','host_security_rescan',?,'queued','tester',?,?)",
                (json.dumps({"expected_node_id": "node-idle"}), now, now),
            )
            conn.commit()
        finally:
            conn.close()

        res3 = self._post_signed("/api/v1/actions/poll", {"host_id": "host-idle", "node_id": "node-idle"})
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(len(res3.json()["actions"]), 1)
        self.assertEqual(res3.json()["actions"][0]["action_type"], "host_security_rescan")
        snap3 = server_metrics.metrics.snapshot()["counters"]
        self.assertEqual(snap3["idle_poll_write_hits"], 2)
        self.assertEqual(snap3["idle_poll_readonly_hits"], 1)

    def test_idle_admission_status_hits_readonly_fast_path_on_unchanged_repeat(self):
        now = int(time.time())
        conn = server.db()
        try:
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES('adm-host',?,'adm-node')", (now,))
            conn.commit()
        finally:
            conn.close()
        server_metrics.metrics.reset()

        payload = {
            "host_id": "adm-host",
            "node_id": "adm-node",
            "items": [
                {
                    "runtime": "incus",
                    "project": "default",
                    "container_name": "c1",
                    "instance_id": "a" * 36,
                    "admission": {
                        "state": "enforced",
                        "observed_at": now,
                        "sources": [],
                        "blocked": {},
                    },
                }
            ],
        }
        res1 = self._post_signed("/api/v1/admission/status", payload)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_write_hits"], 1)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_readonly_hits"], 0)

        res2 = self._post_signed("/api/v1/admission/status", payload)
        self.assertEqual(res2.status_code, 200)
        snap = server_metrics.metrics.snapshot()["counters"]
        self.assertEqual(snap["admission_readonly_hits"], 1)
        self.assertEqual(snap["admission_write_hits"], 1)

    def test_selective_gzip_middleware_compresses_latest_and_skips_sse_and_agent_paths(self):
        now = int(time.time())
        for idx in range(4):
            self._seed_host_and_report(f"gzip-host-{idx}", f"gzip-node-{idx}", ts=now)

        # /api/v1/latest > 1KB should be gzipped when Accept-Encoding: gzip
        latest_res = self.client.get(
            "/api/v1/latest",
            auth=self.admin_auth,
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(latest_res.status_code, 200)
        self.assertGreater(len(latest_res.content), 1024)
        self.assertEqual(latest_res.headers.get("content-encoding"), "gzip")
        self.assertEqual(len(latest_res.json()["items"]), 4)

        # /api/v1/events/stream?once=1 must NOT be gzipped
        sse_res = self.client.get(
            "/api/v1/events/stream?once=1",
            auth=self.admin_auth,
            headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(sse_res.status_code, 200)
        self.assertNotEqual(sse_res.headers.get("content-encoding"), "gzip")
        self.assertIn("event: ready", sse_res.text)

        # Signed agent path > 1KB (/api/v1/tls/ca and /api/v1/actions/poll) must NOT be gzipped
        cert_body = "-----BEGIN CERTIFICATE-----\n" + ("A" * 64 + "\n") * 30 + "-----END CERTIFICATE-----\n"
        Path(self.ca_path).write_bytes(cert_body.encode("utf-8"))
        ca_headers = self._signed_headers(b"")
        ca_headers["Accept-Encoding"] = "gzip"
        ca_res = self.client.get("/api/v1/tls/ca", headers=ca_headers)
        self.assertEqual(ca_res.status_code, 200)
        self.assertGreater(len(ca_res.content), 1024)
        self.assertNotIn("content-encoding", ca_res.headers)
        self.assertEqual(ca_res.text, cert_body)

        conn = server.db()
        try:
            for idx in range(12):
                conn.execute(
                    "INSERT INTO ops_services(host_id,name,payload,enabled) VALUES('gzip-host-0',?,?,1)",
                    (f"svc-{idx}", json.dumps({"name": f"svc-{idx}", "target": f"https://example-{idx}.com/" + "x" * 90})),
                )
            conn.commit()
        finally:
            conn.close()
        poll_res = self._post_signed(
            "/api/v1/actions/poll",
            {"host_id": "gzip-host-0", "node_id": "gzip-node-0"},
            extra_headers={"Accept-Encoding": "gzip"},
        )
        self.assertEqual(poll_res.status_code, 200)
        self.assertGreater(len(poll_res.content), 1024)
        self.assertNotIn("content-encoding", poll_res.headers)

    def test_etag_and_if_none_match_on_latest_and_security_status(self):
        t0 = int(time.time()) - 5
        self._seed_host_and_report("etag-host", "etag-node", ts=t0, cpu=10.0, rx_bps=1000.0)
        server_metrics.metrics.reset()

        # /api/v1/latest 200 -> 304 -> new report -> 200 new ETag
        res_latest_1 = self.client.get("/api/v1/latest", auth=self.admin_auth)
        self.assertEqual(res_latest_1.status_code, 200)
        etag_latest_1 = res_latest_1.headers.get("etag")
        self.assertTrue(etag_latest_1 and etag_latest_1.startswith('W/"'))
        self.assertIn("Accept-Encoding", res_latest_1.headers.get("vary", ""))

        res_latest_304 = self.client.get(
            "/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": etag_latest_1}
        )
        self.assertEqual(res_latest_304.status_code, 304)
        self.assertEqual(res_latest_304.headers.get("etag"), etag_latest_1)

        # /api/v1/security/status 200 -> 304 (even across cache invalidation) -> new report -> 200 new ETag
        res_sec_1 = self.client.get("/api/v1/security/status", auth=self.admin_auth)
        self.assertEqual(res_sec_1.status_code, 200)
        etag_sec_1 = res_sec_1.headers.get("etag")
        self.assertTrue(etag_sec_1 and etag_sec_1.startswith('W/"'))

        res_sec_304 = self.client.get(
            "/api/v1/security/status", auth=self.admin_auth, headers={"If-None-Match": etag_sec_1}
        )
        self.assertEqual(res_sec_304.status_code, 304)

        # Even if the 10s cache expires without a new report, volatile age fields don't bust ETag
        server.invalidate_security_status_cache()
        res_sec_304_refresh = self.client.get(
            "/api/v1/security/status", auth=self.admin_auth, headers={"If-None-Match": etag_sec_1}
        )
        self.assertEqual(res_sec_304_refresh.status_code, 304)
        self.assertGreaterEqual(server_metrics.metrics.snapshot()["counters"]["etag_304_hits"], 3)

        # New report with changed metrics updates both ETags
        self._seed_host_and_report("etag-host", "etag-node", ts=t0 + 3, cpu=77.5, rx_bps=98765.0)
        res_latest_2 = self.client.get(
            "/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": etag_latest_1}
        )
        self.assertEqual(res_latest_2.status_code, 200)
        self.assertNotEqual(res_latest_2.headers.get("etag"), etag_latest_1)

        res_sec_2 = self.client.get(
            "/api/v1/security/status", auth=self.admin_auth, headers={"If-None-Match": etag_sec_1}
        )
        self.assertEqual(res_sec_2.status_code, 200)
        self.assertNotEqual(res_sec_2.headers.get("etag"), etag_sec_1)

    def test_modularization_line_count_dual_imports_and_dockerfile_audit(self):
        app_lines = (ROOT / "server" / "app.py").read_text(encoding="utf-8").splitlines()
        self.assertLess(len(app_lines), 4600, f"server/app.py has {len(app_lines)} lines")

        modules = ("telegram_service", "firewall_service", "alert_service", "live_events", "server_metrics")
        for mod_name in modules:
            mod = __import__(f"server.{mod_name}", fromlist=[mod_name])
            self.assertIsNotNone(mod)

        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "server")
        check_code = "import " + ", ".join(modules) + ", app; assert hasattr(app, 'app')"
        proc = subprocess.run(
            [sys.executable, "-c", check_code],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

        dockerfile_text = (ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")
        for py_file in sorted((ROOT / "server").glob("*.py")):
            self.assertIn(py_file.name, dockerfile_text, f"{py_file.name} missing from server/Dockerfile")

    def test_sse_stream_auth_ready_and_live_update_delivery(self):
        unauth = self.client.get("/api/v1/events/stream?once=1")
        self.assertEqual(unauth.status_code, 401)

        ready_res = self.client.get("/api/v1/events/stream?once=1", auth=self.admin_auth)
        self.assertEqual(ready_res.status_code, 200)
        self.assertEqual(ready_res.headers.get("x-accel-buffering"), "no")
        self.assertIn("text/event-stream", ready_res.headers.get("content-type", ""))
        self.assertIn("event: ready", ready_res.text)

        async def run_live_stream():
            import base64

            auth_token = base64.b64encode(b"test-admin:test-admin-password").decode("ascii")
            send_q: asyncio.Queue = asyncio.Queue()
            recv_q: asyncio.Queue = asyncio.Queue()
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/api/v1/events/stream",
                "raw_path": b"/api/v1/events/stream",
                "query_string": b"",
                "headers": [(b"authorization", f"Basic {auth_token}".encode("ascii"))],
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
            }

            async def receive():
                return await recv_q.get()

            async def send(message):
                await send_q.put(message)

            app_task = asyncio.create_task(server.app(scope, receive, send))
            try:
                start_msg = await asyncio.wait_for(send_q.get(), timeout=3.0)
                self.assertEqual(start_msg["type"], "http.response.start")
                self.assertEqual(start_msg["status"], 200)
                resp_headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in start_msg["headers"]}
                self.assertEqual(resp_headers.get("x-accel-buffering"), "no")

                ready_msg = await asyncio.wait_for(send_q.get(), timeout=3.0)
                ready_text = ready_msg.get("body", b"").decode("utf-8")
                self.assertIn("event: ready", ready_text)

                seq = server.publish_live_event("report", "sse-host-1")
                self.assertGreater(seq, 0)

                update_msg = await asyncio.wait_for(send_q.get(), timeout=3.0)
                update_text = update_msg.get("body", b"").decode("utf-8")
                self.assertIn("event: update", update_text)
                self.assertIn('"topic":"report"', update_text)
                self.assertIn('"host_id":"sse-host-1"', update_text)
            finally:
                await recv_q.put({"type": "http.disconnect"})
                app_task.cancel()
                try:
                    await app_task
                except (asyncio.CancelledError, Exception):
                    pass

        asyncio.run(run_live_stream())
        self.assertEqual(live_events.bus.active_count(), 0)
        self.assertGreaterEqual(server_metrics.metrics.snapshot()["counters"]["sse_events_published"], 1)

    def test_server_metrics_endpoint_rbac_redaction_and_shape(self):
        now = int(time.time())
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO ops_users(username,password_hash,role,enabled,updated_at) VALUES('viewer',?,'viewer',1,?)",
                (ops.password_hash("viewer-pass"), now),
            )
            conn.execute(
                "INSERT INTO ops_users(username,password_hash,role,enabled,updated_at) VALUES('operator',?,'operator',1,?)",
                (ops.password_hash("operator-pass"), now),
            )
            conn.commit()
        finally:
            conn.close()

        # Trigger a telegram callback route so MetricsMiddleware records & redacts the secret
        secret_token = "super-secret-callback-token-xyz"
        self.client.post(f"/api/v1/notifications/telegram/42/{secret_token}", json={"update_id": 1})

        self.assertEqual(self.client.get("/api/v1/ops/server-metrics").status_code, 401)
        self.assertEqual(
            self.client.get("/api/v1/ops/server-metrics", auth=("viewer", "viewer-pass")).status_code,
            403,
        )

        op_res = self.client.get("/api/v1/ops/server-metrics", auth=("operator", "operator-pass"))
        self.assertEqual(op_res.status_code, 200)
        admin_res = self.client.get("/api/v1/ops/server-metrics", auth=self.admin_auth)
        self.assertEqual(admin_res.status_code, 200)

        body = admin_res.json()
        self.assertIn("routes", body)
        self.assertIn("counters", body)
        self.assertIn("slow_threshold_ms", body)
        self.assertIn("gauges", body)
        self.assertIn("recent_slow_requests", body)
        serialized = json.dumps(body)
        self.assertNotIn(secret_token, serialized)
        self.assertIn("/api/v1/notifications/telegram/{bot_id}/{secret}", [r["path"] for r in body["routes"]])


if __name__ == "__main__":
    unittest.main()
