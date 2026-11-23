import gzip
import hashlib
import hmac
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from server import (
    admission_api,
    app as server,
    buyer_notifications,
    db_maintenance,
    investigation,
    live_events,
    operations as ops,
    server_metrics,
    tcping,
)


class _TrackingConn:
    """Proxy sqlite3.Connection that records executed SQL and open/close lifecycle."""

    def __init__(self, inner: sqlite3.Connection, sql_log: list[str], open_set: set[int] | None = None) -> None:
        self._inner = inner
        self._sql_log = sql_log
        self._open_set = open_set
        if open_set is not None:
            open_set.add(id(self))

    def execute(self, sql, *args, **kwargs):
        self._sql_log.append(" ".join(str(sql).strip().split()).upper())
        return self._inner.execute(sql, *args, **kwargs)

    def executemany(self, sql, *args, **kwargs):
        self._sql_log.append(" ".join(str(sql).strip().split()).upper())
        return self._inner.executemany(sql, *args, **kwargs)

    def commit(self):
        self._sql_log.append("COMMIT")
        return self._inner.commit()

    def close(self):
        if self._open_set is not None:
            self._open_set.discard(id(self))
        return self._inner.close()

    def __getattr__(self, item):
        return getattr(self._inner, item)


class ServerPerfV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "monitor.db")
        self.ca_path = str(Path(self.tmp.name) / "root.crt")
        self.patch = mock.patch.multiple(
            server,
            DB_PATH=self.db_path,
            SHARED_SECRET="perf-v2-secret",
            DASHBOARD_USERNAME="test-admin",
            DASHBOARD_PASSWORD="test-admin-password",
            APP_VERSION="2.2.0",
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
    def _signed_headers(body: bytes, secret: str = "perf-v2-secret", ts: int | None = None) -> dict[str, str]:
        stamp = str(int(time.time()) if ts is None else ts)
        sig = hmac.new(secret.encode("utf-8"), body + stamp.encode("utf-8"), hashlib.sha256).hexdigest()
        return {"X-Timestamp": stamp, "X-Signature": sig, "Content-Type": "application/json"}

    def _post_signed(self, path: str, payload: dict):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return self.client.post(path, content=body, headers=self._signed_headers(body))

    def _seed_host(self, host_id: str = "h1", node_id: str = "n1", ts: int | None = None) -> int:
        now = int(time.time()) if ts is None else ts
        conn = server.db()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO hosts(host_id,last_seen,agent_version,node_id,config_json) VALUES(?,?,?,?,?)",
                (host_id, now, "2.2.0", node_id, "{}"),
            )
            conn.commit()
        finally:
            conn.close()
        return now

    def _insert_report(
        self,
        *,
        host_id: str = "h1",
        container_name: str = "c1",
        runtime: str = "podman",
        project: str = "",
        ts: int | None = None,
        conn_count: int = 10,
        rx_bps: float = 100.0,
        tx_bps: float = 200.0,
        inbound_ips: int | None = 2,
        outbound_ips: int | None = 3,
        payload: dict | None = None,
    ) -> int:
        stamp = int(time.time()) if ts is None else ts
        body = payload if payload is not None else {
            "_agent_version": "2.2.0",
            "id": f"cid-{host_id}-{container_name}",
            "stable_id": f"cid-{host_id}-{container_name}",
            "name": container_name,
            "runtime": runtime,
            "project": project,
            "security": {
                "inbound_unique_ips": 7 if inbound_ips is None else inbound_ips,
                "outbound_unique_ips": 5 if outbound_ips is None else outbound_ips,
            },
        }
        conn = server.db()
        try:
            cur = conn.execute(
                """
                INSERT INTO reports(
                    host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,
                    net_rx_bps,net_tx_bps,conn_count,disk_file,disk_size_bytes,disk_used_percent,
                    podman_network_ok_v4,podman_network_ok_v6,ts,payload_json,
                    inbound_unique_ips,outbound_unique_ips
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    host_id,
                    container_name,
                    runtime,
                    project,
                    12.5,
                    1024,
                    5.0,
                    rx_bps,
                    tx_bps,
                    conn_count,
                    "",
                    0,
                    10.0,
                    1,
                    1,
                    stamp,
                    json.dumps(body, separators=(",", ":")),
                    inbound_ips,
                    outbound_ips,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Slice 1 tests
    # ------------------------------------------------------------------

    def test_admission_unchanged_write_throttling_and_bypasses(self):
        base = int(time.time()) - 30
        self._seed_host("adm-h", "adm-n", ts=base)
        server_metrics.metrics.reset()

        def make_payload(observed_at: int, *, limited: bool = False):
            return {
                "host_id": "adm-h",
                "node_id": "adm-n",
                "items": [
                    {
                        "runtime": "incus",
                        "project": "default",
                        "container_name": "c1",
                        "instance_id": "a" * 36,
                        "admission": {
                            "state": "enforced",
                            "observed_at": observed_at,
                            "sampled_at": observed_at,
                            "limited": limited,
                            "sources": [],
                            "blocked": {},
                        },
                    }
                ],
            }

        with mock.patch.object(admission_api.time, "time", return_value=base):
            r1 = self._post_signed("/api/v1/admission/status", make_payload(base))
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_write_hits"], 1)

        # +5s later with only observed_at/sampled_at bumped -> readonly fast path, zero DB writes
        t2 = base + 5
        sql_log: list[str] = []
        orig_db = server.db
        with mock.patch.object(server, "db", side_effect=lambda: _TrackingConn(orig_db(), sql_log)), mock.patch.object(
            admission_api.time, "time", return_value=t2
        ):
            r2 = self._post_signed("/api/v1/admission/status", make_payload(t2))
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(any(s.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE")) or s == "COMMIT" for s in sql_log))
        counters = server_metrics.metrics.snapshot()["counters"]
        self.assertEqual(counters["admission_readonly_hits"], 1)
        self.assertEqual(counters["admission_write_hits"], 1)
        conn = server.db()
        try:
            obs = conn.execute("SELECT observed_at FROM admission_states WHERE host_id='adm-h'").fetchone()[0]
            self.assertEqual(obs, base)
        finally:
            conn.close()

        # Semantic change within <25s triggers immediate write
        t3 = base + 10
        with mock.patch.object(admission_api.time, "time", return_value=t3):
            r3 = self._post_signed("/api/v1/admission/status", make_payload(t3, limited=True))
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_write_hits"], 2)

        # >= 25s interval with unchanged semantic payload triggers heartbeat/observed_at write
        t4 = t3 + admission_api.ADMISSION_UNCHANGED_WRITE_INTERVAL_SECONDS
        with mock.patch.object(admission_api.time, "time", return_value=t4):
            r4 = self._post_signed("/api/v1/admission/status", make_payload(t4, limited=True))
        self.assertEqual(r4.status_code, 200)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_write_hits"], 3)
        conn = server.db()
        try:
            obs = conn.execute("SELECT observed_at FROM admission_states WHERE host_id='adm-h'").fetchone()[0]
            self.assertEqual(obs, t4)
        finally:
            conn.close()

        # Interval=0 bypasses unchanged throttling
        t5 = t4 + 2
        with mock.patch.object(admission_api, "ADMISSION_UNCHANGED_WRITE_INTERVAL_SECONDS", 0), mock.patch.object(
            admission_api.time, "time", return_value=t5
        ):
            r5 = self._post_signed("/api/v1/admission/status", make_payload(t5, limited=True))
        self.assertEqual(r5.status_code, 200)
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["admission_write_hits"], 4)

        # :memory: DB bypasses throttling (db_file == "")
        mem_conn = sqlite3.connect(":memory:")
        mem_conn.row_factory = sqlite3.Row
        mem_conn.executescript(
            """
            CREATE TABLE hosts(host_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL, node_id TEXT NOT NULL DEFAULT '');
            CREATE TABLE security_alerts(id INTEGER PRIMARY KEY, host_id TEXT, alert_type TEXT, status TEXT, last_seen INTEGER);
            """
        )
        admission_api.initialize(mem_conn)
        mem_conn.execute("INSERT INTO hosts VALUES('mh', ?, 'mn')", (base,))
        mem_conn.commit()
        mem_metrics: list[str] = []

        class _NoCloseMemConn:
            def __init__(self, inner):
                self._inner = inner

            def close(self):
                return None

            def __getattr__(self, item):
                return getattr(self._inner, item)

        item = admission_api.normalized_alert(
            {
                "runtime": "incus",
                "project": "default",
                "container_name": "c1",
                "instance_id": "b" * 36,
                "type": "admission_unverified",
                "admission": {"state": "unverified", "observed_at": base, "sources": [], "blocked": {}},
            }
        )
        admission_api._write_admission_status(lambda: _NoCloseMemConn(mem_conn), "mh", "mn", "", [item], base, mem_metrics.append)
        item["admission"]["observed_at"] = base + 3
        admission_api._write_admission_status(lambda: _NoCloseMemConn(mem_conn), "mh", "mn", "", [item], base + 3, mem_metrics.append)
        self.assertEqual(mem_metrics, ["admission_write_hits", "admission_write_hits"])
        mem_conn.close()

    def test_tcping_public_job_get_is_readonly_when_active_and_expires_when_due(self):
        now = int(time.time())
        live_id = "11111111-1111-4111-8111-111111111111"
        due_id = "22222222-2222-4222-8222-222222222222"
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO tcp_sources(id,host_id,node_id,name,region,purchase_url,enabled,revision,sort_order) "
                "VALUES('src1','h1','n1','HK','HK','',1,1,1)"
            )
            conn.execute(
                "INSERT INTO tcp_sources(id,host_id,node_id,name,region,purchase_url,enabled,revision,sort_order) "
                "VALUES('src2','h2','n2','JP','JP','',1,1,2)"
            )
            conn.execute(
                "INSERT INTO tcp_jobs(id,source_id,node_id,host_id,source_revision,generation,scope,targets,samples,status,lease,created_at,deadline_at,started_at,finished_at,message) "
                "VALUES(?,'src1','n1','h1',1,'gen1','province','[]',1,'running','l1',?,?,0,0,'')",
                (live_id, now, now + 60),
            )
            conn.execute(
                "INSERT INTO tcp_jobs(id,source_id,node_id,host_id,source_revision,generation,scope,targets,samples,status,lease,created_at,deadline_at,started_at,finished_at,message) "
                "VALUES(?,'src2','n2','h2',1,'gen1','province','[]',1,'running','l2',?,?,0,0,'')",
                (due_id, now - 120, now - 1),
            )
            conn.commit()
        finally:
            conn.close()

        sql_log: list[str] = []
        orig_db = server.db
        with mock.patch.object(server, "db", side_effect=lambda: _TrackingConn(orig_db(), sql_log)):
            res_live = self.client.get(f"/api/public/tcping/jobs/{live_id}")
        self.assertEqual(res_live.status_code, 200)
        self.assertEqual(res_live.json()["status"], "running")
        self.assertFalse(any(s.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE")) or s == "COMMIT" for s in sql_log))

        res_due = self.client.get(f"/api/public/tcping/jobs/{due_id}")
        self.assertEqual(res_due.status_code, 200)
        self.assertEqual(res_due.json()["status"], "expired")

    def test_operations_partial_open_index_and_dynamic_backup_budget(self):
        conn = server.db()
        try:
            idx = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_ops_incidents_open'"
            ).fetchone()
            self.assertIsNotNone(idx)
            self.assertIn("WHERE status='open'", idx[0])
            plan = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT * FROM ops_incidents WHERE entity='e1' AND kind='k1' AND status='open'"
                ).fetchall()
            ]
            self.assertTrue(any("idx_ops_incidents_open" in str(row) for row in plan), plan)
        finally:
            conn.close()

        # Verify backup() scales deadline and uses pages=1024, sleep=0.01
        recorded: dict = {}

        class _FakeConn:
            def __init__(self, page_count: int):
                self._page_count = page_count

            def execute(self, sql):
                s = sql.upper()
                res = mock.Mock()
                if "PAGE_SIZE" in s:
                    res.fetchone.return_value = (4096,)
                elif "PAGE_COUNT" in s:
                    res.fetchone.return_value = (self._page_count,)
                elif "INTEGRITY_CHECK" in s:
                    res.fetchone.return_value = ("ok",)
                return res

            def backup(self, destination, *, pages=0, progress=None, sleep=0.0):
                recorded["pages"] = pages
                recorded["sleep"] = sleep
                progress(0, 0, 1)

            def close(self):
                return None

        # Simulate ~2 GiB DB -> expected deadline = 120 + 2048/4 = 632s
        fake_src = _FakeConn(page_count=524288)
        fake_dst = _FakeConn(page_count=524288)
        connect_calls = [fake_src, fake_src, fake_dst]
        mono_values = [1000.0, 1600.0]  # 600s elapsed < 632s scaled deadline (would fail old 120s budget!)
        with mock.patch.object(ops.sqlite3, "connect", side_effect=connect_calls), mock.patch.object(
            ops.shutil, "disk_usage", return_value=mock.Mock(free=10 * 1024**3)
        ), mock.patch.object(ops.time, "monotonic", side_effect=mono_values):
            out = ops.backup(self.db_path, retention=7)
        self.assertEqual(recorded["pages"], 1024)
        self.assertEqual(recorded["sleep"], 0.01)
        self.assertIn("sha256", out)

    def test_buyer_notifications_indexes_and_batch_reconcile(self):
        now = int(time.time())
        conn = server.db()
        try:
            indexes = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name IN "
                    "('idx_buyer_outbox_alert_status','idx_buyer_user_notices_alert_status')"
                ).fetchall()
            }
            self.assertEqual(
                indexes, {"idx_buyer_outbox_alert_status", "idx_buyer_user_notices_alert_status"}
            )
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES('bn-h',?,'bn-n')", (now,))
            for idx in range(12):
                conn.execute(
                    "INSERT INTO security_alerts(fingerprint,host_id,runtime,project,container_name,alert_type,severity,title,message,first_seen,last_seen,status) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"fp-{idx}", "bn-h", "incus", "default", f"c-{idx}", "socks_password_review", "warning", "t", "m", now, now, "active"),
                )
            conn.commit()
        finally:
            conn.close()

        sql_log: list[str] = []
        raw_conn = server.db()
        tracked = _TrackingConn(raw_conn, sql_log)
        try:
            buyer_notifications.reconcile(tracked, "bn-h", now)
        finally:
            raw_conn.close()

        # Without pending rows, reconcile must NOT issue N per-alert UPDATE buyer_outbox or SELECT COUNT(*)
        update_outbox_calls = [s for s in sql_log if s.startswith("UPDATE BUYER_OUTBOX")]
        count_outbox_calls = [s for s in sql_log if "COUNT(*)" in s and "BUYER_OUTBOX" in s]
        self.assertEqual(update_outbox_calls, [])
        self.assertEqual(len(count_outbox_calls), 1)

    def test_investigation_approx_below_cap_short_circuits_count_star(self):
        now = int(time.time())
        self._seed_host("inv-h", "inv-n", ts=now)
        sql_log: list[str] = []
        raw_conn = server.db()
        tracked = _TrackingConn(raw_conn, sql_log)
        try:
            self.assertTrue(investigation._approx_below_cap(tracked, "investigation_incidents", investigation.INCIDENT_CAP))
            investigation.observe(
                tracked,
                "inv-h",
                "inv-n",
                now,
                [{"runtime": "podman", "project": "", "name": "c1", "id": "cid1"}],
                set(),
            )
            raw_conn.commit()
            self.assertFalse(any("SELECT COUNT(*)" in s for s in sql_log), f"Unexpected COUNT(*): {sql_log}")

            # When MAX(rowid) >= cap, falls back to exact COUNT(*) so deletions below cap still allow inserts
            raw_conn.execute(
                "INSERT INTO investigation_incidents(id,alert_id,episode,identity_key,host_key,host_id,runtime,project,container_name,"
                "user_id,machine_id,alert_type,severity,title,category,status,state,first_seen,last_anomaly,recorded_from,updated_at,"
                "legacy,value,threshold,initial_value,initial_threshold,evidence_json,action_json) "
                "VALUES(10,1,1,'ik1','inv-n','inv-h','podman','','c1','','','t','warning','title','security','active','active',?,?,?,?,0,1,1,1,1,'{}','{}')",
                (now, now, now, now),
            )
            raw_conn.commit()
            sql_log.clear()
            self.assertTrue(investigation._approx_below_cap(tracked, "investigation_incidents", 5))
            self.assertTrue(any("SELECT COUNT(*) FROM INVESTIGATION_INCIDENTS" in s for s in sql_log))
        finally:
            raw_conn.close()

    def test_db_maintenance_backfill_missing_peak_columns_and_backlog(self):
        now = int(time.time())
        self._seed_host("bf-h", "bf-n", ts=now)
        conn = server.db()
        try:
            for i in range(4):
                self._insert_report(
                    host_id="bf-h",
                    container_name=f"c{i}",
                    ts=now - i,
                    inbound_ips=None,
                    outbound_ips=None,
                    payload={"id": f"cid-{i}", "security": {"inbound_unique_ips": 10 + i, "outbound_unique_ips": 4 + i}},
                )
            for i in range(4):
                conn.execute(
                    "INSERT INTO host_security(host_id,ts,payload_json,total_rx_bps,total_tx_bps) VALUES(?,?,?,NULL,NULL)",
                    ("bf-h", now - i, json.dumps({"total_rx_bps": 1000.0 + i, "total_tx_bps": 500.0 + i})),
                )
            conn.commit()

            # Verify backfill SQL plans use the partial NULL indexes
            rep_plan = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT id, payload_json FROM reports WHERE inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL LIMIT 10"
                ).fetchall()
            ]
            hs_plan = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT id, payload_json FROM host_security WHERE total_rx_bps IS NULL OR total_tx_bps IS NULL LIMIT 10"
                ).fetchall()
            ]
            self.assertTrue(any("idx_reports_null_peaks" in str(r) for r in rep_plan), rep_plan)
            self.assertTrue(any("idx_host_security_null_peaks" in str(r) for r in hs_plan), hs_plan)
        finally:
            conn.close()

        cleanup_status: dict = {}
        _, backlog1 = db_maintenance.run_cleanup(
            db_fn=server.db,
            db_path=self.db_path,
            investigation_maintain_fn=investigation.maintain,
            cleanup_status=cleanup_status,
            purge_seconds=server.PURGE_SECONDS,
            raw_retention_seconds=server.RAW_RETENTION_SECONDS,
            offline_host_purge_seconds=server.OFFLINE_HOST_PURGE_SECONDS,
            report_cleanup_batch_size=3,
            report_max_rows=server.REPORT_MAX_ROWS,
            host_security_max_rows=server.HOST_SECURITY_MAX_ROWS,
            cleanup_time_budget_seconds=5.0,
            now_ts=now,
        )
        self.assertTrue(backlog1)
        self.assertEqual(cleanup_status["backfilled_peak_rows"], 3)

        # Drain remaining 5 rows
        _, backlog2 = db_maintenance.run_cleanup(
            db_fn=server.db,
            db_path=self.db_path,
            investigation_maintain_fn=investigation.maintain,
            cleanup_status=cleanup_status,
            purge_seconds=server.PURGE_SECONDS,
            raw_retention_seconds=server.RAW_RETENTION_SECONDS,
            offline_host_purge_seconds=server.OFFLINE_HOST_PURGE_SECONDS,
            report_cleanup_batch_size=10,
            report_max_rows=server.REPORT_MAX_ROWS,
            host_security_max_rows=server.HOST_SECURITY_MAX_ROWS,
            cleanup_time_budget_seconds=5.0,
            now_ts=now,
        )
        self.assertFalse(backlog2)
        self.assertEqual(cleanup_status["backfilled_peak_rows"], 5)

        conn = server.db()
        try:
            self.assertFalse(db_maintenance._has_missing_peak_columns(conn))
            row = conn.execute("SELECT inbound_unique_ips, outbound_unique_ips FROM reports WHERE container_name='c0'").fetchone()
            self.assertEqual(tuple(row), (10, 4))
            hs_row = conn.execute("SELECT total_rx_bps, total_tx_bps FROM host_security WHERE ts=?", (now,)).fetchone()
            self.assertEqual(tuple(hs_row), (1000.0, 500.0))
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Slice 2 tests
    # ------------------------------------------------------------------

    def test_report_payload_cache_content_verification_lru_and_immutability(self):
        raw1 = json.dumps({"id": "c1", "security": {"inbound_unique_ips": 3}})
        parsed1 = server._parse_report_payload(1, raw1)
        self.assertEqual(parsed1["id"], "c1")
        self.assertIn(1, server._report_payload_cache)
        cached_raw, cached_digest, cached_dict = server._report_payload_cache[1]
        self.assertEqual(cached_raw, raw1)
        self.assertEqual(len(cached_digest), 8)
        self.assertIs(cached_dict, parsed1)

        # Same id + exact same raw hits cache without calling json.loads
        with mock.patch.object(server.json, "loads", side_effect=AssertionError("should hit cache")):
            parsed_hit = server._parse_report_payload(1, raw1)
        self.assertIs(parsed_hit, parsed1)

        # Same id + mutated raw (e.g. SQL UPDATE reports SET payload_json=...) invalidates & reparses
        raw2 = json.dumps({"id": "c1-mutated", "security": {"inbound_unique_ips": 99}})
        parsed2 = server._parse_report_payload(1, raw2)
        self.assertEqual(parsed2["id"], "c1-mutated")
        self.assertIsNot(parsed2, parsed1)

        # LRU eviction at capacity 1024
        server.invalidate_latest_caches()
        for rid in range(1, 1025):
            server._parse_report_payload(rid, json.dumps({"id": f"r-{rid}"}))
        self.assertEqual(len(server._report_payload_cache), 1024)
        # Touch rid=1 so rid=2 becomes oldest
        server._parse_report_payload(1, json.dumps({"id": "r-1"}))
        server._parse_report_payload(1025, json.dumps({"id": "r-1025"}))
        self.assertEqual(len(server._report_payload_cache), 1024)
        self.assertIn(1, server._report_payload_cache)
        self.assertNotIn(2, server._report_payload_cache)

        # Immutability under latest() admission overlay + SQL UPDATE invalidation via HTTP
        now = int(time.time())
        self._seed_host("imm-h", "imm-n", ts=now)
        rid = self._insert_report(
            host_id="imm-h",
            container_name="ctr",
            runtime="incus",
            project="default",
            ts=now,
            payload={"id": "a" * 36, "security": {"inbound_unique_ips": 4}},
        )
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO admission_states VALUES(?,?,?,?,?,?,?)",
                ("imm-h", "incus", "default", "ctr", "a" * 36, now + 5, json.dumps({"state": "enforced", "observed_at": now + 5})),
            )
            conn.commit()
        finally:
            conn.close()

        res1 = self.client.get("/api/v1/latest", auth=self.admin_auth)
        self.assertEqual(res1.status_code, 200)
        item1 = res1.json()["items"][0]
        self.assertEqual(item1["security"]["admission"]["state"], "enforced")
        # Cached dict MUST remain unmodified (no 'admission' key injected)
        self.assertNotIn("admission", server._report_payload_cache[rid][2]["security"])

        # Raw SQL UPDATE invalidates ETag & response & payload cache
        etag1 = res1.headers["etag"]
        conn = server.db()
        try:
            conn.execute(
                "UPDATE reports SET payload_json=? WHERE id=?",
                (json.dumps({"id": "b" * 36, "security": {"inbound_unique_ips": 8}}), rid),
            )
            conn.commit()
        finally:
            conn.close()

        res2 = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": etag1})
        self.assertEqual(res2.status_code, 200)
        self.assertNotEqual(res2.headers["etag"], etag1)
        self.assertEqual(res2.json()["items"][0]["container_id"], "b" * 36)

        # init_db() clears both caches
        self.assertGreater(len(server._report_payload_cache), 0)
        self.assertGreater(len(server._latest_response_cache), 0)
        server.init_db()
        self.assertEqual(len(server._report_payload_cache), 0)
        self.assertEqual(len(server._latest_response_cache), 0)

    def test_latest_early_etag_304_single_pass_response_cache_and_memory_bypass(self):
        now = int(time.time())
        self._seed_host("lat-h", "lat-n", ts=now)
        for idx in range(6):
            self._insert_report(host_id="lat-h", container_name=f"ctr-{idx}", ts=now)
        server_metrics.metrics.reset()

        # First call populates _latest_response_cache with > 1024-byte payload
        res_gz = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(res_gz.status_code, 200)
        self.assertGreaterEqual(len(res_gz.content), 1024)
        self.assertEqual(res_gz.headers.get("content-encoding"), "gzip")
        self.assertEqual(res_gz.headers.get_list("vary"), ["Accept-Encoding"])
        etag = res_gz.headers["etag"]
        self.assertEqual(len(server._latest_response_cache), 1)

        # Warm gzip, plain, q=0, and 304 hits do NOT call _parse_report_payload or gzip.compress
        with mock.patch.object(server, "_parse_report_payload", side_effect=AssertionError("should use response cache")), mock.patch.object(
            server.gzip, "compress", side_effect=AssertionError("should use cached gzip")
        ):
            res_gz_hit = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": "gzip"})
            res_plain_hit = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": "identity"})
            res_q0_hit = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": "gzip;q=0"})
            res_empty_ae_hit = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": ""})
            res_304 = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": etag})

        self.assertEqual(res_gz_hit.status_code, 200)
        self.assertEqual(res_gz_hit.headers.get("content-encoding"), "gzip")
        self.assertEqual(res_gz_hit.headers.get_list("vary"), ["Accept-Encoding"])
        self.assertEqual(len(res_gz_hit.json()["items"]), 6)

        for plain_res in (res_plain_hit, res_q0_hit, res_empty_ae_hit):
            self.assertEqual(plain_res.status_code, 200)
            self.assertGreaterEqual(len(plain_res.content), 1024)
            self.assertNotIn("content-encoding", plain_res.headers)
            self.assertEqual(plain_res.headers.get_list("vary"), ["Accept-Encoding"])
            self.assertEqual(plain_res.json(), res_gz_hit.json())

        self.assertEqual(res_304.status_code, 304)
        self.assertEqual(res_304.headers.get_list("vary"), ["Accept-Encoding"])
        self.assertEqual(server_metrics.metrics.snapshot()["counters"]["etag_304_hits"], 1)

        # Verify raw ASGI bytes for Accept-Encoding: gzip are valid single-gzip (not double-gzipped)
        # (httpx automatically decompresses once; double-gzip would fail .json())
        cache_entry = next(iter(server._latest_response_cache.values()))
        self.assertEqual(json.loads(gzip.decompress(cache_entry[2]).decode("utf-8")), res_plain_hit.json())

        # TTL=2s expiry triggers rebuild
        mono_t = time.monotonic()
        with mock.patch.object(server.time, "monotonic", return_value=mono_t + 3.0), mock.patch.object(
            server.gzip, "compress", wraps=gzip.compress
        ) as gz_spy:
            res_expired = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"Accept-Encoding": "gzip"})
        self.assertEqual(res_expired.status_code, 200)
        self.assertEqual(gz_spy.call_count, 1)

        # Max 4 entries eviction in _latest_response_cache
        server.invalidate_latest_caches()
        for idx in range(6):
            self._insert_report(host_id="lat-h", container_name=f"c-{idx}", ts=now + idx)
            self.client.get("/api/v1/latest", auth=self.admin_auth)
        self.assertEqual(len(server._latest_response_cache), 4)

        # :memory: DB bypasses _latest_response_cache
        server.invalidate_latest_caches()
        with mock.patch.object(server, "DB_PATH", ":memory:"):
            mem_conn = sqlite3.connect(":memory:")
            mem_conn.row_factory = sqlite3.Row
            mem_conn.executescript(
                """
                CREATE TABLE hosts(host_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL, agent_version TEXT DEFAULT 'unknown', node_id TEXT DEFAULT '', config_json TEXT DEFAULT '{}');
                CREATE TABLE reports(id INTEGER PRIMARY KEY, host_id TEXT, container_name TEXT, runtime TEXT, project TEXT, cpu_percent REAL, mem_bytes INTEGER, mem_percent REAL, net_rx_bps REAL, net_tx_bps REAL, conn_count INTEGER, disk_file TEXT, disk_size_bytes INTEGER, disk_used_percent REAL, podman_network_ok_v4 INTEGER, podman_network_ok_v6 INTEGER, ts INTEGER, payload_json TEXT);
                CREATE TABLE admission_states(host_id TEXT, runtime TEXT, project TEXT, container_name TEXT, instance_id TEXT, observed_at INTEGER, payload TEXT);
                CREATE TABLE container_user_notes(host_id TEXT, runtime TEXT, project TEXT, container_name TEXT, container_id TEXT, user_email TEXT, user_note TEXT, updated_at INTEGER, updated_by TEXT);
                CREATE TABLE buyer_targets(host_id TEXT, runtime TEXT, project TEXT, container_name TEXT, vm_id TEXT, user_email TEXT, user_name TEXT, verified_at INTEGER, enabled INTEGER, source TEXT, scope TEXT);
                CREATE TABLE buyer_mapping_issues(host_id TEXT, runtime TEXT, project TEXT, container_name TEXT, reason TEXT);
                """
            )
            class _NoClose:
                def __init__(self, inner): self._inner = inner
                def close(self): return None
                def __getattr__(self, item): return getattr(self._inner, item)
            with mock.patch.object(server, "db", side_effect=lambda: _NoClose(mem_conn)):
                mem_res = server.latest()
            mem_conn.close()
        self.assertEqual(mem_res.status_code, 200)
        self.assertEqual(len(server._latest_response_cache), 0)

        # State mutations (container_user_notes, admission_states, hosts.last_seen, buyer_targets) each bust ETag
        server.init_db()
        self._seed_host("chg-h", "chg-n", ts=now)
        self._insert_report(
            host_id="chg-h",
            container_name="ctr",
            runtime="incus",
            project="default",
            ts=now,
            payload={"id": "c" * 36, "security": {}},
        )
        e0 = self.client.get("/api/v1/latest", auth=self.admin_auth).headers["etag"]

        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO container_user_notes VALUES('chg-h','incus','default','ctr',?,'u@example.com','note',?,'admin')",
                ("c" * 36, now),
            )
            conn.commit()
        finally:
            conn.close()
        e1 = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": e0})
        self.assertEqual(e1.status_code, 200)
        self.assertNotEqual(e1.headers["etag"], e0)

        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO admission_states VALUES('chg-h','incus','default','ctr',?,?,?)",
                ("c" * 36, now + 10, json.dumps({"state": "enforced", "observed_at": now + 10})),
            )
            conn.commit()
        finally:
            conn.close()
        e2 = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": e1.headers["etag"]})
        self.assertEqual(e2.status_code, 200)
        self.assertNotEqual(e2.headers["etag"], e1.headers["etag"])

        conn = server.db()
        try:
            conn.execute("UPDATE hosts SET last_seen=? WHERE host_id='chg-h'", (now + 20,))
            conn.commit()
        finally:
            conn.close()
        e3 = self.client.get("/api/v1/latest", auth=self.admin_auth, headers={"If-None-Match": e2.headers["etag"]})
        self.assertEqual(e3.status_code, 200)
        self.assertNotEqual(e3.headers["etag"], e2.headers["etag"])

    def test_process_report_sync_single_db_connection_and_mock_compatibility(self):
        now = int(time.time())
        db_calls = 0
        orig_db = server.db

        def counting_db():
            nonlocal db_calls
            db_calls += 1
            return orig_db()

        payload = {
            "host_id": "rep-h",
            "node_id": "rep-n",
            "agent_version": "2.2.0",
            "timestamp": now,
            "container_network": {"ipv4_ok": True, "ipv6_ok": True},
            "containers": [
                {
                    "id": "c1",
                    "name": "c1",
                    "runtime": "podman",
                    "project": "",
                    "cpu_percent": 10.0,
                    "mem_bytes": 100,
                    "mem_percent": 1.0,
                    "net_rx_bps": 10.0,
                    "net_tx_bps": 20.0,
                    "conn_count": 3,
                }
            ],
            "security": {"enabled": True, "total_rx_bps": 10.0, "total_tx_bps": 20.0, "alerts": []},
        }
        with mock.patch.object(server, "db", side_effect=counting_db), mock.patch.object(
            server, "sync_configured_bot_alert_messages"
        ):
            res = server._process_report_sync(payload, "127.0.0.1")
        self.assertTrue(res["ok"])
        self.assertIn("motd_states", res)
        self.assertIn("security_policy", res)
        self.assertEqual(db_calls, 1)

        # Patching dispatch_buyer_notifications_for_alerts remains supported
        with mock.patch.object(server, "sync_configured_bot_alert_messages"), mock.patch.object(
            server, "dispatch_buyer_notifications_for_alerts"
        ) as mock_dispatch:
            res2 = server._process_report_sync({**payload, "timestamp": now + 1}, "127.0.0.1")
        self.assertTrue(res2["ok"])
        mock_dispatch.assert_called_once()

    def test_compute_security_status_covering_and_null_fallback_and_eqp(self):
        now = int(time.time())
        self._seed_host("sec-h", "sec-n", ts=now)
        # Same ts=now-10: one backfilled row (conn=10, inbound=2) + one legacy NULL row (conn=25, inbound=14 in JSON)
        # -> combined sum_conn=35, max_conn=25, max_inbound=14!
        t_mixed = now - 10
        self._insert_report(
            host_id="sec-h", container_name="c1", ts=t_mixed, conn_count=10, rx_bps=100, tx_bps=50, inbound_ips=2, outbound_ips=3
        )
        self._insert_report(
            host_id="sec-h",
            container_name="c2",
            ts=t_mixed,
            conn_count=25,
            rx_bps=300,
            tx_bps=150,
            inbound_ips=None,
            outbound_ips=None,
            payload={"id": "c2", "security": {"inbound_unique_ips": 14, "outbound_unique_ips": 9}},
        )
        # Another non-NULL timestamp with higher rx_bps
        self._insert_report(
            host_id="sec-h", container_name="c1", ts=now - 5, conn_count=5, rx_bps=900, tx_bps=40, inbound_ips=6, outbound_ips=4
        )

        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO host_security(host_id,ts,payload_json,total_rx_bps,total_tx_bps) VALUES(?,?,?,?,?)",
                ("sec-h", now - 20, json.dumps({"enabled": True, "total_rx_bps": 1200.0, "total_tx_bps": 800.0}), 1200.0, 800.0),
            )
            conn.execute(
                "INSERT INTO host_security(host_id,ts,payload_json,total_rx_bps,total_tx_bps) VALUES(?,?,?,NULL,NULL)",
                ("sec-h", now - 10, json.dumps({"enabled": True, "total_rx_bps": 2500.0, "total_tx_bps": 700.0})),
            )
            conn.commit()

            # Verify EXPLAIN QUERY PLAN for covering & partial NULL indexes
            eqp_r_cov = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT host_id, ts, SUM(conn_count), MAX(conn_count), SUM(net_rx_bps), SUM(net_tx_bps), "
                    "MAX(inbound_unique_ips), MAX(outbound_unique_ips) "
                    "FROM reports INDEXED BY idx_reports_ts_host_peaks "
                    "WHERE ts >= ? AND inbound_unique_ips IS NOT NULL AND outbound_unique_ips IS NOT NULL GROUP BY host_id, ts",
                    (now - 3600,),
                ).fetchall()
            ]
            eqp_r_null = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT host_id, ts, SUM(conn_count) "
                    "FROM reports INDEXED BY idx_reports_null_peaks "
                    "WHERE ts >= ? AND (inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL) GROUP BY host_id, ts",
                    (now - 3600,),
                ).fetchall()
            ]
            eqp_hs_cov = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT host_id, MAX(total_rx_bps), MAX(total_tx_bps) "
                    "FROM host_security INDEXED BY idx_host_security_ts_peaks "
                    "WHERE ts >= ? AND total_rx_bps IS NOT NULL AND total_tx_bps IS NOT NULL GROUP BY host_id",
                    (now - 3600,),
                ).fetchall()
            ]
            eqp_hs_null = [
                tuple(r)
                for r in conn.execute(
                    "EXPLAIN QUERY PLAN SELECT host_id, MAX(COALESCE(total_rx_bps, 0)) "
                    "FROM host_security INDEXED BY idx_host_security_null_peaks "
                    "WHERE ts >= ? AND (total_rx_bps IS NULL OR total_tx_bps IS NULL) GROUP BY host_id",
                    (now - 3600,),
                ).fetchall()
            ]
            self.assertTrue(any("COVERING INDEX idx_reports_ts_host_peaks" in str(r) for r in eqp_r_cov), eqp_r_cov)
            self.assertTrue(any("idx_reports_null_peaks" in str(r) for r in eqp_r_null), eqp_r_null)
            self.assertTrue(any("COVERING INDEX idx_host_security_ts_peaks" in str(r) for r in eqp_hs_cov), eqp_hs_cov)
            self.assertTrue(any("idx_host_security_null_peaks" in str(r) for r in eqp_hs_null), eqp_hs_null)
        finally:
            conn.close()

        status = server._compute_security_status()["items"][0]
        self.assertEqual(status["today_peak_conn_count"], 35)
        self.assertEqual(status["today_peak_container_conn_count"], 25)
        self.assertEqual(status["today_peak_inbound_ips"], 14)
        self.assertEqual(status["today_peak_outbound_ips"], 9)
        self.assertEqual(status["today_peak_rx_bps"], 2500.0)
        self.assertEqual(status["today_peak_tx_bps"], 800.0)
        # latest_container_15m used _parse_report_payload and populated cache
        self.assertGreater(len(server._report_payload_cache), 0)

        # Legacy DB without named peak/null indexes falls back cleanly without OperationalError
        conn = server.db()
        try:
            conn.execute("DROP INDEX idx_host_security_ts_peaks")
            conn.execute("DROP INDEX idx_reports_ts_host_peaks")
            conn.execute("DROP INDEX idx_reports_null_peaks")
            conn.execute("DROP INDEX idx_host_security_null_peaks")
            conn.commit()
        finally:
            conn.close()
        fallback_status = server._compute_security_status()["items"][0]
        self.assertEqual(fallback_status["today_peak_conn_count"], 35)
        self.assertEqual(fallback_status["today_peak_rx_bps"], 2500.0)

        # After backfilling NULL rows, covering-only path returns exact same peaks
        server.init_db()
        self._seed_host("cov-h", "cov-n", ts=now)
        self._insert_report(
            host_id="cov-h", container_name="c1", ts=now - 10, conn_count=10, rx_bps=100, tx_bps=50, inbound_ips=2, outbound_ips=3
        )
        self._insert_report(
            host_id="cov-h", container_name="c2", ts=now - 10, conn_count=25, rx_bps=300, tx_bps=150, inbound_ips=14, outbound_ips=9
        )
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO host_security(host_id,ts,payload_json,total_rx_bps,total_tx_bps) VALUES(?,?,?,?,?)",
                ("cov-h", now - 10, json.dumps({"enabled": True, "total_rx_bps": 2500.0, "total_tx_bps": 800.0}), 2500.0, 800.0),
            )
            conn.commit()
        finally:
            conn.close()
        cov_status = server._compute_security_status()["items"][0]
        self.assertEqual(cov_status["today_peak_conn_count"], 35)
        self.assertEqual(cov_status["today_peak_container_conn_count"], 25)
        self.assertEqual(cov_status["today_peak_inbound_ips"], 14)
        self.assertEqual(cov_status["today_peak_outbound_ips"], 9)
        self.assertEqual(cov_status["today_peak_rx_bps"], 2500.0)
        self.assertEqual(cov_status["today_peak_tx_bps"], 800.0)

    def test_telegram_sync_closes_db_before_network_io(self):
        conn = server.db()
        try:
            conn.execute(
                "INSERT INTO notification_bots(name,kind,token,target,min_severity,enabled,callback_secret,created_at,updated_at) "
                "VALUES('ops','telegram','123456:abcdefghijklmnopqrstuvwxyz','-1001','warning',1,'sec',1,1)"
            )
            server.process_security_alerts(
                conn,
                "tg-h",
                100,
                [
                    {
                        "type": "container_connection_count",
                        "severity": "critical",
                        "title": "High Conns",
                        "runtime": "incus",
                        "project": "default",
                        "container_name": "c1",
                        "message": "too many",
                    }
                ],
            )
            conn.commit()
        finally:
            conn.close()

        open_conns: set[int] = set()
        sql_log: list[str] = []
        orig_db = server.db
        open_counts_during_api: list[int] = []

        def fake_api(token, method, payload):
            open_counts_during_api.append(len(open_conns))
            if method == "sendMessage":
                return {"ok": True, "result": {"message_id": 501}}
            return {"ok": True}

        with mock.patch.object(
            server, "db", side_effect=lambda: _TrackingConn(orig_db(), sql_log, open_conns)
        ), mock.patch.object(server, "_telegram_api", side_effect=fake_api):
            server.sync_configured_bot_alert_messages("tg-h", 100)
            # Also test editMessageText -> message to edit not found -> resend recovery path
            conn_upd = orig_db()
            try:
                conn_upd.execute("UPDATE security_alerts SET status='resolved', last_seen=200 WHERE host_id='tg-h'")
                conn_upd.commit()
            finally:
                conn_upd.close()

            def fake_edit_then_resend(token, method, payload):
                open_counts_during_api.append(len(open_conns))
                if method == "editMessageText":
                    raise RuntimeError("Bad Request: message to edit not found")
                return {"ok": True, "result": {"message_id": 502}}

            with mock.patch.object(server, "_telegram_api", side_effect=fake_edit_then_resend):
                server.sync_configured_bot_alert_messages("tg-h", 200)

        self.assertGreaterEqual(len(open_counts_during_api), 3)
        self.assertEqual(open_counts_during_api, [0] * len(open_counts_during_api))
        self.assertEqual(open_conns, set())

        conn = server.db()
        try:
            msg = conn.execute("SELECT message_id, last_status FROM telegram_alert_messages").fetchone()
            bot = conn.execute("SELECT last_delivery_status, last_sent_at FROM notification_bots").fetchone()
            self.assertEqual(tuple(msg), (502, "resolved"))
            self.assertEqual(bot["last_delivery_status"], "succeeded")
            self.assertGreater(bot["last_sent_at"], 0)

            conn.execute("UPDATE security_alerts SET status='active', last_seen=300 WHERE host_id='tg-h'")
            conn.commit()
        finally:
            conn.close()

        # Error path also keeps DB closed during _telegram_api and records failure cleanly
        def fake_api_fail(token, method, payload):
            open_counts_during_api.append(len(open_conns))
            raise RuntimeError("telegram timeout")

        with mock.patch.object(
            server, "db", side_effect=lambda: _TrackingConn(orig_db(), sql_log, open_conns)
        ), mock.patch.object(server, "_telegram_api", side_effect=fake_api_fail):
            server.sync_configured_bot_alert_messages("tg-h", 300)

        self.assertEqual(open_counts_during_api, [0] * len(open_counts_during_api))
        self.assertEqual(open_conns, set())
        conn = server.db()
        try:
            bot = conn.execute("SELECT last_delivery_status, last_delivery_error FROM notification_bots").fetchone()
            self.assertEqual(bot["last_delivery_status"], "failed")
            self.assertIn("telegram timeout", bot["last_delivery_error"])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
