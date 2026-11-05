import asyncio
import json
import sqlite3
import unittest
from unittest.mock import patch, MagicMock
from server import reach_monitor

class TestReachMonitor(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE hosts (
            host_id TEXT PRIMARY KEY,
            last_seen INTEGER NOT NULL,
            agent_version TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            container_name TEXT NOT NULL,
            runtime TEXT NOT NULL DEFAULT 'podman',
            project TEXT NOT NULL DEFAULT '',
            cpu_percent REAL NOT NULL,
            mem_bytes INTEGER NOT NULL,
            mem_percent REAL NOT NULL DEFAULT 0,
            net_rx_bps REAL NOT NULL,
            net_tx_bps REAL NOT NULL,
            conn_count INTEGER NOT NULL,
            disk_file TEXT,
            disk_size_bytes INTEGER,
            disk_used_percent REAL,
            podman_network_ok_v4 INTEGER NOT NULL,
            podman_network_ok_v6 INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE host_security (
            host_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY(host_id, ts)
        );
        CREATE TABLE gfw_states (
            host_id TEXT PRIMARY KEY,
            blocked_count INTEGER NOT NULL DEFAULT 0,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            updated_at INTEGER NOT NULL
        );
        """)
        reach_monitor.init_db(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_ssrf_and_bogon_protection(self):
        # RFC1918 Private ranges
        self.assertFalse(reach_monitor.is_public_ip("10.0.0.1"))
        self.assertFalse(reach_monitor.is_public_ip("172.16.5.10"))
        self.assertFalse(reach_monitor.is_public_ip("192.168.1.1"))
        # Loopback & Link-local
        self.assertFalse(reach_monitor.is_public_ip("127.0.0.1"))
        self.assertFalse(reach_monitor.is_public_ip("169.254.1.1"))
        # CGNAT
        self.assertFalse(reach_monitor.is_public_ip("100.64.0.1"))
        # Invalid / Empty
        self.assertFalse(reach_monitor.is_public_ip(""))
        self.assertFalse(reach_monitor.is_public_ip("not-an-ip"))
        # Legitimate public IPs
        self.assertTrue(reach_monitor.is_public_ip("15.204.57.108"))
        self.assertTrue(reach_monitor.is_public_ip("1.1.1.1"))
        self.assertTrue(reach_monitor.is_public_ip("8.8.8.8"))

    def test_cloudflare_ip_filtering(self):
        # Cloudflare edge IPs must be detected and rejected as host targets
        self.assertTrue(reach_monitor.is_cloudflare_ip("104.23.251.79"))
        self.assertTrue(reach_monitor.is_cloudflare_ip("104.16.1.1"))
        self.assertTrue(reach_monitor.is_cloudflare_ip("162.158.187.57"))
        self.assertTrue(reach_monitor.is_cloudflare_ip("172.71.182.123"))
        self.assertFalse(reach_monitor.is_cloudflare_ip("15.204.57.108"))
        self.assertFalse(reach_monitor.is_cloudflare_ip("8.8.8.8"))

        self.assertFalse(reach_monitor.is_public_ip("104.23.251.79"))
        self.assertFalse(reach_monitor.is_public_ip("162.158.187.57"))

    def test_extract_client_ip(self):
        # 1. CF-Connecting-IP takes highest precedence
        class Req1:
            headers = {"cf-connecting-ip": "119.28.1.1", "x-forwarded-for": "104.23.251.79"}
            client = None
        self.assertEqual(reach_monitor.extract_client_ip(Req1), "119.28.1.1")

        # 2. X-Real-IP takes precedence when cf-connecting-ip is Cloudflare or missing
        class Req2:
            headers = {"cf-connecting-ip": "104.23.251.79", "x-real-ip": "119.28.1.2"}
            client = None
        self.assertEqual(reach_monitor.extract_client_ip(Req2), "119.28.1.2")

        # 3. X-Forwarded-For filters out Cloudflare proxy IPs
        class Req3:
            headers = {"x-forwarded-for": "104.23.251.79, 119.28.1.3"}
            client = None
        self.assertEqual(reach_monitor.extract_client_ip(Req3), "119.28.1.3")

    def test_discover_target_and_open_ports(self):
        # Insert host reports and security
        host_id = "test-node-1"
        self.conn.execute(
            "INSERT INTO hosts(host_id, last_seen, agent_version) VALUES(?, 1700000000, '1.7.213')",
            (host_id,),
        )
        report_payload = {
            "network_addresses": ["10.0.0.2", "15.204.57.108"],
            "security": {
                "listening_ports": [80, 443, 8080],
                "network_exposure": [{"host_port": 2222}],
            },
        }
        self.conn.execute(
            "INSERT INTO reports(host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps, conn_count, podman_network_ok_v4, podman_network_ok_v6, ts, payload_json) VALUES(?, 'c1', 'podman', '', 0, 0, 0, 0, 0, 0, 1, 1, 1700000000, ?)",
            (host_id, json.dumps(report_payload)),
        )
        self.conn.commit()

        target = reach_monitor.discover_host_target(self.conn, host_id)
        self.assertEqual(target, "15.204.57.108")

        ports = reach_monitor.discover_host_open_ports(self.conn, host_id)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(8080, ports)
        self.assertIn(2222, ports)

        selected_port = reach_monitor.choose_random_port(ports)
        self.assertIn(selected_port, ports)

    def test_parse_measurement_results_verdict_all_ok(self):
        # Mock results from globalping HTTP probe
        raw_results = []
        for i, reg in enumerate(reach_monitor.REACH_REGIONS):
            raw_results.append({
                "probe": {
                    "asn": reg.get("asn", 10000 + i),
                    "country": reg.get("country", "US"),
                    "city": reg.get("city", f"City-{i}"),
                },
                "result": {
                    "statusCode": 200,
                    "timings": {"total": 45, "tcp": 30, "dns": 5, "tls": 10, "firstByte": 40},
                },
            })

        m_data = {"status": "finished", "results": raw_results}
        summary = reach_monitor.parse_measurement_results(m_data, "1.1.1.1", 443, "TCP")
        self.assertEqual(summary["verdict"], "ok")
        self.assertEqual(summary["verdict_label"], "三网通畅·全球可达")
        self.assertEqual(summary["stats"]["success"], 18)
        self.assertEqual(summary["stats"]["cn_success"], 3)
        self.assertEqual(summary["stats"]["cnAverageMs"], summary["stats"]["cn_avg_ms"])
        self.assertIsNotNone(summary["stats"]["cnTelecomMs"])

    def test_parse_measurement_ping_results(self):
        # Mock results from globalping ICMP ping probe
        raw_results = []
        for i, reg in enumerate(reach_monitor.REACH_REGIONS):
            raw_results.append({
                "probe": {
                    "asn": reg.get("asn", 10000 + i),
                    "country": reg.get("country", "US"),
                    "city": reg.get("city", f"City-{i}"),
                },
                "result": {
                    "rawOutput": "3 packets transmitted, 3 received, 0% packet loss",
                    "stats": {"avg": 35.5, "loss": 0, "rcv": 3, "min": 35.0, "max": 36.0},
                },
            })

        m_data = {"status": "finished", "type": "ping", "results": raw_results}
        summary = reach_monitor.parse_measurement_results(m_data, "1.1.1.1", 0, "PING")
        self.assertEqual(summary["protocol"], "PING")
        self.assertEqual(summary["verdict"], "ok")
        self.assertEqual(summary["verdict_label"], "三网通畅·全球可达")
        self.assertEqual(summary["stats"]["success"], 18)
        self.assertEqual(summary["stats"]["cn_success"], 3)
        self.assertEqual(summary["stats"]["cnAverageMs"], 35.5)

    def test_run_hourly_reach_cycle_thread_safety(self):
        # Verify that run_hourly_reach_cycle runs without SQLite cross-thread errors
        host_id = "node-thread-test"
        import time
        now = int(time.time())
        self.conn.execute(
            "INSERT INTO hosts(host_id, last_seen, agent_version) VALUES(?, ?, '1.7.213')",
            (host_id, now - 60),
        )
        reach_monitor.record_client_ip(self.conn, host_id, "15.204.57.108", now)
        self.conn.commit()

        # Mock execute_globalping_measurement
        mock_raw = []
        for reg in reach_monitor.REACH_REGIONS:
            mock_raw.append({
                "probe": {"asn": reg.get("asn", 1234), "country": reg.get("country", "US"), "city": reg.get("city", "")},
                "result": {
                    "statusCode": 200,
                    "stats": {"avg": 50, "loss": 0, "rcv": 3},
                    "timings": {"total": 50, "tcp": 20},
                },
            })
        mock_mdata = {"status": "finished", "results": mock_raw}

        # Shared in-memory DB or file DB with factory
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        def db_factory():
            c = sqlite3.connect(db_path)
            c.row_factory = sqlite3.Row
            return c

        init_conn = db_factory()
        init_conn.executescript("""
        CREATE TABLE hosts (host_id TEXT PRIMARY KEY, last_seen INTEGER NOT NULL, agent_version TEXT NOT NULL, node_id TEXT NOT NULL DEFAULT '', config_json TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE reports (id INTEGER PRIMARY KEY, host_id TEXT, container_name TEXT, runtime TEXT, project TEXT, cpu_percent REAL, mem_bytes INTEGER, mem_percent REAL, net_rx_bps REAL, net_tx_bps REAL, conn_count INTEGER, disk_file TEXT, disk_size_bytes INTEGER, disk_used_percent REAL, podman_network_ok_v4 INTEGER, podman_network_ok_v6 INTEGER, ts INTEGER, payload_json TEXT);
        CREATE TABLE host_security (host_id TEXT, ts INTEGER, payload_json TEXT, PRIMARY KEY(host_id, ts));
        CREATE TABLE gfw_states (host_id TEXT PRIMARY KEY, blocked_count INTEGER, evidence_json TEXT, updated_at INTEGER);
        """)
        reach_monitor.init_db(init_conn)
        init_conn.execute("INSERT INTO hosts(host_id, last_seen, agent_version) VALUES(?, ?, '1.7.213')", (host_id, now - 60))
        reach_monitor.record_client_ip(init_conn, host_id, "15.204.57.108", now)
        init_conn.commit()
        init_conn.close()

        with patch("server.reach_monitor.sync_rate_limits", return_value={"remaining": 250, "limit": 250, "reset_seconds": 0}), \
             patch("server.reach_monitor.execute_globalping_measurement", return_value=mock_mdata):
            checked = asyncio.run(reach_monitor.run_hourly_reach_cycle(db_factory, pace_seconds_override=0.01))
            self.assertEqual(checked, 1)

        # Verify host_reachability was saved in worker thread
        check_conn = db_factory()
        row = check_conn.execute("SELECT * FROM host_reachability WHERE host_id=?", (host_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["verdict"], "ok")
        self.assertEqual(row["target"], "15.204.57.108")
        check_conn.close()
        os.unlink(db_path)

    def test_perform_host_reach_check_preserves_history_on_rate_limit(self):
        # When rate limit occurs, existing healthy results must NEVER be wiped or overwritten with []
        host_id = "node-preserve-test"
        import time
        now = int(time.time())
        self.conn.execute("INSERT INTO hosts(host_id, last_seen, agent_version) VALUES(?, ?, '1.7.219')", (host_id, now))
        reach_monitor.record_client_ip(self.conn, host_id, "15.204.57.108", now)

        # Populate pre-existing healthy test result
        self.conn.execute("""
            INSERT INTO host_reachability(host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at)
            VALUES(?, '15.204.57.108', 443, 'TCP', 'ok', '三网通畅·全球可达', 'All good', '{"success":18}', '[{"region":{"id":"cn-telecom"},"status":"ok"}]', ?)
        """, (host_id, now - 300))
        self.conn.commit()

        # Execute check that returns rate_limited
        rate_limited_mdata = {"status": "rate_limited", "results": [], "active_regions": []}
        with patch("server.reach_monitor.execute_globalping_measurement", return_value=rate_limited_mdata):
            res = reach_monitor.perform_host_reach_check(self.conn, host_id)
            self.assertIsNone(res)

        # Confirm host_reachability row was preserved untouched
        row = self.conn.execute("SELECT * FROM host_reachability WHERE host_id=?", (host_id,)).fetchone()
        self.assertEqual(row["verdict"], "ok")
        self.assertEqual(row["verdict_label"], "三网通畅·全球可达")
        self.assertIn("cn-telecom", row["results_json"])
        self.assertEqual(row["checked_at"], now - 300)

    def test_budget_aware_region_pruning(self):
        # Under low budget (<8 credits), probe China 3 carriers only (cost: 3 credits)
        reach_monitor._rate_limit_state["remaining"] = 5
        reach_monitor._rate_limit_state["limit"] = 250
        reach_monitor._rate_limit_state["last_sync"] = 1000000.0  # skip sync

        with patch("urllib.request.urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"id": "dummy-m-id"}).encode("utf-8")
            mock_resp.headers = {"X-Credits-Remaining": "2"}
            mock_url.return_value.__enter__.return_value = mock_resp

            with patch("time.sleep"):
                res = reach_monitor.execute_globalping_measurement("1.1.1.1", 443, "TCP", timeout_seconds=1)
                # Active regions should only be China 3 carriers
                self.assertEqual(len(res.get("active_regions", [])), 3)
                ids = {r["id"] for r in res.get("active_regions", [])}
                self.assertEqual(ids, {"cn-telecom", "cn-unicom", "cn-mobile"})

        # Reset rate limit state
        reach_monitor._rate_limit_state["remaining"] = 250

    def test_globalping_api_key_system_settings(self):
        # Verify API key reading from database system_settings
        self.conn.execute("INSERT INTO system_settings(key, value, updated_at) VALUES('globalping_api_key', 'test-token-123', 1000)")
        self.conn.commit()
        key = reach_monitor.get_globalping_api_key(self.conn)
        self.assertEqual(key, "test-token-123")

    def test_reachability_api_unauthenticated_sanitization(self):
        # Populate a sample host reachability result with real IP
        now = 1700000000
        self.conn.execute("""
            INSERT INTO host_reachability(host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at)
            VALUES('node-shanghai', '15.204.57.108', 443, 'TCP', 'ok', '全通', 'ok', '{"ok":1}', '[{"region":{"id":"cn-telecom"},"ip":"15.204.57.108","status":"ok"}]', ?)
        """, (now,))
        self.conn.commit()

        class UnclosableConnection:
            def __init__(self, conn):
                self._conn = conn
            def __getattr__(self, name):
                if name == "close":
                    return lambda: None
                return getattr(self._conn, name)

        from fastapi import FastAPI, HTTPException
        app = FastAPI()
        reach_monitor.attach(app, lambda: UnclosableConnection(self.conn), None, None)

        # 1. Unauthenticated Request (request.state.dashboard_user is None)
        class MockUnauthRequest:
            class state:
                dashboard_user = None

        routes = {r.path: r for r in app.routes}
        summary_route = routes["/api/v1/reachability/summary"].endpoint
        res_unauth = summary_route(MockUnauthRequest())
        body_unauth = json.loads(res_unauth.body.decode("utf-8"))
        item_unauth = body_unauth["items"][0]

        # Target IP must be omitted / empty
        self.assertEqual(item_unauth["target"], "")
        # Probe result IP must be omitted / empty
        self.assertEqual(item_unauth["results"][0]["ip"], "")

        # 2. Authenticated Request (request.state.dashboard_user = 'admin')
        class MockAuthRequest:
            class state:
                dashboard_user = "admin"

        res_auth = summary_route(MockAuthRequest())
        body_auth = json.loads(res_auth.body.decode("utf-8"))
        item_auth = body_auth["items"][0]

        # Target IP and result IP must be preserved for logged-in admin
        self.assertEqual(item_auth["target"], "15.204.57.108")
        self.assertEqual(item_auth["results"][0]["ip"], "15.204.57.108")

    def test_reachability_api_mutation_requires_auth(self):
        class UnclosableConnection:
            def __init__(self, conn):
                self._conn = conn
            def __getattr__(self, name):
                if name == "close":
                    return lambda: None
                return getattr(self._conn, name)

        from fastapi import FastAPI, HTTPException
        app = FastAPI()
        reach_monitor.attach(app, lambda: UnclosableConnection(self.conn), None, None)

        class MockUnauthRequest:
            class state:
                dashboard_user = None

        routes = {r.path: r for r in app.routes}
        trigger_route = routes["/api/v1/reachability/trigger"].endpoint
        settings_route = routes["/api/v1/reachability/settings"].endpoint

        async def _test():
            with self.assertRaises(HTTPException) as cm:
                await trigger_route(MockUnauthRequest())
            self.assertEqual(cm.exception.status_code, 401)

            with self.assertRaises(HTTPException) as cm2:
                await settings_route(MockUnauthRequest())
            self.assertEqual(cm2.exception.status_code, 401)

        asyncio.run(_test())

    def test_discover_dual_stack_targets(self):
        # Insert host with both public IPv4 and IPv6 in host_security
        sec_payload = {
            "host_firewall": {
                "interface_inventory": {
                    "interfaces": [
                        {
                            "name": "eth0",
                            "addresses": [
                                "192.168.1.100/24",
                                "15.204.57.108/32",
                                "2606:4700::1/64",  # Cloudflare IPv6, should be ignored
                                "2001:4860:4860::8888/64",  # Public IPv6
                            ]
                        }
                    ]
                }
            }
        }
        self.conn.execute(
            "INSERT INTO host_security(host_id, ts, payload_json) VALUES(?, ?, ?)",
            ("node-dual-stack", 1000, json.dumps(sec_payload))
        )
        targets = reach_monitor.discover_host_targets(self.conn, "node-dual-stack")
        self.assertEqual(targets.get("ipv4"), "15.204.57.108")
        self.assertEqual(targets.get("ipv6"), "2001:4860:4860::8888")

    @patch("server.reach_monitor.execute_globalping_measurement")
    def test_perform_host_reach_check_dual_stack_budget(self, mock_meas):
        # Prepare dual stack host
        sec_payload = {
            "host_firewall": {
                "interface_inventory": {
                    "interfaces": [
                        {
                            "name": "eth0",
                            "addresses": [
                                "15.204.57.108/32",
                                "2001:4860:4860::8888/64",
                            ]
                        }
                    ]
                },
                "listening_ports": [443]
            }
        }
        self.conn.execute(
            "INSERT INTO host_security(host_id, ts, payload_json) VALUES(?, ?, ?)",
            ("node-dual-test", 1000, json.dumps(sec_payload))
        )

        # Mock Globalping measurements: 1st call for V4 (5 regions), 2nd call for V6 (3 regions)
        calls = []
        def _mock_exec(target, port, protocol="TCP", regions=None, api_key=None, conn=None):
            calls.append({"target": target, "port": port, "regions": regions})
            region_count = len(regions) if regions else 8
            # Return successful results for all regions
            return {
                "status": "finished",
                "results": [
                    {
                        "probe": {"asn": r.get("asn", 0), "country": r.get("country", "CN")},
                        "result": {"status": "finished", "timings": {"tcp": 50, "total": 50}}
                    }
                    for r in (regions or [])
                ],
                "active_regions": regions or [],
            }
        mock_meas.side_effect = _mock_exec

        res = reach_monitor.perform_host_reach_check(self.conn, "node-dual-test")
        self.assertIsNotNone(res)
        self.assertTrue(res.get("is_dual_stack"))
        self.assertTrue(res.get("has_ipv6"))
        self.assertEqual(res.get("target"), "15.204.57.108")
        self.assertEqual(res.get("target_v6"), "2001:4860:4860::8888")

        # Verify calls and budget: V4 must have 5 regions, V6 must have 3 regions (Total = 8)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["target"], "15.204.57.108")
        self.assertEqual(len(calls[0]["regions"]), 5)  # China 3 + HK + US
        self.assertEqual(calls[1]["target"], "2001:4860:4860::8888")
        self.assertEqual(len(calls[1]["regions"]), 3)  # China 3 only

        # Verify DB row contains both V4 and V6
        row = self.conn.execute("SELECT * FROM host_reachability WHERE host_id=?", ("node-dual-test",)).fetchone()
        self.assertEqual(row["target"], "15.204.57.108")
        self.assertEqual(row["target_v6"], "2001:4860:4860::8888")
        self.assertEqual(row["verdict_v6"], "ok")
        self.assertEqual(row["verdict_label_v6"], "三网通畅")

    def test_reachability_api_dual_stack_masking(self):
        class UnclosableConnection:
            def __init__(self, conn):
                self._conn = conn
            def __getattr__(self, name):
                if name == "close":
                    return lambda: None
                return getattr(self._conn, name)

        from fastapi import FastAPI
        app = FastAPI()
        reach_monitor.attach(app, lambda: UnclosableConnection(self.conn), None, None)

        now = 1700000000
        stats_v4 = {"total": 5, "ok": 5, "cn_success": 3, "cnAverageMs": 45}
        stats_v6 = {"total": 3, "ok": 3, "cn_success": 3, "cnAverageMs": 48}
        results_v4 = [{"region": {"id": "cn-telecom"}, "status": "ok", "ip": "15.204.57.108"}]
        results_v6 = [{"region": {"id": "cn-telecom"}, "status": "ok", "ip": "2001:4860:4860::8888"}]

        self.conn.execute("""
            INSERT INTO host_reachability(
                host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at,
                target_v6, port_v6, protocol_v6, verdict_v6, verdict_label_v6, verdict_desc_v6, stats_json_v6, results_json_v6, checked_at_v6
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "node-mask-dual", "15.204.57.108", 443, "TCP", "ok", "三网通畅·核心可达", "描述",
            json.dumps(stats_v4), json.dumps(results_v4), now,
            "2001:4860:4860::8888", 443, "TCP", "ok", "三网通畅", "IPv6描述",
            json.dumps(stats_v6), json.dumps(results_v6), now
        ))
        self.conn.commit()

        class MockUnauthRequest:
            class state:
                dashboard_user = None

        class MockAuthRequest:
            class state:
                dashboard_user = {"username": "admin", "role": "admin"}

        routes = {r.path: r for r in app.routes}
        summary_route = routes["/api/v1/reachability/summary"].endpoint

        # 1. Unauthenticated: both V4 and V6 targets and results IP must be masked
        res_unauth = summary_route(MockUnauthRequest())
        body_unauth = json.loads(res_unauth.body.decode("utf-8"))
        item_unauth = body_unauth["items"][0]
        self.assertTrue(item_unauth["is_dual_stack"])
        self.assertEqual(item_unauth["target"], "")
        self.assertEqual(item_unauth["target_v6"], "")
        self.assertEqual(item_unauth["results"][0]["ip"], "")
        self.assertEqual(item_unauth["results_v6"][0]["ip"], "")
        self.assertEqual(item_unauth["stats"]["cnAverageMs"], 45)
        self.assertEqual(item_unauth["stats_v6"]["cnAverageMs"], 48)

        # 2. Authenticated: both V4 and V6 IPs are visible
        res_auth = summary_route(MockAuthRequest())
        body_auth = json.loads(res_auth.body.decode("utf-8"))
        item_auth = body_auth["items"][0]
        self.assertEqual(item_auth["target"], "15.204.57.108")
        self.assertEqual(item_auth["target_v6"], "2001:4860:4860::8888")
        self.assertEqual(item_auth["results"][0]["ip"], "15.204.57.108")
        self.assertEqual(item_auth["results_v6"][0]["ip"], "2001:4860:4860::8888")
        self.assertTrue(item_auth["checked_at_iso_utc8"].startswith("2023-"))

    def test_icmp_ping_fallback_when_tcp_fails(self):
        # When TCP probe gets 0 successes, it should automatically fall back to ICMP ping
        host_id = "node-tcp-fail-ping-ok"
        now = 1700000000
        self.conn.execute("INSERT INTO hosts(host_id, last_seen, agent_version) VALUES(?, ?, '1.7.219')", (host_id, now))
        reach_monitor.record_client_ip(self.conn, host_id, "103.73.220.161", now)
        # Add host_security with closed port 22
        self.conn.execute(
            "INSERT INTO host_security(host_id, ts, payload_json) VALUES(?, ?, ?)",
            (host_id, now, json.dumps({"host_firewall": {"listening_ports": [22]}}))
        )
        self.conn.commit()

        calls = []
        def _mock_exec(target, port, protocol="TCP", regions=None, **kwargs):
            calls.append({"target": target, "port": port, "protocol": protocol})
            regs = regions or [r for r in reach_monitor.REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile"}]
            if protocol == "TCP":
                # Simulated TCP refused / timeout
                return {
                    "status": "finished",
                    "type": "http",
                    "active_regions": regs,
                    "results": [
                        {"probe": {"asn": r.get("asn", 0), "country": r.get("country", "CN")}, "result": {"rawOutput": "connect ECONNREFUSED"}}
                        for r in regs
                    ],
                }
            else:
                # Simulated Ping success!
                return {
                    "status": "finished",
                    "type": "ping",
                    "active_regions": regs,
                    "results": [
                        {"probe": {"asn": r.get("asn", 0), "country": r.get("country", "CN")}, "result": {"stats": {"avg": 35.0, "loss": 0, "rcv": 3}}}
                        for r in regs
                    ],
                }

        with patch("server.reach_monitor.execute_globalping_measurement", side_effect=_mock_exec):
            res = reach_monitor.perform_host_reach_check(self.conn, host_id)
            self.assertIsNotNone(res)
            # Must have executed 2 calls: first TCP, then Ping fallback
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0]["protocol"], "TCP")
            self.assertEqual(calls[1]["protocol"], "PING")
            self.assertEqual(res["protocol"], "PING")
            self.assertEqual(res["verdict"], "ok")
            self.assertIn("三网通畅", res["verdict_label"])
            self.assertEqual(res["stats"]["cn_success"], 3)

    def test_format_utc8(self):
        self.assertEqual(reach_monitor.format_utc8(0), "")
        self.assertEqual(reach_monitor.format_utc8(None), "")
        # 1700000000 = 2023-11-14 22:13:20 UTC -> 2023-11-15 06:13:20 UTC+8
        formatted = reach_monitor.format_utc8(1700000000)
        self.assertEqual(formatted, "2023-11-15 06:13:20")

if __name__ == "__main__":
    unittest.main()
