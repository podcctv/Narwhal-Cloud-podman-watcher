import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_server", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class ServerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.tmp.name) / "monitor.db")
        server._next_cleanup_monotonic = 0.0
        self.original_tls_ca_path = server.TLS_CA_CERT_PATH
        server.init_db()

    def tearDown(self):
        server.TLS_CA_CERT_PATH = self.original_tls_ca_path
        self.tmp.cleanup()

    def _insert(
        self,
        runtime: str,
        cpu: float,
        project: str = "",
        agent_version: str = "",
        timestamp: int | None = None,
    ):
        now = timestamp or int(time.time())
        payload = {
            "id": f"{runtime}-id",
            "name": "same-name",
            "runtime": runtime,
            "mem_limit_bytes": 4,
            "cpu_effective_cpus": 2,
        }
        if agent_version:
            payload["_agent_version"] = agent_version
        conn = sqlite3.connect(server.DB_PATH)
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent,
                net_rx_bps, net_tx_bps, conn_count, disk_file, disk_size_bytes,
                disk_used_percent, podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            ("host", "same-name", runtime, project, cpu, 1, 1, 1, 1, 1, "", 0, 0, 1, 1, now, json.dumps(payload)),
        )
        conn.commit()
        conn.close()

    def test_latest_keeps_same_name_from_different_runtimes_separate(self):
        self._insert("docker", 10)
        self._insert("incus", 20, "default")
        response = server.latest()
        body = json.loads(response.body)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual({x["runtime"] for x in body["items"]}, {"docker", "incus"})

    def test_history_and_stats_do_not_mix_metric_versions(self):
        now = int(time.time())
        self._insert("incus", 99, "default", "1.0.0", now - 10)
        self._insert("incus", 5, "default", "1.0.1", now)

        history = json.loads(server.history("host", "same-name", "incus", "default", 60).body)
        self.assertEqual([x["agent_version"] for x in history["items"]], ["1.0.0", "1.0.1"])

        stats = json.loads(server.stats(60).body)
        self.assertEqual(stats["containers"][0]["samples"], 1)
        self.assertEqual(stats["containers"][0]["avg"]["cpu_percent"], 5)

    def test_report_accepts_runtime_and_project_fields(self):
        now = int(time.time())
        payload = {
            "host_id": "host",
            "agent_version": "1.0.0",
            "timestamp": now,
            "container_network": {"ipv4_ok": True, "ipv6_ok": False},
            "security": {
                "enabled": True,
                "total_rx_bps": 1234,
                "total_rx_pps": 12,
                "syn_recv_count": 3,
                "access_log": {"enabled": True, "readable_files": 1, "requests_per_second": 2},
                "alerts": [],
            },
            "containers": [
                {
                    "id": "c1",
                    "name": "app",
                    "runtime": "incus",
                    "project": "prod",
                    "cpu_percent": 2.5,
                }
            ],
        }
        body = json.dumps(payload).encode()

        class Request:
            async def body(self):
                return body

        timestamp = str(now)
        signature = hmac.new(
            server.SHARED_SECRET.encode(), body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        result = asyncio.run(server.report(Request(), timestamp, signature))
        self.assertEqual(
            result,
            {
                "ok": True,
                "server_version": server.APP_VERSION,
                "records": 1,
                "new_alerts": 0,
                "automatic_stops_queued": 0,
            },
        )

        conn = sqlite3.connect(server.DB_PATH)
        row = conn.execute("SELECT runtime, project FROM reports").fetchone()
        conn.close()
        self.assertEqual(row, ("incus", "prod"))
        status = json.loads(server.security_status().body)
        self.assertEqual(status["items"][0]["total_rx_bps"], 1234)
        self.assertEqual(status["items"][0]["access_log"]["requests_per_second"], 2)
        latest_body = json.loads(server.latest().body)
        self.assertEqual(latest_body["server_version"], server.APP_VERSION)
        self.assertEqual(latest_body["items"][0]["agent_version"], "1.0.0")

    def test_tls_ca_endpoint_authenticates_request_and_response(self):
        certificate = b"-----BEGIN CERTIFICATE-----\ntest-public-ca\n-----END CERTIFICATE-----\n"
        ca_path = Path(self.tmp.name) / "root.crt"
        ca_path.write_bytes(certificate)
        server.TLS_CA_CERT_PATH = str(ca_path)
        timestamp = str(int(time.time()))
        request_signature = hmac.new(
            server.SHARED_SECRET.encode(), timestamp.encode(), hashlib.sha256
        ).hexdigest()

        response = server.tls_ca(timestamp, request_signature)

        self.assertEqual(response.body, certificate)
        expected_response_signature = hmac.new(
            server.SHARED_SECRET.encode(), certificate + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(response.headers["x-narwhal-ca-signature"], expected_response_signature)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_security_alert_lifecycle_deduplicates_and_resolves(self):
        alert = {
            "type": "ddos_packets",
            "severity": "warning",
            "title": "packet flood",
            "message": "high pps",
            "value": 200,
            "threshold": 100,
            "runtime": "docker",
            "container_name": "panel",
        }
        conn = server.db()
        first = server.process_security_alerts(conn, "host", 100, [alert])
        second = server.process_security_alerts(conn, "host", 110, [alert])
        server.process_security_alerts(conn, "host", 120, [])
        conn.commit()
        row = conn.execute(
            "SELECT occurrence_count, status FROM security_alerts WHERE host_id='host'"
        ).fetchone()
        conn.close()
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(tuple(row), (2, "resolved"))

    def test_security_alert_endpoint_returns_active_alerts(self):
        conn = server.db()
        server.process_security_alerts(
            conn,
            "host",
            int(time.time()),
            [{"type": "port_scan", "severity": "warning", "title": "scan", "message": "scan"}],
        )
        conn.commit()
        conn.close()
        response = server.security_alerts()
        body = json.loads(response.body)
        self.assertEqual(body["active_count"], 1)
        self.assertEqual(body["items"][0]["type"], "port_scan")

    def test_dashboard_basic_auth_validates_generated_credentials(self):
        original_user = server.DASHBOARD_USERNAME
        original_password = server.DASHBOARD_PASSWORD
        try:
            server.DASHBOARD_USERNAME = "narwhal-test"
            server.DASHBOARD_PASSWORD = "random-password"
            token = base64.b64encode(b"narwhal-test:random-password").decode()
            self.assertEqual(
                server.dashboard_user_from_authorization(f"Basic {token}"), "narwhal-test"
            )
            self.assertIsNone(server.dashboard_user_from_authorization("Basic invalid"))
            wrong = base64.b64encode(b"narwhal-test:wrong").decode()
            self.assertIsNone(server.dashboard_user_from_authorization(f"Basic {wrong}"))
        finally:
            server.DASHBOARD_USERNAME = original_user
            server.DASHBOARD_PASSWORD = original_password

    def test_dashboard_groups_containers_into_collapsed_responsive_host_cards(self):
        html = server.dashboard()
        self.assertIn("id='host-containers'", html)
        self.assertIn("const expandedHosts=new Set();", html)
        self.assertIn("className='host-group'", html)
        self.assertIn("className='container-card'", html)
        self.assertIn("panel.hidden=!expanded", html)
        self.assertIn("overflow-x:hidden", html)
        self.assertIn("aria-labelledby", html)
        self.assertIn("/container-detail?", html)
        self.assertIn("versionBadge(latest.agent_version,d.server_version)", html)
        self.assertIn("容器安全与运行状态中心", html)
        self.assertIn("容器日志正常", html)
        self.assertIn("主机 IPv4", html)
        self.assertIn("入站去重 IP", html)
        self.assertNotIn("<table id='t'", html)

    def test_active_socks_enforcement_actions_explain_policy_effects(self):
        html = server.dashboard()
        self.assertIn("解除拦截并允许（不再提醒）", html)
        self.assertIn("仅隐藏本次告警（保留拦截）", html)
        self.assertIn("即使服务仍然无认证并对公网/NAT 暴露", html)
        self.assertIn("节点侧拦截策略不会解除", html)

    def test_container_detail_is_a_dedicated_internal_metrics_page(self):
        html = server.container_detail_page()
        self.assertIn("容器内部进程", html)
        self.assertIn("容器网络命名空间", html)
        self.assertIn("Incus 容器级 cgroup/OpenMetrics", html)
        self.assertIn("/api/v1/latest?include_stale=true", html)
        self.assertIn("/api/v1/history?", html)
        self.assertIn("overflow-x:hidden", html)
        self.assertIn("detail-version", html)
        self.assertIn("通信进程与连接明细", html)
        self.assertIn("communication_sockets", html)
        self.assertIn("入站去重 IP", html)
        self.assertIn("已忽略 ${excludedSamples} 条旧版本口径样本", html)
        self.assertIn("/container-detail?", server.stats_page())

    def test_release_version_is_shared_by_server_client_and_installers(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?$")
        agent_source = (ROOT / "client" / "agent.py").read_text(encoding="utf-8")
        server_source = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
        client_installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        server_installer = (ROOT / "scripts" / "install-server.sh").read_text(encoding="utf-8")
        self.assertIn('os.getenv("NARWHAL_VERSION", "dev")', agent_source)
        self.assertIn('"_pat=" + quoted_pattern', agent_source)
        self.assertNotIn('"_pat=" + pattern', agent_source)
        self.assertIn('os.getenv("NARWHAL_VERSION", "dev")', server_source)
        self.assertIn("NARWHAL_VERSION=$PROJECT_VERSION", client_installer)
        self.assertIn("ALERT_INBOUND_UNIQUE_IPS=$inbound_unique_ips", client_installer)
        self.assertIn("SECURITY_CONNTRACK_SNAPSHOT_MAX=$conntrack_snapshot_max", client_installer)
        self.assertIn("SECURITY_HOST_PROXY_SOCKET_MAX=$host_proxy_socket_max", client_installer)
        self.assertIn("SECURITY_AUTO_REMEDIATE_XMRIG=$auto_remediate_xmrig", client_installer)
        self.assertIn("SECURITY_AUTO_REMEDIATE_XRAYR=$auto_remediate_xrayr", client_installer)
        self.assertIn("NARWHAL_VERSION=$PROJECT_VERSION", server_installer)

    def test_client_installer_waits_for_signed_server_version(self):
        installer = (ROOT / "scripts" / "install-client.sh").read_text(
            encoding="utf-8"
        )
        updater = (ROOT / "scripts" / "auto-update.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/check-server-version.py", installer)
        self.assertIn("--expected-version \"$PROJECT_VERSION\"", installer)
        self.assertIn("exit 75", installer)
        self.assertIn('[[ "$MODE" == "install"', installer)
        self.assertIn("继续首次人工安装", installer)
        self.assertLess(
            installer.index("scripts/check-server-version.py"),
            installer.index("NARWHAL_VERSION=$PROJECT_VERSION"),
        )
        self.assertIn("waiting for Server to run the target version", updater)
        self.assertIn("deployment drift detected", updater)

    def test_automatic_update_unit_allows_image_build_wait(self):
        setup = (ROOT / "scripts" / "setup-auto-update.sh").read_text(
            encoding="utf-8"
        )
        updater = (ROOT / "scripts" / "auto-update.sh").read_text(encoding="utf-8")
        server_installer = (ROOT / "scripts" / "install-server.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("TimeoutStartSec=30min", setup)
        self.assertIn("KillMode=control-group", setup)
        self.assertIn("Delegate=yes", setup)
        self.assertIn("for _ in $(seq 1 30)", updater)
        self.assertIn("sleep 30", updater)
        self.assertIn("deployment drift detected", updater)
        self.assertIn("org.opencontainers.image.revision", updater)
        self.assertIn("flock --exclusive --nonblock", server_installer)
        self.assertIn("--close --conflict-exit-code 75", server_installer)
        self.assertIn("narwhal-monitor-server-deploy-v2.lock", server_installer)
        self.assertNotIn('exec 9>"$DEPLOY_LOCK_FILE"', server_installer)
        self.assertIn("仍在等待其他部署完成", server_installer)
        self.assertIn("部署锁现已释放", server_installer)
        self.assertIn("configure_container_cgroup_args", server_installer)
        self.assertIn("--cgroups=enabled --cgroup-parent=narwhal-monitor.slice", server_installer)
        self.assertIn("podman_run_detached", server_installer)
        self.assertIn("systemd-run --scope --quiet --collect", server_installer)
        self.assertIn("--slice=narwhal-monitor.slice", server_installer)
        self.assertIn('new_id="$(podman_run_detached server', server_installer)
        self.assertNotIn("podman run -d --replace", server_installer)
        self.assertIn("容器仍占用名称", server_installer)
        self.assertIn("Server 容器启动失败", server_installer)
        self.assertIn("conmon 未写入退出状态", server_installer)
        self.assertIn('podman container cleanup --rm "$container_name"', server_installer)
        self.assertIn("Server 运行版本不匹配", server_installer)
        self.assertIn("Server 镜像版本不匹配", server_installer)
        self.assertIn("sanitize_server_port", server_installer)
        self.assertIn("wait_for_backend_http", server_installer)
        self.assertIn("wait_for_tls_http", server_installer)
        self.assertIn("curl --noproxy '*'", server_installer)
        self.assertIn('target_args=( "https://${host}/" )', server_installer)
        self.assertIn("不会终止宿主机进程", server_installer)
        self.assertNotIn("kill -TERM", server_installer)
        self.assertIn('remove_container_for_replace "$TLS_CONTAINER_NAME" "TLS Proxy"', server_installer)
        self.assertIn('tls_container_id="$(podman_run_detached caddy', server_installer)
        self.assertIn("TLS Proxy 容器未能进入运行状态", server_installer)
        self.assertIn('caddy validate --config /etc/caddy/Caddyfile', server_installer)
        self.assertIn("stage_container_replacement", server_installer)
        self.assertIn("rollback_container_replacement", server_installer)
        self.assertIn("TLS Proxy 部署失败，Server 已回滚", server_installer)
        install_entry = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("git -C \"$REPO_DIR\" checkout -- .", updater)
        self.assertNotIn("git -C \"$ROOT_DIR\" checkout -- .", install_entry)
        self.assertIn("refusing automatic update to preserve operator changes", updater)

    def test_install_menus_support_arrows_and_numeric_choices(self):
        interactive = (ROOT / "scripts" / "lib" / "interactive.sh").read_text(
            encoding="utf-8"
        )
        installer = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("使用 ↑/↓ 移动", interactive)
        self.assertIn("请输入数字或名称", interactive)
        self.assertIn("'[A'", interactive)
        self.assertIn("'[B'", interactive)
        self.assertIn('action="$(narwhal_choose', installer)
        self.assertIn('mode="$(narwhal_choose', installer)
        self.assertIn("diagnose-server|诊断 Server（只读）", installer)
        diagnostic = (ROOT / "scripts" / "diagnose-server.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("REDACTED SERVER CONFIG", diagnostic)
        self.assertIn("[REDACTED]", diagnostic)
        self.assertNotIn("podman rm", diagnostic)
        self.assertNotIn("systemctl restart", diagnostic)

    def test_signed_agent_version_endpoint_reports_runtime_server_version(self):
        original_version = server.APP_VERSION
        server.APP_VERSION = "1.5.0"
        body = json.dumps(
            {"expected_version": server.APP_VERSION}, separators=(",", ":")
        ).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(
            server.SHARED_SECRET.encode(), body + timestamp.encode(), hashlib.sha256
        ).hexdigest()

        class Request:
            async def body(self):
                return body

        try:
            response = asyncio.run(
                server.agent_update_version(Request(), timestamp, signature)
            )
        finally:
            server.APP_VERSION = original_version
        payload = json.loads(response.body)
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["server_version"], "1.5.0")
        expected_response_signature = hmac.new(
            server.SHARED_SECRET.encode(),
            response.body + timestamp.encode(),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(
            response.headers["x-narwhal-response-signature"],
            expected_response_signature,
        )

    def test_panel_action_queue_and_agent_poll_are_signed(self):
        now = int(time.time())
        alert = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "unapproved panel",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "unapproved_domains": ["panel.example.net"],
            "process_patterns": ["v2bx"],
            "process_pids": [222],
            "config_files": ["/etc/V2bX/config.json"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", now, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class DashboardRequest:
            state = State()

            async def json(self):
                return {"action": "remediate"}

        queued = asyncio.run(server.queue_security_action(alert_id, DashboardRequest()))
        queued_body = json.loads(queued.body)
        self.assertTrue(queued_body["queued"])
        self.assertEqual(queued_body["action"]["action_type"], "remediate_panel_pairing")
        self.assertEqual(queued_body["action"]["params"]["domains"], ["panel.example.net"])
        self.assertEqual(queued_body["action"]["params"]["process_pids"], [222])

        refreshed_alert = dict(alert, process_pids=[333])
        conn = server.db()
        server.process_security_alerts(conn, "host1", now + 1, [refreshed_alert])
        conn.commit()
        conn.close()

        poll_body = json.dumps({"host_id": "host1"}, separators=(",", ":")).encode()

        class PollRequest:
            async def body(self):
                return poll_body

        timestamp = str(now)
        signature = hmac.new(
            server.SHARED_SECRET.encode(), poll_body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        response = asyncio.run(server.poll_security_actions(PollRequest(), timestamp, signature))
        response_body = json.loads(response.body)
        self.assertEqual(len(response_body["actions"]), 1)
        self.assertEqual(response_body["actions"][0]["params"]["process_pids"], [333])
        expected = hmac.new(
            server.SHARED_SECRET.encode(), response.body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        self.assertEqual(response.headers["x-narwhal-response-signature"], expected)
        self.assertNotIn("stop_container", response.body.decode())

    def test_remediation_result_requires_real_change_and_hides_successful_alert(self):
        alert = {
            "type": "unauthorized_panel_pairing",
            "severity": "warning",
            "title": "panel",
            "message": "节点程序特征 v2bx",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "process_patterns": ["v2bx"],
            "process_pids": [222],
        }

        class State:
            dashboard_user = "operator"

        class DenyRequest:
            state = State()

            async def json(self):
                return {"decision": "deny"}

        async def submit_result(action_id, message):
            result_body = json.dumps(
                {
                    "action_id": action_id,
                    "host_id": "host1",
                    "status": "succeeded",
                    "message": message,
                },
                separators=(",", ":"),
            ).encode()

            class ResultRequest:
                async def body(self):
                    return result_body

            timestamp = str(int(time.time()))
            signature = hmac.new(
                server.SHARED_SECRET.encode(), result_body + timestamp.encode(), hashlib.sha256
            ).hexdigest()
            return await server.security_action_result(ResultRequest(), timestamp, signature)

        conn = server.db()
        server.process_security_alerts(conn, "host1", int(time.time()), [alert])
        conn.commit()
        first_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()
        first_action = json.loads(
            asyncio.run(server.set_security_alert_disposition(first_id, DenyRequest())).body
        )["action"]
        asyncio.run(
            submit_result(
                first_action["id"],
                "killed_processes=0 removed_services=0 removed_configs=0 cleanup_errors=0",
            )
        )
        conn = server.db()
        failed = conn.execute(
            "SELECT status, result_message FROM security_actions WHERE id=?", (first_action["id"],)
        ).fetchone()
        alert_status = conn.execute(
            "SELECT status FROM security_alerts WHERE id=?", (first_id,)
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(failed["status"], "failed")
        self.assertIn("no matching process", failed["result_message"])
        self.assertEqual(alert_status, "active")

        conn = server.db()
        conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (first_id,))
        server.process_security_alerts(conn, "host1", int(time.time()) + 1, [alert])
        conn.commit()
        conn.close()
        second_action = json.loads(
            asyncio.run(server.set_security_alert_disposition(first_id, DenyRequest())).body
        )["action"]
        asyncio.run(
            submit_result(
                second_action["id"],
                "killed_processes=1 removed_services=0 removed_configs=0 cleanup_errors=0",
            )
        )
        conn = server.db()
        succeeded = conn.execute(
            "SELECT status FROM security_actions WHERE id=?", (second_action["id"],)
        ).fetchone()["status"]
        remediated = conn.execute(
            "SELECT status FROM security_alerts WHERE id=?", (first_id,)
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(succeeded, "succeeded")
        self.assertEqual(remediated, "remediated")

    def test_dismiss_once_hides_continuous_alert_but_realerts_after_resolution(self):
        alert = {
            "type": "port_scan",
            "severity": "warning",
            "title": "scan",
            "message": "scan",
            "runtime": "incus",
            "container_name": "node1",
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "dismiss_once"}

        asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        conn = server.db()
        self.assertEqual(server.process_security_alerts(conn, "host1", 110, [alert]), [])
        self.assertEqual(
            conn.execute("SELECT status FROM security_alerts WHERE id=?", (alert_id,)).fetchone()["status"],
            "dismissed",
        )
        server.process_security_alerts(conn, "host1", 120, [])
        notifications = server.process_security_alerts(conn, "host1", 130, [alert])
        conn.commit()
        status = conn.execute(
            "SELECT status FROM security_alerts WHERE id=?", (alert_id,)
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "active")
        self.assertEqual(len(notifications), 1)

    def test_allow_silent_policy_persists_and_suppresses_future_samples(self):
        alert = {
            "type": "docker_container_notice",
            "severity": "info",
            "title": "docker",
            "message": "notice only",
            "runtime": "docker",
            "container_name": "helper",
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "allow_silent"}

        asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        conn = server.db()
        notifications = server.process_security_alerts(conn, "host1", 110, [alert])
        conn.commit()
        row = conn.execute(
            "SELECT status FROM security_alerts WHERE id=?", (alert_id,)
        ).fetchone()
        policy_count = conn.execute("SELECT COUNT(*) FROM security_alert_policies").fetchone()[0]
        conn.close()
        self.assertEqual(notifications, [])
        self.assertEqual(row["status"], "suppressed")
        self.assertEqual(policy_count, 1)

    def test_panel_allow_silent_is_scoped_to_exact_domain(self):
        first = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "panel one",
            "runtime": "incus",
            "container_name": "node1",
            "unapproved_domains": ["one.example.net"],
        }
        second = dict(first, message="panel two", unapproved_domains=["two.example.net"])
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [first])
        fingerprint = conn.execute("SELECT fingerprint FROM security_alerts").fetchone()["fingerprint"]
        conn.execute(
            "INSERT INTO security_alert_policies(fingerprint,mode,requested_by,created_at,updated_at) VALUES(?,'allow_silent','operator',100,100)",
            (fingerprint,),
        )
        notifications = server.process_security_alerts(conn, "host1", 110, [first, second])
        conn.commit()
        statuses = [row["status"] for row in conn.execute("SELECT status FROM security_alerts ORDER BY id")]
        conn.close()
        self.assertEqual(statuses, ["suppressed", "active"])
        self.assertEqual([item["message"] for item in notifications], ["panel two"])

    def test_new_panel_alert_row_inherits_latest_container_remediation_status(self):
        first = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "first domain",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
            "unapproved_domains": ["one.example.net"],
            "process_patterns": ["v2bx"],
        }
        second = dict(first, message="second domain", unapproved_domains=["two.example.net"])
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [first])
        first_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.execute(
            """
            INSERT INTO security_actions(
                alert_id,host_id,runtime,project,container_name,action_type,params_json,
                status,requested_by,result_message,created_at,updated_at
            ) VALUES(?,?,?,?,?,'remediate_panel_pairing','{}','failed','operator',?,101,101)
            """,
            (
                first_id,
                "host1",
                "incus",
                "default",
                "node1",
                "no matching process, service or config was removed",
            ),
        )
        server.process_security_alerts(conn, "host1", 102, [second])
        conn.commit()
        conn.close()
        items = json.loads(server.security_alerts().body)["items"]
        current = next(item for item in items if item["message"] == "second domain")
        self.assertEqual(current["latest_action"]["status"], "failed")
        self.assertEqual(current["latest_action"]["alert_id"], first_id)

    def test_deny_extracts_safe_evidence_from_legacy_alert_message(self):
        alert = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "未授权面板域名 panel.example.net；节点程序特征 v2bx；配置文件 /etc/V2bX/config.json；容器内部监听端口 22,443",
            "runtime": "incus",
            "project": "default",
            "container_name": "node1",
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "deny"}

        response = asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["params"]["domains"], ["panel.example.net"])
        self.assertEqual(body["action"]["params"]["process_patterns"], ["v2bx"])
        self.assertEqual(body["action"]["params"]["config_files"], ["/etc/V2bX/config.json"])

    def test_deny_no_auth_socks_queues_persistent_stop_action(self):
        alert = {
            "type": "socks_weak_auth",
            "severity": "critical",
            "title": "SOCKS risk",
            "message": "SOCKS no auth",
            "runtime": "incus",
            "project": "default",
            "container_name": "proxy",
            "socks_auth_mode": "no_auth",
            "socks_processes": ["microsocks"],
            "socks_process_pids": [42],
            "socks_config_files": ["/etc/microsocks.conf"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "deny"}

        response = asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["action_type"], "enforce_socks_auth")
        self.assertEqual(body["action"]["params"]["auth_mode"], "no_auth")
        self.assertEqual(body["action"]["params"]["process_names"], ["microsocks"])

    def test_legacy_config_confirmed_sockd_alert_keeps_safe_stop_action(self):
        alert = {
            "type": "socks_weak_auth",
            "severity": "critical",
            "title": "SOCKS risk",
            "message": (
                "检测到 SOCKS 服务允许无认证访问；公网/NAT 暴露 是；"
                "进程 sockd；不会上报用户名或密码内容"
            ),
            "runtime": "incus",
            "project": "default",
            "container_name": "proxy",
            "socks_auth_mode": "no_auth",
            "socks_processes": [],
            "socks_process_pids": [],
            "socks_config_files": ["/etc/sockd.conf"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        item = json.loads(server.security_alerts().body)["items"][0]
        self.assertEqual(item["details"]["socks_processes"], ["sockd"])

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "deny"}

        response = asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        body = json.loads(response.body)
        self.assertEqual(body["action"]["params"]["process_names"], ["sockd"])

    def test_deny_rejects_nonempty_weak_socks_password(self):
        alert = {
            "type": "socks_weak_auth",
            "severity": "critical",
            "title": "SOCKS risk",
            "message": "SOCKS weak password",
            "runtime": "incus",
            "project": "default",
            "container_name": "proxy",
            "socks_auth_mode": "weak_password",
            "socks_processes": ["microsocks"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "deny"}

        with self.assertRaises(server.HTTPException) as raised:
            asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        self.assertEqual(raised.exception.status_code, 400)

    def test_allow_socks_alert_queues_enforcement_release(self):
        alert = {
            "type": "socks_weak_auth",
            "severity": "critical",
            "title": "SOCKS risk",
            "message": "SOCKS no auth",
            "runtime": "incus",
            "project": "default",
            "container_name": "proxy",
            "socks_auth_mode": "no_auth",
            "socks_processes": ["microsocks"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            async def json(self):
                return {"decision": "allow_silent"}

        response = asyncio.run(server.set_security_alert_disposition(alert_id, Request()))
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["action_type"], "release_socks_auth")

    def test_latest_keeps_same_incus_name_from_different_projects_separate(self):
        self._insert("incus", 10, "default")
        self._insert("incus", 20, "prod")
        response = server.latest()
        body = json.loads(response.body)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual({x["project"] for x in body["items"]}, {"default", "prod"})

    def test_latest_exposes_container_memory_limit_and_effective_cpus(self):
        self._insert("incus", 20, "default")
        item = json.loads(server.latest().body)["items"][0]
        self.assertEqual(item["mem_limit_bytes"], 4)
        self.assertEqual(item["cpu_effective_cpus"], 2)

    def test_latest_hides_an_entire_stale_host_but_keeps_stale_detail_access(self):
        stale_ts = int(time.time()) - server.STALE_SECONDS - 1
        self._insert("incus", 20, "default", timestamp=stale_ts)
        self.assertEqual(json.loads(server.latest().body)["items"], [])
        stale_items = json.loads(server.latest(include_stale=True).body)["items"]
        self.assertEqual(len(stale_items), 1)
        self.assertTrue(stale_items[0]["alerts"]["host_stale"])

    def test_latest_exposes_warning_and_critical_connection_levels(self):
        now = int(time.time())
        self._insert("podman", 1, timestamp=now)
        conn = sqlite3.connect(server.DB_PATH)
        conn.execute("UPDATE reports SET conn_count=501")
        conn.commit()
        conn.close()
        warning = json.loads(server.latest().body)["items"][0]
        self.assertEqual(warning["alerts"]["conn_severity"], "warning")

        conn = sqlite3.connect(server.DB_PATH)
        conn.execute("UPDATE reports SET conn_count=1001")
        conn.commit()
        conn.close()
        critical = json.loads(server.latest().body)["items"][0]
        self.assertEqual(critical["alerts"]["conn_severity"], "critical")

    def test_sustained_connection_overload_queues_one_automatic_stop(self):
        container = {
            "name": "node1",
            "runtime": "incus",
            "project": "default",
            "conn_count": server.CONNECTION_STOP_THRESHOLD,
        }
        conn = server.db()
        self.assertEqual(server.process_connection_overloads(conn, "host", 900, [container]), 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM connection_overloads").fetchone()[0], 0)
        container["conn_count"] += 1
        self.assertEqual(server.process_connection_overloads(conn, "host", 1000, [container]), 0)
        self.assertEqual(server.process_connection_overloads(conn, "host", 1300, [container]), 0)
        self.assertEqual(server.process_connection_overloads(conn, "host", 1600, [container]), 0)
        self.assertEqual(server.process_connection_overloads(conn, "host", 1900, [container]), 1)
        self.assertEqual(server.process_connection_overloads(conn, "host", 2200, [container]), 0)
        action = conn.execute("SELECT * FROM security_actions").fetchone()
        state = conn.execute("SELECT sample_count, stop_action_id FROM connection_overloads").fetchone()
        conn.close()
        self.assertEqual(action["action_type"], "stop_container")
        self.assertEqual(action["requested_by"], "system:connection-guard")
        self.assertEqual(tuple(state), (5, action["id"]))

    def test_connection_overload_gap_resets_continuous_timer(self):
        container = {
            "name": "node1",
            "runtime": "podman",
            "conn_count": server.CONNECTION_STOP_THRESHOLD + 1,
        }
        conn = server.db()
        server.process_connection_overloads(conn, "host", 1000, [container])
        server.process_connection_overloads(
            conn, "host", 1000 + server.CONNECTION_STOP_MAX_GAP_SECONDS + 1, [container]
        )
        state = conn.execute("SELECT first_seen, sample_count FROM connection_overloads").fetchone()
        actions = conn.execute("SELECT COUNT(*) FROM security_actions").fetchone()[0]
        conn.close()
        self.assertEqual(tuple(state), (1000 + server.CONNECTION_STOP_MAX_GAP_SECONDS + 1, 1))
        self.assertEqual(actions, 0)

    def test_inactive_host_cleanup_removes_associated_monitoring_data(self):
        self._insert("incus", 1, "default", timestamp=1000)
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id, last_seen, agent_version) VALUES('host',1000,'1.0.0')"
        )
        conn.execute(
            "INSERT INTO host_security(host_id,ts,payload_json) VALUES('host',1000,'{}')"
        )
        conn.commit()
        conn.close()

        server.cleanup_old_reports(1000 + server.OFFLINE_HOST_PURGE_SECONDS + 1)
        conn = server.db()
        counts = {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("hosts", "reports", "host_security")
        }
        conn.close()
        self.assertEqual(counts, {"hosts": 0, "reports": 0, "host_security": 0})

    def test_schema_has_runtime_column(self):
        conn = sqlite3.connect(server.DB_PATH)
        names = {row[1] for row in conn.execute("PRAGMA table_info(reports)")}
        conn.close()
        self.assertIn("runtime", names)
        self.assertIn("project", names)

    def test_database_uses_wal_busy_timeout_and_indexed_bounded_cleanup(self):
        conn = server.db()
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertGreaterEqual(
            conn.execute("PRAGMA busy_timeout").fetchone()[0], server.DB_BUSY_TIMEOUT_MS
        )
        index_names = {
            row[1] for row in conn.execute("PRAGMA index_list(reports)").fetchall()
        }
        self.assertIn("idx_reports_ts", index_names)
        plan = " ".join(
            str(row[3])
            for row in conn.execute(
                "EXPLAIN QUERY PLAN DELETE FROM reports WHERE id IN ("
                "SELECT id FROM reports INDEXED BY idx_reports_ts "
                "WHERE ts < ? ORDER BY ts LIMIT ?)",
                (0, server.REPORT_CLEANUP_BATCH_SIZE),
            ).fetchall()
        )
        conn.close()
        self.assertIn("idx_reports_ts", plan)

    def test_scheduled_cleanup_is_throttled(self):
        self._insert("incus", 1, timestamp=1)
        original_purge = server.PURGE_SECONDS
        try:
            server.PURGE_SECONDS = 1
            self.assertEqual(server.cleanup_old_reports(), 1)
            next_cleanup = server._next_cleanup_monotonic
            self.assertEqual(server.cleanup_old_reports(), 0)
            self.assertEqual(server._next_cleanup_monotonic, next_cleanup)
        finally:
            server.PURGE_SECONDS = original_purge

    def test_legacy_schema_is_migrated_without_losing_rows(self):
        conn = sqlite3.connect(server.DB_PATH)
        conn.execute("DROP TABLE reports")
        conn.execute(
            """
            CREATE TABLE reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id TEXT NOT NULL,
                container_name TEXT NOT NULL,
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
            )
            """
        )
        conn.execute(
            """
            INSERT INTO reports(
                host_id, container_name, cpu_percent, mem_bytes, mem_percent,
                net_rx_bps, net_tx_bps, conn_count, podman_network_ok_v4,
                podman_network_ok_v6, ts, payload_json
            ) VALUES('legacy-host','legacy-container',1,1,1,1,1,1,1,1,1,'{}')
            """
        )
        conn.commit()
        conn.close()

        server.init_db()

        conn = sqlite3.connect(server.DB_PATH)
        row = conn.execute("SELECT runtime, project FROM reports").fetchone()
        conn.close()
        self.assertEqual(row, ("podman", ""))

    def test_container_diagnostic_is_deduplicated_and_completed_by_report(self):
        self._insert("incus", 2, "default")

        class State:
            dashboard_user = "operator"

        class DiagnosticRequest:
            state = State()

            async def json(self):
                return {
                    "host_id": "host",
                    "runtime": "incus",
                    "project": "default",
                    "container_name": "same-name",
                }

        first = json.loads(asyncio.run(server.request_container_diagnostic(DiagnosticRequest())).body)
        second = json.loads(asyncio.run(server.request_container_diagnostic(DiagnosticRequest())).body)
        self.assertTrue(first["queued"])
        self.assertFalse(second["queued"])
        self.assertEqual(first["action"]["id"], second["action"]["id"])

        now = int(time.time())
        payload = {
            "host_id": "host",
            "agent_version": "1.1.0",
            "timestamp": now,
            "container_network": {"ipv4_ok": True, "ipv6_ok": True},
            "containers": [
                {
                    "name": "same-name",
                    "runtime": "incus",
                    "project": "default",
                    "deep_sample": {
                        "action_id": first["action"]["id"],
                        "sampled_at": now,
                        "process_count": 7,
                        "network_rates": {"rx_bps": 123, "tx_bps": 456},
                    },
                }
            ],
            "security": {"alerts": []},
        }
        body = json.dumps(payload).encode()

        class ReportRequest:
            async def body(self):
                return body

        timestamp = str(now)
        signature = hmac.new(
            server.SHARED_SECRET.encode(), body + timestamp.encode(), hashlib.sha256
        ).hexdigest()
        asyncio.run(server.report(ReportRequest(), timestamp, signature))
        status = json.loads(
            server.container_diagnostic_status("host", "incus", "same-name", "default").body
        )
        self.assertEqual(status["action"]["status"], "succeeded")
        self.assertEqual(status["sample"]["process_count"], 7)
        self.assertEqual(status["sample"]["agent_version"], "1.1.0")

    def test_container_detail_includes_on_demand_diagnostic_controls(self):
        html = server.container_detail_page()
        self.assertIn("请求深度上报", html)
        self.assertIn("/api/v1/containers/diagnostics", html)
        self.assertIn("不抓包、不扫描文件", html)

    def test_successful_automatic_xmrig_remediation_is_saved_in_history(self):
        alert = {
            "type": "malicious_process",
            "severity": "critical",
            "title": "确认挖矿程序",
            "message": "命中 1 个可疑进程特征；首个特征 xmrig，PID 9157",
            "runtime": "incus",
            "project": "default",
            "container_name": "miner",
            "malicious_processes": [{"process": "xmrig", "pid": 9157}],
            "automatic_remediation": {
                "attempted": True,
                "succeeded": True,
                "message": "killed_processes=1 removed_binaries=1 cleanup_errors=0",
            },
        }
        conn = server.db()
        notifications = server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        conn.close()
        self.assertEqual(notifications, [])
        history = json.loads(server.security_alert_history().body)
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["status"], "remediated")
        self.assertTrue(
            history["items"][0]["details"]["automatic_remediation"]["succeeded"]
        )

    def test_ignored_legacy_xmrig_alert_can_be_reprocessed_from_history(self):
        alert = {
            "type": "malicious_process",
            "severity": "critical",
            "title": "疑似恶意程序",
            "message": "命中 1 个可疑进程特征；首个特征 xmrig，PID 9157",
            "runtime": "incus",
            "project": "default",
            "container_name": "miner",
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            def __init__(self, decision):
                self.decision = decision

            async def json(self):
                return {"decision": self.decision}

        asyncio.run(
            server.set_security_alert_disposition(alert_id, Request("allow_silent"))
        )
        history = json.loads(
            server.security_alert_history(status="suppressed").body
        )
        self.assertEqual(history["items"][0]["latest_decision"]["decision"], "allow_silent")
        response = asyncio.run(
            server.set_security_alert_disposition(alert_id, Request("deny"))
        )
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["action_type"], "remediate_malicious_process")
        self.assertEqual(body["action"]["params"]["process_names"], ["xmrig"])
        conn = server.db()
        status = conn.execute(
            "SELECT status FROM security_alerts WHERE id=?", (alert_id,)
        ).fetchone()["status"]
        policies = conn.execute("SELECT COUNT(*) FROM security_alert_policies").fetchone()[0]
        conn.close()
        self.assertEqual(status, "active")
        self.assertEqual(policies, 0)

    def test_reopen_ignored_panel_alert_removes_node_allowlist_entry(self):
        alert = {
            "type": "unauthorized_panel_pairing",
            "severity": "critical",
            "title": "panel",
            "message": "panel",
            "runtime": "incus",
            "project": "default",
            "container_name": "node",
            "unapproved_domains": ["panel.example.net"],
            "process_patterns": ["xrayr"],
        }
        conn = server.db()
        server.process_security_alerts(conn, "host1", 100, [alert])
        conn.commit()
        alert_id = conn.execute("SELECT id FROM security_alerts").fetchone()["id"]
        conn.close()

        class State:
            dashboard_user = "operator"

        class Request:
            state = State()

            def __init__(self, decision):
                self.decision = decision

            async def json(self):
                return {"decision": self.decision}

        asyncio.run(
            server.set_security_alert_disposition(alert_id, Request("allow_silent"))
        )
        response = asyncio.run(
            server.set_security_alert_disposition(alert_id, Request("reopen"))
        )
        body = json.loads(response.body)
        self.assertTrue(body["queued"])
        self.assertEqual(body["action"]["action_type"], "disallow_panel_domains")
        self.assertEqual(body["action"]["params"]["domains"], ["panel.example.net"])

    def test_alert_history_page_is_responsive_and_linked_from_dashboard(self):
        history_html = server.security_alert_history_page()
        self.assertIn("安全告警历史", history_html)
        self.assertIn("重新禁止/处理", history_html)
        self.assertIn("恢复提醒", history_html)
        self.assertIn("overflow-x:hidden", history_html)
        self.assertIn("@media(max-width:640px)", history_html)
        self.assertIn("prefers-reduced-motion", history_html)
        self.assertIn("/api/v1/security/history", history_html)
        self.assertIn("href='/alerts/history'", server.dashboard())


if __name__ == "__main__":
    unittest.main()
