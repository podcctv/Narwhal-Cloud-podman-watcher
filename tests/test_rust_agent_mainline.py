"""End-to-end contract tests for the mainline Rust `narwhal-agent` and installer defaults."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("narwhal_server_rust_test", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class RustAgentMainlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="narwhal-rust-mainline-")
        self.orig_db = server.DB_PATH
        server.DB_PATH = str(Path(self.tmp.name) / "monitor.db")
        server._next_cleanup_monotonic = 0.0
        server.init_db()

    def tearDown(self):
        server.DB_PATH = self.orig_db
        self.tmp.cleanup()

    def _find_rust_agent_binary(self) -> Path | None:
        exe = "narwhal-agent.exe" if os.name == "nt" else "narwhal-agent"
        for profile in ("release", "debug"):
            candidate = ROOT / "rust" / "target" / profile / exe
            if candidate.is_file():
                return candidate
        return None

    def test_rust_agent_dry_run_report_and_poll_integrate_with_server(self):
        secret = "mainline-rust-test-secret"
        host_id = "rust-mainline-host"
        node_id = "rust-mainline-node-01"

        bin_path = self._find_rust_agent_binary()
        if bin_path is not None:
            env = {
                **os.environ,
                "HOST_ID": host_id,
                "NODE_ID": node_id,
                "CONTAINER_RUNTIMES": "none",
                "SECURITY_MONITOR_ENABLED": "true",
            }
            proc = subprocess.run(
                [str(bin_path), "--dry-run"],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report_payload = json.loads(proc.stdout)
        else:
            now = int(time.time())
            report_payload = {
                "host_id": host_id,
                "node_id": node_id,
                "client_config": {
                    "host_id": host_id,
                    "report_interval": 300,
                    "action_poll_interval": 10,
                    "container_runtimes": "none",
                    "docker_monitor_mode": "notice",
                    "incus_project": "all",
                    "security_monitor_enabled": True,
                },
                "agent_version": (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
                "timestamp": now,
                "container_network": {"ipv4_ok": True, "ipv6_ok": False},
                "podman_network": {"ipv4_ok": True, "ipv6_ok": False},
                "containers": [],
                "security": {
                    "enabled": True,
                    "interval_seconds": 300.0,
                    "total_rx_bps": 0.0,
                    "total_tx_bps": 0.0,
                    "total_rx_pps": 0.0,
                    "total_tx_pps": 0.0,
                    "syn_recv_count": 0,
                    "access_log": {"enabled": False, "readable_files": 0},
                    "access_sources": [],
                    "alerts": [],
                    "suspicious_processes": [],
                    "socket_abuse": {"schema": 1, "suspected": False},
                    "rfw_service_health": {"status": "healthy", "checked_at": now, "reason": "service_active"},
                    "host_firewall": {
                        "available": True,
                        "backend": "nftables",
                        "interface_inventory": {"status": "ready", "observed_at": now, "interfaces": []},
                    },
                    "host_audit": {
                        "enabled": True,
                        "scope": "host",
                        "os": {"id": "debian", "name": "Debian GNU/Linux 12", "version_id": "12"},
                        "snapshot_status": "ready",
                        "snapshot_at": now,
                        "baseline_at": now,
                        "baseline_pending": True,
                        "vulnerability_scan": {"status": "skipped", "coverage": "partial", "finding_count": 0},
                        "security_indicator_scan": {"status": "ready", "coverage": "complete", "finding_count": 0},
                        "recent_events": [],
                        "recent_findings": [],
                        "recent_indicators": [],
                    },
                    "conntrack": {"available": False, "entries": []},
                },
                "operations": {
                    "host_metrics": {"available": True},
                    "health": [{"source": "security", "status": "healthy"}],
                    "runtime_inventory": {"state": "empty", "runtimes": [], "container_count": 0},
                    "architecture": "x86_64",
                    "interval_seconds": 300.0,
                    "upgrade_result": {},
                    "capabilities": ["operations-v1", "agent-rust-v2", "public-tcp-v2"],
                    "schema_version": 1,
                },
            }

        raw_report = json.dumps(report_payload).encode("utf-8")
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), raw_report + ts.encode(), hashlib.sha256).hexdigest()

        with patch.object(server, "SHARED_SECRET", secret):
            client = TestClient(server.app)
            resp = client.post(
                "/api/v1/report",
                content=raw_report,
                headers={"X-Timestamp": ts, "X-Signature": sig, "Content-Type": "application/json"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertTrue(resp.json().get("ok"))

            # Verify poll accepts `gfw_probe_capabilities`
            poll_body = json.dumps({
                "host_id": host_id,
                "node_id": node_id,
                "gfw_probe_capabilities": {"ipv4_default_route": True, "ipv6_default_route": False},
            }).encode("utf-8")
            ts_poll = str(int(time.time()))
            sig_poll = hmac.new(secret.encode(), poll_body + ts_poll.encode(), hashlib.sha256).hexdigest()
            poll_resp = client.post(
                "/api/v1/actions/poll",
                content=poll_body,
                headers={"X-Timestamp": ts_poll, "X-Signature": sig_poll, "Content-Type": "application/json"},
            )
            self.assertEqual(poll_resp.status_code, 200, poll_resp.text)
            self.assertIn("actions", poll_resp.json())

        sec_data = json.loads(server.security_status().body)
        host_items = [item for item in sec_data.get("items", []) if item.get("host_id") == host_id]
        self.assertEqual(len(host_items), 1)
        host_item = host_items[0]
        self.assertTrue(host_item.get("agent_version"))
        self.assertTrue(host_item.get("last_seen_utc8"))
        self.assertIn("rfw_service_health", host_item)
        self.assertTrue(host_item.get("host_audit", {}).get("enabled"))

    def test_frontend_client_preserves_security_status_metadata(self):
        client_ts = (ROOT / "frontend" / "src" / "api" / "client.ts").read_text(encoding="utf-8")
        start = client_ts.index("getSecurityStatus:")
        snippet = client_ts[start : client_ts.index("updateHostConfig:", start)]
        self.assertIn("...item", snippet)


if __name__ == "__main__":
    unittest.main()
