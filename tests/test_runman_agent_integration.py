import asyncio
import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from client import agent
from server import buyer_mapping

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runman_integration_server", ROOT / "server" / "app.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(server)


class SimpleRequest:
    def __init__(self, payload=None, role="admin"):
        self.payload = payload or {}
        self.state = SimpleNamespace(dashboard_role=role, dashboard_user="test-admin")

    async def json(self):
        return self.payload


class RunmanAgentIntegrationTests(unittest.TestCase):
    def setUp(self):
        agent._net_counters.clear()
        agent._runtime_bins = None
        agent._warned_missing_bins.clear()
        self.temp = tempfile.TemporaryDirectory()
        server.DB_PATH = str(Path(self.temp.name) / "monitor.db")
        server.init_db()

    def tearDown(self):
        try:
            self.temp.cleanup()
        except Exception:
            pass

    def test_collect_runman_report_bandwidth_and_counters(self):
        vm_id = "11111111-2222-3333-4444-555555555555"
        container = {
            "id": vm_id,
            "stable_id": vm_id,
            "name": vm_id,
            "runtime": "runman",
            "instance_id": "gen-1",
            "connection_metrics": {
                "schema": 1,
                "source": "runman_local_proc_net",
                "valid": True,
                "tcp_total": 42,
                "total": 42,
            },
            "runman_resources": {
                "cpu": 2,
                "cpu_percent": 15.5,
                "ram_mb": 2048,
                "mem_bytes": 1024 * 1024 * 512,
                "mem_limit_bytes": 1024 * 1024 * 1024,
                "disk_gb": 40,
                "writable_layer": {
                    "available": True,
                    "source": "runman_overlay_upperdir_allocated",
                    "sampled_at": 100,
                    "allocated_bytes": 12 * 1024 * 1024,
                    "logical_file_bytes": 10 * 1024 * 1024,
                    "regular_files": 7,
                },
                "traffic_in_bytes": 1000000,
                "traffic_out_bytes": 2000000,
                "ips": ["10.0.0.2", "192.168.1.100"],
                "net_metrics_available": True,
            },
        }

        with mock.patch("time.time", side_effect=[100.0, 100.0]):
            r1 = agent.collect_runman_report(container)

        self.assertEqual(r1["runtime"], "runman")
        self.assertEqual(r1["net_rx_bps"], 0.0)
        self.assertEqual(r1["net_tx_bps"], 0.0)
        self.assertTrue(r1["traffic_counters"]["available"])
        self.assertEqual(r1["traffic_counters"]["rx"], 1000000)
        self.assertEqual(r1["traffic_counters"]["tx"], 2000000)
        self.assertEqual(r1["traffic_counters"]["source"], "runman")
        self.assertEqual(r1["network_addresses"], ["10.0.0.2", "192.168.1.100"])
        self.assertTrue(r1["container_disk"]["available"])
        self.assertEqual(r1["container_disk"]["rootfs_bytes"], 40 * 1024 * 1024 * 1024)
        self.assertTrue(r1["container_disk"]["rw_available"])
        self.assertEqual(r1["container_disk"]["rw_bytes"], 12 * 1024 * 1024)
        self.assertEqual(r1["container_disk"]["rw_source"], "runman_overlay_upperdir_allocated")
        self.assertTrue(r1["container_disk"]["rw_logical_available"])
        self.assertEqual(r1["container_disk"]["rw_logical_file_bytes"], 10 * 1024 * 1024)
        self.assertEqual(r1["container_disk"]["rw_regular_files"], 7)
        self.assertEqual(r1["container_disk"]["fs"]["root"]["total_bytes"], 40 * 1024 * 1024 * 1024)

        # Second cycle after 10 seconds with 500,000 extra bytes rx and 1,000,000 extra bytes tx
        container2 = dict(container)
        container2["runman_resources"] = dict(container["runman_resources"])
        container2["runman_resources"]["traffic_in_bytes"] = 1500000
        container2["runman_resources"]["traffic_out_bytes"] = 3000000

        with mock.patch("time.time", side_effect=[110.0, 110.0]):
            r2 = agent.collect_runman_report(container2)

        self.assertAlmostEqual(r2["net_rx_bps"], 50000.0, delta=1.0)
        self.assertAlmostEqual(r2["net_tx_bps"], 100000.0, delta=1.0)
        self.assertEqual(r2["traffic_counters"]["rx"], 1500000)
        self.assertEqual(r2["traffic_counters"]["tx"], 3000000)

    def test_latest_exposes_only_fresh_runman_writable_layer_metrics(self):
        vm_id = "11111111-2222-3333-4444-555555555555"
        now = int(time.time())
        payload = {
            "id": vm_id,
            "stable_id": vm_id,
            "runtime": "runman",
            "container_disk": {
                "rw_available": True,
                "rw_source": "runman_overlay_upperdir_allocated",
                "rw_bytes": 8192,
                "rw_sampled_at": now,
                "rw_logical_available": True,
                "rw_logical_source": "runman_overlay_upperdir_logical_file_bytes",
                "rw_logical_file_bytes": 4096,
                "rw_regular_files": 3,
            },
        }
        conn = server.db()
        try:
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES('runman-host',?,'runman-node')", (now,))
            conn.execute(
                """
                INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,
                  net_rx_bps,net_tx_bps,conn_count,disk_file,disk_used_percent,podman_network_ok_v4,
                  podman_network_ok_v6,ts,payload_json)
                VALUES('runman-host',?,'runman','default',0,0,0,0,0,0,'',0,1,1,?,?)
                """,
                (vm_id, now, json.dumps(payload)),
            )
            conn.commit()
        finally:
            conn.close()

        fresh = next(item for item in json.loads(server.latest().body.decode())["items"] if item["container_name"] == vm_id)
        self.assertTrue(fresh["container_disk_rw_available"])
        self.assertTrue(fresh["container_disk_rw_logical_available"])
        self.assertEqual(fresh["container_disk_rw_bytes"], 8192)
        self.assertEqual(fresh["container_disk_rw_logical_file_bytes"], 4096)
        self.assertEqual(fresh["container_disk_rw_regular_files"], 3)

        payload["container_disk"]["rw_sampled_at"] = now - 301
        conn = server.db()
        try:
            conn.execute(
                "UPDATE reports SET payload_json=? WHERE host_id='runman-host' AND container_name=?",
                (json.dumps(payload), vm_id),
            )
            conn.commit()
        finally:
            conn.close()
        stale = next(item for item in json.loads(server.latest().body.decode())["items"] if item["container_name"] == vm_id)
        self.assertFalse(stale["container_disk_rw_available"])
        self.assertFalse(stale["container_disk_rw_logical_available"])
        self.assertIsNone(stale["container_disk_rw_logical_file_bytes"])

    def test_runman_report_preserves_guest_security_scans_and_fresh_io_metrics(self):
        container = {
            "id": "11111111-2222-3333-4444-555555555555",
            "stable_id": "11111111-2222-3333-4444-555555555555",
            "name": "11111111-2222-3333-4444-555555555555",
            "runtime": "runman", "instance_id": "generation-1", "status": "running",
            "connection_metrics": {"schema": 1, "source": "runman_local_proc_net", "valid": True, "tcp_total": 4, "total": 4},
            "runman_resources": {
                "cpu": 2, "cpu_percent": 15.5, "mem_bytes": 1024, "mem_limit_bytes": 4096,
                "disk_gb": 4, "traffic_in_bytes": 100, "traffic_out_bytes": 200,
                "traffic_counters_available": True,
                "monitor_metrics": {
                    "available": True, "sampled_at": 100, "samples": 3,
                    "cpu_percent": 15.5, "disk_read_bytes_per_second": 2048.0,
                    "disk_write_bytes_per_second": 1024.0, "disk_read_iops": 2.0,
                    "disk_write_iops": 1.0, "udp_flows": 7,
                    "net_rx_bits_per_second": 8000.0,
                },
            },
        }
        base = {
            "conn_count": 4,
            "top_cpu_process": {"pid": 9, "cpu_percent": 70.0, "command": "proxy"},
            "security": {"suspicious_processes": [{"pid": 9, "name": "proxy"}],
                         "protocol_rates": {"udp_rx_bps": 10.0}},
        }
        report = agent.collect_runman_report(container, base)
        self.assertEqual(report["top_cpu_process"]["command"], "proxy")
        self.assertEqual(report["security"]["suspicious_processes"][0]["name"], "proxy")
        self.assertEqual(report["security"]["protocol_rates"]["udp_rx_bps"], 10.0)
        self.assertEqual(report["udp_flow_count"], 7)
        self.assertEqual(report["container_disk"]["io"]["read_bytes_per_second"], 2048.0)
        self.assertTrue(report["security"]["deep_process_inspection_supported"])

    def test_runman_banner_exec_is_bound_to_discovered_generation(self):
        container = {
            "name": "11111111-2222-3333-4444-555555555555", "runtime": "runman",
            "runtime_bin": "runman", "instance_id": "generation-1",
        }
        with mock.patch.object(agent, "_runman_exec_request", return_value=(True, "ok")) as execute:
            self.assertEqual(agent._checked_banner_exec(container, "id"), (True, "ok"))
        execute.assert_called_once_with(container["name"], "generation-1", "id", agent._runtime_command_timeout())

    def test_runman_in_runtime_bins_without_warning(self):
        with mock.patch.dict(os.environ, {"CONTAINER_RUNTIMES": "runman"}):
            with mock.patch.object(agent.os.path, "exists", return_value=True), \
                 mock.patch.object(agent.os, "name", "posix"), \
                 mock.patch.object(agent.socket, "AF_UNIX", 1, create=True):
                bins = agent.get_runtime_bins()
                self.assertEqual(bins.get("runman"), "runman")

    def test_server_user_note_allows_runman(self):
        host_id = "node-runman-1"
        vm_id = "aaaa1111-2222-3333-4444-555555555555"
        now = int(time.time())
        conn = server.db()
        try:
            conn.execute("INSERT INTO hosts(host_id,last_seen,node_id) VALUES(?,?,'node-uuid')", (host_id, now))
            conn.execute(
                """
                INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,disk_file,disk_used_percent,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json)
                VALUES(?,?,'runman','default',10.0,1024,50.0,0,0,5,'/disk',10,1,1,?,?)
                """,
                (host_id, vm_id, now, json.dumps({"id": vm_id, "stable_id": vm_id, "runtime": "runman"})),
            )
            conn.commit()
        finally:
            conn.close()

        req = SimpleRequest({
            "host_id": host_id,
            "runtime": "runman",
            "project": "default",
            "container_name": vm_id,
            "container_id": vm_id,
            "user_email": "buyer@example.com",
            "user_note": "VIP runman tenant",
        })

        resp = asyncio.run(server.save_container_user_note(req))
        self.assertEqual(resp.status_code, 200)

        get_req = SimpleRequest()
        get_resp = server.get_container_user_note(
            get_req,
            host_id=host_id,
            runtime="runman",
            container_name=vm_id,
            container_id=vm_id,
            project="default",
        )
        self.assertEqual(get_resp.status_code, 200)
        data = json.loads(get_resp.body.decode("utf-8"))
        self.assertEqual(data["user_email"], "buyer@example.com")
        self.assertEqual(data["user_note"], "VIP runman tenant")

    def test_buyer_mapping_supports_runman(self):
        conn = server.db()
        try:
            now = int(time.time())
            vm_id = "12345678-1234-1234-1234-123456789abc"
            conn.execute(
                """
                INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,disk_file,disk_used_percent,podman_network_ok_v4,podman_network_ok_v6,ts,payload_json)
                VALUES('host-1',?,'runman','default',10.0,1024,50.0,0,0,5,'/disk',10,1,1,?,?)
                """,
                (vm_id, now, json.dumps({"id": vm_id, "stable_id": vm_id, "runtime": "runman"})),
            )
            conn.commit()

            catalog = [{
                "id": vm_id,
                "machine_id": "99999999-9999-9999-9999-999999999999",
                "runtime": "runman",
                "user_id": "user-999",
                "user_email": "tenant@example.com",
                "status": "running",
            }]
            counts = buyer_mapping.apply(conn, catalog, now)
            self.assertEqual(counts["matched"], 1)

            row = conn.execute(
                "SELECT * FROM buyer_targets WHERE host_id='host-1' AND runtime='runman' AND container_name=?",
                (vm_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["user_email"], "tenant@example.com")
            self.assertEqual(row["user_id"], "user-999")
        finally:
            conn.close()

    def test_installer_script_detects_all_runtimes_with_docker_notice_default(self):
        installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        self.assertIn("has_runman=1", installer)
        self.assertIn('detected_runtimes+=("runman (rust)")', installer)
        self.assertIn("Container runtimes (auto or comma-separated podman,docker,incus,runman)", installer)
        self.assertIn("仅发现并提醒（默认不管理，推荐）", installer)


if __name__ == "__main__":
    unittest.main()
