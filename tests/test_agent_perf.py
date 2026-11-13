import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import agent


class AgentPerfTests(unittest.TestCase):
    def setUp(self) -> None:
        agent._cpu_counters.clear()
        agent._proc_cpu_counters.clear()

    def test_tick_scope_scans_proc_once_across_collectors(self):
        def fake_read_proc_text(path: str, limit: int = 8192) -> str:
            if path == "/proc/uptime":
                return "1000.0 500.0\n"
            if path == "/proc/100/status":
                return "Name:\tinit\nState:\tS (sleeping)\nPPid:\t1\nNSpid:\t100\t1\nUid:\t0\t0\t0\t0\nVmRSS:\t1024 kB\n"
            if path == "/proc/101/status":
                return "Name:\txray\nState:\tR (running)\nPPid:\t100\nNSpid:\t101\t15\nUid:\t0\t0\t0\t0\nVmRSS:\t8192 kB\n"
            if path == "/proc/200/status":
                return "Name:\tinit\nState:\tS (sleeping)\nPPid:\t1\nNSpid:\t200\t1\nUid:\t0\t0\t0\t0\nVmRSS:\t1024 kB\n"
            if path == "/proc/100/comm":
                return "init\n"
            if path == "/proc/101/comm":
                return "xray\n"
            if path == "/proc/200/comm":
                return "init\n"
            if path == "/proc/100/stat":
                return "100 (init) S 1 100 100 0 -1 4194304 10 0 0 0 10 5 0 0 20 0 1 0 100 1000000 500 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
            if path == "/proc/101/stat":
                return "101 (xray) R 100 100 100 0 -1 4194304 10 0 0 0 5000 100 0 0 20 0 1 0 200 1000000 500 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
            if path == "/proc/200/stat":
                return "200 (init) S 1 200 200 0 -1 4194304 10 0 0 0 10 5 0 0 20 0 1 0 100 1000000 500 0 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
            return ""

        with mock.patch.object(agent.os.path, "isdir", side_effect=lambda p: p in {"/proc/100", "/proc/200"}), \
             mock.patch.object(agent.os, "listdir", return_value=["100", "101", "200"]) as listdir_mock, \
             mock.patch.object(agent, "_read_host_proc_text", side_effect=fake_read_proc_text), \
             mock.patch.object(agent.os, "sysconf", return_value=100, create=True), \
             mock.patch.object(agent, "run", return_value="") as run_mock:
            with agent._collection_tick_scope():
                snap_a, _ = agent._collect_host_proc_process_snapshot(100, 50)
                snap_b, _ = agent._collect_host_proc_process_snapshot(100, 200)
                snap_c, _ = agent._collect_host_proc_process_snapshot(200, 50)
                top_proc = agent.collect_top_cpu_process("c1", "runman", "default", pid=100)
                suspicious = agent.collect_suspicious_processes("c1", "runman", "default", init_pid=100)

        self.assertEqual(listdir_mock.call_count, 1)
        run_mock.assert_not_called()
        self.assertTrue(snap_a["available"])
        self.assertEqual(len(snap_b["items"]), 2)
        self.assertEqual(len(snap_c["items"]), 1)
        self.assertEqual(top_proc["pid"], 15)
        self.assertEqual(suspicious, [])

    def test_runman_cgroup_quota_falls_back_to_parent_unit_cpu_max(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            unit_dir = Path(tmpdir) / "runman-11111111-2222-3333-4444-555555555555.service"
            ct_dir = unit_dir / "ct"
            ct_dir.mkdir(parents=True, exist_ok=True)
            (unit_dir / "cpu.max").write_text("100000 100000\n", encoding="ascii")
            (ct_dir / "cpu.max").write_text("max 100000\n", encoding="ascii")
            (ct_dir / "cpu.stat").write_text("usage_usec 5000000\n", encoding="ascii")

            with mock.patch.object(agent.cpu_guard, "resolve_container_cgroup", return_value=(ct_dir, "")), \
                 mock.patch.object(agent.time, "time", return_value=1000.0):
                sample = agent._sample_cgroup_cpu_metrics(
                    4321,
                    "runman",
                    "11111111-2222-3333-4444-555555555555",
                    "11111111-2222-3333-4444-555555555555",
                    instance_id="gen-1",
                    expected_start_ticks="999",
                )
        self.assertTrue(sample["available"])
        self.assertAlmostEqual(sample["quota_cpus"], 1.0, places=2)

    def test_incus_collect_container_reads_cgroup_quota_even_when_api_cpu_nonzero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cg_dir = Path(tmpdir) / "lxc.payload.c1"
            cg_dir.mkdir(parents=True, exist_ok=True)
            (cg_dir / "cpu.max").write_text("50000 100000\n", encoding="ascii")
            (cg_dir / "cpu.stat").write_text("usage_usec 2000000\n", encoding="ascii")

            with mock.patch.object(agent, "_incus_stats", return_value={
                "cpu_percent": 12.5,
                "cpu_effective_cpus": 2.0,
                "cpu_sample_available": True,
                "mem_bytes": 1024,
                "mem_limit_bytes": 2048,
                "mem_percent": 50.0,
                "net_rx_total_bytes": 0,
                "net_tx_total_bytes": 0,
                "net_rx_total_packets": 0,
                "net_tx_total_packets": 0,
            }), \
                 mock.patch.object(agent, "_host_cpu_capacity", return_value=2.0), \
                 mock.patch.object(agent.cpu_guard, "resolve_container_cgroup", return_value=(cg_dir, "")), \
                 mock.patch.object(agent, "collect_disk_alert", return_value={}), \
                 mock.patch.object(agent, "collect_container_disk_usage", return_value={"rw_bytes": 0, "rootfs_bytes": 0}), \
                 mock.patch.object(agent, "collect_top_cpu_process", return_value={"pid": 0, "cpu_percent": 0.0, "command": ""}), \
                 mock.patch.object(agent, "collect_suspicious_processes", return_value=[]), \
                 mock.patch.object(agent, "collect_panel_pairing_indicators", return_value={"socks_proxy": {}}), \
                 mock.patch.object(agent, "_collect_socket_security", return_value={"connection_metrics": {"valid": False}}), \
                 mock.patch.object(agent, "collect_hy2_indicators", return_value={}), \
                 mock.patch.object(agent, "_collect_socket_process_details", return_value={"communication_detail_available": True, "communication_sockets": [], "service_listeners": []}), \
                 mock.patch.object(agent, "run", return_value=""):
                report = agent.collect_container("c1", "c1", "incus", "incus", "default", pid_hint=3333)

        self.assertAlmostEqual(report["cpu_effective_cpus"], 0.5, places=2)
        self.assertGreaterEqual(report["cpu_percent"], 12.5)

    def test_runman_report_caps_effective_cpus_at_host_capacity_and_skips_redundant_df(self):
        container = {
            "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "stable_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "name": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "runtime": "runman",
            "runtime_bin": "runman",
            "project": "default",
            "status": "running",
            "instance_id": "gen-1",
            "pid": 0,
            "runman_resources": {
                "cpu": 4,
                "cpu_percent": 25.0,
                "cgroup_cpu_available": True,
                "cgroup_cpu_percent": 25.0,
                "cgroup_quota_cpus": 0.0,
                "mem_bytes": 1024,
                "mem_limit_bytes": 2048,
                "container_fs_available": True,
                "container_fs": {"root": {"total_bytes": 1000, "avail_bytes": 500}, "data": {"total_bytes": 0, "avail_bytes": 0}},
            },
        }
        with mock.patch.object(agent, "_host_cpu_capacity", return_value=1.0), \
             mock.patch.object(agent, "collect_disk_alert", return_value={}), \
             mock.patch.object(agent, "collect_container_disk_usage") as df_mock, \
             mock.patch.object(agent, "collect_top_cpu_process", return_value={"pid": 0, "cpu_percent": 0.0, "command": ""}), \
             mock.patch.object(agent, "collect_suspicious_processes", return_value=[]), \
             mock.patch.object(agent, "collect_panel_pairing_indicators", return_value={"socks_proxy": {}}), \
             mock.patch.object(agent, "_collect_socket_security", return_value={"connection_metrics": {"valid": False}}), \
             mock.patch.object(agent, "collect_hy2_indicators", return_value={}), \
             mock.patch.object(agent, "_collect_socket_process_details", return_value={"communication_detail_available": True, "communication_sockets": [], "service_listeners": []}), \
             mock.patch.object(agent, "run", return_value=""):
            base = agent.collect_container(
                container["name"],
                container["id"],
                "runman",
                "runman",
                "default",
                0,
                precomputed_runman_resources=container["runman_resources"],
                instance_id="gen-1",
            )
            report = agent.collect_runman_report(container, base)

        df_mock.assert_not_called()
        self.assertEqual(report["cpu_effective_cpus"], 1.0)

    def test_apply_low_priority_scheduling_uses_os_nice(self):
        with mock.patch.dict("os.environ", {"AGENT_NICE": "12"}), \
             mock.patch.object(agent.os, "nice", return_value=12, create=True) as nice_mock:
            agent._apply_low_priority_scheduling()
        nice_mock.assert_called_once_with(12)


if __name__ == "__main__":
    unittest.main()
