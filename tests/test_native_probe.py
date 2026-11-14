import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import agent, native_probe, proc_scanner, socket_collector


class NativeProbeUnitTests(unittest.TestCase):
    def test_probe_binary_path_default_and_override(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NARWHAL_NATIVE_PROBE_PATH", None)
            default_path = native_probe.probe_binary_path()
            self.assertEqual(default_path.name, "narwhal-probe")
            self.assertEqual(default_path.parent.name, "bin")

        with mock.patch.dict(os.environ, {"NARWHAL_NATIVE_PROBE_PATH": "/opt/bin/custom-probe"}):
            self.assertEqual(native_probe.probe_binary_path(), Path("/opt/bin/custom-probe"))

    def test_is_available_checks_posix_env_and_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bin_path = Path(tmpdir) / "narwhal-probe"
            bin_path.write_text("#!/bin/sh\n", encoding="utf-8")
            missing_path = Path(tmpdir) / "missing"

            with mock.patch.dict(os.environ, {"NARWHAL_NATIVE_PROBE": "1"}):
                with mock.patch.object(native_probe, "probe_binary_path", return_value=bin_path):
                    with mock.patch.object(native_probe.os, "name", "nt"):
                        self.assertFalse(native_probe.is_available())

                    with mock.patch.object(native_probe.os, "name", "posix"):
                        with mock.patch.object(native_probe.os, "access", return_value=False):
                            self.assertFalse(native_probe.is_available())
                        with mock.patch.object(native_probe.os, "access", return_value=True):
                            self.assertTrue(native_probe.is_available())

                    with mock.patch.dict(os.environ, {"NARWHAL_NATIVE_PROBE": "0"}):
                        with mock.patch.object(native_probe.os, "name", "posix"):
                            with mock.patch.object(native_probe.os, "access", return_value=True):
                                self.assertFalse(native_probe.is_available())

                with mock.patch.object(native_probe, "probe_binary_path", return_value=missing_path):
                    with mock.patch.object(native_probe.os, "name", "posix"):
                        self.assertFalse(native_probe.is_available())

    def test_run_probe_handles_success_errors_timeouts_and_oversized_stdout(self):
        ok_proc = subprocess.CompletedProcess(
            args=["narwhal-probe", "--version"],
            returncode=0,
            stdout=b'{"probe":"narwhal-probe","version":"0.1.0"}',
        )
        with mock.patch.object(native_probe.subprocess, "run", return_value=ok_proc) as run_mock:
            res = native_probe.run_probe(["--version"], timeout=2.5)
            self.assertEqual(res, {"probe": "narwhal-probe", "version": "0.1.0"})
            _, kwargs = run_mock.call_args
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 2.5)

        bad_exit = subprocess.CompletedProcess(args=[], returncode=1, stdout=b'{"ok":true}')
        with mock.patch.object(native_probe.subprocess, "run", return_value=bad_exit):
            self.assertIsNone(native_probe.run_probe(["--version"]))

        bad_json = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"not-json")
        with mock.patch.object(native_probe.subprocess, "run", return_value=bad_json):
            self.assertIsNone(native_probe.run_probe(["--version"]))

        non_dict = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"[1,2,3]")
        with mock.patch.object(native_probe.subprocess, "run", return_value=non_dict):
            self.assertIsNone(native_probe.run_probe(["--version"]))

        huge = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"x" * (native_probe.MAX_STDOUT_BYTES + 1)
        )
        with mock.patch.object(native_probe.subprocess, "run", return_value=huge):
            self.assertIsNone(native_probe.run_probe(["--version"]))

        with mock.patch.object(
            native_probe.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)
        ):
            self.assertIsNone(native_probe.run_probe(["--version"]))

        with mock.patch.object(native_probe.subprocess, "run", side_effect=OSError("no such file")):
            self.assertIsNone(native_probe.run_probe(["--version"]))

    def test_wrapper_cli_flags(self):
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "run_probe", return_value={"available": True}
        ) as run_mock:
            native_probe.proc_snapshot(123, scan_limit=5000, clock_ticks=100.0)
            native_probe.socket_sec(456)
            native_probe.conntrack(limit=1000)

        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            ["proc-snapshot", "--init-pid", "123", "--scan-limit", "5000", "--clock-ticks", "100.0"],
        )
        self.assertEqual(run_mock.call_args_list[1].args[0], ["socket-sec", "--pid", "456"])
        self.assertEqual(run_mock.call_args_list[2].args[0], ["conntrack", "--limit", "1000"])

        with mock.patch.object(native_probe, "is_available", return_value=False):
            self.assertIsNone(native_probe.proc_snapshot(123))
            self.assertIsNone(native_probe.socket_sec(456))
            self.assertIsNone(native_probe.conntrack(1000))


class ProcScannerNativeBridgeTests(unittest.TestCase):
    def setUp(self):
        agent._proc_cpu_counters.clear()
        proc_scanner._proc_cpu_counters.clear()

    def test_proc_snapshot_native_delta_cpu_redaction_and_tick_cache(self):
        sample_1 = {
            "available": True,
            "proc_scan_complete": True,
            "status_scan_complete": True,
            "uptime": 100.0,
            "clock_ticks": 100.0,
            "items": [
                {
                    "host_pid": 500,
                    "pid": 1,
                    "ppid": 1,
                    "user": "0",
                    "state": "S",
                    "cpu_seconds": 1.0,
                    "lifetime_cpu_percent": 1.0,
                    "rss_bytes": 1024 * 1024,
                    "process": "init",
                    "command": "/sbin/init",
                    "start_ticks": "10",
                },
                {
                    "host_pid": 501,
                    "pid": 15,
                    "ppid": 500,
                    "user": "0",
                    "state": "R",
                    "cpu_seconds": 2.0,
                    "lifetime_cpu_percent": 2.0,
                    "rss_bytes": 8 * 1024 * 1024,
                    "process": "xray",
                    "command": "xray --token=supersecret123 -c /etc/xray.json",
                    "start_ticks": "20",
                },
            ],
        }
        sample_2 = {
            **sample_1,
            "uptime": 110.0,
            "items": [
                {**sample_1["items"][0], "cpu_seconds": 1.0},
                {**sample_1["items"][1], "cpu_seconds": 10.0, "lifetime_cpu_percent": 9.0},
            ],
        }

        with mock.patch.object(proc_scanner.os.path, "isdir", return_value=True), mock.patch.object(
            native_probe, "is_available", return_value=True
        ), mock.patch.object(native_probe, "proc_snapshot", side_effect=[sample_1, sample_2]):
            with proc_scanner._collection_tick_scope():
                res1, priv1 = agent._collect_host_proc_process_snapshot(500, 20)
                # Cached within same tick scope
                res1_cached, _ = agent._collect_host_proc_process_snapshot(500, 20)
                self.assertEqual(res1_cached, res1)

            self.assertTrue(res1["available"])
            self.assertEqual(res1["source"], "host_proc")
            self.assertTrue(res1["scope_complete"])
            self.assertEqual(res1["captured"], 2)
            self.assertFalse(res1["truncated"])
            self.assertEqual(priv1[0]["pid"], 15)
            self.assertEqual(priv1[0]["ppid"], 1)
            self.assertNotIn("supersecret123", priv1[0]["command"])
            self.assertIn("REDACTED", priv1[0]["command"])

            # Second tick: 8.0 cpu_seconds over 10.0s dt => 80.0% delta CPU
            res2, priv2 = agent._collect_host_proc_process_snapshot(500, 20)
            self.assertAlmostEqual(priv2[0]["cpu_percent"], 80.0, places=2)
            self.assertEqual(res2["items"][0]["pid"], 15)

    def test_proc_snapshot_falls_back_to_python_on_probe_failure(self):
        fake_tree = {
            "parent_map": {100: 1},
            "children_map": {100: []},
            "status_map": {100: "Name:\tinit\nState:\tS\nPPid:\t1\nNSpid:\t100\t1\nUid:\t0\nVmRSS:\t512 kB\n"},
            "proc_scan_complete": True,
            "status_scan_complete": True,
            "uptime": 100.0,
            "clock_ticks": 100.0,
        }
        with mock.patch.object(proc_scanner.os.path, "isdir", return_value=True), mock.patch.object(
            native_probe, "is_available", return_value=True
        ), mock.patch.object(native_probe, "proc_snapshot", return_value=None) as probe_mock, mock.patch.object(
            proc_scanner, "_has_mocked_proc_primitives", return_value=False
        ), mock.patch.object(
            agent, "_scan_host_proc_tree", return_value=fake_tree
        ) as scan_mock, mock.patch.object(
            agent, "_read_host_proc_text", return_value="init\n"
        ):
            res, priv = agent._collect_host_proc_process_snapshot(100, 20)
        probe_mock.assert_called_once()
        scan_mock.assert_called_once()
        self.assertTrue(res["available"])
        self.assertEqual(priv[0]["pid"], 1)

    def test_proc_snapshot_bypasses_native_when_os_listdir_mocked(self):
        with mock.patch.object(proc_scanner.os.path, "isdir", return_value=True), mock.patch.object(
            proc_scanner.os, "listdir", return_value=[]
        ), mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "proc_snapshot"
        ) as probe_mock:
            res, _ = agent._collect_host_proc_process_snapshot(100, 20)
        probe_mock.assert_not_called()
        self.assertTrue(res["available"] in (True, False))


class SocketCollectorNativeBridgeTests(unittest.TestCase):
    def test_socket_security_consumes_native_probe_and_falls_back(self):
        native_payload = {
            "available": True,
            "read_files": 4,
            "malformed": False,
            "tcp_entries": [
                {
                    "proto": "tcp",
                    "local_ip": "10.0.0.2",
                    "local_port": 443,
                    "remote_ip": "0.0.0.0",
                    "remote_port": 0,
                    "state_hex": "0A",
                    "inode": 1001,
                },
                {
                    "proto": "tcp",
                    "local_ip": "10.0.0.2",
                    "local_port": 443,
                    "remote_ip": "8.8.8.8",
                    "remote_port": 51234,
                    "state_hex": "01",
                    "inode": 1002,
                },
                {
                    "proto": "tcp",
                    "local_ip": "10.0.0.2",
                    "local_port": 41000,
                    "remote_ip": "1.1.1.1",
                    "remote_port": 80,
                    "state_hex": "06",
                    "inode": 1003,
                },
                {
                    "proto": "tcp",
                    "local_ip": "10.0.0.2",
                    "local_port": 42000,
                    "remote_ip": "1.1.1.1",
                    "remote_port": 443,
                    "state_hex": "01",
                    "inode": 1005,
                },
            ],
            "udp_entries": [
                {
                    "proto": "udp",
                    "local_ip": "10.0.0.2",
                    "local_port": 5353,
                    "remote_ip": "0.0.0.0",
                    "remote_port": 0,
                    "state_hex": "07",
                    "inode": 1004,
                }
            ],
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "socket_sec", return_value=native_payload
        ), mock.patch.object(agent, "_connection_metric_epoch", return_value="epoch-1"):
            sec = agent._collect_socket_security(321)

        cm = sec["connection_metrics"]
        self.assertTrue(cm["valid"])
        self.assertEqual(cm["total"], 5)
        self.assertEqual(cm["tcp_established"], 2)
        self.assertEqual(cm["tcp_time_wait"], 1)
        self.assertEqual(cm["udp_sockets"], 1)
        self.assertEqual(sec["listening_ports"], [443])
        self.assertEqual(sec["udp_listening_ports"], [5353])
        self.assertEqual(sec["inbound_unique_ips"], 1)
        self.assertEqual(sec["outbound_unique_ips"], 1)

        # Fallback to Python when probe returns None (deterministic even if PID exists on Linux)
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "socket_sec", return_value=None
        ), mock.patch.object(agent, "_connection_metric_epoch", return_value="epoch-1"), mock.patch(
            "builtins.open", side_effect=FileNotFoundError("/proc/321/net/tcp")
        ):
            sec_fallback = agent._collect_socket_security(321)
        self.assertFalse(sec_fallback["connection_metrics"]["valid"])

    def test_conntrack_consumes_native_probe_and_falls_back(self):
        native_ct = {
            "available": True,
            "entries": [
                {
                    "proto": "tcp",
                    "state": "ESTABLISHED",
                    "src": "8.8.4.4",
                    "dst": "9.9.9.9",
                    "sport": 50000,
                    "dport": 18443,
                    "reply_src": "10.91.0.5",
                    "reply_dst": "8.8.4.4",
                    "reply_sport": 443,
                    "reply_dport": 50000,
                    "unreplied": False,
                    "original_packets": 12,
                    "reply_packets": 9,
                }
            ],
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "conntrack", return_value=native_ct
        ), mock.patch.object(agent, "run", side_effect=["[]", ""]):
            snap = socket_collector._collect_host_conntrack_snapshot()

        self.assertTrue(snap["available"])
        self.assertEqual(snap["snapshot_count"], 1)
        self.assertFalse(snap["snapshot_truncated"])
        self.assertEqual(len(snap["entries"]), 1)
        entry = snap["entries"][0]
        self.assertEqual(entry["proto"], "tcp")
        self.assertEqual(entry["tcp_state"], "ESTABLISHED")
        self.assertEqual(entry["original_src"], "8.8.4.4")
        self.assertEqual(entry["reply_src"], "10.91.0.5")
        self.assertEqual(entry["original_packets"], 12)

        # Fallback when probe returns None
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "conntrack", return_value=None
        ), mock.patch.object(agent, "run", return_value=""):
            snap_fallback = socket_collector._collect_host_conntrack_snapshot()
        self.assertIsInstance(snap_fallback["entries"], list)


class CpuGuardNativeBridgeTests(unittest.TestCase):
    def test_psi_snapshot_and_cgroup_metrics_cli_args(self):
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "run_probe", return_value={"available": True}
        ) as run_mock:
            res1 = native_probe.psi_snapshot(cgroup_dir="/sys/fs/cgroup/c1", proc_root="/proc")
            res2 = native_probe.cgroup_metrics("/sys/fs/cgroup/c1")
        self.assertEqual(res1, {"available": True})
        self.assertEqual(res2, {"available": True})
        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            ["psi-snapshot", "--proc-root", "/proc", "--cgroup-dir", "/sys/fs/cgroup/c1"],
        )
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["cgroup-metrics", "--cgroup-dir", "/sys/fs/cgroup/c1"],
        )

    def test_sample_host_cpu_uses_native_probe_and_falls_back(self):
        from client import cpu_guard

        tick1 = {
            "available": True,
            "host_psi": {
                "cpu": {"status": "ready", "some": {"avg10": 6.5}},
                "memory": {"status": "unavailable", "reason": "FileNotFoundError"},
                "io": {"status": "unsupported"},
            },
            "host_cpu": {"available": True, "total": 1000, "busy": 200, "iowait": 50},
        }
        tick2 = {
            "available": True,
            "host_psi": tick1["host_psi"],
            "host_cpu": {"available": True, "total": 2000, "busy": 700, "iowait": 150},
        }
        orig_prev = cpu_guard._host_cpu_previous
        cpu_guard._host_cpu_previous = None
        try:
            with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
                native_probe, "psi_snapshot", side_effect=[tick1, tick2]
            ), mock.patch.object(cpu_guard.time, "monotonic", side_effect=[100.0, 105.0]):
                first = cpu_guard.sample_host_cpu()
                second = cpu_guard.sample_host_cpu()
            self.assertEqual(first["status"], "warming")
            self.assertEqual(second["status"], "ready")
            self.assertTrue(second["available"])
            self.assertEqual(second["busy_percent"], 50.0)
            self.assertEqual(second["iowait_percent"], 10.0)
            self.assertEqual(second["psi"]["cpu"]["some"]["avg10"], 6.5)
            self.assertIn("reason", second["psi"]["io"])

            # Fallback when probe returns None
            cpu_guard._host_cpu_previous = None
            with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
                native_probe, "psi_snapshot", return_value=None
            ), mock.patch("builtins.open", side_effect=FileNotFoundError("/proc/stat")):
                fallback = cpu_guard.sample_host_cpu()
            self.assertFalse(fallback["available"])
            self.assertEqual(fallback["status"], "unavailable")
        finally:
            cpu_guard._host_cpu_previous = orig_prev

    def test_container_psi_uses_native_probe(self):
        from pathlib import Path
        from client import cpu_guard

        payload = {
            "available": True,
            "cgroup_psi": {
                "cpu": {"status": "ready", "some": {"avg10": 11.0}},
                "memory": {"status": "ready", "some": {"avg10": 1.0}},
                "io": {"status": "unavailable", "reason": "FileNotFoundError"},
            },
        }
        with mock.patch.object(
            cpu_guard, "resolve_container_cgroup", return_value=(Path("/sys/fs/cgroup/test"), "")
        ), mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "psi_snapshot", return_value=payload
        ):
            res = cpu_guard._container_psi({"pid": 123, "runtime": "incus", "id": "c1"})
        self.assertEqual(res["status"], "partial")
        self.assertEqual(res["cpu"]["some"]["avg10"], 11.0)


class ProcSocketsAndHostMetricsNativeBridgeTests(unittest.TestCase):
    def test_proc_sockets_and_host_metrics_cli_args(self):
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "run_probe", return_value={"available": True}
        ) as run_mock:
            res1 = native_probe.proc_sockets(42, [42, 100, 0, -1], max_fds=2048)
            res2 = native_probe.host_metrics(proc_root="/proc")
        self.assertEqual(res1, {"available": True})
        self.assertEqual(res2, {"available": True})
        self.assertEqual(
            run_mock.call_args_list[0].args[0],
            ["proc-sockets", "--init-pid", "42", "--pids", "42,100", "--max-fds", "2048"],
        )
        self.assertEqual(
            run_mock.call_args_list[1].args[0],
            ["host-metrics", "--proc-root", "/proc"],
        )

        with mock.patch.object(native_probe, "is_available", return_value=True):
            self.assertIsNone(native_probe.proc_sockets(0, [42]))
            self.assertIsNone(native_probe.proc_sockets(42, []))
            self.assertIsNone(native_probe.proc_sockets(42, [0, -5]))
            self.assertIsNone(native_probe.proc_sockets(42, [42], max_fds=0))

        with mock.patch.object(native_probe, "is_available", return_value=False):
            self.assertIsNone(native_probe.proc_sockets(42, [42]))
            self.assertIsNone(native_probe.host_metrics())

    def test_host_metrics_uses_native_probe_and_falls_back(self):
        from client import host_metrics

        native_payload = {
            "available": True,
            "uptime_seconds": 1234.5,
            "load": {"available": True, "m1": 0.5, "m5": 0.4, "m15": 0.3},
            "cpu": {"available": True, "total": 1000, "busy": 200, "iowait": 50},
            "memory": {"available": True, "mem_total_bytes": 1024 * 1024},
            "net": {"available": True, "rx_bytes": 100, "tx_bytes": 50, "interfaces": []},
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "host_metrics", return_value=native_payload
        ) as probe_mock:
            res = agent.collect_host_metrics()
        probe_mock.assert_called_once()
        self.assertEqual(res, native_payload)

        # Fallback to Python when probe returns None
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "net").mkdir()
            (root / "uptime").write_text("456.78 100.0\n", encoding="utf-8")
            (root / "loadavg").write_text("0.10 0.20 0.30 1/100 123\n", encoding="utf-8")
            (root / "stat").write_text("cpu  100 0 50 800 50 0 0 0 0 0\n", encoding="utf-8")
            (root / "meminfo").write_text("MemTotal: 2048 kB\nMemAvailable: 1024 kB\n", encoding="utf-8")
            (root / "net" / "dev").write_text(
                "Inter-|   Receive\n"
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n"
                "    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"
                "  eth0: 500 5 0 0 0 0 0 0 250 2 0 0 0 0 0 0\n",
                encoding="utf-8",
            )
            with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
                native_probe, "host_metrics", return_value=None
            ):
                fallback = host_metrics.collect_host_metrics(proc_root=root)

        self.assertTrue(fallback["available"])
        self.assertAlmostEqual(fallback["uptime_seconds"], 456.78, places=2)
        self.assertEqual(fallback["load"], {"available": True, "m1": 0.10, "m5": 0.20, "m15": 0.30})
        self.assertEqual(fallback["cpu"], {"available": True, "total": 1000, "busy": 150, "iowait": 50})
        self.assertEqual(fallback["memory"]["mem_total_bytes"], 2048 * 1024)
        self.assertEqual(fallback["memory"]["mem_available_bytes"], 1024 * 1024)
        self.assertEqual(fallback["net"]["rx_bytes"], 500)
        self.assertEqual(fallback["net"]["tx_bytes"], 250)
        self.assertEqual(fallback["net"]["interfaces"], [{"name": "eth0", "rx_bytes": 500, "tx_bytes": 250}])

    def test_proc_socket_details_uses_native_probe_and_falls_back(self):
        host_processes = [
            {"host_pid": 500, "pid": 1, "process": "init"},
            {"host_pid": 501, "pid": 15, "process": "xray"},
        ]
        native_payload = {
            "available": True,
            "inode_count": 2,
            "fd_scanned": 5,
            "truncated": False,
            "sockets": [
                {
                    "pid": 501,
                    "inode": 2001,
                    "proto": "tcp",
                    "state_hex": "01",
                    "local_ip": "10.0.0.2",
                    "local_port": 443,
                    "remote_ip": "8.8.8.8",
                    "remote_port": 51234,
                },
                {
                    "pid": 501,
                    "inode": 2002,
                    "proto": "udp",
                    "state_hex": "07",
                    "local_ip": "10.0.0.2",
                    "local_port": 5353,
                    "remote_ip": "0.0.0.0",
                    "remote_port": 0,
                },
            ],
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "proc_sockets", return_value=native_payload
        ) as probe_mock:
            res = proc_scanner._collect_host_proc_socket_details(
                500, host_processes, [443], 20, process_scope_complete=True
            )
        probe_mock.assert_called_once_with(500, [500, 501], max_fds=10000)
        self.assertTrue(res["communication_detail_available"])
        self.assertEqual(res["communication_owner_attributed_count"], 1)
        self.assertEqual(len(res["communication_sockets"]), 1)
        self.assertEqual(len(res["service_listeners"]), 1)
        self.assertEqual(res["service_listeners"][0]["port"], 5353)
        self.assertEqual(res["communication_processes"][0]["process"], "xray")

        # Bypass native when os.listdir is mocked and fall back to Python path
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "proc_sockets"
        ) as probe_skip, mock.patch.object(
            proc_scanner.os, "listdir", return_value=[]
        ), mock.patch.object(agent, "_read_host_proc_text", return_value=""):
            fallback = proc_scanner._collect_host_proc_socket_details(
                500, host_processes, [443], 20, process_scope_complete=True
            )
        probe_skip.assert_not_called()
        self.assertTrue(fallback["communication_detail_available"])
        self.assertEqual(fallback["communication_sockets"], [])


class RuntimeCgroupMemoryIoNativeBridgeTests(unittest.TestCase):
    def test_diskstats_cli_args(self):
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "run_probe", return_value={"available": True, "devices": {}}
        ) as run_mock:
            res = native_probe.diskstats("/proc")
        self.assertEqual(res, {"available": True, "devices": {}})
        run_mock.assert_called_once_with(["diskstats", "--proc-root", "/proc"])

    def test_runtime_drivers_cgroup_cpu_sample_uses_native_probe(self):
        from pathlib import Path
        from client import cpu_guard, runtime_drivers

        native_cg = {
            "available": True,
            "cpu_stat": {"usage_usec": 2500000},
            "cpu_max": {"raw": "200000 100000", "quota_usec": 200000, "period_usec": 100000},
        }
        with mock.patch.object(
            cpu_guard, "resolve_container_cgroup", return_value=(Path("/sys/fs/cgroup/test"), "")
        ), mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "cgroup_metrics", return_value=native_cg
        ), mock.patch.object(agent, "_derive_cpu_percent", return_value=42.5):
            sample = runtime_drivers._sample_cgroup_cpu_metrics(123, "podman", "abc123", "c1")
        self.assertTrue(sample["available"])
        self.assertEqual(sample["usage_usec"], 2500000)
        self.assertEqual(sample["quota_cpus"], 2.0)
        self.assertEqual(sample["cpu_percent"], 42.5)

    def test_memory_guard_read_pressure_uses_native_probe(self):
        from pathlib import Path
        from client import memory_guard

        host_payload = {
            "available": True,
            "host_psi": {"memory": {"status": "ready", "some": {"avg10": 7.5}}},
        }
        cg_payload = {
            "available": True,
            "cgroup_psi": {"memory": {"status": "ready", "some": {"avg10": 12.0}}},
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "psi_snapshot", side_effect=[host_payload, cg_payload]
        ):
            host_res = memory_guard._read_pressure(Path("/proc/pressure/memory"))
            cg_res = memory_guard._read_pressure(Path("/sys/fs/cgroup/c1/memory.pressure"))
        self.assertEqual(host_res["status"], "ready")
        self.assertEqual(host_res["some"]["avg10"], 7.5)
        self.assertEqual(cg_res["status"], "ready")
        self.assertEqual(cg_res["some"]["avg10"], 12.0)

    def test_io_guard_diskstats_and_io_stat_use_native_probe(self):
        from pathlib import Path
        from client import io_guard

        disk_payload = {
            "available": True,
            "devices": {
                "8:0": {"rios": 10, "rsectors": 80, "wios": 20, "wsectors": 160, "busy_ms": 50}
            },
        }
        cg_payload = {
            "available": True,
            "io": {
                "available": True,
                "devices": [
                    {"dev": "8:0", "rbytes": 4096, "wbytes": 8192, "rios": 4, "wios": 8}
                ],
            },
        }
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "diskstats", return_value=disk_payload
        ), mock.patch.object(native_probe, "cgroup_metrics", return_value=cg_payload):
            disks = io_guard._parse_diskstats()
            cg_io = io_guard._parse_io_stat(Path("/sys/fs/cgroup/c1"))
        self.assertEqual(disks["8:0"]["busy_ms"], 50)
        self.assertEqual(cg_io["8:0"]["rbytes"], 4096)
        self.assertEqual(cg_io["8:0"]["wios"], 8)


class PersistentServePipeTests(unittest.TestCase):
    def tearDown(self):
        native_probe.close_serve_process()

    def test_run_probe_reuses_persistent_serve_pipe(self):
        import io

        class _FakeStdout:
            def fileno(self):
                return 99

            def close(self):
                pass

        fake_proc = mock.MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.stdin = io.BytesIO()
        fake_proc.stdout = _FakeStdout()

        with mock.patch.object(native_probe.os, "name", "posix"), mock.patch.object(
            native_probe, "probe_binary_path", return_value="/tmp/narwhal-probe"
        ), mock.patch.dict(
            native_probe.os.environ, {"NARWHAL_NATIVE_PROBE_SERVE": "1"}, clear=False
        ), mock.patch.object(
            native_probe.subprocess, "Popen", return_value=fake_proc
        ) as popen_mock, mock.patch.object(
            native_probe.select, "select", return_value=([99], [], [])
        ), mock.patch.object(
            native_probe.os,
            "read",
            side_effect=[b'{"ok":true,"n":1}\n', b'{"ok":true,"n":2}\n'],
        ):
            r1 = native_probe.run_probe(["version"])
            r2 = native_probe.run_probe(["host-metrics", "--proc-root", "/proc"])

        self.assertEqual(popen_mock.call_count, 1)
        self.assertEqual(r1, {"ok": True, "n": 1})
        self.assertEqual(r2, {"ok": True, "n": 2})
        self.assertEqual(
            fake_proc.stdin.getvalue(),
            b"version\nhost-metrics\t--proc-root\t/proc\n",
        )

    def test_serve_bypassed_when_disabled_or_subprocess_run_mocked(self):
        fake_completed = mock.Mock(returncode=0, stdout=b'{"ok":true,"mode":"oneshot"}')
        with mock.patch.object(native_probe.os, "name", "posix"), mock.patch.object(
            native_probe, "probe_binary_path", return_value="/tmp/narwhal-probe"
        ), mock.patch.dict(
            native_probe.os.environ, {"NARWHAL_NATIVE_PROBE_SERVE": "0"}, clear=False
        ), mock.patch.object(native_probe, "_run_via_serve") as serve_mock, mock.patch.object(
            native_probe.subprocess, "run", return_value=fake_completed
        ) as run_mock:
            res = native_probe.run_probe(["version"])
        serve_mock.assert_not_called()
        run_mock.assert_called_once()
        self.assertEqual(res, {"ok": True, "mode": "oneshot"})

    def test_serve_falls_back_to_oneshot_on_broken_pipe_or_bad_json(self):
        class _FakeStdout:
            def fileno(self):
                return 99

            def close(self):
                pass

        bad_proc = mock.MagicMock()
        bad_proc.poll.return_value = None
        bad_proc.stdin = mock.MagicMock()
        bad_proc.stdout = _FakeStdout()
        fake_completed = mock.Mock(returncode=0, stdout=b'{"ok":true,"fallback":true}')

        with mock.patch.object(native_probe.os, "name", "posix"), mock.patch.object(
            native_probe, "probe_binary_path", return_value="/tmp/narwhal-probe"
        ), mock.patch.object(
            native_probe.subprocess, "Popen", return_value=bad_proc
        ), mock.patch.object(
            native_probe.select, "select", return_value=([99], [], [])
        ), mock.patch.object(
            native_probe.os, "read", return_value=b"not-json\n"
        ), mock.patch.object(
            native_probe.subprocess, "run", return_value=fake_completed
        ) as run_mock, mock.patch.object(
            native_probe, "_ORIG_SUBPROCESS_RUN", run_mock
        ):
            res = native_probe.run_probe(["version"])

        self.assertEqual(res, {"ok": True, "fallback": True})
        self.assertIsNone(native_probe._serve_proc)
        run_mock.assert_called_once()


class GeoipProbeBridgeTests(unittest.TestCase):
    def test_geoip_country_batch_cli_args(self):
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "run_probe", return_value={"available": True, "countries": {"1.1.1.1": "AU"}}
        ) as run_mock:
            res = native_probe.geoip_country_batch("/tmp/db.mmdb", ["1.1.1.1", " ", "8.8.8.8"])
        self.assertEqual(res["countries"]["1.1.1.1"], "AU")
        run_mock.assert_called_once_with(
            ["geoip-lookup", "--db", "/tmp/db.mmdb", "--ips", "1.1.1.1,8.8.8.8"]
        )

    def test_geoip_enricher_uses_native_probe_and_falls_back(self):
        from client import geoip_enricher

        with mock.patch.dict(
            geoip_enricher.os.environ, {"GEOIP_MMDB_PATH": "/tmp/GeoLite2-Country.mmdb"}, clear=False
        ), mock.patch.object(geoip_enricher.os.path, "isfile", return_value=True), mock.patch.object(
            native_probe, "is_available", return_value=True
        ), mock.patch.object(
            native_probe,
            "geoip_country_batch",
            return_value={"available": True, "countries": {"1.1.1.1": "au", "8.8.8.8": "US"}},
        ):
            res = geoip_enricher._geoip_local_country_batch(["1.1.1.1", "8.8.8.8"])
        self.assertEqual(res, {"1.1.1.1": "AU", "8.8.8.8": "US"})

        fake_reader = mock.MagicMock()
        fake_reader.get.return_value = {"country": {"iso_code": "jp"}}
        fake_mmdb = mock.MagicMock()
        fake_mmdb.open_database.return_value = fake_reader
        old_reader = geoip_enricher._geoip_reader
        old_path = geoip_enricher._geoip_reader_path
        try:
            with mock.patch.dict(
                geoip_enricher.os.environ, {"GEOIP_MMDB_PATH": "/tmp/GeoLite2-Country.mmdb"}, clear=False
            ), mock.patch.object(
                geoip_enricher.os.path, "isfile", return_value=True
            ), mock.patch.object(
                geoip_enricher, "maxminddb", fake_mmdb
            ), mock.patch.object(
                native_probe, "is_available", return_value=True
            ), mock.patch.object(
                native_probe, "geoip_country_batch"
            ) as probe_mock:
                fb = geoip_enricher._geoip_local_country_batch(["1.2.3.4"])
            probe_mock.assert_not_called()
            self.assertEqual(fb, {"1.2.3.4": "JP"})
        finally:
            geoip_enricher._geoip_reader = old_reader
            geoip_enricher._geoip_reader_path = old_path


if __name__ == "__main__":
    unittest.main()
