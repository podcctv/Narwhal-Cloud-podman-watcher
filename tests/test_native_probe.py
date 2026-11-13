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

        # Fallback to Python when probe returns None
        with mock.patch.object(native_probe, "is_available", return_value=True), mock.patch.object(
            native_probe, "socket_sec", return_value=None
        ), mock.patch.object(agent, "_connection_metric_epoch", return_value="epoch-1"):
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


if __name__ == "__main__":
    unittest.main()
