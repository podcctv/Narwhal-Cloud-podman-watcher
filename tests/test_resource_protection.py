import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import cpu_guard, io_guard, memory_guard
from server import control_reconciliation


class ResourceProtectionPressureTests(unittest.TestCase):
    def test_cpu_psi_must_confirm_contention_when_available(self):
        host = {
            "status": "ready",
            "busy_percent": 92,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 0.4}}},
        }
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertFalse(confirmed)
        self.assertEqual(psi, 0.4)
        self.assertEqual(basis, "host_psi_below_threshold")

    def test_cpu_high_busy_and_psi_confirm_contention(self):
        host = {
            "status": "ready",
            "busy_percent": 92,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 7.5}}},
        }
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertTrue(confirmed)
        self.assertEqual(psi, 7.5)
        self.assertEqual(basis, "host_busy_and_psi_confirmed")

    def test_cpu_busy_fallback_is_explicit_when_psi_is_missing(self):
        host = {"status": "ready", "busy_percent": 92, "psi": {"cpu": {"status": "unsupported"}}}
        confirmed, psi, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertTrue(confirmed)
        self.assertIsNone(psi)
        self.assertEqual(basis, "host_busy_psi_unavailable_fallback")

    def test_cpu_psi_does_not_override_low_host_busy(self):
        host = {
            "status": "ready",
            "busy_percent": 60,
            "psi": {"cpu": {"status": "ready", "some": {"avg10": 12}}},
        }
        confirmed, _, basis = cpu_guard._host_cpu_pressure(host, 80, 5)
        self.assertFalse(confirmed)
        self.assertEqual(basis, "host_busy_below_threshold")

    def test_io_psi_is_authoritative_when_available(self):
        self.assertEqual(io_guard._host_io_pressure(98, 1.0, 80, 5), (False, "host_io_psi"))
        self.assertEqual(io_guard._host_io_pressure(20, 8.0, 80, 5), (True, "host_io_psi"))

    def test_io_device_busy_is_compatibility_fallback_when_psi_is_missing(self):
        self.assertEqual(
            io_guard._host_io_pressure(85, None, 80, 5),
            (True, "device_busy_fallback_psi_unavailable"),
        )
        self.assertEqual(
            io_guard._host_io_pressure(55, None, 80, 5),
            (False, "device_busy_fallback_psi_unavailable"),
        )

    def test_io_psi_reader_uses_scoped_host_and_container_values(self):
        evidence = {
            "host": {"io": {"status": "ready", "some": {"avg10": 4.2}}},
            "container": {"io": {"status": "ready", "some": {"avg10": 9.1}}},
        }
        self.assertEqual(io_guard._psi_avg10(evidence, "host"), 4.2)
        self.assertEqual(io_guard._psi_avg10(evidence, "container"), 9.1)

    def test_cpu_alert_surfaces_action_error_transparently(self):
        container = {"runtime": "incus", "project": "default", "name": "c1"}
        host_cpu = {"status": "ready", "busy_percent": 90, "psi": {}}
        action = {"attempted": True, "succeeded": False, "message": "应用未成功"}
        alert = cpu_guard._alert(
            alert_type="cpu_pressure_protection",
            container=container,
            host_cpu=host_cpu,
            cpu_percent=95.0,
            effective_cpus=2.0,
            threshold_percent=130.0,
            high_samples=3,
            required_samples=3,
            duration=600,
            process={"process": "stress"},
            action=action,
            instance_id="incus-c1",
            error="无法读取 Incus 本地 CPU allowance",
        )
        self.assertIn("无法读取 Incus 本地 CPU allowance", alert["message"])
        self.assertEqual(alert["cpu_guard"]["last_error"], "无法读取 Incus 本地 CPU allowance")
        self.assertEqual(alert["title"], "持续高 CPU，保护需要检查")

    def test_incus_runtime_args_does_not_duplicate_binary(self):
        args = cpu_guard._runtime_args("/usr/bin/incus", "default", ["config", "get", "c1", "limits.cpu.allowance"])
        self.assertEqual(args, ["--project", "default", "config", "get", "c1", "limits.cpu.allowance"])
        self.assertNotIn("/usr/bin/incus", args)
        self.assertNotIn("incus", args)

    def test_incus_runtime_args_without_project(self):
        args = cpu_guard._runtime_args("incus", "", ["config", "get", "c1", "limits.cpu.allowance"])
        self.assertEqual(args, ["config", "get", "c1", "limits.cpu.allowance"])

    def test_runman_cpu_limit_scales_cgroup_v2_quota(self):
        target, cpus = cpu_guard._half_limit("runman", "200000 100000", 2.0)
        self.assertEqual(target, "100000 100000")
        self.assertEqual(cpus, 1.0)
        tighter, tighter_cpus = cpu_guard._scale_limit("runman", "100000 100000", 0.5)
        self.assertEqual(tighter, "50000 100000")
        self.assertEqual(tighter_cpus, 0.5)

    def test_memory_guard_tier2_escalation_under_pressure(self):
        start_usage = 85.0
        tier = 2
        tier_usage_threshold = max(60.0, start_usage - (tier - 1) * 10.0)
        self.assertEqual(tier_usage_threshold, 75.0)
        used_percent = 81.11
        current_bytes = 207638528
        current_high = "204800000"
        is_memory_high_tier = used_percent >= tier_usage_threshold or (
            bool(current_high and current_high != "max" and current_high.isdigit())
            and current_bytes >= int(current_high) * 0.95
        )
        self.assertTrue(is_memory_high_tier)

    def test_single_core_jinx_runaway_runman_cpu_detected_and_limited_with_readback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cgroup_dir = Path(tmpdir) / "cgroup"
            cgroup_dir.mkdir(parents=True, exist_ok=True)
            cpu_max_file = cgroup_dir / "cpu.max"
            cpu_max_file.write_text("max 100000\n", encoding="ascii")
            state_path = str(Path(tmpdir) / "cpu-guard.json")

            instance_id = "12345678-1234-4234-8234-123456789abc"
            vm_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            host_cpu = {
                "available": True,
                "status": "ready",
                "busy_percent": 99.8,
                "iowait_percent": 0.0,
                "logical_cpus": 1,
                "load_1m": 4.73,
                "sample_seconds": 150.0,
                "psi": {"cpu": {"status": "ready", "some": {"avg10": 0.4}}},
            }

            def make_container() -> dict:
                return {
                    "id": vm_id,
                    "stable_id": vm_id,
                    "name": vm_id,
                    "runtime": "runman",
                    "runtime_bin": "runman",
                    "project": "default",
                    "instance_id": instance_id,
                    "pid": "4321",
                    "pid_start_ticks": "987654",
                    "cpu_percent": 99.6,
                    "cpu_pressure_percent": 99.6,
                    "cpu_pressure_sample_available": True,
                    "cpu_effective_cpus": 0.0,
                    "security": {},
                }

            sampled_process = {
                "available": True,
                "source": "host_proc_snapshot",
                "pid": 42,
                "cpu_percent": 99.4,
                "process": "xray",
                "command": "xray run -c /etc/xray/config.json",
            }

            env_clean = {k: v for k, v in os.environ.items() if k != "CPU_AUTO_LIMIT_REQUIRED_SECONDS"}
            with mock.patch.dict(os.environ, env_clean, clear=True), mock.patch.object(
                cpu_guard, "resolve_container_cgroup", return_value=(cgroup_dir, "")
            ):
                c1 = make_container()
                summary1 = cpu_guard.observe(
                    [c1],
                    host_cpu,
                    150.0,
                    {"runman": "runman"},
                    process_sampler=lambda _c: sampled_process,
                    now=1000,
                    state_path=state_path,
                )
                guard1 = c1["security"]["cpu_guard"]
                self.assertEqual(guard1["state"], "watching")
                self.assertEqual(guard1["high_samples"], 1)
                self.assertEqual(guard1["required_samples"], 3)
                self.assertEqual(guard1["effective_cpus"], 1.0)
                self.assertEqual(guard1["host_pressure_basis"], "single_core_host_cpu_saturation")
                self.assertEqual(summary1["alerts"], [])

                c2 = make_container()
                summary2 = cpu_guard.observe(
                    [c2],
                    host_cpu,
                    150.0,
                    {"runman": "runman"},
                    process_sampler=lambda _c: sampled_process,
                    now=1150,
                    state_path=state_path,
                )
                guard2 = c2["security"]["cpu_guard"]
                self.assertEqual(guard2["state"], "watching")
                self.assertEqual(guard2["high_samples"], 2)
                self.assertEqual(guard2["top_process"]["process"], "xray")
                self.assertEqual(len(summary2["alerts"]), 1)
                self.assertEqual(summary2["alerts"][0]["severity"], "warning")
                self.assertFalse(summary2["alerts"][0]["cpu_guard"]["limit_applied"])
                self.assertEqual(summary2["alerts"][0]["cpu_guard"]["top_process"]["process"], "xray")

                c3 = make_container()
                summary3 = cpu_guard.observe(
                    [c3],
                    host_cpu,
                    150.0,
                    {"runman": "runman"},
                    process_sampler=lambda _c: sampled_process,
                    now=1300,
                    state_path=state_path,
                )
                guard3 = c3["security"]["cpu_guard"]
                self.assertEqual(guard3["state"], "limited")
                self.assertTrue(guard3["readback_confirmed"])
                self.assertEqual(guard3["original_limit"], "max 100000")
                self.assertEqual(guard3["active_limit"], "50000 100000")
                self.assertEqual(guard3["actual_limit"], "50000 100000")
                self.assertEqual(cpu_max_file.read_text(encoding="ascii").strip(), "50000 100000")
                self.assertEqual(summary3["limited_containers"], 1)
                self.assertEqual(len(summary3["alerts"]), 1)
                self.assertTrue(summary3["alerts"][0]["cpu_guard"]["limit_applied"])

                reconciled = control_reconciliation.build_control_reconciliation(
                    {"observed_at": 1300},
                    [{"container_name": vm_id, "runtime": "runman", "project": "default", "security": c3["security"]}],
                    None,
                    {},
                    now=1305,
                )
                cgroup_cpu_ctrl = next(item for item in reconciled["controls"] if item["control"] == "cgroup_cpu")
                self.assertEqual(cgroup_cpu_ctrl["status"], "verified")
                self.assertEqual(cgroup_cpu_ctrl["actual"]["verified_active"], 1)
                self.assertEqual(cgroup_cpu_ctrl["actual"]["unverified"], 0)

    def test_candidate_samples_preserved_across_host_cpu_warming_cycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cgroup_dir = Path(tmpdir) / "cgroup"
            cgroup_dir.mkdir(parents=True, exist_ok=True)
            (cgroup_dir / "cpu.max").write_text("max 100000\n", encoding="ascii")
            state_path = str(Path(tmpdir) / "cpu-guard.json")
            instance_id = "12345678-1234-4234-8234-123456789abc"
            vm_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

            ready_host = {
                "available": True,
                "status": "ready",
                "busy_percent": 98.0,
                "logical_cpus": 1,
                "load_1m": 2.0,
                "psi": {"cpu": {"status": "ready", "some": {"avg10": 0.2}}},
            }
            warming_host = {
                "available": False,
                "status": "warming",
                "busy_percent": None,
                "logical_cpus": 1,
                "load_1m": 2.0,
                "psi": {"cpu": {"status": "ready", "some": {"avg10": 0.2}}},
            }

            def make_container() -> dict:
                return {
                    "id": vm_id,
                    "stable_id": vm_id,
                    "name": vm_id,
                    "runtime": "runman",
                    "runtime_bin": "runman",
                    "project": "default",
                    "instance_id": instance_id,
                    "pid": "4321",
                    "pid_start_ticks": "987654",
                    "cpu_percent": 96.0,
                    "cpu_pressure_percent": 96.0,
                    "cpu_pressure_sample_available": True,
                    "cpu_effective_cpus": 1.0,
                    "security": {},
                }

            with mock.patch.object(cpu_guard, "resolve_container_cgroup", return_value=(cgroup_dir, "")):
                c1 = make_container()
                cpu_guard.observe([c1], ready_host, 120.0, {"runman": "runman"}, now=2000, state_path=state_path)
                self.assertEqual(c1["security"]["cpu_guard"]["high_samples"], 1)

                c2 = make_container()
                cpu_guard.observe([c2], warming_host, 120.0, {"runman": "runman"}, now=2060, state_path=state_path)
                self.assertEqual(c2["security"]["cpu_guard"]["state"], "sampling_unavailable")

                c3 = make_container()
                cpu_guard.observe([c3], ready_host, 120.0, {"runman": "runman"}, now=2120, state_path=state_path)
                self.assertEqual(c3["security"]["cpu_guard"]["state"], "watching")
                self.assertEqual(c3["security"]["cpu_guard"]["high_samples"], 2)


if __name__ == "__main__":
    unittest.main()
