import unittest

from server.control_reconciliation import build_control_reconciliation


class ControlReconciliationTests(unittest.TestCase):
    def test_reports_verified_readbacks_and_explicit_desired_actual(self):
        result = build_control_reconciliation(
            {"observed_at": 1000, "manual_bandwidth_limits": {
                "state": "applied", "revision": 4,
                "items": [{"scope": "host", "interface": "ens3", "target": "ens3", "direction": "upload", "rate_mbps": 20, "state": "applied"}],
                "active_limits": [{"scope": "host", "interface": "ens3", "upload_mbps": 20, "download_mbps": 20, "last_confirmed_at": 990}],
            }},
            [{"runtime": "incus", "project": "default", "container_name": "app", "security": {
                "cpu_guard": {"state": "limited", "readback_confirmed": True, "expected_limit": "50000 100000", "actual_limit": "50000 100000"},
                "memory_guard": {"state": "active", "readback_confirmed": True, "expected_limit": "90000000", "actual_limit": "90000000"},
                "io_guard": {"state": "active", "readback_confirmed": True},
                "admission": {"state": "enforced"},
            }}],
            {"revision": 8, "rules": [{"protocol": "socks"}]},
            {"status": "ready", "stale": False, "sync_status": "in_sync", "rule_count": 1,
             "managed_rule_count": 1, "drift_count": 0, "missing_count": 0, "last_success_at": 995,
             "snapshot": {"policy_revision": 8}},
            1000,
        )
        self.assertEqual(result["status"], "verified")
        by_control = {item["control"]: item for item in result["controls"]}
        self.assertEqual(by_control["tc"]["expected"]["revision"], 4)
        self.assertEqual(by_control["tc"]["actual"]["active_limits"], 1)
        self.assertEqual(by_control["cgroup_cpu"]["actual"]["verified_active"], 1)
        self.assertEqual(by_control["cgroup_memory"]["actual"]["verified_active"], 1)
        self.assertEqual(by_control["nftables_admission"]["actual"]["verified_active"], 1)
        self.assertEqual(by_control["rfw"]["status"], "verified")

    def test_unverified_restore_failure_and_rfw_drift_are_visible(self):
        result = build_control_reconciliation(
            {"observed_at": 1000, "manual_bandwidth_limits": {"state": "failed", "items": [{"state": "failed", "message": "tc readback mismatch"}]}},
            [{"runtime": "podman", "container_name": "worker", "security": {
                "io_guard": {"state": "restore_failed", "readback_confirmed": True, "actual_limit": {"rbps": "1048576"}},
            }}],
            {"revision": 9, "rules": []},
            {"status": "ready", "stale": False, "drift_count": 1, "missing_count": 2},
            1000,
        )
        by_control = {item["control"]: item for item in result["controls"]}
        self.assertEqual(result["status"], "attention")
        self.assertEqual(by_control["tc"]["status"], "failed")
        self.assertEqual(by_control["cgroup_io"]["status"], "attention")
        self.assertEqual(by_control["rfw"]["status"], "drift")
        self.assertEqual(by_control["cgroup_io"]["samples"][0]["container"], "podman/worker")
        self.assertEqual(by_control["cgroup_io"]["samples"][0]["rollback"]["state"], "failed")

    def test_reports_guard_retry_and_rfw_rollback_progress(self):
        result = build_control_reconciliation(
            {"observed_at": 1000, "manual_bandwidth_limits": {"state": "applied", "items": [], "active_limits": []}},
            [{"runtime": "incus", "container_name": "worker", "security": {
                "cpu_guard": {"state": "restore_failed", "readback_confirmed": True,
                              "original_limit": "max 100000", "active_limit": "50000 100000",
                              "expected_limit": "50000 100000", "actual_limit": "50000 100000"},
                "io_guard": {"state": "retry_wait", "retry_after_seconds": 90,
                             "message": "等待冷却后重试"},
            }}],
            {"revision": 8, "rules": []},
            {"status": "ready", "stale": False, "sync_status": "in_sync", "rule_count": 0,
             "managed_rule_count": 0, "drift_count": 0, "missing_count": 0,
             "snapshot": {"policy_revision": 8},
             "latest_action": {"status": "running", "attempts": 2, "policy_revision": 8,
                               "rollback": {"requested": True, "target_revision": 7}}},
            1000,
        )
        by_control = {item["control"]: item for item in result["controls"]}
        self.assertEqual(by_control["cgroup_cpu"]["actual"]["verified_active"], 1)
        self.assertEqual(by_control["cgroup_cpu"]["actual"]["restore_failed"], 1)
        self.assertEqual(by_control["cgroup_cpu"]["samples"][0]["rollback"]["state"], "failed")
        self.assertEqual(by_control["cgroup_io"]["samples"][0]["retry"]["after_seconds"], 90)
        self.assertEqual(by_control["rfw"]["status"], "applying")
        self.assertEqual(by_control["rfw"]["retry"]["state"], "pending_agent")
        self.assertEqual(by_control["rfw"]["rollback"]["state"], "in_progress")

    def test_ignores_failed_firewall_action_for_superseded_revision(self):
        result = build_control_reconciliation(
            {"observed_at": 1000}, [],
            {"revision": 8, "rules": []},
            {"status": "ready", "stale": False, "sync_status": "in_sync",
             "rule_count": 0, "managed_rule_count": 0, "drift_count": 0, "missing_count": 0,
             "snapshot": {"policy_revision": 8},
             "latest_action": {"status": "failed", "policy_revision": 7}},
            1000,
        )
        rfw = next(item for item in result["controls"] if item["control"] == "rfw")
        self.assertEqual(rfw["status"], "verified")

    def test_retry_summary_includes_guards_beyond_visible_sample_limit(self):
        containers = [{"runtime": "incus", "container_name": f"worker-{index}", "security": {
            "io_guard": ({"state": "retry_wait", "retry_after_seconds": 75}
                         if index == 5 else {"state": "active", "readback_confirmed": True})
        }} for index in range(6)]
        result = build_control_reconciliation({"observed_at": 1000}, containers, None, {}, 1000)
        io = next(item for item in result["controls"] if item["control"] == "cgroup_io")
        self.assertEqual(len(io["samples"]), 5)
        self.assertEqual(io["retry"]["state"], "waiting")
        self.assertEqual(io["retry"]["pending"], 1)
        self.assertEqual(io["retry"]["after_seconds"], 75)

    def test_tc_rate_mismatch_is_drift_with_retry_and_rollback_readback(self):
        result = build_control_reconciliation(
            {"observed_at": 1000, "manual_bandwidth_limits": {
                "state": "applied", "revision": 10,
                "items": [{"scope": "host", "interface": "ens3", "target": "ens3", "direction": "upload", "rate_mbps": 20, "state": "applied"}],
                "active_limits": [{"scope": "host", "interface": "ens3", "upload_mbps": 10, "download_mbps": 20}],
                "rollback": {"state": "verified", "attempted": True},
            }},
            [], None, {}, 1000,
        )
        tc = next(item for item in result["controls"] if item["control"] == "tc")
        self.assertEqual(tc["status"], "drift")
        self.assertEqual(tc["retry"]["state"], "next_agent_cycle")
        self.assertEqual(tc["rollback"]["state"], "verified")


if __name__ == "__main__":
    unittest.main()
