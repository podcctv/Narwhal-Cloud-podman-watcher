import unittest

from server.control_reconciliation import build_control_reconciliation


class ControlReconciliationTests(unittest.TestCase):
    def test_reports_verified_readbacks_and_explicit_desired_actual(self):
        result = build_control_reconciliation(
            {"observed_at": 1000, "manual_bandwidth_limits": {
                "state": "applied", "revision": 4, "items": [{}],
                "active_limits": [{"interface": "ens3", "upload_mbps": 20, "download_mbps": 20, "last_confirmed_at": 990}],
            }},
            [{"runtime": "incus", "project": "default", "container_name": "app", "security": {
                "cpu_guard": {"state": "limited", "readback_confirmed": True, "expected_limit": "50000 100000", "actual_limit": "50000 100000"},
                "io_guard": {"state": "active", "readback_confirmed": True},
                "admission": {"state": "enforced"},
            }}],
            {"revision": 8, "rules": [{"protocol": "socks"}]},
            {"status": "ready", "stale": False, "sync_status": "applied", "rule_count": 1,
             "managed_rule_count": 1, "drift_count": 0, "missing_count": 0, "last_success_at": 995},
            1000,
        )
        self.assertEqual(result["status"], "verified")
        by_control = {item["control"]: item for item in result["controls"]}
        self.assertEqual(by_control["tc"]["expected"]["revision"], 4)
        self.assertEqual(by_control["tc"]["actual"]["active_limits"], 1)
        self.assertEqual(by_control["cgroup_cpu"]["actual"]["verified_active"], 1)
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


if __name__ == "__main__":
    unittest.main()
