import json
import unittest
from pathlib import Path
from unittest.mock import patch
import uuid

from client import manual_bandwidth as limiter


HOST = "node-a"
NODE = "enrollment-a"
TARGET = {
    "schema": 1,
    "host_id": HOST,
    "expected_node_id": NODE,
    "revision": 1,
    "limits": [{"scope": "host", "interface": "eth0", "upload_mbps": 50, "download_mbps": 80}],
}


class ManualBandwidthTests(unittest.TestCase):
    def state_path(self):
        path = Path(__file__).resolve().parent / f".manual-bandwidth-test-{uuid.uuid4().hex}.json"
        self.addCleanup(lambda: path.unlink(missing_ok=True))
        return str(path)

    def test_policy_is_bound_to_host_and_enrollment(self):
        with self.assertRaises(limiter.BandwidthPolicyError):
            limiter.validate_policy({**TARGET, "expected_node_id": "other"}, HOST, NODE)
        with self.assertRaises(limiter.BandwidthPolicyError):
            limiter.validate_policy({**TARGET, "limits": [{**TARGET["limits"][0], "upload_mbps": 1.0}]}, HOST, NODE)

    def test_proc_stat_handles_spaces_in_process_name(self):
        rest = ["S"] + ["0"] * 18 + ["987654"]
        self.assertEqual(limiter._proc_start_ticks("12 (a process with spaces) " + " ".join(rest)), "987654")

    def test_podman_pid_requires_matching_container_id(self):
        item = {"runtime": "podman", "container_name": "proxy", "container_id": "abc123"}
        match = {"runtime_bin": "podman"}
        with patch.object(limiter, "_runner", return_value=(0, "abc123456789|42")):
            self.assertEqual(limiter._container_process_pid(item, match), 42)
        with patch.object(limiter, "_runner", return_value=(0, "def456789abc|42")):
            with self.assertRaises(limiter.BandwidthPolicyError):
                limiter._container_process_pid(item, match)

    def test_apply_and_remove_use_only_policy_owned_filters(self):
        path = self.state_path()
        target = {
            "key": "host:eth0", "owner_key": "node-a:host:eth0", "scope": "host",
            "prefix": [], "interface": "eth0", "interface_index": 2,
            "namespace_inode": "host",
        }
        resolver = lambda host, item, containers: dict(target)
        with patch.object(limiter, "_ensure_clsact"), patch.object(limiter, "_apply_filter") as apply:
            result = limiter.reconcile(TARGET, HOST, NODE, [], state_path=path, resolve=resolver)
        self.assertEqual(result["state"], "applied")
        self.assertEqual(apply.call_count, 2)
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual(saved["entries"]["host:eth0"]["directions"], ["download", "upload"])

        with patch.object(limiter, "_remove_entry") as remove:
            result = limiter.reconcile({**TARGET, "revision": 2, "limits": []}, HOST, NODE, [], state_path=path, resolve=resolver)
        self.assertEqual(result["state"], "unconfigured")
        remove.assert_called_once()

    def test_temporary_target_failure_preserves_existing_limit(self):
        path = self.state_path()
        entry = {
            "key": "host:eth0", "owner_key": "node-a:host:eth0", "scope": "host",
            "prefix": [], "interface": "eth0", "interface_index": 2,
            "namespace_inode": "host", "expected_node_id": NODE, "directions": ["download"],
        }
        Path(path).write_text(json.dumps({"schema": 1, "host_id": HOST, "expected_node_id": NODE,
                                          "entries": {"host:eth0": entry}}), encoding="utf-8")

        def unavailable(*_args):
            raise limiter.BandwidthPolicyError("target temporarily unavailable")

        with patch.object(limiter, "_remove_entry") as remove:
            result = limiter.reconcile(TARGET, HOST, NODE, [], state_path=path, resolve=unavailable)
        self.assertEqual(result["state"], "failed")
        remove.assert_not_called()
        self.assertIn("host:eth0", json.loads(Path(path).read_text(encoding="utf-8"))["entries"])

    def test_state_write_failure_rolls_back_new_filter(self):
        path = self.state_path()
        target = {
            "key": "host:eth0", "owner_key": "node-a:host:eth0", "scope": "host",
            "prefix": [], "interface": "eth0", "interface_index": 2,
            "namespace_inode": "host",
        }
        with patch.object(limiter, "_ensure_clsact"), patch.object(limiter, "_apply_filter"), \
                patch.object(limiter, "_remove_filter") as remove, \
                patch.object(limiter, "_write_state", side_effect=OSError("disk full")):
            result = limiter.reconcile(TARGET, HOST, NODE, [], state_path=path,
                                       resolve=lambda host, item, containers: dict(target))
        self.assertEqual(result["state"], "failed")
        self.assertIn("rolled back", result["message"])
        self.assertEqual(remove.call_count, 2)


if __name__ == "__main__":
    unittest.main()
