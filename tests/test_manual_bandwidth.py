import json
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch
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

    def reconcile_container(self, *, host_network=False, shared_peer=False,
                            unreadable_peer=False, inventory_failure=False,
                            incus_peer=False, malformed_incus_inventory=False):
        container_id, peer_id = "a" * 64, "b" * 64
        inventory = [{"runtime": "podman", "runtime_bin": "podman", "project": "",
                      "name": "proxy", "id": container_id, "pid": "42"}]
        policy = {**TARGET, "limits": [{"scope": "container", "runtime": "podman",
                  "project": "", "container_name": "proxy", "container_id": container_id,
                  "upload_mbps": 5, "download_mbps": 10}]}
        proc_stat = "42 (container init) " + " ".join(["S"] + ["0"] * 18 + ["987654"])
        original_stat, original_open = limiter.os.stat, open

        def stat(path, *args, **kwargs):
            inodes = {"/proc/1/ns/net": 1, "/proc/42/ns/net": 1 if host_network else 42,
                      "/proc/43/ns/net": 42 if shared_peer or incus_peer else 43}
            if str(path) in inodes:
                if unreadable_peer and str(path) == "/proc/43/ns/net":
                    raise PermissionError("peer namespace denied")
                return SimpleNamespace(st_ino=inodes[str(path)])
            return original_stat(path, *args, **kwargs)

        def read(path, *args, **kwargs):
            if str(path) == "/proc/42/stat":
                return mock_open(read_data=proc_stat)()
            return original_open(path, *args, **kwargs)

        def which(binary):
            return "/usr/bin/" + binary if binary == "podman" or (incus_peer and binary == "incus") else None

        def run(args, **kwargs):
            if args[1] == "ps":
                return (1, "runtime unavailable") if inventory_failure else (0, container_id + ("\n" + peer_id if not incus_peer else ""))
            if args[1] == "inspect":
                return 0, container_id + "|42" + ("\n" + peer_id + "|43" if not incus_peer else "")
            if args[1] == "list":
                if inventory_failure:
                    return 1, "Incus inventory unavailable"
                if malformed_incus_inventory:
                    return 0, "not-monitored,other-project,43,STOPPED,CONTAINER\n"
                return 0, "not-monitored,other-project,43,RUNNING,CONTAINER\n"
            if args[-5:] == ["ip", "-j", "route", "show", "default"]:
                return 0, '[{"dev":"eth0"}]'
            if args[-6:] == ["ip", "-j", "link", "show", "dev", "eth0"]:
                return 0, '[{"ifindex":2,"link_index":7}]'
            raise AssertionError(f"unexpected command: {args}")

        with ExitStack() as stack:
            stack.enter_context(patch.object(limiter.os, "stat", side_effect=stat))
            stack.enter_context(patch("builtins.open", side_effect=read))
            stack.enter_context(patch.object(limiter.shutil, "which", side_effect=which))
            runtime_query = stack.enter_context(patch.object(limiter, "_runner", side_effect=run))
            clsact = stack.enter_context(patch.object(limiter, "_ensure_clsact"))
            apply = stack.enter_context(patch.object(limiter, "_apply_filter", return_value=49150))
            result = limiter.reconcile(policy, HOST, NODE, inventory, state_path=self.state_path())
        return result, clsact, apply, runtime_query

    def test_manual_container_limit_rejects_host_namespace_before_tc(self):
        result, clsact, apply, _ = self.reconcile_container(host_network=True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("host network namespace", result["items"][0]["message"])
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_limit_rejects_unmonitored_podman_namespace_peer(self):
        result, clsact, apply, query = self.reconcile_container(shared_peer=True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("shared container network namespace", result["items"][0]["message"])
        self.assertTrue(any(call.args[0][1] == "ps" for call in query.call_args_list))
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_limit_rejects_unmonitored_incus_namespace_peer(self):
        result, clsact, apply, query = self.reconcile_container(incus_peer=True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("shared container network namespace", result["items"][0]["message"])
        self.assertTrue(any("--all-projects" in call.args[0] for call in query.call_args_list))
        incus_query = next(call.args[0] for call in query.call_args_list if call.args[0][1] == "list")
        self.assertIn("--format=csv", incus_query)
        self.assertIn("--columns=nepst", incus_query)
        self.assertNotIn("--format=json", incus_query)
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_container_limit_requires_complete_incus_inventory(self):
        result, clsact, apply, _ = self.reconcile_container(
            incus_peer=True, inventory_failure=True,
        )
        self.assertEqual(result["state"], "failed")
        self.assertIn("Incus inventory is unavailable", result["items"][0]["message"])
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_container_limit_rejects_unexpected_incus_inventory_row(self):
        result, clsact, apply, _ = self.reconcile_container(
            incus_peer=True, malformed_incus_inventory=True,
        )
        self.assertEqual(result["state"], "failed")
        self.assertIn("Incus inventory could not be verified", result["items"][0]["message"])
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_container_limit_requires_complete_runtime_inventory(self):
        result, clsact, apply, _ = self.reconcile_container(inventory_failure=True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("inventory is unavailable", result["items"][0]["message"])
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_container_limit_rejects_unreadable_peer_namespace(self):
        result, clsact, apply, _ = self.reconcile_container(unreadable_peer=True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("peer namespace is unavailable", result["items"][0]["message"])
        clsact.assert_not_called()
        apply.assert_not_called()

    def test_manual_container_limit_applies_to_proven_isolated_namespace(self):
        result, clsact, apply, query = self.reconcile_container()
        self.assertEqual(result["state"], "applied")
        clsact.assert_called_once_with(["nsenter", "--target", "42", "--net"], "eth0")
        self.assertEqual(apply.call_count, 2)
        self.assertEqual(sum(call.args[0][1] == "ps" for call in query.call_args_list), 1)

    def test_explicit_host_limit_does_not_require_container_isolation_inventory(self):
        policy = {**TARGET, "auto_throttle": {"enabled": False}}
        with patch.object(limiter.socket, "if_nametoindex", return_value=2), \
                patch.object(limiter, "_running_container_inventory") as inventory, \
                patch.object(limiter, "_ensure_clsact"), patch.object(limiter, "_apply_filter") as apply:
            result = limiter.reconcile(policy, HOST, NODE, [], state_path=self.state_path())
        self.assertEqual(result["state"], "applied")
        self.assertEqual(apply.call_count, 2)
        inventory.assert_not_called()

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
        self.assertEqual(result["rollback"]["state"], "verified")
        self.assertEqual(remove.call_count, 2)

    def test_partial_filter_cleanup_restores_removed_direction_and_reports_rollback(self):
        path = self.state_path()
        entry = {
            "key": "host:eth0", "owner_key": "node-a:host:eth0", "scope": "host",
            "prefix": [], "interface": "eth0", "interface_index": 2,
            "namespace_inode": "host", "expected_node_id": NODE,
            "directions": ["download", "upload"], "rates_mbps": {"download": 80, "upload": 50},
            "filter_prefs": {"download": 49150, "upload": 49151},
            "confirmed_at": {"download": 100, "upload": 100},
        }
        Path(path).write_text(json.dumps({"schema": 1, "host_id": HOST, "expected_node_id": NODE,
                                          "entries": {"host:eth0": entry}}), encoding="utf-8")
        remove = patch.object(limiter, "_remove_filter", side_effect=[True, limiter.BandwidthPolicyError("second direction failed")])
        restore = patch.object(limiter, "_apply_filter", return_value=49150)
        with patch.object(limiter.socket, "if_nametoindex", return_value=2), remove as remove_mock, restore as restore_mock:
            result = limiter.reconcile({**TARGET, "revision": 2, "limits": []}, HOST, NODE, [], state_path=path)

        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["rollback"]["state"], "verified")
        self.assertEqual(result["rollback"]["results"][0]["direction"], "cleanup")
        self.assertEqual(restore_mock.call_count, 1)
        self.assertEqual(restore_mock.call_args.args[4], 80)
        self.assertEqual(remove_mock.call_count, 2)
        persisted = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertIn("host:eth0", persisted["entries"])

    def test_unverified_old_filter_cleanup_blocks_replacing_same_target(self):
        path = self.state_path()
        old_entry = {
            "key": "host:eth0", "owner_key": "node-a:host:eth0", "scope": "host",
            "prefix": [], "interface": "eth0", "interface_index": 2,
            "namespace_inode": "host", "expected_node_id": NODE,
            "directions": ["download"], "rates_mbps": {"download": 80},
            "filter_prefs": {"download": 49150}, "confirmed_at": {"download": 100},
        }
        Path(path).write_text(json.dumps({"schema": 1, "host_id": HOST, "expected_node_id": NODE,
                                          "entries": {"host:eth0": old_entry}}), encoding="utf-8")
        target = {**old_entry, "interface_index": 3}
        with patch.object(limiter, "_remove_entry", side_effect=limiter.BandwidthPolicyError("old identity unreadable")), \
                patch.object(limiter, "_ensure_clsact") as clsact, patch.object(limiter, "_apply_filter") as apply:
            result = limiter.reconcile(TARGET, HOST, NODE, [], state_path=path,
                                       resolve=lambda host, item, containers: dict(target))

        self.assertEqual(result["state"], "failed")
        self.assertTrue(any("旧的 tc 所有限额" in item.get("message", "") for item in result["items"]))
        clsact.assert_not_called()
        apply.assert_not_called()
        persisted = json.loads(Path(path).read_text(encoding="utf-8"))
        self.assertEqual(persisted["entries"]["host:eth0"]["interface_index"], 2)


if __name__ == "__main__":
    unittest.main()
