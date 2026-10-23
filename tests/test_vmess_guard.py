import hashlib
import json
import unittest
from unittest import mock

from client import socks_detector
from client import vmess_guard
from client import security_banner
from client import agent


class VmessPlanTests(unittest.TestCase):
    def setUp(self):
        self.config = [{
            "pid": 120,
            "process": "xray",
            "protocol": "vmess",
            "port": 443,
            "listen": "0.0.0.0",
            "transports": ["tcp"],
        }]
        self.listener = {
            "pid": 120,
            "process": "xray",
            "proto": "tcp",
            "local": "0.0.0.0:443",
            "port": 443,
            "application_protocols": ["vmess"],
            "application_protocol_evidence": "config_matches_live_pid_and_port",
        }

    def test_only_config_and_live_listener_match_is_eligible(self):
        result = vmess_guard.plan("incus", self.config, [self.listener], [], "complete")
        self.assertEqual(result["state"], "candidate")
        self.assertEqual(result["blocked_endpoints"], [{
            "proto": "tcp", "port": 443, "pid": 120, "process": "xray",
        }])

    def test_truncated_listener_inventory_never_becomes_a_block_target(self):
        result = vmess_guard.plan("podman", self.config, [self.listener], [], "partial")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "configuration_scan_incomplete")

    def test_unknown_or_shared_listener_owner_is_not_blocked(self):
        shared = {**self.listener, "pid": 121, "process": "other", "application_protocols": ["vless"]}
        result = vmess_guard.plan("incus", self.config, [self.listener, shared], [], "complete")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["blocked_endpoints"], [])
        self.assertEqual(result["pending_endpoints"][0]["reason"], "shared_live_listener")

    def test_loopback_only_listener_is_not_mistaken_for_public_service(self):
        listener = {**self.listener, "local": "127.0.0.1:443"}
        result = vmess_guard.plan("podman", self.config, [listener], [], "complete")
        self.assertEqual(result["state"], "internal_only")
        self.assertEqual(result["blocked_endpoints"], [])

    def test_runtime_scope_is_limited_to_incus_and_podman(self):
        result = vmess_guard.plan("docker", self.config, [self.listener], [], "complete")
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "runtime_not_supported")
        self.assertEqual(result["blocked_endpoints"], [])

    def test_config_parser_reports_protocol_without_secrets(self):
        xray = socks_detector.parse_inbound_protocols(
            '{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"network":"tcp"},"settings":{"clients":[{"id":"secret"}]}}]}',
            "xray",
        )
        sing_box = socks_detector.parse_inbound_protocols(
            '{"inbounds":[{"type":"vmess","listen_port":8443}]}', "sing-box"
        )
        self.assertEqual(xray["endpoints"][0]["protocol"], "vmess")
        self.assertEqual(xray["endpoints"][0]["transports"], ["tcp"])
        self.assertEqual(sing_box["endpoints"][0]["port"], 8443)
        self.assertNotIn("secret", json.dumps(xray))

    def test_unrelated_gost_process_does_not_make_vmess_scan_incomplete(self):
        process_output = (
            "120 S xray /usr/bin/xray -config /etc/xray/config.json\n"
            "121 S gost /usr/bin/gost -C /etc/gost/config.json\n"
        )
        with mock.patch.object(agent, "run", return_value='{"inbounds":[]}'):
            result = agent._collect_socks_config_evidence(
                "incus", "fixture", "default", False, process_output
            )
        self.assertEqual(result["protocol_inventory_state"], "complete")
        self.assertEqual(result["configured_inbound_protocols"], [])

    def test_customer_banner_copy_says_only_port_is_blocked(self):
        title, detail, extra, advice = security_banner.customer_copy({
            "type": "vmess_port_blocked",
            "title": "VMess 入站端口已自动阻断",
            "detail": "已阻断 TCP/443",
        })
        self.assertIn("VMess", title)
        self.assertIn("TCP/443", detail)
        self.assertEqual(extra, [])
        self.assertIn("没有停止进程、容器或其他端口", advice)
        self.assertIn("VLESS + Reality + Vision", advice)


class VmessReconcileTests(unittest.TestCase):
    def test_namespace_fd_is_closed_if_pid_identity_changes_while_opening(self):
        with mock.patch.object(vmess_guard, "_pid_epoch", side_effect=["epoch", "changed"]), \
                mock.patch.object(vmess_guard.os, "open", return_value=23), \
                mock.patch.object(vmess_guard.os, "close") as close:
            self.assertIsNone(vmess_guard._open_namespace_fd(120, "epoch"))
        close.assert_called_once_with(23)

    def test_nft_rules_are_namespace_local_validated_applied_and_read_back(self):
        identity = "podman\0\0fixture\0container-id"
        digest = hashlib.sha256(identity.encode()).hexdigest()[:12]
        marker = f"narwhal-vmess-guard-v1-{digest}"
        calls = []
        applied = False

        def runner(args, **kwargs):
            nonlocal applied
            calls.append((args, kwargs))
            command = args[4:]
            if command[:4] == ["-a", "list", "table", "inet"]:
                return mock.Mock(returncode=0 if applied else 1,
                                 stdout=(marker + "-tcp-443") if applied else "", stderr="")
            if command == ["-j", "list", "tables"]:
                return mock.Mock(returncode=0, stdout='{"nftables":[]}', stderr="")
            if command[:1] == ["--check"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if command == ["-f", "-"]:
                applied = True
                return mock.Mock(returncode=0, stdout="", stderr="")
            return mock.Mock(returncode=2, stdout="", stderr="unexpected command")

        with mock.patch.object(vmess_guard, "_pid_epoch", return_value="epoch"), \
                mock.patch.object(vmess_guard, "_open_namespace_fd", return_value=17), \
                mock.patch.object(vmess_guard.os, "close"), \
                mock.patch.object(vmess_guard.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
            result = vmess_guard.reconcile(
                120, identity, "epoch", [{"proto": "tcp", "port": 443}], runner=runner
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blocked_endpoints"], [{"proto": "tcp", "port": 443}])
        self.assertTrue(all(call[0][0] == "/usr/bin/nsenter" for call in calls))
        self.assertTrue(all(call[0][1] == "--net=/proc/self/fd/17" for call in calls))
        self.assertTrue(all(call[1]["pass_fds"] == (17,) for call in calls))
        script = next(kwargs["input"] for args, kwargs in calls if "--check" in args)
        self.assertIn("add chain inet narwhal_vmess_", script)
        self.assertIn("meta l4proto tcp tcp dport 443 drop", script)
        self.assertIn(marker + "-tcp-443", script)

    def test_namespace_mismatch_fails_closed_before_running_commands(self):
        with mock.patch.object(vmess_guard, "_pid_epoch", return_value="changed"):
            runner = mock.Mock()
            result = vmess_guard.reconcile(
                120, "container", "expected", [{"proto": "tcp", "port": 443}], runner=runner
            )
        self.assertEqual(result["state"], "unverified")
        self.assertEqual(result["reason"], "container_namespace_changed_or_shared")
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
