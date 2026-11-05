"""Unit tests for client/anti_spoof_guard.py"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client import anti_spoof_guard


class TestAntiSpoofGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.journal_path = Path(self.temp_dir.name) / "anti-spoof-journal.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_valid_ips(self):
        raw = ["192.168.1.100", "127.0.0.1", "2001:db8::1", "::1", "invalid-ip", "10.0.0.2"]
        v4, v6 = anti_spoof_guard._parse_valid_ips(raw)
        self.assertEqual(v4, ["10.0.0.2", "192.168.1.100"])
        self.assertEqual(v6, ["2001:db8::1"])

    def test_invalid_params(self):
        ok, msg = anti_spoof_guard.apply_anti_spoof("bad;veth", ["192.168.1.10"])
        self.assertFalse(ok)
        self.assertIn("无效的网卡接口名", msg)

        ok, msg = anti_spoof_guard.apply_anti_spoof("veth123", ["not-an-ip"])
        self.assertFalse(ok)
        self.assertIn("未提供已分配的有效 IPv4 / IPv6 列表", msg)

    def test_apply_and_release_flow(self):
        commands_run: list[list[str]] = []

        def mock_runner(cmd: list[str]) -> tuple[bool, str]:
            commands_run.append(cmd)
            return True, ""

        with patch.object(anti_spoof_guard, "JOURNAL_PATH", str(self.journal_path)):
            # Apply
            ok, msg = anti_spoof_guard.apply_anti_spoof(
                "veth1a2b", ["198.51.100.10", "2001:db8::5"],
                runtime="runman", name="test-vm",
                runner=mock_runner, nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(ok)
            self.assertIn("已在接口 veth1a2b 启用源地址防伪造保护", msg)

            # Check sysctl command
            sysctl_calls = [cmd for cmd in commands_run if cmd[0] == "sysctl"]
            self.assertTrue(any("net.ipv4.conf.veth1a2b.rp_filter=1" in c[2] for c in sysctl_calls))

            # Check status
            status = anti_spoof_guard.get_anti_spoof_status("veth1a2b")
            self.assertTrue(status.get("active"))
            self.assertEqual(status.get("v4_ips"), ["198.51.100.10"])
            self.assertEqual(status.get("v6_ips"), ["2001:db8::5"])

            # Check lookup for container
            status_c = anti_spoof_guard.get_anti_spoof_status_for_container("runman", "test-vm")
            self.assertTrue(status_c.get("active"))
            self.assertEqual(status_c.get("veth"), "veth1a2b")

            # Release
            commands_run.clear()
            ok, msg = anti_spoof_guard.release_anti_spoof(
                "veth1a2b", runtime="runman", name="test-vm",
                runner=mock_runner, nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(ok)
            self.assertIn("已在接口 veth1a2b 解除", msg)

            # Check sysctl revert
            sysctl_calls = [cmd for cmd in commands_run if cmd[0] == "sysctl"]
            self.assertTrue(any("net.ipv4.conf.veth1a2b.rp_filter=2" in c[2] for c in sysctl_calls))

            # Status should be inactive
            status = anti_spoof_guard.get_anti_spoof_status("veth1a2b")
            self.assertFalse(status.get("active"))


if __name__ == "__main__":
    unittest.main()

