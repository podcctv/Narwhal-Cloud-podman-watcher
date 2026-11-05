"""Unit tests for client/udp_guard.py"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client import udp_guard


class TestUdpGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.journal_path = Path(self.temp_dir.name) / "udp-journal.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_invalid_params(self):
        ok, msg = udp_guard.apply_udp_blackhole("docker", "my-container", pid=100)
        self.assertFalse(ok)
        self.assertIn("不支持的运行时", msg)

        ok, msg = udp_guard.apply_udp_blackhole("runman", "bad/name", pid=100)
        self.assertFalse(ok)
        self.assertIn("容器名称格式无效", msg)

        ok, msg = udp_guard.apply_udp_blackhole("runman", "c1", pid=0)
        self.assertFalse(ok)
        self.assertIn("容器 PID 无效", msg)

    def test_apply_and_release_with_runner(self):
        commands_run: list[list[str]] = []

        def mock_runner(cmd: list[str]) -> tuple[bool, str]:
            commands_run.append(cmd)
            return True, "table inet narwhal_udp_guard"

        with patch.object(udp_guard, "JOURNAL_PATH", str(self.journal_path)):
            # 1. Apply with allow_dns=True
            ok, msg = udp_guard.apply_udp_blackhole(
                "runman", "test-vm-1", pid=1234, allow_dns=True,
                runner=mock_runner, nsenter_bin="/usr/bin/nsenter", nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(ok)
            self.assertIn("专项阻断", msg)
            self.assertIn("放行 53 端口 DNS", msg)

            # Check journal
            status = udp_guard.get_udp_blackhole_status(
                "runman", "test-vm-1", pid=1234, runner=mock_runner,
                nsenter_bin="/usr/bin/nsenter", nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(status.get("active"))
            self.assertTrue(status.get("allow_dns"))

            # 2. Release
            ok, msg = udp_guard.release_udp_blackhole(
                "runman", "test-vm-1", pid=1234,
                runner=mock_runner, nsenter_bin="/usr/bin/nsenter", nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(ok)
            self.assertIn("已解除", msg)

            status = udp_guard.get_udp_blackhole_status("runman", "test-vm-1", pid=1234)
            self.assertFalse(status.get("active"))

    def test_apply_without_dns(self):
        commands_run: list[list[str]] = []

        def mock_runner(cmd: list[str]) -> tuple[bool, str]:
            commands_run.append(cmd)
            return True, ""

        with patch.object(udp_guard, "JOURNAL_PATH", str(self.journal_path)):
            ok, msg = udp_guard.apply_udp_blackhole(
                "incus", "c-no-dns", pid=2222, allow_dns=False,
                runner=mock_runner, nsenter_bin="/usr/bin/nsenter", nft_bin="/usr/sbin/nft"
            )
            self.assertTrue(ok)
            self.assertIn("完全阻断全部 UDP", msg)

            status = udp_guard.get_udp_blackhole_status("incus", "c-no-dns", pid=2222)
            self.assertTrue(status.get("active"))
            self.assertFalse(status.get("allow_dns"))


if __name__ == "__main__":
    unittest.main()

