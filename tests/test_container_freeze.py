"""Unit tests for client/container_freeze.py"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from client import container_freeze


class TestContainerFreeze(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cgroup_root = Path(self.temp_dir.name) / "cgroup"
        self.proc_root = Path(self.temp_dir.name) / "proc"
        self.journal_path = Path(self.temp_dir.name) / "freeze-journal.json"
        self.cgroup_root.mkdir(parents=True, exist_ok=True)
        self.proc_root.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_invalid_params(self):
        # Unsupported runtime
        ok, msg = container_freeze.freeze_container("docker", "my-container", 100)
        self.assertFalse(ok)
        self.assertIn("不支持的运行时", msg)

        # Invalid container name
        ok, msg = container_freeze.freeze_container("incus", "bad/name", 100)
        self.assertFalse(ok)
        self.assertIn("容器名称格式无效", msg)

        # Invalid PID
        ok, msg = container_freeze.freeze_container("incus", "valid-name", 0)
        self.assertFalse(ok)
        self.assertIn("PID 必须大于 1", msg)

        # Runman non-uuid
        ok, msg = container_freeze.freeze_container("runman", "not-a-uuid", 100)
        self.assertFalse(ok)
        self.assertIn("Runman 容器必须为有效 VM UUID", msg)

    def test_freeze_and_unfreeze_flow(self):
        # Setup mock cgroup for an incus container
        pid = 1234
        container_name = "test-c1"
        proc_pid_dir = self.proc_root / str(pid)
        proc_pid_dir.mkdir(parents=True, exist_ok=True)
        (proc_pid_dir / "cgroup").write_text(f"0::/incus/lxc.payload.{container_name}\n", encoding="ascii")
        (proc_pid_dir / "stat").write_text(f"{pid} (test) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0\n", encoding="ascii")

        target_cgroup = self.cgroup_root / "incus" / f"lxc.payload.{container_name}"
        target_cgroup.mkdir(parents=True, exist_ok=True)
        freeze_file = target_cgroup / "cgroup.freeze"
        events_file = target_cgroup / "cgroup.events"
        freeze_file.write_text("0\n", encoding="ascii")
        events_file.write_text("populated 1\nfrozen 0\n", encoding="ascii")

        with patch.object(container_freeze, "JOURNAL_PATH", str(self.journal_path)):
            # Before freeze, status is not frozen
            status = container_freeze.get_freeze_status(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(status.get("supported"))
            self.assertFalse(status.get("frozen"))

            # Freeze container (simulate kernel transition to frozen 1)
            events_file.write_text("populated 1\nfrozen 1\n", encoding="ascii")
            ok, msg = container_freeze.freeze_container(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(ok)
            self.assertIn("已成功挂起冻结", msg)
            self.assertEqual(freeze_file.read_text(encoding="ascii").strip(), "1")

            # Check status
            status = container_freeze.get_freeze_status(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(status.get("frozen"))
            self.assertTrue(status.get("journaled"))

            # Now unfreeze
            events_file.write_text("populated 1\nfrozen 0\n", encoding="ascii")
            ok, msg = container_freeze.unfreeze_container(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(ok)
            self.assertIn("已成功解冻恢复运行", msg)
            self.assertEqual(freeze_file.read_text(encoding="ascii").strip(), "0")

            # Check status after thaw
            status = container_freeze.get_freeze_status(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertFalse(status.get("frozen"))
            self.assertFalse(status.get("journaled"))

    def test_runman_freeze_and_unfreeze(self):
        vm_id = "12345678-1234-1234-1234-123456789abc"
        pid = 4321
        proc_pid_dir = self.proc_root / str(pid)
        proc_pid_dir.mkdir(parents=True, exist_ok=True)
        (proc_pid_dir / "cgroup").write_text(f"0::/system.slice/runman-{vm_id}.service/ct\n", encoding="ascii")
        # 19 fields before field 20 (start_ticks = 9999)
        (proc_pid_dir / "stat").write_text(f"{pid} (runman) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9999 0\n", encoding="ascii")

        target_cgroup = self.cgroup_root / "system.slice" / f"runman-{vm_id}.service" / "ct"
        target_cgroup.mkdir(parents=True, exist_ok=True)
        freeze_file = target_cgroup / "cgroup.freeze"
        events_file = target_cgroup / "cgroup.events"
        freeze_file.write_text("0\n", encoding="ascii")
        events_file.write_text("populated 1\nfrozen 0\n", encoding="ascii")

        with patch.object(container_freeze, "JOURNAL_PATH", str(self.journal_path)):
            events_file.write_text("populated 1\nfrozen 1\n", encoding="ascii")
            ok, msg = container_freeze.freeze_container(
                "runman", vm_id, pid, instance_id=vm_id,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(ok)
            self.assertIn("已成功挂起冻结", msg)

            events_file.write_text("populated 1\nfrozen 0\n", encoding="ascii")
            ok, msg = container_freeze.unfreeze_container(
                "runman", vm_id, pid, instance_id=vm_id,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root)
            )
            self.assertTrue(ok)
            self.assertIn("已成功解冻恢复运行", msg)

    def test_freeze_timeout_reverts(self):
        # If cgroup.events never transitions to frozen 1, it should revert cgroup.freeze back to 0
        pid = 5678
        container_name = "timeout-c1"
        proc_pid_dir = self.proc_root / str(pid)
        proc_pid_dir.mkdir(parents=True, exist_ok=True)
        (proc_pid_dir / "cgroup").write_text(f"0::/incus/lxc.payload.{container_name}\n", encoding="ascii")
        (proc_pid_dir / "stat").write_text(f"{pid} (test) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0\n", encoding="ascii")

        target_cgroup = self.cgroup_root / "incus" / f"lxc.payload.{container_name}"
        target_cgroup.mkdir(parents=True, exist_ok=True)
        freeze_file = target_cgroup / "cgroup.freeze"
        events_file = target_cgroup / "cgroup.events"
        freeze_file.write_text("0\n", encoding="ascii")
        events_file.write_text("populated 1\nfrozen 0\n", encoding="ascii")

        with patch.object(container_freeze, "JOURNAL_PATH", str(self.journal_path)):
            ok, msg = container_freeze.freeze_container(
                "incus", container_name, pid,
                cgroup_root=self.cgroup_root, proc_root=str(self.proc_root),
                timeout_sec=0.1
            )
            self.assertFalse(ok)
            self.assertIn("超时", msg)
            # Reverted to 0
            self.assertEqual(freeze_file.read_text(encoding="ascii").strip(), "0")


if __name__ == "__main__":
    unittest.main()
