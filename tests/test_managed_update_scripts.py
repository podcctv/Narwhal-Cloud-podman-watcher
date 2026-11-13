"""Tests for Phase 2 upgrade/rollback hardening and architecture detection."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import update_archive

HAS_BASH = bool(shutil.which("bash"))
HAS_POSIX_SHELL = os.name == "posix" and HAS_BASH and bool(shutil.which("flock"))


class ManagedUpdateScriptsContractTests(unittest.TestCase):
    def test_managed_client_update_uses_dynamic_discovery_and_unit_snapshot(self):
        updater = (ROOT / "scripts" / "managed-client-update.sh").read_text(encoding="utf-8")
        # No hardcoded module list loops remain.
        self.assertNotIn("for module in abuse_detection", updater)
        self.assertIn('stage_py_files=("$stage/client"/*.py)', updater)
        self.assertIn('"$app_dir/.venv/bin/python" -m py_compile "${stage_py_files[@]}"', updater)
        self.assertIn('for app_py in "$app_dir"/*.py; do', updater)
        self.assertIn('for snap_py in "$snapshot_client_dir"/*.py; do', updater)
        self.assertIn("$snapshot/installed-files.manifest", updater)
        self.assertIn("$snapshot/staged-files.manifest", updater)
        self.assertIn("$app_dir/bin", updater)
        # Systemd unit and updater helpers are snapshotted and restored with daemon-reload.
        self.assertIn("narwhal-monitor-client.service", updater)
        self.assertIn("$snapshot/narwhal-monitor-client.service", updater)
        self.assertIn("systemctl daemon-reload", updater)
        self.assertIn("$snapshot/managed-client-update.sh", updater)
        self.assertIn("$snapshot/update_archive.py", updater)

    def test_install_client_updates_all_modules_and_helpers_and_normalizes_arch(self):
        installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        self.assertIn("normalize_arch()", installer)
        self.assertIn("x86_64|amd64", installer)
        self.assertIn("aarch64|arm64", installer)
        self.assertIn('for f in "$ROOT_DIR"/client/*.py; do', installer)
        self.assertIn('$ROOT_DIR/client/bin', installer)
        self.assertIn('install -m 0755 "$ROOT_DIR/scripts/managed-client-update.sh" /opt/narwhal-monitor/managed-client-update.sh', installer)
        self.assertIn('install -m 0755 "$ROOT_DIR/scripts/update_archive.py" /opt/narwhal-monitor/update_archive.py', installer)

    def test_update_archive_normalize_arch(self):
        self.assertEqual(update_archive.normalize_arch("x86_64"), "amd64")
        self.assertEqual(update_archive.normalize_arch("amd64"), "amd64")
        self.assertEqual(update_archive.normalize_arch("aarch64"), "arm64")
        self.assertEqual(update_archive.normalize_arch("arm64"), "arm64")
        with self.assertRaisesRegex(RuntimeError, "unsupported CPU architecture"):
            update_archive.normalize_arch("riscv64")
        with self.assertRaisesRegex(RuntimeError, "unsupported CPU architecture"):
            update_archive.normalize_arch("")

    def test_update_archive_arch_cli_command(self):
        with patch.object(sys, "argv", ["update_archive.py", "arch", "x86_64"]):
            self.assertEqual(update_archive.main(), 0)
        with patch.object(sys, "argv", ["update_archive.py", "arch", "mips64"]):
            self.assertEqual(update_archive.main(), 1)

    @unittest.skipUnless(HAS_BASH, "bash is not available")
    def test_bash_syntax_check(self):
        for rel in ("scripts/managed-client-update.sh", "scripts/install-client.sh"):
            res = subprocess.run(
                ["bash", "-n", str(ROOT / rel)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, f"{rel} failed bash -n: {res.stderr}")

    @unittest.skipUnless(HAS_BASH, "bash is not available")
    def test_install_client_normalize_arch_in_bash(self):
        installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        start = installer.index("normalize_arch() {")
        end = installer.index("\n}\n", start) + 3
        fn_body = installer[start:end]
        for raw, expected in (
            ("x86_64", "amd64"),
            ("amd64", "amd64"),
            ("aarch64", "arm64"),
            ("arm64", "arm64"),
        ):
            res = subprocess.run(
                ["bash", "-c", f"{fn_body}\nnormalize_arch {shlex.quote(raw)}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), expected)
        bad = subprocess.run(
            ["bash", "-c", f"{fn_body}\nnormalize_arch s390x"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("Unsupported CPU architecture", bad.stderr)


@unittest.skipUnless(HAS_POSIX_SHELL, "Linux/POSIX shell integration requires bash and flock")
class ManagedUpdateRollbackIntegrationTests(unittest.TestCase):
    def test_rollback_removes_newly_added_modules_and_restores_unit_and_helpers(self):
        with tempfile.TemporaryDirectory(prefix="narwhal-phase2-test-") as temp:
            root = Path(temp)
            base = root / "base"
            app = base / "client-agent"
            bins = root / "bin"
            fixture = root / "release"
            repo = root / "repo"
            systemd_unit = root / "narwhal-monitor-client.service"
            for p in (base, app, bins, fixture / "client" / "bin", fixture / "scripts", repo / ".git", app / ".venv" / "bin"):
                p.mkdir(parents=True, exist_ok=True)

            def executable(path: Path, text: str) -> None:
                path.write_text(text, encoding="utf-8")
                path.chmod(0o755)

            (app / "agent.py").write_text("old_agent = True\n", encoding="utf-8")
            (app / "operations.py").write_text("old_operations = True\n", encoding="utf-8")
            (app / "requirements.txt").write_text("", encoding="utf-8")
            (base / "client.env").write_text("NARWHAL_VERSION=1.8.24\n", encoding="utf-8")
            (base / "client-auto-update.env").write_text(
                f"AUTO_UPDATE_MODE=git\nAUTO_UPDATE_REPO_DIR={shlex.quote(str(repo))}\n",
                encoding="utf-8",
            )
            executable(base / "managed-client-update.sh", "#!/bin/bash\n# old updater\n")
            executable(base / "update_archive.py", "#!/usr/bin/env python3\n# old archive\n")
            systemd_unit.write_text("[Service]\nExecStart=/old/python\n", encoding="utf-8")

            # Staged release adds new modularized files + native bin + modified unit/helpers, then fails.
            (fixture / "client" / "agent.py").write_text("new_agent = True\n", encoding="utf-8")
            (fixture / "client" / "proc_scanner.py").write_text("new_proc_scanner = True\n", encoding="utf-8")
            (fixture / "client" / "socket_collector.py").write_text("new_socket_collector = True\n", encoding="utf-8")
            executable(fixture / "client" / "bin" / "narwhal-probe", "#!/bin/sh\necho probe\n")
            (fixture / "client" / "requirements.txt").write_text("", encoding="utf-8")
            (fixture / "VERSION").write_text("1.8.25\n", encoding="utf-8")
            executable(
                fixture / "scripts" / "install-client.sh",
                "\n".join(
                    [
                        "#!/bin/bash",
                        f"cp {shlex.quote(str(fixture / 'client'))}/*.py {shlex.quote(str(app))}/",
                        f"mkdir -p {shlex.quote(str(app / 'bin'))}",
                        f"cp {shlex.quote(str(fixture / 'client' / 'bin' / 'narwhal-probe'))} {shlex.quote(str(app / 'bin' / 'narwhal-probe'))}",
                        f"printf '[Service]\\nExecStart=/new/rust-bin\\n' > {shlex.quote(str(systemd_unit))}",
                        f"printf '#!/bin/bash\\n# new updater\\n' > {shlex.quote(str(base / 'managed-client-update.sh'))}",
                        f"printf '#!/usr/bin/env python3\\n# new archive\\n' > {shlex.quote(str(base / 'update_archive.py'))}",
                        f"printf 'NARWHAL_VERSION=1.8.25\\n' > {shlex.quote(str(base / 'client.env'))}",
                        "exit 1",
                    ]
                )
                + "\n",
            )
            executable(app / ".venv" / "bin" / "python", "#!/bin/bash\nexit 0\n")
            executable(app / ".venv" / "bin" / "pip", "#!/bin/bash\nexit 0\n")

            systemctl_log = root / "systemctl.log"
            executable(
                bins / "systemctl",
                f"""#!/bin/bash
printf '%s\\n' "$*" >> {shlex.quote(str(systemctl_log))}
if [[ "$1" == show ]]; then
  printf 'ActiveState=active\\nSubState=running\\nMainPID=1234\\nNRestarts=0\\n'
fi
exit 0
""",
            )
            executable(
                bins / "git",
                f"""#!/bin/bash
shift 2
case "$1" in
  remote) printf '%s\\n' https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git ;;
  status) : ;;
  fetch|merge-base|merge) exit 0 ;;
  rev-parse) printf '%s\\n' {'a' * 40} ;;
  show) printf '1.8.25\\n' ;;
  archive) tar -c -C {shlex.quote(str(fixture))} . ;;
  *) exit 2 ;;
esac
""",
            )

            script = root / "worker.sh"
            source = (ROOT / "scripts" / "managed-client-update.sh").read_text(encoding="utf-8")
            source = source.replace("/opt/narwhal-monitor", str(base)).replace(
                "/run/narwhal-monitor-client-auto-update.lock", str(root / "auto-update.lock")
            )
            source = source.replace("local timeout_seconds=45 stable_seconds=15", "local timeout_seconds=6 stable_seconds=1").replace(
                "sleep 2", "sleep 1"
            )
            script.write_text(source, encoding="utf-8")

            env = {
                **os.environ,
                "PATH": str(bins) + os.pathsep + os.environ["PATH"],
                "NARWHAL_SYSTEMD_SERVICE_FILE": str(systemd_unit),
            }
            res = subprocess.run(
                ["bash", str(script), "upgrade", "a" * 40, "1.8.25", "99"],
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            # Newly added modules and binary are removed; previous modules, unit, and helpers are restored.
            self.assertFalse((app / "proc_scanner.py").exists())
            self.assertFalse((app / "socket_collector.py").exists())
            self.assertFalse((app / "bin" / "narwhal-probe").exists())
            self.assertIn("old_agent = True", (app / "agent.py").read_text(encoding="utf-8"))
            self.assertIn("old_operations = True", (app / "operations.py").read_text(encoding="utf-8"))
            self.assertIn("ExecStart=/old/python", systemd_unit.read_text(encoding="utf-8"))
            self.assertIn("# old updater", (base / "managed-client-update.sh").read_text(encoding="utf-8"))
            self.assertIn("# old archive", (base / "update_archive.py").read_text(encoding="utf-8"))
            self.assertIn("daemon-reload", systemctl_log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
