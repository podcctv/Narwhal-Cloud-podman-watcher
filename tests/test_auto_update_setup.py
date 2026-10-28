import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("bash") and shutil.which("git"), "Linux shell integration")
class AutoUpdateSetupTests(unittest.TestCase):
    def test_archive_install_bootstraps_a_clean_trusted_checkout(self):
        with tempfile.TemporaryDirectory(prefix="narwhal-auto-update-setup-") as temp:
            root = Path(temp)
            origin = root / "trusted-origin.git"
            seed = root / "seed"
            base = root / "base"
            units = root / "units"
            fake_bin = root / "bin"
            installer_dir = root / "downloaded-installer"
            for path in (seed / "scripts", units, fake_bin, installer_dir):
                path.mkdir(parents=True, exist_ok=True)

            def git(*args):
                return subprocess.run(["git", *args], check=True, capture_output=True, text=True)

            git("init", "--bare", str(origin))
            git("init", str(seed))
            git("-C", str(seed), "config", "user.name", "Narwhal Test")
            git("-C", str(seed), "config", "user.email", "narwhal-test@example.invalid")
            (seed / "scripts" / "auto-update.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            git("-C", str(seed), "add", "scripts/auto-update.sh")
            git("-C", str(seed), "commit", "-m", "test fixture")
            git("-C", str(seed), "branch", "-M", "main")
            git("-C", str(seed), "remote", "add", "origin", str(origin))
            git("-C", str(seed), "push", "-u", "origin", "main")

            systemctl = fake_bin / "systemctl"
            systemctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            systemctl.chmod(0o755)

            source = (ROOT / "scripts" / "setup-auto-update.sh").read_text(encoding="utf-8")
            source = source.replace('TRUSTED_REPO="https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git"', f'TRUSTED_REPO="{origin}"')
            source = source.replace('BASE_DIR="/opt/narwhal-monitor"', f'BASE_DIR="{base}"')
            source = source.replace('cat >"/etc/systemd/system/$SERVICE_NAME"', f'cat >"{units}/$SERVICE_NAME"')
            source = source.replace('cat >"/etc/systemd/system/$TIMER_NAME"', f'cat >"{units}/$TIMER_NAME"')
            source = source.replace(
                'if [[ ${EUID:-$(id -u)} -ne 0 ]]; then\n  echo "setup-auto-update.sh must run as root" >&2\n  exit 1\nfi\n',
                "",
            )
            script = root / "setup-auto-update.sh"
            script.write_text(source, encoding="utf-8")
            env = {**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]}
            result = subprocess.run(
                ["bash", str(script), "client", str(installer_dir)],
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Bootstrapped a clean, trusted update checkout", result.stdout)

            fallback = base / "client-update-repo"
            config = (base / "client-auto-update.env").read_text(encoding="utf-8")
            repo_value = next(line.split("=", 1)[1] for line in config.splitlines() if line.startswith("AUTO_UPDATE_REPO_DIR="))
            self.assertEqual(shlex.split(repo_value), [str(fallback)])
            self.assertTrue((fallback / ".git").is_dir())
            self.assertEqual(git("-C", str(fallback), "remote", "get-url", "origin").stdout.strip(), str(origin))
            self.assertTrue((base / "auto-update.sh").is_file())
            self.assertTrue((units / "narwhal-monitor-client-update.timer").is_file())
