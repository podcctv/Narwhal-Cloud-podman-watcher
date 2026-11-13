"""Tests for Phase 2 upgrade/rollback hardening and architecture detection."""
from __future__ import annotations

import hashlib
import hmac
import http.server
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
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


class ProbeDistributionAndChecksumTests(unittest.TestCase):
    def _extract_probe_python(self) -> str:
        installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        marker = "python3 - \"$arch\" \"$dest_path\" \"$server_url\" \"$secret\" \"$ca_file\" <<'PY' || true\n"
        start = installer.index(marker) + len(marker)
        end = installer.index("\nPY\n", start)
        return installer[start:end] + "\n"

    def test_ci_workflow_and_dockerfile_probe_contracts(self):
        workflow = (ROOT / ".github" / "workflows" / "build-and-push-ghcr.yml").read_text(encoding="utf-8")
        self.assertIn("rust-probe:", workflow)
        self.assertIn("x86_64-unknown-linux-musl", workflow)
        self.assertIn("aarch64-unknown-linux-musl", workflow)
        self.assertIn("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc", workflow)
        self.assertIn("narwhal-probe-binaries", workflow)
        self.assertIn("needs: [test, rust-probe, compatibility-tests, image-architecture-smoke]", workflow)
        self.assertIn("path: server/client_bins", workflow)
        self.assertIn("git diff --quiet HEAD^ HEAD -- client server scripts rust", workflow)

        dockerfile = (ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY client_bins/ client_bins/", dockerfile)
        self.assertTrue((ROOT / "server" / "client_bins" / ".gitkeep").is_file())

        installer = (ROOT / "scripts" / "install-client.sh").read_text(encoding="utf-8")
        self.assertIn("fetch_narwhal_probe()", installer)

    def test_server_probe_endpoints_auth_404_and_download(self):
        from fastapi.testclient import TestClient
        from server import app as server_app

        with tempfile.TemporaryDirectory(prefix="narwhal-probe-srv-") as temp:
            bins_dir = Path(temp)
            secret = "test-probe-secret"
            with (
                patch.object(server_app, "SHARED_SECRET", secret),
                patch.dict(os.environ, {"NARWHAL_CLIENT_BINS_DIR": str(bins_dir)}),
            ):
                client = TestClient(server_app.app)

                # Unauthenticated requests are rejected.
                self.assertEqual(client.get("/api/v1/update/probe/sha256").status_code, 401)
                self.assertEqual(client.get("/api/v1/update/probe/amd64").status_code, 401)

                def auth_headers() -> tuple[str, dict[str, str]]:
                    ts = str(int(time.time()))
                    sig = hmac.new(secret.encode(), ts.encode(), hashlib.sha256).hexdigest()
                    return ts, {"X-Timestamp": ts, "X-Signature": sig}

                # Empty client_bins returns 404 cleanly.
                _, hdrs = auth_headers()
                self.assertEqual(client.get("/api/v1/update/probe/sha256", headers=hdrs).status_code, 404)
                self.assertEqual(client.get("/api/v1/update/probe/amd64", headers=hdrs).status_code, 404)

                # Bundled amd64 binary + SHA256SUMS returns 200 with signed checksums.
                payload = b"\x7fELF-mock-narwhal-probe-amd64"
                digest = hashlib.sha256(payload).hexdigest()
                sums = f"{digest}  narwhal-probe-amd64\n".encode("utf-8")
                (bins_dir / "narwhal-probe-amd64").write_bytes(payload)
                (bins_dir / "SHA256SUMS").write_bytes(sums)

                ts, hdrs = auth_headers()
                sha_resp = client.get("/api/v1/update/probe/sha256", headers=hdrs)
                self.assertEqual(sha_resp.status_code, 200)
                self.assertEqual(sha_resp.content, sums)
                expected_resp_sig = hmac.new(
                    secret.encode(), sums + ts.encode(), hashlib.sha256
                ).hexdigest()
                self.assertEqual(sha_resp.headers.get("X-Narwhal-Response-Signature"), expected_resp_sig)

                _, hdrs = auth_headers()
                bin_resp = client.get("/api/v1/update/probe/amd64", headers=hdrs)
                self.assertEqual(bin_resp.status_code, 200)
                self.assertEqual(bin_resp.content, payload)

                # Missing arm64 still returns 404.
                self.assertEqual(client.get("/api/v1/update/probe/arm64", headers=hdrs).status_code, 404)

    def test_client_probe_fetch_verifies_checksum_and_falls_back_gracefully(self):
        script_code = self._extract_probe_python()
        secret = "client-fetch-secret"
        valid_binary = b"#!/bin/sh\necho probe-v1\n"
        valid_sha = hashlib.sha256(valid_binary).hexdigest()
        sums_body = f"{valid_sha}  narwhal-probe-amd64\n".encode("utf-8")

        state = {
            "sha_status": 200,
            "sha_body": sums_body,
            "bad_sig": False,
            "bin_status": 200,
            "bin_body": valid_binary,
            "bin_requests": 0,
        }

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                ts = self.headers.get("X-Timestamp", "")
                sig = self.headers.get("X-Signature", "")
                expected = hmac.new(secret.encode(), ts.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, sig):
                    self.send_response(401)
                    self.end_headers()
                    return
                if self.path == "/api/v1/update/probe/sha256":
                    self.send_response(state["sha_status"])
                    body = state["sha_body"]
                    resp_sig = (
                        "0" * 64
                        if state["bad_sig"]
                        else hmac.new(secret.encode(), body + ts.encode(), hashlib.sha256).hexdigest()
                    )
                    self.send_header("X-Narwhal-Response-Signature", resp_sig)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path == "/api/v1/update/probe/amd64":
                    state["bin_requests"] += 1
                    self.send_response(state["bin_status"])
                    body = state["bin_body"]
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory(prefix="narwhal-probe-cli-") as temp:
                helper = Path(temp) / "fetch.py"
                helper.write_text(script_code, encoding="utf-8")
                dest = Path(temp) / "bin" / "narwhal-probe"
                dest.parent.mkdir(parents=True, exist_ok=True)

                # 1. Valid download and verification succeeds.
                res = subprocess.run(
                    [sys.executable, str(helper), "amd64", str(dest), url, secret, ""],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(dest.read_bytes(), valid_binary)
                self.assertEqual(state["bin_requests"], 1)

                # 2. Re-running with matching SHA256 skips re-download.
                res2 = subprocess.run(
                    [sys.executable, str(helper), "amd64", str(dest), url, secret, ""],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
                self.assertEqual(state["bin_requests"], 1)

                # 3. Checksum mismatch is non-fatal and does not overwrite/create dest.
                dest.unlink()
                state["bin_body"] = b"corrupted-binary"
                res3 = subprocess.run(
                    [sys.executable, str(helper), "amd64", str(dest), url, secret, ""],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res3.returncode, 0, res3.stdout + res3.stderr)
                self.assertFalse(dest.exists())
                self.assertIn("SHA256 mismatch", res3.stdout)

                # 4. Bad response signature on SHA256SUMS is non-fatal and skips binary fetch.
                prev_reqs = state["bin_requests"]
                state["bad_sig"] = True
                res4 = subprocess.run(
                    [sys.executable, str(helper), "amd64", str(dest), url, secret, ""],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res4.returncode, 0, res4.stdout + res4.stderr)
                self.assertEqual(state["bin_requests"], prev_reqs)
                self.assertFalse(dest.exists())

                # 5. Server 404 is non-fatal.
                state["bad_sig"] = False
                state["sha_status"] = 404
                res5 = subprocess.run(
                    [sys.executable, str(helper), "amd64", str(dest), url, secret, ""],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(res5.returncode, 0, res5.stdout + res5.stderr)
                self.assertFalse(dest.exists())
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
