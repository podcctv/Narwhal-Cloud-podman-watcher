"""Execute generated remediation scripts against fixtures, never real /proc.

Signal, sleep and service commands are shell stubs. This catches shell expansion
bugs that mocked subprocess return values cannot detect, on Linux and Git Bash.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import agent


SHELL = shutil.which("sh")
if not SHELL and os.name == "nt":
    git_bash = Path("C:/Program Files/Git/bin/bash.exe")
    if git_bash.is_file():
        SHELL = str(git_bash)


@unittest.skipUnless(SHELL, "POSIX shell required")
class RemediationShellTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()

    def process(self, pid, comm, argv, state="S"):
        directory = self.proc / str(pid)
        directory.mkdir()
        (directory / "comm").write_text(comm + "\n", encoding="utf-8")
        (directory / "stat").write_text(f"{pid} ({comm}) {state}\n", encoding="utf-8")
        (directory / "cmdline").write_bytes(b"\0".join(s.encode() for s in argv) + b"\0")
        (directory / "cgroup").write_text("", encoding="utf-8")

    def execute(self, script, fail_signal=False):
        # Every read/delete target is remapped beneath the temporary directory.
        for source in ("/usr/lib/systemd/system", "/etc/systemd/system",
                       "/lib/systemd/system", "/run/systemd/system", "/etc/init.d",
                       "/etc/supervisor", "/etc/cron.d", "/etc/cron.daily",
                       "/etc/cron.hourly", "/var/spool/cron", "/proc/"):
            target = self.root.as_posix() + source
            script = script.replace(source, target)
        prefix = (
            "sleep() { :; }; systemctl() { :; }; rc-service() { :; }; "
            "rc-update() { :; }; supervisorctl() { :; }; "
            "kill() { printf 'fixture_signal=%s:%s\\n' \"$1\" \"$2\"; "
            + ("return 1; " if fail_signal else "return 0; ") + "}; "
        )
        result = subprocess.run([SHELL, "-c", prefix + script], capture_output=True,
                                text=True, timeout=20)
        return result.returncode == 0, result.stdout + result.stderr

    def fallback(self, fail_signal=False, **kwargs):
        with mock.patch.object(agent, "_incus_instance_pid", return_value=9876), \
             mock.patch.object(agent.shutil, "which", return_value="/usr/bin/nsenter"), \
             mock.patch.object(agent, "_run_action_command",
                               side_effect=lambda cmd: self.execute(cmd[-1], fail_signal)):
            return agent._incus_host_namespace_kill(
                "incus", "node1", "default", ["xboard-node"], **kwargs)

    def test_fallback_expands_proc_and_matches_openrc_supervisor(self):
        self.process(446, "supervise-daemo", ["supervise-daemon", "flyair-reality-tokyo",
                     "--user", "flyair-node", "/opt/flyair-reality-tokyo/xboard-node"])
        self.process(447, "xboard-node", ["/opt/flyair-reality-tokyo/xboard-node"])
        self.process(1, "xboard-node", ["xboard-node"])
        self.process(449, "xboard-node", ["xboard-node"], state="Z")
        self.process(450, "cat", ["cat", "/opt/flyair-reality-tokyo/xboard-node"])
        matched, killed, errors, output = self.fallback()
        self.assertEqual((matched, killed, errors), (2, 2, 0), output)
        self.assertIn("fixture_signal=-TERM:446", output)
        self.assertIn("fixture_signal=-TERM:447", output)
        for pid in (1, 449, 450):
            self.assertNotIn(f"fixture_signal=-TERM:{pid}\n", output)

    def test_supervisor_argv_glob_does_not_match_unrelated_filename(self):
        self.process(446, "supervise-daemo", ["supervise-daemon", "/opt/xboard-*"])
        (self.root / "xboard-node").touch()
        matched, killed, errors, output = self.fallback()
        self.assertEqual((matched, killed, errors), (0, 0, 0), output)

    def test_fallback_reports_signal_permission_failure(self):
        self.process(447, "xboard-node", ["/opt/flyair-reality-tokyo/xboard-node"])
        matched, killed, errors, output = self.fallback(fail_signal=True)
        self.assertEqual((matched, killed, errors), (1, 0, 1), output)
        self.assertIn("@@NW_ACTION\tprocess\txboard-node:447\tfailed", output)

    def test_fallback_pid_restriction_is_preserved(self):
        self.process(446, "xboard-node", ["xboard-node"])
        self.process(447, "xboard-node", ["xboard-node"])
        matched, killed, errors, output = self.fallback(process_pids=[447], restrict_pids=True)
        self.assertEqual((matched, killed, errors), (1, 1, 0), output)
        self.assertNotIn("fixture_signal=-TERM:446", output)

    def test_zero_changes_keep_diagnostics_and_verify_remaining_supervisor(self):
        self.process(446, "supervise-daemo", ["supervise-daemon", "flyair-reality-tokyo",
                     "/opt/flyair-reality-tokyo/xboard-node"])
        self.process(447, "xboard-node", ["/opt/flyair-reality-tokyo/xboard-node"])
        action = {"runtime": "incus", "project": "default", "container_name": "node1",
                  "params": {"process_patterns": ["xboard-node"]}}
        with mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), \
             mock.patch.object(agent, "_incus_host_namespace_kill",
                               return_value=(0, 0, 0, "host namespace fallback unavailable")), \
             mock.patch.object(agent, "_run_action_command",
                               side_effect=lambda cmd: self.execute(cmd[-1], fail_signal=True)):
            ok, output = agent.remediate_panel_pairing(action)
        self.assertFalse(ok, output)
        self.assertIn("matched_processes=2 signal_errors=2", output)
        self.assertIn("host namespace fallback unavailable", output)
        self.assertIn("remaining_processes=2", output)

    def test_host_fallback_can_recover_container_signal_failure(self):
        action = {"runtime": "incus", "project": "default", "container_name": "node1",
                  "params": {"process_patterns": ["xboard-node"]}}
        results = [(False, "killed_processes=0 removed_services=0 removed_configs=0 "
                    "cleanup_errors=0 matched_processes=2 signal_errors=2"),
                   (True, "remaining_processes=0")]
        with mock.patch.object(agent, "get_runtime_bins", return_value={"incus": "incus"}), \
             mock.patch.object(agent, "_incus_host_namespace_kill", return_value=(
                 2, 2, 0, "host_matched_processes=2 host_killed_processes=2 host_kill_errors=0")), \
             mock.patch.object(agent, "_run_action_command", side_effect=results):
            ok, output = agent.remediate_panel_pairing(action)
        self.assertTrue(ok, output)
        self.assertIn("killed_processes=2", output)
        self.assertIn("signal_errors=2", output)
        self.assertIn("remaining_processes=0", output)

