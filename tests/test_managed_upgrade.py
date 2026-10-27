"""Linux shell transaction tests. All systemctl/git/pip calls are local fakes."""
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ClientPackagingTests(unittest.TestCase):
    def test_installer_copies_incus_metrics_module(self):
        installer=(ROOT/"scripts"/"install-client.sh").read_text(encoding="utf-8")
        self.assertIn('cp "$ROOT_DIR/client/incus_metrics.py" "$CLIENT_APP_DIR/incus_metrics.py"',installer)

    def test_managed_upgrade_validates_and_snapshots_incus_metrics(self):
        updater=(ROOT/"scripts"/"managed-client-update.sh").read_text(encoding="utf-8")
        self.assertGreaterEqual(updater.count("incus_metrics"),4)
        self.assertIn("wait_for_client_stable",updater)
        self.assertIn("systemctl show --no-pager --property=ActiveState,SubState,MainPID,NRestarts",updater)
        self.assertIn("&& wait_for_client_stable; then",updater)


@unittest.skipUnless(os.name=="posix" and shutil.which("bash") and shutil.which("flock"),"Linux shell integration")
class ManagedUpgradeTests(unittest.TestCase):
    def run_worker(self, fail=False, dirty=False, unstable=False):
        with tempfile.TemporaryDirectory(prefix="narwhal-upgrade-test-") as temp:
            root=Path(temp)
            base=root/"base"
            app=base/"client-agent"
            bins=root/"bin"
            fixture=root/"release"
            repo=root/"repo"
            for p in (base,app,bins,fixture/"client",fixture/"scripts",repo/".git",app/".venv"/"bin"):
                p.mkdir(parents=True,exist_ok=True)
            def executable(path,text):
                path.write_text(text)
                path.chmod(0o755)
            (app/"agent.py").write_text("old_agent=True\n")
            (app/"operations.py").write_text("old_operations=True\n")
            (app/"requirements.txt").write_text("")
            (base/"client.env").write_text("NARWHAL_VERSION=1.6.74\n")
            (base/"client-auto-update.env").write_text("AUTO_UPDATE_REPO_DIR="+shlex.quote(str(repo))+"\n")
            (fixture/"client"/"agent.py").write_text("new_agent=True\n")
            (fixture/"client"/"operations.py").write_text("new_operations=True\n")
            (fixture/"client"/"security_banner.py").write_text("new_banner=True\n")
            (fixture/"client"/"requirements.txt").write_text("")
            executable(fixture/"scripts"/"install-client.sh",f"#!/bin/bash\ncp {shlex.quote(str(fixture/'client'/'agent.py'))} {shlex.quote(str(app/'agent.py'))}\nprintf 'NARWHAL_VERSION=1.7.0\\n' >{shlex.quote(str(base/'client.env'))}\nsystemctl restart narwhal-monitor-client.service\nexit {1 if fail else 0}\n")
            executable(app/".venv"/"bin"/"python","#!/bin/bash\nexit 0\n")
            executable(app/".venv"/"bin"/"pip","#!/bin/bash\nexit 0\n")
            systemctl_state=root/"systemctl-restarts"
            executable(bins/"systemctl",f"""#!/bin/bash
state_file={shlex.quote(str(systemctl_state))}
if [[ "$1" == restart ]]; then
  count=0
  [[ ! -f "$state_file" ]] || count=$(cat "$state_file")
  printf '%s\\n' "$((count+1))" >"$state_file"
fi
if [[ "$1" == show ]]; then
  count=0
  [[ ! -f "$state_file" ]] || count=$(cat "$state_file")
  if [[ {1 if unstable else 0} == 1 && "$count" -lt 2 ]]; then
    printf 'ActiveState=activating\\nSubState=auto-restart\\nMainPID=0\\nNRestarts=1\\n'
  else
    printf 'ActiveState=active\\nSubState=running\\nMainPID=1234\\nNRestarts=0\\n'
  fi
fi
exit 0
""")
            executable(bins/"git",f"""#!/bin/bash
shift 2
case "$1" in
 remote) printf '%s\\n' https://github.com/podcctv/Narwhal-Cloud-podman-watcher.git ;;
 status) {'echo dirty' if dirty else ':'} ;;
 fetch|merge-base|merge) exit 0 ;;
 rev-parse) printf '%s\\n' {'a'*40} ;;
 show) printf '1.7.0\\n' ;;
 archive) tar -c -C {shlex.quote(str(fixture))} . ;;
 *) exit 2 ;;
esac
""")
            script=root/"worker.sh"
            source=(ROOT/"scripts"/"managed-client-update.sh").read_text(encoding="utf-8")
            source=source.replace("/opt/narwhal-monitor",str(base)).replace("/run/narwhal-monitor-client-auto-update.lock",str(root/"auto-update.lock"))
            source=source.replace("local timeout_seconds=45 stable_seconds=15","local timeout_seconds=3 stable_seconds=1")
            script.write_text(source)
            env={**os.environ,"PATH":str(bins)+os.pathsep+os.environ["PATH"]}
            result=subprocess.run(["bash",str(script),"upgrade","a"*40,"1.7.0","17"],env=env,text=True,capture_output=True,timeout=30)
            if dirty:
                self.assertNotEqual(result.returncode,0)
                self.assertIn("old_agent",(app/"agent.py").read_text())
                self.assertFalse((base/"client-previous").exists())
                return
            should_fail=fail or unstable
            self.assertEqual(result.returncode,1 if should_fail else 0,result.stdout+result.stderr)
            self.assertIn("old_agent" if should_fail else "new_agent",(app/"agent.py").read_text())
            self.assertIn("1.6.74" if should_fail else "1.7.0",(base/"client.env").read_text())
            receipt=json.loads((base/"managed-update-result.json").read_text())
            self.assertEqual(receipt["status"],"failed" if should_fail else "installed")
            self.assertEqual(receipt["action_id"],17)
            self.assertFalse(list(base.glob("managed-stage.*")))
            if not should_fail:
                rollback=subprocess.run(["bash",str(script),"rollback","18"],env=env,text=True,capture_output=True,timeout=30)
                self.assertEqual(rollback.returncode,0,rollback.stdout+rollback.stderr)
                self.assertIn("old_agent",(app/"agent.py").read_text())
                self.assertIn("1.6.74",(base/"client.env").read_text())

    def test_success_and_explicit_rollback(self):
        self.run_worker()

    def test_installer_failure_restores_previous(self):
        self.run_worker(fail=True)

    def test_unstable_service_is_not_marked_installed(self):
        self.run_worker(unstable=True)

    def test_dirty_checkout_preserved(self):
        self.run_worker(dirty=True)
