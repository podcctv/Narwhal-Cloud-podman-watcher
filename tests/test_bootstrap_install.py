import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = ROOT / "scripts" / "bootstrap-install.sh"


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}")
    return result.stdout


class BootstrapInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = shutil.which("bash")
        if not cls.bash and os.name == "nt":
            candidate = Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Git" / "bin" / "bash.exe"
            if candidate.is_file():
                cls.bash = str(candidate)

    def test_existing_dirty_repository_is_stashed_before_remote_update(self):
        if not self.bash:
            self.skipTest("bash is required to exercise the shell installer")
        if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.skipTest("the bootstrap installer deliberately requires a root POSIX shell")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            remote = root / "remote.git"
            install_base = root / "install"
            source.mkdir()
            (source / "scripts").mkdir()
            shutil.copy2(BOOTSTRAP, source / "scripts" / "bootstrap-install.sh")
            (source / "scripts" / "install.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            (source / ".gitignore").write_text(".env\n", encoding="utf-8")
            (source / "tracked.txt").write_text("old\n", encoding="utf-8")
            run("git", "init", "--initial-branch=main", cwd=source)
            run("git", "add", ".", cwd=source)
            run("git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "initial", cwd=source)
            run("git", "clone", "--bare", str(source), str(remote))
            run("git", "remote", "add", "origin", str(remote), cwd=source)

            target = install_base / remote.stem
            target.parent.mkdir()
            run("git", "clone", str(remote), str(target))
            (target / "tracked.txt").write_text("operator edit\n", encoding="utf-8")
            (target / "new-file.txt").write_text("operator untracked file\n", encoding="utf-8")
            (target / ".env").write_text("KEEP_ME=1\n", encoding="utf-8")

            (source / "tracked.txt").write_text("new release\n", encoding="utf-8")
            (source / "new-file.txt").write_text("now tracked\n", encoding="utf-8")
            run("git", "add", ".", cwd=source)
            run("git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-m", "release", cwd=source)
            run("git", "push", "origin", "main", cwd=source)

            env = os.environ | {"REPO_URL": str(remote), "INSTALL_BASE_DIR": str(install_base)}
            output = run(self.bash, str(BOOTSTRAP), env=env)

            self.assertIn("保存到 Git stash", output)
            self.assertEqual((target / "tracked.txt").read_text(encoding="utf-8"), "new release\n")
            self.assertEqual((target / "new-file.txt").read_text(encoding="utf-8"), "now tracked\n")
            self.assertEqual((target / ".env").read_text(encoding="utf-8"), "KEEP_ME=1\n")
            stash = run("git", "stash", "list", "-1", cwd=target)
            self.assertIn("narwhal-bootstrap before update", stash)


if __name__ == "__main__":
    unittest.main()
