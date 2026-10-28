"""Run the browser regression suite only against synthetic loopback fixtures."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = Path(os.environ.get("NARWHAL_UI_OUTPUT_ROOT", Path(tempfile.gettempdir()) / "narwhal-ui-regressions"))

CASES = [
    ("test_abuse_ui.cjs", ["-m", "tests.abuse_preview"], 8787),
    ("test_admission_ui.cjs", ["-m", "tests.admission_preview"], 8795),
    ("test_commerce_balances_ui.cjs", ["-m", "tests.commerce_preview"], 8793),
    ("test_disk_cleanup_ui.cjs", ["-m", "tests.disk_cleanup_preview"], 8788),
    ("test_echarts_security_ui.cjs", None, None),
    ("test_firewall_host_switch_ui.cjs", None, None),
    ("test_header_ui.cjs", ["-m", "tests.tcping_auto_preview"], 8791),
    ("test_login_ui.cjs", ["-m", "tests.login_preview"], 8786),
    ("test_password_review_ui.cjs", ["-m", "tests.password_review_preview"], 8793),
    ("test_tcping_auto_ui.cjs", ["-m", "tests.tcping_auto_preview"], 8791),
    ("test_tcping_carriers_ui.cjs", ["-m", "http.server", "8795", "--bind", "127.0.0.1", "--directory", str(ROOT / "server" / "static")], 8795),
    ("test_tcping_stock_ui.cjs", ["-m", "tests.tcping_stock_preview"], 8794),
    ("test_tcping_carriers.cjs", None, None),
]


def wait_for_port(process: subprocess.Popen, port: int, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Preview process exited early with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                time.sleep(0.25)
                if process.poll() is not None:
                    raise RuntimeError(f"Preview process exited after opening the port with code {process.returncode}")
                return
        except OSError:
            time.sleep(0.25)
    raise TimeoutError(f"Synthetic preview did not open 127.0.0.1:{port}")


def run_case(node: str, script: str, preview: list[str] | None, port: int | None) -> None:
    print(f"\n=== {script} ===", flush=True)
    env = os.environ.copy()
    output = OUTPUT_ROOT / Path(script).stem
    output.mkdir(parents=True, exist_ok=True)
    env["NARWHAL_UI_OUTPUT"] = str(output)
    browser_modules = str(ROOT / "tests" / "browser-runtime" / "node_modules")
    env["NODE_PATH"] = os.pathsep.join(filter(None, (browser_modules, env.get("NODE_PATH", ""))))
    process = None
    try:
        if preview:
            command = [sys.executable, *preview]
            env["NARWHAL_PREVIEW_PORT"] = "8793"
            try:
                with socket.create_connection(("127.0.0.1", port or 0), timeout=0.25):
                    raise RuntimeError(f"Refusing to run against an existing listener on 127.0.0.1:{port}")
            except OSError:
                pass
            process = subprocess.Popen(command, cwd=ROOT, env=env)
            wait_for_port(process, port or 0)
        subprocess.run([node, str(ROOT / "tests" / script)], cwd=ROOT, env=env, check=True)
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main() -> int:
    node = os.environ.get("NODE_BINARY") or shutil.which("node")
    if not node:
        print("Node.js is required to run UI regression scripts.", file=sys.stderr)
        return 2
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    for script, preview, port in CASES:
        run_case(node, script, preview, port)
    print(f"\nAll {len(CASES)} UI regression scripts passed. Screenshots: {OUTPUT_ROOT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
