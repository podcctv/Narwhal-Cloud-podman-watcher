"""Bridge to the optional static Rust `narwhal-probe` CLI binary."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

MAX_STDOUT_BYTES = 8 * 1024 * 1024


def probe_binary_path() -> Path:
    """Return the configured or default path to the `narwhal-probe` binary."""
    override = os.getenv("NARWHAL_NATIVE_PROBE_PATH", "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent / "bin" / "narwhal-probe"


def is_available() -> bool:
    """Return True iff the native probe is enabled, supported on POSIX, and executable."""
    if os.name != "posix":
        return False
    if os.getenv("NARWHAL_NATIVE_PROBE", "1").strip() == "0":
        return False
    path = probe_binary_path()
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def run_probe(args: List[str], timeout: float = 5.0) -> Dict[str, Any] | None:
    """Execute `narwhal-probe` with bounded output and return parsed JSON dict or None."""
    binary = probe_binary_path()
    try:
        proc = subprocess.run(
            [str(binary), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout or b""
    if len(raw) > MAX_STDOUT_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def proc_snapshot(
    init_pid: int, scan_limit: int = 20000, clock_ticks: float = 100.0
) -> Dict[str, Any] | None:
    """Collect a container process tree snapshot via `narwhal-probe proc-snapshot`."""
    if init_pid <= 0 or not is_available():
        return None
    return run_probe(
        [
            "proc-snapshot",
            "--init-pid",
            str(int(init_pid)),
            "--scan-limit",
            str(int(scan_limit)),
            "--clock-ticks",
            str(float(clock_ticks)),
        ]
    )


def socket_sec(pid: int) -> Dict[str, Any] | None:
    """Collect `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` tables via `narwhal-probe socket-sec`."""
    if pid <= 0 or not is_available():
        return None
    return run_probe(["socket-sec", "--pid", str(int(pid))])


def conntrack(limit: int = 50000) -> Dict[str, Any] | None:
    """Collect host conntrack entries via `narwhal-probe conntrack`."""
    if limit <= 0 or not is_available():
        return None
    return run_probe(["conntrack", "--limit", str(int(limit))])
