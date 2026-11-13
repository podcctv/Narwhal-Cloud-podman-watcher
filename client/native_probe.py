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
    return Path(os.path.abspath(__file__)).parent / "bin" / "narwhal-probe"


def is_available() -> bool:
    """Return True iff the native probe is enabled, supported on POSIX, and executable."""
    if os.name != "posix":
        return False
    if os.getenv("NARWHAL_NATIVE_PROBE", "1").strip() == "0":
        return False
    path = probe_binary_path()
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except (OSError, TypeError):
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


def psi_snapshot(
    cgroup_dir: str | os.PathLike[str] | None = None,
    proc_root: str | os.PathLike[str] = "/proc",
) -> Dict[str, Any] | None:
    """Collect host PSI, `/proc/stat` CPU counters, and optional cgroup PSI via `narwhal-probe`."""
    if not is_available():
        return None
    args = ["psi-snapshot", "--proc-root", str(proc_root)]
    if cgroup_dir is not None:
        args.extend(["--cgroup-dir", str(cgroup_dir)])
    return run_probe(args)


def cgroup_metrics(cgroup_dir: str | os.PathLike[str]) -> Dict[str, Any] | None:
    """Collect cgroup v2 cpu/memory/io counters via `narwhal-probe cgroup-metrics`."""
    if not cgroup_dir or not is_available():
        return None
    return run_probe(["cgroup-metrics", "--cgroup-dir", str(cgroup_dir)])


def proc_sockets(
    init_pid: int, pids: List[int], max_fds: int = 4096
) -> Dict[str, Any] | None:
    """Collect `/proc/<init_pid>/net/*` sockets attributed to `pids` via `narwhal-probe proc-sockets`."""
    if init_pid <= 0 or not pids or max_fds <= 0 or not is_available():
        return None
    clean_pids = [str(int(pid)) for pid in pids if int(pid) > 0]
    if not clean_pids:
        return None
    return run_probe(
        [
            "proc-sockets",
            "--init-pid",
            str(int(init_pid)),
            "--pids",
            ",".join(clean_pids),
            "--max-fds",
            str(int(max_fds)),
        ]
    )


def host_metrics(proc_root: str | os.PathLike[str] = "/proc") -> Dict[str, Any] | None:
    """Collect host uptime, loadavg, cpu, meminfo, and net/dev via `narwhal-probe host-metrics`."""
    if not proc_root or not is_available():
        return None
    return run_probe(["host-metrics", "--proc-root", str(proc_root)])
