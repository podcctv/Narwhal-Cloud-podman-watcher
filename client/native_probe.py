"""Bridge to the optional static Rust `narwhal-probe` CLI binary."""

from __future__ import annotations

import atexit
import json
import os
import select
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

MAX_STDOUT_BYTES = 8 * 1024 * 1024
_ORIG_SUBPROCESS_RUN = subprocess.run
_SERVE_LOCK = threading.Lock()
_serve_proc: subprocess.Popen[bytes] | None = None
_serve_binary: str = ""


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


def close_serve_process() -> None:
    """Terminate the persistent `narwhal-probe serve` child process if running."""
    global _serve_proc, _serve_binary
    proc = _serve_proc
    _serve_proc = None
    _serve_binary = ""
    if proc is None:
        return
    for stream in (proc.stdin, proc.stdout):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=1.0)
    except (OSError, subprocess.SubprocessError):
        try:
            proc.kill()
        except OSError:
            pass


atexit.register(close_serve_process)


def _readline_bounded(stdout: Any, timeout: float) -> bytes | None:
    """Read a single newline-terminated line within `timeout` seconds and `MAX_STDOUT_BYTES`."""
    deadline = time.monotonic() + max(0.05, float(timeout))
    buf = bytearray()
    fd = stdout.fileno()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None
        chunk = os.read(fd, 65536)
        if not chunk:
            return None
        buf.extend(chunk)
        if len(buf) > MAX_STDOUT_BYTES:
            return None
        nl = buf.find(b"\n")
        if nl != -1:
            return bytes(buf[:nl])


def _run_via_serve(binary: Path, args: List[str], timeout: float) -> Dict[str, Any] | None:
    """Send a single tab-delimited command over the persistent `serve` pipe."""
    global _serve_proc, _serve_binary
    if any(("\t" in a or "\n" in a or "\r" in a) for a in args):
        return None
    bin_str = str(binary)
    line = ("\t".join(args) + "\n").encode("utf-8")
    with _SERVE_LOCK:
        if _serve_proc is None or _serve_proc.poll() is not None or _serve_binary != bin_str:
            close_serve_process()
            try:
                _serve_proc = subprocess.Popen(
                    [bin_str, "serve"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                _serve_binary = bin_str
            except (OSError, subprocess.SubprocessError, ValueError):
                close_serve_process()
                return None

        proc = _serve_proc
        if proc is None or proc.stdin is None or proc.stdout is None:
            close_serve_process()
            return None
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
            raw = _readline_bounded(proc.stdout, timeout)
        except (OSError, ValueError):
            close_serve_process()
            return None
        if raw is None:
            close_serve_process()
            return None

    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, TypeError):
        with _SERVE_LOCK:
            close_serve_process()
        return None
    if not isinstance(payload, dict) or payload.get("ok") is False:
        return None
    return payload


def run_probe(args: List[str], timeout: float = 5.0) -> Dict[str, Any] | None:
    """Execute `narwhal-probe` with bounded output and return parsed JSON dict or None."""
    binary = probe_binary_path()
    if (
        os.name == "posix"
        and os.getenv("NARWHAL_NATIVE_PROBE_SERVE", "1").strip() != "0"
        and subprocess.run is _ORIG_SUBPROCESS_RUN
    ):
        served = _run_via_serve(binary, args, timeout)
        if served is not None:
            return served

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


def diskstats(proc_root: str | os.PathLike[str] = "/proc") -> Dict[str, Any] | None:
    """Collect host `/proc/diskstats` per-device counters via `narwhal-probe diskstats`."""
    if not proc_root or not is_available():
        return None
    return run_probe(["diskstats", "--proc-root", str(proc_root)])
