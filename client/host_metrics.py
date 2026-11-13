"""Host-level /proc metrics sampling (uptime, loadavg, cpu, meminfo, net/dev) with native probe bridge."""

from __future__ import annotations

import builtins
import math
import os
from pathlib import Path
from typing import Any, Dict, List

try:
    from client import native_probe
except ImportError:
    import native_probe

_ORIG_OPEN = builtins.open
_ORIG_OS_GETLOADAVG = getattr(os, "getloadavg", None)

_AGENT_NAMESPACES: List[Dict[str, Any]] = []

_MEMINFO_KEYS = {
    "MemTotal": "mem_total_bytes",
    "MemAvailable": "mem_available_bytes",
    "MemFree": "mem_free_bytes",
    "Buffers": "buffers_bytes",
    "Cached": "cached_bytes",
    "SwapTotal": "swap_total_bytes",
    "SwapFree": "swap_free_bytes",
}


def register_agent_module(ns_or_mod: Any) -> None:
    """Register an agent facade module or namespace dict so patched attributes are honored."""
    ns = ns_or_mod if isinstance(ns_or_mod, dict) else getattr(ns_or_mod, "__dict__", None)
    if ns is not None and ns not in _AGENT_NAMESPACES:
        _AGENT_NAMESPACES.append(ns)


def _has_mocked_host_primitives() -> bool:
    if builtins.open is not _ORIG_OPEN:
        return True
    if getattr(os, "getloadavg", None) is not _ORIG_OS_GETLOADAVG:
        return True
    for ns in _AGENT_NAMESPACES:
        ns_os = ns.get("os")
        if ns_os is not None and (
            ns_os is not os
            or getattr(ns_os, "getloadavg", None) is not _ORIG_OS_GETLOADAVG
        ):
            return True
    return False


def _read_proc_text(path: Path, limit: int = 65536) -> str:
    try:
        with open(str(path), "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def parse_uptime(text: str) -> float | None:
    """Parse `/proc/uptime` and return uptime in seconds or None."""
    parts = text.split()
    if not parts:
        return None
    try:
        value = float(parts[0])
    except ValueError:
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return value


def parse_loadavg(text: str) -> Dict[str, Any]:
    """Parse `/proc/loadavg` into `{available, m1, m5, m15}`."""
    parts = text.split()
    if len(parts) < 3:
        return {"available": False}
    try:
        m1, m5, m15 = float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return {"available": False}
    if not (math.isfinite(m1) and math.isfinite(m5) and math.isfinite(m15)):
        return {"available": False}
    return {"available": True, "m1": m1, "m5": m5, "m15": m15}


def parse_proc_stat_cpu(text: str) -> Dict[str, Any]:
    """Parse aggregate `cpu` jiffies from `/proc/stat`."""
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "cpu":
            continue
        try:
            values = [int(value) for value in parts[1:9]]
        except ValueError:
            return {"available": False}
        if len(values) < 5:
            return {"available": False}
        total = sum(values)
        idle = values[3] + values[4]
        iowait = values[4]
        busy = max(0, total - idle)
        return {"available": True, "total": total, "busy": busy, "iowait": iowait}
    return {"available": False}


def parse_meminfo(text: str) -> Dict[str, Any]:
    """Parse `/proc/meminfo` fields into byte counts."""
    parsed: Dict[str, int] = {field: 0 for field in _MEMINFO_KEYS.values()}
    found = False
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        target = _MEMINFO_KEYS.get(key.strip())
        if target is None:
            continue
        tokens = rest.split()
        if not tokens:
            continue
        try:
            value_kb = int(tokens[0])
        except ValueError:
            continue
        parsed[target] = max(0, value_kb) * 1024
        found = True
    if not found:
        return {"available": False}
    return {"available": True, **parsed}


def parse_net_dev(text: str) -> Dict[str, Any]:
    """Parse `/proc/net/dev` summing rx/tx bytes across non-loopback interfaces."""
    lines = text.splitlines()
    if len(lines) < 2:
        return {"available": False, "rx_bytes": 0, "tx_bytes": 0, "interfaces": []}
    interfaces: List[Dict[str, Any]] = []
    total_rx = 0
    total_tx = 0
    for line in lines[2:]:
        iface_raw, sep, rest = line.partition(":")
        if not sep:
            continue
        iface = iface_raw.strip()
        if not iface or iface == "lo":
            continue
        fields = rest.split()
        if len(fields) < 9:
            continue
        try:
            rx_bytes = max(0, int(fields[0]))
            tx_bytes = max(0, int(fields[8]))
        except ValueError:
            continue
        total_rx += rx_bytes
        total_tx += tx_bytes
        interfaces.append({"name": iface, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes})
    return {
        "available": True,
        "rx_bytes": total_rx,
        "tx_bytes": total_tx,
        "interfaces": interfaces,
    }


def collect_host_metrics(proc_root: str | os.PathLike[str] = "/proc") -> Dict[str, Any]:
    """Collect host uptime, loadavg, cpu, memory, and net/dev counters."""
    if not _has_mocked_host_primitives() and native_probe.is_available():
        payload = native_probe.host_metrics(proc_root=proc_root)
        if (
            isinstance(payload, dict)
            and payload.get("available")
            and isinstance(payload.get("load"), dict)
            and isinstance(payload.get("cpu"), dict)
            and isinstance(payload.get("memory"), dict)
            and isinstance(payload.get("net"), dict)
        ):
            return payload

    root = Path(proc_root)
    uptime_seconds = parse_uptime(_read_proc_text(root / "uptime", 256))
    load = parse_loadavg(_read_proc_text(root / "loadavg", 256))
    if not load.get("available") and str(proc_root) == "/proc":
        getloadavg_fn = getattr(os, "getloadavg", None)
        if callable(getloadavg_fn):
            try:
                m1, m5, m15 = getloadavg_fn()
                load = {"available": True, "m1": float(m1), "m5": float(m5), "m15": float(m15)}
            except (OSError, ValueError):
                pass
    cpu = parse_proc_stat_cpu(_read_proc_text(root / "stat", 4096))
    memory = parse_meminfo(_read_proc_text(root / "meminfo", 32768))
    net = parse_net_dev(_read_proc_text(root / "net" / "dev", 65536))
    available = bool(
        uptime_seconds is not None
        or load.get("available")
        or cpu.get("available")
        or memory.get("available")
        or net.get("available")
    )
    return {
        "available": available,
        "uptime_seconds": uptime_seconds,
        "load": load,
        "cpu": cpu,
        "memory": memory,
        "net": net,
    }
