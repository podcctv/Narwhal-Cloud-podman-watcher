"""Host /proc tree scanning, process snapshot, FD/socket attribution, and per-tick cache."""

from __future__ import annotations

import builtins
import contextlib
import os
import re
import threading
import time
from collections import deque
from typing import Any, Dict, List, Tuple

try:
    from client import native_probe, vmess_guard
except ImportError:
    import native_probe
    import vmess_guard

_ORIG_OS_LISTDIR = os.listdir
_ORIG_OS_READLINK = os.readlink
_ORIG_OS_STAT = os.stat
_ORIG_OPEN = builtins.open

_AGENT_NAMESPACES: List[Dict[str, Any]] = []

_proc_cpu_counters: Dict[Tuple[int, str], Tuple[float, float, float]] = {}
_collection_tick_cache: Dict[str, Any] | None = None
_collection_tick_lock = threading.RLock()


def register_agent_module(ns_or_mod: Any) -> None:
    """Register an agent facade module or namespace dict so patched attributes are honored."""
    ns = ns_or_mod if isinstance(ns_or_mod, dict) else getattr(ns_or_mod, "__dict__", None)
    if ns is not None and ns not in _AGENT_NAMESPACES:
        _AGENT_NAMESPACES.append(ns)


def _agent_attr(name: str, fallback: Any) -> Any:
    baseline = fallback
    for ns in _AGENT_NAMESPACES:
        if name not in ns:
            continue
        val = ns[name]
        if fallback is not None:
            if val is not fallback:
                return val
        else:
            if baseline is None:
                baseline = val
            elif val is not baseline and getattr(val, "__code__", None) is not getattr(baseline, "__code__", None):
                return val
            if hasattr(val, "assert_called"):
                return val
    return baseline


def _get_tick_cache() -> Dict[str, Any] | None:
    for ns in _AGENT_NAMESPACES:
        if "_collection_tick_cache" in ns:
            val = ns["_collection_tick_cache"]
            if val is not None:
                return val
    return _collection_tick_cache


def _set_tick_cache(cache: Dict[str, Any] | None) -> None:
    global _collection_tick_cache
    _collection_tick_cache = cache
    for ns in _AGENT_NAMESPACES:
        ns["_collection_tick_cache"] = cache


@contextlib.contextmanager
def _collection_tick_scope():
    """Share expensive host-wide scans (such as /proc trees) within one collection round."""
    with _collection_tick_lock:
        existing = _get_tick_cache()
        if existing is not None:
            yield existing
            return
        cache: Dict[str, Any] = {
            "proc_tree": {},
            "proc_snapshots": {},
            "ps_by_container": {},
        }
        _set_tick_cache(cache)
        try:
            yield cache
        finally:
            _set_tick_cache(None)


def _redact_process_command(command: str) -> str:
    """Remove common inline credentials before a process command is reported."""
    value = re.sub(
        r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[=:]\s*|\s+)([^\s]{1,300})",
        r"\1\2[REDACTED]",
        command or "",
    )
    if re.search(r"\bmicrosocks(?:\b|[-_])", value, re.IGNORECASE):
        value = re.sub(
            r"(?<!\S)(-[uP])(?:\s+|=)?(\"[^\"]*\"|'[^']*'|(?!-)[^\s]+)",
            r"\1 [REDACTED]",
            value,
        )
    value = re.sub(r"(?i)([a-z][a-z0-9+.\-]{1,30}://[^\s:/@]+:)[^@\s]+@", r"\1[REDACTED]@", value)
    value = re.sub(r"(?i)([?&](?:auth|key|secret|token|password|pass|psk)=)[^&\s]+", r"\1[REDACTED]", value)
    return value[:500]


def _collect_deep_process_snapshot(
    runtime: str, name: str, project: str, process_limit: int
) -> Dict[str, object]:
    """Collect a bounded sorted process snapshot inside a container via runtime exec."""
    capture_limit = max(20, min(200, int(process_limit)))
    command = (
        "(ps -eo pid=,ppid=,user=,stat=,pcpu=,rss=,comm=,args= --sort=-pcpu 2>/dev/null || "
        "ps -eo pid=,ppid=,user=,stat=,pcpu=,rss=,comm=,args= 2>/dev/null) "
        f"| head -n {capture_limit + 1}"
    )
    run_fn = _agent_attr("run", None)
    exec_cmd_fn = _agent_attr("_runtime_exec_cmd", None)
    redact_fn = _agent_attr("_redact_process_command", _redact_process_command)
    if run_fn is None or exec_cmd_fn is None:
        return {"available": False, "captured": 0, "truncated": False, "items": []}
    output = run_fn(exec_cmd_fn(runtime, name, command, project))
    processes: List[Dict[str, object]] = []
    for raw_line in output.splitlines():
        parts = raw_line.strip().split(None, 7)
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        try:
            processes.append(
                {
                    "pid": int(parts[0]),
                    "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                    "user": parts[2][:80],
                    "state": parts[3][:20],
                    "cpu_percent": max(0.0, float(parts[4].replace(",", "."))),
                    "rss_bytes": max(0, int(parts[5])) * 1024,
                    "process": parts[6][:120],
                    "command": redact_fn(parts[7] if len(parts) > 7 else parts[6]),
                }
            )
        except (TypeError, ValueError):
            continue
    processes.sort(key=lambda item: float(item.get("cpu_percent") or 0), reverse=True)
    return {
        "available": bool(output.strip()),
        "captured": min(len(processes), capture_limit),
        "truncated": len(processes) > capture_limit,
        "items": processes[:capture_limit],
    }


def _read_host_proc_text(path: str, limit: int = 8192) -> str:
    """Safely read bounded UTF-8 text from a /proc file."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return ""


def _extract_proc_ppid(status: str) -> int | None:
    """Extract numeric PPid from /proc/<pid>/status without per-PID regex overhead."""
    for line in status.splitlines():
        if line.startswith("PPid:"):
            raw = line[5:].strip()
            if raw.isdigit():
                return int(raw)
            return None
    return None


def _scan_host_proc_tree(scan_limit: int) -> Dict[str, Any]:
    """Scan host /proc once per tick to build parent/child maps and status texts."""
    tick_cache = _get_tick_cache()
    if tick_cache is not None:
        cached_tree = tick_cache["proc_tree"].get(scan_limit)
        if isinstance(cached_tree, dict):
            return cached_tree

    read_proc_fn = _agent_attr("_read_host_proc_text", _read_host_proc_text)
    extract_ppid_fn = _agent_attr("_extract_proc_ppid", _extract_proc_ppid)

    parent_map: Dict[int, int] = {}
    children_map: Dict[int, List[int]] = {}
    status_map: Dict[int, str] = {}
    proc_scan_complete = True
    try:
        all_proc_ids = sorted(int(value) for value in os.listdir("/proc") if value.isdigit())
    except OSError:
        all_proc_ids = []
        proc_scan_complete = False
    if len(all_proc_ids) > scan_limit:
        proc_scan_complete = False
    proc_ids = all_proc_ids[:scan_limit]
    status_scan_complete = True
    for idx, host_pid in enumerate(proc_ids):
        if idx > 0 and idx % 256 == 0:
            time.sleep(0)
        status = read_proc_fn(f"/proc/{host_pid}/status")
        ppid = extract_ppid_fn(status)
        if ppid is None:
            try:
                os.stat(f"/proc/{host_pid}")
            except FileNotFoundError:
                continue
            except OSError:
                status_scan_complete = False
                continue
            status_scan_complete = False
            continue
        parent_map[host_pid] = ppid
        children_map.setdefault(ppid, []).append(host_pid)
        status_map[host_pid] = status

    try:
        uptime = float(read_proc_fn("/proc/uptime", 128).split()[0])
        clock_ticks = float(os.sysconf("SC_CLK_TCK"))
    except (IndexError, OSError, TypeError, ValueError):
        uptime, clock_ticks = 0.0, 100.0

    tree = {
        "parent_map": parent_map,
        "children_map": children_map,
        "status_map": status_map,
        "proc_scan_complete": proc_scan_complete,
        "status_scan_complete": status_scan_complete,
        "uptime": uptime,
        "clock_ticks": clock_ticks,
    }
    if tick_cache is not None:
        tick_cache["proc_tree"][scan_limit] = tree
    return tree


def _fallback_env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _has_mocked_proc_primitives(scan_tree_fn: Any, read_proc_fn: Any) -> bool:
    if scan_tree_fn is not _scan_host_proc_tree or read_proc_fn is not _read_host_proc_text:
        return True
    if os.listdir is not _ORIG_OS_LISTDIR or os.stat is not _ORIG_OS_STAT:
        return True
    for ns in _AGENT_NAMESPACES:
        ns_os = ns.get("os")
        if ns_os is not None and (
            ns_os is not os
            or getattr(ns_os, "listdir", None) is not _ORIG_OS_LISTDIR
            or getattr(ns_os, "stat", None) is not _ORIG_OS_STAT
        ):
            return True
    return False


def _compute_proc_cpu_percent(
    proc_cpu_counters: Dict[Tuple[int, str], Tuple[float, float, float]],
    host_pid: int,
    start_ticks: str,
    cpu_seconds: float,
    uptime: float,
    lifetime_cpu_percent: float,
) -> float:
    if uptime <= 0 or not start_ticks:
        return max(0.0, lifetime_cpu_percent)
    delta_cpu_percent = 0.0
    proc_key = (int(host_pid), str(start_ticks))
    prev_proc = proc_cpu_counters.get(proc_key)
    if prev_proc is not None:
        prev_cpu_sec, prev_uptime, prev_pct = prev_proc
        dt = uptime - prev_uptime
        dcpu = cpu_seconds - prev_cpu_sec
        if dt >= 0.5 and dcpu >= 0:
            delta_cpu_percent = max(0.0, (dcpu / dt) * 100.0)
            proc_cpu_counters[proc_key] = (cpu_seconds, uptime, delta_cpu_percent)
        elif 0 <= dt < 0.5 and dcpu >= 0:
            delta_cpu_percent = max(0.0, prev_pct)
        else:
            proc_cpu_counters[proc_key] = (cpu_seconds, uptime, 0.0)
    else:
        if len(proc_cpu_counters) > 10000:
            proc_cpu_counters.clear()
        proc_cpu_counters[proc_key] = (cpu_seconds, uptime, 0.0)
    return max(max(0.0, lifetime_cpu_percent), delta_cpu_percent)


def _finalize_host_proc_snapshot(
    host_processes: List[Dict[str, object]],
    proc_scan_complete: bool,
    status_scan_complete: bool,
    capture_limit: int,
    init_pid: int,
    tick_cache: Dict[str, Any] | None,
) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    namespace_by_host = {
        int(item.get("host_pid") or 0): int(item.get("pid") or 0) for item in host_processes
    }
    for item in host_processes:
        item["ppid"] = namespace_by_host.get(int(item.get("ppid") or 0), 0)
    host_processes.sort(key=lambda item: float(item.get("cpu_percent") or 0), reverse=True)
    public_items = [
        {key: value for key, value in item.items() if key not in {"host_pid", "start_ticks"}}
        for item in host_processes
    ]
    meta = {
        "available": bool(host_processes),
        "source": "host_proc",
        "scope_complete": proc_scan_complete and status_scan_complete,
    }
    if tick_cache is not None:
        tick_cache["proc_snapshots"][init_pid] = (meta, public_items, host_processes)
    return (
        {
            **meta,
            "captured": min(len(public_items), capture_limit),
            "truncated": len(public_items) > capture_limit,
            "items": public_items[:capture_limit],
        },
        host_processes,
    )


def _collect_host_proc_snapshot_native(
    init_pid: int,
    scan_limit: int,
    redact_fn: Any,
    proc_cpu_counters: Dict[Tuple[int, str], Tuple[float, float, float]],
) -> Tuple[List[Dict[str, object]], bool, bool] | None:
    try:
        clock_ticks = float(os.sysconf("SC_CLK_TCK"))
    except (AttributeError, OSError, TypeError, ValueError):
        clock_ticks = 100.0
    payload = native_probe.proc_snapshot(init_pid, scan_limit=scan_limit, clock_ticks=clock_ticks)
    if not isinstance(payload, dict) or not payload.get("available"):
        return None
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return None
    uptime = float(payload.get("uptime") or 0.0)
    proc_scan_complete = bool(payload.get("proc_scan_complete"))
    status_scan_complete = bool(payload.get("status_scan_complete"))
    host_processes: List[Dict[str, object]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        host_pid = int(item.get("host_pid") or 0)
        if host_pid <= 0:
            continue
        comm = str(item.get("process") or "unknown")[:120] or "unknown"
        command = str(item.get("command") or comm)
        start_ticks = str(item.get("start_ticks") or "")
        cpu_seconds = float(item.get("cpu_seconds") or 0.0)
        lifetime_cpu_percent = max(0.0, float(item.get("lifetime_cpu_percent") or 0.0))
        cpu_percent = _compute_proc_cpu_percent(
            proc_cpu_counters,
            host_pid,
            start_ticks,
            cpu_seconds,
            uptime,
            lifetime_cpu_percent,
        )
        host_processes.append(
            {
                "host_pid": host_pid,
                "pid": int(item.get("pid") or 0),
                "ppid": int(item.get("ppid") or 0),
                "user": str(item.get("user") or "-"),
                "state": str(item.get("state") or "-"),
                "cpu_percent": cpu_percent,
                "rss_bytes": int(item.get("rss_bytes") or 0),
                "process": comm,
                "command": redact_fn(command or comm),
                "start_ticks": start_ticks,
            }
        )
    return host_processes, proc_scan_complete, status_scan_complete


def _collect_host_proc_process_snapshot(
    init_pid: int, process_limit: int
) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    """Read a target container process tree from host /proc when the image has no ps."""
    if init_pid <= 1 or not os.path.isdir(f"/proc/{init_pid}"):
        return {"available": False, "captured": 0, "truncated": False, "items": []}, []
    capture_limit = max(20, min(200, int(process_limit)))
    tick_cache = _get_tick_cache()
    if tick_cache is not None:
        cached_snap = tick_cache["proc_snapshots"].get(init_pid)
        if isinstance(cached_snap, tuple) and len(cached_snap) == 3:
            meta, public_items, host_processes = cached_snap
            return (
                {
                    **meta,
                    "captured": min(len(public_items), capture_limit),
                    "truncated": len(public_items) > capture_limit,
                    "items": list(public_items[:capture_limit]),
                },
                list(host_processes),
            )

    env_float_fn = _agent_attr("_env_float", _fallback_env_float)
    scan_tree_fn = _agent_attr("_scan_host_proc_tree", _scan_host_proc_tree)
    read_proc_fn = _agent_attr("_read_host_proc_text", _read_host_proc_text)
    redact_fn = _agent_attr("_redact_process_command", _redact_process_command)
    proc_cpu_counters = _agent_attr("_proc_cpu_counters", _proc_cpu_counters)

    scan_limit = max(1000, min(50000, int(env_float_fn("DEEP_HOST_PROC_SCAN_MAX", 20000))))
    if not _has_mocked_proc_primitives(scan_tree_fn, read_proc_fn) and native_probe.is_available():
        native_result = _collect_host_proc_snapshot_native(
            init_pid, scan_limit, redact_fn, proc_cpu_counters
        )
        if native_result is not None:
            host_processes, proc_scan_complete, status_scan_complete = native_result
            return _finalize_host_proc_snapshot(
                host_processes,
                proc_scan_complete,
                status_scan_complete,
                capture_limit,
                init_pid,
                tick_cache,
            )

    tree = scan_tree_fn(scan_limit)
    parent_map: Dict[int, int] = tree["parent_map"]
    children_map: Dict[int, List[int]] = tree["children_map"]
    status_map: Dict[int, str] = tree["status_map"]
    proc_scan_complete: bool = bool(tree["proc_scan_complete"])
    status_scan_complete: bool = bool(tree["status_scan_complete"])
    uptime: float = float(tree["uptime"])
    clock_ticks: float = float(tree["clock_ticks"])

    descendants = {init_pid}
    queue = deque([init_pid])
    while queue and len(descendants) <= scan_limit:
        current_pid = queue.popleft()
        for child_pid in children_map.get(current_pid, ()):
            if child_pid not in descendants:
                descendants.add(child_pid)
                queue.append(child_pid)
                if len(descendants) > scan_limit:
                    break
    if len(descendants) > scan_limit:
        proc_scan_complete = False
    host_processes: List[Dict[str, object]] = []
    for host_pid in sorted(descendants):
        status = status_map.get(host_pid) or read_proc_fn(f"/proc/{host_pid}/status")
        namespace_match = re.search(r"(?m)^NSpid:\s+(.+)$", status)
        namespace_values = re.findall(r"\d+", namespace_match.group(1)) if namespace_match else []
        namespace_pid = int(namespace_values[-1]) if namespace_values else (1 if host_pid == init_pid else host_pid)
        uid_match = re.search(r"(?m)^Uid:\s+(\d+)", status)
        state_match = re.search(r"(?m)^State:\s+([^\s]+)", status)
        rss_match = re.search(r"(?m)^VmRSS:\s+(\d+)\s+kB", status, flags=re.IGNORECASE)
        comm = read_proc_fn(f"/proc/{host_pid}/comm", 256).strip()[:120] or "unknown"
        try:
            with open(f"/proc/{host_pid}/cmdline", "rb") as handle:
                command = handle.read(8192).replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        except OSError:
            command = comm
        cpu_percent = 0.0
        stat = read_proc_fn(f"/proc/{host_pid}/stat", 4096)
        close_paren = stat.rfind(")")
        stat_fields = stat[close_paren + 2 :].split() if close_paren >= 0 else []
        start_ticks = stat_fields[19] if len(stat_fields) > 19 and stat_fields[19].isdigit() else ""
        if len(stat_fields) > 19 and uptime > 0 and clock_ticks > 0:
            try:
                cpu_seconds = (float(stat_fields[11]) + float(stat_fields[12])) / clock_ticks
                lifetime = max(0.001, uptime - (float(stat_fields[19]) / clock_ticks))
                lifetime_cpu_percent = max(0.0, (cpu_seconds / lifetime) * 100.0)
                cpu_percent = _compute_proc_cpu_percent(
                    proc_cpu_counters,
                    host_pid,
                    str(start_ticks or stat_fields[19]),
                    cpu_seconds,
                    uptime,
                    lifetime_cpu_percent,
                )
            except (TypeError, ValueError):
                pass
        host_processes.append(
            {
                "host_pid": host_pid,
                "pid": namespace_pid,
                "ppid": int(parent_map.get(host_pid, 0)),
                "user": uid_match.group(1) if uid_match else "-",
                "state": state_match.group(1) if state_match else "-",
                "cpu_percent": cpu_percent,
                "rss_bytes": int(rss_match.group(1)) * 1024 if rss_match else 0,
                "process": comm,
                "command": redact_fn(command or comm),
                "start_ticks": start_ticks,
            }
        )
    return _finalize_host_proc_snapshot(
        host_processes,
        proc_scan_complete,
        status_scan_complete,
        capture_limit,
        init_pid,
        tick_cache,
    )


_SOCKET_STATE_NAMES = {
    "01": "established", "02": "syn-sent", "03": "syn-recv", "04": "fin-wait-1",
    "05": "fin-wait-2", "06": "time-wait", "07": "close", "08": "close-wait",
    "09": "last-ack", "0A": "listen", "0B": "closing",
}


def _has_mocked_socket_primitives(read_proc_fn: Any) -> bool:
    if read_proc_fn is not _read_host_proc_text:
        return True
    if (
        os.listdir is not _ORIG_OS_LISTDIR
        or os.readlink is not _ORIG_OS_READLINK
        or builtins.open is not _ORIG_OPEN
    ):
        return True
    for ns in _AGENT_NAMESPACES:
        ns_os = ns.get("os")
        if ns_os is not None and (
            ns_os is not os
            or getattr(ns_os, "listdir", None) is not _ORIG_OS_LISTDIR
            or getattr(ns_os, "readlink", None) is not _ORIG_OS_READLINK
        ):
            return True
    return False


def _finalize_host_proc_socket_details(
    sockets: List[Dict[str, object]],
    service_listeners: List[Dict[str, object]],
    socket_fd_references: Dict[Tuple[int, str], Dict[str, int]],
    snapshot_count: int,
    snapshot_cap: int,
    listener_inventory_complete: bool,
    fd_inventory_complete: bool,
    owner_count_fn: Any,
) -> Dict[str, object]:
    totals: Dict[Tuple[int, str], Dict[str, object]] = {}
    for item in sockets:
        key = (int(item.get("pid") or 0), str(item.get("process") or "unknown"))
        aggregate = totals.setdefault(
            key,
            {"pid": key[0], "process": key[1], "inbound_connections": 0, "outbound_connections": 0, "unknown_connections": 0, "remote_ips": set()},
        )
        direction = item.get("direction") if item.get("direction") in ("inbound", "outbound") else "unknown"
        aggregate[f"{direction}_connections"] = int(aggregate[f"{direction}_connections"]) + 1
        remote_ips = aggregate.get("remote_ips")
        if isinstance(remote_ips, set):
            remote_ips.add(str(item.get("remote_ip") or ""))
    process_totals = []
    for (owner_pid, owner_name), counts in socket_fd_references.items():
        aggregate = totals.setdefault(
            (owner_pid, owner_name),
            {"pid": owner_pid, "process": owner_name, "inbound_connections": 0,
             "outbound_connections": 0, "unknown_connections": 0, "remote_ips": set()},
        )
        aggregate["tcp_socket_fd_references"] = counts["tcp"]
        aggregate["udp_socket_fd_references"] = counts["udp"]
    for aggregate in totals.values():
        remote_ips = aggregate.pop("remote_ips", set())
        aggregate["unique_remote_ips"] = len(remote_ips) if isinstance(remote_ips, set) else 0
        process_totals.append(aggregate)
    process_totals.sort(
        key=lambda item: int(item.get("inbound_connections") or 0) + int(item.get("outbound_connections") or 0),
        reverse=True,
    )
    owner_count = owner_count_fn({"communication_sockets": sockets})
    return {
        "communication_detail_available": True,
        "communication_source": "host_proc",
        "communication_snapshot_count": snapshot_count,
        "communication_snapshot_truncated": snapshot_count >= snapshot_cap,
        "communication_processes": process_totals[:50],
        "communication_sockets": sockets,
        "service_listeners": service_listeners,
        "listener_inventory_complete": listener_inventory_complete,
        "socket_fd_attribution_complete": fd_inventory_complete,
        "communication_owner_attributed_count": owner_count,
        "process_attribution_available": owner_count > 0,
    }


def _collect_host_proc_socket_details_native(
    init_pid: int,
    host_processes: List[Dict[str, object]],
    listening_ports: List[int],
    socket_limit: int,
    fd_budget: int,
    process_scope_complete: bool,
    is_trackable_fn: Any,
    classify_origin_fn: Any,
    owner_count_fn: Any,
) -> Dict[str, object] | None:
    host_pid_to_proc: Dict[int, Tuple[int, str]] = {}
    pids: List[int] = []
    all_valid_pids = True
    for process in host_processes:
        host_pid = int(process.get("host_pid") or 0)
        if host_pid <= 1:
            all_valid_pids = False
            continue
        if host_pid not in host_pid_to_proc:
            host_pid_to_proc[host_pid] = (
                int(process.get("pid") or 0),
                str(process.get("process") or "unknown")[:120],
            )
            pids.append(host_pid)
    if not pids:
        return None
    payload = native_probe.proc_sockets(init_pid, pids, max_fds=fd_budget)
    if (
        not isinstance(payload, dict)
        or not payload.get("available")
        or not isinstance(payload.get("sockets"), list)
    ):
        return None

    tcp_listening = {int(port) for port in listening_ports if int(port) > 0}
    udp_listening: set[int] = set()
    grouped_sockets: Dict[Tuple[int, str, str, str, int, str, int], set[Tuple[int, str]]] = {}
    for entry in payload["sockets"]:
        if not isinstance(entry, dict):
            continue
        proto = str(entry.get("proto") or "").lower()
        if proto == "tcp6":
            proto = "tcp"
        elif proto == "udp6":
            proto = "udp"
        if proto not in ("tcp", "udp"):
            continue
        state = str(entry.get("state_hex") or "").upper()
        local_ip = str(entry.get("local_ip") or "")
        remote_ip = str(entry.get("remote_ip") or "")
        try:
            inode = int(entry.get("inode") or 0)
            local_port = int(entry.get("local_port") or 0)
            remote_port = int(entry.get("remote_port") or 0)
            host_pid = int(entry.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if proto == "tcp" and state == "0A" and local_port > 0:
            tcp_listening.add(local_port)
        elif proto == "udp" and remote_port == 0 and local_port > 0:
            udp_listening.add(local_port)
        key = (inode, proto, state, local_ip, local_port, remote_ip, remote_port)
        owners = grouped_sockets.setdefault(key, set())
        if host_pid > 0:
            owners.add(host_pid_to_proc.get(host_pid, (0, "unknown")))

    truncated = bool(payload.get("truncated", False))
    fd_inventory_complete = bool(process_scope_complete) and not truncated and all_valid_pids
    listener_inventory_complete = fd_inventory_complete
    sockets: List[Dict[str, object]] = []
    service_listeners: List[Dict[str, object]] = []
    listener_keys = set()
    socket_fd_references: Dict[Tuple[int, str], Dict[str, int]] = {}
    snapshot_count = len(grouped_sockets)
    snapshot_cap = max(500, min(2000, socket_limit * 2))

    for (_inode, proto, state, local_ip, local_port, remote_ip, remote_port), owners in grouped_sockets.items():
        for owner_pid, owner_name in owners:
            counts = socket_fd_references.setdefault((owner_pid, owner_name), {"tcp": 0, "udp": 0})
            counts[proto] += 1
        is_listener = (proto == "tcp" and state == "0A") or (proto == "udp" and remote_port == 0)
        if is_listener and local_port > 0:
            listener_owners = owners if owners else {(0, "")}
            local_endpoint = f"[{local_ip}]:{local_port}" if ":" in local_ip else f"{local_ip}:{local_port}"
            for owner_pid, owner_name in sorted(listener_owners):
                listener_key = (proto, local_ip, local_port, owner_pid, owner_name)
                if listener_key in listener_keys:
                    continue
                if len(service_listeners) >= 100:
                    listener_inventory_complete = False
                    continue
                listener_keys.add(listener_key)
                service_listeners.append({
                    "process": owner_name,
                    "pid": owner_pid,
                    "proto": proto,
                    "local": local_endpoint,
                    "port": local_port,
                    "source": "host_proc_fd_inode" if owner_pid > 0 else "host_proc_unattributed",
                })
        if proto == "tcp" and state not in ("01", "02", "03"):
            continue
        if proto == "udp" and remote_port <= 0:
            continue
        if not is_trackable_fn(remote_ip):
            continue
        owner_pid, owner_name = sorted(owners)[0] if owners else (0, "unknown")
        state_name = _SOCKET_STATE_NAMES.get(state, state.lower())
        direction, origin, direction_evidence = classify_origin_fn(
            proto, state_name, local_port, tcp_listening if proto == "tcp" else udp_listening
        )
        local_text = f"[{local_ip}]:{local_port}" if ":" in local_ip else f"{local_ip}:{local_port}"
        remote_text = f"[{remote_ip}]:{remote_port}" if ":" in remote_ip else f"{remote_ip}:{remote_port}"
        if len(sockets) < socket_limit:
            sockets.append({
                "proto": proto,
                "state": state_name,
                "direction": direction,
                "local": local_text,
                "remote": remote_text,
                "remote_ip": remote_ip,
                "process": owner_name,
                "pid": owner_pid,
                "origin": origin,
                "origin_confidence": "confirmed" if direction_evidence.startswith("confirmed_") else "probable" if direction != "unknown" else "unknown",
                "direction_evidence": direction_evidence,
                "process_role": "acceptor" if direction == "inbound" else "initiator" if direction == "outbound" else "unknown",
                "process_attribution": "attributed" if owner_pid > 0 else "unavailable",
            })

    return _finalize_host_proc_socket_details(
        sockets,
        service_listeners,
        socket_fd_references,
        snapshot_count,
        snapshot_cap,
        listener_inventory_complete,
        fd_inventory_complete,
        owner_count_fn,
    )


def _collect_host_proc_socket_details(
    init_pid: int,
    host_processes: List[Dict[str, object]],
    listening_ports: List[int],
    socket_limit: int,
    *,
    process_scope_complete: bool = False,
) -> Dict[str, object]:
    """Attribute bounded /proc socket tables to container processes without requiring ss."""
    if init_pid <= 1 or not host_processes:
        return {"communication_detail_available": False, "communication_sockets": [], "communication_processes": []}

    env_float_fn = _agent_attr("_env_float", _fallback_env_float)
    read_proc_fn = _agent_attr("_read_host_proc_text", _read_host_proc_text)
    parse_port_fn = _agent_attr("_parse_port", None)
    decode_addr_fn = _agent_attr("_decode_proc_addr", None)
    is_trackable_fn = _agent_attr("_is_trackable_ip", None)
    classify_origin_fn = _agent_attr("_classify_socket_origin", None)
    owner_count_fn = _agent_attr("_communication_socket_owner_count", None)

    fd_budget = max(1000, min(20000, int(env_float_fn("DEEP_HOST_PROC_FD_MAX", 10000))))
    if not _has_mocked_socket_primitives(read_proc_fn) and native_probe.is_available():
        native_result = _collect_host_proc_socket_details_native(
            init_pid,
            host_processes,
            listening_ports,
            socket_limit,
            fd_budget,
            process_scope_complete,
            is_trackable_fn,
            classify_origin_fn,
            owner_count_fn,
        )
        if native_result is not None:
            return native_result

    inode_owners: Dict[str, set[Tuple[int, str]]] = {}
    visited_fds = 0
    fd_inventory_complete = bool(process_scope_complete)
    for process in host_processes:
        host_pid = int(process.get("host_pid") or 0)
        if host_pid <= 1:
            fd_inventory_complete = False
            continue
        try:
            all_fd_names = os.listdir(f"/proc/{host_pid}/fd")
        except OSError:
            fd_inventory_complete = False
            continue
        if len(all_fd_names) > 1024:
            fd_inventory_complete = False
        fd_names = all_fd_names[:1024]
        for fd_name in fd_names:
            if visited_fds >= fd_budget:
                fd_inventory_complete = False
                break
            visited_fds += 1
            try:
                target = os.readlink(f"/proc/{host_pid}/fd/{fd_name}")
            except OSError:
                fd_inventory_complete = False
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                inode_owners.setdefault(match.group(1), set()).add(
                    (int(process.get("pid") or 0), str(process.get("process") or "unknown")[:120])
                )
        if visited_fds >= fd_budget:
            fd_inventory_complete = False
            break

    state_names = {
        "01": "established", "02": "syn-sent", "03": "syn-recv", "04": "fin-wait-1",
        "05": "fin-wait-2", "06": "time-wait", "07": "close", "08": "close-wait",
        "09": "last-ack", "0A": "listen", "0B": "closing",
    }
    tcp_listening = {int(port) for port in listening_ports if int(port) > 0}
    udp_listening: set[int] = set()
    socket_tables: Dict[str, str] = {}
    socket_tables_complete = True
    socket_tables_parse_complete = True
    table_specs = (
        ("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True)
    )
    for filename, proto, _is_v6 in table_specs:
        table = read_proc_fn(f"/proc/{init_pid}/net/{filename}", 2_000_000)
        socket_tables[filename] = table
        if not table or len(table) >= 2_000_000:
            socket_tables_complete = False
        for line in table.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1] or ":" not in parts[2]:
                socket_tables_parse_complete = False
                continue
            _, local_port_hex = parts[1].rsplit(":", 1)
            observed_port = parse_port_fn(local_port_hex)
            _, remote_port_hex = parts[2].rsplit(":", 1)
            remote_port = parse_port_fn(remote_port_hex)
            if proto == "tcp" and parts[3].upper() == "0A" and observed_port > 0:
                tcp_listening.add(observed_port)
            elif proto == "udp" and remote_port == 0 and observed_port > 0:
                udp_listening.add(observed_port)
    sockets: List[Dict[str, object]] = []
    service_listeners: List[Dict[str, object]] = []
    listener_keys = set()
    socket_fd_references: Dict[Tuple[int, str], Dict[str, int]] = {}
    snapshot_count = 0
    snapshot_cap = max(500, min(2000, socket_limit * 2))
    listener_inventory_complete = fd_inventory_complete and socket_tables_complete and socket_tables_parse_complete
    for filename, proto, is_v6 in table_specs:
        table = socket_tables[filename]
        for line in table.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10 or ":" not in parts[1] or ":" not in parts[2]:
                listener_inventory_complete = False
                continue
            snapshot_count += 1
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            remote_ip_hex, remote_port_hex = parts[2].rsplit(":", 1)
            local_ip = decode_addr_fn(local_ip_hex, is_v6=is_v6)
            remote_ip = decode_addr_fn(remote_ip_hex, is_v6=is_v6)
            local_port = parse_port_fn(local_port_hex)
            remote_port = parse_port_fn(remote_port_hex)
            state = parts[3].upper()
            owners = inode_owners.get(parts[9], set())
            for owner_pid, owner_name in owners:
                counts = socket_fd_references.setdefault((owner_pid, owner_name), {"tcp": 0, "udp": 0})
                counts[proto] += 1
            is_listener = (proto == "tcp" and state == "0A") or (proto == "udp" and remote_port == 0)
            if is_listener and local_port > 0:
                if not owners:
                    owners = {(0, "")}
                local_endpoint = f"[{local_ip}]:{local_port}" if ":" in local_ip else f"{local_ip}:{local_port}"
                for owner_pid, owner_name in sorted(owners):
                    listener_key = (proto, local_ip, local_port, owner_pid, owner_name)
                    if listener_key in listener_keys:
                        continue
                    if len(service_listeners) >= 100:
                        listener_inventory_complete = False
                        continue
                    listener_keys.add(listener_key)
                    service_listeners.append({
                        "process": owner_name,
                        "pid": owner_pid,
                        "proto": proto,
                        "local": local_endpoint,
                        "port": local_port,
                        "source": "host_proc_fd_inode" if owner_pid > 0 else "host_proc_unattributed",
                    })
            if proto == "tcp" and state not in ("01", "02", "03"):
                continue
            if proto == "udp" and remote_port <= 0:
                continue
            if not is_trackable_fn(remote_ip):
                continue
            owner_pid, owner_name = sorted(owners)[0] if owners else (0, "unknown")
            state_name = state_names.get(state, state.lower())
            direction, origin, direction_evidence = classify_origin_fn(
                proto, state_name, local_port, tcp_listening if proto == "tcp" else udp_listening
            )
            local_text = f"[{local_ip}]:{local_port}" if ":" in local_ip else f"{local_ip}:{local_port}"
            remote_text = f"[{remote_ip}]:{remote_port}" if ":" in remote_ip else f"{remote_ip}:{remote_port}"
            if len(sockets) < socket_limit:
                sockets.append(
                    {
                        "proto": proto,
                        "state": state_name,
                        "direction": direction,
                        "local": local_text,
                        "remote": remote_text,
                        "remote_ip": remote_ip,
                        "process": owner_name,
                        "pid": owner_pid,
                        "origin": origin,
                        "origin_confidence": "confirmed" if direction_evidence.startswith("confirmed_") else "probable" if direction != "unknown" else "unknown",
                        "direction_evidence": direction_evidence,
                        "process_role": "acceptor" if direction == "inbound" else "initiator" if direction == "outbound" else "unknown",
                        "process_attribution": "attributed" if owner_pid > 0 else "unavailable",
                    }
                )
    return _finalize_host_proc_socket_details(
        sockets,
        service_listeners,
        socket_fd_references,
        snapshot_count,
        snapshot_cap,
        listener_inventory_complete,
        fd_inventory_complete and socket_tables_complete and socket_tables_parse_complete,
        owner_count_fn,
    )


def _collect_vmess_host_proc_listener_inventory(
    init_pid: int,
    configured_protocols: List[Dict[str, object]],
    process_scan_states: List[Dict[str, object]],
    listening_ports: List[int],
) -> Dict[str, object]:
    """Use host /proc inode ownership to complete candidate VMess listener evidence."""
    candidates = [
        item for item in configured_protocols[:100]
        if isinstance(item, dict) and str(item.get("protocol") or "").lower() in vmess_guard.SUPPORTED_PROTOCOLS
    ]
    if not candidates or len(candidates) > vmess_guard.MAX_ENDPOINTS * len(vmess_guard.SUPPORTED_PROTOCOLS):
        return {"complete": False, "reason": "candidate_limit_or_absence", "listeners": []}

    states: Dict[Tuple[int, str], Dict[str, object]] = {}
    for item in process_scan_states if isinstance(process_scan_states, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            pid = int(item.get("pid") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        process = str(item.get("process") or "").lower()
        if 1 < pid <= 4194304 and process in vmess_guard.SUPPORTED_ENGINES:
            states[(pid, process)] = item

    expected_processes: Dict[Tuple[int, str], str] = {}
    candidate_ports = set()
    for candidate in candidates:
        try:
            pid = int(candidate.get("pid") or 0)
            port = int(candidate.get("port") or 0)
        except (TypeError, ValueError, OverflowError):
            return {"complete": False, "reason": "candidate_identity_invalid", "listeners": []}
        process = str(candidate.get("process") or "").lower()
        state = states.get((pid, process))
        start_ticks = str(state.get("start_ticks") or "") if state else ""
        if (
            pid <= 1 or pid > 4194304 or not 0 < port <= 65535
            or process not in vmess_guard.SUPPORTED_ENGINES
            or not state or str(state.get("state") or "").lower() != "complete"
            or not start_ticks.isdigit()
        ):
            return {"complete": False, "reason": "candidate_process_scan_incomplete", "listeners": []}
        expected_processes[(pid, process)] = start_ticks
        candidate_ports.add(port)

    snap_fn = _agent_attr("_collect_host_proc_process_snapshot", _collect_host_proc_process_snapshot)
    sock_fn = _agent_attr("_collect_host_proc_socket_details", _collect_host_proc_socket_details)

    process_snapshot, host_processes = snap_fn(init_pid, 200)
    if process_snapshot.get("scope_complete") is not True or not host_processes:
        return {"complete": False, "reason": "host_process_scope_incomplete", "listeners": []}
    for (pid, process), start_ticks in expected_processes.items():
        matches = [
            item for item in host_processes
            if int(item.get("pid") or 0) == pid
            and str(item.get("process") or "").lower() == process
            and str(item.get("start_ticks") or "") == start_ticks
        ]
        if len(matches) != 1:
            return {"complete": False, "reason": "candidate_process_owner_unverified", "listeners": []}

    host_communication = sock_fn(
        init_pid,
        host_processes,
        listening_ports,
        500,
        process_scope_complete=process_snapshot.get("scope_complete") is True,
    )
    if host_communication.get("listener_inventory_complete") is not True:
        return {"complete": False, "reason": "host_listener_inventory_incomplete", "listeners": []}
    listeners = [
        item for item in host_communication.get("service_listeners", [])
        if isinstance(item, dict) and int(item.get("port") or 0) in candidate_ports
    ]
    return {
        "complete": True,
        "reason": "",
        "source": "host_proc_fd_inode",
        "candidate_ports": sorted(candidate_ports),
        "listeners": listeners,
    }
