import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Dict, List, Tuple
from urllib.parse import quote, urlparse

import requests

try:
    import maxminddb
except ImportError:  # Optional at import time for source-only/test environments.
    maxminddb = None

APP_VERSION = os.getenv("NARWHAL_VERSION", "dev").strip() or "dev"

_warned_missing_bins = set()
_warned_timeout_commands = set()
_podman_bin = None
_container_bin = None
_runtime_bins = None
_net_counters: Dict[str, Dict[str, float]] = {}
_cpu_counters: Dict[str, Dict[str, float]] = {}
_warned_parse_paths = set()
_geoip_country_cache: Dict[str, Tuple[str, float]] = {}
_geoip_reader = None
_geoip_reader_path = ""
_incus_metrics_cache: Dict[str, object] = {"ts": 0.0, "text": "", "parsed": {}}
_incus_forward_cache: Dict[str, Dict[str, object]] = {}
_packet_counters: Dict[str, Dict[str, float]] = {}
_protocol_counters: Dict[str, Dict[str, float]] = {}
_access_log_states: Dict[str, Dict[str, object]] = {}
_security_last_sample_ts = 0.0
_pending_deep_samples: Dict[int, Dict[str, object]] = {}

_SOCKS_DIRECT_NAMES = {"microsocks", "sockd", "danted", "srelay", "hev-socks5-server"}
_SOCKS_CONFIGURABLE_NAMES = {"3proxy", "gost", "xray", "v2ray", "sing-box"}
_SOCKS_PROCESS_NAMES = _SOCKS_DIRECT_NAMES | _SOCKS_CONFIGURABLE_NAMES
_AUTO_REMEDIATE_MALWARE_NAMES = {"xmrig"}


def _is_containerized_runtime() -> bool:
    return os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv")


def get_podman_bin(warn: bool = True) -> str:
    global _podman_bin
    if _podman_bin is not None:
        return _podman_bin

    # In containerized deployments we usually mount the host Podman socket.
    # Prefer podman-remote in containers so we can inspect host containers.
    # For host-based agents prefer local podman first, because podman-remote
    # often exists but is not configured with a valid CONTAINER_HOST.
    bin_candidates = ("podman-remote", "podman") if _is_containerized_runtime() else ("podman", "podman-remote")
    for name in bin_candidates:
        if shutil.which(name):
            _podman_bin = name
            return _podman_bin

    _podman_bin = ""
    if warn and "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


def _runtime_kind(runtime: str) -> str:
    name = os.path.basename(runtime or "")
    return "podman" if name in ("podman", "podman-remote") else name


def _docker_monitor_mode() -> str:
    mode = os.getenv("DOCKER_MONITOR_MODE", "notice").strip().lower()
    return mode if mode in ("notice", "full", "off") else "notice"


def get_runtime_bins() -> Dict[str, str]:
    """Return all enabled and available container runtimes.

    CONTAINER_RUNTIMES accepts ``auto`` (the default) or a comma-separated
    subset of podman,docker,incus.  Unlike the legacy fallback logic this lets
    a host report containers from multiple runtimes in the same cycle.
    """
    global _runtime_bins
    if _runtime_bins is not None:
        return dict(_runtime_bins)

    configured = os.getenv("CONTAINER_RUNTIMES", "auto").strip().lower()
    requested = [x.strip() for x in configured.split(",") if x.strip()]
    auto = not requested or "auto" in requested
    enabled = ("podman", "docker", "incus") if auto else tuple(dict.fromkeys(requested))
    invalid = [name for name in enabled if name not in ("podman", "docker", "incus")]
    if invalid:
        print(f"warn: unsupported container runtimes ignored: {', '.join(invalid)}")

    found: Dict[str, str] = {}
    if "podman" in enabled:
        podman = get_podman_bin(warn=False)
        if podman:
            found["podman"] = podman
    for name in ("docker", "incus"):
        if name not in enabled:
            continue
        if shutil.which(name):
            found[name] = name

    if not found and "container_runtimes" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtimes")
        wanted = ", ".join(x for x in enabled if x in ("podman", "docker", "incus"))
        print(f"missing command: no enabled container runtime found ({wanted})")
    elif not auto:
        for name in enabled:
            if name in ("podman", "docker", "incus") and name not in found:
                key = f"runtime:{name}"
                if key not in _warned_missing_bins:
                    _warned_missing_bins.add(key)
                    print(f"missing command: enabled runtime '{name}' is not installed or not in PATH")

    _runtime_bins = found
    return dict(found)


def get_container_bin() -> str:
    global _container_bin
    if _container_bin is not None:
        return _container_bin

    runtimes = get_runtime_bins()
    for name in ("podman", "docker", "incus"):
        if name in runtimes:
            _container_bin = runtimes[name]
            return _container_bin

    _container_bin = ""
    if "container_runtime" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtime")
        print("missing command: podman (or podman-remote) / docker / incus")
    return _container_bin


def _runtime_command_timeout() -> float:
    try:
        configured = float(os.getenv("RUNTIME_COMMAND_TIMEOUT_SECONDS", "30"))
    except ValueError:
        configured = 30.0
    return max(5.0, min(300.0, configured))


def run(cmd: List[str], timeout: float | None = None) -> str:
    env = None
    if cmd and cmd[0] == "podman-remote":
        socket_path = os.getenv("PODMAN_SOCKET", "/run/podman/podman.sock")
        if "CONTAINER_HOST" not in os.environ and os.path.exists(socket_path):
            env = os.environ.copy()
            env["CONTAINER_HOST"] = f"unix://{socket_path}"
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=_runtime_command_timeout() if timeout is None else timeout,
        )
    except FileNotFoundError:
        if cmd and cmd[0] not in _warned_missing_bins:
            _warned_missing_bins.add(cmd[0])
            print(f"missing command: {cmd[0]}")
        return ""
    except subprocess.TimeoutExpired:
        command_name = cmd[0] if cmd else "unknown"
        if command_name not in _warned_timeout_commands:
            _warned_timeout_commands.add(command_name)
            print(f"runtime command timed out and was skipped: {command_name}")
        return ""
    if p.returncode != 0:
        return ""
    return p.stdout


def run_first_success(commands: List[List[str]]) -> str:
    for cmd in commands:
        out = run(cmd)
        if out.strip():
            return out
    return ""


def _runtime_base(runtime: str, project: str = "") -> List[str]:
    cmd = [runtime]
    if _runtime_kind(runtime) == "incus" and project:
        cmd.extend(["--project", project])
    return cmd


def _runtime_exec_cmd(runtime: str, name: str, shell_command: str, project: str = "") -> List[str]:
    cmd = _runtime_base(runtime, project) + ["exec", name]
    if _runtime_kind(runtime) == "incus":
        cmd.append("--")
    return cmd + ["sh", "-lc", shell_command]


def parse_size(s: str) -> int:
    m = re.match(r"([0-9.]+)([kKmMgGtTpP]?[bB]?)?", s.strip())
    if not m:
        return 0
    n = float(m.group(1))
    unit = (m.group(2) or "").lower()
    mult = 1
    if unit.startswith("k"):
        mult = 1024
    elif unit.startswith("m"):
        mult = 1024**2
    elif unit.startswith("g"):
        mult = 1024**3
    elif unit.startswith("t"):
        mult = 1024**4
    return int(n * mult)


def _normalize_stat_number(raw: object) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if not text:
        return 0.0
    if text.endswith("%"):
        text = text[:-1].strip()
    try:
        return float(text)
    except ValueError:
        return 0.0


def _normalize_key(key: object) -> str:
    text = str(key or "").strip().lower()
    return "".join(ch for ch in text if ch.isalnum())


def _find_value_ci(item: Dict[str, object], keys: List[str]) -> object:
    if not isinstance(item, dict):
        return None
    normalized_map = {_normalize_key(k): v for k, v in item.items()}
    for key in keys:
        k = _normalize_key(key)
        if k in normalized_map and normalized_map[k] is not None:
            return normalized_map[k]
    return None


def _pick_first(item: Dict[str, object], keys: List[str]) -> object:
    for key in keys:
        if key in item and item.get(key) is not None:
            return item.get(key)
    return None


def _parse_stats_json(stats_text: str) -> Dict[str, float | int]:
    cpu_percent = 0.0
    mem_bytes = 0
    mem_limit_bytes = 0
    mem_percent = 0.0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    if not stats_text:
        return {
            "cpu_percent": cpu_percent,
            "mem_bytes": mem_bytes,
            "mem_limit_bytes": mem_limit_bytes,
            "mem_percent": mem_percent,
            "net_rx_total_bytes": net_rx_total_bytes,
            "net_tx_total_bytes": net_tx_total_bytes,
        }

    try:
        payload = json.loads(stats_text)
    except Exception:
        payload = None

    item = None
    if isinstance(payload, list) and payload:
        item = payload[0]
    elif isinstance(payload, dict):
        item = payload

    if isinstance(item, dict):
        cpu_percent = _normalize_stat_number(
            _find_value_ci(item, ["CPU", "CPUPerc", "CPU%", "cpu_percent", "cpu"])
            or _pick_first(item, ["CPU", "CPUPerc", "CPU%"])
        )
        if cpu_percent <= 0:
            cpu_nano = _normalize_stat_number(
                _find_value_ci(item, ["CPUNano", "cpu_nano", "cpu_nanoseconds", "cpu_time"])
            )
            if cpu_nano > 0:
                # 某些运行时仅提供累计 CPU 时间，无法可靠算百分比。
                # 这里保留为 0，后续会尝试 template/top 兜底。
                cpu_percent = 0.0

        mem_usage = _find_value_ci(item, ["MemUsage", "Mem Usage", "mem_usage", "memory"])
        if mem_usage is None:
            mem_usage = _pick_first(item, ["MemUsage", "Mem Usage"])
        if mem_usage is not None:
            mem_usage_parts = str(mem_usage).split("/")
            mem_bytes = parse_size(mem_usage_parts[0].strip())
            if len(mem_usage_parts) == 2:
                mem_limit_bytes = parse_size(mem_usage_parts[1].strip())
        else:
            mem_bytes = int(
                _normalize_stat_number(
                    _find_value_ci(item, ["MemUsageBytes", "MemUsageBytesValue", "mem_usage_bytes", "memory_bytes"])
                    or _pick_first(item, ["MemUsageBytes", "MemUsageBytesValue"])
                )
            )
        mem_percent = _normalize_stat_number(
            _find_value_ci(item, ["MemPerc", "Mem%", "mem_percent", "memory_percent"])
            or _pick_first(item, ["MemPerc", "Mem%"])
        )
        if mem_percent <= 0:
            mem_limit = _normalize_stat_number(
                _find_value_ci(item, ["MemLimit", "MemLimitBytes", "mem_limit", "memory_limit"])
            )
            if mem_limit > 0:
                mem_limit_bytes = int(mem_limit)
            if mem_limit > 0 and mem_bytes > 0:
                mem_percent = (float(mem_bytes) / mem_limit) * 100.0
        if mem_percent <= 0 and mem_limit_bytes > 0 and mem_bytes > 0:
            mem_percent = (float(mem_bytes) / float(mem_limit_bytes)) * 100.0

        net_io = _find_value_ci(item, ["NetIO", "Net I/O", "net_io"])
        if net_io is None:
            net_io = _pick_first(item, ["NetIO", "Net I/O"])
        if net_io is not None:
            net = str(net_io).split("/")
            if len(net) == 2:
                net_rx_total_bytes = parse_size(net[0].strip())
                net_tx_total_bytes = parse_size(net[1].strip())
        else:
            net_in = _normalize_stat_number(
                _find_value_ci(item, ["NetInput", "Net In", "net_input", "rxbytes", "rx"])
                or _pick_first(item, ["NetInput", "Net In"])
            )
            net_out = _normalize_stat_number(
                _find_value_ci(item, ["NetOutput", "Net Out", "net_output", "txbytes", "tx"])
                or _pick_first(item, ["NetOutput", "Net Out"])
            )
            net_rx_total_bytes = int(net_in)
            net_tx_total_bytes = int(net_out)

        if net_rx_total_bytes <= 0 and net_tx_total_bytes <= 0:
            network_obj = _find_value_ci(item, ["Network", "Networks", "network", "networks"])
            if isinstance(network_obj, dict):
                rx_sum = 0.0
                tx_sum = 0.0
                for net_item in network_obj.values():
                    if not isinstance(net_item, dict):
                        continue
                    rx_sum += _normalize_stat_number(
                        _find_value_ci(net_item, ["RxBytes", "rx_bytes", "rx", "received"])
                    )
                    tx_sum += _normalize_stat_number(
                        _find_value_ci(net_item, ["TxBytes", "tx_bytes", "tx", "transmit"])
                    )
                net_rx_total_bytes = int(rx_sum)
                net_tx_total_bytes = int(tx_sum)

    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "mem_limit_bytes": mem_limit_bytes,
        "mem_percent": mem_percent,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_template(stats_text: str) -> Dict[str, float | int]:
    cpu_percent = 0.0
    mem_bytes = 0
    mem_limit_bytes = 0
    mem_percent = 0.0
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0

    parts = (stats_text or "").strip().split("|")
    if len(parts) >= 3:
        cpu_percent = _normalize_stat_number(parts[0])
        mem_bytes = parse_size(parts[1].split("/")[0].strip())
        mem_usage_parts = parts[1].split("/")
        if len(mem_usage_parts) == 2:
            mem_total = parse_size(mem_usage_parts[1].strip())
            mem_limit_bytes = mem_total
            if mem_total > 0 and mem_bytes > 0:
                mem_percent = (float(mem_bytes) / mem_total) * 100.0
        net = parts[2].split("/")
        if len(net) == 2:
            net_rx_total_bytes = parse_size(net[0].strip())
            net_tx_total_bytes = parse_size(net[1].strip())
        if len(parts) >= 4 and net_rx_total_bytes <= 0:
            net_rx_total_bytes = parse_size(parts[2].strip())
        if len(parts) >= 5 and net_tx_total_bytes <= 0:
            net_tx_total_bytes = parse_size(parts[3].strip())

    return {
        "cpu_percent": cpu_percent,
        "mem_bytes": mem_bytes,
        "mem_limit_bytes": mem_limit_bytes,
        "mem_percent": mem_percent,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _parse_stats_compact(stats_text: str) -> Dict[str, float | int]:
    parts = (stats_text or "").strip().split("|")
    if len(parts) < 3:
        return {"cpu_percent": 0.0, "mem_bytes": 0, "mem_limit_bytes": 0, "mem_percent": 0.0, "net_rx_total_bytes": 0, "net_tx_total_bytes": 0}
    net_rx_total_bytes = 0
    net_tx_total_bytes = 0
    net = parts[2].split("/")
    if len(net) == 2:
        net_rx_total_bytes = parse_size(net[0].strip())
        net_tx_total_bytes = parse_size(net[1].strip())
    elif len(parts) >= 4:
        net_rx_total_bytes = parse_size(parts[2])
        net_tx_total_bytes = parse_size(parts[3])
    return {
        "cpu_percent": _normalize_stat_number(parts[0]),
        "mem_bytes": parse_size(parts[1]),
        "mem_limit_bytes": 0,
        "mem_percent": 0.0,
        "net_rx_total_bytes": net_rx_total_bytes,
        "net_tx_total_bytes": net_tx_total_bytes,
    }


def _derive_net_bps(container_key: str, rx_total: int, tx_total: int) -> Tuple[float, float]:
    now = float(time.time())
    prev = _net_counters.get(container_key)
    _net_counters[container_key] = {"ts": now, "rx": float(rx_total), "tx": float(tx_total)}
    if not prev:
        return 0.0, 0.0

    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0, 0.0

    rx_delta = max(0.0, float(rx_total) - float(prev.get("rx", 0.0)))
    tx_delta = max(0.0, float(tx_total) - float(prev.get("tx", 0.0)))
    return rx_delta / dt, tx_delta / dt


def _derive_cpu_percent(container_key: str, cpu_seconds: float) -> float:
    now = float(time.time())
    prev = _cpu_counters.get(container_key)
    _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds)}
    if not prev:
        return 0.0
    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0
    delta = max(0.0, float(cpu_seconds) - float(prev.get("cpu", 0.0)))
    return (delta / dt) * 100.0


def _derive_packet_rates(container_key: str, rx_packets: int, tx_packets: int) -> Tuple[float, float]:
    now = float(time.time())
    prev = _packet_counters.get(container_key)
    _packet_counters[container_key] = {
        "ts": now,
        "rx_packets": float(rx_packets),
        "tx_packets": float(tx_packets),
    }
    if not prev:
        return 0.0, 0.0
    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        return 0.0, 0.0
    rx_delta = max(0.0, float(rx_packets) - float(prev.get("rx_packets", 0.0)))
    tx_delta = max(0.0, float(tx_packets) - float(prev.get("tx_packets", 0.0)))
    return rx_delta / dt, tx_delta / dt


def _read_protocol_counters(pid: int) -> Dict[str, int]:
    wanted = {
        "Tcp": ("ActiveOpens", "AttemptFails", "EstabResets", "OutRsts"),
        "Udp": ("OutDatagrams", "NoPorts", "InErrors"),
    }
    result: Dict[str, int] = {}
    if pid <= 0:
        return result
    try:
        with open(f"/proc/{pid}/net/snmp", "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
    except Exception:
        return result
    for index in range(0, len(lines) - 1, 2):
        header = lines[index].split()
        values = lines[index + 1].split()
        if not header or not values or header[0] != values[0]:
            continue
        protocol = header[0].rstrip(":")
        if protocol not in wanted:
            continue
        mapping = dict(zip(header[1:], values[1:]))
        for field in wanted[protocol]:
            try:
                result[f"{protocol}_{field}"] = int(mapping.get(field, "0"))
            except ValueError:
                result[f"{protocol}_{field}"] = 0
    return result


def _derive_protocol_rates(container_key: str, counters: Dict[str, int]) -> Dict[str, float]:
    now = float(time.time())
    previous = _protocol_counters.get(container_key)
    current: Dict[str, float] = {"ts": now}
    current.update({key: float(value) for key, value in counters.items()})
    _protocol_counters[container_key] = current
    if not previous:
        return {f"{key}_per_second": 0.0 for key in counters}
    dt = now - float(previous.get("ts", 0.0))
    if dt <= 0:
        return {f"{key}_per_second": 0.0 for key in counters}
    return {
        f"{key}_per_second": max(0.0, float(value) - float(previous.get(key, value))) / dt
        for key, value in counters.items()
    }


_PROM_LABEL_RE = re.compile(r'(\w+)="((?:\\.|[^"\\])*)"')


def _parse_prometheus_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for match in _PROM_LABEL_RE.finditer(raw or ""):
        value = match.group(2)
        try:
            value = json.loads(f'"{value}"')
        except Exception:
            pass
        labels[match.group(1)] = value
    return labels


def _parse_incus_metrics(text: str) -> Dict[Tuple[str, str], Dict[str, float]]:
    """Parse the subset of Incus OpenMetrics used by this agent."""
    result: Dict[Tuple[str, str], Dict[str, float]] = {}
    wanted = {
        "incus_cpu_seconds_total",
        "incus_cpu_effective_total",
        "incus_memory_MemTotal_bytes",
        "incus_memory_MemAvailable_bytes",
        "incus_network_receive_bytes_total",
        "incus_network_transmit_bytes_total",
        "incus_network_receive_packets_total",
        "incus_network_transmit_packets_total",
        "incus_filesystem_size_bytes",
        "incus_filesystem_avail_bytes",
    }
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)", line)
        if not match or match.group(1) not in wanted:
            continue
        metric, raw_labels, raw_value = match.groups()
        try:
            value = float(raw_value)
        except ValueError:
            continue
        labels = _parse_prometheus_labels(raw_labels or "")
        if labels.get("type") not in (None, "container"):
            continue
        name = labels.get("name", "")
        if not name:
            continue
        project = labels.get("project", "default")
        item = result.setdefault(
            (project, name),
            {
                "cpu_seconds": 0.0,
                "effective_cpus": 0.0,
                "mem_bytes": 0.0,
                "mem_total_bytes": 0.0,
                "mem_available_bytes": -1.0,
                "net_rx_total_bytes": 0.0,
                "net_tx_total_bytes": 0.0,
                "net_rx_total_packets": 0.0,
                "net_tx_total_packets": 0.0,
                "fs_total_bytes": 0.0,
                "fs_avail_bytes": 0.0,
            },
        )
        if metric == "incus_cpu_seconds_total":
            if labels.get("mode", "") != "idle":
                item["cpu_seconds"] += value
        elif metric == "incus_cpu_effective_total":
            item["effective_cpus"] = value
        elif metric == "incus_memory_MemTotal_bytes":
            item["mem_total_bytes"] = value
        elif metric == "incus_memory_MemAvailable_bytes":
            item["mem_available_bytes"] = value
        elif metric == "incus_network_receive_bytes_total":
            if labels.get("device") != "lo":
                item["net_rx_total_bytes"] += value
        elif metric == "incus_network_transmit_bytes_total":
            if labels.get("device") != "lo":
                item["net_tx_total_bytes"] += value
        elif metric == "incus_network_receive_packets_total":
            if labels.get("device") != "lo":
                item["net_rx_total_packets"] += value
        elif metric == "incus_network_transmit_packets_total":
            if labels.get("device") != "lo":
                item["net_tx_total_packets"] += value
        elif metric == "incus_filesystem_size_bytes":
            item["fs_total_bytes"] = max(item["fs_total_bytes"], value)
        elif metric == "incus_filesystem_avail_bytes":
            item["fs_avail_bytes"] = max(item["fs_avail_bytes"], value)
    for item in result.values():
        total = float(item.get("mem_total_bytes", 0.0) or 0.0)
        available = float(item.get("mem_available_bytes", -1.0))
        if total > 0 and available >= 0:
            item["mem_bytes"] = max(0.0, min(total, total - available))
    return result


def _get_incus_metrics(runtime: str = "incus") -> Dict[Tuple[str, str], Dict[str, float]]:
    now = float(time.time())
    cached_ts = float(_incus_metrics_cache.get("ts", 0.0) or 0.0)
    if now - cached_ts < 7 and isinstance(_incus_metrics_cache.get("parsed"), dict):
        return _incus_metrics_cache["parsed"]  # type: ignore[return-value]
    text = run([runtime, "query", "/1.0/metrics"])
    parsed = _parse_incus_metrics(text)
    _incus_metrics_cache.update({"ts": now, "text": text, "parsed": parsed})
    return parsed


def _count_proc_net_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0
    if len(lines) <= 1:
        return 0
    return len(lines) - 1


def _count_connections_from_pid(pid: int) -> int:
    if pid <= 0:
        return 0
    base = f"/proc/{pid}/net"
    files = ("tcp", "tcp6", "udp", "udp6")
    total = 0
    for name in files:
        total += _count_proc_net_lines(f"{base}/{name}")
    return total


def _decode_proc_addr(hex_ip: str, is_v6: bool = False) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if is_v6:
            # /proc/net/tcp6 and udp6 store four little-endian 32-bit words.
            normalized = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
            address = ipaddress.IPv6Address(normalized)
            if address.ipv4_mapped:
                return str(address.ipv4_mapped)
            return str(address)
        return str(ipaddress.IPv4Address(raw[::-1]))
    except Exception:
        return ""


def _collect_tcp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "tcp")


def _collect_udp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "udp")


def _parse_remote_endpoint_ip(endpoint: str) -> str:
    text = (endpoint or "").strip()
    if not text or text in ("*", "*:*"):
        return ""
    if text.startswith("[") and "]" in text:
        return text[1:text.find("]")]
    if text.count(":") >= 2:
        # IPv6 endpoint，可能是 "2001:db8::1:443" 或 "::ffff:1.2.3.4:443"
        host, _, _ = text.rpartition(":")
        return host.strip("[]")
    if ":" in text:
        return text.split(":", 1)[0]
    return text


def _is_trackable_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # 私网地址也保留，GeoIP 失败时统一归为 UN，避免前端“国家 Top3”整列为空。
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    return True


def _is_public_source_ip(ip: str) -> bool:
    if not _is_trackable_ip(ip):
        return False
    try:
        return bool(ipaddress.ip_address(ip).is_global)
    except ValueError:
        return False


def _collect_remote_ips_from_exec(runtime: str, name: str, proto: str, project: str = "") -> Dict[str, int]:
    if not runtime or not name:
        return {}
    if proto == "udp":
        cmd = "ss -Huan 2>/dev/null | awk '{print $5}' || (netstat -nu 2>/dev/null | awk 'NR>2{print $5}')"
    else:
        cmd = "ss -Htan state established 2>/dev/null | awk '{print $5}' || (netstat -nt 2>/dev/null | awk 'NR>2{print $5}')"
    out = run(_runtime_exec_cmd(runtime, name, cmd, project))
    ip_counter: Dict[str, int] = {}
    for line in out.splitlines():
        ip = _parse_remote_endpoint_ip(line)
        if not _is_trackable_ip(ip):
            continue
        ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _collect_remote_ips_by_proto(pid: int, proto: str) -> Dict[str, int]:
    if pid <= 0:
        return {}
    ip_counter: Dict[str, int] = {}
    if proto == "udp":
        files = (("udp", False), ("udp6", True))
    else:
        files = (("tcp", False), ("tcp6", True))
    for name, is_v6 in files:
        path = f"/proc/{pid}/net/{name}"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            rem = parts[2]
            state = parts[3].upper()
            # TCP 仅统计 ESTABLISHED；UDP 无连接状态语义，统计所有有效远端。
            if proto == "tcp" and state != "01":
                continue
            if ":" not in rem:
                continue
            rem_ip_hex = rem.split(":", 1)[0]
            ip = _decode_proc_addr(rem_ip_hex, is_v6=is_v6)
            if not ip:
                continue
            if ip in ("0.0.0.0", "::"):
                continue
            if not _is_trackable_ip(ip):
                continue
            ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _parse_socket_endpoint(endpoint: str) -> Tuple[str, int]:
    text = (endpoint or "").strip()
    if not text or text in ("*", "*:*", "0.0.0.0:*", "[::]:*"):
        return "", 0
    host, separator, port_text = text.rpartition(":")
    if not separator:
        return text.strip("[]"), 0
    host = host.strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    try:
        parsed_host = ipaddress.ip_address(host)
        if isinstance(parsed_host, ipaddress.IPv6Address) and parsed_host.ipv4_mapped:
            host = str(parsed_host.ipv4_mapped)
        else:
            host = str(parsed_host)
    except ValueError:
        pass
    return host, port


def _collect_socket_process_details(
    runtime: str,
    name: str,
    project: str,
    listening_ports: List[int],
    snapshot_limit_override: int = 0,
    detail_limit_override: int = 0,
) -> Dict[str, object]:
    """Collect one bounded socket snapshot and reuse it for process attribution."""
    snapshot_limit = (
        max(50, min(2000, int(snapshot_limit_override)))
        if snapshot_limit_override
        else max(50, min(2000, int(_env_float("SECURITY_SOCKET_SNAPSHOT_MAX", 500))))
    )
    detail_limit = (
        max(10, min(500, int(detail_limit_override)))
        if detail_limit_override
        else max(10, min(500, int(_env_float("SECURITY_COMMUNICATION_DETAIL_MAX", 100))))
    )
    command = (
        "if command -v ss >/dev/null 2>&1; then "
        "echo @@SS_AVAILABLE@@; "
        f"ss -H -t -u -n -a -p 2>/dev/null | head -n {snapshot_limit}; "
        "fi"
    )
    output = run(_runtime_exec_cmd(runtime, name, command, project))
    available = "@@SS_AVAILABLE@@" in output
    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.strip() != "@@SS_AVAILABLE@@"
    ]
    listening = {int(port) for port in listening_ports if int(port) > 0}
    sockets: List[Dict[str, object]] = []
    process_totals: Dict[Tuple[int, str], Dict[str, object]] = {}

    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue
        state = parts[1].upper()
        local_endpoint = parts[4]
        remote_endpoint = parts[5]
        process_text = parts[6] if len(parts) > 6 else ""
        remote_ip, remote_port = _parse_socket_endpoint(remote_endpoint)
        _, local_port = _parse_socket_endpoint(local_endpoint)
        if not _is_trackable_ip(remote_ip):
            continue
        if proto.startswith("tcp") and state not in ("ESTAB", "ESTABLISHED", "SYN-SENT", "SYN-RECV"):
            continue
        if proto.startswith("udp") and remote_port <= 0:
            continue
        direction = "inbound" if local_port in listening or state == "SYN-RECV" else "outbound"
        owners = re.findall(r'\("([^"\\]{1,120})",pid=(\d+)', process_text)
        process_name = owners[0][0] if owners else "unknown"
        process_pid = int(owners[0][1]) if owners else 0
        item = {
            "proto": "tcp" if proto.startswith("tcp") else "udp",
            "state": state.lower(),
            "direction": direction,
            "local": local_endpoint,
            "remote": remote_endpoint,
            "remote_ip": remote_ip,
            "process": process_name,
            "pid": process_pid,
        }
        if len(sockets) < detail_limit:
            sockets.append(item)
        key = (process_pid, process_name)
        aggregate = process_totals.setdefault(
            key,
            {
                "pid": process_pid,
                "process": process_name,
                "inbound_connections": 0,
                "outbound_connections": 0,
                "remote_ips": set(),
            },
        )
        aggregate[f"{direction}_connections"] = int(aggregate[f"{direction}_connections"]) + 1
        remote_ips = aggregate["remote_ips"]
        if isinstance(remote_ips, set):
            remote_ips.add(remote_ip)

    processes = []
    for aggregate in process_totals.values():
        remote_ips = aggregate.pop("remote_ips", set())
        aggregate["unique_remote_ips"] = len(remote_ips) if isinstance(remote_ips, set) else 0
        processes.append(aggregate)
    processes.sort(
        key=lambda item: int(item["inbound_connections"]) + int(item["outbound_connections"]),
        reverse=True,
    )
    return {
        "communication_detail_available": available,
        "communication_snapshot_count": len(lines),
        "communication_snapshot_truncated": len(lines) >= snapshot_limit,
        "communication_processes": processes[:50],
        "communication_sockets": sockets,
    }


def _geoip_cache_limits() -> Tuple[int, float, float]:
    try:
        max_entries = int(os.getenv("GEOIP_CACHE_MAX_ENTRIES", "4096"))
    except ValueError:
        max_entries = 4096
    try:
        ttl = float(os.getenv("GEOIP_CACHE_TTL_SECONDS", "86400"))
    except ValueError:
        ttl = 86400.0
    try:
        negative_ttl = float(os.getenv("GEOIP_NEGATIVE_CACHE_TTL_SECONDS", "900"))
    except ValueError:
        negative_ttl = 900.0
    return (
        max(100, min(50000, max_entries)),
        max(300.0, min(2592000.0, ttl)),
        max(60.0, min(86400.0, negative_ttl)),
    )


def _geoip_cache_get(ip: str, now: float) -> str:
    cached = _geoip_country_cache.get(ip)
    if cached is None:
        return ""
    country, expires_at = cached
    if expires_at <= now:
        _geoip_country_cache.pop(ip, None)
        return ""
    # Refresh insertion order so trimming behaves like a small LRU cache.
    _geoip_country_cache.pop(ip, None)
    _geoip_country_cache[ip] = (country, expires_at)
    return country


def _geoip_cache_put(ip: str, country: str, now: float) -> None:
    max_entries, ttl, negative_ttl = _geoip_cache_limits()
    normalized = country.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", normalized):
        normalized = "UN"
    _geoip_country_cache.pop(ip, None)
    _geoip_country_cache[ip] = (
        normalized,
        now + (negative_ttl if normalized == "UN" else ttl),
    )
    while len(_geoip_country_cache) > max_entries:
        _geoip_country_cache.pop(next(iter(_geoip_country_cache)))


def _geoip_local_country_batch(ips: List[str]) -> Dict[str, str]:
    global _geoip_reader, _geoip_reader_path
    if not ips or maxminddb is None:
        return {}
    configured_path = os.getenv(
        "GEOIP_MMDB_PATH", "/usr/share/GeoIP/GeoLite2-Country.mmdb"
    ).strip()
    if not configured_path or not os.path.isfile(configured_path):
        return {}
    if _geoip_reader is None or _geoip_reader_path != configured_path:
        if _geoip_reader is not None:
            try:
                _geoip_reader.close()
            except Exception:
                pass
        try:
            _geoip_reader = maxminddb.open_database(configured_path)
            _geoip_reader_path = configured_path
        except Exception:
            _geoip_reader = None
            _geoip_reader_path = ""
            return {}
    result: Dict[str, str] = {}
    for ip in ips:
        try:
            record = _geoip_reader.get(ip) or {}
            country = str((record.get("country") or {}).get("iso_code") or "")
        except Exception:
            country = ""
        if re.fullmatch(r"[A-Za-z]{2}", country):
            result[ip] = country.upper()
    return result


def _geoip_https_country_batch(ips: List[str]) -> Dict[str, str]:
    if not ips or os.getenv("GEOIP_HTTPS_ENABLED", "true").strip().lower() in (
        "0", "false", "no", "off"
    ):
        return {}
    endpoint = os.getenv("GEOIP_HTTPS_ENDPOINT", "https://api.country.is/").strip()
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        return {}
    try:
        response = requests.post(
            endpoint,
            json=ips[:100],
            headers={"User-Agent": f"Narwhal-Monitor/{APP_VERSION}"},
            timeout=8,
        )
        response.raise_for_status()
        values = response.json()
    except Exception:
        return {}
    if not isinstance(values, list):
        return {}
    result: Dict[str, str] = {}
    requested = set(ips)
    for item in values:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "")
        country = str(item.get("country") or "").upper()
        if ip in requested and re.fullmatch(r"[A-Z]{2}", country):
            result[ip] = country
    return result


def _geoip_country_batch(ip_counts: Dict[str, int]) -> List[Dict[str, int | str]]:
    if not ip_counts:
        return []
    now = time.monotonic()
    countries = {ip: _geoip_cache_get(ip, now) for ip in ip_counts}
    unresolved = [ip for ip, country in countries.items() if not country]
    if unresolved:
        public_unresolved = [ip for ip in unresolved if _is_public_source_ip(ip)]
        resolved = (
            _geoip_local_country_batch(public_unresolved)
            if public_unresolved
            else {}
        )
        still_unresolved = [ip for ip in public_unresolved if ip not in resolved]
        if still_unresolved:
            resolved.update(_geoip_https_country_batch(still_unresolved))
        for ip in unresolved:
            country = resolved.get(ip, "UN")
            _geoip_cache_put(ip, country, now)
            countries[ip] = country

    country_counter: Dict[str, Dict[str, int | str]] = {}
    for ip, cnt in ip_counts.items():
        country = countries.get(ip) or "UN"
        if country not in country_counter:
            country_counter[country] = {"country": country, "connections": 0, "ip_count": 0}
        country_counter[country]["connections"] = int(country_counter[country]["connections"]) + int(cnt)
        country_counter[country]["ip_count"] = int(country_counter[country]["ip_count"]) + 1
    return sorted(country_counter.values(), key=lambda x: int(x["connections"]), reverse=True)


def _read_mem_usage_from_pid(pid: int) -> Tuple[int, float]:
    if pid <= 0:
        return 0, 0.0
    base = f"/proc/{pid}/root/sys/fs/cgroup"
    candidates = (
        (f"{base}/memory.current", f"{base}/memory.max"),  # cgroup v2
        (f"{base}/memory/memory.usage_in_bytes", f"{base}/memory/memory.limit_in_bytes"),  # cgroup v1
    )
    for usage_path, limit_path in candidates:
        try:
            with open(usage_path, "r", encoding="utf-8", errors="ignore") as f:
                usage_raw = f.read().strip()
            with open(limit_path, "r", encoding="utf-8", errors="ignore") as f:
                limit_raw = f.read().strip()
        except Exception:
            continue
        if not usage_raw.isdigit():
            continue
        usage = int(usage_raw)
        if usage <= 0:
            continue
        if limit_raw.isdigit():
            limit = int(limit_raw)
            if limit > 0 and limit < (1 << 60):
                return usage, (float(usage) / float(limit)) * 100.0
        return usage, 0.0
    return 0, 0.0


def _read_process_count_from_pid(pid: int) -> int:
    if pid <= 0:
        return 0
    for path in (
        f"/proc/{pid}/root/sys/fs/cgroup/pids.current",
        f"/proc/{pid}/root/sys/fs/cgroup/pids/pids.current",
    ):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                value = handle.read().strip()
            if value.isdigit():
                return int(value)
        except Exception:
            continue
    return 0


def _read_net_stats_from_pid(pid: int) -> Tuple[int, int, int, int]:
    if pid <= 0:
        return 0, 0, 0, 0
    path = f"/proc/{pid}/net/dev"
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0, 0, 0, 0
    if len(lines) <= 2:
        return 0, 0, 0, 0

    rx_total = 0
    tx_total = 0
    rx_packets = 0
    tx_packets = 0
    for line in lines[2:]:
        if ":" not in line:
            continue
        interface, data = line.split(":", 1)
        if interface.strip() == "lo":
            continue
        cols = data.split()
        if len(cols) < 16:
            continue
        try:
            rx_total += int(cols[0])
            rx_packets += int(cols[1])
            tx_total += int(cols[8])
            tx_packets += int(cols[9])
        except ValueError:
            continue
    return rx_total, tx_total, rx_packets, tx_packets


def _read_net_bytes_from_pid(pid: int) -> Tuple[int, int]:
    rx_total, tx_total, _, _ = _read_net_stats_from_pid(pid)
    return rx_total, tx_total


def _count_connections_from_exec(runtime: str, name: str, project: str = "") -> int:
    if not runtime or not name:
        return 0
    cmd = (
        "if command -v ss >/dev/null 2>&1; then "
        "  (ss -Htan 2>/dev/null; ss -Huan 2>/dev/null) | wc -l; "
        "elif command -v netstat >/dev/null 2>&1; then "
        "  tcp=$(netstat -nt 2>/dev/null | awk 'NR>2' | wc -l); "
        "  udp=$(netstat -nu 2>/dev/null | awk 'NR>2' | wc -l); "
        "  echo $((tcp + udp)); "
        "else "
        "  echo 0; "
        "fi"
    )
    out = run(_runtime_exec_cmd(runtime, name, cmd, project)).strip()
    return int(out) if out.isdigit() else 0


def _parse_port(hex_port: str) -> int:
    try:
        return int(hex_port, 16)
    except (TypeError, ValueError):
        return 0


def _collect_socket_security(pid: int) -> Dict[str, object]:
    result: Dict[str, object] = {
        "tcp_states": {},
        "syn_recv_count": 0,
        "incoming_established": 0,
        "inbound_unique_ips": 0,
        "inbound_top_ips": [],
        "inbound_unique_ip_threshold": int(_env_float("ALERT_INBOUND_UNIQUE_IPS", 10)),
        "inbound_ip_observation": "container_socket",
        "inbound_public_flows": [],
        "container_ips": [],
        "outbound_established": 0,
        "outbound_unique_ips": 0,
        "outbound_unique_ports": 0,
        "suspicious_outbound_connections": 0,
        "scan_unique_ports_max": 0,
        "scan_source_ip": "",
        "listening_ports": [],
        "listening_endpoints": [],
    }
    if pid <= 0:
        return result

    entries: List[Dict[str, object]] = []
    for filename, is_v6 in (("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)):
        try:
            with open(f"/proc/{pid}/net/{filename}", "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
        except Exception:
            continue
        proto = "udp" if filename.startswith("udp") else "tcp"
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1] or ":" not in parts[2]:
                continue
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            remote_ip_hex, remote_port_hex = parts[2].rsplit(":", 1)
            entries.append(
                {
                    "proto": proto,
                    "state": parts[3].upper(),
                    "local_ip": _decode_proc_addr(local_ip_hex, is_v6=is_v6),
                    "local_port": _parse_port(local_port_hex),
                    "remote_port": _parse_port(remote_port_hex),
                    "remote_ip": _decode_proc_addr(remote_ip_hex, is_v6=is_v6),
                }
            )

    listening_ports = {
        int(x["local_port"])
        for x in entries
        if x["proto"] == "tcp" and x["state"] == "0A" and int(x["local_port"]) > 0
    }
    listening_endpoints = sorted(
        {
            f"[{entry['local_ip']}]:{int(entry['local_port'])}"
            if ":" in str(entry["local_ip"])
            else f"{entry['local_ip']}:{int(entry['local_port'])}"
            for entry in entries
            if entry["proto"] == "tcp" and entry["state"] == "0A" and int(entry["local_port"]) > 0
        }
    )
    container_ips = {
        str(entry["local_ip"])
        for entry in entries
        if _is_trackable_ip(str(entry.get("local_ip") or ""))
    }
    state_names = {
        "01": "established",
        "02": "syn_sent",
        "03": "syn_recv",
        "04": "fin_wait1",
        "05": "fin_wait2",
        "06": "time_wait",
        "07": "close",
        "08": "close_wait",
        "09": "last_ack",
        "0A": "listen",
        "0B": "closing",
    }
    tcp_states: Dict[str, int] = {}
    outbound_ips = set()
    outbound_ports = set()
    inbound_source_ports: Dict[str, set] = {}
    inbound_ip_connections: Dict[str, int] = {}
    suspicious_ports = {
        int(x.strip())
        for x in os.getenv("SECURITY_SUSPICIOUS_OUTBOUND_PORTS", "25,465,587,23,445,6667").split(",")
        if x.strip().isdigit()
    }
    suspicious_connections = 0
    incoming_established = 0
    outbound_established = 0
    syn_recv = 0

    for entry in entries:
        proto = str(entry["proto"])
        state = str(entry["state"])
        local_port = int(entry["local_port"])
        local_ip = str(entry["local_ip"])
        remote_port = int(entry["remote_port"])
        remote_ip = str(entry["remote_ip"])
        if proto == "tcp":
            state_name = state_names.get(state, state.lower())
            tcp_states[state_name] = tcp_states.get(state_name, 0) + 1
            if state == "03":
                syn_recv += 1
            if state not in ("01", "02", "03"):
                continue
        elif remote_port <= 0:
            continue

        incoming = local_port in listening_ports or state == "03"
        if incoming:
            if state == "01":
                incoming_established += 1
            if _is_trackable_ip(remote_ip) and remote_ip != local_ip:
                inbound_source_ports.setdefault(remote_ip, set()).add(local_port)
                inbound_ip_connections[remote_ip] = inbound_ip_connections.get(remote_ip, 0) + 1
            continue
        if not _is_trackable_ip(remote_ip):
            continue
        outbound_ips.add(remote_ip)
        if remote_port > 0:
            outbound_ports.add(remote_port)
        if state == "01" or proto == "udp":
            outbound_established += 1
            if remote_port in suspicious_ports:
                suspicious_connections += 1

    scan_source_ip = ""
    scan_unique_ports_max = 0
    for source_ip, ports in inbound_source_ports.items():
        if len(ports) > scan_unique_ports_max:
            scan_unique_ports_max = len(ports)
            scan_source_ip = source_ip

    result.update(
        {
            "tcp_states": tcp_states,
            "syn_recv_count": syn_recv,
            "incoming_established": incoming_established,
            "inbound_unique_ips": len(inbound_source_ports),
            "inbound_top_ips": [
                {"ip": ip, "connections": count}
                for ip, count in sorted(
                    inbound_ip_connections.items(), key=lambda item: item[1], reverse=True
                )[:20]
            ],
            "inbound_unique_ip_threshold": int(_env_float("ALERT_INBOUND_UNIQUE_IPS", 10)),
            "container_ips": sorted(container_ips),
            "outbound_established": outbound_established,
            "outbound_unique_ips": len(outbound_ips),
            "outbound_unique_ports": len(outbound_ports),
            "suspicious_outbound_connections": suspicious_connections,
            "scan_unique_ports_max": scan_unique_ports_max,
            "scan_source_ip": scan_source_ip,
            "listening_ports": sorted(listening_ports),
            "listening_endpoints": listening_endpoints,
        }
    )
    return result


def _parse_conntrack_line(line: str) -> Dict[str, object] | None:
    """Parse the original and reply tuples from one conntrack record."""
    proto = next((token.lower() for token in line.split()[:8] if token.lower() in ("tcp", "udp")), "")
    src_values = re.findall(r"\bsrc=([^\s]+)", line)
    dst_values = re.findall(r"\bdst=([^\s]+)", line)
    sport_values = re.findall(r"\bsport=(\d+)", line)
    dport_values = re.findall(r"\bdport=(\d+)", line)
    if not proto or len(src_values) < 2 or len(dst_values) < 2:
        return None
    if not _is_trackable_ip(src_values[0]):
        return None
    try:
        original_sport = int(sport_values[0]) if sport_values else 0
        original_dport = int(dport_values[0]) if dport_values else 0
        reply_sport = int(sport_values[1]) if len(sport_values) > 1 else 0
        reply_dport = int(dport_values[1]) if len(dport_values) > 1 else 0
    except ValueError:
        return None
    return {
        "proto": proto,
        "original_src": src_values[0],
        "original_dst": dst_values[0],
        "original_sport": original_sport,
        "original_dport": original_dport,
        "reply_src": src_values[1],
        "reply_dst": dst_values[1],
        "reply_sport": reply_sport,
        "reply_dport": reply_dport,
    }


def _collect_host_conntrack_snapshot() -> Dict[str, object]:
    """Read one bounded host conntrack snapshot for NAT-aware source attribution."""
    limit = max(100, min(50000, int(_env_float("SECURITY_CONNTRACK_SNAPSHOT_MAX", 5000))))
    lines: List[str] = []
    available = False
    for path in ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                available = True
                for index, line in enumerate(handle):
                    if index >= limit:
                        break
                    if line.strip():
                        lines.append(line.strip())
            break
        except (FileNotFoundError, PermissionError, OSError):
            continue
    if not available:
        output = run(
            [
                "sh",
                "-lc",
                "if command -v conntrack >/dev/null 2>&1; then "
                f"conntrack -L -o extended 2>/dev/null | sed -n '1,{limit}p'; fi",
            ]
        )
        if output.strip():
            available = True
            lines = [line.strip() for line in output.splitlines()[:limit] if line.strip()]
    host_addresses = set()
    address_output = run(["ip", "-j", "address", "show"])
    if address_output.strip():
        try:
            address_payload = json.loads(address_output)
        except (TypeError, ValueError):
            address_payload = []
        for interface in address_payload if isinstance(address_payload, list) else []:
            if not isinstance(interface, dict):
                continue
            address_info = interface.get("addr_info") if isinstance(interface.get("addr_info"), list) else []
            for address in address_info:
                if not isinstance(address, dict):
                    continue
                value = str(address.get("local") or "")
                if _is_trackable_ip(value):
                    host_addresses.add(value)
    nat_mappings: List[Dict[str, object]] = []
    nat_output = run(["sh", "-lc", "iptables-save -t nat 2>/dev/null || true"])
    for line in nat_output.splitlines():
        proto_match = re.search(r"(?:^|\s)-p\s+(tcp|udp)\b", line, re.IGNORECASE)
        port_match = re.search(r"(?:^|\s)--dport\s+(\d+)\b", line)
        target_match = re.search(r"(?:^|\s)--to-destination\s+([^\s]+)", line)
        if not port_match or not target_match:
            continue
        target_host, target_port = _parse_socket_endpoint(target_match.group(1))
        destination_match = re.search(r"(?:^|\s)-d\s+([^\s/]+)(?:/\d+)?", line)
        nat_mappings.append(
            {
                "proto": proto_match.group(1).lower() if proto_match else "",
                "host": destination_match.group(1) if destination_match else "",
                "public_port": int(port_match.group(1)),
                "target_host": target_host,
                "container_port": target_port,
            }
        )
    if not nat_mappings:
        nft_output = run(
            [
                "sh",
                "-lc",
                "if command -v nft >/dev/null 2>&1; then "
                "nft list ruleset 2>/dev/null | grep -E '(^|[[:space:]])dnat[[:space:]]+to[[:space:]]' | "
                "sed -n '1,2000p'; fi",
            ]
        )
        for line in nft_output.splitlines():
            mapping_match = re.search(
                r"\b(tcp|udp)\s+dport\s+(\d+).*?\bdnat\s+to\s+([^\s]+)",
                line,
                re.IGNORECASE,
            )
            if not mapping_match:
                continue
            target_host, target_port = _parse_socket_endpoint(mapping_match.group(3))
            destination_match = re.search(r"\b(?:ip|ip6)\s+daddr\s+([^\s]+)", line)
            nat_mappings.append(
                {
                    "proto": mapping_match.group(1).lower(),
                    "host": destination_match.group(1) if destination_match else "",
                    "public_port": int(mapping_match.group(2)),
                    "target_host": target_host,
                    "container_port": target_port,
                }
            )
    entries = []
    for line in lines:
        parsed = _parse_conntrack_line(line)
        if parsed:
            entries.append(parsed)
    return {
        "available": available,
        "snapshot_count": len(lines),
        "snapshot_truncated": len(lines) >= limit,
        "host_addresses": sorted(host_addresses),
        "nat_mappings": nat_mappings[:2000],
        "entries": entries,
    }


def _augment_conntrack_with_host_proxy_sockets(
    conntrack: Dict[str, object], containers: List[Dict[str, object]]
) -> None:
    """Safely correlate two-leg user-space proxy sockets when one PID has one target."""
    address_owners: Dict[str, str] = {}
    for container in containers:
        if not isinstance(container, dict) or container.get("runtime") == "docker":
            continue
        for address in container.get("network_addresses") or []:
            value = str(address)
            if _is_trackable_ip(value):
                address_owners[value] = str(container.get("name") or "")
    if not address_owners:
        return
    limit = max(100, min(20000, int(_env_float("SECURITY_HOST_PROXY_SOCKET_MAX", 5000))))
    output = run(
        [
            "sh",
            "-lc",
            "if command -v ss >/dev/null 2>&1; then "
            f"ss -H -t -u -n -a -p 2>/dev/null | sed -n '1,{limit}p'; fi",
        ]
    )
    lines = [line.strip() for line in output.splitlines()[:limit] if line.strip()]
    listeners: Dict[Tuple[int, str], set] = {}
    established: List[Dict[str, object]] = []
    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        state = parts[1].upper()
        local_ip, local_port = _parse_socket_endpoint(parts[4])
        remote_ip, remote_port = _parse_socket_endpoint(parts[5])
        process_text = parts[6] if len(parts) > 6 else ""
        owners = re.findall(r'\("([^"\\]{1,120})",pid=(\d+)', process_text)
        if not owners:
            continue
        owner = (int(owners[0][1]), owners[0][0])
        if state == "LISTEN" and local_port > 0:
            listeners.setdefault(owner, set()).add((proto, local_ip, local_port))
        elif state in ("ESTAB", "ESTABLISHED") and local_port > 0 and remote_port > 0:
            established.append(
                {
                    "owner": owner,
                    "proto": "tcp" if proto.startswith("tcp") else proto,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                }
            )
    targets: Dict[Tuple[int, str], set] = {}
    external_sources: Dict[Tuple[int, str], List[Dict[str, object]]] = {}
    for socket_item in established:
        owner = socket_item["owner"]
        remote_ip = str(socket_item["remote_ip"])
        remote_port = int(socket_item["remote_port"])
        if remote_ip in address_owners:
            targets.setdefault(owner, set()).add((remote_ip, remote_port))
            continue
        if not _is_public_source_ip(remote_ip):
            continue
        local_port = int(socket_item["local_port"])
        listening = listeners.get(owner, set())
        if not any(int(item[2]) == local_port for item in listening):
            continue
        external_sources.setdefault(owner, []).append(socket_item)
    entries = conntrack.get("entries") if isinstance(conntrack.get("entries"), list) else []
    nat_mappings = conntrack.get("nat_mappings") if isinstance(conntrack.get("nat_mappings"), list) else []
    matched_connections = 0
    for owner, sources in external_sources.items():
        owner_targets = targets.get(owner, set())
        if len(owner_targets) != 1:
            continue
        target_ip, target_port = next(iter(owner_targets))
        for source in sources:
            local_ip = str(source["local_ip"])
            local_port = int(source["local_port"])
            proto = str(source["proto"])
            remote_ip = str(source["remote_ip"])
            remote_port = int(source["remote_port"])
            entries.append(
                {
                    "proto": proto,
                    "original_src": remote_ip,
                    "original_dst": local_ip,
                    "original_sport": remote_port,
                    "original_dport": local_port,
                    "reply_src": local_ip,
                    "reply_dst": remote_ip,
                    "reply_sport": local_port,
                    "reply_dport": remote_port,
                    "proxy_process": owner[1],
                    "proxy_pid": owner[0],
                }
            )
            nat_mappings.append(
                {
                    "proto": proto,
                    "host": local_ip,
                    "public_port": local_port,
                    "target_host": target_ip,
                    "container_port": target_port,
                    "source": "host-proxy-socket",
                }
            )
            matched_connections += 1
    conntrack["entries"] = entries
    conntrack["nat_mappings"] = nat_mappings
    conntrack["host_proxy_socket_available"] = bool(lines)
    conntrack["host_proxy_socket_snapshot_count"] = len(lines)
    conntrack["host_proxy_socket_snapshot_truncated"] = len(lines) >= limit
    conntrack["host_proxy_matched_connections"] = matched_connections


def _parse_exposure_endpoint(value: str) -> Tuple[str, str, int]:
    text = (value or "").strip()
    proto = ""
    if text.lower().startswith(("tcp:", "udp:")):
        proto, text = text.split(":", 1)
        proto = proto.lower()
    elif "/" in text and text.rsplit("/", 1)[1].lower() in ("tcp", "udp"):
        text, proto = text.rsplit("/", 1)
        proto = proto.lower()
    host, port = _parse_socket_endpoint(text)
    if port <= 0 and text.isdigit():
        port = int(text)
        host = ""
    return proto, host, port


def _apply_host_conntrack_security(
    security: Dict[str, object],
    conntrack: Dict[str, object],
    container_addresses: List[str],
    network_exposure: List[Dict[str, str]],
) -> None:
    """Replace proxy-collapsed source counts with original host conntrack tuples."""
    entries = conntrack.get("entries") if isinstance(conntrack.get("entries"), list) else []
    host_addresses = {
        str(address)
        for address in (conntrack.get("host_addresses") or [])
        if _is_trackable_ip(str(address))
    }
    addresses = {
        str(address)
        for address in list(container_addresses) + list(security.get("container_ips") or [])
        if _is_trackable_ip(str(address))
    }
    mappings = []
    for exposure in network_exposure:
        if not isinstance(exposure, dict):
            continue
        listen_proto, listen_host, listen_port = _parse_exposure_endpoint(str(exposure.get("listen") or ""))
        target_proto, target_host, target_port = _parse_exposure_endpoint(str(exposure.get("target") or ""))
        if target_host and _is_trackable_ip(target_host):
            addresses.add(target_host)
        if listen_port > 0 or (str(exposure.get("source") or "") == "incus-forward" and listen_host):
            mappings.append(
                {
                    "proto": listen_proto or target_proto,
                    "host": listen_host,
                    "public_port": listen_port,
                    "container_port": target_port,
                }
            )
    host_nat_mappings = conntrack.get("nat_mappings") if isinstance(conntrack.get("nat_mappings"), list) else []
    for mapping in host_nat_mappings:
        if not isinstance(mapping, dict):
            continue
        target_host = str(mapping.get("target_host") or "")
        if target_host not in addresses:
            continue
        mappings.append(
            {
                "proto": str(mapping.get("proto") or ""),
                "host": str(mapping.get("host") or ""),
                "public_port": int(mapping.get("public_port") or 0),
                "container_port": int(mapping.get("container_port") or 0),
            }
        )

    source_connections: Dict[str, int] = {}
    flow_connections: Dict[Tuple[str, str, int, int], int] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source_ip = str(entry.get("original_src") or "")
        proto = str(entry.get("proto") or "")
        original_dst = str(entry.get("original_dst") or "")
        original_dport = int(entry.get("original_dport") or 0)
        reply_src = str(entry.get("reply_src") or "")
        reply_sport = int(entry.get("reply_sport") or 0)
        matched = reply_src in addresses
        container_port = reply_sport if matched else 0
        if not matched:
            for mapping in mappings:
                mapping_proto = str(mapping.get("proto") or "")
                mapping_host = str(mapping.get("host") or "")
                if mapping_proto and mapping_proto != proto:
                    continue
                mapping_public_port = int(mapping.get("public_port") or 0)
                if mapping_public_port > 0 and mapping_public_port != original_dport:
                    continue
                if mapping_host and mapping_host not in ("0.0.0.0", "::", "*") and mapping_host != original_dst:
                    continue
                if mapping_host in ("", "0.0.0.0", "::", "*") and host_addresses and original_dst not in host_addresses:
                    continue
                matched = True
                container_port = int(mapping.get("container_port") or 0) or original_dport
                break
        if not matched or not _is_public_source_ip(source_ip) or source_ip in addresses:
            continue
        source_connections[source_ip] = source_connections.get(source_ip, 0) + 1
        flow_key = (source_ip, proto, original_dport, container_port)
        flow_connections[flow_key] = flow_connections.get(flow_key, 0) + 1

    security["host_conntrack_available"] = bool(conntrack.get("available"))
    security["host_conntrack_snapshot_count"] = int(conntrack.get("snapshot_count") or 0)
    security["host_conntrack_snapshot_truncated"] = bool(conntrack.get("snapshot_truncated"))
    security["host_proxy_socket_available"] = bool(conntrack.get("host_proxy_socket_available"))
    security["host_proxy_socket_snapshot_count"] = int(conntrack.get("host_proxy_socket_snapshot_count") or 0)
    security["host_proxy_matched_connections"] = int(conntrack.get("host_proxy_matched_connections") or 0)
    security["container_ips"] = sorted(addresses)
    if not source_connections:
        return
    security["inbound_ip_observation"] = "host_conntrack"
    security["inbound_unique_ips"] = len(source_connections)
    security["inbound_top_ips"] = [
        {"ip": ip, "connections": count}
        for ip, count in sorted(source_connections.items(), key=lambda item: item[1], reverse=True)[:20]
    ]
    security["inbound_public_flows"] = [
        {
            "remote_ip": key[0],
            "proto": key[1],
            "public_port": key[2],
            "container_port": key[3],
            "connections": count,
        }
        for key, count in sorted(flow_connections.items(), key=lambda item: item[1], reverse=True)[:100]
    ]


def _enrich_communication_with_original_sources(
    communication: Dict[str, object], public_flows: List[Dict[str, object]]
) -> None:
    flows_by_port: Dict[int, List[Dict[str, object]]] = {}
    for flow in public_flows:
        if not isinstance(flow, dict):
            continue
        port = int(flow.get("container_port") or 0)
        if port > 0:
            flows_by_port.setdefault(port, []).append(flow)
    process_sources: Dict[Tuple[int, str], set] = {}
    sockets = communication.get("communication_sockets")
    if not isinstance(sockets, list):
        sockets = []
    for item in sockets:
        if not isinstance(item, dict) or item.get("direction") != "inbound":
            continue
        _, local_port = _parse_socket_endpoint(str(item.get("local") or ""))
        matched_flows = flows_by_port.get(local_port, [])
        original_ips = sorted({str(flow.get("remote_ip") or "") for flow in matched_flows if flow.get("remote_ip")})
        if not original_ips:
            continue
        item["original_remote_ips"] = original_ips[:20]
        key = (int(item.get("pid") or 0), str(item.get("process") or "unknown"))
        process_sources.setdefault(key, set()).update(original_ips)
    processes = communication.get("communication_processes")
    if not isinstance(processes, list):
        return
    for process in processes:
        if not isinstance(process, dict):
            continue
        key = (int(process.get("pid") or 0), str(process.get("process") or "unknown"))
        sources = sorted(process_sources.get(key, set()))
        process["original_inbound_unique_ips"] = len(sources)
        process["original_inbound_top_ips"] = sources[:20]


_NGINX_ACCESS_RE = re.compile(r'^([^ ]+)\s+.*?"([A-Z]+)\s+([^ ]+)\s+[^\"]+"\s+(\d{3})\b')


def _parse_access_log_line(line: str) -> Dict[str, object] | None:
    text = (line or "").strip()
    if not text:
        return None
    try:
        item = json.loads(text)
    except Exception:
        item = None
    if isinstance(item, dict):
        request = item.get("request") if isinstance(item.get("request"), dict) else item
        remote_ip = str(
            request.get("client_ip")
            or request.get("remote_ip")
            or request.get("remote_addr")
            or item.get("remote_addr")
            or ""
        )
        status = item.get("status", request.get("status", 0))
        try:
            status_int = int(status or 0)
        except (TypeError, ValueError):
            status_int = 0
        return {
            "ip": remote_ip,
            "status": status_int,
            "method": str(request.get("method") or item.get("request_method") or ""),
            "uri": str(request.get("uri") or item.get("request_uri") or ""),
        }
    match = _NGINX_ACCESS_RE.match(text)
    if not match:
        return None
    return {"ip": match.group(1), "method": match.group(2), "uri": match.group(3), "status": int(match.group(4))}


def _collect_access_log_stats(interval_seconds: float) -> Dict[str, object]:
    raw_paths = os.getenv("SECURITY_ACCESS_LOG_PATHS", "").strip()
    paths = [x.strip() for x in raw_paths.split(",") if x.strip()]
    stats: Dict[str, object] = {
        "enabled": bool(paths),
        "configured_files": len(paths),
        "readable_files": 0,
        "missing_files": 0,
        "unreadable_files": 0,
        "requests": 0,
        "requests_per_second": 0.0,
        "unique_ips": 0,
        "top_ip": "",
        "top_ip_requests": 0,
        "top_ip_requests_per_second": 0.0,
        "status_4xx": 0,
        "status_5xx": 0,
        "top_ip_4xx": "",
        "top_ip_4xx_requests": 0,
        "suspicious_requests": 0,
        "suspicious_unique_paths": 0,
        "top_scanner_ip": "",
        "top_scanner_requests": 0,
        "parse_errors": 0,
    }
    if not paths:
        return stats
    max_bytes = max(65536, int(os.getenv("SECURITY_ACCESS_LOG_MAX_BYTES", "1048576")))
    ip_counts: Dict[str, int] = {}
    ip_4xx_counts: Dict[str, int] = {}
    scanner_ip_counts: Dict[str, int] = {}
    suspicious_paths_seen = set()
    requests_count = 0
    status_4xx = 0
    status_5xx = 0
    parse_errors = 0
    readable_files = 0
    missing_files = 0
    unreadable_files = 0
    web_scan_patterns = [
        item.strip().lower()
        for item in os.getenv(
            "SECURITY_WEB_SCAN_PATTERNS",
            ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1",
        ).split(",")
        if item.strip()
    ]

    for path in paths:
        try:
            stat = os.stat(path)
            state = _access_log_states.get(path, {})
            inode = int(getattr(stat, "st_ino", 0) or 0)
            if not state:
                _access_log_states[path] = {"inode": inode, "offset": int(stat.st_size)}
                readable_files += 1
                continue
            previous_inode = int(state.get("inode", 0) or 0)
            previous_offset = int(state.get("offset", 0) or 0)
            if previous_inode != inode or previous_offset > stat.st_size:
                previous_offset = 0
            start = max(previous_offset, int(stat.st_size) - max_bytes)
            skip_partial_line = start > previous_offset
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(start)
                if skip_partial_line:
                    f.readline()
                lines = f.readlines()
                offset = f.tell()
            _access_log_states[path] = {"inode": inode, "offset": offset}
            readable_files += 1
        except FileNotFoundError:
            missing_files += 1
            continue
        except (PermissionError, OSError):
            unreadable_files += 1
            continue
        for line in lines[-20000:]:
            event = _parse_access_log_line(line)
            if not event:
                parse_errors += 1
                continue
            requests_count += 1
            ip = str(event.get("ip") or "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            status = int(event.get("status") or 0)
            if 400 <= status < 500:
                status_4xx += 1
                if ip and status in (401, 403, 429):
                    ip_4xx_counts[ip] = ip_4xx_counts.get(ip, 0) + 1
            elif status >= 500:
                status_5xx += 1
            uri = str(event.get("uri") or "")
            uri_lower = uri.lower()
            if uri_lower and any(pattern in uri_lower for pattern in web_scan_patterns):
                suspicious_paths_seen.add(uri.split("?", 1)[0][:500])
                if ip:
                    scanner_ip_counts[ip] = scanner_ip_counts.get(ip, 0) + 1

    top_ip = ""
    top_ip_requests = 0
    for ip, count in ip_counts.items():
        if count > top_ip_requests:
            top_ip = ip
            top_ip_requests = count
    top_ip_4xx = ""
    top_ip_4xx_requests = 0
    for ip, count in ip_4xx_counts.items():
        if count > top_ip_4xx_requests:
            top_ip_4xx = ip
            top_ip_4xx_requests = count
    top_scanner_ip = ""
    top_scanner_requests = 0
    for ip, count in scanner_ip_counts.items():
        if count > top_scanner_requests:
            top_scanner_ip = ip
            top_scanner_requests = count
    interval = max(1.0, float(interval_seconds))
    stats.update(
        {
            "readable_files": readable_files,
            "missing_files": missing_files,
            "unreadable_files": unreadable_files,
            "requests": requests_count,
            "requests_per_second": requests_count / interval,
            "unique_ips": len(ip_counts),
            "top_ip": top_ip,
            "top_ip_requests": top_ip_requests,
            "top_ip_requests_per_second": top_ip_requests / interval,
            "status_4xx": status_4xx,
            "status_5xx": status_5xx,
            "top_ip_4xx": top_ip_4xx,
            "top_ip_4xx_requests": top_ip_4xx_requests,
            "suspicious_requests": sum(scanner_ip_counts.values()),
            "suspicious_unique_paths": len(suspicious_paths_seen),
            "top_scanner_ip": top_scanner_ip,
            "top_scanner_requests": top_scanner_requests,
            "parse_errors": parse_errors,
        }
    )
    return stats


def _summarize_access_lines(
    lines: List[str], interval_seconds: float, enabled: bool, readable_files: int
) -> Dict[str, object]:
    ip_counts: Dict[str, int] = {}
    ip_4xx_counts: Dict[str, int] = {}
    scanner_ip_counts: Dict[str, int] = {}
    suspicious_paths_seen = set()
    requests_count = 0
    status_4xx = 0
    status_5xx = 0
    parse_errors = 0
    web_scan_patterns = [
        item.strip().lower()
        for item in os.getenv(
            "SECURITY_WEB_SCAN_PATTERNS",
            ".env,.git,wp-login,wp-admin,phpmyadmin,actuator,server-status,cgi-bin,vendor/phpunit,etc/passwd,boaform,hnap1",
        ).split(",")
        if item.strip()
    ]
    for line in lines[-20000:]:
        event = _parse_access_log_line(line)
        if not event:
            parse_errors += 1
            continue
        requests_count += 1
        ip = str(event.get("ip") or "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        status = int(event.get("status") or 0)
        if 400 <= status < 500:
            status_4xx += 1
            if ip and status in (401, 403, 429):
                ip_4xx_counts[ip] = ip_4xx_counts.get(ip, 0) + 1
        elif status >= 500:
            status_5xx += 1
        uri = str(event.get("uri") or "")
        uri_lower = uri.lower()
        if uri_lower and any(pattern in uri_lower for pattern in web_scan_patterns):
            suspicious_paths_seen.add(uri.split("?", 1)[0][:500])
            if ip:
                scanner_ip_counts[ip] = scanner_ip_counts.get(ip, 0) + 1

    top_ip, top_ip_requests = max(ip_counts.items(), key=lambda item: item[1], default=("", 0))
    top_ip_4xx, top_ip_4xx_requests = max(ip_4xx_counts.items(), key=lambda item: item[1], default=("", 0))
    top_scanner_ip, top_scanner_requests = max(
        scanner_ip_counts.items(), key=lambda item: item[1], default=("", 0)
    )
    interval = max(1.0, float(interval_seconds))
    return {
        "enabled": enabled,
        "readable_files": readable_files,
        "requests": requests_count,
        "requests_per_second": requests_count / interval,
        "unique_ips": len(ip_counts),
        "top_ip": top_ip,
        "top_ip_requests": top_ip_requests,
        "top_ip_requests_per_second": top_ip_requests / interval,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "top_ip_4xx": top_ip_4xx,
        "top_ip_4xx_requests": top_ip_4xx_requests,
        "suspicious_requests": sum(scanner_ip_counts.values()),
        "suspicious_unique_paths": len(suspicious_paths_seen),
        "top_scanner_ip": top_scanner_ip,
        "top_scanner_requests": top_scanner_requests,
        "parse_errors": parse_errors,
    }


def _collect_container_access_log_stats(
    container: Dict[str, str], interval_seconds: float
) -> Dict[str, object]:
    raw_paths = os.getenv(
        "SECURITY_CONTAINER_ACCESS_LOG_PATHS",
        "/var/log/nginx/access.log,/var/log/caddy/access.log",
    ).strip()
    paths = [path.strip() for path in raw_paths.split(",") if re.fullmatch(r"/[A-Za-z0-9_./-]+", path.strip())]
    if not paths:
        return _summarize_access_lines([], interval_seconds, False, 0)

    runtime = container.get("runtime_bin", "") or get_container_bin()
    name = container.get("name", "")
    project = container.get("project", "")
    runtime_name = container.get("runtime", "") or _runtime_kind(runtime)
    if not runtime or not name:
        return _summarize_access_lines([], interval_seconds, True, 0)
    max_bytes = max(65536, int(os.getenv("SECURITY_ACCESS_LOG_MAX_BYTES", "1048576")))
    readable_files = 0
    collected_lines: List[str] = []
    for path in paths:
        quoted_path = shlex.quote(path)
        size_out = run(
            _runtime_exec_cmd(
                runtime,
                name,
                f"if [ -r {quoted_path} ]; then wc -c < {quoted_path}; fi",
                project,
            )
        ).strip()
        if not size_out.isdigit():
            continue
        size = int(size_out)
        readable_files += 1
        key = f"container-log:{runtime_name}:{project}:{name}:{path}"
        state = _access_log_states.get(key)
        if not state:
            _access_log_states[key] = {"inode": 0, "offset": size}
            continue
        previous_offset = int(state.get("offset", 0) or 0)
        if previous_offset > size:
            previous_offset = 0
        start = max(previous_offset, size - max_bytes)
        output = run(
            _runtime_exec_cmd(
                runtime,
                name,
                f"tail -c +{start + 1} {quoted_path} 2>/dev/null | tail -c {max_bytes}",
                project,
            )
        )
        _access_log_states[key] = {"inode": 0, "offset": size}
        if start > previous_offset and "\n" in output:
            output = output.split("\n", 1)[1]
        collected_lines.extend(output.splitlines())
    return _summarize_access_lines(collected_lines, interval_seconds, True, readable_files)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _security_alert(
    alert_type: str,
    severity: str,
    title: str,
    message: str,
    value: float,
    threshold: float,
    container: Dict[str, object] | None = None,
) -> Dict[str, object]:
    container = container or {}
    return {
        "type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "value": value,
        "threshold": threshold,
        "runtime": str(container.get("runtime") or ""),
        "project": str(container.get("project") or ""),
        "container_name": str(container.get("name") or ""),
    }


def _http_security_alerts(
    access: Dict[str, object], container: Dict[str, object] | None = None
) -> List[Dict[str, object]]:
    alerts: List[Dict[str, object]] = []
    http_rps = _env_float("ALERT_CC_TOTAL_RPS", 100)
    http_ip_rps = _env_float("ALERT_CC_IP_RPS", 30)
    http_4xx_rate = _env_float("ALERT_CC_4XX_RATE", 0.5)
    http_min_requests = _env_float("ALERT_CC_MIN_REQUESTS", 50)
    web_scan_requests = _env_float("ALERT_WEB_SCAN_REQUESTS", 10)
    auth_failures_per_ip = _env_float("ALERT_AUTH_FAILURES_PER_IP", 20)
    scope = "容器访问日志" if container else "主机访问日志"
    requests_count = int(access.get("requests") or 0)
    total_rps = float(access.get("requests_per_second") or 0)
    top_ip_rps = float(access.get("top_ip_requests_per_second") or 0)
    if total_rps >= http_rps:
        alerts.append(
            _security_alert(
                "cc_total_rps",
                "critical" if total_rps >= http_rps * 2 else "warning",
                "疑似 HTTP/CC 攻击",
                f"{scope}请求速率 {total_rps:.1f} req/s 超过阈值 {http_rps:.1f} req/s",
                total_rps,
                http_rps,
                container,
            )
        )
    if top_ip_rps >= http_ip_rps:
        top_ip = str(access.get("top_ip") or "unknown")
        alerts.append(
            _security_alert(
                "cc_single_ip",
                "warning",
                "单 IP 请求洪泛",
                f"来源 {top_ip} 请求速率 {top_ip_rps:.1f} req/s 超过阈值 {http_ip_rps:.1f} req/s",
                top_ip_rps,
                http_ip_rps,
                container,
            )
        )
    if requests_count >= http_min_requests:
        bad_rate = float(int(access.get("status_4xx") or 0)) / max(1, requests_count)
        if bad_rate >= http_4xx_rate:
            alerts.append(
                _security_alert(
                    "cc_4xx_ratio",
                    "warning",
                    "HTTP 异常请求比例过高",
                    f"4xx 比例 {bad_rate:.1%} 超过阈值 {http_4xx_rate:.1%}",
                    bad_rate,
                    http_4xx_rate,
                    container,
                )
            )
    suspicious_requests = int(access.get("suspicious_requests") or 0)
    if suspicious_requests >= web_scan_requests:
        scanner_ip = str(access.get("top_scanner_ip") or "unknown")
        suspicious_unique_paths = int(access.get("suspicious_unique_paths") or 0)
        alerts.append(
            _security_alert(
                "web_scan",
                "warning",
                "疑似 Web 路径扫描",
                f"来源 {scanner_ip} 命中 {suspicious_requests} 次敏感路径规则，涉及 {suspicious_unique_paths} 个路径",
                suspicious_requests,
                web_scan_requests,
                container,
            )
        )
    top_ip_4xx_requests = int(access.get("top_ip_4xx_requests") or 0)
    if top_ip_4xx_requests >= auth_failures_per_ip:
        top_ip_4xx = str(access.get("top_ip_4xx") or "unknown")
        alerts.append(
            _security_alert(
                "http_abuse",
                "warning",
                "疑似登录或接口滥用",
                f"来源 {top_ip_4xx} 在采样周期产生 {top_ip_4xx_requests} 次 4xx 响应",
                top_ip_4xx_requests,
                auth_failures_per_ip,
                container,
            )
        )
    return alerts


def collect_security_summary(containers: List[Dict[str, object]], interval_seconds: float) -> Dict[str, object]:
    enabled = os.getenv("SECURITY_MONITOR_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
    access = _collect_access_log_stats(interval_seconds) if enabled else {"enabled": False, "readable_files": 0}
    summary: Dict[str, object] = {
        "enabled": enabled,
        "interval_seconds": round(max(1.0, interval_seconds), 3),
        "total_rx_bps": 0.0,
        "total_tx_bps": 0.0,
        "total_rx_pps": 0.0,
        "total_tx_pps": 0.0,
        "syn_recv_count": 0,
        "access_log": access,
        "alerts": [],
    }
    if not enabled:
        return summary

    ddos_rx_bps = _env_float("ALERT_DDOS_RX_BPS", 100_000_000)
    ddos_rx_pps = _env_float("ALERT_DDOS_RX_PPS", 50_000)
    ddos_syn = _env_float("ALERT_DDOS_SYN_RECV", 200)
    conn_warning = _env_float("ALERT_CONN_WARNING_THRESHOLD", 500)
    conn_critical = _env_float("ALERT_CONN_CRITICAL_THRESHOLD", 1000)
    inbound_unique_ip_threshold = _env_float("ALERT_INBOUND_UNIQUE_IPS", 10)
    scan_ports = _env_float("ALERT_SCAN_UNIQUE_PORTS", 20)
    abuse_unique_ips = _env_float("ALERT_ABUSE_OUTBOUND_UNIQUE_IPS", 200)
    abuse_suspicious = _env_float("ALERT_ABUSE_SUSPICIOUS_CONNECTIONS", 20)
    abuse_tx_bps = _env_float("ALERT_ABUSE_TX_BPS", 100_000_000)
    abuse_tx_pps = _env_float("ALERT_ABUSE_TX_PPS", 50_000)
    abuse_tcp_opens = _env_float("ALERT_ABUSE_TCP_OPENS_PER_SEC", 200)
    abuse_tcp_fails = _env_float("ALERT_ABUSE_TCP_FAILS_PER_SEC", 50)
    abuse_udp_out = _env_float("ALERT_ABUSE_UDP_OUT_PER_SEC", 10_000)
    abuse_processes = _env_float("ALERT_ABUSE_PROCESS_COUNT", 500)
    config_audit_enabled = os.getenv("SECURITY_CONFIG_AUDIT_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    panel_detection_enabled = os.getenv("SECURITY_PANEL_PAIRING_DETECTION_ENABLED", "true").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )
    auto_remediate_xmrig = os.getenv(
        "SECURITY_AUTO_REMEDIATE_XMRIG", "true"
    ).strip().lower() not in ("0", "false", "no", "off")
    auto_remediate_xrayr = os.getenv(
        "SECURITY_AUTO_REMEDIATE_XRAYR", "true"
    ).strip().lower() not in ("0", "false", "no", "off")
    alerts: List[Dict[str, object]] = []
    container_access_readable_files = 0
    socks_enforcement_entries = _socks_auth_enforcement_entries()

    for container in containers:
        if container.get("runtime") == "docker" and container.get("monitor_mode") == "notice":
            alerts.append(
                _security_alert(
                    "docker_container_notice",
                    "info",
                    "发现 Docker 容器（仅提醒）",
                    f"Docker 容器 {container.get('name') or 'unknown'} 已发现；默认不执行深度采集或安全扫描",
                    1,
                    1,
                    container,
                )
            )
            continue
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        enforce_socks_auth_policy(container, socks_enforcement_entries)
        rx_bps = float(container.get("net_rx_bps") or 0)
        tx_bps = float(container.get("net_tx_bps") or 0)
        rx_pps = float(security.get("net_rx_pps") or 0)
        tx_pps = float(security.get("net_tx_pps") or 0)
        syn_recv = int(security.get("syn_recv_count") or 0)
        summary["total_rx_bps"] = float(summary["total_rx_bps"]) + rx_bps
        summary["total_tx_bps"] = float(summary["total_tx_bps"]) + tx_bps
        summary["total_rx_pps"] = float(summary["total_rx_pps"]) + rx_pps
        summary["total_tx_pps"] = float(summary["total_tx_pps"]) + tx_pps
        summary["syn_recv_count"] = int(summary["syn_recv_count"]) + syn_recv

        conn_count = int(container.get("conn_count") or 0)
        if conn_count > conn_warning:
            critical = conn_count > conn_critical
            alerts.append(
                _security_alert(
                    "container_connection_count",
                    "critical" if critical else "warning",
                    "容器连接数严重过高" if critical else "容器连接数过高",
                    f"容器当前连接数 {conn_count} 超过"
                    f"{'严重告警' if critical else '告警'}阈值 "
                    f"{int(conn_critical if critical else conn_warning)}",
                    conn_count,
                    conn_critical if critical else conn_warning,
                    container,
                )
            )

        if rx_bps >= ddos_rx_bps:
            alerts.append(
                _security_alert(
                    "ddos_bandwidth",
                    "critical" if rx_bps >= ddos_rx_bps * 2 else "warning",
                    "疑似流量型 DDoS",
                    f"容器入站速率 {rx_bps:.0f} B/s 超过阈值 {ddos_rx_bps:.0f} B/s",
                    rx_bps,
                    ddos_rx_bps,
                    container,
                )
            )
        if rx_pps >= ddos_rx_pps:
            alerts.append(
                _security_alert(
                    "ddos_packets",
                    "critical" if rx_pps >= ddos_rx_pps * 2 else "warning",
                    "疑似高包速率 DDoS",
                    f"容器入站包速率 {rx_pps:.0f} pps 超过阈值 {ddos_rx_pps:.0f} pps",
                    rx_pps,
                    ddos_rx_pps,
                    container,
                )
            )
        if syn_recv >= ddos_syn:
            alerts.append(
                _security_alert(
                    "ddos_syn",
                    "critical" if syn_recv >= ddos_syn * 2 else "warning",
                    "疑似 SYN Flood",
                    f"SYN_RECV 连接数 {syn_recv} 超过阈值 {int(ddos_syn)}",
                    syn_recv,
                    ddos_syn,
                    container,
                )
            )
        socks_proxy = security.get("socks_proxy") if isinstance(security.get("socks_proxy"), dict) else {}
        socks_detected = bool(socks_proxy.get("detected"))
        socks_auth_mode = str(socks_proxy.get("auth_mode") or "unknown")
        if socks_detected and socks_auth_mode in ("no_auth", "weak_password"):
            public_exposure = bool(socks_proxy.get("public_exposure"))
            reason = "允许无认证访问" if socks_auth_mode == "no_auth" else "命中短密码或常见弱密码"
            process_matches = [
                item
                for item in socks_proxy.get("process_matches", [])
                if isinstance(item, dict)
            ]
            process_names = sorted(
                {
                    str(item.get("process") or "")
                    for item in process_matches
                    if item.get("process")
                }
            )
            action_process_matches = [
                item
                for item in process_matches
                if socks_auth_mode == "no_auth"
                and str(item.get("auth_state") or "no_auth") == "no_auth"
            ]
            socks_alert = _security_alert(
                "socks_weak_auth",
                "critical" if public_exposure else "warning",
                "SOCKS 代理认证风险",
                f"检测到 SOCKS 服务{reason}；"
                f"公网/NAT 暴露 {'是' if public_exposure else '未确认'}；"
                f"进程 {','.join(process_names) if process_names else 'unknown'}；"
                "不会上报用户名或密码内容",
                1,
                0,
                container,
            )
            socks_alert.update(
                {
                    "socks_auth_mode": socks_auth_mode,
                    "socks_processes": sorted(
                        {
                            str(item.get("process") or "")
                            for item in action_process_matches
                            if item.get("process")
                        }
                    )[:20],
                    "socks_process_pids": [
                        int(item.get("pid") or 0)
                        for item in action_process_matches[:20]
                        if int(item.get("pid") or 0) > 1
                    ],
                    "socks_config_files": [
                        str(item)
                        for item in socks_proxy.get("config_files", [])[:20]
                        if isinstance(item, str)
                    ],
                    "socks_auth_enforcement": socks_proxy.get("auth_enforcement")
                    if isinstance(socks_proxy.get("auth_enforcement"), dict)
                    else {},
                }
            )
            alerts.append(socks_alert)
        inbound_unique_ips = int(security.get("inbound_unique_ips") or 0)
        if inbound_unique_ips > inbound_unique_ip_threshold:
            communication_processes = (
                security.get("communication_processes")
                if isinstance(security.get("communication_processes"), list)
                else []
            )
            top_process = max(
                (item for item in communication_processes if isinstance(item, dict)),
                key=lambda item: int(item.get("inbound_connections") or 0),
                default={},
            )
            process_hint = ""
            if isinstance(top_process, dict) and top_process.get("process"):
                process_hint = (
                    f"；主要通信进程 {top_process.get('process')}"
                    f"(PID {int(top_process.get('pid') or 0)})"
                )
            alert_type = "socks_inbound_fanout" if socks_detected else "inbound_ip_fanout"
            alert_title = "SOCKS 入站来源 IP 数量过多" if socks_detected else "入站来源 IP 数量过多"
            socks_hint = "；已识别 SOCKS 服务，此告警替代通用入站 IP 告警" if socks_detected else ""
            alerts.append(
                _security_alert(
                    alert_type,
                    "critical"
                    if inbound_unique_ips > inbound_unique_ip_threshold * 2
                    else "warning",
                    alert_title,
                    f"容器当前有 {inbound_unique_ips} 个不同入站 IP，"
                    f"超过重点提醒阈值 {int(inbound_unique_ip_threshold)}{process_hint}{socks_hint}",
                    inbound_unique_ips,
                    inbound_unique_ip_threshold,
                    container,
                )
            )
        scan_count = int(security.get("scan_unique_ports_max") or 0)
        if scan_count >= scan_ports:
            source_ip = str(security.get("scan_source_ip") or "unknown")
            alerts.append(
                _security_alert(
                    "port_scan",
                    "warning",
                    "疑似端口扫描",
                    f"来源 {source_ip} 同时探测 {scan_count} 个本地端口",
                    scan_count,
                    scan_ports,
                    container,
                )
            )
        unique_ips = int(security.get("outbound_unique_ips") or 0)
        suspicious_connections = int(security.get("suspicious_outbound_connections") or 0)
        if unique_ips >= abuse_unique_ips:
            alerts.append(
                _security_alert(
                    "outbound_fanout",
                    "warning",
                    "疑似出站滥用",
                    f"容器同时连接 {unique_ips} 个外部 IP，可能存在代理滥用或扫描",
                    unique_ips,
                    abuse_unique_ips,
                    container,
                )
            )
        if suspicious_connections >= abuse_suspicious:
            alerts.append(
                _security_alert(
                    "outbound_sensitive_ports",
                    "critical",
                    "敏感端口出站连接异常",
                    f"敏感出站端口连接数 {suspicious_connections} 超过阈值 {int(abuse_suspicious)}",
                    suspicious_connections,
                    abuse_suspicious,
                    container,
                )
            )
        if tx_bps >= abuse_tx_bps:
            alerts.append(
                _security_alert(
                    "outbound_bandwidth_abuse",
                    "critical" if tx_bps >= abuse_tx_bps * 2 else "warning",
                    "异常大流量出站",
                    f"容器出站速率 {tx_bps:.0f} B/s 超过阈值 {abuse_tx_bps:.0f} B/s",
                    tx_bps,
                    abuse_tx_bps,
                    container,
                )
            )
        if tx_pps >= abuse_tx_pps:
            alerts.append(
                _security_alert(
                    "outbound_packet_abuse",
                    "critical" if tx_pps >= abuse_tx_pps * 2 else "warning",
                    "异常高包速率出站",
                    f"容器出站包速率 {tx_pps:.0f} pps 超过阈值 {abuse_tx_pps:.0f} pps",
                    tx_pps,
                    abuse_tx_pps,
                    container,
                )
            )
        protocol_rates = security.get("protocol_rates") if isinstance(security.get("protocol_rates"), dict) else {}
        tcp_open_rate = float(protocol_rates.get("Tcp_ActiveOpens_per_second") or 0)
        tcp_fail_rate = float(protocol_rates.get("Tcp_AttemptFails_per_second") or 0)
        udp_out_rate = float(protocol_rates.get("Udp_OutDatagrams_per_second") or 0)
        if tcp_open_rate >= abuse_tcp_opens:
            alerts.append(
                _security_alert(
                    "outbound_connection_churn",
                    "warning",
                    "异常 TCP 建连速率",
                    f"容器主动 TCP 建连速率 {tcp_open_rate:.1f}/s 超过阈值 {abuse_tcp_opens:.1f}/s",
                    tcp_open_rate,
                    abuse_tcp_opens,
                    container,
                )
            )
        if tcp_fail_rate >= abuse_tcp_fails:
            alerts.append(
                _security_alert(
                    "outbound_connection_failures",
                    "critical" if tcp_fail_rate >= abuse_tcp_fails * 2 else "warning",
                    "异常 TCP 连接失败速率",
                    f"容器 TCP 连接失败速率 {tcp_fail_rate:.1f}/s 超过阈值 {abuse_tcp_fails:.1f}/s，可能存在扫描或僵尸网络活动",
                    tcp_fail_rate,
                    abuse_tcp_fails,
                    container,
                )
            )
        if udp_out_rate >= abuse_udp_out:
            alerts.append(
                _security_alert(
                    "udp_outbound_flood",
                    "critical" if udp_out_rate >= abuse_udp_out * 2 else "warning",
                    "异常 UDP 出站速率",
                    f"容器 UDP 出站数据报速率 {udp_out_rate:.1f}/s 超过阈值 {abuse_udp_out:.1f}/s",
                    udp_out_rate,
                    abuse_udp_out,
                    container,
                )
            )
        process_count = int(security.get("process_count") or 0)
        if process_count >= abuse_processes:
            alerts.append(
                _security_alert(
                    "process_fanout_abuse",
                    "critical" if process_count >= abuse_processes * 2 else "warning",
                    "容器进程数量异常",
                    f"容器进程数量 {process_count} 超过阈值 {int(abuse_processes)}，可能存在 fork bomb 或任务滥用",
                    process_count,
                    abuse_processes,
                    container,
                )
            )
        suspicious_processes = security.get("suspicious_processes")
        if isinstance(suspicious_processes, list) and suspicious_processes:
            first_process = suspicious_processes[0] if isinstance(suspicious_processes[0], dict) else {}
            confirmed_xmrig = [
                item
                for item in suspicious_processes
                if isinstance(item, dict)
                and str(item.get("process") or "").strip().lower() == "xmrig"
            ]
            automatic_result: Dict[str, object] = {}
            if (
                auto_remediate_xmrig
                and confirmed_xmrig
                and str(container.get("runtime") or "").lower() in ("podman", "incus")
            ):
                auto_ok, auto_message = remediate_malicious_process(
                    {
                        "runtime": container.get("runtime"),
                        "project": container.get("project"),
                        "container_name": container.get("name"),
                        "params": {
                            "process_names": ["xmrig"],
                            "process_pids": [
                                int(item.get("pid") or 0)
                                for item in confirmed_xmrig
                                if int(item.get("pid") or 0) > 1
                            ],
                        },
                    }
                )
                automatic_result = {
                    "attempted": True,
                    "succeeded": auto_ok,
                    "message": auto_message[:500],
                }
                print(
                    f"automatic XMRig remediation {'succeeded' if auto_ok else 'failed'} for "
                    f"{container.get('runtime')}/{container.get('name')}: {auto_message}"
                )
            malicious_alert = _security_alert(
                "malicious_process",
                "critical",
                "确认挖矿程序" if confirmed_xmrig else "疑似恶意程序",
                f"命中 {len(suspicious_processes)} 个可疑进程特征；首个特征 {first_process.get('pattern') or 'unknown'}，PID {first_process.get('pid') or 0}",
                len(suspicious_processes),
                1,
                container,
            )
            malicious_alert.update(
                {
                    "malicious_processes": [
                        {
                            "pid": int(item.get("pid") or 0),
                            "process": str(item.get("process") or "")[:80],
                            "pattern": str(item.get("pattern") or "")[:120],
                        }
                        for item in suspicious_processes[:20]
                        if isinstance(item, dict)
                    ],
                    "automatic_remediation": automatic_result,
                }
            )
            alerts.append(malicious_alert)
        configuration_risks = security.get("configuration_risks")
        if config_audit_enabled and isinstance(configuration_risks, list) and configuration_risks:
            risk_items = [item for item in configuration_risks if isinstance(item, dict)]
            severity = "critical" if any(item.get("severity") == "critical" for item in risk_items) else "warning"
            alerts.append(
                _security_alert(
                    "container_security_risk",
                    severity,
                    "容器隔离配置风险",
                    "；".join(str(item.get("message") or item.get("code") or "unknown") for item in risk_items[:5]),
                    len(risk_items),
                    1,
                    container,
                )
            )
        panel_pairing = security.get("panel_pairing") if isinstance(security.get("panel_pairing"), dict) else {}
        panel_domains = panel_pairing.get("panel_domains") if isinstance(panel_pairing.get("panel_domains"), list) else []
        unapproved_domains = (
            panel_pairing.get("unapproved_domains") if isinstance(panel_pairing.get("unapproved_domains"), list) else []
        )
        process_patterns = (
            panel_pairing.get("process_patterns") if isinstance(panel_pairing.get("process_patterns"), list) else []
        )
        process_matches = (
            panel_pairing.get("process_matches") if isinstance(panel_pairing.get("process_matches"), list) else []
        )
        identity_patterns = (
            panel_pairing.get("identity_patterns") if isinstance(panel_pairing.get("identity_patterns"), list) else []
        )
        config_files = panel_pairing.get("config_files") if isinstance(panel_pairing.get("config_files"), list) else []
        auto_domains = set(_configured_auto_remediate_panel_domains())
        normalized_unapproved = [str(item).strip().lower().rstrip(".") for item in unapproved_domains]
        auto_matched_domains = sorted(set(normalized_unapproved) & auto_domains)
        remaining_unapproved_domains = [
            item for item in normalized_unapproved if item not in auto_domains
        ]
        xrayr_auto_result: Dict[str, object] = {}
        xrayr_confirmed = "xrayr" in {
            str(item).strip().lower() for item in process_patterns
        }
        if (
            panel_detection_enabled
            and auto_remediate_xrayr
            and xrayr_confirmed
            and not bool(panel_pairing.get("approved"))
            and str(container.get("runtime") or "").lower() in ("podman", "incus")
        ):
            xrayr_ok, xrayr_message = remediate_panel_pairing(
                {
                    "runtime": container.get("runtime"),
                    "project": container.get("project"),
                    "container_name": container.get("name"),
                    "params": {
                        "process_patterns": ["xrayr"],
                        "process_pids": [
                            int(item.get("pid") or 0)
                            for item in process_matches[:20]
                            if isinstance(item, dict)
                            and str(item.get("pattern") or "").lower() == "xrayr"
                            and int(item.get("pid") or 0) > 1
                        ],
                        "config_files": config_files,
                    },
                }
            )
            xrayr_auto_result = {
                "attempted": True,
                "succeeded": xrayr_ok,
                "message": xrayr_message[:500],
            }
            print(
                f"automatic XrayR remediation {'succeeded' if xrayr_ok else 'failed'} for "
                f"{container.get('runtime')}/{container.get('name')}: {xrayr_message}"
            )
        suppress_panel_alert = bool(
            panel_detection_enabled
            and auto_matched_domains
            and not remaining_unapproved_domains
            and not xrayr_auto_result
        )
        if panel_detection_enabled and auto_matched_domains and not xrayr_auto_result:
            auto_ok, auto_message = remediate_panel_pairing(
                {
                    "runtime": container.get("runtime"),
                    "project": container.get("project"),
                    "container_name": container.get("name"),
                    "params": {
                        "process_patterns": process_patterns,
                        "process_pids": [
                            int(item.get("pid") or 0)
                            for item in process_matches[:20]
                            if isinstance(item, dict) and int(item.get("pid") or 0) > 1
                        ],
                        "config_files": config_files,
                    },
                }
            )
            print(
                f"automatic panel remediation {'succeeded' if auto_ok else 'failed'} for "
                f"{container.get('runtime')}/{container.get('name')}: {auto_message}"
            )
            unapproved_domains = remaining_unapproved_domains
        allowlist_configured = bool(_configured_allowed_panel_domains())
        pairing_is_allowed = allowlist_configured and bool(panel_domains) and not unapproved_domains
        if (
            panel_detection_enabled
            and panel_pairing.get("detected")
            and not pairing_is_allowed
            and not suppress_panel_alert
        ):
            evidence = []
            if unapproved_domains:
                evidence.append(f"未授权面板域名 {','.join(str(item) for item in unapproved_domains[:5])}")
            if process_patterns:
                evidence.append(f"节点程序特征 {','.join(str(item) for item in process_patterns[:5])}")
            if identity_patterns:
                evidence.append(f"容器名称/镜像特征 {','.join(str(item) for item in identity_patterns[:5])}")
            if config_files:
                evidence.append(f"配置文件 {','.join(str(item) for item in config_files[:3])}")
            listening_ports = security.get("listening_ports") if isinstance(security.get("listening_ports"), list) else []
            if listening_ports:
                evidence.append(f"容器内部监听端口 {','.join(str(item) for item in listening_ports[:10])}")
            if not evidence:
                evidence.append("发现 ApiHost/ApiKey/NodeID 等面板对接配置特征")
            panel_alert = _security_alert(
                "unauthorized_panel_pairing",
                "critical" if unapproved_domains else "warning",
                "疑似对接第三方机场面板",
                "；".join(evidence),
                len(unapproved_domains) or len(process_patterns) or len(config_files) or 1,
                1,
                container,
            )
            panel_alert.update(
                {
                    "unapproved_domains": [str(item) for item in unapproved_domains[:20]],
                    "process_patterns": [str(item) for item in process_patterns[:20]],
                    "process_pids": [
                        int(item.get("pid") or 0)
                        for item in process_matches[:20]
                        if isinstance(item, dict) and int(item.get("pid") or 0) > 1
                    ],
                    "identity_patterns": [str(item) for item in identity_patterns[:20]],
                    "config_files": [str(item) for item in config_files[:20]],
                    "automatic_remediation": xrayr_auto_result,
                }
            )
            alerts.append(panel_alert)
        container_access = security.get("access_log")
        if isinstance(container_access, dict):
            container_access_readable_files += int(container_access.get("readable_files") or 0)
            alerts.extend(_http_security_alerts(container_access, container))

    total_rx_bps = float(summary["total_rx_bps"])
    total_rx_pps = float(summary["total_rx_pps"])
    total_syn_recv = int(summary["syn_recv_count"])
    alert_types = {str(item.get("type") or "") for item in alerts}
    if total_rx_bps >= ddos_rx_bps and "ddos_bandwidth" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_bandwidth",
                "critical" if total_rx_bps >= ddos_rx_bps * 2 else "warning",
                "主机疑似流量型 DDoS",
                f"主机容器合计入站速率 {total_rx_bps:.0f} B/s 超过阈值 {ddos_rx_bps:.0f} B/s",
                total_rx_bps,
                ddos_rx_bps,
            )
        )
    if total_rx_pps >= ddos_rx_pps and "ddos_packets" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_packets",
                "critical" if total_rx_pps >= ddos_rx_pps * 2 else "warning",
                "主机疑似高包速率 DDoS",
                f"主机容器合计入站包速率 {total_rx_pps:.0f} pps 超过阈值 {ddos_rx_pps:.0f} pps",
                total_rx_pps,
                ddos_rx_pps,
            )
        )
    if total_syn_recv >= ddos_syn and "ddos_syn" not in alert_types:
        alerts.append(
            _security_alert(
                "ddos_host_syn",
                "critical" if total_syn_recv >= ddos_syn * 2 else "warning",
                "主机疑似 SYN Flood",
                f"主机容器合计 SYN_RECV {total_syn_recv} 超过阈值 {int(ddos_syn)}",
                total_syn_recv,
                ddos_syn,
            )
        )

    access["container_readable_files"] = container_access_readable_files
    if int(access.get("readable_files") or 0) > 0:
        access["source"] = "host"
    elif container_access_readable_files > 0:
        access["source"] = "container"
    elif int(access.get("unreadable_files") or 0) > 0:
        access["source"] = "permission_denied"
    elif int(access.get("missing_files") or 0) > 0:
        access["source"] = "not_found"
    else:
        access["source"] = "disabled"

    alerts.extend(_http_security_alerts(access))

    summary["alerts"] = alerts
    return summary


def collect_top_cpu_process(name: str, runtime: str = "", project: str = "") -> Dict[str, object]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return {"pid": 0, "cpu_percent": 0.0, "command": ""}

    kind = _runtime_kind(runtime)
    top_cmd = [runtime, "top", name, "pcpu,pid,comm,args"]
    if kind == "docker":
        top_cmd = [runtime, "top", name, "-eo", "pcpu,pid,comm,args"]
    elif kind == "incus":
        top_cmd = _runtime_base(runtime, project) + ["exec", name, "--", "ps", "-eo", "pcpu,pid,comm,args"]
    out = run(top_cmd)
    best = {"pid": 0, "cpu_percent": 0.0, "command": ""}
    for line in out.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("pcpu"):
            continue
        parts = text.split(None, 3)
        if len(parts) < 3:
            continue
        cpu = _normalize_stat_number(parts[0])
        pid = int(parts[1]) if parts[1].isdigit() else 0
        cmd = parts[3] if len(parts) >= 4 else parts[2]
        if cpu >= float(best["cpu_percent"]):
            best = {"pid": pid, "cpu_percent": cpu, "command": cmd}
    return best


def collect_suspicious_processes(name: str, runtime: str = "", project: str = "") -> List[Dict[str, object]]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return []
    patterns = [
        pattern.strip().lower()
        for pattern in os.getenv(
            "SECURITY_SUSPICIOUS_PROCESS_PATTERNS",
            "xmrig,kinsing,kdevtmpfsi,watchbog,cryptonight,minerd,pwnrig,teamtnt,stratum+tcp,stratum+ssl,/dev/tcp/,nc -e,ncat -e,socat exec:,mkfifo /tmp",
        ).split(",")
        if pattern.strip()
    ]
    if not patterns:
        return []
    output = run(_runtime_exec_cmd(runtime, name, "ps -eo pid,pcpu,comm,args 2>/dev/null", project))
    matches: List[Dict[str, object]] = []
    for line in output.splitlines():
        text = line.strip()
        if not text or text.lower().startswith("pid"):
            continue
        lowered = text.lower()
        matched_pattern = next((pattern for pattern in patterns if pattern in lowered), "")
        if not matched_pattern:
            continue
        parts = text.split(None, 3)
        try:
            pid = int(parts[0])
        except (IndexError, ValueError):
            pid = 0
        try:
            cpu_percent = float(parts[1])
        except (IndexError, ValueError):
            cpu_percent = 0.0
        matches.append(
            {
                "pid": pid,
                "cpu_percent": cpu_percent,
                "process": posixpath.basename(parts[2]).lower() if len(parts) > 2 else "",
                "pattern": matched_pattern,
                "command": (parts[3] if len(parts) > 3 else text)[:500],
            }
        )
        if len(matches) >= 20:
            break
    return matches


def _panel_domain_allowed(domain: str, allowed_domains: List[str]) -> bool:
    candidate = domain.strip().lower().rstrip(".")
    for raw in allowed_domains:
        allowed = raw.strip().lower().lstrip("*.").rstrip(".")
        if allowed and (candidate == allowed or candidate.endswith(f".{allowed}")):
            return True
    return False


def _valid_panel_domain(value: str) -> bool:
    candidate = value.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        pass
    if len(candidate) > 253 or not candidate:
        return False
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is not None
        for label in candidate.split(".")
    )


def _configured_allowed_panel_domains() -> List[str]:
    values = {
        item.strip().lower().lstrip("*.").rstrip(".")
        for item in os.getenv("SECURITY_ALLOWED_PANEL_DOMAINS", "").split(",")
        if item.strip()
    }
    policy_path = os.getenv(
        "SECURITY_PANEL_ALLOWLIST_FILE", "/opt/narwhal-monitor/panel-allowlist.json"
    ).strip()
    if policy_path:
        try:
            with open(policy_path, "r", encoding="utf-8") as policy_file:
                stored = json.load(policy_file)
            stored_domains = stored.get("domains", []) if isinstance(stored, dict) else stored
            if isinstance(stored_domains, list):
                values.update(
                    str(item).strip().lower().lstrip("*.").rstrip(".")
                    for item in stored_domains
                    if isinstance(item, str) and item.strip()
                )
        except (OSError, TypeError, ValueError):
            pass
    denied_domains = set(_configured_auto_remediate_panel_domains())
    return sorted(
        item for item in values if _valid_panel_domain(item) and item not in denied_domains
    )


def add_allowed_panel_domains(domains: List[str]) -> List[str]:
    normalized = {
        str(item).strip().lower().rstrip(".")
        for item in domains
        if isinstance(item, str) and _valid_panel_domain(item)
    }
    if not normalized:
        raise ValueError("no valid panel domains supplied")
    merged = sorted(set(_configured_allowed_panel_domains()) | normalized)
    policy_path = os.getenv(
        "SECURITY_PANEL_ALLOWLIST_FILE", "/opt/narwhal-monitor/panel-allowlist.json"
    ).strip()
    if not policy_path or not (posixpath.isabs(policy_path) or os.path.isabs(policy_path)):
        raise ValueError("SECURITY_PANEL_ALLOWLIST_FILE must be an absolute path")
    parent = os.path.dirname(policy_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".panel-allowlist-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as policy_file:
            json.dump({"domains": merged, "updated_at": int(time.time())}, policy_file, ensure_ascii=False)
            policy_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, policy_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return merged


def _configured_auto_remediate_panel_domains() -> List[str]:
    policy_path = os.getenv(
        "SECURITY_PANEL_AUTO_REMEDIATE_FILE",
        "/opt/narwhal-monitor/panel-auto-remediate.json",
    ).strip()
    if not policy_path:
        return []
    try:
        with open(policy_path, "r", encoding="utf-8") as policy_file:
            stored = json.load(policy_file)
        stored_domains = stored.get("domains", []) if isinstance(stored, dict) else stored
    except (OSError, TypeError, ValueError):
        return []
    if not isinstance(stored_domains, list):
        return []
    return sorted(
        {
            str(item).strip().lower().rstrip(".")
            for item in stored_domains
            if isinstance(item, str) and _valid_panel_domain(item)
        }
    )


def add_auto_remediate_panel_domains(domains: List[str]) -> List[str]:
    normalized = {
        str(item).strip().lower().rstrip(".")
        for item in domains
        if isinstance(item, str) and _valid_panel_domain(item)
    }
    if not normalized:
        return _configured_auto_remediate_panel_domains()
    merged = sorted(set(_configured_auto_remediate_panel_domains()) | normalized)
    policy_path = os.getenv(
        "SECURITY_PANEL_AUTO_REMEDIATE_FILE",
        "/opt/narwhal-monitor/panel-auto-remediate.json",
    ).strip()
    if not policy_path or not (posixpath.isabs(policy_path) or os.path.isabs(policy_path)):
        raise ValueError("SECURITY_PANEL_AUTO_REMEDIATE_FILE must be an absolute path")
    parent = os.path.dirname(policy_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".panel-auto-remediate-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as policy_file:
            json.dump({"domains": merged, "updated_at": int(time.time())}, policy_file, ensure_ascii=False)
            policy_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, policy_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return merged


def remove_auto_remediate_panel_domains(domains: List[str]) -> List[str]:
    normalized = {
        str(item).strip().lower().rstrip(".")
        for item in domains
        if isinstance(item, str) and _valid_panel_domain(item)
    }
    remaining = sorted(set(_configured_auto_remediate_panel_domains()) - normalized)
    policy_path = os.getenv(
        "SECURITY_PANEL_AUTO_REMEDIATE_FILE",
        "/opt/narwhal-monitor/panel-auto-remediate.json",
    ).strip()
    if not policy_path or not (posixpath.isabs(policy_path) or os.path.isabs(policy_path)):
        raise ValueError("SECURITY_PANEL_AUTO_REMEDIATE_FILE must be an absolute path")
    parent = os.path.dirname(policy_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".panel-auto-remediate-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as policy_file:
            json.dump(
                {"domains": remaining, "updated_at": int(time.time())},
                policy_file,
                ensure_ascii=False,
            )
            policy_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, policy_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return remaining


def remove_allowed_panel_domains(domains: List[str]) -> List[str]:
    normalized = {
        str(item).strip().lower().rstrip(".")
        for item in domains
        if isinstance(item, str) and _valid_panel_domain(item)
    }
    policy_path = os.getenv(
        "SECURITY_PANEL_ALLOWLIST_FILE", "/opt/narwhal-monitor/panel-allowlist.json"
    ).strip()
    if not policy_path or not (posixpath.isabs(policy_path) or os.path.isabs(policy_path)):
        raise ValueError("SECURITY_PANEL_ALLOWLIST_FILE must be an absolute path")
    stored_domains: List[str] = []
    try:
        with open(policy_path, "r", encoding="utf-8") as policy_file:
            stored = json.load(policy_file)
        values = stored.get("domains", []) if isinstance(stored, dict) else stored
        if isinstance(values, list):
            stored_domains = [
                str(item).strip().lower().rstrip(".")
                for item in values
                if isinstance(item, str) and _valid_panel_domain(item)
            ]
    except (OSError, TypeError, ValueError):
        pass
    remaining = sorted(set(stored_domains) - normalized)
    parent = os.path.dirname(policy_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".panel-allowlist-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as policy_file:
            json.dump(
                {"domains": remaining, "updated_at": int(time.time())},
                policy_file,
                ensure_ascii=False,
            )
            policy_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, policy_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return remaining


def _socks_auth_enforcement_path() -> str:
    return os.getenv(
        "SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE",
        "/opt/narwhal-monitor/socks-auth-enforcement.json",
    ).strip()


def _socks_auth_enforcement_entries() -> List[Dict[str, object]]:
    policy_path = _socks_auth_enforcement_path()
    if not policy_path:
        return []
    try:
        with open(policy_path, "r", encoding="utf-8") as policy_file:
            stored = json.load(policy_file)
    except (OSError, TypeError, ValueError):
        return []
    entries = stored.get("entries", []) if isinstance(stored, dict) else []
    if not isinstance(entries, list):
        return []
    normalized: List[Dict[str, object]] = []
    for item in entries[:1000]:
        if not isinstance(item, dict):
            continue
        runtime = str(item.get("runtime") or "").strip().lower()
        project = str(item.get("project") or "").strip()
        container_name = str(item.get("container_name") or "").strip()
        process_names = sorted(
            {
                str(name).strip().lower()
                for name in item.get("process_names", [])
                if isinstance(name, str) and str(name).strip().lower() in _SOCKS_PROCESS_NAMES
            }
        ) if isinstance(item.get("process_names"), list) else []
        if runtime not in ("incus", "podman") or not container_name or not process_names:
            continue
        try:
            created_at = int(item.get("created_at") or 0)
            updated_at = int(item.get("updated_at") or 0)
        except (TypeError, ValueError):
            created_at = 0
            updated_at = 0
        normalized.append(
            {
                "runtime": runtime,
                "project": project,
                "container_name": container_name,
                "process_names": process_names,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
    return normalized


def _write_socks_auth_enforcement_entries(entries: List[Dict[str, object]]) -> None:
    policy_path = _socks_auth_enforcement_path()
    if not policy_path or not (posixpath.isabs(policy_path) or os.path.isabs(policy_path)):
        raise ValueError("SECURITY_SOCKS_AUTH_ENFORCEMENT_FILE must be an absolute path")
    parent = os.path.dirname(policy_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".socks-auth-enforcement-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as policy_file:
            json.dump(
                {"entries": entries[:1000], "updated_at": int(time.time())},
                policy_file,
                ensure_ascii=False,
            )
            policy_file.write("\n")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, policy_path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def set_socks_auth_enforcement(
    runtime: str, project: str, container_name: str, process_names: List[str]
) -> Dict[str, object]:
    runtime = runtime.strip().lower()
    project = project.strip()
    container_name = container_name.strip()
    approved_names = sorted(
        {
            str(name).strip().lower()
            for name in process_names
            if isinstance(name, str) and str(name).strip().lower() in _SOCKS_PROCESS_NAMES
        }
    )
    if (
        runtime not in ("incus", "podman")
        or not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name)
        or (project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project))
        or not approved_names
    ):
        raise ValueError("invalid SOCKS enforcement target")
    now = int(time.time())
    entries = _socks_auth_enforcement_entries()
    existing = next(
        (
            item
            for item in entries
            if item["runtime"] == runtime
            and item["project"] == project
            and item["container_name"] == container_name
        ),
        None,
    )
    if existing is None:
        existing = {
            "runtime": runtime,
            "project": project,
            "container_name": container_name,
            "created_at": now,
        }
        entries.append(existing)
    existing["process_names"] = approved_names
    existing["updated_at"] = now
    _write_socks_auth_enforcement_entries(entries)
    return dict(existing)


def remove_socks_auth_enforcement(runtime: str, project: str, container_name: str) -> bool:
    entries = _socks_auth_enforcement_entries()
    remaining = [
        item
        for item in entries
        if not (
            item["runtime"] == runtime.strip().lower()
            and item["project"] == project.strip()
            and item["container_name"] == container_name.strip()
        )
    ]
    if len(remaining) == len(entries):
        return False
    _write_socks_auth_enforcement_entries(remaining)
    return True


def _socks_auth_enforcement_for_container(
    container: Dict[str, object], entries: List[Dict[str, object]] | None = None
) -> Dict[str, object] | None:
    runtime = str(container.get("runtime") or "").strip().lower()
    project = str(container.get("project") or "").strip()
    container_name = str(container.get("name") or "").strip()
    source_entries = entries if entries is not None else _socks_auth_enforcement_entries()
    return next(
        (
            item
            for item in source_entries
            if item["runtime"] == runtime
            and item["project"] == project
            and item["container_name"] == container_name
        ),
        None,
    )


_SOCKS_WEAK_PASSWORDS = {
    "123456", "12345678", "123123", "admin", "admin123", "changeme", "default",
    "guest", "letmein", "pass", "password", "qwerty", "root", "socks", "socks5", "test", "toor",
}


def _socks_process_evidence(process_output: str, combined_identity: str) -> Dict[str, object]:
    matches: List[Dict[str, object]] = []
    candidate_matches: List[Dict[str, object]] = []
    candidate_found = any(name in combined_identity for name in _SOCKS_PROCESS_NAMES)
    detected = any(name in combined_identity for name in _SOCKS_DIRECT_NAMES)
    auth_modes = set()
    reasons = set()
    for line in process_output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3 or not parts[0].isdigit() or "z" in parts[1].lower():
            continue
        args = parts[3] if len(parts) > 3 else parts[2]
        try:
            tokens = shlex.split(args)
        except ValueError:
            tokens = args.split()
        executable_names = {parts[2].lower()}
        executable_names.update(
            posixpath.basename(token).lower() for token in tokens if token and not token.startswith("-")
        )
        matched = next((name for name in _SOCKS_PROCESS_NAMES if name in executable_names), "")
        if not matched:
            continue
        candidate_found = True
        candidate_matches.append({"pid": int(parts[0]), "process": matched})
        lowered_args = args.lower()
        process_detected = matched in _SOCKS_DIRECT_NAMES or "socks" in lowered_args
        if not process_detected and matched in _SOCKS_CONFIGURABLE_NAMES:
            continue
        detected = True
        matches.append({"pid": int(parts[0]), "process": matched})
        process_auth_state = "unknown"
        if matched == "microsocks":
            username_present = "-u" in tokens
            password = tokens[tokens.index("-P") + 1] if "-P" in tokens and tokens.index("-P") + 1 < len(tokens) else ""
            if not username_present or not password:
                auth_modes.add("no_auth")
                process_auth_state = "no_auth"
                reasons.add("microsocks 未同时配置用户名和密码")
            elif password.lower() in _SOCKS_WEAK_PASSWORDS or len(password) < 8:
                auth_modes.add("weak_password")
                process_auth_state = "weak"
                reasons.add("microsocks 使用短密码或常见弱密码")
            else:
                auth_modes.add("configured")
                process_auth_state = "configured"
        elif matched == "gost":
            urls = re.findall(r"socks(?:4|5|5h)?://[^\s]+", args, flags=re.IGNORECASE)
            gost_modes = set()
            if any("@" not in url.split("/", 3)[2] for url in urls):
                auth_modes.add("no_auth")
                gost_modes.add("no_auth")
                reasons.add("gost SOCKS 监听地址未见认证信息")
            for url in urls:
                try:
                    password = urlparse(url).password or ""
                except ValueError:
                    password = ""
                if password and (password.lower() in _SOCKS_WEAK_PASSWORDS or len(password) < 8):
                    auth_modes.add("weak_password")
                    gost_modes.add("weak_password")
                    reasons.add("gost 使用短密码或常见弱密码")
                elif password:
                    auth_modes.add("configured")
                    gost_modes.add("configured")
            process_auth_state = (
                "no_auth" if "no_auth" in gost_modes else
                "weak" if "weak_password" in gost_modes else
                "configured" if "configured" in gost_modes else "unknown"
            )
        matches[-1]["auth_state"] = process_auth_state
    if "no_auth" in auth_modes:
        auth_mode = "no_auth"
    elif "weak_password" in auth_modes:
        auth_mode = "weak_password"
    elif "configured" in auth_modes:
        auth_mode = "configured"
    else:
        auth_mode = "unknown"
    return {
        "candidate_found": candidate_found,
        "detected": detected,
        "process_matches": matches[:20],
        "candidate_matches": candidate_matches[:20],
        "auth_mode": auth_mode,
        "risk_reasons": sorted(reasons),
    }


def _collect_socks_config_evidence(
    runtime: str, name: str, project: str, enabled: bool
) -> Dict[str, object]:
    result: Dict[str, object] = {
        "detected": False,
        "config_files": [],
        "auth_mode": "unknown",
        "risk_reasons": [],
    }
    if not enabled:
        return result
    raw_paths = os.getenv(
        "SECURITY_SOCKS_CONFIG_PATHS",
        "/etc/danted.conf,/etc/sockd.conf,/etc/3proxy/3proxy.cfg,/etc/3proxy.cfg,"
        "/etc/xray/config.json,/usr/local/etc/xray/config.json,/etc/v2ray/config.json,"
        "/usr/local/etc/v2ray/config.json,/etc/sing-box/config.json,/etc/sing-box.json,"
        "/etc/gost/config.yaml,/etc/gost/config.json",
    )
    paths = [
        path.strip()
        for path in raw_paths.split(",")
        if re.fullmatch(r"/[A-Za-z0-9_./-]+", path.strip())
    ][:30]
    if not paths:
        return result
    quoted_paths = " ".join(shlex.quote(path) for path in paths)
    socks_pattern = r"socks5|socksmethod|(^|[[:space:]])socks([[:space:]]|$)|['\"]?(protocol|type)['\"]?[[:space:]]*:[[:space:]]*['\"]?socks"
    no_auth_pattern = r"socksmethod[[:space:]]*:[^#]*(none)|auth[[:space:]]+(none)|['\"]?(auth|method)['\"]?[[:space:]]*:[[:space:]]*['\"]?(noauth|none)"
    weak_pattern = r"((password|passwd|pass)[[:space:]\"']*[:=][[:space:]\"']*|users[[:space:]]+[^[:space:]:]+:CL:)(123456|12345678|123123|admin|admin123|changeme|default|guest|letmein|pass|password|qwerty|root|socks5?|test|toor)([[:space:]\"',}]|$)"
    auth_pattern = r"socksmethod[[:space:]]*:[^#]*(username|pam)|['\"]?(username|password|users)['\"]?[[:space:]]*[:=]"
    command = (
        f"for p in {quoted_paths}; do [ -r \"$p\" ] || continue; "
        f"head -c 262144 \"$p\" 2>/dev/null | grep -Eiq {shlex.quote(socks_pattern)} && echo \"@@SOCKS:$p\"; "
        f"head -c 262144 \"$p\" 2>/dev/null | grep -Eiq {shlex.quote(no_auth_pattern)} && echo \"@@NOAUTH:$p\"; "
        f"head -c 262144 \"$p\" 2>/dev/null | grep -Eiq {shlex.quote(weak_pattern)} && echo \"@@WEAK:$p\"; "
        f"head -c 262144 \"$p\" 2>/dev/null | grep -Eiq {shlex.quote(auth_pattern)} && echo \"@@AUTH:$p\"; done"
    )
    output = run(_runtime_exec_cmd(runtime, name, command, project))
    files = set()
    modes = set()
    reasons = set()
    for raw_line in output.splitlines():
        marker, separator, path = raw_line.strip().partition(":")
        if not separator or path not in paths:
            continue
        if marker == "@@SOCKS":
            files.add(path)
        elif marker == "@@NOAUTH":
            files.add(path)
            modes.add("no_auth")
            reasons.add("SOCKS 配置允许无认证访问")
        elif marker == "@@WEAK":
            files.add(path)
            modes.add("weak_password")
            reasons.add("SOCKS 配置命中短密码或常见弱密码")
        elif marker == "@@AUTH":
            modes.add("configured")
    result.update(
        {
            "detected": bool(files),
            "config_files": sorted(files),
            "auth_mode": "no_auth"
            if "no_auth" in modes
            else "weak_password"
            if "weak_password" in modes
            else "configured"
            if "configured" in modes
            else "unknown",
            "risk_reasons": sorted(reasons),
        }
    )
    return result


def collect_panel_pairing_indicators(
    name: str, runtime: str = "", project: str = "", image: str = ""
) -> Dict[str, object]:
    runtime = runtime or get_container_bin()
    result: Dict[str, object] = {
        "detected": False,
        "process_patterns": [],
        "process_matches": [],
        "identity_patterns": [],
        "config_files": [],
        "credential_markers": [],
        "panel_domains": [],
        "unapproved_domains": [],
        "approved": False,
        "socks_proxy": {},
    }
    if not runtime:
        return result
    patterns = [
        pattern.strip().lower()
        for pattern in os.getenv(
            "SECURITY_PANEL_PROCESS_PATTERNS",
            "xboard-node,xrayr,v2bx,soga,sspanel-uim-node",
        ).split(",")
        if pattern.strip()
    ]
    process_output = run(
        _runtime_exec_cmd(runtime, name, "ps -eo pid=,stat=,comm=,args= 2>/dev/null", project)
    )
    combined_identity = f"{name} {image}".lower()
    socks_process = _socks_process_evidence(process_output, combined_identity)
    socks_config = _collect_socks_config_evidence(
        runtime, name, project, bool(socks_process.get("candidate_found"))
    )
    socks_auth_modes = {str(socks_process.get("auth_mode") or "unknown"), str(socks_config.get("auth_mode") or "unknown")}
    socks_auth_mode = (
        "no_auth" if "no_auth" in socks_auth_modes else
        "weak_password" if "weak_password" in socks_auth_modes else
        "configured" if "configured" in socks_auth_modes else "unknown"
    )
    socks_process_matches = socks_process.get("process_matches", [])
    if socks_config.get("detected"):
        config_auth_mode = str(socks_config.get("auth_mode") or "unknown")
        detected_auth_states = {
            (int(item.get("pid") or 0), str(item.get("process") or "")): str(
                item.get("auth_state") or "unknown"
            )
            for item in socks_process.get("process_matches", [])
            if isinstance(item, dict)
        }
        config_confirmed_matches = []
        for item in socks_process.get("candidate_matches", []):
            if not isinstance(item, dict):
                continue
            identity = (int(item.get("pid") or 0), str(item.get("process") or ""))
            auth_state = detected_auth_states.get(identity, "unknown")
            config_confirmed_matches.append(
                {
                    **item,
                    "auth_state": config_auth_mode
                    if auth_state in ("", "unknown")
                    else auth_state,
                }
            )
        socks_process_matches = config_confirmed_matches
    result["socks_proxy"] = {
        "detected": bool(socks_process.get("detected") or socks_config.get("detected")),
        "process_matches": socks_process_matches,
        "config_files": socks_config.get("config_files", []),
        "auth_mode": socks_auth_mode,
        "risk_reasons": sorted(
            set(socks_process.get("risk_reasons", [])) | set(socks_config.get("risk_reasons", []))
        ),
    }
    process_matches: List[Dict[str, object]] = []
    process_patterns_set = set()
    for line in process_output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3 or not parts[0].isdigit() or "z" in parts[1].lower():
            continue
        candidates = {parts[2].lower()}
        if len(parts) >= 4:
            try:
                command_tokens = shlex.split(parts[3])
            except ValueError:
                command_tokens = parts[3].split()
            candidates.update(
                posixpath.basename(token).lower()
                for token in command_tokens
                if token and not token.startswith("-")
            )
        for pattern in patterns:
            if pattern not in candidates:
                continue
            process_patterns_set.add(pattern)
            process_matches.append({"pid": int(parts[0]), "pattern": pattern})
            break
        if len(process_matches) >= 20:
            break
    process_patterns = sorted(process_patterns_set)
    identity_patterns = sorted({pattern for pattern in patterns if pattern in combined_identity})
    panel_process_pids = sorted(
        {
            int(item.get("pid") or 0)
            for item in process_matches
            if isinstance(item, dict) and int(item.get("pid") or 0) > 1
        }
    )
    env_scan_max = max(
        0,
        min(
            256,
            int(_env_float("SECURITY_PANEL_ENV_SCAN_MAX_PROCESSES", 32)),
        ),
    )
    env_max_bytes = max(
        1024,
        min(65536, int(_env_float("SECURITY_PANEL_ENV_MAX_BYTES", 16384))),
    )
    candidate_pid_text = " ".join(str(pid) for pid in panel_process_pids)

    raw_paths = os.getenv(
        "SECURITY_PANEL_CONFIG_PATHS",
        "/etc/XrayR/config.yml,/etc/V2bX/config.json,/etc/xboard-node/config.yml,/etc/xboard-node/config.yaml,/usr/local/etc/bby-agent.yml,/opt/xboard-node/config.yml,/app/config/config.yml,/etc/soga/soga.conf,/etc/soga/config.yml",
    )
    paths = [path.strip() for path in raw_paths.split(",") if re.fullmatch(r"/[A-Za-z0-9_./-]+", path.strip())]
    quoted_paths = " ".join(shlex.quote(path) for path in paths)
    evidence_output = ""
    if quoted_paths:
        shell_command = (
            f"for p in {quoted_paths}; do "
            "if [ -r \"$p\" ]; then "
            "echo \"@@FILE:$p\"; "
            "grep -Eio 'https?://[^\"[:space:],}]+' \"$p\" 2>/dev/null | head -n 20; "
            "grep -Eio 'ApiHost|ApiKey|NodeID|MachineToken|machine_token|panel[.]url|api_host' \"$p\" 2>/dev/null "
            "| sort -u | sed 's/^/@@KEY:/'; "
            "fi; done; echo '@@ENV'; "
            f"env_scan_max={env_scan_max}; env_max_bytes={env_max_bytes}; "
            "env_scanned=0; env_seen=' '; "
            "scan_panel_env() { "
            "[ \"$env_scanned\" -lt \"$env_scan_max\" ] || return 0; "
            "pid=$1; case \"$env_seen\" in *\" $pid \"*) return 0;; esac; "
            "f=\"/proc/$pid/environ\"; [ -r \"$f\" ] || return 0; "
            "env_seen=\"$env_seen$pid \"; env_scanned=$((env_scanned+1)); "
            "env_dump=$(dd if=\"$f\" bs=\"$env_max_bytes\" count=1 2>/dev/null | tr '\\000' '\\n'); "
            "printf '%s\\n' \"$env_dump\" | grep -Ei '^(apiHost|API_HOST|PANEL_URL|webapi)=https?://' | head -n 20; "
            "printf '%s\\n' \"$env_dump\" | grep -Eio '^(apiKey|API_KEY|MACHINE_TOKEN|nodeID|NODE_ID)=' "
            "| cut -d= -f1 | sed 's/^/@@KEY:/'; "
            "}; "
            f"for pid in {candidate_pid_text or '0'}; do [ \"$pid\" -gt 1 ] 2>/dev/null && scan_panel_env \"$pid\"; done; "
            "for f in /proc/[0-9]*/environ; do "
            "[ \"$env_scanned\" -lt \"$env_scan_max\" ] || break; "
            "pid=${f#/proc/}; pid=${pid%/environ}; scan_panel_env \"$pid\"; "
            "done"
        )
        evidence_output = run(_runtime_exec_cmd(runtime, name, shell_command, project))

    config_files = set()
    credential_markers = set()
    domains = set()
    current_file = ""
    for line in evidence_output.splitlines():
        text = line.strip()
        if text.startswith("@@FILE:"):
            current_file = text.removeprefix("@@FILE:")[:300]
        elif text == "@@ENV":
            current_file = ""
        elif text.startswith("@@KEY:"):
            credential_markers.add(text.removeprefix("@@KEY:")[:80])
            if current_file:
                config_files.add(current_file)
        else:
            found_url = False
            for url in re.findall(r"https?://[^\s\"',}]+", text, flags=re.IGNORECASE):
                try:
                    hostname = urlparse(url).hostname
                except ValueError:
                    hostname = None
                if hostname:
                    domains.add(hostname.lower().rstrip("."))
                    found_url = True
            if current_file and found_url:
                config_files.add(current_file)
    allowed_domains = _configured_allowed_panel_domains()
    unapproved_domains = sorted(domain for domain in domains if not _panel_domain_allowed(domain, allowed_domains))
    detected = bool(process_patterns or identity_patterns or config_files or credential_markers or domains)
    result.update(
        {
            "detected": detected,
            "process_patterns": process_patterns,
            "process_matches": process_matches,
            "identity_patterns": identity_patterns,
            "config_files": sorted(config_files),
            "credential_markers": sorted(credential_markers),
            "panel_domains": sorted(domains),
            "unapproved_domains": unapproved_domains,
            "approved": bool(allowed_domains and domains and not unapproved_domains),
        }
    )
    return result


def _image_matches(image: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    val = image.strip().lower()
    for p in patterns:
        token = p.strip().lower()
        if not token:
            continue
        if token == "*":
            return True
        if token in val:
            return True
    return False


def _oci_containers(runtime_name: str, runtime: str, patterns: List[str]) -> List[Dict[str, str]]:
    out = run([runtime, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"])
    items: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) != 3:
            continue
        container_id, name, image = (x.strip() for x in parts)
        if not _image_matches(image, patterns):
            continue
        items.append({"id": container_id, "name": name, "image": image, "runtime": runtime_name, "runtime_bin": runtime})
    return items


def _incus_security_risks(item: Dict[str, object]) -> List[Dict[str, str]]:
    config: Dict[str, object] = {}
    for key in ("config", "expanded_config"):
        value = item.get(key)
        if isinstance(value, dict):
            config.update(value)
    risks: List[Dict[str, str]] = []
    if str(config.get("security.privileged") or "").lower() == "true":
        risks.append({"code": "incus_privileged", "severity": "critical", "message": "Incus 容器启用了 security.privileged"})
    if str(config.get("security.nesting") or "").lower() == "true":
        risks.append({"code": "incus_nesting", "severity": "warning", "message": "Incus 容器启用了 security.nesting"})
    for key in ("raw.lxc", "raw.apparmor", "raw.seccomp", "raw.idmap"):
        if str(config.get(key) or "").strip():
            risks.append({"code": f"incus_{key.replace('.', '_')}", "severity": "warning", "message": f"Incus 容器设置了 {key}"})
    devices = item.get("expanded_devices") if isinstance(item.get("expanded_devices"), dict) else {}
    for device_name, raw_device in devices.items():
        if not isinstance(raw_device, dict):
            continue
        device_type = str(raw_device.get("type") or "")
        source = str(raw_device.get("source") or "")
        if device_type in ("unix-char", "unix-block"):
            risks.append(
                {
                    "code": "incus_host_device",
                    "severity": "warning",
                    "message": f"Incus 设备 {device_name} 暴露宿主机设备 {source or device_type}",
                }
            )
        if device_type == "disk" and source in ("/", "/proc", "/sys", "/dev", "/run"):
            risks.append(
                {
                    "code": "incus_sensitive_mount",
                    "severity": "critical",
                    "message": f"Incus 设备 {device_name} 挂载宿主机敏感路径 {source}",
                }
            )
    return risks


def _incus_network_exposure(item: Dict[str, object]) -> List[Dict[str, str]]:
    devices = item.get("expanded_devices") if isinstance(item.get("expanded_devices"), dict) else {}
    mappings: List[Dict[str, str]] = []
    for device_name, raw_device in devices.items():
        if not isinstance(raw_device, dict) or str(raw_device.get("type") or "") != "proxy":
            continue
        mappings.append(
            {
                "source": "incus-proxy",
                "device": str(device_name),
                "listen": str(raw_device.get("listen") or ""),
                "target": str(raw_device.get("connect") or ""),
                "nat": str(raw_device.get("nat") or "false"),
            }
        )
    return mappings


def _expand_port_spec(value: str, limit: int = 4096) -> List[int]:
    ports: List[int] = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                continue
            start = max(1, int(start_text))
            end = min(65535, int(end_text))
            if end < start:
                continue
            ports.extend(range(start, min(end, start + limit - len(ports) - 1) + 1))
        elif part.isdigit():
            port = int(part)
            if 0 < port <= 65535:
                ports.append(port)
        if len(ports) >= limit:
            break
    return ports[:limit]


def _incus_network_forward_mappings(runtime: str, project: str) -> List[Dict[str, str]]:
    """Read managed Incus network forwards, cached for one report interval."""
    cache_key = f"{runtime}:{project}"
    cached = _incus_forward_cache.get(cache_key, {})
    now = time.monotonic()
    if cached and now - float(cached.get("ts") or 0) < 240:
        value = cached.get("mappings")
        return list(value) if isinstance(value, list) else []
    base = _runtime_base(runtime, project)
    network_output = run(base + ["network", "list", "--format=json"])
    try:
        networks = json.loads(network_output) if network_output else []
    except (TypeError, ValueError):
        networks = []
    mappings: List[Dict[str, str]] = []
    for network in networks if isinstance(networks, list) else []:
        if not isinstance(network, dict) or not bool(network.get("managed", True)):
            continue
        network_name = str(network.get("name") or "")
        if not network_name:
            continue
        forward_output = run(base + ["network", "forward", "list", network_name, "--format=json"])
        try:
            forwards = json.loads(forward_output) if forward_output else []
        except (TypeError, ValueError):
            forwards = []
        for forward in forwards if isinstance(forwards, list) else []:
            if not isinstance(forward, dict):
                continue
            listen_address = str(forward.get("listen_address") or "")
            config = forward.get("config") if isinstance(forward.get("config"), dict) else {}
            default_target = str(config.get("target_address") or "")
            if listen_address and _is_trackable_ip(default_target):
                mappings.append(
                    {
                        "source": "incus-forward",
                        "device": network_name,
                        "listen": listen_address,
                        "target": default_target,
                        "nat": "true",
                    }
                )
            ports = forward.get("ports") if isinstance(forward.get("ports"), list) else []
            for port_spec in ports:
                if not isinstance(port_spec, dict):
                    continue
                proto = str(port_spec.get("protocol") or "tcp").lower()
                target_address = str(port_spec.get("target_address") or default_target)
                listen_ports = _expand_port_spec(str(port_spec.get("listen_port") or ""))
                target_ports = _expand_port_spec(str(port_spec.get("target_port") or ""))
                if not target_ports:
                    target_ports = list(listen_ports)
                elif len(target_ports) == 1 and len(listen_ports) > 1:
                    target_ports = target_ports * len(listen_ports)
                for index, listen_port in enumerate(listen_ports):
                    target_port = target_ports[index] if index < len(target_ports) else listen_port
                    mappings.append(
                        {
                            "source": "incus-forward",
                            "device": network_name,
                            "listen": f"{proto}:{listen_address}:{listen_port}",
                            "target": f"{proto}:{target_address}:{target_port}",
                            "nat": str(port_spec.get("snat", False)).lower(),
                        }
                    )
                    if len(mappings) >= 4096:
                        break
                if len(mappings) >= 4096:
                    break
            if len(mappings) >= 4096:
                break
        if len(mappings) >= 4096:
            break
    _incus_forward_cache[cache_key] = {"ts": now, "mappings": list(mappings)}
    return mappings


def _oci_security_risks(inspect_data: Dict[str, object]) -> List[Dict[str, str]]:
    host_config = inspect_data.get("HostConfig") if isinstance(inspect_data.get("HostConfig"), dict) else {}
    risks: List[Dict[str, str]] = []
    if bool(host_config.get("Privileged")):
        risks.append({"code": "oci_privileged", "severity": "critical", "message": "容器以 privileged 模式运行"})
    raw_capabilities = host_config.get("CapAdd") or []
    if not isinstance(raw_capabilities, list):
        raw_capabilities = [raw_capabilities]
    capabilities = {str(item).upper() for item in raw_capabilities}
    dangerous_capabilities = sorted(capabilities & {"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH"})
    if dangerous_capabilities:
        risks.append(
            {
                "code": "oci_dangerous_capabilities",
                "severity": "warning",
                "message": f"容器增加高风险 capabilities: {','.join(dangerous_capabilities)}",
            }
        )
    for field, label in (("NetworkMode", "network"), ("PidMode", "PID"), ("IpcMode", "IPC")):
        if str(host_config.get(field) or "").lower() == "host":
            risks.append({"code": f"oci_host_{label.lower()}", "severity": "warning", "message": f"容器共享宿主机 {label} 命名空间"})
    raw_security_options = host_config.get("SecurityOpt") or []
    if not isinstance(raw_security_options, list):
        raw_security_options = [raw_security_options]
    security_options = " ".join(str(item).lower() for item in raw_security_options)
    if any(value in security_options for value in ("seccomp=unconfined", "apparmor=unconfined", "label=disable")):
        risks.append({"code": "oci_isolation_disabled", "severity": "warning", "message": "容器关闭了部分 seccomp/AppArmor/SELinux 隔离"})
    mounts = inspect_data.get("Mounts") if isinstance(inspect_data.get("Mounts"), list) else []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        source = str(mount.get("Source") or "")
        if source in ("/", "/proc", "/sys", "/dev", "/run", "/var/run/podman/podman.sock"):
            risks.append(
                {
                    "code": "oci_sensitive_mount",
                    "severity": "critical" if source in ("/", "/var/run/podman/podman.sock") else "warning",
                    "message": f"容器挂载宿主机敏感路径 {source}",
                }
            )
    return risks


def _oci_network_exposure(inspect_data: Dict[str, object]) -> List[Dict[str, str]]:
    network_settings = (
        inspect_data.get("NetworkSettings") if isinstance(inspect_data.get("NetworkSettings"), dict) else {}
    )
    ports = network_settings.get("Ports") if isinstance(network_settings.get("Ports"), dict) else {}
    if not ports:
        host_config = inspect_data.get("HostConfig") if isinstance(inspect_data.get("HostConfig"), dict) else {}
        ports = host_config.get("PortBindings") if isinstance(host_config.get("PortBindings"), dict) else {}
    mappings: List[Dict[str, str]] = []
    for container_port, bindings in ports.items():
        if not isinstance(bindings, list):
            continue
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            host_ip = str(binding.get("HostIp") or "0.0.0.0")
            host_port = str(binding.get("HostPort") or "")
            mappings.append(
                {
                    "source": "podman-publish",
                    "listen": f"{host_ip}:{host_port}" if host_port else host_ip,
                    "target": str(container_port),
                }
            )
    return mappings


def _incus_containers(runtime: str) -> List[Dict[str, str]]:
    project = os.getenv("INCUS_PROJECT", "").strip()
    cmd = _runtime_base(runtime, project) + ["list", "type=container", "status=running", "--format=json"]
    output = run(cmd)
    try:
        payload = json.loads(output) if output else []
    except Exception:
        payload = []
    patterns_env = os.getenv("MONITORED_INCUS_PATTERNS", "*")
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    items: List[Dict[str, str]] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        if str(item.get("type") or "container").lower() not in ("container", ""):
            continue
        if str(item.get("status") or "running").lower() != "running":
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        config = item.get("config") if isinstance(item.get("config"), dict) else {}
        expanded_config = item.get("expanded_config") if isinstance(item.get("expanded_config"), dict) else {}
        image = str(
            config.get("image.description")
            or expanded_config.get("image.description")
            or config.get("image.os")
            or expanded_config.get("image.os")
            or config.get("volatile.base_image")
            or "incus-container"
        )
        if not _image_matches(f"{name} {image}", patterns):
            continue
        item_project = project or str(item.get("project") or "default")
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        network = state.get("network") if isinstance(state.get("network"), dict) else {}
        network_addresses: List[str] = []
        for interface in network.values():
            if not isinstance(interface, dict):
                continue
            addresses = interface.get("addresses") if isinstance(interface.get("addresses"), list) else []
            for address in addresses:
                if not isinstance(address, dict):
                    continue
                value = str(address.get("address") or "")
                if str(address.get("scope") or "").lower() == "global" and _is_trackable_ip(value):
                    network_addresses.append(value)
        items.append(
            {
                "id": name,
                "name": name,
                "image": image,
                "runtime": "incus",
                "runtime_bin": runtime,
                "project": item_project,
                "pid": str(state.get("pid") or ""),
                "security_risks": _incus_security_risks(item),
                "network_exposure": _incus_network_exposure(item),
                "network_addresses": sorted(set(network_addresses)),
            }
        )
    forward_mappings = _incus_network_forward_mappings(runtime, project)
    for item in items:
        addresses = set(item.get("network_addresses") or [])
        exposures = item.get("network_exposure") if isinstance(item.get("network_exposure"), list) else []
        for mapping in forward_mappings:
            _, target_host, _ = _parse_exposure_endpoint(str(mapping.get("target") or ""))
            if target_host in addresses:
                exposures.append(dict(mapping))
        item["network_exposure"] = exposures
    return items


def list_containers() -> List[Dict[str, str]]:
    patterns_env = os.getenv(
        "MONITORED_IMAGE_PATTERNS",
        "*",
    )
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    items: List[Dict[str, str]] = []
    for runtime_name, runtime in get_runtime_bins().items():
        if runtime_name == "docker" and _docker_monitor_mode() == "off":
            continue
        if runtime_name == "incus":
            items.extend(_incus_containers(runtime))
        else:
            items.extend(_oci_containers(runtime_name, runtime, patterns))
    return items


def collect_docker_notice(container: Dict[str, str]) -> Dict[str, object]:
    runtime = container.get("runtime_bin", "") or "docker"
    return {
        "id": container.get("id", ""),
        "name": container.get("name", "unknown"),
        "image": container.get("image", ""),
        "runtime": "docker",
        "project": "",
        "monitor_mode": "notice",
        "cpu_percent": 0.0,
        "mem_bytes": 0,
        "mem_percent": 0.0,
        "net_rx_bps": 0.0,
        "net_tx_bps": 0.0,
        "conn_count": 0,
        "tcp_country_stats": [],
        "udp_country_stats": [],
        "disk": collect_disk_alert(),
        "container_disk": collect_container_disk_usage(
            container.get("name", ""), runtime, "", include_layer_size=False
        ),
        "top_cpu_process": {"pid": 0, "cpu_percent": 0.0, "command": ""},
        "security": {"notice_only": True},
    }


def podman_containers() -> List[Dict[str, str]]:
    """Backward-compatible alias for callers using the old function name."""
    return list_containers()




def _parse_df_target(df_out: str, target: str) -> Dict[str, int]:
    for line in df_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        mountpoint = parts[5]
        if mountpoint != target:
            continue
        try:
            return {
                "total_bytes": int(parts[1]) * 1024,
                "avail_bytes": int(parts[3]) * 1024,
            }
        except ValueError:
            continue
    return {"total_bytes": 0, "avail_bytes": 0}


def collect_container_disk_usage(
    name: str,
    runtime: str = "",
    project: str = "",
    include_layer_size: bool | None = None,
) -> Dict[str, Dict[str, int] | int]:
    runtime = runtime or get_container_bin()
    if not runtime:
        return {
            "rw_bytes": 0,
            "rootfs_bytes": 0,
            "fs": {"root": {"total_bytes": 0, "avail_bytes": 0}, "data": {"total_bytes": 0, "avail_bytes": 0}},
        }

    if include_layer_size is None:
        include_layer_size = os.getenv("CONTAINER_LAYER_SIZE_ENABLED", "false").strip().lower() in (
            "1", "true", "yes", "on"
        )
    rw_bytes = 0
    rootfs_bytes = 0
    if include_layer_size and _runtime_kind(runtime) != "incus":
        inspect = run([runtime, "container", "inspect", "--size", name])
        if inspect:
            try:
                item = json.loads(inspect)[0]
                rw_bytes = int(item.get("SizeRw") or 0)
                rootfs_bytes = int(item.get("SizeRootFs") or 0)
            except Exception:
                pass

    fs_df = run(_runtime_exec_cmd(runtime, name, "df -P / /data 2>/dev/null || true", project))
    fs = {
        "root": _parse_df_target(fs_df, "/"),
        "data": _parse_df_target(fs_df, "/data"),
    }
    return {"rw_bytes": rw_bytes, "rootfs_bytes": rootfs_bytes, "fs": fs}


def _incus_instance_pid(runtime: str, name: str, project: str = "") -> int:
    path = f"/1.0/instances/{quote(name, safe='')}/state"
    if project:
        path += f"?project={quote(project, safe='')}"
    output = run([runtime, "query", path])
    if not output:
        return 0
    try:
        payload = json.loads(output)
        state = payload.get("metadata", payload) if isinstance(payload, dict) else {}
        return int(state.get("pid", 0) or 0) if isinstance(state, dict) else 0
    except Exception:
        return 0


def _incus_stats(
    runtime: str,
    name: str,
    project: str,
    metrics_snapshot: Dict[Tuple[str, str], Dict[str, float]] | None = None,
) -> Dict[str, float | int]:
    all_metrics = metrics_snapshot if metrics_snapshot is not None else _get_incus_metrics(runtime)
    metrics = all_metrics.get((project or "default", name), {})
    cpu_seconds = float(metrics.get("cpu_seconds", 0.0) or 0.0)
    container_key = f"incus:{project or 'default'}:{name}"
    cpu_percent = _derive_cpu_percent(container_key, cpu_seconds)
    mem_bytes = int(metrics.get("mem_bytes", 0.0) or 0)
    mem_limit = int(metrics.get("mem_total_bytes", 0.0) or 0)
    mem_percent = (float(mem_bytes) / float(mem_limit)) * 100.0 if mem_limit > 0 else 0.0
    return {
        "cpu_percent": cpu_percent,
        "cpu_effective_cpus": float(metrics.get("effective_cpus", 0.0) or 0.0),
        "mem_bytes": mem_bytes,
        "mem_limit_bytes": mem_limit,
        "mem_percent": mem_percent,
        "net_rx_total_bytes": int(metrics.get("net_rx_total_bytes", 0.0) or 0),
        "net_tx_total_bytes": int(metrics.get("net_tx_total_bytes", 0.0) or 0),
        "net_rx_total_packets": int(metrics.get("net_rx_total_packets", 0.0) or 0),
        "net_tx_total_packets": int(metrics.get("net_tx_total_packets", 0.0) or 0),
    }


def collect_container(
    name: str,
    container_id: str = "",
    runtime: str = "",
    runtime_name: str = "",
    project: str = "",
    pid_hint: int = 0,
    precomputed_security_risks: List[Dict[str, str]] | None = None,
    precomputed_network_exposure: List[Dict[str, str]] | None = None,
    image: str = "",
    precomputed_incus_metrics: Dict[Tuple[str, str], Dict[str, float]] | None = None,
    precomputed_network_addresses: List[str] | None = None,
    host_conntrack: Dict[str, object] | None = None,
) -> Dict:
    runtime = runtime or get_container_bin()
    runtime_name = runtime_name or _runtime_kind(runtime)
    if not runtime:
        return {
            "id": container_id,
            "name": name,
            "cpu_percent": 0.0,
            "mem_bytes": 0,
            "mem_limit_bytes": 0,
            "mem_percent": 0.0,
            "net_rx_bps": 0.0,
            "net_tx_bps": 0.0,
            "conn_count": 0,
            "tcp_country_stats": [],
            "udp_country_stats": [],
            "disk": collect_disk_alert(),
            "container_disk": {"rw_bytes": 0, "rootfs_bytes": 0},
        }

    cpu_percent = 0.0
    mem = 0
    mem_limit = 0
    mem_percent = 0.0
    rx_total = 0
    tx_total = 0
    net_rx = 0.0
    net_tx = 0.0
    rx_packet_total = 0
    tx_packet_total = 0

    stats_json = ""
    stats_tpl = ""
    stats_compact = ""
    if runtime_name == "incus":
        parsed_stats = _incus_stats(runtime, name, project, precomputed_incus_metrics)
        parsed_tpl = _parse_stats_template("")
        parsed_compact = _parse_stats_compact("")
    else:
        stats_json = run([runtime, "stats", "--no-stream", "--format", "json", name])
        parsed_stats = _parse_stats_json(stats_json)
        stats_tpl = run_first_success(
            [
                [runtime, "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}", name],
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsage}}|{{.NetIO}}", name],
            ]
        )
        parsed_tpl = _parse_stats_template(stats_tpl)
        stats_compact = run_first_success(
            [
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsageBytes}}|{{.NetIO}}", name],
                [runtime, "stats", "--no-stream", "--format", "{{.CPU}}|{{.MemUsage}}|{{.NetIO}}", name],
            ]
        )
        parsed_compact = _parse_stats_compact(stats_compact)

    cpu_candidates = [parsed_stats["cpu_percent"], parsed_tpl["cpu_percent"], parsed_compact["cpu_percent"]]
    mem_candidates = [parsed_stats["mem_bytes"], parsed_tpl["mem_bytes"], parsed_compact["mem_bytes"]]
    mem_limit_candidates = [
        parsed_stats.get("mem_limit_bytes", 0),
        parsed_tpl.get("mem_limit_bytes", 0),
        parsed_compact.get("mem_limit_bytes", 0),
    ]
    mem_percent_candidates = [parsed_stats["mem_percent"], parsed_tpl["mem_percent"], parsed_compact["mem_percent"]]
    net_candidates = [
        (parsed_stats["net_rx_total_bytes"], parsed_stats["net_tx_total_bytes"]),
        (parsed_tpl["net_rx_total_bytes"], parsed_tpl["net_tx_total_bytes"]),
        (parsed_compact["net_rx_total_bytes"], parsed_compact["net_tx_total_bytes"]),
    ]

    for c in cpu_candidates:
        if float(c) > 0:
            cpu_percent = float(c)
            break
    for m in mem_candidates:
        if int(m) > 0:
            mem = int(m)
            break
    for limit in mem_limit_candidates:
        if int(limit) > 0:
            mem_limit = int(limit)
            break
    for mp in mem_percent_candidates:
        if float(mp) > 0:
            mem_percent = float(mp)
            break
    for rx_c, tx_c in net_candidates:
        if int(rx_c) > 0 or int(tx_c) > 0:
            rx_total = int(rx_c)
            tx_total = int(tx_c)
            break
    rx_packet_total = int(parsed_stats.get("net_rx_total_packets", 0) or 0)
    tx_packet_total = int(parsed_stats.get("net_tx_total_packets", 0) or 0)

    conn_count = 0
    pid = int(pid_hint or 0)
    inspect = ""
    configuration_risks = list(precomputed_security_risks or [])
    network_exposure = list(precomputed_network_exposure or [])
    network_addresses = list(precomputed_network_addresses or [])
    if runtime_name == "incus":
        if pid <= 0:
            pid = _incus_instance_pid(runtime, name, project)
    else:
        inspect = run([runtime, "inspect", name])
    if inspect:
        try:
            d = json.loads(inspect)[0]
            pid = int(d.get("State", {}).get("Pid", 0) or 0)
            configuration_risks = _oci_security_risks(d)
            network_exposure = _oci_network_exposure(d)
            network_settings = d.get("NetworkSettings") if isinstance(d.get("NetworkSettings"), dict) else {}
            networks = network_settings.get("Networks") if isinstance(network_settings.get("Networks"), dict) else {}
            for network in networks.values():
                if not isinstance(network, dict):
                    continue
                for key in ("IPAddress", "GlobalIPv6Address"):
                    value = str(network.get(key) or "")
                    if _is_trackable_ip(value):
                        network_addresses.append(value)
        except Exception:
            pass
    if pid:
        conn_count = _count_connections_from_pid(pid)
        if conn_count <= 0:
            conn_out = run(["sh", "-lc", f"ss -Hantup | grep -c 'pid={pid},'"])
            conn_count = int(conn_out.strip() or 0)

    if pid > 0:
        proc_rx, proc_tx, proc_rx_packets, proc_tx_packets = _read_net_stats_from_pid(pid)
        if proc_rx > 0 or proc_tx > 0:
            if rx_total <= 0 and tx_total <= 0:
                rx_total = proc_rx
                tx_total = proc_tx
        if rx_packet_total <= 0 and tx_packet_total <= 0:
            rx_packet_total = proc_rx_packets
            tx_packet_total = proc_tx_packets

    container_key = f"{runtime_name}:{project}:{container_id or name}"
    net_rx, net_tx = _derive_net_bps(container_key, rx_total, tx_total)
    net_rx_pps, net_tx_pps = _derive_packet_rates(container_key, rx_packet_total, tx_packet_total)
    protocol_rates = _derive_protocol_rates(container_key, _read_protocol_counters(pid)) if pid > 0 else {}
    process_count = _read_process_count_from_pid(pid)

    if runtime_name != "incus" and stats_json.strip() == "" and stats_tpl.strip() == "" and stats_compact.strip() == "":
        warn_key = f"{runtime}:stats-empty"
        if warn_key not in _warned_parse_paths:
            _warned_parse_paths.add(warn_key)
            print(f"warn: '{runtime} stats' returned empty output; CPU/内存/网络将显示为 0。")
    if conn_count <= 0:
        conn_count = _count_connections_from_exec(runtime, name, project)
    tcp_ip_counter = _collect_tcp_remote_ips(pid)
    udp_ip_counter = _collect_udp_remote_ips(pid)
    if not tcp_ip_counter:
        tcp_ip_counter = _collect_remote_ips_from_exec(runtime, name, "tcp", project)
    if not udp_ip_counter:
        udp_ip_counter = _collect_remote_ips_from_exec(runtime, name, "udp", project)
    tcp_country_stats = _geoip_country_batch(tcp_ip_counter)
    udp_country_stats = _geoip_country_batch(udp_ip_counter)

    if (mem <= 0 or mem_percent <= 0) and pid > 0:
        pid_mem_bytes, pid_mem_percent = _read_mem_usage_from_pid(pid)
        if mem <= 0 and pid_mem_bytes > 0:
            mem = pid_mem_bytes
        if mem_percent <= 0 and pid_mem_percent > 0:
            mem_percent = pid_mem_percent
    if mem_limit <= 0 and mem > 0 and mem_percent > 0:
        mem_limit = int((float(mem) * 100.0) / float(mem_percent))

    disk = collect_disk_alert()
    container_disk = collect_container_disk_usage(name, runtime, project)
    top_cpu_process = collect_top_cpu_process(name, runtime, project)
    suspicious_processes = collect_suspicious_processes(name, runtime, project)
    panel_pairing = collect_panel_pairing_indicators(name, runtime, project, image)
    socks_proxy = panel_pairing.pop("socks_proxy", {})
    socket_security = _collect_socket_security(pid)
    _apply_host_conntrack_security(
        socket_security,
        host_conntrack or {},
        network_addresses,
        network_exposure,
    )
    if isinstance(socks_proxy, dict) and socks_proxy.get("detected"):
        listening_endpoints = (
            socket_security.get("listening_endpoints")
            if isinstance(socket_security.get("listening_endpoints"), list)
            else []
        )
        socks_proxy["listening_ports"] = socket_security.get("listening_ports", [])
        socks_proxy["public_exposure"] = bool(network_exposure) or any(
            str(endpoint).startswith(("0.0.0.0:", "[::]:")) for endpoint in listening_endpoints
        )
    has_remote_connections = any(
        int(socket_security.get(key) or 0) > 0
        for key in (
            "incoming_established",
            "outbound_established",
            "inbound_unique_ips",
            "outbound_unique_ips",
        )
    )
    communication = (
        _collect_socket_process_details(
            runtime,
            name,
            project,
            socket_security.get("listening_ports", [])
            if isinstance(socket_security.get("listening_ports"), list)
            else [],
        )
        if has_remote_connections
        else {
            "communication_detail_available": True,
            "communication_snapshot_count": 0,
            "communication_snapshot_truncated": False,
            "communication_processes": [],
            "communication_sockets": [],
        }
    )
    _enrich_communication_with_original_sources(
        communication,
        socket_security.get("inbound_public_flows", [])
        if isinstance(socket_security.get("inbound_public_flows"), list)
        else [],
    )
    socket_security.update(
        {
            "net_rx_pps": net_rx_pps,
            "net_tx_pps": net_tx_pps,
            "net_rx_total_packets": rx_packet_total,
            "net_tx_total_packets": tx_packet_total,
            "suspicious_processes": suspicious_processes,
            "configuration_risks": configuration_risks,
            "protocol_rates": protocol_rates,
            "process_count": process_count,
            "panel_pairing": panel_pairing,
            "socks_proxy": socks_proxy,
            "network_exposure": network_exposure,
            **communication,
        }
    )
    if cpu_percent <= 0 and float(top_cpu_process.get("cpu_percent") or 0) > 0:
        cpu_percent = float(top_cpu_process.get("cpu_percent") or 0)
    return {
        "id": container_id,
        "name": name,
        "image": image,
        "runtime": runtime_name,
        "project": project,
        "cpu_percent": cpu_percent,
        "cpu_effective_cpus": float(parsed_stats.get("cpu_effective_cpus", 0.0) or 0.0),
        "mem_bytes": mem,
        "mem_limit_bytes": mem_limit,
        "mem_percent": mem_percent,
        "net_rx_bps": net_rx,
        "net_tx_bps": net_tx,
        "conn_count": conn_count,
        "tcp_country_stats": tcp_country_stats,
        "udp_country_stats": udp_country_stats,
        "disk": disk,
        "container_disk": container_disk,
        "top_cpu_process": top_cpu_process,
        "security": socket_security,
    }


def _redact_process_command(command: str) -> str:
    """Remove common inline credentials before a process command is reported."""
    value = re.sub(
        r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[=:]\s*|\s+)([^\s]{1,300})",
        r"\1\2[REDACTED]",
        command or "",
    )
    value = re.sub(r"(?i)(https?://[^\s:/]+:)[^@\s]+@", r"\1[REDACTED]@", value)
    return value[:500]


def _collect_deep_process_snapshot(
    runtime: str, name: str, project: str, process_limit: int
) -> Dict[str, object]:
    capture_limit = max(20, min(200, int(process_limit)))
    command = (
        "(ps -eo pid=,ppid=,user=,stat=,pcpu=,rss=,comm=,args= --sort=-pcpu 2>/dev/null || "
        "ps -eo pid=,ppid=,user=,stat=,pcpu=,rss=,comm=,args= 2>/dev/null) "
        f"| head -n {capture_limit + 1}"
    )
    output = run(_runtime_exec_cmd(runtime, name, command, project))
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
                    "command": _redact_process_command(parts[7] if len(parts) > 7 else parts[6]),
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
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return ""


def _collect_host_proc_process_snapshot(
    init_pid: int, process_limit: int
) -> Tuple[Dict[str, object], List[Dict[str, object]]]:
    """Read a target container process tree from host /proc when the image has no ps."""
    if init_pid <= 1 or not os.path.isdir(f"/proc/{init_pid}"):
        return {"available": False, "captured": 0, "truncated": False, "items": []}, []
    scan_limit = max(1000, min(50000, int(_env_float("DEEP_HOST_PROC_SCAN_MAX", 20000))))
    parent_map: Dict[int, int] = {}
    status_map: Dict[int, str] = {}
    try:
        proc_ids = sorted(int(value) for value in os.listdir("/proc") if value.isdigit())[:scan_limit]
    except OSError:
        proc_ids = []
    for host_pid in proc_ids:
        status = _read_host_proc_text(f"/proc/{host_pid}/status")
        parent_match = re.search(r"(?m)^PPid:\s+(\d+)", status)
        if not parent_match:
            continue
        parent_map[host_pid] = int(parent_match.group(1))
        status_map[host_pid] = status

    descendants = {init_pid}
    changed = True
    while changed and len(descendants) <= scan_limit:
        changed = False
        for host_pid, parent_pid in parent_map.items():
            if host_pid not in descendants and parent_pid in descendants:
                descendants.add(host_pid)
                changed = True
    capture_limit = max(20, min(200, int(process_limit)))
    try:
        uptime = float(_read_host_proc_text("/proc/uptime", 128).split()[0])
        clock_ticks = float(os.sysconf("SC_CLK_TCK"))
    except (IndexError, OSError, TypeError, ValueError):
        uptime, clock_ticks = 0.0, 100.0
    host_processes: List[Dict[str, object]] = []
    for host_pid in sorted(descendants):
        status = status_map.get(host_pid) or _read_host_proc_text(f"/proc/{host_pid}/status")
        namespace_match = re.search(r"(?m)^NSpid:\s+(.+)$", status)
        namespace_values = re.findall(r"\d+", namespace_match.group(1)) if namespace_match else []
        namespace_pid = int(namespace_values[-1]) if namespace_values else (1 if host_pid == init_pid else host_pid)
        uid_match = re.search(r"(?m)^Uid:\s+(\d+)", status)
        state_match = re.search(r"(?m)^State:\s+([^\s]+)", status)
        rss_match = re.search(r"(?m)^VmRSS:\s+(\d+)\s+kB", status, flags=re.IGNORECASE)
        comm = _read_host_proc_text(f"/proc/{host_pid}/comm", 256).strip()[:120] or "unknown"
        try:
            with open(f"/proc/{host_pid}/cmdline", "rb") as handle:
                command = handle.read(8192).replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        except OSError:
            command = comm
        cpu_percent = 0.0
        stat = _read_host_proc_text(f"/proc/{host_pid}/stat", 4096)
        close_paren = stat.rfind(")")
        stat_fields = stat[close_paren + 2 :].split() if close_paren >= 0 else []
        if len(stat_fields) > 19 and uptime > 0 and clock_ticks > 0:
            try:
                cpu_seconds = (float(stat_fields[11]) + float(stat_fields[12])) / clock_ticks
                lifetime = max(0.001, uptime - (float(stat_fields[19]) / clock_ticks))
                cpu_percent = max(0.0, (cpu_seconds / lifetime) * 100.0)
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
                "command": _redact_process_command(command or comm),
            }
        )
    namespace_by_host = {
        int(item.get("host_pid") or 0): int(item.get("pid") or 0) for item in host_processes
    }
    for item in host_processes:
        item["ppid"] = namespace_by_host.get(int(item.get("ppid") or 0), 0)
    host_processes.sort(key=lambda item: float(item.get("cpu_percent") or 0), reverse=True)
    public_items = [{key: value for key, value in item.items() if key != "host_pid"} for item in host_processes]
    return (
        {
            "available": bool(host_processes),
            "source": "host_proc",
            "captured": min(len(public_items), capture_limit),
            "truncated": len(public_items) > capture_limit,
            "items": public_items[:capture_limit],
        },
        host_processes,
    )


def _collect_host_proc_socket_details(
    init_pid: int,
    host_processes: List[Dict[str, object]],
    listening_ports: List[int],
    socket_limit: int,
) -> Dict[str, object]:
    """Attribute bounded /proc socket tables to container processes without requiring ss."""
    if init_pid <= 1 or not host_processes:
        return {"communication_detail_available": False, "communication_sockets": [], "communication_processes": []}
    inode_owners: Dict[str, Tuple[int, str]] = {}
    fd_budget = max(1000, min(20000, int(_env_float("DEEP_HOST_PROC_FD_MAX", 10000))))
    visited_fds = 0
    for process in host_processes:
        host_pid = int(process.get("host_pid") or 0)
        try:
            fd_names = os.listdir(f"/proc/{host_pid}/fd")[:1024]
        except OSError:
            continue
        for fd_name in fd_names:
            if visited_fds >= fd_budget:
                break
            visited_fds += 1
            try:
                target = os.readlink(f"/proc/{host_pid}/fd/{fd_name}")
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                inode_owners.setdefault(
                    match.group(1),
                    (int(process.get("pid") or 0), str(process.get("process") or "unknown")[:120]),
                )
        if visited_fds >= fd_budget:
            break

    state_names = {
        "01": "established", "02": "syn-sent", "03": "syn-recv", "04": "fin-wait-1",
        "05": "fin-wait-2", "06": "time-wait", "07": "close", "08": "close-wait",
        "09": "last-ack", "0A": "listen", "0B": "closing",
    }
    listening = {int(port) for port in listening_ports if int(port) > 0}
    sockets: List[Dict[str, object]] = []
    snapshot_count = 0
    snapshot_cap = max(500, min(2000, socket_limit * 2))
    for filename, proto, is_v6 in (
        ("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True)
    ):
        table = _read_host_proc_text(f"/proc/{init_pid}/net/{filename}", 2_000_000)
        for line in table.splitlines()[1:]:
            if snapshot_count >= snapshot_cap:
                break
            parts = line.split()
            if len(parts) < 10 or ":" not in parts[1] or ":" not in parts[2]:
                continue
            snapshot_count += 1
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            remote_ip_hex, remote_port_hex = parts[2].rsplit(":", 1)
            local_ip = _decode_proc_addr(local_ip_hex, is_v6=is_v6)
            remote_ip = _decode_proc_addr(remote_ip_hex, is_v6=is_v6)
            local_port = _parse_port(local_port_hex)
            remote_port = _parse_port(remote_port_hex)
            state = parts[3].upper()
            if proto == "tcp" and state not in ("01", "02", "03"):
                continue
            if proto == "udp" and remote_port <= 0:
                continue
            if not _is_trackable_ip(remote_ip):
                continue
            owner_pid, owner_name = inode_owners.get(parts[9], (0, "unknown"))
            direction = "inbound" if local_port in listening or state == "03" else "outbound"
            local_text = f"[{local_ip}]:{local_port}" if ":" in local_ip else f"{local_ip}:{local_port}"
            remote_text = f"[{remote_ip}]:{remote_port}" if ":" in remote_ip else f"{remote_ip}:{remote_port}"
            if len(sockets) < socket_limit:
                sockets.append(
                    {
                        "proto": proto,
                        "state": state_names.get(state, state.lower()),
                        "direction": direction,
                        "local": local_text,
                        "remote": remote_text,
                        "remote_ip": remote_ip,
                        "process": owner_name,
                        "pid": owner_pid,
                    }
                )
        if snapshot_count >= snapshot_cap:
            break
    totals: Dict[Tuple[int, str], Dict[str, object]] = {}
    for item in sockets:
        key = (int(item.get("pid") or 0), str(item.get("process") or "unknown"))
        aggregate = totals.setdefault(
            key,
            {"pid": key[0], "process": key[1], "inbound_connections": 0, "outbound_connections": 0, "remote_ips": set()},
        )
        direction = "inbound" if item.get("direction") == "inbound" else "outbound"
        aggregate[f"{direction}_connections"] = int(aggregate[f"{direction}_connections"]) + 1
        remote_ips = aggregate.get("remote_ips")
        if isinstance(remote_ips, set):
            remote_ips.add(str(item.get("remote_ip") or ""))
    process_totals = []
    for aggregate in totals.values():
        remote_ips = aggregate.pop("remote_ips", set())
        aggregate["unique_remote_ips"] = len(remote_ips) if isinstance(remote_ips, set) else 0
        process_totals.append(aggregate)
    process_totals.sort(
        key=lambda item: int(item.get("inbound_connections") or 0) + int(item.get("outbound_connections") or 0),
        reverse=True,
    )
    return {
        "communication_detail_available": True,
        "communication_source": "host_proc",
        "communication_snapshot_count": snapshot_count,
        "communication_snapshot_truncated": snapshot_count >= snapshot_cap,
        "communication_processes": process_totals[:50],
        "communication_sockets": sockets,
    }


def collect_container_deep_sample(
    name: str,
    runtime: str,
    runtime_name: str,
    project: str,
    pid: int,
    action: Dict[str, object],
    base_report: Dict[str, object],
) -> Dict[str, object]:
    """Collect a single bounded diagnostic snapshot for an explicitly requested container."""
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    sample_seconds = max(0.5, min(2.0, float(params.get("sample_seconds") or 1.0)))
    process_limit = max(20, min(200, int(params.get("process_limit") or 100)))
    socket_limit = max(50, min(500, int(params.get("socket_limit") or 250)))
    started = time.monotonic()
    errors: List[str] = []

    first = _read_net_stats_from_pid(pid)
    time.sleep(sample_seconds)
    second = _read_net_stats_from_pid(pid)
    elapsed = max(0.001, time.monotonic() - started)
    if pid <= 0:
        errors.append("container init pid unavailable; instantaneous network counters are unavailable")
    rates = {
        "sample_seconds": round(elapsed, 3),
        "rx_bps": max(0.0, float(second[0] - first[0]) / elapsed),
        "tx_bps": max(0.0, float(second[1] - first[1]) / elapsed),
        "rx_pps": max(0.0, float(second[2] - first[2]) / elapsed),
        "tx_pps": max(0.0, float(second[3] - first[3]) / elapsed),
    }

    process_snapshot = _collect_deep_process_snapshot(runtime, name, project, process_limit)
    host_processes: List[Dict[str, object]] = []
    if not process_snapshot.get("available"):
        process_snapshot, host_processes = _collect_host_proc_process_snapshot(pid, process_limit)
        if not process_snapshot.get("available"):
            errors.append("process metadata is unavailable from both container ps and host /proc")
    security = base_report.get("security") if isinstance(base_report.get("security"), dict) else {}
    listening_ports = security.get("listening_ports") if isinstance(security.get("listening_ports"), list) else []
    communication = _collect_socket_process_details(
        runtime,
        name,
        project,
        listening_ports,
        snapshot_limit_override=max(500, socket_limit * 2),
        detail_limit_override=socket_limit,
    )
    if not communication.get("communication_detail_available"):
        if not host_processes:
            _, host_processes = _collect_host_proc_process_snapshot(pid, process_limit)
        host_communication = _collect_host_proc_socket_details(
            pid, host_processes, listening_ports, socket_limit
        )
        if host_communication.get("communication_detail_available"):
            communication = host_communication
        else:
            errors.append("socket ownership is unavailable from both container ss and host /proc")
    _enrich_communication_with_original_sources(
        communication,
        security.get("inbound_public_flows", [])
        if isinstance(security.get("inbound_public_flows"), list)
        else [],
    )
    sockets = communication.get("communication_sockets")
    sockets = sockets if isinstance(sockets, list) else []
    ip_totals: Dict[str, Dict[str, object]] = {}
    for item in sockets:
        if not isinstance(item, dict):
            continue
        remote_ip = str(item.get("remote_ip") or "")
        original_ips = item.get("original_remote_ips") if isinstance(item.get("original_remote_ips"), list) else []
        candidates = original_ips if item.get("direction") == "inbound" and original_ips else [remote_ip]
        for ip in candidates:
            normalized = str(ip or "")
            if not _is_trackable_ip(normalized):
                continue
            entry = ip_totals.setdefault(
                normalized,
                {"ip": normalized, "connections": 0, "inbound": 0, "outbound": 0, "processes": set()},
            )
            entry["connections"] = int(entry["connections"]) + 1
            direction = "inbound" if item.get("direction") == "inbound" else "outbound"
            entry[direction] = int(entry[direction]) + 1
            processes = entry.get("processes")
            if isinstance(processes, set):
                processes.add(str(item.get("process") or "unknown")[:120])
    connection_ips = []
    for entry in ip_totals.values():
        processes = entry.pop("processes", set())
        entry["processes"] = sorted(processes)[:20] if isinstance(processes, set) else []
        connection_ips.append(entry)
    connection_ips.sort(key=lambda item: int(item.get("connections") or 0), reverse=True)

    return {
        "action_id": int(action.get("id") or 0),
        "sampled_at": int(time.time()),
        "runtime": runtime_name,
        "project": project,
        "container_name": name,
        "network_rates": rates,
        "process_count": int(security.get("process_count") or process_snapshot.get("captured") or 0),
        "processes": process_snapshot,
        "connection_count": max(int(base_report.get("conn_count") or 0), len(sockets)),
        "unique_connection_ips": len(connection_ips),
        "inbound_unique_ips": int(security.get("inbound_unique_ips") or 0),
        "outbound_unique_ips": int(security.get("outbound_unique_ips") or 0),
        "connection_ips": connection_ips[:100],
        "communication_processes": communication.get("communication_processes", []),
        "communication_sockets": sockets,
        "socket_snapshot_count": int(communication.get("communication_snapshot_count") or 0),
        "socket_snapshot_truncated": bool(communication.get("communication_snapshot_truncated")),
        "errors": errors,
    }


_disk_alert_cache: Dict[str, object] = {}
_disk_alert_cache_at = 0.0


def collect_disk_alert() -> Dict:
    global _disk_alert_cache, _disk_alert_cache_at
    now = time.monotonic()
    if _disk_alert_cache and now - _disk_alert_cache_at < 30:
        return dict(_disk_alert_cache)
    file_path = os.getenv("WATCH_DISK_FILE", "/xfs_disk.img")
    image_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    def parse_host_df(output: str) -> Dict[str, object]:
        for line in reversed(output.splitlines()):
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                return {
                    "device": parts[0],
                    "total_bytes": int(parts[1]) * 1024,
                    "avail_bytes": int(parts[3]) * 1024,
                    "used_percent": float(parts[4].rstrip("%")),
                    "mountpoint": parts[5],
                }
            except ValueError:
                continue
        return {"device": "", "total_bytes": 0, "avail_bytes": 0, "used_percent": 0.0, "mountpoint": ""}

    root_usage = parse_host_df(run(["df", "-P", "/"]))
    requested_main_path = "/data" if os.path.exists("/data") else "/"
    main_usage = parse_host_df(run(["df", "-P", requested_main_path]))
    result = {
        "file": file_path,
        "size_bytes": image_size,
        "used_percent": float(main_usage["used_percent"]),
        "root_device": str(root_usage["device"]),
        "root_total_bytes": int(root_usage["total_bytes"]),
        "root_avail_bytes": int(root_usage["avail_bytes"]),
        "data_requested_path": requested_main_path,
        "data_mountpoint": str(main_usage["mountpoint"] or requested_main_path),
        "data_total_bytes": int(main_usage["total_bytes"]),
        "data_avail_bytes": int(main_usage["avail_bytes"]),
    }
    _disk_alert_cache = result
    _disk_alert_cache_at = now
    return dict(result)


def _host_ip_family_available(family: int) -> bool:
    target = ("1.1.1.1", 53) if family == socket.AF_INET else ("2606:4700:4700::1111", 53)
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
        probe.settimeout(2)
        probe.connect(target)
        address = probe.getsockname()[0]
        probe.close()
        return bool(address) and address not in ("0.0.0.0", "::")
    except OSError:
        return False


def network_health(containers: List[Dict[str, str]] | None = None) -> Tuple[bool, bool]:
    containers = containers if containers is not None else list_containers()
    v4_ok = _host_ip_family_available(socket.AF_INET)
    v6_ok = _host_ip_family_available(socket.AF_INET6)
    if not containers or (v4_ok and v6_ok):
        return v4_ok, v6_ok
    for item in containers:
        name = item.get("name", "")
        if not name:
            continue
        runtime = item.get("runtime_bin", "") or get_container_bin()
        runtime_name = item.get("runtime", "") or _runtime_kind(runtime)
        project = item.get("project", "")
        try:
            pid = int(item.get("pid", "") or 0)
        except ValueError:
            pid = 0
        if runtime_name == "incus":
            if pid <= 0:
                pid = _incus_instance_pid(runtime, name, project)
        else:
            inspect = run([runtime, "inspect", name])
            try:
                detail = json.loads(inspect)[0]
                pid = int(detail.get("State", {}).get("Pid", 0) or 0)
            except Exception:
                pid = 0

        if pid > 0:
            if not v4_ok:
                v4_ok = bool(
                    run(
                        [
                            "sh",
                            "-lc",
                            f"nsenter -t {pid} -n sh -lc 'curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok'",
                        ]
                    ).strip()
                )
            if not v6_ok:
                v6_ok = bool(
                    run(
                        [
                            "sh",
                            "-lc",
                            f"nsenter -t {pid} -n sh -lc 'curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok'",
                        ]
                    ).strip()
                )
        else:
            if not v4_ok:
                v4_ok = bool(
                    run(_runtime_exec_cmd(runtime, name, "curl -4 -s --max-time 5 ip.sb >/dev/null && echo ok", project)).strip()
                )
            if not v6_ok:
                v6_ok = bool(
                    run(_runtime_exec_cmd(runtime, name, "curl -6 -s --max-time 5 ip.sb >/dev/null && echo ok", project)).strip()
                )

        if v4_ok and v6_ok:
            break
    return v4_ok, v6_ok


def sign(body: bytes, secret: str, ts: int) -> str:
    return hmac.new(secret.encode(), body + str(ts).encode(), hashlib.sha256).hexdigest()


def normalize_server_url(server: str) -> str:
    cleaned = (server or "").strip()
    if not cleaned:
        return "https://127.0.0.1:8080"
    if not urlparse(cleaned).scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def server_tls_verify() -> bool | str:
    ca_file = os.getenv("SERVER_TLS_CA_FILE", "").strip()
    if not ca_file:
        return True
    if not os.path.isfile(ca_file):
        raise RuntimeError(f"SERVER_TLS_CA_FILE does not exist: {ca_file}")
    return ca_file


def signed_post_json(server: str, secret: str, path: str, payload: Dict) -> Dict:
    server = normalize_server_url(server)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    response = requests.post(
        f"{server.rstrip('/')}{path}",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Timestamp": timestamp,
            "X-Signature": sign(body, secret, int(timestamp)),
        },
        timeout=30,
        verify=server_tls_verify(),
    )
    response.raise_for_status()
    expected = hmac.new(
        secret.encode(), response.content + timestamp.encode(), hashlib.sha256
    ).hexdigest()
    received = response.headers.get("X-Narwhal-Response-Signature", "")
    if not received or not hmac.compare_digest(expected, received):
        raise RuntimeError("Server action response signature verification failed")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("Server action response is not a JSON object")
    return value


def _run_action_command(cmd: List[str]) -> Tuple[bool, str]:
    env = None
    if cmd and cmd[0] == "podman-remote":
        socket_path = os.getenv("PODMAN_SOCKET", "/run/podman/podman.sock")
        if "CONTAINER_HOST" not in os.environ and os.path.exists(socket_path):
            env = os.environ.copy()
            env["CONTAINER_HOST"] = f"unix://{socket_path}"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=90)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[:500]
    message = (result.stdout or result.stderr or "").strip()[:1000]
    return result.returncode == 0, message


def _configured_panel_process_patterns() -> List[str]:
    return [
        item.strip().lower()
        for item in os.getenv(
            "SECURITY_PANEL_PROCESS_PATTERNS", "xboard-node,xrayr,v2bx,soga,sspanel-uim-node"
        ).split(",")
        if re.fullmatch(r"[a-zA-Z0-9_.@-]{2,80}", item.strip())
    ]


def _configured_panel_config_paths() -> List[str]:
    raw = os.getenv(
        "SECURITY_PANEL_CONFIG_PATHS",
        "/etc/XrayR/config.yml,/etc/V2bX/config.json,/etc/V2bX/config.json.bak,/usr/local/V2bX/config.json,/usr/local/V2bX/config.json.bak,/etc/xboard-node/config.yml,/etc/xboard-node/config.yaml,/usr/local/etc/bby-agent.yml,/opt/xboard-node/config.yml,/app/config/config.yml,/etc/soga/soga.conf,/etc/soga/config.yml",
    )
    return sorted(
        {
            posixpath.normpath(item.strip())
            for item in raw.split(",")
            if re.fullmatch(r"/[A-Za-z0-9_./-]+", item.strip())
        }
    )


def _incus_host_namespace_kill(
    runtime_bin: str,
    container_name: str,
    project: str,
    patterns: List[str],
    process_pids: List[int] | None = None,
) -> Tuple[int, int, int, str]:
    """Kill exact allowlisted process identities with host user-namespace privileges.

    Some unprivileged Incus/OpenRC containers expose UID 0 inside ``incus exec``
    but deny signals to older processes that retain a different kernel uid map.
    Host root enters only the target container PID/mount namespaces and rechecks
    the exact process identity before signalling it.
    """
    init_pid = _incus_instance_pid(runtime_bin, container_name, project)
    if init_pid <= 1 or not shutil.which("nsenter") or not patterns:
        return 0, 0, 0, "host namespace fallback unavailable"
    safe_patterns = " ".join(shlex.quote(item) for item in patterns)
    script = (
        "set -f; matched=0; killed=0; errors=0; "
        f"for pattern in {safe_patterns}; do "
        "for proc in /proc/[0-9]*; do pid=${proc##*/}; "
        "[ \"$pid\" = 1 ] && continue; [ \"$pid\" = \"$$\" ] && continue; "
        "state=$(awk '{print $3}' \"$proc/stat\" 2>/dev/null || true); [ \"$state\" = Z ] && continue; "
        "comm=$(cat \"$proc/comm\" 2>/dev/null || true); "
        "argv0=$(tr '\\000' '\\n' < \"$proc/cmdline\" 2>/dev/null | head -n 1); "
        "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); found=0; "
        "extra_candidates=''; lower_comm=$(printf '%s' \"$comm\" | tr '[:upper:]' '[:lower:]'); "
        "case \"$lower_comm\" in supervise-daemo|supervise-daemon) "
        "extra_candidates=$(tr '\\000' '\\n' < \"$proc/cmdline\" 2>/dev/null | sed 's#.*/##');; esac; "
        "for candidate in \"$comm\" \"${argv0##*/}\" \"${exe##*/}\" $extra_candidates; do "
        "candidate=$(printf '%s' \"$candidate\" | tr '[:upper:]' '[:lower:]'); "
        "[ \"$candidate\" = \"$pattern\" ] && found=1; done; "
        "[ \"$found\" -eq 1 ] || continue; "
        "matched=$((matched+1)); "
        "if kill -TERM \"$pid\" 2>/dev/null; then killed=$((killed+1)); "
        "sleep 1; [ -d \"$proc\" ] && kill -KILL \"$pid\" 2>/dev/null || true; "
        "else errors=$((errors+1)); fi; done; done; "
        "printf 'host_matched_processes=%s host_killed_processes=%s host_kill_errors=%s\\n' "
        '"$matched" "$killed" "$errors"; [ "$errors" -eq 0 ]'
    )
    ok, output = _run_action_command(
        ["nsenter", "-t", str(init_pid), "-p", "-m", "--", "/bin/sh", "-lc", script]
    )
    values = {
        key: int(value)
        for key, value in re.findall(
            r"\b(host_matched_processes|host_killed_processes|host_kill_errors)=(\d+)\b",
            output or "",
        )
    }
    errors = values.get("host_kill_errors", 0)
    if not ok and not values:
        errors = 1
    return (
        values.get("host_matched_processes", 0),
        values.get("host_killed_processes", 0),
        errors,
        output,
    )


def stop_unauthenticated_socks(action: Dict) -> Tuple[bool, str]:
    """Stop only the allowlisted SOCKS process/service inside one container."""
    runtime_kind = str(action.get("runtime") or "").strip().lower()
    container_name = str(action.get("container_name") or "").strip()
    project = str(action.get("project") or "").strip()
    if runtime_kind not in ("podman", "incus"):
        return False, "Docker and unknown runtimes are notice-only"
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name):
        return False, "invalid container target"
    if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
        return False, "invalid Incus project"
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    if str(params.get("auth_mode") or "") != "no_auth":
        return False, "SOCKS stop requires confirmed no-auth evidence"
    requested_names = params.get("process_names") if isinstance(params.get("process_names"), list) else []
    process_names = sorted(
        {
            str(item).strip().lower()
            for item in requested_names
            if isinstance(item, str) and str(item).strip().lower() in _SOCKS_PROCESS_NAMES
        }
    )
    requested_pids = params.get("process_pids") if isinstance(params.get("process_pids"), list) else []
    process_pids = sorted(
        {
            int(item)
            for item in requested_pids
            if isinstance(item, int) and 1 < item <= 4194304
        }
    )
    if not process_names:
        return False, "no locally approved SOCKS process target"
    runtime_bin = get_runtime_bins().get(runtime_kind, "")
    if not runtime_bin:
        return False, f"runtime {runtime_kind} is unavailable"

    names = " ".join(shlex.quote(item) for item in process_names)
    pids = " ".join(str(item) for item in process_pids)
    script = (
        "set -u; stopped_services=0; killed_processes=0; stop_errors=0; targets=''; "
        f"requested_pids={shlex.quote((' ' + pids + ' ') if pids else '')}; "
        f"for pattern in {names}; do "
        "for proc in /proc/[0-9]*; do pid=${proc##*/}; [ \"$pid\" = \"$$\" ] && continue; "
        "state=$(awk '{print $3}' \"$proc/stat\" 2>/dev/null || true); [ \"$state\" = Z ] && continue; "
        "comm=$(cat \"$proc/comm\" 2>/dev/null || true); "
        "argv0=$(tr '\\000' '\\n' < \"$proc/cmdline\" 2>/dev/null | head -n 1); "
        "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); matched=0; "
        "for candidate in \"$comm\" \"${argv0##*/}\" \"${exe##*/}\"; do "
        "candidate=$(printf '%s' \"$candidate\" | tr '[:upper:]' '[:lower:]'); "
        "[ \"$candidate\" = \"$pattern\" ] && matched=1; done; "
        "if [ \"$matched\" -eq 1 ]; then if [ -n \"$requested_pids\" ]; then "
        "case \"$requested_pids\" in *\" $pid \"*) targets=\"$targets $pid\";; esac; "
        "else targets=\"$targets $pid\"; fi; fi; done; "
        "if [ -z \"$requested_pids\" ]; then command -v systemctl >/dev/null 2>&1 && "
        "systemctl stop \"${pattern}.service\" >/dev/null 2>&1 && stopped_services=$((stopped_services+1)) || true; "
        "if [ -x \"/etc/init.d/$pattern\" ]; then \"/etc/init.d/$pattern\" stop >/dev/null 2>&1 && "
        "stopped_services=$((stopped_services+1)) || true; fi; fi; done; "
        "for pid in $targets; do [ -r \"/proc/$pid/stat\" ] || continue; "
        "unit=$(sed -n 's#.*[/]\\([^/]*\\.service\\)$#\\1#p' \"/proc/$pid/cgroup\" 2>/dev/null | head -n 1); "
        "case \"$unit\" in *.service) case \"$unit\" in *[!A-Za-z0-9_.@:-]*) ;; *) "
        "command -v systemctl >/dev/null 2>&1 && systemctl stop \"$unit\" >/dev/null 2>&1 && "
        "stopped_services=$((stopped_services+1)) || true;; esac;; esac; "
        "if kill -TERM \"$pid\" 2>/dev/null; then killed_processes=$((killed_processes+1)); "
        "sleep 1; [ -d \"/proc/$pid\" ] && kill -KILL \"$pid\" 2>/dev/null || true; fi; done; "
        "printf 'stopped_services=%s killed_processes=%s stop_errors=%s\\n' "
        "\"$stopped_services\" \"$killed_processes\" \"$stop_errors\"; [ \"$stop_errors\" -eq 0 ]"
    )
    ok, output = _run_action_command(
        _runtime_exec_cmd(runtime_bin, container_name, script, project)
    )
    counts = {
        key: int(value)
        for key, value in re.findall(
            r"\b(stopped_services|killed_processes|stop_errors)=(\d+)\b", output or ""
        )
    }
    if runtime_kind == "incus":
        container_stop_ok = ok
        _, host_killed, host_errors, host_output = _incus_host_namespace_kill(
            runtime_bin, container_name, project, process_names, process_pids
        )
        counts["killed_processes"] = counts.get("killed_processes", 0) + host_killed
        counts["stop_errors"] = counts.get("stop_errors", 0) + host_errors
        output = (
            f"stopped_services={counts.get('stopped_services', 0)} "
            f"killed_processes={counts.get('killed_processes', 0)} "
            f"stop_errors={counts.get('stop_errors', 0)}; {host_output}"
        )
        ok = counts.get("stop_errors", 0) == 0 and (
            container_stop_ok or host_killed > 0
        )
    return ok, output or ("SOCKS service stopped" if ok else "SOCKS stop command failed")


def enforce_socks_auth_policy(
    container: Dict[str, object], entries: List[Dict[str, object]] | None = None
) -> Dict[str, object] | None:
    """Apply an operator-approved no-auth policy using this cycle's existing evidence."""
    policy = _socks_auth_enforcement_for_container(container, entries)
    if policy is None:
        return None
    security = container.get("security") if isinstance(container.get("security"), dict) else {}
    socks_proxy = security.get("socks_proxy") if isinstance(security.get("socks_proxy"), dict) else {}
    auth_mode = str(socks_proxy.get("auth_mode") or "unknown")
    if auth_mode in ("configured", "weak_password"):
        released = remove_socks_auth_enforcement(
            str(container.get("runtime") or ""),
            str(container.get("project") or ""),
            str(container.get("name") or ""),
        )
        result = {
            "active": False,
            "released": released,
            "reason": "non_empty_auth_detected",
        }
        socks_proxy["auth_enforcement"] = result
        return result
    if not socks_proxy.get("detected") or auth_mode != "no_auth":
        result = {"active": True, "attempted": False, "reason": "awaiting_auth_evidence"}
        socks_proxy["auth_enforcement"] = result
        return result
    current_names = {
        str(item.get("process") or "").strip().lower()
        for item in socks_proxy.get("process_matches", [])
        if isinstance(item, dict)
        and str(item.get("process") or "").strip().lower() in _SOCKS_PROCESS_NAMES
        and str(item.get("auth_state") or "no_auth") == "no_auth"
    }
    approved_names = sorted(set(policy.get("process_names", [])) & current_names)
    if not approved_names:
        result = {"active": True, "attempted": False, "reason": "process_identity_changed"}
        socks_proxy["auth_enforcement"] = result
        return result
    process_pids = [
        int(item.get("pid") or 0)
        for item in socks_proxy.get("process_matches", [])
        if isinstance(item, dict)
        and str(item.get("process") or "").strip().lower() in approved_names
        and str(item.get("auth_state") or "no_auth") == "no_auth"
        and int(item.get("pid") or 0) > 1
    ]
    ok, message = stop_unauthenticated_socks(
        {
            "runtime": container.get("runtime"),
            "project": container.get("project"),
            "container_name": container.get("name"),
            "params": {
                "auth_mode": "no_auth",
                "process_names": approved_names,
                "process_pids": process_pids,
            },
        }
    )
    result = {"active": True, "attempted": True, "succeeded": ok, "message": message[:500]}
    socks_proxy["auth_enforcement"] = result
    print(
        f"automatic no-auth SOCKS stop {'succeeded' if ok else 'failed'} for "
        f"{container.get('runtime')}/{container.get('name')}: {message}"
    )
    return result


def remediate_malicious_process(action: Dict) -> Tuple[bool, str]:
    """Remove an exact allowlisted malware process without stopping its container."""
    runtime_kind = str(action.get("runtime") or "").strip().lower()
    container_name = str(action.get("container_name") or "").strip()
    project = str(action.get("project") or "").strip()
    if runtime_kind not in ("podman", "incus"):
        return False, "Docker and unknown runtimes are notice-only"
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name):
        return False, "invalid container target"
    if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
        return False, "invalid Incus project"
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    requested_names = params.get("process_names") if isinstance(params.get("process_names"), list) else []
    process_names = sorted(
        {
            str(item).strip().lower()
            for item in requested_names
            if isinstance(item, str)
            and str(item).strip().lower() in _AUTO_REMEDIATE_MALWARE_NAMES
        }
    )
    if not process_names:
        return False, "no exact allowlisted malware target"
    runtime_bin = get_runtime_bins().get(runtime_kind, "")
    if not runtime_bin:
        return False, f"runtime {runtime_kind} is unavailable"

    names = " ".join(shlex.quote(item) for item in process_names)
    config_paths = " ".join(
        shlex.quote(path)
        for path in (
            "/etc/xmrig.json",
            "/etc/xmrig/config.json",
            "/usr/local/etc/xmrig.json",
            "/opt/xmrig/config.json",
            "/root/.xmrig.json",
        )
    )
    binary_paths = " ".join(
        shlex.quote(path)
        for path in (
            "/usr/bin/xmrig",
            "/usr/local/bin/xmrig",
            "/opt/xmrig/xmrig",
            "/tmp/xmrig",
            "/var/tmp/xmrig",
        )
    )
    script = (
        "set -u; killed_processes=0; removed_services=0; removed_configs=0; "
        "removed_binaries=0; cleanup_errors=0; "
        f"for pattern in {names}; do "
        "command -v systemctl >/dev/null 2>&1 && systemctl disable --now \"${pattern}.service\" >/dev/null 2>&1 || true; "
        "for unit_dir in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do "
        "unit=\"$unit_dir/${pattern}.service\"; [ -e \"$unit\" ] || [ -L \"$unit\" ] || continue; "
        "if rm -f -- \"$unit\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; done; "
        "if [ -e \"/etc/init.d/$pattern\" ]; then \"/etc/init.d/$pattern\" stop >/dev/null 2>&1 || true; "
        "if rm -f -- \"/etc/init.d/$pattern\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; fi; "
        "for proc in /proc/[0-9]*; do pid=${proc##*/}; [ \"$pid\" = \"$$\" ] && continue; "
        "state=$(awk '{print $3}' \"$proc/stat\" 2>/dev/null || true); [ \"$state\" = Z ] && continue; "
        "comm=$(cat \"$proc/comm\" 2>/dev/null || true); argv0=$(tr '\\000' '\\n' < \"$proc/cmdline\" 2>/dev/null | head -n 1); "
        "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); matched=0; "
        "for candidate in \"$comm\" \"${argv0##*/}\" \"${exe##*/}\"; do "
        "candidate=$(printf '%s' \"$candidate\" | tr '[:upper:]' '[:lower:]'); [ \"$candidate\" = \"$pattern\" ] && matched=1; done; "
        "if [ \"$matched\" -eq 1 ]; then if kill -TERM \"$pid\" 2>/dev/null; then killed_processes=$((killed_processes+1)); "
        "sleep 1; [ -d \"$proc\" ] && kill -KILL \"$pid\" 2>/dev/null || true; fi; fi; done; done; "
        f"for path in {config_paths}; do [ -e \"$path\" ] || [ -L \"$path\" ] || continue; "
        "if rm -f -- \"$path\"; then removed_configs=$((removed_configs+1)); else cleanup_errors=$((cleanup_errors+1)); fi; done; "
        f"for path in {binary_paths}; do [ -e \"$path\" ] || [ -L \"$path\" ] || continue; "
        "if rm -f -- \"$path\"; then removed_binaries=$((removed_binaries+1)); else cleanup_errors=$((cleanup_errors+1)); fi; done; "
        "command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true; "
        "printf 'killed_processes=%s removed_services=%s removed_configs=%s removed_binaries=%s cleanup_errors=%s\\n' "
        "\"$killed_processes\" \"$removed_services\" \"$removed_configs\" \"$removed_binaries\" \"$cleanup_errors\"; "
        "changes=$((killed_processes+removed_services+removed_configs+removed_binaries)); "
        "[ \"$cleanup_errors\" -eq 0 ] && [ \"$changes\" -gt 0 ]"
    )
    ok, output = _run_action_command(
        _runtime_exec_cmd(runtime_bin, container_name, script, project)
    )
    counts = {
        key: int(value)
        for key, value in re.findall(
            r"\b(killed_processes|removed_services|removed_configs|removed_binaries|cleanup_errors)=(\d+)\b",
            output or "",
        )
    }
    if runtime_kind == "incus":
        _, host_killed, host_errors, host_output = _incus_host_namespace_kill(
            runtime_bin, container_name, project, process_names
        )
        counts["killed_processes"] = counts.get("killed_processes", 0) + host_killed
        counts["cleanup_errors"] = counts.get("cleanup_errors", 0) + host_errors
        changes = sum(
            counts.get(key, 0)
            for key in (
                "killed_processes",
                "removed_services",
                "removed_configs",
                "removed_binaries",
            )
        )
        output = (
            f"killed_processes={counts.get('killed_processes', 0)} "
            f"removed_services={counts.get('removed_services', 0)} "
            f"removed_configs={counts.get('removed_configs', 0)} "
            f"removed_binaries={counts.get('removed_binaries', 0)} "
            f"cleanup_errors={counts.get('cleanup_errors', 0)}; {host_output}"
        )
        ok = counts.get("cleanup_errors", 0) == 0 and changes > 0
    return ok, output or ("malware remediation completed" if ok else "malware remediation failed")


def remediate_panel_pairing(action: Dict) -> Tuple[bool, str]:
    runtime_kind = str(action.get("runtime") or "").lower()
    if runtime_kind not in ("podman", "incus"):
        return False, "Docker and unknown runtimes are notice-only"
    container_name = str(action.get("container_name") or "")
    project = str(action.get("project") or "")
    if not container_name or not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name):
        return False, "invalid container target"
    if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
        return False, "invalid Incus project"
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    requested_patterns = params.get("process_patterns") if isinstance(params.get("process_patterns"), list) else []
    requested_pids = params.get("process_pids") if isinstance(params.get("process_pids"), list) else []
    requested_files = params.get("config_files") if isinstance(params.get("config_files"), list) else []
    allowed_patterns = set(_configured_panel_process_patterns())
    patterns = sorted(
        {
            str(item).strip().lower()
            for item in requested_patterns
            if isinstance(item, str) and str(item).strip().lower() in allowed_patterns
        }
    )
    process_pids = sorted(
        {
            int(item)
            for item in requested_pids
            if isinstance(item, int) and 1 < item <= 4194304
        }
    )
    allowed_files = set(_configured_panel_config_paths())
    config_files = sorted(
        {
            posixpath.normpath(str(item).strip())
            for item in requested_files
            if isinstance(item, str) and posixpath.normpath(str(item).strip()) in allowed_files
        }
    )
    if not patterns and not config_files:
        return False, "no locally approved remediation targets"

    script_parts = [
        "set -u",
        "removed_services=0",
        "removed_configs=0",
        "killed_processes=0",
        "cleanup_errors=0",
    ]
    for pattern in patterns:
        quoted_pattern = shlex.quote(pattern)
        # 彻底移除托管该进程的服务，避免 kill 后由服务管理器自动重启。
        # 匹配方式：① systemd 单元文件名包含特征串（递归，含 .wants 软链）；
        # ② 单元 ExecStart* 引用了特征串；③ init.d / OpenRC；④ supervisor；⑤ cron。
        script_parts.append(
            "_pat=" + quoted_pattern + ";\n"
            "rem_unit() { "
            "u=\"$1\"; [ -e \"$u\" ] || [ -L \"$u\" ] || return 0; "
            "un=${u##*/}; "
            "command -v systemctl >/dev/null 2>&1 && systemctl disable --now \"$un\" >/dev/null 2>&1 || true; "
            "real=$(readlink -f \"$u\" 2>/dev/null || echo \"$u\"); "
            "for t in \"$u\" \"$real\"; do "
            "[ -e \"$t\" ] || [ -L \"$t\" ] || continue; "
            "if rm -f -- \"$t\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; "
            "done; "
            "};\n"
            "for ud in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system; do "
            "[ -d \"$ud\" ] || continue; "
            "for u in $(find \"$ud\" \\( -type f -o -type l \\) \\( -iname \"*${_pat}*.service\" -o -iname \"*${_pat}*.timer\" -o -iname \"*${_pat}*.socket\" -o -iname \"*${_pat}*.path\" \\) 2>/dev/null); do rem_unit \"$u\"; done; "
            "for u in $(grep -rIl --include='*.service' --include='*.timer' --include='*.socket' \"${_pat}\" \"$ud\" 2>/dev/null); do "
            "if grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost)=' \"$u\" 2>/dev/null | grep -Fqi -- \"${_pat}\"; then rem_unit \"$u\"; fi; "
            "done; "
            "done; "
            "for f in $(find /etc/init.d -maxdepth 2 \\( -type f -o -type l \\) 2>/dev/null); do "
            "if printf '%s' \"${f##*/}\" | grep -Fiq -- \"${_pat}\" || grep -Fiq -- \"${_pat}\" \"$f\" 2>/dev/null; then "
            "svc=${f##*/}; "
            "command -v rc-service >/dev/null 2>&1 && rc-service \"$svc\" stop >/dev/null 2>&1 || \"$f\" stop >/dev/null 2>&1 || true; "
            "command -v rc-update >/dev/null 2>&1 && rc-update del \"$svc\" >/dev/null 2>&1 || true; "
            "if rm -f -- \"$f\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; "
            "fi; done; "
            "command -v rc-update >/dev/null 2>&1 && rc-update del \"${_pat}\" >/dev/null 2>&1 || true; "
            "for sc in $(grep -rIl --include='*.conf' \"${_pat}\" /etc/supervisor 2>/dev/null); do "
            "if rm -f -- \"$sc\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; done; "
            "command -v supervisorctl >/dev/null 2>&1 && supervisorctl reread >/dev/null 2>&1 && supervisorctl update >/dev/null 2>&1 || true; "
            "for cf in $(grep -rIl \"${_pat}\" /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron 2>/dev/null); do "
            "grep -vF \"${_pat}\" \"$cf\" > \"$cf.tmp\" 2>/dev/null && mv -f \"$cf.tmp\" \"$cf\" || true; done"
        )
        # PID evidence can become stale while a supervisor respawns the child.
        # Re-resolve the exact allowlisted identity and derive OpenRC/systemd
        # aliases from cgroups before signalling the current process.
        script_parts.append(
            "for proc in /proc/[0-9]*; do "
            "pid=${proc##*/}; [ \"$pid\" = \"$$\" ] && continue; "
            "state=$(awk '{print $3}' \"$proc/stat\" 2>/dev/null || true); [ \"$state\" = Z ] && continue; "
            "comm=$(cat \"$proc/comm\" 2>/dev/null || true); "
            "argv0=$(tr '\\000' '\\n' < \"$proc/cmdline\" 2>/dev/null | head -n 1); "
            "exe=$(readlink \"$proc/exe\" 2>/dev/null || true); matched=0; "
            "for candidate in \"$comm\" \"${argv0##*/}\" \"${exe##*/}\"; do "
            f"[ \"$(printf '%s' \"$candidate\" | tr '[:upper:]' '[:lower:]')\" = {quoted_pattern} ] && matched=1; done; "
            "[ \"$matched\" -eq 1 ] || continue; "
            "svc=$(sed -n 's#.*[/]openrc\\.\\([^/]*\\)$#\\1#p' \"$proc/cgroup\" 2>/dev/null | head -n 1); "
            "case \"$svc\" in ''|*[!A-Za-z0-9_.@:-]*) ;; *) "
            "command -v rc-service >/dev/null 2>&1 && rc-service \"$svc\" stop >/dev/null 2>&1 || true; "
            "command -v rc-update >/dev/null 2>&1 && rc-update del \"$svc\" >/dev/null 2>&1 || true; "
            "sf=\"/etc/init.d/$svc\"; if [ -e \"$sf\" ] || [ -L \"$sf\" ]; then "
            "if rm -f -- \"$sf\"; then removed_services=$((removed_services+1)); else cleanup_errors=$((cleanup_errors+1)); fi; fi;; esac; "
            "unit=$(sed -n 's#.*[/]\\([^/]*\\.service\\)$#\\1#p' \"$proc/cgroup\" 2>/dev/null | head -n 1); "
            "case \"$unit\" in ''|*[!A-Za-z0-9_.@:-]*) ;; *.service) "
            "command -v systemctl >/dev/null 2>&1 && systemctl disable --now \"$unit\" >/dev/null 2>&1 || true;; esac; "
            "if kill -TERM \"$pid\" 2>/dev/null; then killed_processes=$((killed_processes+1)); "
            "sleep 1; [ -d \"$proc\" ] && kill -KILL \"$pid\" 2>/dev/null || true; fi; done"
        )
    for config_file in config_files:
        quoted_file = shlex.quote(config_file)
        script_parts.append(
            f"if [ -f {quoted_file} ] || [ -L {quoted_file} ]; then "
            f"if rm -f -- {quoted_file}; then removed_configs=$((removed_configs+1)); "
            "else cleanup_errors=$((cleanup_errors+1)); fi; fi"
        )
    script_parts.extend(
        [
            "command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true",
            "printf 'killed_processes=%s removed_services=%s removed_configs=%s cleanup_errors=%s\\n' \"$killed_processes\" \"$removed_services\" \"$removed_configs\" \"$cleanup_errors\"",
            "changes=$((killed_processes+removed_services+removed_configs))",
            "[ \"$cleanup_errors\" -eq 0 ] && [ \"$changes\" -gt 0 ]",
        ]
    )
    runtime_bin = get_runtime_bins().get(runtime_kind, "")
    if not runtime_bin:
        return False, f"runtime {runtime_kind} is unavailable"
    command = _runtime_exec_cmd(runtime_bin, container_name, "; ".join(script_parts), project)
    ok, output = _run_action_command(command)
    counts = {
        key: int(value)
        for key, value in re.findall(
            r"\b(killed_processes|removed_services|removed_configs|cleanup_errors)=(\d+)\b",
            output or "",
        )
    }
    if runtime_kind == "incus" and patterns:
        _, host_killed, host_errors, host_output = _incus_host_namespace_kill(
            runtime_bin, container_name, project, patterns, process_pids
        )
        if host_killed or host_errors:
            counts["killed_processes"] = counts.get("killed_processes", 0) + host_killed
            counts["cleanup_errors"] = counts.get("cleanup_errors", 0) + host_errors
            output = (
                f"killed_processes={counts.get('killed_processes', 0)} "
                f"removed_services={counts.get('removed_services', 0)} "
                f"removed_configs={counts.get('removed_configs', 0)} "
                f"cleanup_errors={counts.get('cleanup_errors', 0)}; {host_output}"
            )
            changes = sum(counts.get(key, 0) for key in ("killed_processes", "removed_services", "removed_configs"))
            ok = counts.get("cleanup_errors", 0) == 0 and changes > 0
    return ok, output or ("remediation completed" if ok else "remediation command failed")


def execute_security_action(action: Dict) -> Tuple[bool, str]:
    action_type = str(action.get("action_type") or "")
    if action_type == "release_socks_auth":
        runtime_kind = str(action.get("runtime") or "").strip().lower()
        project = str(action.get("project") or "").strip()
        container_name = str(action.get("container_name") or "").strip()
        if runtime_kind not in ("incus", "podman"):
            return False, "Docker and unknown runtimes are notice-only"
        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name):
            return False, "invalid container target"
        if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
            return False, "invalid Incus project"
        try:
            removed = remove_socks_auth_enforcement(
                runtime_kind, project, container_name
            )
        except (OSError, ValueError) as exc:
            return False, f"SOCKS enforcement policy removal failed: {exc}"
        return True, f"policy_removed={1 if removed else 0}; SOCKS service is allowed to recover"
    if action_type == "enforce_socks_auth":
        runtime_kind = str(action.get("runtime") or "").strip().lower()
        project = str(action.get("project") or "").strip()
        container_name = str(action.get("container_name") or "").strip()
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        process_names = params.get("process_names") if isinstance(params.get("process_names"), list) else []
        if str(params.get("auth_mode") or "") != "no_auth":
            return False, "SOCKS enforcement requires confirmed no-auth evidence"
        try:
            set_socks_auth_enforcement(runtime_kind, project, container_name, process_names)
        except (OSError, ValueError) as exc:
            return False, f"SOCKS enforcement policy update failed: {exc}"
        ok, message = stop_unauthenticated_socks(action)
        prefix = "policy_installed=1; "
        return ok, prefix + message
    if action_type == "remediate_malicious_process":
        return remediate_malicious_process(action)
    if action_type == "stop_container":
        runtime_kind = str(action.get("runtime") or "").strip().lower()
        container_name = str(action.get("container_name") or "").strip()
        project = str(action.get("project") or "").strip()
        if runtime_kind not in ("podman", "docker", "incus"):
            return False, "unsupported runtime for automatic stop"
        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,200}", container_name):
            return False, "invalid container target"
        if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
            return False, "invalid Incus project"
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        if str(params.get("reason") or "") != "sustained_connection_overload":
            return False, "automatic stop reason is missing or invalid"
        runtime_bin = get_runtime_bins().get(runtime_kind, "")
        if not runtime_bin:
            return False, f"runtime {runtime_kind} is unavailable"
        command = _runtime_base(runtime_bin, project) + ["stop", container_name]
        ok, message = _run_action_command(command)
        if ok:
            count = int(params.get("connection_count") or 0)
            duration = int(params.get("duration_seconds") or 0)
            return True, (
                message
                or f"stopped after {count} connections remained above the limit for {duration} seconds"
            )
        return False, message or "container stop command failed"
    if action_type == "allow_panel_domains":
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        domains = params.get("domains") if isinstance(params.get("domains"), list) else []
        try:
            remove_auto_remediate_panel_domains(domains)
            merged = add_allowed_panel_domains(domains)
        except (OSError, ValueError) as exc:
            return False, f"allowlist update failed: {exc}"
        return True, f"allowed {len(domains)} exact domain(s); allowlist now contains {len(merged)}"
    if action_type == "disallow_panel_domains":
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        domains = params.get("domains") if isinstance(params.get("domains"), list) else []
        try:
            remaining = remove_allowed_panel_domains(domains)
        except (OSError, ValueError) as exc:
            return False, f"allowlist removal failed: {exc}"
        return True, (
            f"removed {len(domains)} exact domain(s) from the node allowlist; "
            f"allowlist now contains {len(remaining)}"
        )
    if action_type == "remediate_panel_pairing":
        ok, message = remediate_panel_pairing(action)
        if not ok:
            return ok, message
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        domains = params.get("domains") if isinstance(params.get("domains"), list) else []
        try:
            remove_allowed_panel_domains(domains)
            add_auto_remediate_panel_domains(domains)
        except (OSError, ValueError) as exc:
            return False, f"remediation completed but automatic policy update failed: {exc}"
        if domains:
            message = f"{message}; remembered {len(domains)} domain(s) for silent automatic remediation"
        return True, message
    return False, "unsupported action type"


def _schedule_deep_sample(action: Dict) -> Tuple[bool, str]:
    action_id = int(action.get("id") or 0)
    runtime = str(action.get("runtime") or "").strip().lower()
    container_name = str(action.get("container_name") or "").strip()
    if action_id <= 0 or not container_name:
        return False, "invalid deep sample request"
    if runtime not in ("incus", "podman"):
        return False, "deep sampling is limited to Incus and Podman containers"
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    try:
        normalized_params = {
            "sample_seconds": max(0.5, min(2.0, float(params.get("sample_seconds") or 1.0))),
            "process_limit": max(20, min(200, int(params.get("process_limit") or 100))),
            "socket_limit": max(50, min(500, int(params.get("socket_limit") or 250))),
        }
    except (TypeError, ValueError):
        return False, "invalid deep sample limits"
    scheduled = dict(action)
    scheduled["params"] = normalized_params
    _pending_deep_samples[action_id] = scheduled
    return True, "scheduled for the next report cycle"


def _pending_deep_sample_for(container: Dict[str, object]) -> Dict[str, object] | None:
    runtime = str(container.get("runtime") or "")
    project = str(container.get("project") or "")
    name = str(container.get("name") or "")
    return next(
        (
            action
            for action in _pending_deep_samples.values()
            if str(action.get("runtime") or "") == runtime
            and str(action.get("project") or "") == project
            and str(action.get("container_name") or "") == name
        ),
        None,
    )


def process_security_actions(server: str, secret: str, host_id: str) -> bool:
    response = signed_post_json(server, secret, "/api/v1/actions/poll", {"host_id": host_id})
    actions = response.get("actions") if isinstance(response.get("actions"), list) else []
    changed = False
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_id = int(action.get("id") or 0)
        if str(action.get("action_type") or "") == "request_deep_sample":
            ok, message = _schedule_deep_sample(action)
            if ok:
                print(f"diagnostic action {action_id} accepted: {message}")
                changed = True
                continue
        else:
            ok, message = execute_security_action(action)
        signed_post_json(
            server,
            secret,
            "/api/v1/actions/result",
            {
                "action_id": action_id,
                "host_id": host_id,
                "status": "succeeded" if ok else "failed",
                "message": message,
            },
        )
        print(f"security action {action_id} {'succeeded' if ok else 'failed'}: {message}")
        changed = changed or ok
    return changed


def push(server: str, secret: str, payload: Dict) -> None:
    server = normalize_server_url(server)
    body = json.dumps(payload, ensure_ascii=False).encode()
    ts = int(time.time())
    sig = sign(body, secret, ts)
    r = requests.post(
        f"{server.rstrip('/')}/api/v1/report",
        data=body,
        headers={"Content-Type": "application/json", "X-Timestamp": str(ts), "X-Signature": sig},
        timeout=15,
        verify=server_tls_verify(),
    )
    r.raise_for_status()


def main() -> None:
    global _security_last_sample_ts
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "https://127.0.0.1:8080"))
    parser.add_argument("--secret", default=os.getenv("SHARED_SECRET", "change-me"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("REPORT_INTERVAL", "300")))
    parser.add_argument("--host-id", default=os.getenv("HOST_ID", socket.gethostname()))
    args = parser.parse_args()

    while True:
        containers = list_containers()
        docker_mode = _docker_monitor_mode()
        monitored_containers = [
            item for item in containers if item.get("runtime") != "docker" or docker_mode == "full"
        ]
        v4, v6 = network_health(monitored_containers) if monitored_containers else (True, True)
        sample_now = float(time.time())
        security_interval = sample_now - _security_last_sample_ts if _security_last_sample_ts > 0 else float(max(60, args.interval))
        _security_last_sample_ts = sample_now
        security_enabled = os.getenv("SECURITY_MONITOR_ENABLED", "true").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        incus_metrics_by_runtime: Dict[str, Dict[Tuple[str, str], Dict[str, float]]] = {}
        for item in containers:
            if item.get("runtime") != "incus":
                continue
            runtime_bin = str(item.get("runtime_bin") or "incus")
            if runtime_bin not in incus_metrics_by_runtime:
                incus_metrics_by_runtime[runtime_bin] = _get_incus_metrics(runtime_bin)
        host_conntrack = _collect_host_conntrack_snapshot() if security_enabled else {}
        if security_enabled:
            _augment_conntrack_with_host_proxy_sockets(host_conntrack, containers)
        collected = []
        included_deep_sample_ids: List[int] = []
        for c in containers:
            if c.get("runtime") == "docker" and docker_mode == "notice":
                collected.append(collect_docker_notice(c))
                continue
            try:
                pid_hint = int(c.get("pid", "") or 0)
            except ValueError:
                pid_hint = 0
            container_report = collect_container(
                    c["name"],
                    c.get("id", ""),
                    c.get("runtime_bin", ""),
                    c.get("runtime", ""),
                    c.get("project", ""),
                    pid_hint,
                    c.get("security_risks") if isinstance(c.get("security_risks"), list) else None,
                    c.get("network_exposure") if isinstance(c.get("network_exposure"), list) else None,
                    c.get("image", ""),
                    incus_metrics_by_runtime.get(str(c.get("runtime_bin") or "incus"))
                    if c.get("runtime") == "incus"
                    else None,
                    c.get("network_addresses") if isinstance(c.get("network_addresses"), list) else None,
                    host_conntrack,
                )
            container_security = container_report.get("security")
            if security_enabled and isinstance(container_security, dict):
                container_security["access_log"] = _collect_container_access_log_stats(c, security_interval)
            pending_deep_sample = _pending_deep_sample_for(c)
            if pending_deep_sample is not None:
                try:
                    container_report["deep_sample"] = collect_container_deep_sample(
                        c["name"],
                        str(c.get("runtime_bin") or ""),
                        str(c.get("runtime") or ""),
                        str(c.get("project") or ""),
                        pid_hint,
                        pending_deep_sample,
                        container_report,
                    )
                    included_deep_sample_ids.append(int(pending_deep_sample.get("id") or 0))
                except Exception as deep_error:
                    print(f"deep sample failed for {c.get('name')}: {deep_error}")
            collected.append(container_report)
        security = collect_security_summary(collected, security_interval)
        payload = {
            "host_id": args.host_id,
            "agent_version": APP_VERSION,
            "timestamp": int(time.time()),
            "container_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "podman_network": {"ipv4_ok": v4, "ipv6_ok": v6},
            "containers": collected,
            "security": security,
        }
        try:
            push(args.server, args.secret, payload)
            for action_id in included_deep_sample_ids:
                _pending_deep_samples.pop(action_id, None)
            print(f"reported {len(containers)} containers and {len(security.get('alerts', []))} security alerts to {args.server}")
        except Exception as e:
            print(f"report failed: {e}")
        report_delay = max(60, args.interval)
        try:
            action_poll_interval = max(5, int(os.getenv("ACTION_POLL_INTERVAL", "10")))
        except ValueError:
            action_poll_interval = 10
        deadline = time.monotonic() + report_delay
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(action_poll_interval, remaining))
            try:
                if process_security_actions(args.server, args.secret, args.host_id):
                    break
            except Exception as action_error:
                print(f"security action poll failed: {action_error}")


if __name__ == "__main__":
    main()
