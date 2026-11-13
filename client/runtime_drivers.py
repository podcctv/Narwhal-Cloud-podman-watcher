"""Container runtime drivers (Podman, Incus, Docker, Runman) and cgroup/metric sampling."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

try:
    from client import cpu_guard, incus_health, network_quarantine, resource_cgroup, security_banner
    from client.incus_metrics import parse_incus_metrics as _parse_incus_metrics
except ImportError:
    import cpu_guard
    import incus_health
    import network_quarantine
    import resource_cgroup
    import security_banner
    from incus_metrics import parse_incus_metrics as _parse_incus_metrics

for _guard_name in ("container_freeze", "udp_guard", "anti_spoof_guard", "file_guard", "microburst_guard"):
    try:
        globals()[_guard_name] = __import__(f"client.{_guard_name}", fromlist=[_guard_name])
    except ImportError:
        try:
            globals()[_guard_name] = __import__(_guard_name)
        except ImportError:
            globals()[_guard_name] = None

_AGENT_NAMESPACES: List[Dict[str, Any]] = []

_warned_missing_bins = set()
_warned_timeout_commands = set()
_unresponsive_exec_containers = set()
_podman_bin = None
_container_bin = None
_runtime_bins = None
_RUNMAN_EXEC_SENTINEL = "__narwhal_runman_exec__"
_runman_instance_generations: Dict[str, str] = {}
_net_counters: Dict[str, Dict[str, float]] = {}
_cpu_counters: Dict[str, Dict[str, float]] = {}
_incus_metrics_cache: Dict[str, object] = {"ts": 0.0, "text": "", "parsed": {}}
_incus_forward_cache: Dict[str, Dict[str, object]] = {}
_packet_counters: Dict[str, Dict[str, float]] = {}
_protocol_counters: Dict[str, Dict[str, float]] = {}


def register_agent_module(ns_or_mod: Any) -> None:
    """Register an agent facade module or namespace dict so patched attributes are honored."""
    ns = ns_or_mod if isinstance(ns_or_mod, dict) else getattr(ns_or_mod, "__dict__", None)
    if ns is not None and ns not in _AGENT_NAMESPACES:
        _AGENT_NAMESPACES.append(ns)


def _agent_attr(name: str, fallback: Any = None) -> Any:
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


def _call_agent(name: str, fallback: Any, *args: Any, **kwargs: Any) -> Any:
    fn = _agent_attr(name, fallback)
    if fn is None:
        raise RuntimeError(f"Missing helper {name!r} in runtime_drivers")
    return fn(*args, **kwargs)


def _is_containerized_runtime() -> bool:
    return os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv")


def _get_cached_bin(name: str, local_val: Any) -> Any:
    for ns in _AGENT_NAMESPACES:
        if name in ns and ns[name] is not local_val:
            return ns[name]
    return local_val


def _set_cached_bin(name: str, val: Any) -> None:
    for ns in _AGENT_NAMESPACES:
        ns[name] = val


def get_podman_bin(warn: bool = True) -> str:
    global _podman_bin
    cached = _get_cached_bin("_podman_bin", _podman_bin)
    if cached is not None:
        return cached

    # In containerized deployments we usually mount the host Podman socket.
    # Prefer podman-remote in containers so we can inspect host containers.
    # For host-based agents prefer local podman first, because podman-remote
    # often exists but is not configured with a valid CONTAINER_HOST.
    bin_candidates = ("podman-remote", "podman") if _call_agent("_is_containerized_runtime", _is_containerized_runtime, ) else ("podman", "podman-remote")
    for name in bin_candidates:
        if shutil.which(name):
            _podman_bin = name
            _set_cached_bin("_podman_bin", _podman_bin)
            return _podman_bin

    _podman_bin = ""
    _set_cached_bin("_podman_bin", _podman_bin)
    if warn and "podman" not in _warned_missing_bins:
        _warned_missing_bins.add("podman")
        print("missing command: podman (or podman-remote)")
    return _podman_bin


def _runtime_kind(runtime: str) -> str:
    name = os.path.basename(runtime or "")
    return "podman" if name in ("podman", "podman-remote") else name


def _cpu_set_count(value: object) -> float:
    cpus = set()
    for item in str(value or "").split(","):
        part = item.strip()
        if not part:
            continue
        if re.fullmatch(r"\d+", part):
            cpus.add(int(part))
            continue
        match = re.fullmatch(r"(\d+)-(\d+)", part)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if end >= start and end - start < 4096:
                cpus.update(range(start, end + 1))
    return float(len(cpus))


def _host_cpu_capacity() -> float:
    try:
        return float(max(1, len(os.sched_getaffinity(0))))
    except (AttributeError, OSError, TypeError):
        return float(max(1, os.cpu_count() or 1))


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
    cached_bins = _get_cached_bin("_runtime_bins", _runtime_bins)
    if cached_bins is not None:
        if (
            "runman" not in cached_bins
            and os.name == "posix"
            and hasattr(socket, "AF_UNIX")
            and os.path.exists("/run/narwhal-agent/connlimit.sock")
        ):
            cached_bins["runman"] = "runman"
        return dict(cached_bins)

    configured = os.getenv("CONTAINER_RUNTIMES", "auto").strip().lower()
    requested = [x.strip() for x in configured.split(",") if x.strip()]
    auto = not requested or "auto" in requested
    enabled = ("podman", "docker", "incus", "runman") if auto else tuple(dict.fromkeys(requested))
    invalid = [name for name in enabled if name not in ("podman", "docker", "incus", "runman")]
    if invalid:
        print(f"warn: unsupported container runtimes ignored: {', '.join(invalid)}")

    found: Dict[str, str] = {}
    if "podman" in enabled:
        podman = _call_agent("get_podman_bin", get_podman_bin, warn=False)
        if podman:
            found["podman"] = podman
    for name in ("docker", "incus"):
        if name not in enabled:
            continue
        if shutil.which(name):
            found[name] = name
    if "runman" in enabled:
        if os.name == "posix" and hasattr(socket, "AF_UNIX") and os.path.exists("/run/narwhal-agent/connlimit.sock"):
            found["runman"] = "runman"

    if not found and "container_runtimes" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtimes")
        wanted = ", ".join(x for x in enabled if x in ("podman", "docker", "incus", "runman"))
        print(f"missing command: no enabled container runtime found ({wanted})")
    elif not auto:
        for name in enabled:
            if name in ("podman", "docker", "incus", "runman") and name not in found:
                key = f"runtime:{name}"
                if key not in _warned_missing_bins:
                    _warned_missing_bins.add(key)
                    print(f"missing command: enabled runtime '{name}' is not installed or not in PATH")

    _runtime_bins = found
    _set_cached_bin("_runtime_bins", _runtime_bins)
    return dict(found)


def get_container_bin() -> str:
    global _container_bin
    cached = _get_cached_bin("_container_bin", _container_bin)
    if cached is not None:
        return cached

    runtimes = _call_agent("get_runtime_bins", get_runtime_bins, )
    for name in ("podman", "docker", "incus"):
        if name in runtimes:
            _container_bin = runtimes[name]
            _set_cached_bin("_container_bin", _container_bin)
            return _container_bin

    _container_bin = ""
    _set_cached_bin("_container_bin", _container_bin)
    if "container_runtime" not in _warned_missing_bins:
        _warned_missing_bins.add("container_runtime")
        print("missing command: podman (or podman-remote) / docker / incus")
    return _container_bin


def _runtime_command_timeout() -> float:
    try:
        configured = float(os.getenv("RUNTIME_COMMAND_TIMEOUT_SECONDS", "10"))
    except ValueError:
        configured = 10.0
    return max(3.0, min(300.0, configured))


def _runman_exec_request(
    container_name: str,
    instance_id: str,
    command: str,
    timeout: float = 30.0,
) -> Tuple[bool, str]:
    """Use Runman's generation-bound, root-only guest execution endpoint."""
    if (
        os.name != "posix" or not hasattr(socket, "AF_UNIX")
        or not re.fullmatch(r"[0-9a-fA-F-]{36}", container_name or "")
        or not instance_id or len(instance_id) > 200
        or not command or len(command.encode("utf-8")) > 64 * 1024 or "\0" in command
    ):
        return False, "Runman guest execution target or command is invalid"
    timeout_seconds = max(1, min(90, int(float(timeout))))
    connection = _agent_attr("network_quarantine", network_quarantine)._UnixHTTP("/run/narwhal-agent/connlimit.sock")
    connection.timeout = timeout_seconds + 5
    body = json.dumps({
        "container_name": container_name,
        "project": "default",
        "instance_id": instance_id,
        "command": command,
        "timeout_seconds": timeout_seconds,
    }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        connection.request(
            "POST", "/v1/exec", body=body,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        # JSON escaping can expand 64 KiB of guest output several-fold.
        raw = response.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            return False, "Runman guest execution response exceeded the limit"
        try:
            result = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, ValueError):
            result = {}
        if not isinstance(result, dict):
            return False, "Runman guest execution returned an invalid response"
        output = str(result.get("stdout") or "")
        error = str(result.get("stderr") or result.get("message") or "")
        if response.status != 200 or result.get("ok") is not True:
            return False, (output or error or "Runman guest execution failed")[:8000]
        if result.get("instance_id") != instance_id:
            return False, "Runman guest execution identity was not confirmed"
        if result.get("exit_code") != 0:
            return False, (output or error or f"Runman guest command exited with code {result.get('exit_code')}")[:8000]
        return True, output
    except (OSError, ValueError, http.client.HTTPException):
        return False, "Runman guest execution socket unavailable or timed out"
    finally:
        connection.close()


def _runman_stop_overload_request(
    container_name: str,
    instance_id: str,
    threshold: int,
    metric_tcp_active: bool,
) -> Tuple[bool, str]:
    """Ask Runman to stop only the exact generation still over its threshold."""
    if (
        os.name != 'posix' or not hasattr(socket, 'AF_UNIX')
        or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', container_name or '')
        or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', instance_id or '')
        or type(threshold) is not int or not 1 <= threshold <= 10_000_000
        or type(metric_tcp_active) is not bool
    ):
        return False, 'Runman overload stop target or evidence is invalid'
    connection = _agent_attr("network_quarantine", network_quarantine)._UnixHTTP('/run/narwhal-agent/connlimit.sock')
    connection.timeout = 95
    body = json.dumps({
        'container_name': container_name,
        'project': 'default',
        'instance_id': instance_id,
        'threshold': threshold,
        'metric_tcp_active': metric_tcp_active,
        'reason': 'sustained_connection_overload',
    }, separators=(',', ':')).encode('utf-8')
    try:
        connection.request(
            'POST', '/v1/stop-overload', body=body,
            headers={'Content-Type': 'application/json', 'Connection': 'close'},
        )
        response = connection.getresponse()
        raw = response.read(8193)
        if len(raw) > 8192:
            return False, 'Runman overload stop response exceeded the limit'
        try:
            result = json.loads(raw.decode('utf-8')) if raw else {}
        except (UnicodeDecodeError, ValueError):
            result = {}
        if (
            response.status != 200 or not isinstance(result, dict)
            or result.get('ok') is not True or result.get('stopped') is not True
            or result.get('instance_id') != instance_id
            or type(result.get('current_connections')) is not int
            or result['current_connections'] <= threshold
        ):
            message = result.get('message') if isinstance(result, dict) else None
            return False, str(message or 'Runman did not confirm a same-generation overload stop')[:500]
        return True, f"stopped after {result['current_connections']} connections remained above the limit"
    except (OSError, ValueError, http.client.HTTPException):
        return False, 'Runman overload stop socket unavailable or timed out; stop was not confirmed'
    finally:
        connection.close()


def _runman_current_resource_percent(container: Dict[str, object], metric: str, now: int):
    if not isinstance(container, dict) or container.get('runtime') != 'runman' or container.get('status') != 'running':
        return None
    resources = container.get('runman_resources') if isinstance(container.get('runman_resources'), dict) else {}
    if metric == 'cpu_percent':
        monitor = resources.get('monitor_metrics') if isinstance(resources.get('monitor_metrics'), dict) else {}
        sampled_at = monitor.get('sampled_at')
        value = monitor.get('cpu_percent')
        if (
            monitor.get('available') is not True or type(sampled_at) is not int
            or sampled_at <= 0 or sampled_at > now + 30 or now - sampled_at > 180
            or type(value) not in (int, float) or not math.isfinite(float(value))
            or float(value) < 0 or float(value) > 1000
        ):
            return None
        return float(value)
    if metric == 'memory_percent':
        used = resources.get('mem_bytes')
        limit = resources.get('mem_limit_bytes')
        if type(used) is not int or used < 0 or type(limit) is not int or limit <= 0:
            return None
        value = 100.0 * used / limit
        return value if math.isfinite(value) and value <= 10000 else None
    return None


def _runman_systemd_unit_state(unit: str, container_name: str):
    if not shutil.which('systemctl') or not os.path.isdir('/run/systemd/system'):
        return None, 'systemd is unavailable on the Runman host'
    try:
        result = subprocess.run(
            ['systemctl', 'show', unit, '--property=LoadState', '--property=ActiveState',
             '--property=MainPID', '--property=ControlGroup', '--no-pager'],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, 'unable to read the exact Runman systemd unit'
    if result.returncode != 0:
        return None, 'the exact Runman systemd unit could not be read'
    properties = {}
    for line in result.stdout.splitlines():
        name, sep, value = line.partition('=')
        if sep:
            properties[name.strip()] = value.strip()
    expected_cgroup = f'/system.slice/runman-{container_name}.service'
    try:
        pid = int(properties.get('MainPID') or 0)
    except ValueError:
        pid = 0
    if (
        properties.get('LoadState') != 'loaded'
        or properties.get('ActiveState') != 'active'
        or properties.get('ControlGroup') != expected_cgroup
        or pid <= 1
    ):
        return None, 'the exact Runman unit is not loaded, active, and identity-matched'
    return {'pid': pid, 'cgroup': expected_cgroup}, ''


def _runman_read_io_max(container: Dict[str, object]):
    target, error = resource_cgroup.resolve_container_cgroup(
        container.get('pid'), 'runman', container.get('stable_id') or container.get('id'),
        container.get('name'), expected_start_ticks=str(container.get('pid_start_ticks') or ''),
    )
    if target is None:
        return None, error or 'Runman cgroup identity is unavailable'
    path = os.path.join(str(target), 'io.max')
    if not os.path.isfile(path):
        return [], ''
    try:
        with open(path, 'r', encoding='ascii', errors='strict') as handle:
            raw = handle.read(65537)
    except (OSError, UnicodeError):
        return None, 'current Runman io.max could not be read'
    if len(raw) > 65536:
        return None, 'current Runman io.max exceeded the safe read limit'
    limits = []
    for line in raw.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r'\d+:\d+', fields[0]):
            return None, 'current Runman io.max format is invalid'
        values = {'rbps': 'max', 'wbps': 'max', 'riops': 'max', 'wiops': 'max'}
        for field in fields[1:]:
            key, sep, value = field.partition('=')
            if not sep or key not in values or (value != 'max' and not value.isdigit()):
                return None, 'current Runman io.max format is invalid'
            values[key] = value
        limits.append((fields[0], values))
    return limits, ''


def _runman_restore_io_max(container: Dict[str, object], limits):
    if not limits:
        return True, ''
    target, error = resource_cgroup.resolve_container_cgroup(
        container.get('pid'), 'runman', container.get('stable_id') or container.get('id'),
        container.get('name'), expected_start_ticks=str(container.get('pid_start_ticks') or ''),
    )
    if target is None:
        return False, error or 'new Runman cgroup identity is unavailable'
    path = os.path.join(str(target), 'io.max')
    if not os.path.isfile(path):
        return False, 'new Runman cgroup does not expose io.max'
    try:
        for device, values in limits:
            line = device + ' ' + ' '.join(f'{key}={values[key]}' for key in ('rbps', 'wbps', 'riops', 'wiops'))
            with open(path, 'w', encoding='ascii') as handle:
                handle.write(line)
        current, read_error = _runman_read_io_max(container)
        if current is None:
            return False, read_error
        observed = {device: values for device, values in current}
        if any(observed.get(device) != values for device, values in limits):
            return False, 'restored Runman io.max did not match the saved values'
        return True, ''
    except OSError:
        return False, 'saved Runman io.max could not be restored'


def _runman_restart_overload_request(action: Dict[str, object], node_id: str) -> Tuple[bool, str]:
    """Restart only the still-overloaded Runman UUID service after fresh checks."""
    runtime = str(action.get('runtime') or '').lower()
    project = str(action.get('project') or '')
    container_name = str(action.get('container_name') or '').lower()
    params = action.get('params') if isinstance(action.get('params'), dict) else {}
    metric = str(params.get('metric') or '')
    try:
        threshold = float(params.get('threshold_percent'))
        observed = float(params.get('observed_percent'))
        duration = int(params.get('duration_seconds'))
        required = int(params.get('required_duration_seconds'))
        samples = int(params.get('sample_count'))
        max_gap = int(params.get('max_gap_seconds'))
        observed_at = int(params.get('observed_at'))
        expires_at = int(params.get('expires_at'))
    except (TypeError, ValueError, OverflowError):
        return False, 'resource restart evidence is incomplete'
    instance_id = str(params.get('instance_id') or '').lower()
    current_time = int(time.time())
    if (
        os.name != 'posix' or not hasattr(socket, 'AF_UNIX')
        or runtime != 'runman' or project != 'default'
        or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', container_name)
        or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', instance_id)
        or params.get('reason') != 'sustained_resource_overload'
        or params.get('metric_schema') != 1 or metric not in {'cpu_percent', 'memory_percent'}
        or not math.isfinite(threshold) or not 1 <= threshold <= 100
        or not math.isfinite(observed) or observed < threshold
        or duration < required or required < 3600 or required > 86400
        or samples < 5 or samples > 100000
        or not 60 <= max_gap <= 1800
        or params.get('duration_verified') is not True
        or params.get('expected_node_id') != node_id or not node_id
        or observed_at <= 0 or observed_at > current_time + 30
        or current_time - observed_at > max_gap
        or expires_at < current_time or expires_at - current_time > max_gap + 30
        or _runman_instance_generations.get(container_name) != instance_id
    ):
        return False, 'Runman resource restart evidence is invalid, stale, or bound to another generation'

    try:
        import fcntl
    except ImportError:
        return False, 'exclusive restart locking is unavailable; no restart attempted'
    lock_path = '/run/narwhal-agent/resource-overload-restart.lock'
    lock_fd = None
    try:
        if not os.path.isdir(os.path.dirname(lock_path)):
            return False, 'Runman agent runtime directory is unavailable; no restart attempted'
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False, 'another resource restart is being handled; no duplicate restart attempted'

        # Re-read the authoritative inventory after taking the local lock.
        inventory = _agent_attr('_runman_inventory_containers', _runman_inventory_containers)
        containers = inventory()
        target = next((item for item in containers if item.get('name') == container_name), None)
        generations = _agent_attr('_runman_instance_generations', _runman_instance_generations)
        if (
            target is None or target.get('project') != 'default'
            or target.get('status') != 'running'
            or str(target.get('instance_id') or '').lower() != instance_id
            or generations.get(container_name) != instance_id
        ):
            return False, 'Runman instance changed or stopped before restart; action cancelled'
        current_value = _runman_current_resource_percent(target, metric, int(time.time()))
        if current_value is None or current_value < threshold:
            return False, 'Runman resource pressure recovered or current metric is unavailable; action cancelled'
        saved_io_limits, io_error = _runman_read_io_max(target)
        if saved_io_limits is None:
            return False, f'current Runman I/O limits could not be preserved: {io_error}; no restart attempted'

        unit = f'runman-{container_name}.service'
        try:
            jobs = subprocess.run(
                ['systemctl', 'list-jobs', '--no-legend', '--no-pager'],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False, 'unable to check active systemd lifecycle jobs; no restart attempted'
        if jobs.returncode != 0:
            return False, 'unable to verify systemd lifecycle jobs; no restart attempted'
        if any(len(fields := line.split()) >= 4 and fields[1] == unit for line in jobs.stdout.splitlines()):
            return False, 'the Runman instance already has a systemd lifecycle job; restart cancelled'

        before, reason = _runman_systemd_unit_state(unit, container_name)
        if before is None:
            return False, reason
        try:
            restarted = subprocess.run(
                ['systemctl', 'restart', unit], capture_output=True, text=True,
                timeout=180, check=False,
            )
        except subprocess.TimeoutExpired:
            restarted = None
        except OSError:
            return False, 'systemd restart could not be requested'

        deadline = time.monotonic() + 120
        after = None
        while time.monotonic() < deadline:
            after, _ = _runman_systemd_unit_state(unit, container_name)
            if after is not None and after['pid'] != before['pid']:
                break
            time.sleep(2)
        if after is None or after['pid'] == before['pid']:
            if restarted is None or restarted.returncode == 0:
                return False, 'systemd restart did not verify an active unit with a new MainPID'
            return False, 'systemd did not verify a restart of the exact Runman unit'
        io_message = ''
        if saved_io_limits:
            restarted_containers = inventory()
            target_after = next((item for item in restarted_containers if item.get('name') == container_name), None)
            if target_after is None or target_after.get('status') != 'running':
                io_message = '; warning: restart verified but previous io.max could not be restored because Runman inventory is unavailable'
            else:
                restored, restore_error = _runman_restore_io_max(target_after, saved_io_limits)
                if restored:
                    io_message = '; previous io.max limits restored and read back'
                else:
                    io_message = f'; warning: restart verified but previous io.max restore failed: {restore_error}'
        return True, (
            f'restarted exact Runman unit; active MainPID changed {before["pid"]}->{after["pid"]}; '
            f'pre-restart {metric} was {current_value:.1f}% (threshold {threshold:.1f}%){io_message}'
        )
    except OSError:
        return False, 'resource restart lock or systemd access failed; no success was confirmed'
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except (NameError, OSError):
                pass
            os.close(lock_fd)


def run(cmd: List[str], timeout: float | None = None) -> str:
    if cmd and cmd[0] == _RUNMAN_EXEC_SENTINEL:
        if len(cmd) != 4:
            return ""
        ok, output = _call_agent("_runman_exec_request", _runman_exec_request, 
            cmd[1], cmd[2], cmd[3],
            _call_agent("_runtime_command_timeout", _runtime_command_timeout, ) if timeout is None else timeout,
        )
        return output if ok else ""
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
            timeout=_call_agent("_runtime_command_timeout", _runtime_command_timeout, ) if timeout is None else timeout,
        )
    except FileNotFoundError:
        if cmd and cmd[0] not in _warned_missing_bins:
            _warned_missing_bins.add(cmd[0])
            print(f"missing command: {cmd[0]}")
        return ""
    except subprocess.TimeoutExpired:
        command_name = cmd[0] if cmd else "unknown"
        if len(cmd) >= 3 and cmd[1] == "exec":
            _unresponsive_exec_containers.add(cmd[2])
        elif len(cmd) >= 4 and "exec" in cmd:
            for idx, arg in enumerate(cmd):
                if arg == "exec" and idx + 1 < len(cmd):
                    _unresponsive_exec_containers.add(cmd[idx + 1])
                    break
        if command_name not in _warned_timeout_commands:
            _warned_timeout_commands.add(command_name)
            print(f"runtime command timed out and was skipped: {command_name}")
        return ""
    if p.returncode != 0:
        return ""
    return p.stdout


def run_first_success(commands: List[List[str]]) -> str:
    for cmd in commands:
        out = _call_agent("run", run, cmd)
        if out.strip():
            return out
    return ""


def _runtime_base(runtime: str, project: str = "") -> List[str]:
    cmd = [runtime]
    if _runtime_kind(runtime) == "incus" and project:
        cmd.extend(["--project", project])
    return cmd


def _runtime_exec_cmd(runtime: str, name: str, shell_command: str, project: str = "") -> List[str]:
    if name and name in _unresponsive_exec_containers:
        return ["true"]
    if _runtime_kind(runtime) == "runman":
        return [
            _RUNMAN_EXEC_SENTINEL,
            name,
            _agent_attr("_runman_instance_generations", _runman_instance_generations).get(name, ""),
            shell_command,
        ]
    cmd = _runtime_base(runtime, project) + ["exec", name]
    if _runtime_kind(runtime) == "incus":
        cmd.append("--")
    return cmd + ["sh", "-lc", shell_command]


def _runtime_config_exec_cmd(runtime: str, name: str, shell_command: str, project: str = "") -> List[str]:
    """Read protocol config files with container-root permissions, never host privileges.

    Podman exec otherwise inherits the image's configured USER, which can make
    root-owned proxy configuration look absent. Incus exec already enters as
    container root by default, so it keeps the ordinary command path.
    """
    if _runtime_kind(runtime) in {"podman", "podman-remote"}:
        return _runtime_base(runtime, project) + ["exec", "--user", "0", name, "sh", "-lc", shell_command]
    return _call_agent("_runtime_exec_cmd", _runtime_exec_cmd, runtime, name, shell_command, project)


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
    if not prev:
        _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds), "last_percent": 0.0}
        return 0.0
    dt = now - float(prev.get("ts", 0.0))
    if dt <= 0:
        if float(cpu_seconds) == float(prev.get("cpu", 0.0)):
            return float(prev.get("last_percent", 0.0))
        _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds), "last_percent": 0.0}
        return 0.0
    if float(cpu_seconds) < float(prev.get("cpu", 0.0)):
        _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds), "last_percent": 0.0}
        return 0.0
    delta = max(0.0, float(cpu_seconds) - float(prev.get("cpu", 0.0)))
    percent = (delta / dt) * 100.0
    _cpu_counters[container_key] = {"ts": now, "cpu": float(cpu_seconds), "last_percent": percent}
    return percent


def _sample_cgroup_cpu_metrics(
    pid: int | str | None,
    runtime: str,
    stable_id: str,
    name: str,
    *,
    instance_id: str = "",
    expected_start_ticks: str = "",
) -> Dict[str, object]:
    """Read cgroup v2 cpu.stat usage_usec delta and finite cpu.max quota for a verified container."""
    result: Dict[str, object] = {
        "available": False,
        "cpu_percent": 0.0,
        "usage_usec": None,
        "quota_cpus": 0.0,
    }
    try:
        pid_int = int(pid or 0)
    except (TypeError, ValueError, OverflowError):
        pid_int = 0
    if pid_int <= 1:
        return result
    target, _ = _agent_attr("cpu_guard", cpu_guard).resolve_container_cgroup(
        pid_int,
        runtime,
        stable_id or name,
        name,
        expected_start_ticks=(str(expected_start_ticks or "") if runtime == "runman" else ""),
    )
    if target is None:
        return result

    def _read_quota_cpus(cg_path: Path) -> float:
        try:
            cpu_max_raw = (cg_path / "cpu.max").read_text(encoding="ascii", errors="ignore").strip()
            max_match = re.fullmatch(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", cpu_max_raw)
            if max_match:
                quota_str, period_str = max_match.groups()
                period_val = int(period_str)
                if quota_str != "max" and period_val >= 1000:
                    return max(0.0, int(quota_str) / float(period_val))
        except (OSError, ValueError):
            pass
        return 0.0

    quota_cpus = _read_quota_cpus(target)
    if quota_cpus <= 0 and runtime == "runman" and target.name == "ct":
        quota_cpus = _read_quota_cpus(target.parent)
    if quota_cpus > 0:
        result["quota_cpus"] = quota_cpus

    try:
        stat_lines = (target / "cpu.stat").read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError:
        return result

    usage_usec: int | None = None
    user_usec: int | None = None
    system_usec: int | None = None
    for raw_line in stat_lines[:32]:
        parts = raw_line.strip().split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        key, val = parts[0], int(parts[1])
        if key == "usage_usec":
            usage_usec = val
            break
        if key == "user_usec":
            user_usec = val
        elif key == "system_usec":
            system_usec = val
    if usage_usec is None and (user_usec is not None or system_usec is not None):
        usage_usec = int(user_usec or 0) + int(system_usec or 0)
    if usage_usec is None or usage_usec < 0:
        return result

    counter_id = str(stable_id or name or pid_int)
    generation_id = str(instance_id or expected_start_ticks or pid_int)
    cpu_seconds = usage_usec / 1_000_000.0
    cpu_percent = _call_agent("_derive_cpu_percent", _derive_cpu_percent, f"cgroup:{runtime}:{counter_id}:{generation_id}", cpu_seconds)
    result.update(
        available=True,
        cpu_percent=round(max(0.0, cpu_percent), 2),
        usage_usec=usage_usec,
    )
    return result


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
        "Tcp": (
            "ActiveOpens", "AttemptFails", "EstabResets", "OutRsts",
            "InSegs", "OutSegs", "RetransSegs",
        ),
        "Udp": (
            "InDatagrams", "OutDatagrams", "NoPorts", "InErrors",
            "RcvbufErrors", "SndbufErrors",
        ),
    }
    result: Dict[str, int] = {}
    if pid <= 0:
        return result
    try:
        with open(f"/proc/{pid}/net/snmp", "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
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
    except Exception:
        pass

    try:
        with open(f"/proc/{pid}/net/netstat", "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
        for index in range(0, len(lines) - 1, 2):
            header = lines[index].split()
            values = lines[index + 1].split()
            if not header or not values or header[0] != values[0]:
                continue
            protocol = header[0].rstrip(":")
            if protocol == "TcpExt":
                mapping = dict(zip(header[1:], values[1:]))
                for field in (
                    "TCPInDataOctets", "TCPOutDataOctets", "SyncookiesSent",
                    "ListenOverflows", "ListenDrops",
                ):
                    if field in mapping:
                        try:
                            result[f"TcpExt_{field}"] = int(mapping.get(field, "0"))
                        except ValueError:
                            result[f"TcpExt_{field}"] = 0
    except Exception:
        pass

    return result


def _derive_protocol_rates(
    container_key: str,
    counters: Dict[str, int],
    total_rx_bps: float = 0.0,
    total_tx_bps: float = 0.0,
) -> Dict[str, float]:
    now = float(time.time())
    previous = _protocol_counters.get(container_key)
    current: Dict[str, float] = {"ts": now}
    current.update({key: float(value) for key, value in counters.items()})
    _protocol_counters[container_key] = current

    base_rates: Dict[str, float] = {f"{key}_per_second": 0.0 for key in counters}
    base_rates.update({
        "tcp_rx_bps": round(total_rx_bps, 2),
        "tcp_tx_bps": round(total_tx_bps, 2),
        "udp_rx_bps": 0.0,
        "udp_tx_bps": 0.0,
        "tcp_rx_pps": 0.0,
        "tcp_tx_pps": 0.0,
        "udp_rx_pps": 0.0,
        "udp_tx_pps": 0.0,
    })

    if not previous:
        return base_rates

    dt = now - float(previous.get("ts", 0.0))
    if dt <= 0:
        return base_rates

    for key, value in counters.items():
        base_rates[f"{key}_per_second"] = max(0.0, float(value) - float(previous.get(key, value))) / dt

    tcp_rx_pps = max(0.0, float(counters.get("Tcp_InSegs", 0) - previous.get("Tcp_InSegs", 0))) / dt
    tcp_tx_pps = max(0.0, float(counters.get("Tcp_OutSegs", 0) - previous.get("Tcp_OutSegs", 0))) / dt
    udp_rx_pps = max(0.0, float(counters.get("Udp_InDatagrams", 0) - previous.get("Udp_InDatagrams", 0))) / dt
    udp_tx_pps = max(0.0, float(counters.get("Udp_OutDatagrams", 0) - previous.get("Udp_OutDatagrams", 0))) / dt
    base_rates["tcp_rx_pps"] = round(tcp_rx_pps, 2)
    base_rates["tcp_tx_pps"] = round(tcp_tx_pps, 2)
    base_rates["udp_rx_pps"] = round(udp_rx_pps, 2)
    base_rates["udp_tx_pps"] = round(udp_tx_pps, 2)

    has_octets = (
        "TcpExt_TCPInDataOctets" in counters
        and "TcpExt_TCPInDataOctets" in previous
        and "TcpExt_TCPOutDataOctets" in counters
        and "TcpExt_TCPOutDataOctets" in previous
    )
    if has_octets:
        raw_tcp_rx = max(0.0, float(counters.get("TcpExt_TCPInDataOctets", 0) - previous.get("TcpExt_TCPInDataOctets", 0))) / dt
        raw_tcp_tx = max(0.0, float(counters.get("TcpExt_TCPOutDataOctets", 0) - previous.get("TcpExt_TCPOutDataOctets", 0))) / dt
        if total_rx_bps > 0:
            tcp_rx_bps = min(total_rx_bps, raw_tcp_rx)
            udp_rx_bps = max(0.0, total_rx_bps - tcp_rx_bps)
        else:
            tcp_rx_bps = raw_tcp_rx
            udp_rx_bps = 0.0

        if total_tx_bps > 0:
            tcp_tx_bps = min(total_tx_bps, raw_tcp_tx)
            udp_tx_bps = max(0.0, total_tx_bps - tcp_tx_bps)
        else:
            tcp_tx_bps = raw_tcp_tx
            udp_tx_bps = 0.0
    else:
        tot_rx_pps = tcp_rx_pps + udp_rx_pps
        if tot_rx_pps > 0 and total_rx_bps > 0:
            tcp_ratio = tcp_rx_pps / tot_rx_pps
            tcp_rx_bps = total_rx_bps * tcp_ratio
            udp_rx_bps = max(0.0, total_rx_bps - tcp_rx_bps)
        elif udp_rx_pps > 0 and total_rx_bps > 0:
            tcp_rx_bps = 0.0
            udp_rx_bps = total_rx_bps
        else:
            tcp_rx_bps = total_rx_bps
            udp_rx_bps = 0.0

        tot_tx_pps = tcp_tx_pps + udp_tx_pps
        if tot_tx_pps > 0 and total_tx_bps > 0:
            tcp_ratio = tcp_tx_pps / tot_tx_pps
            tcp_tx_bps = total_tx_bps * tcp_ratio
            udp_tx_bps = max(0.0, total_tx_bps - tcp_tx_bps)
        elif udp_tx_pps > 0 and total_tx_bps > 0:
            tcp_tx_bps = 0.0
            udp_tx_bps = total_tx_bps
        else:
            tcp_tx_bps = total_tx_bps
            udp_tx_bps = 0.0

    base_rates["tcp_rx_bps"] = round(tcp_rx_bps, 2)
    base_rates["tcp_tx_bps"] = round(tcp_tx_bps, 2)
    base_rates["udp_rx_bps"] = round(udp_rx_bps, 2)
    base_rates["udp_tx_bps"] = round(udp_tx_bps, 2)
    return base_rates


def _get_incus_metrics(runtime: str = "incus") -> Dict[Tuple[str, str], Dict[str, float]]:
    now = float(time.time())
    cached_ts = float(_incus_metrics_cache.get("ts", 0.0) or 0.0)
    if now - cached_ts < 7 and isinstance(_incus_metrics_cache.get("parsed"), dict):
        return _incus_metrics_cache["parsed"]  # type: ignore[return-value]
    text = _call_agent("run", run, [runtime, "query", "/1.0/metrics"])
    parsed = _parse_incus_metrics(text)
    _incus_metrics_cache.update({"ts": now, "text": text, "parsed": parsed})
    return parsed



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
    out = _call_agent("run", run, _call_agent("_runtime_exec_cmd", _runtime_exec_cmd, runtime, name, cmd, project)).strip()
    return int(out) if out.isdigit() else 0



_NGINX_ACCESS_RE = re.compile(r'^([^ ]+)\s+.*?"([A-Z]+)\s+([^ ]+)\s+[^\"]+"\s+(\d{3})\b')




def _oci_containers(runtime_name: str, runtime: str, patterns: List[str]) -> List[Dict[str, str]]:
    out = _call_agent("run", run, [runtime, "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}"])
    items: List[Dict[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) != 3:
            continue
        container_id, name, image = (x.strip() for x in parts)
        if not _call_agent("_image_matches", None, image, patterns):
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
    expanded_devices = item.get("expanded_devices") if isinstance(item.get("expanded_devices"), dict) else {}
    local_devices = item.get("devices") if isinstance(item.get("devices"), dict) else {}
    # Incus may omit expanded_devices from older/all-project JSON responses.
    # Local proxy devices are still explicit exposure evidence.
    devices = dict(local_devices)
    devices.update(expanded_devices)
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
                "protocol": str(raw_device.get("protocol") or "tcp").lower(),
                "nat": str(raw_device.get("nat") or "false"),
            }
        )
    return mappings


def _host_dnat_network_exposure(
    runtime_name: str,
    network_addresses: List[str],
    host_conntrack: Dict[str, object] | None,
) -> List[Dict[str, str]]:
    """Map explicit host TCP DNAT rules to a matching container address."""
    if runtime_name not in {"incus", "podman", "runman"} or not isinstance(host_conntrack, dict):
        return []
    addresses = {str(value) for value in network_addresses if _call_agent("_is_trackable_ip", None, str(value))}
    mappings = host_conntrack.get("nat_mappings")
    if not addresses or not isinstance(mappings, list):
        return []
    exposures: List[Dict[str, str]] = []
    seen = set()
    for mapping in mappings[:2000]:
        if not isinstance(mapping, dict) or str(mapping.get("proto") or "").lower() != "tcp":
            continue
        target_host = str(mapping.get("target_host") or "")
        if target_host not in addresses:
            continue
        try:
            public_port = int(mapping.get("public_port") or 0)
            target_port = int(mapping.get("container_port") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if not (1 <= public_port <= 65535 and 1 <= target_port <= 65535):
            continue
        bind_host = str(mapping.get("host") or "")
        if bind_host and not _call_agent("_is_trackable_ip", None, bind_host):
            continue
        bind_host = bind_host or "0.0.0.0"
        key = (bind_host, public_port, target_host, target_port)
        if key in seen:
            continue
        seen.add(key)
        exposures.append({
            "source": "host-dnat",
            "mapping_source": str(mapping.get("source") or "host-nat"),
            "listen": f"tcp:{bind_host}:{public_port}",
            "target": f"tcp:{target_host}:{target_port}",
            "nat": "true",
        })
        if len(exposures) >= 128:
            break
    return exposures



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
    network_output = _call_agent("run", run, base + ["network", "list", "--format=json"])
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
        forward_output = _call_agent("run", run, base + ["network", "forward", "list", network_name, "--format=json"])
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
            if listen_address and _call_agent("_is_trackable_ip", None, default_target):
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
    project = os.getenv("INCUS_PROJECT", "all").strip()
    all_projects = not project or project.lower() in ("all", "*")
    if all_projects:
        cmd = [runtime, "list", "--all-projects", "type=container", "status=running", "--format=json"]
    else:
        cmd = _runtime_base(runtime, project) + ["list", "type=container", "status=running", "--format=json"]
    output = _call_agent("run", run, cmd)
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
        if not _call_agent("_image_matches", None, f"{name} {image}", patterns):
            continue
        item_project = str(item.get("project") or ("default" if all_projects else project))
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
                if str(address.get("scope") or "").lower() == "global" and _call_agent("_is_trackable_ip", None, value):
                    network_addresses.append(value)
        items.append(
            {
                "id": name,
                "stable_id": str(item.get('config', {}).get('volatile.uuid') or ''),
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
    forward_mappings_by_project: Dict[str, List[Dict[str, str]]] = {}
    for item in items:
        item_project = str(item.get("project") or "default")
        if item_project not in forward_mappings_by_project:
            forward_mappings_by_project[item_project] = _incus_network_forward_mappings(
                runtime, item_project
            )
        addresses = set(item.get("network_addresses") or [])
        exposures = item.get("network_exposure") if isinstance(item.get("network_exposure"), list) else []
        for mapping in forward_mappings_by_project[item_project]:
            _, target_host, _ = _call_agent("_parse_exposure_endpoint", None, str(mapping.get("target") or ""))
            if target_host in addresses:
                exposures.append(dict(mapping))
        item["network_exposure"] = exposures
    return items


def _runman_proc_snapshot(pid: int) -> Dict[str, object]:
    """Read PID identity and filesystem usage from one pinned proc directory."""
    result: Dict[str, object] = {
        'pid_start_ticks': '',
        'disk_used_bytes': 0,
        'container_fs': {
            'root': {'total_bytes': 0, 'avail_bytes': 0},
            'data': {'total_bytes': 0, 'avail_bytes': 0},
        },
        'container_fs_available': False,
    }
    procfd = None
    rootfd = None
    try:
        procfd = os.open(f'/proc/{pid}', os.O_RDONLY | os.O_DIRECTORY)
        if not security_banner._proc_host_pid_matches(procfd, pid):
            return result
        samples = []
        for _ in range(2):
            fd = os.open('stat', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=procfd)
            with os.fdopen(fd, 'r', encoding='ascii', errors='ignore') as handle:
                samples.append(_call_agent("_proc_stat_start_ticks", None, handle.read(4096)))
        if not samples[0] or samples[0] != samples[1]:
            return result
        result['pid_start_ticks'] = samples[0]
        rootfd = os.open('root', os.O_RDONLY | os.O_DIRECTORY, dir_fd=procfd)

        def fs_usage(usage) -> Dict[str, int] | None:
            block_size = int(usage.f_frsize or usage.f_bsize or 0)
            if block_size <= 0:
                return None
            total = int(usage.f_blocks) * block_size
            available = min(int(usage.f_bavail), int(usage.f_blocks)) * block_size
            return {'total_bytes': max(0, total), 'avail_bytes': max(0, available)}

        root_stat = os.fstatvfs(rootfd)
        root_usage = fs_usage(root_stat)
        if root_usage is None:
            return result
        result['container_fs']['root'] = root_usage
        result['disk_used_bytes'] = max(
            0, (int(root_stat.f_blocks) - int(root_stat.f_bfree))
            * int(root_stat.f_frsize or root_stat.f_bsize),
        )
        try:
            datafd = os.open('data', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
            try:
                data_usage = fs_usage(os.fstatvfs(datafd))
                if data_usage is not None:
                    result['container_fs']['data'] = data_usage
            finally:
                os.close(datafd)
        except OSError:
            pass
        result['container_fs_available'] = True
        return result
    except OSError:
        return result
    finally:
        if rootfd is not None:
            os.close(rootfd)
        if procfd is not None:
            os.close(procfd)


def _runman_inventory_containers() -> List[Dict[str, str]]:
    """Read Runman's bounded, root-only inventory and generation-bound metrics."""
    _runman_instance_generations.clear()
    if os.name != 'posix' or not hasattr(socket, 'AF_UNIX'):
        return []
    configured = os.getenv('CONTAINER_RUNTIMES', 'auto').strip().lower().replace(' ', '')
    if configured != 'auto' and 'runman' not in configured.split(','):
        return []
    connection = _agent_attr("network_quarantine", network_quarantine)._UnixHTTP('/run/narwhal-agent/connlimit.sock')
    try:
        connection.request('GET', '/v1/inventory', headers={'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if response.status != 200 or len(raw) > 2 * 1024 * 1024:
            return []
        body = json.loads(raw.decode('utf-8')) if raw else {}
    except (OSError, ValueError, UnicodeDecodeError, http.client.HTTPException):
        return []
    finally:
        connection.close()
    if not isinstance(body, dict) or body.get('schema') != 1 or not isinstance(body.get('items'), list):
        return []

    inventory_now = int(time.time())
    items: List[Dict[str, str]] = []
    generations: Dict[str, str] = {}
    for raw_item in body['items'][:4096]:
        if not isinstance(raw_item, dict):
            continue
        vm_id = str(raw_item.get('id') or '').lower()
        generation = str(raw_item.get('instance_id') or '')
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', vm_id):
            continue
        if not generation or len(generation) > 200:
            continue
        generations[vm_id] = generation
        raw_metrics = raw_item.get('connection_metrics')
        metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
        established = metrics.get('tcp_established')
        pending = metrics.get('tcp_pending')
        time_wait = metrics.get('tcp_time_wait')
        udp_sockets = metrics.get('udp_sockets')
        sampled_at = metrics.get('sampled_at')
        counts_valid = all(type(value) is int and value >= 0 for value in (established, pending, time_wait))
        raw_total = metrics.get('tcp_total')
        udp_valid = type(udp_sockets) is int and udp_sockets >= 0
        metrics_valid = (
            raw_item.get('running') is True
            and metrics.get('schema') == 1
            and metrics.get('source') == 'runman_proc_net'
            and metrics.get('valid') is True
            and counts_valid
            and udp_valid
            and type(raw_total) is int
            and raw_total == established + pending + time_wait
            and metrics.get('epoch') == generation
            and type(sampled_at) is int
            and sampled_at > 0
            and sampled_at <= inventory_now + 30
        )
        total_connections = raw_total + udp_sockets if metrics_valid else 0
        traffic_in = raw_item.get('traffic_in_bytes')
        traffic_out = raw_item.get('traffic_out_bytes')
        traffic_counters_available = (
            type(traffic_in) is int and traffic_in >= 0
            and type(traffic_out) is int and traffic_out >= 0
        )
        raw_monitor = raw_item.get('monitor_metrics')
        monitor = raw_monitor if isinstance(raw_monitor, dict) else {}
        monitor_at = monitor.get('sampled_at')
        monitor_valid = (
            raw_item.get('running') is True
            and monitor.get('schema') == 1
            and monitor.get('source') == 'runman_history'
            and monitor.get('valid') is True
            and type(monitor_at) is int
            and monitor_at > 0
            and monitor_at <= inventory_now + 30
            and inventory_now - monitor_at <= 180
            and type(monitor.get('samples')) is int
            and monitor.get('samples') > 0
        )
        monitor_metrics: Dict[str, object] = {
            'available': monitor_valid,
            'sampled_at': monitor_at if type(monitor_at) is int and monitor_at > 0 else 0,
            'window_seconds': monitor.get('window_seconds') if type(monitor.get('window_seconds')) is int else 0,
            'samples': monitor.get('samples') if type(monitor.get('samples')) is int else 0,
        }
        for field in (
            'cpu_percent', 'disk_used_bytes', 'disk_read_bytes_per_second',
            'disk_write_bytes_per_second', 'disk_read_iops', 'disk_write_iops',
            'net_rx_bits_per_second', 'net_tx_bits_per_second',
            'net_rx_packets_per_second', 'net_tx_packets_per_second',
            'tcp_connections', 'udp_flows', 'remote_ip_count',
        ):
            value = monitor.get(field)
            valid_value = (
                type(value) is int and value >= 0
                or type(value) is float and math.isfinite(value) and value >= 0
            )
            monitor_metrics[field] = value if monitor_valid and valid_value else None
        raw_cpu = raw_item.get('cpu_percent')
        if monitor_valid and type(monitor_metrics.get('cpu_percent')) in (int, float):
            raw_cpu = monitor_metrics['cpu_percent']
        if type(raw_cpu) not in (int, float) or not math.isfinite(float(raw_cpu)) or raw_cpu < 0:
            raw_cpu = 0.0
        connection_metrics = {
            'schema': 1,
            'source': 'runman_local_proc_net',
            'sampled_at': sampled_at if metrics_valid else 0,
            'epoch': generation,
            'valid': metrics_valid,
            'total': total_connections,
            'tcp_total': raw_total if metrics_valid else 0,
            'tcp_established': established if metrics_valid else 0,
            'tcp_pending': pending if metrics_valid else 0,
            'tcp_time_wait': time_wait if metrics_valid else 0,
            'udp_sockets': udp_sockets if metrics_valid else None,
            'udp_sockets_available': metrics_valid,
            'udp_flows': monitor_metrics.get('udp_flows') if monitor_valid else None,
        }
        raw_disk_image = raw_item.get('disk_image') if isinstance(raw_item.get('disk_image'), dict) else {}
        disk_image_valid = (
            raw_disk_image.get('source') == 'runman_disk_image'
            and raw_disk_image.get('available') is True
            and type(raw_disk_image.get('sampled_at')) is int
            and raw_disk_image['sampled_at'] > 0
            and raw_disk_image['sampled_at'] <= inventory_now + 30
            and type(raw_disk_image.get('logical_bytes')) is int
            and raw_disk_image['logical_bytes'] >= 0
            and type(raw_disk_image.get('allocated_bytes')) is int
            and 0 <= raw_disk_image['allocated_bytes'] <= raw_disk_image['logical_bytes']
        )
        raw_writable_layer = raw_item.get('writable_layer') if isinstance(raw_item.get('writable_layer'), dict) else {}
        writable_layer_valid = (
            raw_item.get('running') is True
            and raw_writable_layer.get('source') == 'runman_overlay_upperdir_allocated'
            and raw_writable_layer.get('available') is True
            and type(raw_writable_layer.get('sampled_at')) is int
            and 0 < raw_writable_layer['sampled_at'] <= inventory_now + 30
            and inventory_now - raw_writable_layer['sampled_at'] <= 180
            and type(raw_writable_layer.get('allocated_bytes')) is int
            and raw_writable_layer['allocated_bytes'] >= 0
            and disk_image_valid
            and raw_writable_layer['allocated_bytes'] <= raw_disk_image['logical_bytes']
        )
        pid = raw_item.get('init_pid') if raw_item.get('running') is True else None
        proc_snapshot = _runman_proc_snapshot(pid) if type(pid) is int and pid > 1 else {}
        pid_start_ticks = str(proc_snapshot.get('pid_start_ticks') or '')
        cgroup_cpu = (
            _call_agent("_sample_cgroup_cpu_metrics", _sample_cgroup_cpu_metrics, 
                pid, 'runman', vm_id, vm_id,
                instance_id=generation, expected_start_ticks=pid_start_ticks,
            )
            if type(pid) is int and pid > 1
            else {'available': False, 'cpu_percent': 0.0, 'usage_usec': None, 'quota_cpus': 0.0}
        )
        if cgroup_cpu.get('available') is True:
            raw_cpu = max(float(raw_cpu), float(cgroup_cpu.get('cpu_percent') or 0.0))
        ips_list = [str(ip)[:64] for ip in raw_item.get('ips', [])[:32]] if isinstance(raw_item.get('ips'), list) else []
        items.append({
            'id': vm_id,
            'stable_id': vm_id,
            'name': vm_id,
            'runtime': 'runman',
            # Dispatch marker for _runtime_exec_cmd; this is not a binary to
            # invoke. Runman commands go through its generation-bound API.
            'runtime_bin': 'runman',
            'project': 'default',
            'pid': str(pid) if type(pid) is int and pid > 0 else '',
            'pid_start_ticks': pid_start_ticks,
            'image': str(raw_item.get('os_image') or '')[:160],
            'status': 'running' if raw_item.get('running') is True else 'stopped',
            'instance_id': generation,
            'network_addresses': [ip for ip in ips_list if ip],
            'connection_metrics': connection_metrics,
            'runman_resources': {
                'cpu': raw_item.get('cpu') if type(raw_item.get('cpu')) is int else 0,
                'cpu_percent': raw_cpu,
                'cgroup_cpu_available': bool(cgroup_cpu.get('available')),
                'cgroup_cpu_percent': float(cgroup_cpu.get('cpu_percent') or 0.0),
                'cgroup_quota_cpus': float(cgroup_cpu.get('quota_cpus') or 0.0),
                'ram_mb': raw_item.get('ram_mb') if type(raw_item.get('ram_mb')) is int else 0,
                'mem_bytes': raw_item.get('mem_bytes') if type(raw_item.get('mem_bytes')) is int else 0,
                'mem_limit_bytes': raw_item.get('mem_limit_bytes') if type(raw_item.get('mem_limit_bytes')) is int else 0,
                'disk_gb': raw_item.get('disk_gb') if type(raw_item.get('disk_gb')) is int else 0,
                'bandwidth_mbps': raw_item.get('bandwidth_mbps') if type(raw_item.get('bandwidth_mbps')) is int else 0,
                'traffic_in_bytes': traffic_in if traffic_counters_available else 0,
                'traffic_out_bytes': traffic_out if traffic_counters_available else 0,
                'traffic_counters_available': traffic_counters_available,
                'disk_used_bytes': (
                    proc_snapshot.get('disk_used_bytes', 0)
                    if proc_snapshot.get('container_fs_available') is True
                    else monitor_metrics.get('disk_used_bytes') or 0
                ),
                'disk_image': {
                    'available': disk_image_valid,
                    'source': 'runman_sparse_disk_image',
                    'sampled_at': raw_disk_image.get('sampled_at') if disk_image_valid else 0,
                    'logical_bytes': raw_disk_image.get('logical_bytes') if disk_image_valid else None,
                    'allocated_bytes': raw_disk_image.get('allocated_bytes') if disk_image_valid else None,
                },
                'writable_layer': {
                    'available': writable_layer_valid,
                    'source': 'runman_overlay_upperdir_allocated',
                    'sampled_at': raw_writable_layer.get('sampled_at') if writable_layer_valid else 0,
                    'allocated_bytes': raw_writable_layer.get('allocated_bytes') if writable_layer_valid else None,
                },
                'monitor_metrics': monitor_metrics,
                'container_fs': proc_snapshot.get('container_fs', {
                    'root': {'total_bytes': 0, 'avail_bytes': 0},
                    'data': {'total_bytes': 0, 'avail_bytes': 0},
                }),
                'container_fs_available': proc_snapshot.get('container_fs_available') is True,
                'ips': [str(ip)[:64] for ip in raw_item.get('ips', [])[:32]] if isinstance(raw_item.get('ips'), list) else [],
                'net_metrics_available': raw_item.get('net_metrics_available') is True,
            },
        })
    _runman_instance_generations.update(generations)
    return items


def _collect_incus_runtime_health() -> Dict[str, object] | None:
    configured = os.getenv("CONTAINER_RUNTIMES", "auto").strip().lower()
    requested = {item.strip() for item in configured.split(",") if item.strip()}
    incus_enabled = not requested or "auto" in requested or "incus" in requested
    if not incus_enabled:
        return None

    runtime = _call_agent("get_runtime_bins", get_runtime_bins, ).get("incus")
    if not runtime:
        if "auto" in requested or not requested:
            return None
        runtime = "incus"
    project = os.getenv("INCUS_PROJECT", "all").strip() or "all"
    try:
        instance_scan = _agent_attr("incus_health", incus_health).list_instances(runtime, project)
        operation_scan = _agent_attr("incus_health", incus_health).list_operations(runtime, project)
        return _agent_attr("incus_health", incus_health).build_snapshot(instance_scan, operation_scan, project=project)
    except Exception:
        unavailable = {"ok": False, "items": [], "latency_ms": 0, "error": "collector_failed"}
        return _agent_attr("incus_health", incus_health).build_snapshot(unavailable, unavailable, project=project)


def list_containers() -> List[Dict[str, str]]:
    patterns_env = os.getenv(
        "MONITORED_IMAGE_PATTERNS",
        "*",
    )
    patterns = [x.strip() for x in patterns_env.split(",") if x.strip()]
    items: List[Dict[str, str]] = []
    for runtime_name, runtime in _call_agent("get_runtime_bins", get_runtime_bins, ).items():
        if runtime_name == "docker" and _docker_monitor_mode() == "off":
            continue
        if runtime_name == "incus":
            items.extend(_call_agent("_incus_containers", _incus_containers, runtime))
        elif runtime_name in ("podman", "docker"):
            items.extend(_call_agent("_oci_containers", _oci_containers, runtime_name, runtime, patterns))
    items.extend(_runman_inventory_containers())
    return items


def _runman_bridge_interface() -> str:
    if os.name != 'posix' or not hasattr(socket, 'AF_UNIX'):
        return ''
    connection = _agent_attr("network_quarantine", network_quarantine)._UnixHTTP('/run/narwhal-agent/connlimit.sock')
    try:
        connection.request('GET', '/v1/inventory', headers={'Connection': 'close'})
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if response.status != 200 or len(raw) > 2 * 1024 * 1024:
            return ''
        body = json.loads(raw.decode('utf-8')) if raw else {}
        bridge = str(body.get('bridge') or '') if isinstance(body, dict) else ''
        return bridge if re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', bridge) else ''
    except (OSError, ValueError, UnicodeDecodeError, http.client.HTTPException):
        return ''
    finally:
        connection.close()


def collect_runman_report(
    container: Dict[str, object], base_report: Dict[str, object] | None = None,
) -> Dict[str, object]:
    metrics = container.get('connection_metrics') if isinstance(container.get('connection_metrics'), dict) else {}
    resources = dict(container.get('runman_resources')) if isinstance(container.get('runman_resources'), dict) else {}
    total_connections = metrics.get('total') if type(metrics.get('total')) is int else 0
    mem_bytes = resources.get('mem_bytes') if type(resources.get('mem_bytes')) is int else 0
    mem_limit = resources.get('mem_limit_bytes') if type(resources.get('mem_limit_bytes')) is int else 0
    stable_id = str(container.get('stable_id') or container.get('id') or '')
    instance_id = str(container.get('instance_id') or '')
    is_running = str(container.get('status') or '') == 'running'
    pid_int = int(container.get('pid') or 0) if str(container.get('pid') or '').isdigit() or isinstance(container.get('pid'), int) else 0
    if is_running and pid_int > 1 and 'cgroup_cpu_available' not in resources:
        cgroup_cpu = _call_agent("_sample_cgroup_cpu_metrics", _sample_cgroup_cpu_metrics, 
            pid_int,
            'runman',
            stable_id,
            str(container.get('name') or stable_id),
            instance_id=instance_id,
            expected_start_ticks=str(container.get('pid_start_ticks') or ''),
        )
        resources['cgroup_cpu_available'] = bool(cgroup_cpu.get('available'))
        resources['cgroup_cpu_percent'] = float(cgroup_cpu.get('cpu_percent') or 0.0)
        resources['cgroup_quota_cpus'] = float(cgroup_cpu.get('quota_cpus') or 0.0)
    raw_cpu = resources.get('cpu_percent') if type(resources.get('cpu_percent')) in (int, float) else 0.0
    if not math.isfinite(float(raw_cpu)) or float(raw_cpu) < 0:
        raw_cpu = 0.0
    cgroup_cpu_pct = resources.get('cgroup_cpu_percent') if type(resources.get('cgroup_cpu_percent')) in (int, float) else 0.0
    if not math.isfinite(float(cgroup_cpu_pct)) or float(cgroup_cpu_pct) < 0:
        cgroup_cpu_pct = 0.0
    cgroup_quota_cpus = resources.get('cgroup_quota_cpus') if type(resources.get('cgroup_quota_cpus')) in (int, float) else 0.0
    if not math.isfinite(float(cgroup_quota_cpus)) or float(cgroup_quota_cpus) < 0:
        cgroup_quota_cpus = 0.0
    cpu = max(float(raw_cpu), float(cgroup_cpu_pct)) if is_running else 0.0
    traffic_valid = (
        resources.get('traffic_counters_available') is True
        or resources.get('net_metrics_available') is True
        or bool(resources.get('traffic_in_bytes') or resources.get('traffic_out_bytes'))
    )
    traffic_rx = resources.get('traffic_in_bytes') if type(resources.get('traffic_in_bytes')) is int else 0
    traffic_tx = resources.get('traffic_out_bytes') if type(resources.get('traffic_out_bytes')) is int else 0
    raw_fs = resources.get('container_fs') if isinstance(resources.get('container_fs'), dict) else {}

    def fs_usage(name: str) -> Dict[str, int]:
        raw = raw_fs.get(name) if isinstance(raw_fs.get(name), dict) else {}
        total = raw.get('total_bytes') if type(raw.get('total_bytes')) is int else 0
        available = raw.get('avail_bytes') if type(raw.get('avail_bytes')) is int else 0
        return {'total_bytes': max(0, total), 'avail_bytes': max(0, min(total, available))}

    container_fs = {'root': fs_usage('root'), 'data': fs_usage('data')}
    if traffic_valid:
        net_rx_bps, net_tx_bps = _derive_net_bps(
            f'runman:{stable_id}:{instance_id}', traffic_rx, traffic_tx,
        )
    else:
        _net_counters.pop(f'runman:{stable_id}:{instance_id}', None)
        net_rx_bps, net_tx_bps = 0.0, 0.0

    ips = [str(ip) for ip in resources.get('ips', []) if isinstance(ip, str) and ip]
    if not ips and isinstance(container.get('network_addresses'), list):
        ips = [str(ip) for ip in container.get('network_addresses') if isinstance(ip, str) and ip]

    disk_gb = resources.get('disk_gb') if type(resources.get('disk_gb')) is int else 0
    disk_bytes = disk_gb * 1024 * 1024 * 1024 if disk_gb > 0 else 0
    fs_root_total = container_fs['root']['total_bytes'] or disk_bytes
    if fs_root_total > 0 and container_fs['root']['total_bytes'] == 0:
        container_fs['root']['total_bytes'] = fs_root_total

    raw_metrics = resources.get('monitor_metrics') if isinstance(resources.get('monitor_metrics'), dict) else {}
    metrics_available = raw_metrics.get('available') is True
    disk_io = {
        'available': metrics_available,
        'sampled_at': raw_metrics.get('sampled_at') if type(raw_metrics.get('sampled_at')) is int else 0,
        'samples': raw_metrics.get('samples') if type(raw_metrics.get('samples')) is int else 0,
        'read_bytes_per_second': raw_metrics.get('disk_read_bytes_per_second') if metrics_available else None,
        'write_bytes_per_second': raw_metrics.get('disk_write_bytes_per_second') if metrics_available else None,
        'read_iops': raw_metrics.get('disk_read_iops') if metrics_available else None,
        'write_iops': raw_metrics.get('disk_write_iops') if metrics_available else None,
    }
    writable_layer = resources.get('writable_layer') if isinstance(resources.get('writable_layer'), dict) else {}
    writable_layer_available = (
        writable_layer.get('available') is True
        and writable_layer.get('source') == 'runman_overlay_upperdir_allocated'
        and type(writable_layer.get('allocated_bytes')) is int
        and writable_layer.get('allocated_bytes') >= 0
        and type(writable_layer.get('sampled_at')) is int
        and writable_layer.get('sampled_at') > 0
    )
    container_disk = {
        'rw_bytes': writable_layer.get('allocated_bytes') if writable_layer_available else 0,
        'rw_available': writable_layer_available,
        'rw_source': 'runman_overlay_upperdir_allocated',
        'rw_sampled_at': writable_layer.get('sampled_at') if writable_layer_available else 0,
        'rw_logical_file_bytes': (
            writable_layer.get('logical_file_bytes')
            if writable_layer_available
            and type(writable_layer.get('logical_file_bytes')) is int
            and writable_layer.get('logical_file_bytes') >= 0
            else None
        ),
        'rw_logical_available': (
            writable_layer_available
            and type(writable_layer.get('logical_file_bytes')) is int
            and writable_layer.get('logical_file_bytes') >= 0
        ),
        'rw_logical_source': 'runman_overlay_upperdir_logical_file_bytes',
        'rw_regular_files': (
            writable_layer.get('regular_files')
            if writable_layer_available
            and type(writable_layer.get('regular_files')) is int
            and 0 <= writable_layer.get('regular_files') <= 50_000
            else None
        ),
        'rootfs_bytes': disk_bytes,
        'fs': container_fs,
        'available': resources.get('container_fs_available') is True or disk_bytes > 0,
        'io': disk_io,
        'backing_image': resources.get('disk_image') if isinstance(resources.get('disk_image'), dict) else {
            'available': False, 'source': 'runman_sparse_disk_image',
        },
    }
    report = dict(base_report) if isinstance(base_report, dict) else {}
    security = dict(report.get('security')) if isinstance(report.get('security'), dict) else {}
    security.update({
        'connection_metrics': metrics,
        'runman_metrics': raw_metrics,
        'inspection_status': 'runman_guest_exec' if str(container.get('status')) == 'running' else 'stopped',
        'deep_process_inspection_supported': str(container.get('status')) == 'running',
        'freeze_guard': container_freeze.get_freeze_status('runman', str(container.get('name') or ''), container.get('pid'), instance_id=instance_id, expected_start_ticks=str(container.get('pid_start_ticks') or '')) if container_freeze is not None else {},
        'udp_blackhole': udp_guard.get_udp_blackhole_status('runman', str(container.get('name') or ''), pid=int(container.get('pid') or 0)) if udp_guard is not None else {},
        'anti_spoof': anti_spoof_guard.get_anti_spoof_status_for_container('runman', str(container.get('name') or '')) if anti_spoof_guard is not None else {},
        'sensitive_file_events': file_guard.scan_container_sensitive_drops(int(container.get('pid') or 0), runtime='runman', name=str(container.get('name') or '')) if file_guard is not None else [],
        'microburst': microburst_guard.detect_microburst('runman', str(container.get('name') or ''), 0, 0, traffic_rx, traffic_tx) if microburst_guard is not None else {},
    })
    if base_report is None:
        _call_agent("_enrich_socket_ips_geoip", None, security, allow_network=True)
    security['socket_abuse'] = _call_agent("_evaluate_socket_abuse", None, 
        {
            'conn_count': total_connections if metrics.get('valid') is True else int(report.get('conn_count') or 0),
            'net_rx_bps': net_rx_bps,
            'net_tx_bps': net_tx_bps,
        },
        security,
        rx_bps=net_rx_bps,
        tx_bps=net_tx_bps,
        rx_pps=float(raw_metrics.get('net_rx_packets_per_second') or security.get('net_rx_pps') or 0.0),
        tx_pps=float(raw_metrics.get('net_tx_packets_per_second') or security.get('net_tx_pps') or 0.0),
    )
    existing_disk = report.get('container_disk') if isinstance(report.get('container_disk'), dict) else {}
    existing_fs = existing_disk.get('fs') if isinstance(existing_disk.get('fs'), dict) else {}
    merged_fs = dict(existing_fs)
    for fs_name in ('root', 'data'):
        # Generation-checked procfs values are authoritative; guest df is a
        # fallback where the host cannot traverse /proc/PID/root.
        if container_fs[fs_name]['total_bytes'] > 0:
            merged_fs[fs_name] = container_fs[fs_name]
        elif isinstance(existing_fs.get(fs_name), dict):
            merged_fs[fs_name] = existing_fs[fs_name]
    container_disk.update({
        key: value for key, value in existing_disk.items()
        if key not in {
            'rw_bytes', 'rw_available', 'rw_source', 'rw_sampled_at',
            'rw_logical_file_bytes', 'rw_logical_available', 'rw_regular_files',
            'rootfs_bytes', 'fs', 'io', 'available', 'backing_image',
        }
    })
    container_disk['fs'] = merged_fs
    top_cpu_process = report.get('top_cpu_process') if isinstance(report.get('top_cpu_process'), dict) else {}
    if is_running and pid_int > 1 and float(top_cpu_process.get('cpu_percent') or 0.0) <= 0:
        proc_snapshot, _ = _call_agent("_collect_host_proc_process_snapshot", None, pid_int, 50)
        proc_items = proc_snapshot.get('items') if isinstance(proc_snapshot.get('items'), list) else []
        if proc_items and isinstance(proc_items[0], dict) and float(proc_items[0].get('cpu_percent') or 0.0) > 0:
            top_item = proc_items[0]
            top_cpu_process = {
                'pid': int(top_item.get('pid') or 0),
                'cpu_percent': round(max(0.0, float(top_item.get('cpu_percent') or 0.0)), 2),
                'command': str(top_item.get('command') or top_item.get('process') or '')[:160],
            }
    if not top_cpu_process:
        top_cpu_process = {'pid': 0, 'cpu_percent': 0.0, 'command': ''}
    base_cpu = float(report.get('cpu_percent') or 0.0) if type(report.get('cpu_percent')) in (int, float) else 0.0
    if not math.isfinite(base_cpu) or base_cpu < 0:
        base_cpu = 0.0
    top_proc_cpu = float(top_cpu_process.get('cpu_percent') or 0.0) if type(top_cpu_process.get('cpu_percent')) in (int, float) else 0.0
    if not math.isfinite(top_proc_cpu) or top_proc_cpu < 0:
        top_proc_cpu = 0.0
    effective_cpu_percent = max(0.0, float(cpu), base_cpu, top_proc_cpu) if is_running else 0.0
    configured_cpus = float(resources.get('cpu') or 0.0) if type(resources.get('cpu')) in (int, float) else 0.0
    if not math.isfinite(configured_cpus) or configured_cpus < 0:
        configured_cpus = 0.0
    base_effective_cpus = float(report.get('cpu_effective_cpus') or 0.0) if type(report.get('cpu_effective_cpus')) in (int, float) else 0.0
    if not math.isfinite(base_effective_cpus) or base_effective_cpus < 0:
        base_effective_cpus = 0.0
    host_cpus = _call_agent("_host_cpu_capacity", _host_cpu_capacity, )
    if configured_cpus > 0 and cgroup_quota_cpus > 0:
        effective_cpus = min(configured_cpus, float(cgroup_quota_cpus))
    elif configured_cpus > 0:
        effective_cpus = configured_cpus
    elif cgroup_quota_cpus > 0:
        effective_cpus = float(cgroup_quota_cpus)
    elif base_effective_cpus > 0:
        effective_cpus = base_effective_cpus
    else:
        effective_cpus = host_cpus
    if host_cpus > 0 and effective_cpus > host_cpus:
        effective_cpus = host_cpus
    cpu_pressure_sample_available = bool(
        is_running
        and (
            type(resources.get('cpu_percent')) in (int, float)
            or resources.get('cgroup_cpu_available') is True
            or report.get('cpu_pressure_sample_available') is True
            or effective_cpu_percent > 0
        )
    )
    report.update({
        'id': str(container.get('id') or ''),
        'stable_id': stable_id,
        'name': str(container.get('name') or ''),
        'image': str(container.get('image') or ''),
        'runtime': 'runman',
        'runtime_bin': 'runman',
        'project': 'default',
        'status': str(container.get('status') or 'unknown'),
        'instance_id': instance_id,
        'pid': str(container.get('pid') or ''),
        'pid_start_ticks': str(container.get('pid_start_ticks') or ''),
        'monitor_mode': 'runman_guest_exec' if base_report is not None else 'runman_inventory',
        'cpu_percent': effective_cpu_percent,
        'cpu_pressure_percent': effective_cpu_percent,
        'cpu_pressure_sample_available': cpu_pressure_sample_available,
        'cpu_effective_cpus': effective_cpus,
        'mem_bytes': max(0, mem_bytes),
        'mem_limit_bytes': max(0, mem_limit),
        'mem_percent': (100.0 * mem_bytes / mem_limit) if mem_limit > 0 else 0.0,
        'net_rx_bps': net_rx_bps,
        'net_tx_bps': net_tx_bps,
        'traffic_counters': {
            'available': traffic_valid,
            'rx': traffic_rx,
            'tx': traffic_tx,
            'source': 'runman',
            'epoch': f'{stable_id}:{instance_id}:runman',
        },
        'network_addresses': sorted(set(ips)),
        'conn_count': total_connections if metrics.get('valid') is True else int(report.get('conn_count') or 0),
        'udp_flow_count': (
            int(raw_metrics['udp_flows'])
            if metrics_available and type(raw_metrics.get('udp_flows')) in (int, float)
            else int(report.get('udp_flow_count') or 0)
        ),
        'tcp_country_stats': report.get('tcp_country_stats', []),
        'udp_country_stats': report.get('udp_country_stats', []),
        'disk': report.get('disk') or _call_agent("collect_disk_alert", None),
        'container_disk': container_disk,
        'top_cpu_process': top_cpu_process,
        'security': security,
        'runman_resources': resources,
        'instance_id': instance_id,
        'pid': str(container.get('pid') or ''),
        'pid_start_ticks': str(container.get('pid_start_ticks') or ''),
    })
    return report


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
        "disk": _call_agent("collect_disk_alert", None),
        "container_disk": _call_agent("collect_container_disk_usage", collect_container_disk_usage, 
            container.get("name", ""), runtime, "", include_layer_size=False
        ),
        "top_cpu_process": {"pid": 0, "cpu_percent": 0.0, "command": ""},
        "security": {"notice_only": True},
    }


def podman_containers() -> List[Dict[str, str]]:
    """Backward-compatible alias for callers using the old function name."""
    return _call_agent("list_containers", list_containers, )




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
    runtime = runtime or _call_agent("get_container_bin", get_container_bin, )
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
    if include_layer_size and _runtime_kind(runtime) not in {"incus", "runman"}:
        inspect = _call_agent("run", run, [runtime, "container", "inspect", "--size", name])
        if inspect:
            try:
                item = json.loads(inspect)[0]
                rw_bytes = int(item.get("SizeRw") or 0)
                rootfs_bytes = int(item.get("SizeRootFs") or 0)
            except Exception:
                pass

    fs_df = _call_agent("run", run, _call_agent("_runtime_exec_cmd", _runtime_exec_cmd, runtime, name, "df -P / /data 2>/dev/null || true", project))
    fs = {
        "root": _parse_df_target(fs_df, "/"),
        "data": _parse_df_target(fs_df, "/data"),
    }
    return {"rw_bytes": rw_bytes, "rootfs_bytes": rootfs_bytes, "fs": fs}


def _incus_instance_pid(runtime: str, name: str, project: str = "") -> int:
    path = f"/1.0/instances/{quote(name, safe='')}/state"
    if project:
        path += f"?project={quote(project, safe='')}"
    output = _call_agent("run", run, [runtime, "query", path])
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
    all_metrics = metrics_snapshot if metrics_snapshot is not None else _call_agent("_get_incus_metrics", _get_incus_metrics, runtime)
    metrics = all_metrics.get((project or "default", name), {})
    cpu_seconds = float(metrics.get("cpu_seconds", 0.0) or 0.0)
    container_key = f"incus:{project or 'default'}:{name}"
    cpu_percent = _call_agent("_derive_cpu_percent", _derive_cpu_percent, container_key, cpu_seconds)
    mem_bytes = int(metrics.get("mem_bytes", 0.0) or 0)
    mem_limit = int(metrics.get("mem_total_bytes", 0.0) or 0)
    mem_percent = (float(mem_bytes) / float(mem_limit)) * 100.0 if mem_limit > 0 else 0.0
    return {
        "cpu_percent": cpu_percent,
        "cpu_effective_cpus": float(metrics.get("effective_cpus", 0.0) or 0.0),
        "cpu_sample_available": cpu_seconds > 0,
        "mem_bytes": mem_bytes,
        "mem_limit_bytes": mem_limit,
        "mem_percent": mem_percent,
        "net_rx_total_bytes": int(metrics.get("net_rx_total_bytes", 0.0) or 0),
        "net_tx_total_bytes": int(metrics.get("net_tx_total_bytes", 0.0) or 0),
        "net_rx_total_packets": int(metrics.get("net_rx_total_packets", 0.0) or 0),
        "net_tx_total_packets": int(metrics.get("net_tx_total_packets", 0.0) or 0),
    }


