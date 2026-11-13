"""Conservative, reversible CPU protection for Incus, Podman, and Runman containers.

The guard limits runaway or contending containers after sustained container/host
CPU saturation is confirmed. It supports multi-container contention capping on
low-core hosts, never stops a process or container, and restores the exact saved
runtime CPU setting after sustained recovery. State is persisted before runtime
changes so an agent restart can resume verification and restoration safely.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import time
import uuid
from typing import Any, Callable

try:
    from client.resource_cgroup import resolve_container_cgroup
except ImportError:
    from resource_cgroup import resolve_container_cgroup


STATE_PATH = os.getenv("NARWHAL_CPU_GUARD_STATE", "/var/lib/narwhal-agent/cpu-guard.json")
_host_cpu_previous: tuple[int, int, int, float] | None = None


def _finite_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _psi_avg10(psi: Any, resource: str) -> float | None:
    if not isinstance(psi, dict):
        return None
    sample = psi.get(resource)
    if not isinstance(sample, dict) or sample.get("status") != "ready":
        return None
    some = sample.get("some")
    if not isinstance(some, dict):
        return None
    value = _finite_number(some.get("avg10"), -1.0)
    return value if value >= 0 else None


def _host_cpu_pressure(
    host_cpu: dict[str, Any], busy_threshold: float, psi_threshold: float,
) -> tuple[bool, float | None, str]:
    """Confirm host CPU contention with PSI, falling back only when PSI is absent."""
    busy = _finite_number(host_cpu.get("busy_percent"), -1.0)
    if host_cpu.get("status") != "ready" or busy < busy_threshold:
        return False, _psi_avg10(host_cpu.get("psi"), "cpu"), "host_busy_below_threshold"
    psi_some = _psi_avg10(host_cpu.get("psi"), "cpu")
    if psi_some is None:
        return True, None, "host_busy_psi_unavailable_fallback"
    if psi_some < psi_threshold:
        return False, psi_some, "host_psi_below_threshold"
    return True, psi_some, "host_busy_and_psi_confirmed"


def _container_cpu_pressure_confirmed(
    container: dict[str, Any],
    host_cpu: dict[str, Any],
    metrics_cpu: float,
    effective_cpus: float,
    saturation: float,
    high_threshold: float,
    host_threshold: float,
    host_psi_threshold: float,
    host_pressure_confirmed: bool,
    host_pressure_basis: str,
) -> tuple[bool, str, bool]:
    """Confirm whether container + host CPU saturation warrants CPU guard tracking/protection.

    On 1-core hosts (e.g. 1 vCPU VPS like JINX) or when a single runaway container
    pins CPU at 85-100%, kernel `/proc/pressure/cpu` `some avg10` can stay below 5%
    when no other runnable host threads are competing on the runqueue, even though
    the container has saturated host CPU capacity.
    """
    if host_cpu.get("status") != "ready":
        return False, host_pressure_basis, False
    busy = _finite_number(host_cpu.get("busy_percent"), -1.0)
    logical_cpus = max(1, int(_finite_number(host_cpu.get("logical_cpus"), float(os.cpu_count() or 1))))
    load_1m = _finite_number(host_cpu.get("load_1m"), -1.0)
    runaway_threshold = min(99.0, max(85.0, high_threshold))
    is_runaway = bool(
        metrics_cpu >= runaway_threshold
        and (
            saturation * 100.0 >= runaway_threshold
            or metrics_cpu >= logical_cpus * 75.0
            or (logical_cpus <= 1 and metrics_cpu >= runaway_threshold)
        )
    )
    if host_pressure_confirmed:
        return True, host_pressure_basis, is_runaway
    if busy < host_threshold:
        return False, host_pressure_basis, False
    security = container.get("security") if isinstance(container.get("security"), dict) else {}
    res_pressure = security.get("resource_pressure") if isinstance(security.get("resource_pressure"), dict) else {}
    cgroup_psi = res_pressure.get("container") if isinstance(res_pressure.get("container"), dict) else {}
    cgroup_cpu_psi = _psi_avg10(cgroup_psi, "cpu")
    if cgroup_cpu_psi is not None and cgroup_cpu_psi >= host_psi_threshold:
        return True, "host_busy_and_container_psi_confirmed", is_runaway
    if logical_cpus <= 1 and busy >= max(host_threshold, 85.0) and (
        metrics_cpu >= runaway_threshold or saturation * 100.0 >= runaway_threshold
    ):
        return True, "single_core_host_cpu_saturation", True
    if busy >= max(host_threshold, 85.0) and metrics_cpu >= max(runaway_threshold, logical_cpus * 75.0):
        return True, "host_dominant_container_cpu_saturation", True
    if (
        (busy >= max(95.0, host_threshold) or (busy >= max(host_threshold, 85.0) and load_1m >= float(logical_cpus)))
        and is_runaway
    ):
        return True, "host_extreme_busy_runaway_container", True
    return False, host_pressure_basis, False


def _read_psi(path: str) -> dict[str, Any]:
    """Read Linux PSI averages without treating absent kernel support as zero pressure."""
    result: dict[str, Any] = {}
    try:
        with open(path, "r", encoding="ascii", errors="ignore") as stream:
            lines = stream.readlines()
    except OSError as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    for line in lines[:2]:
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        values: dict[str, float | int] = {}
        for field in fields[1:]:
            key, sep, raw = field.partition("=")
            if not sep or key not in {"avg10", "avg60", "avg300", "total"}:
                continue
            try:
                parsed = int(raw) if key == "total" else float(raw)
                if math.isfinite(float(parsed)) and parsed >= 0:
                    values[key] = parsed
            except (ValueError, OverflowError):
                continue
        if "avg10" in values:
            result[fields[0]] = values
    if not result:
        return {"status": "unsupported", "reason": "PSI 数据不可用或格式不受支持"}
    return {"status": "ready", **result}


def _host_psi() -> dict[str, Any]:
    return {resource: _read_psi(f"/proc/pressure/{resource}")
            for resource in ("cpu", "memory", "io")}


def _container_psi(container: dict[str, Any]) -> dict[str, Any]:
    target, error = resolve_container_cgroup(
        container.get("pid"),
        container.get("runtime"),
        container.get("stable_id") or container.get("id"),
        container.get("name"),
        expected_start_ticks=(str(container.get("pid_start_ticks") or "") if container.get("runtime") == "runman" else ""),
    )
    if target is None:
        return {"status": "unavailable", "reason": error}
    resources = {resource: _read_psi(str(target / f"{resource}.pressure"))
                 for resource in ("cpu", "memory", "io")}
    available = [value for value in resources.values() if value.get("status") == "ready"]
    if not available:
        return {"status": "unsupported", "reason": "当前内核或 cgroup 未提供 PSI 文件", **resources}
    missing = [name for name, value in resources.items() if value.get("status") != "ready"]
    reason = "" if not missing else "部分 cgroup PSI 文件不可用：" + "、".join(missing)
    return {"status": "ready" if not missing else "partial", "reason": reason, **resources}


def _resource_pressure(container: dict[str, Any], host_pressure: dict[str, Any]) -> dict[str, Any]:
    cgroup = _container_psi(container)
    cpu_percent = _finite_number(container.get("cpu_pressure_percent"), -1.0)
    cgroup_cpu = cgroup.get("cpu") if isinstance(cgroup.get("cpu"), dict) else {}
    host_cpu = host_pressure.get("cpu") if isinstance(host_pressure.get("cpu"), dict) else {}
    cgroup_some = cgroup_cpu.get("some") if isinstance(cgroup_cpu.get("some"), dict) else {}
    host_some = host_cpu.get("some") if isinstance(host_cpu.get("some"), dict) else {}
    cgroup_wait = _finite_number(cgroup_some.get("avg10"), -1.0)
    host_wait = _finite_number(host_some.get("avg10"), -1.0)
    if cpu_percent >= 80 and cgroup_wait >= 0 and cgroup_wait < 1:
        classification = "active_compute_low_wait"
        explanation = "容器 CPU 正忙，但近 10 秒 CPU 等待压力低；更像持续计算负载，而非明显排队争用。"
    elif cgroup_wait >= 10 and host_wait >= 10:
        classification = "host_and_container_cpu_contention"
        explanation = "宿主机与该容器都出现明显 CPU 等待；存在主机级 CPU 争用或配额排队。"
    elif cgroup_wait >= 10:
        classification = "container_cpu_contention"
        explanation = "该容器出现明显 CPU 等待；可能受配额限制或同机任务争用。"
    else:
        classification = "insufficient_pressure_evidence"
        explanation = "当前 PSI 样本不足以判断资源争用；PSI 是等待压力证据，不表示进程身份或用户归属。"
    return {"status": cgroup.get("status", "unavailable"), "classification": classification,
            "explanation": explanation, "host": host_pressure, "container": cgroup}


def sample_host_cpu() -> dict[str, Any]:
    """Return host-wide CPU busy percent over the interval between agent reports."""
    global _host_cpu_previous
    now = time.monotonic()
    result: dict[str, Any] = {
        "available": False,
        "status": "unavailable",
        "busy_percent": None,
        "iowait_percent": None,
        "logical_cpus": max(1, int(os.cpu_count() or 1)),
        "load_1m": None,
        "sample_seconds": 0.0,
        "psi": _host_psi(),
    }
    try:
        with open("/proc/stat", "r", encoding="ascii", errors="ignore") as stream:
            first = stream.readline().split()
        values = [int(value) for value in first[1:9]]
        if len(values) < 5:
            return result
        total = sum(values)
        idle = values[3] + values[4]
        iowait = values[4]
        busy = max(0, total - idle)
    except (OSError, ValueError, IndexError):
        return result
    try:
        load = os.getloadavg()[0]
        result["load_1m"] = round(max(0.0, float(load)), 3)
    except (AttributeError, OSError, ValueError):
        pass
    previous = _host_cpu_previous
    _host_cpu_previous = (total, busy, iowait, now)
    if previous is None:
        result["status"] = "warming"
        return result
    delta_total = total - previous[0]
    delta_busy = busy - previous[1]
    elapsed = max(0.0, now - previous[3])
    if delta_total <= 0 or elapsed < 1.0:
        result["status"] = "warming"
        return result
    delta_iowait = max(0, iowait - previous[2])
    result.update(
        available=True,
        status="ready",
        busy_percent=round(max(0.0, min(100.0, delta_busy * 100.0 / delta_total)), 2),
        iowait_percent=round(max(0.0, min(100.0, delta_iowait * 100.0 / delta_total)), 2),
        sample_seconds=round(elapsed, 2),
    )
    return result


def _read_state(path: str) -> tuple[dict[str, Any], str]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            state = json.load(stream)
    except FileNotFoundError:
        return {"schema": 1, "instances": {}}, ""
    except (OSError, ValueError, TypeError) as exc:
        return {"schema": 1, "instances": {}}, f"CPU protection state is unreadable ({type(exc).__name__}); no new automatic limit will be applied."
    if not isinstance(state, dict) or state.get("schema") != 1 or not isinstance(state.get("instances"), dict):
        return {"schema": 1, "instances": {}}, "CPU protection state format is invalid; no new automatic limit will be applied."
    return state, ""


def _write_state(path: str, state: dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temp_path = os.path.join(directory, f".cpu-guard-{os.getpid()}-{uuid.uuid4().hex}.tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            os.chmod(temp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _run(runtime: str, args: list[str], timeout: float = 20.0) -> tuple[int, str]:
    env = None
    if os.path.basename(runtime) == "podman-remote":
        socket_path = os.getenv("PODMAN_SOCKET", "/run/podman/podman.sock")
        if "CONTAINER_HOST" not in os.environ and os.path.exists(socket_path):
            env = os.environ.copy()
            env["CONTAINER_HOST"] = f"unix://{socket_path}"
    try:
        result = subprocess.run([runtime, *args], capture_output=True, text=True, env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)[:500]
    output = (result.stdout or result.stderr or "").strip()
    return int(result.returncode), output[:4000]


def _runtime_args(runtime: str, project: str, args: list[str]) -> list[str]:
    prefix: list[str] = []
    if os.path.basename(runtime) == "incus" and project:
        prefix.extend(["--project", project])
    return prefix + args


def _identity(container: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    runtime = str(container.get("runtime") or "").strip().lower()
    if runtime not in {"incus", "podman", "runman"}:
        return None
    name = str(container.get("name") or "").strip()
    project = str(container.get("project") or "default").strip()
    stable_id = str(container.get("stable_id") or container.get("id") or "").strip()
    if not name or not stable_id or len(name) > 200 or len(stable_id) > 256:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", name):
        return None
    if project and not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
        return None
    generation = str(container.get("instance_id") or "").strip() if runtime == "runman" else stable_id
    if runtime == "runman" and not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", generation):
        return None
    key = "|".join((runtime, project, generation))
    return runtime, project, name, generation, key


def _runman_cpu_cgroup(container: dict[str, Any] | None) -> tuple[Any, str]:
    if not isinstance(container, dict):
        return None, "Runman 资源限额缺少容器身份"
    target, error = resolve_container_cgroup(
        container.get("pid"), "runman", container.get("stable_id") or container.get("id"),
        container.get("name"), expected_start_ticks=str(container.get("pid_start_ticks") or ""),
    )
    if target is None:
        return None, error or "Runman 资源 cgroup 无法确认"
    return target, ""


def _runman_effective_cpus_from_cgroup(target: Any, host_logical: float) -> float:
    """Resolve effective Runman CPUs from /ct/cpu.max, falling back to parent unit cpu.max."""
    for candidate_dir in (target, getattr(target, "parent", None)):
        if candidate_dir is None:
            continue
        try:
            raw = (candidate_dir / "cpu.max").read_text(encoding="ascii").strip()
        except OSError:
            continue
        match = re.fullmatch(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", raw)
        if not match:
            continue
        quota, period = match.groups()
        if quota != "max":
            return min(host_logical, int(quota) / int(period))
    return host_logical


def _valid_runman_cpu_max(value: str) -> bool:
    match = re.fullmatch(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", str(value or "").strip())
    if not match:
        return False
    quota, period = match.groups()
    return 1000 <= int(period) <= 1_000_000 and (quota == "max" or 1000 <= int(quota) <= 1_000_000_000)


def _read_limit(runtime: str, binary: str, project: str, name: str, container: dict[str, Any] | None = None) -> tuple[dict[str, Any] | str | None, str]:
    if runtime == "runman":
        target, error = _runman_cpu_cgroup(container)
        if target is None:
            return None, error
        try:
            value = (target / "cpu.max").read_text(encoding="ascii").strip()
        except OSError as exc:
            return None, f"无法读取 Runman cpu.max（{type(exc).__name__}）"
        return (value, "") if _valid_runman_cpu_max(value) else (None, "Runman cpu.max 格式无法确认")
    if runtime == "incus":
        code, output = _run(binary, _runtime_args(binary, project, ["config", "get", name, "limits.cpu.allowance"]))
        if code != 0:
            return None, output or "无法读取 Incus 本地 CPU allowance"
        return output.strip(), ""
    # Read only the CPU fields. A full inspect includes environment variables
    # and other customer data that this guard does not need.
    code, output = _run(binary, ["inspect", "--format", "{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.CpusetCpus}}", name])
    if code != 0:
        return None, output or "无法读取 Podman CPU quota"
    try:
        values = output.split("|")
        if len(values) != 4:
            raise ValueError("missing CPU fields")
        quota, period, nano_cpus = (int(value) for value in values[:3])
        return {
            "cpu_quota": quota,
            "cpu_period": period,
            "nano_cpus": nano_cpus,
            "cpuset_cpus": values[3].strip(),
        }, ""
    except (TypeError, ValueError, IndexError, OverflowError):
        return None, "Podman inspect 未返回可验证的 CPU quota"


def _limit_cpus(runtime: str, limit: dict[str, Any] | str, effective_cpus: float) -> float:
    if runtime == "incus":
        value = str(limit or "").strip().lower()
        hard = re.fullmatch(r"\s*(\d+(?:\.\d+)?)ms\s*/\s*(\d+(?:\.\d+)?)ms\s*", value)
        if hard:
            quota, period = float(hard.group(1)), float(hard.group(2))
            return quota / period if period > 0 else 0.0
        pct = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*%\s*", value)
        if pct and effective_cpus > 0:
            return max(0.0, effective_cpus * (float(pct.group(1)) / 100.0))
        return max(0.0, effective_cpus)
    if runtime == "runman":
        match = re.fullmatch(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", str(limit or "").strip())
        if not match:
            return 0.0
        quota, period = match.groups()
        return max(0.0, effective_cpus) if quota == "max" else int(quota) / int(period)
    quota = int(limit.get("cpu_quota") or 0)
    period = int(limit.get("cpu_period") or 0)
    return quota / period if quota > 0 and period > 0 else max(0.0, effective_cpus)


def _target_limit(
    runtime: str,
    limit: dict[str, Any] | str,
    effective_cpus: float,
    target_cpus: float | None = None,
) -> tuple[dict[str, Any] | str | None, float]:
    ratio = min(0.75, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_TARGET_RATIO", "0.5"), 0.5)))
    available_cpus = max(0.0, _finite_number(effective_cpus, 0.0))
    if runtime == "incus":
        value = str(limit or "").strip().lower()
        hard = re.fullmatch(r"\s*(\d+(?:\.\d+)?)ms\s*/\s*(\d+(?:\.\d+)?)ms\s*", value)
        pct = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*%\s*", value)
        if hard and float(hard.group(2)) > 0:
            configured_cpus = float(hard.group(1)) / float(hard.group(2))
        elif pct and available_cpus > 0:
            configured_cpus = available_cpus * (float(pct.group(1)) / 100.0)
        else:
            configured_cpus = available_cpus
        baseline = min(configured_cpus, available_cpus) if available_cpus > 0 else configured_cpus
        if baseline <= 0:
            return None, 0.0
        desired_cpus = baseline * ratio
        if target_cpus is not None and target_cpus > 0:
            desired_cpus = min(desired_cpus, max(0.1, float(target_cpus)))
        if hard:
            period = max(1, int(float(hard.group(2))))
            quota = max(1, int(desired_cpus * period))
            return f"{quota}ms/{period}ms", quota / period
        quota = max(1, int(desired_cpus * 100))
        return f"{quota}ms/100ms", quota / 100.0
    if runtime == "runman":
        match = re.fullmatch(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", str(limit or "").strip())
        if not match:
            return None, 0.0
        quota, period = match.groups()
        period_value = int(period)
        configured = int(quota) / period_value if quota != "max" else available_cpus
        baseline = min(configured, available_cpus) if available_cpus > 0 else configured
        if baseline <= 0:
            return None, 0.0
        desired_cpus = baseline * ratio
        if target_cpus is not None and target_cpus > 0:
            desired_cpus = min(desired_cpus, max(0.1, float(target_cpus)))
        applied_quota = max(1000, int(desired_cpus * period_value))
        if quota != "max" and applied_quota >= int(quota):
            return None, 0.0
        return f"{applied_quota} {period_value}", applied_quota / period_value
    quota = int(limit.get("cpu_quota") or 0)
    period = int(limit.get("cpu_period") or 0)
    if int(limit.get("nano_cpus") or 0) > 0:
        return None, 0.0
    if period <= 0:
        period = 100_000
    configured_cpus = quota / period if quota > 0 else available_cpus
    baseline = min(configured_cpus, available_cpus) if available_cpus > 0 else configured_cpus
    if baseline <= 0:
        return None, 0.0
    desired_cpus = baseline * ratio
    if target_cpus is not None and target_cpus > 0:
        desired_cpus = min(desired_cpus, max(0.1, float(target_cpus)))
    applied_quota = max(1000, int(desired_cpus * period))
    if applied_quota >= baseline * period:
        return None, 0.0
    return {
        "cpu_quota": applied_quota,
        "cpu_period": period,
        "nano_cpus": int(limit.get("nano_cpus") or 0),
        "cpuset_cpus": str(limit.get("cpuset_cpus") or ""),
    }, applied_quota / period


def _half_limit(
    runtime: str, limit: dict[str, Any] | str, effective_cpus: float
) -> tuple[dict[str, Any] | str | None, float]:
    return _target_limit(runtime, limit, effective_cpus, target_cpus=None)


def _scale_limit(runtime: str, value: dict[str, Any] | str, ratio: float) -> tuple[dict[str, Any] | str | None, float]:
    """Tighten an already confirmed hard CPU limit while preserving its period."""
    ratio = min(0.9, max(0.1, _finite_number(ratio, 0.5)))
    if runtime == "incus":
        hard = re.fullmatch(r"\s*(\d+(?:\.\d+)?)ms\s*/\s*(\d+(?:\.\d+)?)ms\s*", str(value or "").strip().lower())
        if not hard:
            return None, 0.0
        quota, period = float(hard.group(1)), float(hard.group(2))
        if quota <= 0 or period <= 0:
            return None, 0.0
        next_quota = max(1, int(math.floor(quota * ratio)))
        if next_quota >= quota:
            return None, 0.0
        return f"{next_quota}ms/{max(1, int(period))}ms", next_quota / period
    if runtime == "runman":
        match = re.fullmatch(r"([1-9][0-9]*) ([1-9][0-9]*)", str(value or "").strip())
        if not match:
            return None, 0.0
        quota, period = (int(item) for item in match.groups())
        next_quota = max(1000, int(math.floor(quota * ratio)))
        if next_quota >= quota:
            return None, 0.0
        return f"{next_quota} {period}", next_quota / period
    if not isinstance(value, dict):
        return None, 0.0
    quota = int(value.get("cpu_quota") or 0)
    period = int(value.get("cpu_period") or 0)
    if quota <= 0 or period <= 0 or int(value.get("nano_cpus") or 0) > 0:
        return None, 0.0
    next_quota = max(1000, int(math.floor(quota * ratio)))
    if next_quota >= quota:
        return None, 0.0
    return {
        "cpu_quota": next_quota,
        "cpu_period": period,
        "nano_cpus": 0,
        "cpuset_cpus": str(value.get("cpuset_cpus") or ""),
    }, next_quota / period


def _matches(runtime: str, current: dict[str, Any] | str | None, expected: dict[str, Any] | str) -> bool:
    if runtime in {"incus", "runman"}:
        return str(current or "").strip() == str(expected or "").strip()
    if not isinstance(current, dict) or not isinstance(expected, dict):
        return False
    if int(current.get("cpu_quota") or 0) != int(expected.get("cpu_quota") or 0):
        return False
    if int(current.get("nano_cpus") or 0) != int(expected.get("nano_cpus") or 0):
        return False
    if str(current.get("cpuset_cpus") or "").strip() != str(expected.get("cpuset_cpus") or "").strip():
        return False
    expected_period = int(expected.get("cpu_period") or 0)
    return expected_period <= 0 or int(current.get("cpu_period") or 0) == expected_period


def _format_limit(runtime: str, value: dict[str, Any] | str) -> str:
    if runtime in {"incus", "runman"}:
        return str(value or "未设置（继承/default）")
    quota = int(value.get("cpu_quota") or 0) if isinstance(value, dict) else 0
    period = int(value.get("cpu_period") or 0) if isinstance(value, dict) else 0
    return f"{quota}/{period}" if quota > 0 and period > 0 else "不限额"


def _set_limit(runtime: str, binary: str, project: str, name: str, value: dict[str, Any] | str, container: dict[str, Any] | None = None) -> tuple[bool, str]:
    if runtime == "runman":
        if not isinstance(value, str) or not _valid_runman_cpu_max(value):
            return False, "Runman cpu.max 限值格式无效"
        target, error = _runman_cpu_cgroup(container)
        if target is None:
            return False, error
        try:
            (target / "cpu.max").write_text(value, encoding="ascii")
            return True, ""
        except OSError as exc:
            return False, f"写入 Runman cpu.max 失败（{type(exc).__name__}）"
    if runtime == "incus":
        code, output = _run(binary, _runtime_args(binary, project, ["config", "set", name, "limits.cpu.allowance", str(value)]))
        return code == 0, output
    quota = int(value.get("cpu_quota") or 0)
    period = int(value.get("cpu_period") or 0)
    args = ["update", f"--cpu-quota={quota}"]
    if period > 0:
        args.append(f"--cpu-period={period}")
    args.append(name)
    code, output = _run(binary, args)
    return code == 0, output


def _restore_limit(runtime: str, binary: str, project: str, name: str, value: dict[str, Any] | str, container: dict[str, Any] | None = None) -> tuple[bool, str]:
    if runtime == "runman":
        if not isinstance(value, str) or not _valid_runman_cpu_max(value):
            return False, "Runman 原始 cpu.max 限值格式无效"
        target, error = _runman_cpu_cgroup(container)
        if target is None:
            return False, error
        try:
            (target / "cpu.max").write_text(value, encoding="ascii")
            return True, ""
        except OSError as exc:
            return False, f"恢复 Runman cpu.max 失败（{type(exc).__name__}）"
    if runtime == "incus":
        if str(value or "").strip():
            code, output = _run(binary, _runtime_args(binary, project, ["config", "set", name, "limits.cpu.allowance", str(value)]))
        else:
            code, output = _run(binary, _runtime_args(binary, project, ["config", "unset", name, "limits.cpu.allowance"]))
        return code == 0, output
    quota = int(value.get("cpu_quota") or 0) if isinstance(value, dict) else 0
    period = int(value.get("cpu_period") or 0) if isinstance(value, dict) else 0
    args = ["update", f"--cpu-quota={quota}"]
    if period > 0:
        args.append(f"--cpu-period={period}")
    args.append(name)
    code, output = _run(binary, args)
    return code == 0, output


def _alert(
    *, alert_type: str, container: dict[str, Any], host_cpu: dict[str, Any],
    cpu_percent: float, effective_cpus: float, threshold_percent: float,
    high_samples: int, required_samples: int, duration: int, process: dict[str, Any],
    action: dict[str, Any], instance_id: str, error: str = "", tier: int = 1,
) -> dict[str, Any]:
    watching_only = action.get("watching") is True or action.get("attempted") is False
    limited = action.get("succeeded") is True
    restore_failed = action.get("restore_succeeded") is False
    top_process = process if isinstance(process, dict) else {}
    clean_error = str(error or "").strip()
    if watching_only and not clean_error:
        message = str(action.get("message") or "检测到容器 CPU 持续异常高占用，已采样高占用进程并进入自动限额保护观察窗口；没有停止进程或容器。")
        severity = "warning"
        title = "持续高 CPU，正在监测并准备限额保护"
    elif clean_error:
        message = f"主机与容器 CPU 指标已连续达到保护条件，但节点未能确认 CPU 限额生效（{clean_error}）；没有停止进程或容器。"
        severity = "critical"
        title = "持续高 CPU，保护需要检查"
    elif restore_failed:
        message = "容器 CPU 已回落，但原配额未能恢复；临时保护限额仍在生效，需要管理员检查。"
        severity = "critical"
        title = "持续高 CPU，保护需要检查"
    else:
        message = "容器 CPU 已连续达到保护条件，系统已临时降低该容器 CPU 配额；没有停止进程或容器。" if limited else "容器 CPU 已连续达到保护条件，但未能确认临时 CPU 配额生效；没有停止进程或容器。"
        severity = "critical" if not limited else "warning"
        title = "持续高 CPU，已启用临时保护" if limited else "持续高 CPU，保护需要检查"
    pressure_basis = str(action.get("pressure_basis") or "") or _host_cpu_pressure(
        host_cpu,
        min(99.0, max(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT", "80"), 80))),
        min(50.0, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_PSI_PERCENT", "5"), 5))),
    )[2]
    entry = {
        "type": "cpu_pressure_protection",
        "severity": severity,
        "title": title,
        "message": message,
        "value": round(cpu_percent, 2) if cpu_percent >= 0 else None,
        "threshold": round(threshold_percent, 2) if effective_cpus > 0 else None,
        "runtime": str(container.get("runtime") or ""),
        "project": str(container.get("project") or ""),
        "container_name": str(container.get("name") or ""),
        "alert_key": "cpu-pressure:" + instance_id[:200],
        "instance_id": instance_id[:200],
        "ongoing_protection": True,
        "cpu_guard": {
            "container_cpu_percent": round(cpu_percent, 2) if cpu_percent >= 0 else None,
            "cpu_sample_available": cpu_percent >= 0,
            "effective_cpus": round(effective_cpus, 3),
            "host_busy_percent": host_cpu.get("busy_percent"),
            "host_iowait_percent": host_cpu.get("iowait_percent"),
            "host_logical_cpus": host_cpu.get("logical_cpus"),
            "host_load_1m": host_cpu.get("load_1m"),
            "host_psi": host_cpu.get("psi"),
            "host_cpu_psi_some_avg10": _psi_avg10(host_cpu.get("psi"), "cpu"),
            "host_cpu_psi_threshold_percent": round(min(50.0, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_PSI_PERCENT", "5"), 5))), 2),
            "host_pressure_basis": pressure_basis,
            "resource_pressure": (container.get("security") or {}).get("resource_pressure") if isinstance(container.get("security"), dict) else None,
            "sample_count": high_samples,
            "required_samples": required_samples,
            "confirmed_duration_seconds": max(0, int(duration)),
            "threshold_percent_of_container_capacity": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "65"), 65), 2),
            "threshold_percent_of_one_cpu": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "65"), 65), 2),
            "host_busy_threshold_percent": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT", "80"), 80), 2),
            "top_process": top_process,
            "limit_applied": limited,
            "tier": max(1, min(3, int(tier or 1))) if limited else 0,
            "tier_percent_of_original": {1: 50, 2: 25, 3: 10}.get(max(1, min(3, int(tier or 1)))) if limited else None,
            "restore_failed": restore_failed,
            "last_error": clean_error,
            "reason_is_user_abuse": False,
        },
        "automatic_remediation": action,
    }
    return entry


def observe(
    containers: list[dict[str, Any]],
    host_cpu: dict[str, Any],
    interval_seconds: float,
    runtime_bins: dict[str, str],
    process_sampler: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    *,
    allow_new_limits: bool = True,
    now: int | None = None,
    state_path: str | None = None,
) -> dict[str, Any]:
    """Update persistent CPU protection state, apply/release one quota, and emit alerts."""
    cpu_auto_enabled = os.getenv("SECURITY_CPU_AUTO_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    allow_new_limits = allow_new_limits and cpu_auto_enabled
    timestamp = int(time.time()) if now is None else int(now)
    interval = max(30.0, _finite_number(interval_seconds, 300.0))
    high_threshold = min(99.0, max(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "65"), 65.0)))
    host_threshold = min(99.0, max(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT", "80"), 80.0)))
    recovery_ratio = min(0.8, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_RATIO", "0.5"), 0.5)))
    recovery_host_threshold = min(99.0, max(0.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_HOST_BUSY_PERCENT", "70"), 70.0)))
    host_psi_threshold = min(50.0, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_PSI_PERCENT", "5"), 5.0)))
    recovery_host_psi_threshold = min(host_psi_threshold, max(0.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_HOST_PSI_PERCENT", "2"), 2.0)))
    required_duration = max(600, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_REQUIRED_SECONDS", "600"), 600)))
    escalation_duration = max(300, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_ESCALATION_SECONDS", "300"), 300)))
    recovery_duration = max(600, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_SECONDS", "600"), 600)))
    min_samples = max(3, int(math.ceil(required_duration / interval)) + 1)
    max_gap = max(180, int(interval * 2.5))
    escalation_samples = max(2, int(math.ceil(escalation_duration / interval)) + 1)
    recovery_samples = max(3, int(math.ceil(recovery_duration / interval)) + 1,
                           int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_SAMPLES", "3"), 3)))
    retry_seconds = max(300, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RETRY_SECONDS", "600"), 600)))
    cooldown_seconds = max(300, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_COOLDOWN_SECONDS", "900"), 900)))
    path = state_path or STATE_PATH
    state, state_error = _read_state(path)
    allow_new_limits = allow_new_limits and not state_error
    instances = state["instances"]
    seen: set[str] = set()
    candidates: list[tuple[float, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    alerts: list[dict[str, Any]] = []
    active_keys: set[str] = set()
    host_busy = _finite_number(host_cpu.get("busy_percent"), -1.0) if host_cpu.get("status") == "ready" else -1.0
    logical_cpus = max(1, int(_finite_number(host_cpu.get("logical_cpus"), float(os.cpu_count() or 1))))
    load_1m = _finite_number(host_cpu.get("load_1m"), -1.0)
    host_pressure_confirmed, host_cpu_psi, host_pressure_basis = _host_cpu_pressure(
        host_cpu, host_threshold, host_psi_threshold
    )
    host_contention_confirmed = bool(
        host_cpu.get("status") == "ready"
        and host_busy >= host_threshold
        and (
            host_pressure_confirmed
            or (host_busy >= max(host_threshold, 85.0) and load_1m >= float(logical_cpus))
            or host_busy >= 95.0
        )
    )
    default_contention_min = "8.0" if logical_cpus <= 1 else ("10.0" if logical_cpus <= 2 else "15.0")
    contention_min_cpu = max(5.0, min(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_CONTENTION_MIN_CPU_PERCENT", default_contention_min), float(default_contention_min))))
    contending_cpus: list[float] = []
    for item in containers:
        if not isinstance(item, dict) or not _identity(item):
            continue
        item_avail = item.get("cpu_pressure_sample_available") is True
        item_cpu = _finite_number(item.get("cpu_pressure_percent"), -1.0) if item_avail else -1.0
        if item_cpu < 0:
            item_fallback = _finite_number(item.get("cpu_percent"), -1.0)
            if item_fallback > 0:
                item_cpu = item_fallback
        if item_cpu >= contention_min_cpu:
            contending_cpus.append(item_cpu)
    multi_container_contention = bool(
        host_contention_confirmed
        and len(contending_cpus) >= 2
        and sum(contending_cpus) >= max(25.0, float(logical_cpus) * 25.0)
    )
    max_simultaneous_limits = max(
        1,
        int(_finite_number(os.getenv("CPU_AUTO_LIMIT_MAX_SIMULTANEOUS", str(max(2, logical_cpus * 4))), float(max(2, logical_cpus * 4)))),
    )

    for container in containers:
        if not isinstance(container, dict):
            continue
        ident = _identity(container)
        if not ident:
            continue
        runtime, project, name, instance_id, key = ident
        binary = str(container.get("runtime_bin") or runtime_bins.get(runtime) or runtime)
        seen.add(key)
        sample_available = container.get("cpu_pressure_sample_available") is True
        metrics_cpu = _finite_number(container.get("cpu_pressure_percent"), -1.0) if sample_available else -1.0
        if metrics_cpu < 0:
            fallback_cpu = _finite_number(container.get("cpu_percent"), -1.0)
            if fallback_cpu > 0:
                metrics_cpu = fallback_cpu
                sample_available = True
        effective_cpus = _finite_number(container.get("cpu_effective_cpus"), 0.0)
        if effective_cpus <= 0:
            host_logical = float(logical_cpus)
            if runtime == "runman":
                target, limit_err = _runman_cpu_cgroup(container)
                if not limit_err and target is not None:
                    effective_cpus = _runman_effective_cpus_from_cgroup(target, host_logical)
            if effective_cpus <= 0:
                effective_cpus = host_logical
            container["cpu_effective_cpus"] = effective_cpus
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        container["security"] = security
        security["resource_pressure"] = _resource_pressure(container, host_cpu.get("psi") or {})
        record = instances.get(key)

        if isinstance(record, dict) and record.get("stage") == "cooldown":
            remaining = max(0, int(record.get("cooldown_until") or 0) - timestamp)
            if remaining:
                security["cpu_guard"] = {
                    "state": "cooldown", "retry_after_seconds": remaining,
                    "message": f"CPU 保护刚恢复，冷却中；约 {remaining} 秒后重新评估。",
                    "reason_is_user_abuse": False,
                }
                continue
            instances.pop(key, None)
            record = None

        if isinstance(record, dict) and record.get("stage") in {"applying", "escalating", "active", "restoring", "restore_failed", "apply_unverified", "manual_override"}:
            current, read_error = _read_limit(runtime, binary, project, name, container)
            original = record.get("original")
            applied = record.get("applied")
            if read_error or current is None:
                record["last_error"] = (read_error or "CPU quota readback unavailable")[:400]
                record["last_seen"] = timestamp
                status = {"state": "limited_unverified", "message": "无法读取当前 CPU 配置，保留现有设置并继续核验。"}
                security["cpu_guard"] = status
                active_keys.add(key)
                failed_action = {"attempted": True, "succeeded": False,
                    "message": "节点曾执行 CPU 限额；当前无法读回验证，系统不会更改未知的运行配置。"}
                alerts.append(_alert(alert_type="cpu_pressure_protection", container=container, host_cpu=host_cpu,
                    cpu_percent=metrics_cpu, effective_cpus=max(0.0, effective_cpus),
                    threshold_percent=max(0.0, effective_cpus * high_threshold),
                    high_samples=int(record.get("high_samples") or min_samples),
                    required_samples=min_samples,
                    duration=max(0, timestamp - int(record.get("high_since") or timestamp)),
                    process=record.get("top_process") or {},
                    action=failed_action,
                    instance_id=instance_id,
                    error=record["last_error"]))
                continue

            if record.get("stage") == "applying":
                if _matches(runtime, current, applied):
                    record["stage"] = "active"
                    record["applied_at"] = int(record.get("applied_at") or timestamp)
                    record["last_error"] = ""
                elif _matches(runtime, current, original):
                    # The agent may have restarted between persisting the
                    # intent and applying the quota. Retain evidence and retry
                    # only after the normal backoff.
                    record["stage"] = "candidate"
                    record["last_attempt"] = int(record.get("last_attempt") or timestamp)
                    record["last_seen"] = timestamp
                    instances[key] = record
                else:
                    record["stage"] = "manual_override"
                    record["last_error"] = "CPU 配置在操作期间变为其他值；不覆盖人工设置"
                    record["last_seen"] = timestamp
                    security["cpu_guard"] = {"state": "manual_override", "message": record["last_error"]}
                    continue

            if isinstance(record, dict) and record.get("stage") == "escalating":
                pending = record.get("pending_applied")
                if _matches(runtime, current, pending):
                    record["applied"] = pending
                    record["applied_cpus"] = _finite_number(record.get("pending_applied_cpus"), 0.0)
                    record["tier"] = int(record.get("pending_tier") or int(record.get("tier") or 1) + 1)
                    record["stage"] = "active"
                    record["pending_applied"] = None
                    record["last_step_at"] = timestamp
                    record["last_error"] = ""
                elif _matches(runtime, current, applied):
                    # The write was not confirmed. Keep the old enforced tier
                    # and require a fresh full escalation window before retrying.
                    record["stage"] = "active"
                    record["pending_applied"] = None
                    record["last_escalation_attempt"] = timestamp
                    record["escalation_high_samples"] = 0
                    record["escalation_high_since"] = 0
                    record["escalation_last_high"] = 0
                else:
                    record["stage"] = "manual_override"
                    record["last_error"] = "CPU 配置在阶梯限额期间变为其他值；不覆盖人工设置"
                    record["last_seen"] = timestamp
                    security["cpu_guard"] = {"state": "manual_override", "message": record["last_error"]}
                    continue
                applied = record.get("applied")

            if isinstance(record, dict) and record.get("stage") == "manual_override":
                if _matches(runtime, current, original):
                    instances.pop(key, None)
                    security["cpu_guard"] = {"state": "manual_reset", "message": "管理员已还原原 CPU 设置；本轮不重新应用限制。"}
                else:
                    record["last_seen"] = timestamp
                    security["cpu_guard"] = {"state": "manual_override", "message": "检测到人工更改 CPU 配置，系统保留该配置。"}
                continue

            if isinstance(record, dict) and record.get("stage") == "apply_unverified" and _matches(runtime, current, original):
                record["stage"] = "candidate"
                record["last_attempt"] = timestamp
                record["last_seen"] = timestamp
                instances[key] = record

            if isinstance(record, dict) and record.get("stage") in {"active", "restoring", "restore_failed", "apply_unverified"}:
                if _matches(runtime, current, original):
                    if record.get("stage") == "apply_unverified":
                        record["stage"] = "candidate"
                        record["last_attempt"] = timestamp
                        record["last_seen"] = timestamp
                        instances[key] = record
                    else:
                        instances.pop(key, None)
                        security["cpu_guard"] = {"state": "restored", "message": "原 CPU 配置已恢复。"}
                        continue
                elif not _matches(runtime, current, applied):
                    record["stage"] = "manual_override"
                    record["last_seen"] = timestamp
                    security["cpu_guard"] = {"state": "manual_override", "message": "检测到人工更改 CPU 配置，系统保留该配置。"}
                    continue
                if record.get("stage") == "candidate":
                    # A write attempt was not confirmed; carry the sustained
                    # observations forward and honor the retry backoff.
                    pass
                else:
                    record["stage"] = "active"
                    active_keys.add(key)
                record["last_seen"] = timestamp
                applied_cpus = max(0.001, _finite_number(record.get("applied_cpus"), effective_cpus * 0.5))
                ratio = metrics_cpu / (applied_cpus * 100.0) if metrics_cpu >= 0 else -1.0
                tier = max(1, min(3, int(record.get("tier") or 1)))
                active_pressure_confirmed, active_pressure_basis, _ = _container_cpu_pressure_confirmed(
                    container,
                    host_cpu,
                    metrics_cpu,
                    applied_cpus,
                    max(0.0, ratio),
                    high_threshold,
                    host_threshold,
                    host_psi_threshold,
                    host_pressure_confirmed,
                    host_pressure_basis,
                )
                high_now = (
                    record.get("stage") == "active"
                    and ratio * 100.0 >= high_threshold
                    and (active_pressure_confirmed or ratio >= 0.90)
                )
                if high_now and tier < 3:
                    last_high = int(record.get("escalation_last_high") or 0)
                    if last_high <= 0 or timestamp <= last_high or timestamp - last_high > max_gap:
                        record["escalation_high_since"] = timestamp
                        record["escalation_high_samples"] = 1
                    else:
                        record["escalation_high_samples"] = int(record.get("escalation_high_samples") or 0) + 1
                    record["escalation_last_high"] = timestamp
                    high_since = int(record.get("escalation_high_since") or timestamp)
                    step_ratio = 0.5 if tier == 1 else 0.4
                    target, target_cpus = _scale_limit(runtime, applied, step_ratio)
                    if (target is not None and target_cpus > 0
                            and int(record.get("escalation_high_samples") or 0) >= escalation_samples
                            and timestamp - high_since >= escalation_duration
                            and timestamp - int(record.get("last_step_at") or record.get("applied_at") or timestamp) >= escalation_duration):
                        record["stage"] = "escalating"
                        record["pending_applied"] = target
                        record["pending_applied_cpus"] = target_cpus
                        record["pending_tier"] = tier + 1
                        try:
                            _write_state(path, state)
                        except OSError as exc:
                            record["stage"] = "active"
                            record["pending_applied"] = None
                            record["last_error"] = f"无法持久化下一阶 CPU 限额：{exc}"[:300]
                        else:
                            before, before_error = _read_limit(runtime, binary, project, name, container)
                            if before_error or not _matches(runtime, before, applied):
                                record["stage"] = "manual_override"
                                record["last_error"] = before_error or "CPU 配额在阶梯保护执行前发生人工更改；未覆盖。"
                            else:
                                changed, change_output = _set_limit(runtime, binary, project, name, target, container)
                                after, after_error = _read_limit(runtime, binary, project, name, container)
                                if changed and not after_error and _matches(runtime, after, target):
                                    record["applied"] = target
                                    record["applied_cpus"] = target_cpus
                                    record["tier"] = tier + 1
                                    record["stage"] = "active"
                                    record["pending_applied"] = None
                                    record["last_step_at"] = timestamp
                                    record["escalation_high_samples"] = 0
                                    record["escalation_high_since"] = 0
                                    record["last_error"] = ""
                                    applied = target
                                    applied_cpus = target_cpus
                                    ratio = metrics_cpu / (applied_cpus * 100.0) if metrics_cpu >= 0 else -1.0
                                    tier += 1
                                elif not after_error and _matches(runtime, after, applied):
                                    record["stage"] = "active"
                                    record["pending_applied"] = None
                                    record["last_escalation_attempt"] = timestamp
                                    record["escalation_high_samples"] = 0
                                    record["escalation_high_since"] = 0
                                    record["escalation_last_high"] = 0
                                    record["last_error"] = change_output or "下一阶 CPU 配额未生效；保留当前已确认限额。"
                                else:
                                    # Leave the durable intent for the next
                                    # report to reconcile against actual state.
                                    record["last_error"] = change_output or after_error or "下一阶 CPU 配额等待读回确认。"
                else:
                    record["escalation_high_samples"] = 0
                    record["escalation_high_since"] = 0
                    record["escalation_last_high"] = 0

                recovering = (
                    record.get("stage") in {"active", "restore_failed"}
                    and 0 <= ratio <= recovery_ratio
                    and host_cpu.get("status") == "ready"
                    and host_busy < recovery_host_threshold
                    and (host_cpu_psi is None or host_cpu_psi < recovery_host_psi_threshold)
                )
                if record.get("stage") != "candidate" and recovering:
                    if not int(record.get("low_since") or 0):
                        record["low_since"] = timestamp
                    record["low_samples"] = int(record.get("low_samples") or 0) + 1
                elif record.get("stage") != "candidate":
                    record["low_samples"] = 0
                    record["low_since"] = 0
                if (record.get("stage") != "candidate"
                        and int(record.get("low_samples") or 0) >= recovery_samples
                        and timestamp - int(record.get("low_since") or timestamp) >= recovery_duration):
                    record["stage"] = "restoring"
                    try:
                        _write_state(path, state)
                    except OSError as exc:
                        record["stage"] = "restore_failed"
                        record["last_error"] = f"无法持久化恢复计划：{exc}"[:400]
                    else:
                        restored, restore_output = _restore_limit(runtime, binary, project, name, original, container)
                        after, after_error = _read_limit(runtime, binary, project, name, container)
                        if restored and not after_error and _matches(runtime, after, original):
                            instances[key] = {"stage": "cooldown", "cooldown_until": timestamp + cooldown_seconds,
                                              "last_seen": timestamp, "restored_at": timestamp}
                            active_keys.discard(key)
                            security["cpu_guard"] = {"state": "restored", "cooldown_until": timestamp + cooldown_seconds,
                                                      "message": "容器 CPU 使用已持续恢复，原 CPU 配置已读回确认；进入冷却期后再重新评估。"}
                            continue
                        record["stage"] = "restore_failed"
                        record["last_error"] = (restore_output or after_error or "恢复配置读回不一致")[:400]

                if record.get("stage") == "candidate":
                    # The limit was not applied; continue accumulating valid
                    # samples and retry only after the configured backoff.
                    record["low_samples"] = 0
                else:
                    if record.get("stage") == "manual_override":
                        security["cpu_guard"] = {"state": "manual_override", "message": record.get("last_error") or "检测到人工更改 CPU 配置；系统保留该配置。"}
                        continue
                    process = record.get("top_process") if isinstance(record.get("top_process"), dict) else {}
                    expected_applied = record.get("pending_applied") if record.get("stage") == "escalating" else applied
                    readback_confirmed = not read_error and current is not None and _matches(runtime, current, expected_applied)
                    if readback_confirmed:
                        record["readback_confirmed_at"] = timestamp
                    status = {
                        "state": "limited" if record.get("stage") == "active" else "limit_unverified" if record.get("stage") == "escalating" else "restore_failed",
                        "original_limit": _format_limit(runtime, original),
                        "active_limit": _format_limit(runtime, applied),
                        "expected_limit": _format_limit(runtime, expected_applied),
                        "actual_limit": _format_limit(runtime, current),
                        "readback_confirmed": readback_confirmed,
                        "readback_confirmed_at": int(record.get("readback_confirmed_at") or record.get("last_step_at") or record.get("applied_at") or timestamp) if readback_confirmed else 0,
                        "tier": tier,
                        "tier_percent_of_original": {1: 50, 2: 25, 3: 10}.get(tier),
                        "applied_at": int(record.get("applied_at") or timestamp),
                        "recheck_interval_seconds": int(interval),
                        "low_samples": int(record.get("low_samples") or 0),
                        "recovery_samples_required": recovery_samples,
                        "recovery_duration_seconds": recovery_duration,
                        "recovery_elapsed_seconds": max(0, timestamp - int(record.get("low_since") or timestamp)) if int(record.get("low_samples") or 0) else 0,
                        "current_cpu_percent": round(metrics_cpu, 2) if metrics_cpu >= 0 else None,
                        "current_cpu_saturation_percent": round(max(0.0, ratio) * 100.0, 2),
                        "host_busy_percent": host_busy,
                        "host_cpu_psi_some_avg10": host_cpu_psi,
                        "host_cpu_psi_threshold_percent": host_psi_threshold,
                        "host_pressure_basis": host_pressure_basis,
                        "escalation_samples": int(record.get("escalation_high_samples") or 0),
                        "escalation_required_samples": escalation_samples,
                        "escalation_duration_seconds": max(0, timestamp - int(record.get("escalation_high_since") or timestamp)),
                        "trigger_basis": record.get("trigger_basis"),
                        "top_process": process,
                        "reason_is_user_abuse": False,
                    }
                    security["cpu_guard"] = status
                    message = f"CPU 第 {tier} 阶保护限额仍在生效（约为原有效 CPU 容量的 {status['tier_percent_of_original']}%）；容器 CPU 与主机压力持续恢复后自动还原。"
                    if record.get("stage") == "restore_failed":
                        message = "CPU 已恢复正常但原配置还原失败，当前保护限额仍保留，需管理员检查。"
                    if record.get("stage") == "escalating":
                        message = record.get("last_error") or "下一阶 CPU 限额正在等待运行时读回确认；系统保留已确认限额。"
                    succeeded = record.get("stage") == "active"
                    alerts.append(_alert(alert_type="cpu_pressure_protection", container=container, host_cpu=host_cpu,
                        cpu_percent=metrics_cpu, effective_cpus=max(0.0, effective_cpus),
                        high_samples=int(record.get("high_samples") or min_samples),
                        required_samples=min_samples,
                        duration=max(0, timestamp - int(record.get("high_since") or timestamp)),
                        process=process,
                        action={"attempted": True, "succeeded": succeeded, "restore_succeeded": record.get("stage") != "restore_failed", "message": message,
                                "original_limit": _format_limit(runtime, original), "active_limit": _format_limit(runtime, applied), "tier": tier},
                        instance_id=instance_id,
                        threshold_percent=_finite_number(record.get("trigger_threshold_percent"), max(0.0, effective_cpus * high_threshold)),
                        error=record.get("last_error", "") if record.get("stage") != "active" else "", tier=tier))
                    continue

        if state_error:
            security["cpu_guard"] = {"state": "state_unavailable", "message": state_error, "reason_is_user_abuse": False}
            continue
        if not allow_new_limits:
            instances.pop(key, None)
            security["cpu_guard"] = {"state": "disabled", "reason_is_user_abuse": False}
            continue

        if isinstance(record, dict) and record.get("stage") == "candidate":
            candidate = record
        else:
            candidate = {"stage": "candidate", "high_samples": 0, "high_since": 0, "last_high": 0, "last_attempt": 0}
        saturation = metrics_cpu / (effective_cpus * 100.0) if metrics_cpu >= 0 and effective_cpus > 0 else -1.0
        per_core_pressure = metrics_cpu >= high_threshold
        pressure_confirmed, container_pressure_basis, is_runaway = _container_cpu_pressure_confirmed(
            container,
            host_cpu,
            metrics_cpu,
            effective_cpus,
            saturation,
            high_threshold,
            host_threshold,
            host_psi_threshold,
            host_pressure_confirmed,
            host_pressure_basis,
        )
        is_contention = bool(multi_container_contention and metrics_cpu >= contention_min_cpu)
        qualifies = (
            (
                ((saturation * 100.0 >= high_threshold or per_core_pressure) and pressure_confirmed)
                or is_contention
            )
            and effective_cpus > 0
            and host_cpu.get("status") == "ready"
        )
        if is_contention and not (saturation * 100.0 >= high_threshold or per_core_pressure):
            container_pressure_basis = host_pressure_basis if host_pressure_confirmed else "multi_container_host_cpu_contention"
        if qualifies:
            previous_high = int(candidate.get("last_high") or 0)
            if previous_high <= 0 or timestamp <= previous_high or timestamp - previous_high > max_gap:
                candidate["high_samples"] = 1
                candidate["high_since"] = timestamp
            else:
                candidate["high_samples"] = int(candidate.get("high_samples") or 0) + 1
            candidate["last_high"] = timestamp
            candidate["runaway"] = bool(is_runaway)
            candidate["contention"] = bool(is_contention)
            candidate["pressure_basis"] = container_pressure_basis
            if (is_runaway or is_contention) and "CPU_AUTO_LIMIT_REQUIRED_SECONDS" not in os.environ:
                runaway_duration = max(
                    120,
                    int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RUNAWAY_REQUIRED_SECONDS", "180"), 180)),
                )
                candidate_required_duration = min(required_duration, runaway_duration)
                candidate_min_samples = max(2, int(math.ceil(candidate_required_duration / interval)) + 1)
            else:
                candidate_required_duration = required_duration
                candidate_min_samples = min_samples
            candidate["required_duration"] = candidate_required_duration
            candidate["required_samples"] = candidate_min_samples
            if int(candidate.get("high_samples") or 0) >= 2:
                if process_sampler is not None and timestamp - int(candidate.get("last_process_sample") or 0) >= 300:
                    try:
                        sampled = process_sampler(container)
                        if isinstance(sampled, dict):
                            candidate["top_process"] = sampled
                            candidate["last_process_sample"] = timestamp
                    except Exception as exc:
                        candidate["top_process"] = {"available": False, "reason": str(exc)[:200]}
                if not isinstance(candidate.get("top_process"), dict) or not candidate["top_process"].get("available"):
                    fallback_top = container.get("top_cpu_process") if isinstance(container.get("top_cpu_process"), dict) else {}
                    if _finite_number(fallback_top.get("cpu_percent"), 0.0) > 0:
                        candidate["top_process"] = {
                            "available": True,
                            "source": "container_top_cpu_process",
                            "pid": int(fallback_top.get("pid") or 0),
                            "cpu_percent": round(_finite_number(fallback_top.get("cpu_percent"), 0.0), 2),
                            "process": str(fallback_top.get("command") or "").split()[0][:120] if str(fallback_top.get("command") or "").strip() else "unknown",
                            "command": str(fallback_top.get("command") or "")[:300],
                        }
            ratio = saturation
            candidates.append((metrics_cpu, container, candidate, {"binary": binary, "runtime": runtime,
                "project": project, "name": name, "instance_id": instance_id, "effective_cpus": effective_cpus,
                "cpu_percent": metrics_cpu,
                "pressure_basis": container_pressure_basis,
                "trigger_basis": "one_cpu" if per_core_pressure else "configured_capacity"}))
            instances[key] = candidate
            security["cpu_guard"] = {
                "state": "watching", "high_samples": int(candidate.get("high_samples") or 0),
                "required_samples": candidate_min_samples,
                "recheck_interval_seconds": int(interval),
                "confirmed_duration_seconds": max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                "container_cpu_percent": round(metrics_cpu, 2),
                "effective_cpus": round(effective_cpus, 3),
                "host_busy_percent": host_busy,
                "host_iowait_percent": host_cpu.get("iowait_percent"),
                "host_cpu_psi_some_avg10": host_cpu_psi,
                "host_cpu_psi_threshold_percent": host_psi_threshold,
                "host_pressure_basis": container_pressure_basis,
                "host_busy_threshold_percent": host_threshold,
                "threshold_percent_of_container_capacity": high_threshold,
                "threshold_percent_of_one_cpu": high_threshold,
                "trigger_basis": "one_cpu" if per_core_pressure else "configured_capacity",
                "top_process": candidate.get("top_process") if isinstance(candidate.get("top_process"), dict) else {},
                "reason_is_user_abuse": False,
            }
        else:
            if (
                (host_cpu.get("status") == "warming" or not sample_available)
                and int(candidate.get("high_samples") or 0) > 0
                and timestamp - int(candidate.get("last_high") or 0) <= max_gap
            ):
                instances[key] = candidate
            else:
                instances.pop(key, None)
            security["cpu_guard"] = {
                "state": "sampling_unavailable" if not sample_available or effective_cpus <= 0 or host_cpu.get("status") != "ready" else "normal" if saturation < high_threshold / 100.0 and not per_core_pressure else "waiting_for_host_psi" if host_busy >= host_threshold and host_cpu_psi is not None and host_cpu_psi < host_psi_threshold else "waiting_for_host_pressure",
                "container_cpu_percent": round(metrics_cpu, 2) if metrics_cpu >= 0 else None,
                "effective_cpus": round(max(0.0, effective_cpus), 3),
                "host_busy_percent": host_cpu.get("busy_percent"),
                "host_cpu_psi_some_avg10": host_cpu_psi,
                "host_cpu_psi_threshold_percent": host_psi_threshold,
                "host_pressure_basis": container_pressure_basis,
                "threshold_percent_of_container_capacity": high_threshold,
                "recheck_interval_seconds": int(interval),
                "reason_is_user_abuse": False,
            }

    # Candidate state is meaningful only for containers present in this complete inventory.
    for key in list(instances):
        record = instances.get(key)
        if key not in seen and isinstance(record, dict):
            if record.get("stage") == "candidate":
                instances.pop(key, None)
            elif timestamp - int(record.get("last_seen") or record.get("applied_at") or timestamp) > 30 * 86400:
                instances.pop(key, None)

    ready_candidates = [item for item in candidates if
        int(item[2].get("high_samples") or 0) >= int(item[2].get("required_samples") or min_samples)
        and timestamp - int(item[2].get("high_since") or timestamp) >= int(item[2].get("required_duration") or required_duration)
    ]
    limited_candidate_instance_ids: set[str] = set()
    remaining_slots = max(0, max_simultaneous_limits - len(active_keys))
    if remaining_slots > 0 and ready_candidates:
        ready_candidates.sort(key=lambda item: item[0], reverse=True)
        to_limit = ready_candidates[:remaining_slots]
        total_contending_limited = len(active_keys) + len(to_limit)
        fair_share_cpus = (
            max(0.15, (0.85 * float(logical_cpus)) / float(total_contending_limited))
            if total_contending_limited >= 2
            else None
        )
        for _, container, candidate, identity in to_limit:
            runtime, project, name = identity["runtime"], identity["project"], identity["name"]
            binary = identity["binary"]
            instance_id = identity["instance_id"]
            last_attempt = int(candidate.get("last_attempt") or 0)
            result_action: dict[str, Any]
            process: dict[str, Any] = {}
            if process_sampler is not None and timestamp - int(candidate.get("last_process_sample") or 0) >= 900:
                try:
                    sampled = process_sampler(container)
                    if isinstance(sampled, dict):
                        process = sampled
                        candidate["top_process"] = sampled
                        candidate["last_process_sample"] = timestamp
                except Exception as exc:
                    process = {"available": False, "reason": str(exc)[:200]}
            else:
                process = candidate.get("top_process") if isinstance(candidate.get("top_process"), dict) else {}

            if timestamp - last_attempt < retry_seconds:
                current, error = _read_limit(runtime, binary, project, name, container)
                result_action = {"attempted": True, "succeeded": False,
                    "message": "CPU 限额操作处于安全重试间隔；本次未重复修改配置。"}
                current_limit = current
                action_error = error
            else:
                original, read_error = _read_limit(runtime, binary, project, name, container)
                applied, applied_cpus = _target_limit(
                    runtime, original, identity["effective_cpus"], target_cpus=fair_share_cpus
                ) if original is not None else (None, 0.0)
                if read_error or original is None or applied is None or applied_cpus <= 0:
                    candidate["last_attempt"] = timestamp
                    candidate["last_error"] = (read_error or "没有安全的 CPU 配额基线")[:400]
                    action_error = candidate["last_error"]
                    result_action = {"attempted": True, "succeeded": False,
                        "message": "无法读取或计算可恢复的原 CPU 配置；为避免破坏现有设置，未修改容器。"}
                    current_limit = original
                else:
                    record = {
                        "stage": "applying", "runtime": runtime, "project": project,
                        "name": name, "instance_id": instance_id,
                        "original": original, "applied": applied,
                        "effective_cpus_before": identity["effective_cpus"],
                        "applied_cpus": applied_cpus,
                        "trigger_basis": identity.get("trigger_basis"),
                        "trigger_threshold_percent": high_threshold if identity.get("trigger_basis") == "one_cpu" else identity["effective_cpus"] * high_threshold,
                        "high_samples": int(candidate.get("high_samples") or 0),
                        "high_since": int(candidate.get("high_since") or timestamp),
                        "last_high": timestamp, "last_seen": timestamp,
                        "last_attempt": timestamp, "last_step_at": timestamp,
                        "tier": 1, "low_samples": 0, "low_since": 0,
                        "escalation_high_samples": 0, "escalation_high_since": 0,
                        "top_process": process, "applied_at": timestamp,
                    }
                    instances[identity["runtime"] + "|" + identity["project"] + "|" + instance_id] = record
                    try:
                        _write_state(path, state)
                    except OSError as exc:
                        instances.pop(identity["runtime"] + "|" + identity["project"] + "|" + instance_id, None)
                        candidate["last_attempt"] = timestamp
                        action_error = f"无法保存自动恢复状态：{exc}"[:400]
                        result_action = {"attempted": True, "succeeded": False,
                            "message": "无法可靠保存自动恢复状态；为避免留下无法还原的配额，未修改容器。"}
                        current_limit = original
                    else:
                        before_apply, before_error = _read_limit(runtime, binary, project, name, container)
                        if before_error or not _matches(runtime, before_apply, original):
                            record["stage"] = "apply_unverified" if before_error else "manual_override"
                            record["last_error"] = (before_error or "检测到管理员在保护执行前更改 CPU 配额；保留人工设置")[:400]
                            result_action = {"attempted": True, "succeeded": False,
                                "message": "执行前 CPU 配额与已保存的原设置不一致；系统没有覆盖该设置。"}
                            action_error = record["last_error"]
                        else:
                            applied_ok, apply_output = _set_limit(runtime, binary, project, name, applied, container)
                            current_limit, read_error = _read_limit(runtime, binary, project, name, container)
                            if applied_ok and not read_error and _matches(runtime, current_limit, applied):
                                record["stage"] = "active"
                                record["applied_at"] = timestamp
                                record["last_error"] = ""
                                active_keys.add(identity["runtime"] + "|" + identity["project"] + "|" + instance_id)
                                share_pct = round(max(1.0, (applied_cpus / max(0.01, identity["effective_cpus"])) * 100.0), 1)
                                result_action = {"attempted": True, "succeeded": True,
                                    "action_type": "set_cpu_quota",
                                    "message": f"已读回确认第一阶 CPU 保护限额生效（约为原有效 CPU 容量的 {share_pct:g}%）；没有停止进程或容器。",
                                    "original_limit": _format_limit(runtime, original),
                                    "active_limit": _format_limit(runtime, applied)}
                                action_error = ""
                            else:
                                record["stage"] = "apply_unverified"
                                record["last_error"] = (apply_output or read_error or "应用后的 CPU 配额读回不一致")[:400]
                                result_action = {"attempted": True, "succeeded": False,
                                    "message": "CPU 配额应用结果未通过读回确认；系统保留原配置记录并继续核验。"}
                                action_error = record["last_error"]
                        try:
                            _write_state(path, state)
                        except OSError as exc:
                            record["last_error"] = f"无法更新自动恢复状态：{exc}"[:400]
                            action_error = record["last_error"]
            alert_type = "cpu_pressure_protection"
            cpu_now = identity["cpu_percent"]
            effective_now = identity["effective_cpus"]
            limited_candidate_instance_ids.add(instance_id)
            result_action["pressure_basis"] = identity.get("pressure_basis") or host_pressure_basis
            req_samples_now = int(candidate.get("required_samples") or min_samples)
            container_security = container.get("security") if isinstance(container.get("security"), dict) else {}
            succeeded_now = result_action.get("succeeded") is True
            container_security["cpu_guard"] = {
                "state": "limited" if succeeded_now else "limit_failed",
                "original_limit": result_action.get("original_limit"),
                "active_limit": result_action.get("active_limit"),
                "expected_limit": result_action.get("active_limit"),
                "actual_limit": _format_limit(runtime, current_limit) if current_limit is not None else None,
                "readback_confirmed": succeeded_now,
                "readback_confirmed_at": timestamp if succeeded_now else 0,
                "applied_at": timestamp if succeeded_now else 0,
                "high_samples": int(candidate.get("high_samples") or 0),
                "required_samples": req_samples_now,
                "confirmed_duration_seconds": max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                "container_cpu_percent": round(cpu_now, 2),
                "effective_cpus": round(effective_now, 3),
                "host_busy_percent": host_cpu.get("busy_percent"),
                "host_iowait_percent": host_cpu.get("iowait_percent"),
                "host_busy_threshold_percent": host_threshold,
                "host_cpu_psi_some_avg10": host_cpu_psi,
                "host_cpu_psi_threshold_percent": host_psi_threshold,
                "host_pressure_basis": identity.get("pressure_basis") or host_pressure_basis,
                "threshold_percent_of_one_cpu": high_threshold,
                "tier": 1,
                "tier_percent_of_original": 50,
                "trigger_basis": identity.get("trigger_basis"),
                "top_process": process,
                "reason_is_user_abuse": False,
                "action": result_action,
            }
            alerts.append(_alert(alert_type=alert_type, container=container, host_cpu=host_cpu,
                cpu_percent=cpu_now, effective_cpus=effective_now,
                threshold_percent=(high_threshold if cpu_now >= high_threshold else effective_now * high_threshold),
                high_samples=int(candidate.get("high_samples") or 0),
                required_samples=req_samples_now,
                duration=max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                process=process, action=result_action, instance_id=instance_id,
                error=action_error, tier=1))
            # The local runtime action and restore state are durable before any network notification.

    for cpu_val, container, candidate, identity in candidates:
        cand_instance_id = identity["instance_id"]
        if cand_instance_id in limited_candidate_instance_ids:
            continue
        if (candidate.get("runaway") is True or candidate.get("contention") is True) and int(candidate.get("high_samples") or 0) >= 2:
            req_samples_cand = int(candidate.get("required_samples") or min_samples)
            req_duration_cand = int(candidate.get("required_duration") or required_duration)
            elapsed_cand = max(0, timestamp - int(candidate.get("high_since") or timestamp))
            process_cand = candidate.get("top_process") if isinstance(candidate.get("top_process"), dict) else {}
            watching_action = {
                "attempted": False,
                "succeeded": False,
                "watching": True,
                "pressure_basis": identity.get("pressure_basis") or host_pressure_basis,
                "message": (
                    f"检测到容器 CPU 持续异常高占用（{cpu_val:.1f}%），已连续确认 "
                    f"{int(candidate.get('high_samples') or 0)}/{req_samples_cand} 次采样"
                    f"（持续 {elapsed_cand}s / 阈值 {req_duration_cand}s），达到持续窗口后将自动应用 cgroup CPU 限额。"
                ),
            }
            alerts.append(_alert(
                alert_type="cpu_pressure_protection",
                container=container,
                host_cpu=host_cpu,
                cpu_percent=cpu_val,
                effective_cpus=identity["effective_cpus"],
                threshold_percent=(high_threshold if cpu_val >= high_threshold else identity["effective_cpus"] * high_threshold),
                high_samples=int(candidate.get("high_samples") or 0),
                required_samples=req_samples_cand,
                duration=elapsed_cand,
                process=process_cand,
                action=watching_action,
                instance_id=cand_instance_id,
                error="",
                tier=1,
            ))

    if not state_error:
        try:
            _write_state(path, state)
        except OSError as exc:
            print(f"cpu guard state could not be saved: {exc}")
    summary = {
        "enabled": cpu_auto_enabled and allow_new_limits,
        "limited_containers": len(active_keys),
        "limit_policy": {
            "container_saturation_percent": high_threshold,
            "one_cpu_usage_percent": high_threshold,
            "host_busy_percent": host_threshold,
            "host_cpu_psi_some_avg10_percent": host_psi_threshold,
            "required_duration_seconds": required_duration,
            "required_samples": min_samples,
            "target_cpu_ratio": min(0.75, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_TARGET_RATIO", "0.5"), 0.5))),
            "tier_percent_of_original": [50, 25, 10],
            "escalation_required_duration_seconds": escalation_duration,
            "escalation_required_samples": escalation_samples,
            "recovery_required_duration_seconds": recovery_duration,
            "recovery_ratio_of_limited_capacity": recovery_ratio,
            "recovery_host_busy_percent": recovery_host_threshold,
            "recovery_host_cpu_psi_some_avg10_percent": recovery_host_psi_threshold,
            "recovery_samples": recovery_samples,
            "max_simultaneous_container_limits": max_simultaneous_limits,
            "multi_container_contention": multi_container_contention,
            "contention_min_cpu_percent": contention_min_cpu,
            "cooldown_seconds": cooldown_seconds,
        },
        "host_cpu": host_cpu,
        "state_error": state_error,
        "alerts": alerts,
    }
    return summary
