"""Conservative, reversible CPU protection for Incus and Podman containers.

The guard only limits one container at a time, after sustained container CPU
saturation coincides with high host CPU utilization. It never stops a process or
container, and it restores the exact saved runtime CPU setting after sustained
recovery. State is persisted before runtime changes so an agent restart can
resume verification and restoration safely.
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


STATE_PATH = os.getenv("NARWHAL_CPU_GUARD_STATE", "/var/lib/narwhal-agent/cpu-guard.json")
_host_cpu_previous: tuple[int, int, int, float] | None = None


def _finite_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


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


def _read_state(path: str) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            state = json.load(stream)
    except (OSError, ValueError, TypeError):
        return {"schema": 1, "instances": {}}
    if not isinstance(state, dict) or state.get("schema") != 1 or not isinstance(state.get("instances"), dict):
        return {"schema": 1, "instances": {}}
    return state


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
    prefix = [runtime]
    if os.path.basename(runtime) == "incus" and project:
        prefix.extend(["--project", project])
    return prefix + args


def _identity(container: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    runtime = str(container.get("runtime") or "").strip().lower()
    if runtime not in {"incus", "podman"}:
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
    key = "|".join((runtime, project, stable_id))
    return runtime, project, name, stable_id, key


def _read_limit(runtime: str, binary: str, project: str, name: str) -> tuple[dict[str, Any] | str | None, str]:
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
        return max(0.0, effective_cpus)
    quota = int(limit.get("cpu_quota") or 0)
    period = int(limit.get("cpu_period") or 0)
    return quota / period if quota > 0 and period > 0 else max(0.0, effective_cpus)


def _half_limit(
    runtime: str, limit: dict[str, Any] | str, effective_cpus: float, cpu_percent: float
) -> tuple[dict[str, Any] | str | None, float]:
    ratio = min(0.75, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_TARGET_RATIO", "0.5"), 0.5)))
    measured_cpus = max(0.0, _finite_number(cpu_percent, 0.0)) / 100.0
    if runtime == "incus":
        value = str(limit or "").strip().lower()
        hard = re.fullmatch(r"\s*(\d+(?:\.\d+)?)ms\s*/\s*(\d+(?:\.\d+)?)ms\s*", value)
        baseline = float(hard.group(1)) / float(hard.group(2)) if hard and float(hard.group(2)) > 0 else effective_cpus
        baseline = min(baseline, measured_cpus)
        if baseline <= 0:
            return None, 0.0
        if hard:
            period = max(1, int(float(hard.group(2))))
            quota = max(1, int(baseline * ratio * period))
            return f"{quota}ms/{period}ms", quota / period
        quota = max(1, int(baseline * ratio * 100))
        return f"{quota}ms/100ms", quota / 100.0
    quota = int(limit.get("cpu_quota") or 0)
    period = int(limit.get("cpu_period") or 0)
    if int(limit.get("nano_cpus") or 0) > 0:
        return None, 0.0
    if period <= 0:
        period = 100_000
    baseline = min(quota / period if quota > 0 else effective_cpus, measured_cpus)
    if baseline <= 0:
        return None, 0.0
    applied_quota = max(1000, int(baseline * ratio * period))
    if applied_quota >= baseline * period:
        return None, 0.0
    return {
        "cpu_quota": applied_quota,
        "cpu_period": period,
        "nano_cpus": int(limit.get("nano_cpus") or 0),
        "cpuset_cpus": str(limit.get("cpuset_cpus") or ""),
    }, applied_quota / period


def _matches(runtime: str, current: dict[str, Any] | str | None, expected: dict[str, Any] | str) -> bool:
    if runtime == "incus":
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
    if runtime == "incus":
        return str(value or "未设置（继承/default）")
    quota = int(value.get("cpu_quota") or 0) if isinstance(value, dict) else 0
    period = int(value.get("cpu_period") or 0) if isinstance(value, dict) else 0
    return f"{quota}/{period}" if quota > 0 and period > 0 else "不限额"


def _set_limit(runtime: str, binary: str, project: str, name: str, value: dict[str, Any] | str) -> tuple[bool, str]:
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


def _restore_limit(runtime: str, binary: str, project: str, name: str, value: dict[str, Any] | str) -> tuple[bool, str]:
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
    action: dict[str, Any], instance_id: str, error: str = "",
) -> dict[str, Any]:
    limited = action.get("succeeded") is True
    restore_failed = action.get("restore_succeeded") is False
    top_process = process if isinstance(process, dict) else {}
    if error:
        message = "主机与容器 CPU 指标已连续达到保护条件，但节点未能确认 CPU 限额已生效；没有停止进程或容器。"
    elif restore_failed:
        message = "容器 CPU 已回落，但原配额未能恢复；临时保护限额仍在生效，需要管理员检查。"
    else:
        message = "容器 CPU 已连续达到保护条件，系统已临时降低该容器 CPU 配额；没有停止进程或容器。" if limited else "容器 CPU 已连续达到保护条件，但未能确认临时 CPU 配额生效；没有停止进程或容器。"
    entry = {
        "type": "cpu_pressure_protection",
        "severity": "critical" if (not limited or restore_failed) else "warning",
        "title": "持续高 CPU，已启用临时保护" if limited and not restore_failed else "持续高 CPU，保护需要检查",
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
            "sample_count": high_samples,
            "required_samples": required_samples,
            "confirmed_duration_seconds": max(0, int(duration)),
            "threshold_percent_of_container_capacity": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "90"), 90), 2),
            "threshold_percent_of_one_cpu": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "90"), 90), 2),
            "host_busy_threshold_percent": round(_finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT", "80"), 80), 2),
            "top_process": top_process,
            "limit_applied": limited,
            "restore_failed": restore_failed,
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
    interval = max(60.0, _finite_number(interval_seconds, 300.0))
    high_threshold = min(99.0, max(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_SATURATION_PERCENT", "90"), 90.0)))
    host_threshold = min(99.0, max(50.0, _finite_number(os.getenv("CPU_AUTO_LIMIT_HOST_BUSY_PERCENT", "80"), 80.0)))
    recovery_ratio = min(0.8, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_RATIO", "0.5"), 0.5)))
    required_duration = max(600, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_REQUIRED_SECONDS", "600"), 600)))
    min_samples = max(3, int(math.ceil(required_duration / interval)) + 1)
    max_gap = max(180, int(interval * 2.5))
    recovery_samples = max(2, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RECOVERY_SAMPLES", "2"), 2)))
    retry_seconds = max(300, int(_finite_number(os.getenv("CPU_AUTO_LIMIT_RETRY_SECONDS", "600"), 600)))
    path = state_path or STATE_PATH
    state = _read_state(path)
    instances = state["instances"]
    seen: set[str] = set()
    candidates: list[tuple[float, dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    alerts: list[dict[str, Any]] = []
    active_keys: set[str] = set()
    host_busy = _finite_number(host_cpu.get("busy_percent"), -1.0) if host_cpu.get("status") == "ready" else -1.0

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
        effective_cpus = _finite_number(container.get("cpu_effective_cpus"), 0.0)
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        container["security"] = security
        record = instances.get(key)

        if isinstance(record, dict) and record.get("stage") in {"applying", "active", "restoring", "restore_failed", "apply_unverified", "manual_override"}:
            current, read_error = _read_limit(runtime, binary, project, name)
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
                    instance_id=instance_id))
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
                if record.get("stage") != "candidate" and 0 <= ratio <= recovery_ratio:
                    record["low_samples"] = int(record.get("low_samples") or 0) + 1
                elif record.get("stage") != "candidate":
                    record["low_samples"] = 0
                if record.get("stage") != "candidate" and int(record.get("low_samples") or 0) >= recovery_samples:
                    record["stage"] = "restoring"
                    try:
                        _write_state(path, state)
                    except OSError as exc:
                        record["stage"] = "restore_failed"
                        record["last_error"] = f"无法持久化恢复计划：{exc}"[:400]
                    else:
                        restored, restore_output = _restore_limit(runtime, binary, project, name, original)
                        after, after_error = _read_limit(runtime, binary, project, name)
                        if restored and not after_error and _matches(runtime, after, original):
                            instances.pop(key, None)
                            active_keys.discard(key)
                            security["cpu_guard"] = {"state": "restored", "message": "容器 CPU 使用已连续恢复正常，原 CPU 配置已还原。"}
                            continue
                        record["stage"] = "restore_failed"
                        record["last_error"] = (restore_output or after_error or "恢复配置读回不一致")[:400]

                if record.get("stage") == "candidate":
                    # The limit was not applied; continue accumulating valid
                    # samples and retry only after the configured backoff.
                    record["low_samples"] = 0
                else:
                    process = record.get("top_process") if isinstance(record.get("top_process"), dict) else {}
                    status = {
                        "state": "limited" if record.get("stage") == "active" else "restore_failed",
                        "original_limit": _format_limit(runtime, original),
                        "active_limit": _format_limit(runtime, applied),
                        "applied_at": int(record.get("applied_at") or timestamp),
                        "low_samples": int(record.get("low_samples") or 0),
                        "recovery_samples_required": recovery_samples,
                        "current_cpu_percent": round(metrics_cpu, 2) if metrics_cpu >= 0 else None,
                        "current_cpu_saturation_percent": round(max(0.0, ratio) * 100.0, 2),
                        "trigger_basis": record.get("trigger_basis"),
                        "top_process": process,
                        "reason_is_user_abuse": False,
                    }
                    security["cpu_guard"] = status
                    message = "CPU 限额仍在生效；原配置会在容器 CPU 持续恢复后自动还原。"
                    if record.get("stage") == "restore_failed":
                        message = "CPU 已恢复正常但原配置还原失败，当前保护限额仍保留，需管理员检查。"
                    alerts.append(_alert(alert_type="cpu_pressure_protection", container=container, host_cpu=host_cpu,
                        cpu_percent=metrics_cpu, effective_cpus=max(0.0, effective_cpus),
                        high_samples=int(record.get("high_samples") or min_samples),
                        required_samples=min_samples,
                        duration=max(0, timestamp - int(record.get("high_since") or timestamp)),
                        process=process,
                        action={"attempted": True, "succeeded": True, "restore_succeeded": record.get("stage") != "restore_failed", "message": message,
                                "original_limit": _format_limit(runtime, original), "active_limit": _format_limit(runtime, applied)},
                        instance_id=instance_id,
                        threshold_percent=_finite_number(record.get("trigger_threshold_percent"), max(0.0, effective_cpus * high_threshold))))
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
        qualifies = (
            (saturation * 100.0 >= high_threshold or per_core_pressure)
            and host_busy >= host_threshold
            and effective_cpus > 0
            and host_cpu.get("status") == "ready"
        )
        if qualifies:
            previous_high = int(candidate.get("last_high") or 0)
            if previous_high <= 0 or timestamp <= previous_high or timestamp - previous_high > max_gap:
                candidate["high_samples"] = 1
                candidate["high_since"] = timestamp
            else:
                candidate["high_samples"] = int(candidate.get("high_samples") or 0) + 1
            candidate["last_high"] = timestamp
            ratio = saturation
            candidates.append((metrics_cpu, container, candidate, {"binary": binary, "runtime": runtime,
                "project": project, "name": name, "instance_id": instance_id, "effective_cpus": effective_cpus,
                "cpu_percent": metrics_cpu,
                "trigger_basis": "one_cpu" if per_core_pressure else "configured_capacity"}))
            instances[key] = candidate
            security["cpu_guard"] = {
                "state": "watching", "high_samples": int(candidate.get("high_samples") or 0),
                "required_samples": min_samples,
                "confirmed_duration_seconds": max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                "container_cpu_percent": round(metrics_cpu, 2),
                "effective_cpus": round(effective_cpus, 3),
                "host_busy_percent": host_busy,
                "host_iowait_percent": host_cpu.get("iowait_percent"),
                "host_busy_threshold_percent": host_threshold,
                "threshold_percent_of_container_capacity": high_threshold,
                "threshold_percent_of_one_cpu": high_threshold,
                "trigger_basis": "one_cpu" if per_core_pressure else "configured_capacity",
                "reason_is_user_abuse": False,
            }
        else:
            instances.pop(key, None)
            security["cpu_guard"] = {
                "state": "sampling_unavailable" if not sample_available else "normal" if saturation < high_threshold / 100.0 else "waiting_for_host_pressure",
                "container_cpu_percent": round(metrics_cpu, 2) if metrics_cpu >= 0 else None,
                "effective_cpus": round(max(0.0, effective_cpus), 3),
                "host_busy_percent": host_cpu.get("busy_percent"),
                "threshold_percent_of_container_capacity": high_threshold,
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

    already_limited = bool(active_keys)
    ready_candidates = [item for item in candidates if
        int(item[2].get("high_samples") or 0) >= min_samples
        and timestamp - int(item[2].get("high_since") or timestamp) >= required_duration
    ]
    if not already_limited and ready_candidates:
        ready_candidates.sort(key=lambda item: item[0], reverse=True)
        _, container, candidate, identity = ready_candidates[0]
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
            current, error = _read_limit(runtime, binary, project, name)
            result_action = {"attempted": True, "succeeded": False,
                "message": "CPU 限额操作处于安全重试间隔；本次未重复修改配置。"}
            current_limit = current
            action_error = error
        else:
            original, read_error = _read_limit(runtime, binary, project, name)
            applied, applied_cpus = _half_limit(
                runtime, original, identity["effective_cpus"], identity["cpu_percent"]
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
                    "last_attempt": timestamp, "low_samples": 0,
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
                    before_apply, before_error = _read_limit(runtime, binary, project, name)
                    if before_error or not _matches(runtime, before_apply, original):
                        record["stage"] = "apply_unverified" if before_error else "manual_override"
                        record["last_error"] = (before_error or "检测到管理员在保护执行前更改 CPU 配额；保留人工设置")[:400]
                        result_action = {"attempted": True, "succeeded": False,
                            "message": "执行前 CPU 配额与已保存的原设置不一致；系统没有覆盖该设置。"}
                        action_error = record["last_error"]
                    else:
                        applied_ok, apply_output = _set_limit(runtime, binary, project, name, applied)
                        current_limit, read_error = _read_limit(runtime, binary, project, name)
                        if applied_ok and not read_error and _matches(runtime, current_limit, applied):
                            record["stage"] = "active"
                            record["applied_at"] = timestamp
                            record["last_error"] = ""
                            active_keys.add(identity["runtime"] + "|" + identity["project"] + "|" + instance_id)
                            result_action = {"attempted": True, "succeeded": True,
                                "action_type": "set_cpu_quota",
                                "message": "已读回确认硬 CPU 配额降至原有效配额的一半；没有停止进程或容器。",
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
        container_security = container.get("security") if isinstance(container.get("security"), dict) else {}
        container_security["cpu_guard"] = {
            "state": "limited" if result_action.get("succeeded") is True else "limit_failed",
            "high_samples": int(candidate.get("high_samples") or 0),
            "required_samples": min_samples,
            "confirmed_duration_seconds": max(0, timestamp - int(candidate.get("high_since") or timestamp)),
            "container_cpu_percent": round(cpu_now, 2),
            "effective_cpus": round(effective_now, 3),
            "host_busy_percent": host_cpu.get("busy_percent"),
            "host_iowait_percent": host_cpu.get("iowait_percent"),
            "host_busy_threshold_percent": host_threshold,
            "threshold_percent_of_one_cpu": high_threshold,
            "trigger_basis": identity.get("trigger_basis"),
            "top_process": process,
            "reason_is_user_abuse": False,
            "action": result_action,
        }
        alerts.append(_alert(alert_type=alert_type, container=container, host_cpu=host_cpu,
            cpu_percent=cpu_now, effective_cpus=effective_now,
            threshold_percent=(high_threshold if cpu_now >= high_threshold else effective_now * high_threshold),
            high_samples=int(candidate.get("high_samples") or 0),
            required_samples=min_samples,
            duration=max(0, timestamp - int(candidate.get("high_since") or timestamp)),
            process=process, action=result_action, instance_id=instance_id,
            error=action_error))
        # The local runtime action and restore state are durable before any network notification.

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
            "required_duration_seconds": required_duration,
            "required_samples": min_samples,
            "target_cpu_ratio": min(0.75, max(0.1, _finite_number(os.getenv("CPU_AUTO_LIMIT_TARGET_RATIO", "0.5"), 0.5))),
            "recovery_ratio_of_limited_capacity": recovery_ratio,
            "recovery_samples": recovery_samples,
            "max_simultaneous_container_limits": 1,
        },
        "host_cpu": host_cpu,
        "alerts": alerts,
    }
    return summary
