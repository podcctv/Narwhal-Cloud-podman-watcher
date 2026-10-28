"""Fail-closed, reversible per-container cgroup v2 disk I/O protection.

The guard only writes ``io.max`` for a container cgroup after sustained host
device pressure and measured cgroup attribution. It does not stop workloads,
enable controllers, guess block devices, or overwrite a changed administrator
limit. Original per-device limits are persisted before any write.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any


STATE_PATH = os.getenv("NARWHAL_IO_GUARD_STATE", "/var/lib/narwhal-agent/io-guard.json")
CGROUP_ROOT = Path(os.getenv("NARWHAL_CGROUP_ROOT", "/sys/fs/cgroup"))
_host_previous: tuple[float, dict[str, dict[str, int]]] | None = None
_cgroup_previous: dict[str, tuple[float, dict[str, dict[str, int]]]] = {}
_IO_KEYS = ("rbps", "wbps", "riops", "wiops")
_COUNTER_KEYS = ("rbytes", "wbytes", "rios", "wios")


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return result if math.isfinite(result) else default


def _read_state(path: str) -> tuple[dict[str, Any], str]:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return {"schema": 1, "instances": {}}, ""
    except (OSError, ValueError, TypeError):
        return {"schema": 1, "instances": {}}, "磁盘 I/O 保护状态文件不可读；为避免丢失原限额，不执行新限制。"
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("instances"), dict):
        return {"schema": 1, "instances": {}}, "磁盘 I/O 保护状态文件格式无效；为避免丢失原限额，不执行新限制。"
    return value, ""


def _write_state(path: str, value: dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temp = os.path.join(directory, f".io-guard-{os.getpid()}-{uuid.uuid4().hex}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            os.chmod(temp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def _parse_diskstats() -> dict[str, dict[str, int]]:
    devices: dict[str, dict[str, int]] = {}
    with open("/proc/diskstats", "r", encoding="ascii", errors="ignore") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 14:
                continue
            try:
                major, minor = int(fields[0]), int(fields[1])
                values = [int(item) for item in fields[3:14]]
            except ValueError:
                continue
            key = f"{major}:{minor}"
            devices[key] = {
                "rios": values[0],
                "rsectors": values[2],
                "wios": values[4],
                "wsectors": values[6],
                "busy_ms": values[9],
            }
    return devices


def _parse_io_stat(path: Path) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    with (path / "io.stat").open("r", encoding="ascii", errors="ignore") as stream:
        for line in stream:
            fields = line.split()
            if not fields or not re.fullmatch(r"\d+:\d+", fields[0]):
                continue
            counters: dict[str, int] = {}
            for item in fields[1:]:
                key, sep, raw = item.partition("=")
                if sep and key in _COUNTER_KEYS:
                    try:
                        counters[key] = int(raw)
                    except ValueError:
                        pass
            if counters:
                output[fields[0]] = counters
    return output


def _read_cgroup(pid: int) -> tuple[str | None, dict[str, dict[str, int]], str]:
    if pid <= 1:
        return None, {}, "容器宿主机 PID 不可用"
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii", errors="ignore").splitlines()
        cgroup_line = next((line for line in lines if line.startswith("0::")), "")
        relative = cgroup_line[3:].strip()
        if not relative or relative == "/" or "(deleted)" in relative:
            return None, {}, "未能确认非根 cgroup v2 路径"
        root = CGROUP_ROOT.resolve(strict=True)
        target = (root / relative.lstrip("/")).resolve(strict=True)
        if target == root or not target.is_relative_to(root):
            return None, {}, "容器 cgroup 路径越出受控目录"
        # cgroup.controllers lists controllers available to *children*, not
        # controllers enabled for this cgroup. The io.max/io.stat files on the
        # exact leaf are the evidence we need; requiring "io" in that file
        # incorrectly rejects ordinary leaf cgroups with no children.
        if not (target / "io.max").is_file():
            return None, {}, "该 cgroup 未提供可验证的 v2 I/O 控制器"
        events = (target / "cgroup.events").read_text(encoding="ascii", errors="ignore")
        if not re.search(r"(?m)^populated 1\s*$", events):
            return None, {}, "容器 cgroup 当前没有活动进程"
        stats = _parse_io_stat(target)
        if not stats:
            return str(target), {}, "cgroup v2 尚无可读取的 io.stat 设备样本"
        return str(target), stats, ""
    except (OSError, RuntimeError, StopIteration) as exc:
        return None, {}, f"无法读取容器 cgroup I/O 证据：{str(exc)[:180]}"


def _parse_io_max(path: Path, device: str) -> dict[str, str] | None:
    values = {key: "max" for key in _IO_KEYS}
    try:
        lines = (path / "io.max").read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if not fields or fields[0] != device:
            continue
        for item in fields[1:]:
            key, sep, raw = item.partition("=")
            if sep and key in values and (raw == "max" or raw.isdigit()):
                values[key] = raw
        break
    return values


def _normalize_io_max(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    normalized = {}
    for key in _IO_KEYS:
        raw = str(value.get(key, "max"))
        if raw != "max" and not raw.isdigit():
            return None
        normalized[key] = raw
    return normalized


def _matches_io_max(path: Path, device: str, expected: Any) -> bool:
    normalized = _normalize_io_max(expected)
    current = _parse_io_max(path, device)
    return normalized is not None and current is not None and current == normalized


def _write_io_max(path: Path, device: str, values: dict[str, str]) -> tuple[bool, str]:
    normalized = _normalize_io_max(values)
    if normalized is None or not re.fullmatch(r"\d+:\d+", device):
        return False, "I/O 限额格式无效"
    line = device + " " + " ".join(f"{key}={normalized[key]}" for key in _IO_KEYS)
    try:
        with (path / "io.max").open("w", encoding="ascii") as stream:
            stream.write(line)
        return True, ""
    except OSError as exc:
        return False, str(exc)[:300]


def _populated(cgroup_path: str) -> bool | None:
    """Return whether a previous cgroup still owns processes; None means unknown."""
    if not cgroup_path:
        return None
    try:
        (Path(cgroup_path) / "cgroup.events").stat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    try:
        events = (Path(cgroup_path) / "cgroup.events").read_text(encoding="ascii", errors="ignore")
    except OSError:
        return None
    match = re.search(r"(?m)^populated ([01])\s*$", events)
    return match.group(1) == "1" if match else None


def _identity(container: dict[str, Any]) -> tuple[str, str] | None:
    runtime = str(container.get("runtime") or "").strip().lower()
    name = str(container.get("name") or "").strip()
    project = str(container.get("project") or "default").strip()
    stable_id = str(container.get("stable_id") or container.get("id") or "").strip()
    if runtime not in {"incus", "podman"} or not name or not stable_id:
        return None
    if len(name) > 200 or len(stable_id) > 256 or not re.fullmatch(r"[A-Za-z0-9_.:@+-]+", name):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", project):
        return None
    return "|".join((runtime, project, stable_id)), name


def _counter_rates(
    key: str, current: dict[str, dict[str, int]], now: float, interval: float
) -> tuple[dict[str, dict[str, float]], float]:
    previous = _cgroup_previous.get(key)
    _cgroup_previous[key] = (now, current)
    if previous is None:
        return {}, 0.0
    old_at, old = previous
    elapsed = now - old_at
    if elapsed < max(1.0, interval * 0.5) or elapsed > max(900.0, interval * 3.0):
        return {}, 0.0
    rates: dict[str, dict[str, float]] = {}
    for device, counters in current.items():
        before = old.get(device, {})
        delta = {metric: counters.get(metric, 0) - before.get(metric, 0) for metric in _COUNTER_KEYS}
        if any(value < 0 for value in delta.values()):
            continue
        rates[device] = {
            "rbps": delta["rbytes"] / elapsed,
            "wbps": delta["wbytes"] / elapsed,
            "riops": delta["rios"] / elapsed,
            "wiops": delta["wios"] / elapsed,
        }
    return rates, elapsed


def sample_host_devices(now: float | None = None) -> dict[str, Any]:
    """Return per-device busy, throughput and IOPS deltas from diskstats."""
    global _host_previous
    sampled_at = time.monotonic() if now is None else float(now)
    try:
        current = _parse_diskstats()
    except OSError as exc:
        return {"available": False, "state": "unavailable", "message": str(exc)[:200], "devices": {}}
    previous = _host_previous
    _host_previous = (sampled_at, current)
    if previous is None:
        return {"available": False, "state": "warming", "message": "等待第二次磁盘采样", "devices": {}}
    previous_at, old = previous
    elapsed = sampled_at - previous_at
    if elapsed < 1 or elapsed > 900:
        return {"available": False, "state": "warming", "message": "磁盘采样间隔无效，重新建立基线", "devices": {}}
    devices: dict[str, dict[str, float]] = {}
    for device, counters in current.items():
        before = old.get(device)
        if not before:
            continue
        deltas = {key: counters[key] - before[key] for key in counters}
        if any(value < 0 for value in deltas.values()):
            continue
        total_bps = (deltas["rsectors"] + deltas["wsectors"]) * 512.0 / elapsed
        total_iops = (deltas["rios"] + deltas["wios"]) / elapsed
        busy_percent = max(0.0, min(100.0, deltas["busy_ms"] / (elapsed * 10.0)))
        devices[device] = {
            "busy_percent": round(busy_percent, 2),
            "total_bps": round(total_bps, 2),
            "total_iops": round(total_iops, 2),
            "sample_seconds": round(elapsed, 2),
        }
    return {"available": bool(devices), "state": "ready" if devices else "warming", "devices": devices}


def _target_limits(baseline: dict[str, float], original: dict[str, str], ratio: float) -> dict[str, str]:
    target: dict[str, str] = {}
    for key in _IO_KEYS:
        rate = max(0.0, _number(baseline.get(key)))
        # Do not turn a tiny/noisy opposite-direction rate into a 1 B/s or
        # 1 IOPS cap just because the other direction triggered protection.
        floor_rate = 1024.0 * 1024.0 if key in {"rbps", "wbps"} else 25.0
        if rate < floor_rate:
            target[key] = original.get(key, "max")
            continue
        # I/O limits are integral. A one-unit minimum keeps low-IOPS devices
        # representable; a target that does not tighten an existing admin
        # value is rejected rather than treated as a successful enforcement.
        value = max(1, int(math.floor(rate * ratio)))
        old = original.get(key, "max")
        if old != "max":
            value = min(value, int(old))
        target[key] = str(value)
    return target


def _strictly_tighter(target: dict[str, str], current: dict[str, str]) -> bool:
    changed = False
    for key in _IO_KEYS:
        new, old = target[key], current[key]
        if new == old:
            continue
        if old != "max" and int(new) >= int(old):
            continue
        if new != "max":
            changed = True
    return changed


def _trigger_alert(container: dict[str, Any], record: dict[str, Any], action: dict[str, Any], message: str) -> dict[str, Any]:
    succeeded = action.get("succeeded") is True
    restored = record.get("stage") == "restored"
    io_detail = {
        "state": record.get("stage"),
        "device": record.get("device"),
        "device_busy_percent": record.get("device_busy_percent"),
        "dominant_share_percent": round(_number(record.get("dominant_share")) * 100.0, 1),
        "container_rates": record.get("observed_rates"),
        "device_rates": record.get("device_rates"),
        "tier": int(record.get("tier") or 0),
        "tier_percent_of_baseline": {0: 100, 1: 50, 2: 25, 3: 10}.get(int(record.get("tier") or 0)),
        "original_limit": record.get("original"),
        "active_limit": record.get("applied"),
        "confirmed_duration_seconds": int(record.get("confirmed_duration") or 0),
        "sample_count": int(record.get("high_samples") or 0),
        "required_samples": int(record.get("required_samples") or 0),
        "reason_is_user_abuse": False,
        "limit_applied": succeeded,
        "restore_failed": record.get("stage") == "restore_failed",
    }
    return {
        "type": "io_pressure_protection",
        "severity": "critical" if (not succeeded and not restored) or record.get("stage") == "restore_failed" else "warning",
        "title": "持续磁盘 I/O 压力，已启用容器保护" if succeeded else "磁盘 I/O 保护需要检查",
        "message": message,
        "runtime": str(container.get("runtime") or ""),
        "project": str(container.get("project") or ""),
        "container_name": str(container.get("name") or ""),
        "instance_id": str(container.get("stable_id") or container.get("id") or "")[:200],
        "alert_key": "io-pressure:" + str(container.get("stable_id") or container.get("id") or "")[:200],
        "ongoing_protection": record.get("stage") not in {"restored", "candidate"},
        "io_guard": io_detail,
        "automatic_remediation": action,
    }


def observe(
    containers: list[dict[str, Any]],
    interval_seconds: float,
    *,
    allow_new_limits: bool = True,
    now: int | None = None,
    monotonic_now: float | None = None,
    state_path: str | None = None,
) -> dict[str, Any]:
    """Measure pressure and enforce at most one confirmed container I/O ladder."""
    global _cgroup_previous
    enabled = os.getenv("SECURITY_IO_AUTO_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    allow_new_limits = allow_new_limits and enabled
    timestamp = int(time.time()) if now is None else int(now)
    monotonic_ts = time.monotonic() if monotonic_now is None else float(monotonic_now)
    interval = max(60.0, _number(interval_seconds, 300.0))
    pressure_threshold = min(99.0, max(50.0, _number(os.getenv("IO_AUTO_LIMIT_DEVICE_BUSY_PERCENT", "80"), 80.0)))
    recovery_pressure = min(90.0, max(20.0, _number(os.getenv("IO_AUTO_LIMIT_RECOVERY_BUSY_PERCENT", "60"), 60.0)))
    share_threshold = min(0.95, max(0.2, _number(os.getenv("IO_AUTO_LIMIT_CONTAINER_SHARE", "0.5"), 0.5)))
    min_bps = max(1024.0, _number(os.getenv("IO_AUTO_LIMIT_MIN_BPS", str(10 * 1024 * 1024)), 10 * 1024 * 1024))
    min_iops = max(10.0, _number(os.getenv("IO_AUTO_LIMIT_MIN_IOPS", "250"), 250.0))
    required_duration = max(300, int(_number(os.getenv("IO_AUTO_LIMIT_REQUIRED_SECONDS", "300"), 300)))
    recovery_duration = max(600, int(_number(os.getenv("IO_AUTO_LIMIT_RECOVERY_SECONDS", "600"), 600)))
    escalation_duration = max(300, int(_number(os.getenv("IO_AUTO_LIMIT_ESCALATION_SECONDS", "300"), 300)))
    min_samples = max(2, int(math.ceil(required_duration / interval)) + 1)
    recovery_samples = max(3, int(math.ceil(recovery_duration / interval)) + 1)
    max_gap = max(180, int(interval * 2.5))
    path = state_path or STATE_PATH
    state, state_error = _read_state(path)
    instances = state["instances"]
    host = sample_host_devices(monotonic_ts)
    seen: set[str] = set()
    alerts: list[dict[str, Any]] = []
    reserved_stages = {"applying", "escalating", "active", "restoring", "restore_failed", "orphaned_cgroup"}
    guarded_stages = reserved_stages | {"manual_override"}
    reserved = {
        key for key, record in instances.items()
        if isinstance(record, dict) and (
            record.get("stage") in reserved_stages
            or (record.get("stage") == "manual_override" and record.get("auto_limit_may_be_active") is not False)
        )
    }
    unresolved = 0

    for container in containers:
        if not isinstance(container, dict):
            continue
        identity = _identity(container)
        if not identity:
            continue
        key, _name = identity
        seen.add(key)
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        container["security"] = security
        try:
            pid = int(container.get("pid") or 0)
        except (TypeError, ValueError, OverflowError):
            pid = 0
        cgroup_path, io_stats, cgroup_error = _read_cgroup(pid)
        if not cgroup_path or not io_stats:
            security["io_guard"] = {"state": "unavailable", "message": cgroup_error or "容器 I/O 数据不可用", "reason_is_user_abuse": False}
            record = instances.get(key)
            if isinstance(record, dict) and record.get("stage") not in {"candidate"}:
                # Keep durable rollback information while ownership is unclear.
                unresolved += 1
            else:
                instances.pop(key, None)
                reserved.discard(key)
            continue
        rates, sample_seconds = _counter_rates(key, io_stats, monotonic_ts, interval)
        record = instances.get(key)
        if isinstance(record, dict) and record.get("stage") not in {"candidate", "manual_override"}:
            if record.get("cgroup_path") != cgroup_path:
                old_populated = _populated(str(record.get("cgroup_path") or ""))
                if old_populated is False:
                    # The old cgroup is empty, so its limit cannot affect a
                    # running workload. Drop the stale record and re-baseline.
                    instances.pop(key, None)
                    reserved.discard(key)
                    record = None
                else:
                    # A restarted container must not inherit an unverified
                    # rollback record, and a still-populated old cgroup keeps
                    # the single-container reservation until resolved.
                    record["stage"] = "orphaned_cgroup"
                    record["last_error"] = "容器重启后 cgroup 路径改变；旧限额归属尚未确认，暂不对其他容器新增 I/O 限额。"
                    security["io_guard"] = {"state": "orphaned_cgroup", "message": record["last_error"], "reason_is_user_abuse": False}
                    unresolved += 1
                    continue
            else:
                io_file_path = Path(cgroup_path)
                device = str(record.get("device") or "")
                current = _parse_io_max(io_file_path, device)
                applied = _normalize_io_max(record.get("applied"))
                original = _normalize_io_max(record.get("original"))
                pending = _normalize_io_max(record.get("pending"))
                stage = record.get("stage")
                if stage in {"applying", "escalating", "restoring"}:
                    if pending and _matches_io_max(io_file_path, device, pending):
                        if stage == "restoring":
                            instances.pop(key, None)
                            reserved.discard(key)
                            security["io_guard"] = {"state": "restored", "message": "磁盘 I/O 压力已回落，原容器 I/O 限额已读回确认并恢复。"}
                            record = None
                            continue
                        record["applied"] = pending
                        record["tier"] = int(record.get("pending_tier") or 1)
                        record["stage"] = "active"
                        record["pending"] = None
                        record["last_step_at"] = timestamp
                    elif applied and _matches_io_max(io_file_path, device, applied):
                        record["stage"] = "active"
                        record["pending"] = None
                        record["last_step_at"] = int(record.get("last_step_at") or timestamp)
                    elif original and _matches_io_max(io_file_path, device, original):
                        # A prior write did not occur. Retry only with fresh
                        # pressure evidence and the normal next sample.
                        record["stage"] = "candidate"
                        record["last_attempt"] = timestamp
                        reserved.discard(key)
                    else:
                        record["stage"] = "manual_override"
                        record["last_error"] = "检测到人工修改 io.max；保留管理员设置，不覆盖。"
                elif stage in {"active", "restore_failed"} and applied and not _matches_io_max(io_file_path, device, applied):
                    if original and _matches_io_max(io_file_path, device, original):
                        instances.pop(key, None)
                        reserved.discard(key)
                        security["io_guard"] = {"state": "restored", "message": "检测到限额已由管理员恢复，系统保留该设置。"}
                        record = None
                        continue
                    record["stage"] = "manual_override"
                    record["last_error"] = "检测到人工修改 io.max；保留管理员设置，不覆盖。"

                if record and record.get("stage") == "manual_override":
                    security["io_guard"] = {"state": "manual_override", "message": record.get("last_error"), "reason_is_user_abuse": False}
                    continue
                if record and record.get("stage") in {"active", "restore_failed"}:
                    record["last_seen"] = timestamp
                    device_sample = host.get("devices", {}).get(device, {}) if isinstance(host.get("devices"), dict) else {}
                    busy = _number(device_sample.get("busy_percent"), -1)
                    observed = rates.get(device, {})
                    record["device_busy_percent"] = round(busy, 2) if busy >= 0 else None
                    record["observed_rates"] = {k: round(_number(v), 2) for k, v in observed.items()}
                    record["device_rates"] = device_sample
                    lower = all(
                        original is None or applied is None or applied.get(k) == "max"
                        or _number(observed.get(k), 0) <= max(1, _number(applied.get(k)) * 0.5)
                        for k in _IO_KEYS
                    )
                    low_pressure = busy >= 0 and busy < recovery_pressure
                    if lower and low_pressure:
                        since = int(record.get("low_since") or timestamp)
                        if timestamp <= since or timestamp - int(record.get("last_low") or 0) > max_gap:
                            since = timestamp
                            record["low_samples"] = 1
                        else:
                            record["low_samples"] = int(record.get("low_samples") or 0) + 1
                        record["low_since"] = since
                        record["last_low"] = timestamp
                    else:
                        record["low_since"] = 0
                        record["low_last"] = 0
                        record["low_samples"] = 0
                    if (int(record.get("low_samples") or 0) >= recovery_samples
                            and timestamp - int(record.get("low_since") or timestamp) >= recovery_duration):
                        record["stage"] = "restoring"
                        record["pending"] = original
                        record["pending_tier"] = 0
                        try:
                            _write_state(path, state)
                        except OSError as exc:
                            record["stage"] = "restore_failed"
                            record["last_error"] = f"无法保存恢复计划：{str(exc)[:200]}"
                        else:
                            ok, output = _write_io_max(io_file_path, device, original or {})
                            if ok and _matches_io_max(io_file_path, device, original):
                                instances.pop(key, None)
                                security["io_guard"] = {"state": "restored", "message": "磁盘 I/O 压力已连续恢复，原容器 I/O 限额已恢复。"}
                                reserved.discard(key)
                                continue
                            record["stage"] = "restore_failed"
                            record["last_error"] = output or "恢复后的 io.max 读回不一致"
                    if record.get("stage") in {"active", "restore_failed"}:
                        tier = max(1, min(3, int(record.get("tier") or 1)))
                        host_bps = _number(device_sample.get("total_bps"), 0)
                        host_iops = _number(device_sample.get("total_iops"), 0)
                        observed_bps = _number(observed.get("rbps")) + _number(observed.get("wbps"))
                        observed_iops = _number(observed.get("riops")) + _number(observed.get("wiops"))
                        share = max(observed_bps / host_bps if host_bps > 0 else 0.0,
                                    observed_iops / host_iops if host_iops > 0 else 0.0)
                        high = busy >= pressure_threshold and share >= share_threshold and (
                            observed_bps >= min_bps or observed_iops >= min_iops
                        )
                        if high and tier < 3:
                            last_high = int(record.get("last_high") or 0)
                            if not last_high or timestamp <= last_high or timestamp - last_high > max_gap:
                                record["escalation_since"] = timestamp
                                record["escalation_samples"] = 1
                            else:
                                record["escalation_samples"] = int(record.get("escalation_samples") or 0) + 1
                            record["last_high"] = timestamp
                            tier_since = int(record.get("escalation_since") or timestamp)
                            required_step_samples = max(2, int(math.ceil(escalation_duration / interval)) + 1)
                            if (timestamp - tier_since >= escalation_duration
                                    and int(record.get("escalation_samples") or 0) >= required_step_samples
                                    and timestamp - int(record.get("last_step_at") or 0) >= escalation_duration):
                                baseline = record.get("baseline_rates") if isinstance(record.get("baseline_rates"), dict) else {}
                                target = _target_limits(baseline, original or {}, {1: 0.25, 2: 0.10}.get(tier, 0.10))
                                if _strictly_tighter(target, applied or {}):
                                    record["stage"] = "escalating"
                                    record["pending"] = target
                                    record["pending_tier"] = tier + 1
                                    record["escalation_samples"] = 0
                                    record["escalation_since"] = 0
                                    try:
                                        _write_state(path, state)
                                    except OSError as exc:
                                        record["stage"] = "active"
                                        record["pending"] = None
                                        record["last_error"] = f"无法保存阶梯限额计划：{str(exc)[:180]}"
                                    else:
                                        ok, output = _write_io_max(io_file_path, device, target)
                                        if ok and _matches_io_max(io_file_path, device, target):
                                            record["applied"] = target
                                            record["tier"] = tier + 1
                                            record["stage"] = "active"
                                            record["pending"] = None
                                            record["last_step_at"] = timestamp
                                            record["last_error"] = ""
                                        else:
                                            record["last_error"] = output or "阶梯限额读回不一致"
                        else:
                            record["escalation_since"] = 0
                            record["last_high"] = 0
                            record["escalation_samples"] = 0
                        tier = int(record.get("tier") or 1)
                        security["io_guard"] = {
                            "state": record.get("stage"), "device": device,
                            "device_busy_percent": record.get("device_busy_percent"),
                            "dominant_share_percent": round(_number(record.get("dominant_share")) * 100.0, 1),
                            "observed_rates": record.get("observed_rates"),
                            "tier": tier, "tier_percent_of_baseline": {1: 50, 2: 25, 3: 10}.get(tier),
                            "original_limit": original, "active_limit": record.get("applied"),
                            "recovery_samples": int(record.get("low_samples") or 0),
                            "recovery_samples_required": recovery_samples,
                            "message": record.get("last_error") or "容器 I/O 限额已读回确认；达到持续恢复条件后自动恢复。",
                            "reason_is_user_abuse": False,
                        }
                        action = {"attempted": True, "succeeded": record.get("stage") == "active",
                                  "action_type": "set_container_io_max", "message": security["io_guard"]["message"],
                                  "original_limit": original, "active_limit": record.get("applied")}
                        alerts.append(_trigger_alert(container, record, action, str(action["message"])))
                        continue

        if record and record.get("stage") == "manual_override":
            security["io_guard"] = {"state": "manual_override", "message": record.get("last_error"), "reason_is_user_abuse": False}
            continue
        if not allow_new_limits:
            instances.pop(key, None)
            security["io_guard"] = {"state": "disabled", "reason_is_user_abuse": False}
            continue
        if state_error:
            security["io_guard"] = {"state": "state_unavailable", "message": state_error, "reason_is_user_abuse": False}
            continue
        if host.get("state") != "ready":
            security["io_guard"] = {"state": "warming", "message": host.get("message") or "等待宿主机磁盘采样", "reason_is_user_abuse": False}
            continue

        candidate = record if isinstance(record, dict) and record.get("stage") == "candidate" else {
            "stage": "candidate", "high_samples": 0, "high_since": 0, "last_high": 0,
        }
        # ``rates`` was sampled above so both the active and candidate paths
        # use the same interval delta instead of consuming it twice.
        pressured: list[tuple[float, str, dict[str, float], dict[str, float]]] = []
        for device, io_rate in rates.items():
            device_stats = host.get("devices", {}).get(device, {})
            busy = _number(device_stats.get("busy_percent"), -1)
            if busy < pressure_threshold:
                continue
            host_bps = _number(device_stats.get("total_bps"), 0)
            host_iops = _number(device_stats.get("total_iops"), 0)
            bytes_rate = _number(io_rate.get("rbps")) + _number(io_rate.get("wbps"))
            iops_rate = _number(io_rate.get("riops")) + _number(io_rate.get("wiops"))
            share = max(bytes_rate / host_bps if host_bps > 0 else 0.0, iops_rate / host_iops if host_iops > 0 else 0.0)
            if share >= share_threshold and (bytes_rate >= min_bps or iops_rate >= min_iops):
                pressured.append((share, device, io_rate, device_stats))
        if pressured:
            pressured.sort(key=lambda item: item[0], reverse=True)
            share, device, observed_rates, device_stats = pressured[0]
            if candidate.get("device") and candidate.get("device") != device:
                candidate["high_samples"] = 0
                candidate["high_since"] = 0
                candidate["last_high"] = 0
                candidate["baseline_rates"] = {}
            last_high = int(candidate.get("last_high") or 0)
            if not last_high or timestamp <= last_high or timestamp - last_high > max_gap:
                candidate["high_samples"] = 1
                candidate["high_since"] = timestamp
            else:
                candidate["high_samples"] = int(candidate.get("high_samples") or 0) + 1
            candidate["last_high"] = timestamp
            baseline_rates = candidate.get("baseline_rates") if isinstance(candidate.get("baseline_rates"), dict) else {}
            candidate["baseline_rates"] = {
                key_name: max(_number(baseline_rates.get(key_name)), _number(observed_rates.get(key_name)))
                for key_name in _IO_KEYS
            }
            candidate.update(device=device, cgroup_path=cgroup_path, observed_rates=observed_rates,
                             device_rates=device_stats, device_busy_percent=_number(device_stats.get("busy_percent")),
                             dominant_share=round(share, 4), sample_seconds=round(sample_seconds, 2))
            instances[key] = candidate
            security["io_guard"] = {
                "state": "watching", "device": device,
                "device_busy_percent": candidate["device_busy_percent"],
                "dominant_share_percent": round(share * 100.0, 1),
                "observed_rates": {k: round(_number(v), 2) for k, v in observed_rates.items()},
                "confirmed_duration_seconds": max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                "sample_count": int(candidate.get("high_samples") or 0), "required_samples": min_samples,
                "reason_is_user_abuse": False,
            }
            if (int(candidate.get("high_samples") or 0) >= min_samples
                    and timestamp - int(candidate.get("high_since") or timestamp) >= required_duration):
                if any(other_key != key for other_key in reserved):
                    security["io_guard"] = {
                        **security.get("io_guard", {}),
                        "state": "waiting_for_other_limit",
                        "message": "另一容器的磁盘 I/O 保护仍在生效或等待核验；当前容器继续采样，暂不叠加限额。",
                    }
                    continue
                current = _parse_io_max(Path(cgroup_path), device)
                if current is None:
                    security["io_guard"] = {"state": "limit_readback_unavailable", "message": "无法读取当前 io.max；为保护管理员原配置，本轮不修改限额。", "reason_is_user_abuse": False}
                    continue
                baseline = {k: max(0.0, _number(v)) for k, v in candidate["baseline_rates"].items()}
                target = _target_limits(baseline, current, 0.5)
                if _strictly_tighter(target, current):
                    record = {
                        "stage": "applying", "device": device, "cgroup_path": cgroup_path,
                        "original": current, "applied": current, "pending": target,
                        "auto_limit_may_be_active": True,
                        "pending_tier": 1, "tier": 0, "baseline_rates": baseline,
                        "observed_rates": observed_rates, "device_rates": device_stats,
                        "device_busy_percent": candidate["device_busy_percent"],
                        "dominant_share": share, "high_samples": int(candidate.get("high_samples") or 0),
                        "required_samples": min_samples,
                        "confirmed_duration": timestamp - int(candidate.get("high_since") or timestamp),
                        "last_seen": timestamp, "last_attempt": timestamp, "last_step_at": timestamp,
                        "low_samples": 0,
                    }
                    instances[key] = record
                    reserved.add(key)
                    try:
                        _write_state(path, state)
                    except OSError as exc:
                        instances[key] = candidate
                        reserved.discard(key)
                        action = {"attempted": True, "succeeded": False, "message": f"无法保存原限额回滚状态，未修改容器：{str(exc)[:180]}"}
                    else:
                        current_before = _parse_io_max(Path(cgroup_path), device)
                        if current_before != current:
                            record["stage"] = "manual_override"
                            record["auto_limit_may_be_active"] = False
                            record["last_error"] = "执行前 io.max 已被管理员修改；未覆盖。"
                            reserved.discard(key)
                            action = {"attempted": True, "succeeded": False, "message": record["last_error"]}
                        else:
                            ok, output = _write_io_max(Path(cgroup_path), device, target)
                            if ok and _matches_io_max(Path(cgroup_path), device, target):
                                record["applied"] = target
                                record["tier"] = 1
                                record["stage"] = "active"
                                record["pending"] = None
                                record["last_error"] = ""
                                action = {"attempted": True, "succeeded": True, "action_type": "set_container_io_max",
                                          "message": "已读回确认第一阶容器 I/O 限额；未停止进程或容器。"}
                            else:
                                record["last_error"] = output or "应用后的 io.max 读回不一致"
                                action = {"attempted": True, "succeeded": False, "message": record["last_error"]}
                    security["io_guard"] = {
                        "state": record.get("stage"), "device": device,
                        "tier": int(record.get("tier") or 0), "tier_percent_of_baseline": {1: 50, 2: 25, 3: 10}.get(int(record.get("tier") or 0)),
                        "original_limit": record.get("original"), "active_limit": record.get("applied"),
                        "observed_rates": {k: round(_number(v), 2) for k, v in observed_rates.items()},
                        "message": action["message"], "reason_is_user_abuse": False,
                    }
                    alerts.append(_trigger_alert(container, record, action, str(action["message"])))
                else:
                    security["io_guard"] = {**security["io_guard"], "state": "limit_not_needed", "message": "现有限额不高于自动保护目标；未改写管理员配置。"}
        else:
            if isinstance(record, dict) and record.get("stage") == "candidate":
                instances.pop(key, None)
            security["io_guard"] = {
                "state": "sampling_unavailable" if sample_seconds <= 0 else "normal",
                "message": cgroup_error or "未达到持续宿主机磁盘压力与容器归属阈值。",
                "reason_is_user_abuse": False,
            }

    for key in list(instances):
        record = instances.get(key)
        if key not in seen and isinstance(record, dict):
            if record.get("stage") == "candidate":
                instances.pop(key, None)
            elif record.get("stage") in guarded_stages:
                if _populated(str(record.get("cgroup_path") or "")) is False:
                    instances.pop(key, None)
                    reserved.discard(key)
                    continue
            elif timestamp - int(record.get("last_seen") or timestamp) > 30 * 86400:
                instances.pop(key, None)
    for key in list(_cgroup_previous):
        if key not in seen:
            _cgroup_previous.pop(key, None)
    if not state_error:
        try:
            _write_state(path, state)
        except OSError as exc:
            print(f"io guard state could not be saved: {exc}")
    return {
        "enabled": bool(enabled and allow_new_limits),
        "state": host.get("state", "unavailable"),
        "limited_containers": sum(
            1 for record in instances.values()
            if isinstance(record, dict) and record.get("stage") in {"active", "restore_failed"}
        ),
        "reserved_containers": len(reserved),
        "unresolved_containers": unresolved,
        "policy": {
            "device_busy_percent": pressure_threshold,
            "container_io_share": share_threshold,
            "minimum_bytes_per_second": min_bps,
            "minimum_iops": min_iops,
            "required_duration_seconds": required_duration,
            "recovery_device_busy_percent": recovery_pressure,
            "recovery_duration_seconds": recovery_duration,
            "tier_percent_of_baseline": [50, 25, 10],
            "max_simultaneous_container_limits": 1,
        },
        "host_devices": host.get("devices", {}),
        "alerts": alerts,
    }
