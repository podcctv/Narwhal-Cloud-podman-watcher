"""Reversible cgroup-v2 memory pressure protection for Incus and Podman.

The guard uses memory PSI from both the host and the exact container cgroup.
It only lowers ``memory.high`` (the reclaim/throttle boundary), never
``memory.max`` and never stops a process or container. Every write is preceded
by a durable rollback record and is read back before being reported as active.
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


STATE_PATH = os.getenv("NARWHAL_MEMORY_GUARD_STATE", "/var/lib/narwhal-agent/memory-guard.json")
CGROUP_ROOT = Path(os.getenv("NARWHAL_CGROUP_ROOT", "/sys/fs/cgroup"))
_ACTIVE_STAGES = {"applying", "escalating", "apply_unverified", "active", "restoring", "restore_failed", "manual_override"}
_RESERVED_STAGES = set(_ACTIVE_STAGES)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if math.isfinite(number) else default


def _read_pressure(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        lines = path.read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    for line in lines[:2]:
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        parsed: dict[str, float | int] = {}
        for item in fields[1:]:
            key, sep, raw = item.partition("=")
            if not sep or key not in {"avg10", "avg60", "avg300", "total"}:
                continue
            try:
                value = int(raw) if key == "total" else float(raw)
                if math.isfinite(float(value)) and value >= 0:
                    parsed[key] = value
            except (ValueError, OverflowError):
                continue
        if "avg10" in parsed:
            result[fields[0]] = parsed
    return {"status": "ready", **result} if result else {
        "status": "unsupported", "reason": "memory PSI 文件不可用或格式不受支持"
    }


def _cgroup(pid_value: Any) -> tuple[Path | None, dict[str, Any], str]:
    try:
        pid = int(pid_value or 0)
    except (TypeError, ValueError, OverflowError):
        pid = 0
    if pid <= 1:
        return None, {}, "容器宿主机 PID 不可用"
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii", errors="ignore").splitlines()
        relative = next((line[3:].strip() for line in lines if line.startswith("0::")), "")
        if not relative or relative == "/" or "(deleted)" in relative:
            return None, {}, "未能确认非根 cgroup v2 路径"
        root = CGROUP_ROOT.resolve(strict=True)
        target = (root / relative.lstrip("/")).resolve(strict=True)
        if target == root or not target.is_relative_to(root):
            return None, {}, "容器 cgroup 路径越出受控目录"
        required = ("memory.current", "memory.max", "memory.high", "memory.pressure", "cgroup.events")
        if any(not (target / name).is_file() for name in required):
            return None, {}, "该 cgroup 未提供完整的 v2 memory controller"
        events = (target / "cgroup.events").read_text(encoding="ascii", errors="ignore")
        if not re.search(r"(?m)^populated 1\s*$", events):
            return None, {}, "容器 cgroup 当前没有活动进程"
        current_raw = (target / "memory.current").read_text(encoding="ascii").strip()
        maximum_raw = (target / "memory.max").read_text(encoding="ascii").strip()
        high_raw = (target / "memory.high").read_text(encoding="ascii").strip()
        if not current_raw.isdigit() or (maximum_raw != "max" and not maximum_raw.isdigit()) or (high_raw != "max" and not high_raw.isdigit()):
            return None, {}, "cgroup memory.current / max / high 格式无法确认"
        return target, {
            "current_bytes": int(current_raw),
            "max_bytes": None if maximum_raw == "max" else int(maximum_raw),
            "high": high_raw,
            "pressure": _read_pressure(target / "memory.pressure"),
        }, ""
    except (OSError, RuntimeError, StopIteration) as exc:
        return None, {}, f"无法读取容器 cgroup 内存证据：{type(exc).__name__}"


def _read_state(path: str) -> tuple[dict[str, Any], str]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": 1, "instances": {}}, ""
    except (OSError, ValueError, TypeError) as exc:
        return {"schema": 1, "instances": {}}, f"内存保护状态文件不可读（{type(exc).__name__}）；不会新增长期限额。"
    if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("instances"), dict):
        return {"schema": 1, "instances": {}}, "内存保护状态文件格式无效；不会新增长期限额。"
    return value, ""


def _write_state(path: str, state: dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temp = os.path.join(directory, f".memory-guard-{os.getpid()}-{uuid.uuid4().hex}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            os.chmod(temp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def _write_high(path: Path, value: str) -> tuple[bool, str]:
    if value != "max" and not value.isdigit():
        return False, "memory.high 限值格式无效"
    try:
        (path / "memory.high").write_text(value, encoding="ascii")
        return True, ""
    except OSError as exc:
        return False, f"写入 memory.high 失败（{type(exc).__name__}）"


def _identity(container: dict[str, Any]) -> tuple[str, str, str] | None:
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
    return "|".join((runtime, project, stable_id)), name, stable_id


def _pressure_value(pressure: dict[str, Any], kind: str) -> float:
    item = pressure.get(kind) if isinstance(pressure, dict) else None
    return _number(item.get("avg10"), -1.0) if isinstance(item, dict) else -1.0


def _target(max_bytes: int, tier: int) -> str:
    ratio = {1: 0.90, 2: 0.80, 3: 0.70}[max(1, min(3, tier))]
    return str(max(16 * 1024 * 1024, int(max_bytes * ratio)))


def _alert(container: dict[str, Any], record: dict[str, Any], succeeded: bool, message: str) -> dict[str, Any]:
    security = container.get("security") if isinstance(container.get("security"), dict) else {}
    detail = {
        "state": record.get("stage"),
        "tier": int(record.get("tier") or 0),
        "tier_percent_of_max": {1: 90, 2: 80, 3: 70}.get(int(record.get("tier") or 0)),
        "original_limit": record.get("original"),
        "active_limit": record.get("applied"),
        "memory_current_bytes": record.get("memory_current_bytes"),
        "memory_max_bytes": record.get("memory_max_bytes"),
        "container_psi_some_avg10": record.get("container_psi_some_avg10"),
        "host_psi_some_avg10": record.get("host_psi_some_avg10"),
        "confirmed_duration_seconds": int(record.get("confirmed_duration") or 0),
        "sample_count": int(record.get("high_samples") or 0),
        "required_samples": int(record.get("required_samples") or 0),
        "recovery_samples": int(record.get("low_samples") or 0),
        "recovery_samples_required": int(record.get("recovery_samples_required") or 0),
        "recovery_duration_seconds": int(record.get("recovery_duration_seconds") or 0),
        "limit_applied": succeeded,
        "restore_failed": record.get("stage") == "restore_failed",
        "reason_is_user_abuse": False,
        "resource_pressure": security.get("resource_pressure"),
    }
    return {
        "type": "memory_pressure_protection",
        "severity": "critical" if not succeeded or record.get("stage") == "restore_failed" else "warning",
        "title": "持续内存压力，已启用可恢复保护" if succeeded else "内存保护需要检查",
        "message": message,
        "runtime": str(container.get("runtime") or ""),
        "project": str(container.get("project") or ""),
        "container_name": str(container.get("name") or ""),
        "instance_id": str(container.get("stable_id") or container.get("id") or "")[:200],
        "alert_key": "memory-pressure:" + str(container.get("stable_id") or container.get("id") or "")[:200],
        "ongoing_protection": record.get("stage") not in {"restored", "candidate", "cooldown"},
        "memory_guard": detail,
        "automatic_remediation": {"attempted": True, "succeeded": succeeded, "action_type": "set_cgroup_memory_high", "message": message},
    }


def observe(
    containers: list[dict[str, Any]], *, allow_new_limits: bool = True,
    now: int | None = None, interval_seconds: float = 300.0,
    state_path: str | None = None,
) -> dict[str, Any]:
    enabled = os.getenv("SECURITY_MEMORY_AUTO_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    allow_new_limits = bool(allow_new_limits and enabled)
    timestamp = int(time.time()) if now is None else int(now)
    interval = max(60.0, _number(interval_seconds, 300.0))
    start_usage = min(98.0, max(70.0, _number(os.getenv("MEMORY_AUTO_LIMIT_USAGE_PERCENT", "85"), 85.0)))
    host_pressure_threshold = min(80.0, max(1.0, _number(os.getenv("MEMORY_AUTO_LIMIT_HOST_PSI_PERCENT", "5"), 5.0)))
    container_pressure_threshold = min(90.0, max(1.0, _number(os.getenv("MEMORY_AUTO_LIMIT_CGROUP_PSI_PERCENT", "5"), 5.0)))
    required_duration = max(600, int(_number(os.getenv("MEMORY_AUTO_LIMIT_REQUIRED_SECONDS", "600"), 600)))
    escalation_duration = max(300, int(_number(os.getenv("MEMORY_AUTO_LIMIT_ESCALATION_SECONDS", "600"), 600)))
    recovery_duration = max(600, int(_number(os.getenv("MEMORY_AUTO_LIMIT_RECOVERY_SECONDS", "900"), 900)))
    cooldown_seconds = max(300, int(_number(os.getenv("MEMORY_AUTO_LIMIT_COOLDOWN_SECONDS", "900"), 900)))
    recovery_pressure = min(host_pressure_threshold, max(0.5, _number(os.getenv("MEMORY_AUTO_LIMIT_RECOVERY_PSI_PERCENT", "2"), 2.0)))
    min_samples = max(3, int(math.ceil(required_duration / interval)) + 1)
    recovery_samples = max(3, int(math.ceil(recovery_duration / interval)) + 1)
    escalation_samples = max(2, int(math.ceil(escalation_duration / interval)) + 1)
    max_gap = max(180, int(interval * 2.5))
    path = state_path or STATE_PATH
    state, state_error = _read_state(path)
    instances = state["instances"]
    host_pressure = _read_pressure(Path("/proc/pressure/memory"))
    host_some = _pressure_value(host_pressure, "some")
    seen: set[str] = set()
    reserved = {key for key, record in instances.items() if isinstance(record, dict) and record.get("stage") in _RESERVED_STAGES}
    candidates: list[tuple[float, dict[str, Any], dict[str, Any], Path, dict[str, Any]]] = []
    alerts: list[dict[str, Any]] = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        identity = _identity(container)
        if not identity:
            continue
        key, _name, stable_id = identity
        seen.add(key)
        security = container.get("security") if isinstance(container.get("security"), dict) else {}
        container["security"] = security
        cgroup_path, metrics, cgroup_error = _cgroup(container.get("pid"))
        cgroup_pressure = metrics.get("pressure") if isinstance(metrics.get("pressure"), dict) else {}
        cgroup_some = _pressure_value(cgroup_pressure, "some")
        maximum = metrics.get("max_bytes")
        current_bytes = int(metrics.get("current_bytes") or 0)
        used_percent = current_bytes * 100.0 / maximum if isinstance(maximum, int) and maximum > 0 else -1.0
        status: dict[str, Any] = {
            "state": "sampling_unavailable" if cgroup_error else "normal",
            "message": cgroup_error or "尚未达到持续宿主机和容器内存压力阈值。",
            "memory_current_bytes": current_bytes if not cgroup_error else None,
            "memory_max_bytes": maximum,
            "memory_used_percent": round(used_percent, 2) if used_percent >= 0 else None,
            "host_psi_some_avg10": host_some if host_some >= 0 else None,
            "container_psi_some_avg10": cgroup_some if cgroup_some >= 0 else None,
            "required_duration_seconds": required_duration,
            "recovery_duration_seconds": recovery_duration,
            "cooldown_seconds": cooldown_seconds,
            "reason_is_user_abuse": False,
        }
        record = instances.get(key)

        if isinstance(record, dict) and record.get("stage") == "cooldown":
            remaining = max(0, int(record.get("cooldown_until") or 0) - timestamp)
            if remaining:
                status.update(state="cooldown", retry_after_seconds=remaining,
                              message=f"刚恢复后冷却中，约 {remaining} 秒后才重新评估限额。")
                security["memory_guard"] = status
                continue
            instances.pop(key, None)
            record = None

        if isinstance(record, dict) and record.get("stage") in _ACTIVE_STAGES:
            if cgroup_error or cgroup_path is None or str(cgroup_path) != str(record.get("cgroup_path") or ""):
                record["last_error"] = cgroup_error or "容器 cgroup 路径已变化；为避免写入错误目标，保护状态待核实。"
                status.update(state="orphaned_cgroup", message=record["last_error"], tier=record.get("tier"),
                              original_limit=record.get("original"), active_limit=record.get("applied"))
                security["memory_guard"] = status
                continue
            current_high = str(metrics.get("high") or "")
            stage = str(record.get("stage") or "")
            if stage in {"applying", "escalating", "apply_unverified"}:
                pending = str(record.get("pending") or "")
                initial_attempt = stage == "applying" or (stage == "apply_unverified" and not int(record.get("tier") or 0))
                if initial_attempt:
                    previous = str(record.get("original") or "")
                else:
                    previous = str(record.get("applied") or record.get("original") or "")
                if pending and current_high == pending:
                    record.update(stage="active", applied=pending,
                                  tier=int(record.get("pending_tier") or record.get("tier") or 1),
                                  pending=None, pending_tier=None, last_error="")
                    stage = "active"
                elif current_high == previous:
                    if initial_attempt:
                        message = record.get("last_error") or "memory.high 未发生变化；自动限额未生效。"
                        instances.pop(key, None)
                        status.update(state="limit_failed", message=message, original_limit=record.get("original"),
                                      active_limit=current_high, limit_applied=False)
                        security["memory_guard"] = status
                        alerts.append(_alert(container, record, False, message))
                        continue
                    record.update(stage="active", pending=None, pending_tier=None,
                                  last_error=record.get("last_error") or "阶梯限额未读回；保留此前已确认的限额。")
                    stage = "active"
                else:
                    record.update(stage="manual_override", last_error="限额写入后读回值与预期不一致；为保护当前管理员设置，不再自动覆盖。")
                    status.update(state="manual_override", message=record["last_error"], tier=record.get("tier"),
                                  original_limit=record.get("original"), active_limit=current_high)
                    security["memory_guard"] = status
                    continue
            if stage == "restoring":
                original = str(record.get("original") or "max")
                if current_high == original:
                    instances[key] = {"stage": "cooldown", "cooldown_until": timestamp + cooldown_seconds,
                                      "last_seen": timestamp, "restored_at": timestamp}
                    reserved.discard(key)
                    status.update(state="restored", cooldown_until=timestamp + cooldown_seconds,
                                  message="原 memory.high 已读回恢复；进入冷却期后再重新评估。")
                    security["memory_guard"] = status
                    continue
                if current_high == str(record.get("applied") or ""):
                    record.update(stage="restore_failed", pending=None,
                                  last_error=record.get("last_error") or "恢复写入尚未读回；保留最后确认的内存保护限额。")
                else:
                    record.update(stage="manual_override", last_error="恢复期间 memory.high 出现外部更改；保留当前管理员配置。")
                    status.update(state="manual_override", message=record["last_error"], tier=record.get("tier"),
                                  original_limit=record.get("original"), active_limit=current_high)
                    security["memory_guard"] = status
                    continue
            if record.get("stage") == "restore_failed" and current_high == str(record.get("original") or "max"):
                instances[key] = {"stage": "cooldown", "cooldown_until": timestamp + cooldown_seconds,
                                  "last_seen": timestamp, "restored_at": timestamp}
                reserved.discard(key)
                status.update(state="restored", cooldown_until=timestamp + cooldown_seconds,
                              message="复查确认原 memory.high 已恢复；进入冷却期后再重新评估。")
                security["memory_guard"] = status
                continue
            if record.get("stage") == "manual_override":
                if current_high == str(record.get("original") or "max"):
                    instances[key] = {"stage": "cooldown", "cooldown_until": timestamp + cooldown_seconds,
                                      "last_seen": timestamp, "restored_at": timestamp}
                    reserved.discard(key)
                    status.update(state="restored", cooldown_until=timestamp + cooldown_seconds,
                                  message="已读回确认管理员恢复了原 memory.high；进入冷却期后再重新评估。")
                    security["memory_guard"] = status
                else:
                    status.update(state="manual_override", message=record.get("last_error") or "检测到管理员更改 memory.high；保留当前设置。",
                                  tier=record.get("tier"), original_limit=record.get("original"), active_limit=current_high)
                    security["memory_guard"] = status
                continue
            if current_high != str(record.get("applied") or ""):
                record["stage"] = "manual_override"
                record["last_error"] = "检测到 memory.high 被管理员或运行时修改；保留当前设置，不再覆盖。"
                status.update(state="manual_override", message=record["last_error"], tier=record.get("tier"),
                              original_limit=record.get("original"), active_limit=current_high)
                security["memory_guard"] = status
                continue

            tier = max(1, min(3, int(record.get("tier") or 1)))
            record.update(last_seen=timestamp, memory_current_bytes=current_bytes, memory_max_bytes=maximum,
                          host_psi_some_avg10=host_some, container_psi_some_avg10=cgroup_some)
            pressure_high = host_some >= host_pressure_threshold and cgroup_some >= container_pressure_threshold
            if pressure_high and used_percent >= start_usage and tier < 3:
                last_high = int(record.get("last_high") or 0)
                if last_high <= 0 or timestamp <= last_high or timestamp - last_high > max_gap:
                    record["escalation_since"], record["escalation_samples"] = timestamp, 1
                else:
                    record["escalation_samples"] = int(record.get("escalation_samples") or 0) + 1
                record["last_high"] = timestamp
                elapsed = timestamp - int(record.get("escalation_since") or timestamp)
                if elapsed >= escalation_duration and int(record.get("escalation_samples") or 0) >= escalation_samples:
                    target = _target(int(maximum), tier + 1) if isinstance(maximum, int) else ""
                    can_tighten = bool(target) and (current_high == "max" or int(target) < int(current_high))
                    if can_tighten:
                        record.update(stage="escalating", pending=target, pending_tier=tier + 1)
                        try:
                            _write_state(path, state)
                        except OSError as exc:
                            record.update(stage="active", pending=None, pending_tier=None,
                                          last_error=f"无法保存阶梯保护计划：{type(exc).__name__}")
                        else:
                            try:
                                before = str((cgroup_path / "memory.high").read_text(encoding="ascii").strip())
                            except OSError:
                                before = None
                            if before != current_high:
                                record.update(stage="manual_override", last_error="执行前 memory.high 已改变；未覆盖管理员配置。")
                            else:
                                ok, output = _write_high(cgroup_path, target)
                                try:
                                    readback = (cgroup_path / "memory.high").read_text(encoding="ascii").strip()
                                except OSError:
                                    readback = None
                                if readback == target:
                                    record.update(stage="active", applied=target, tier=tier + 1, pending=None,
                                                  last_step_at=timestamp, escalation_since=0, escalation_samples=0, last_error="")
                                elif readback == current_high:
                                    record.update(stage="active", pending=None, pending_tier=None,
                                                  last_error=output or "阶梯 memory.high 未改变；保留此前已确认的限额。")
                                else:
                                    record.update(stage="escalating", last_error=output or "阶梯限额写入结果暂不可读；等待下一轮核验。")
            elif not pressure_high or used_percent < start_usage:
                record["escalation_since"], record["escalation_samples"], record["last_high"] = 0, 0, 0

            low = host_some >= 0 and cgroup_some >= 0 and host_some < recovery_pressure and cgroup_some < recovery_pressure
            if low:
                if not int(record.get("low_since") or 0):
                    record["low_since"], record["low_samples"] = timestamp, 1
                elif timestamp - int(record.get("last_low") or 0) > max_gap:
                    record["low_since"], record["low_samples"] = timestamp, 1
                else:
                    record["low_samples"] = int(record.get("low_samples") or 0) + 1
                record["last_low"] = timestamp
            else:
                record["low_since"], record["last_low"], record["low_samples"] = 0, 0, 0
            if (int(record.get("low_samples") or 0) >= recovery_samples
                    and timestamp - int(record.get("low_since") or timestamp) >= recovery_duration
                    and used_percent < 95.0):
                record.update(stage="restoring", pending=record.get("original"))
                try:
                    _write_state(path, state)
                except OSError as exc:
                    record.update(stage="restore_failed", last_error=f"无法保存恢复计划：{type(exc).__name__}")
                else:
                    ok, output = _write_high(cgroup_path, str(record.get("original") or "max"))
                    try:
                        restored_value = (cgroup_path / "memory.high").read_text(encoding="ascii").strip()
                    except OSError:
                        restored_value = None
                    if restored_value == str(record.get("original") or "max"):
                        instances[key] = {"stage": "cooldown", "cooldown_until": timestamp + cooldown_seconds,
                                          "last_seen": timestamp, "restored_at": timestamp}
                        reserved.discard(key)
                        status.update(state="restored", cooldown_until=timestamp + cooldown_seconds,
                                      message="内存压力持续回落，原 memory.high 已读回恢复；进入冷却期后再重新评估。")
                        security["memory_guard"] = status
                        continue
                    record.update(stage="restore_failed", last_error=output or "恢复后的 memory.high 读回不一致")

            record["confirmed_duration"] = max(0, timestamp - int(record.get("high_since") or record.get("applied_at") or timestamp))
            current_tier = max(1, min(3, int(record.get("tier") or 1)))
            status.update(state=record.get("stage"), tier=current_tier,
                          tier_percent_of_max={1: 90, 2: 80, 3: 70}.get(current_tier),
                          original_limit=record.get("original"), active_limit=record.get("applied"),
                          confirmed_duration_seconds=record["confirmed_duration"],
                          high_samples=int(record.get("high_samples") or record.get("escalation_samples") or 0),
                          required_samples=min_samples, recovery_samples=int(record.get("low_samples") or 0),
                          recovery_samples_required=recovery_samples, recovery_elapsed_seconds=max(0, timestamp - int(record.get("low_since") or timestamp)) if record.get("low_since") else 0,
                          message=record.get("last_error") or "可恢复内存 high 限额已应用；压力连续回落后会恢复原值。")
            security["memory_guard"] = status
            alerts.append(_alert(container, record, record.get("stage") == "active", status["message"]))
            continue

        if state_error:
            status.update(state="state_unavailable", message=state_error)
            security["memory_guard"] = status
            continue
        if not allow_new_limits:
            status.update(state="disabled", message="内存自动保护尚未启用；现有活动保护仍会继续恢复与核验。")
            security["memory_guard"] = status
            continue
        if cgroup_error or cgroup_path is None:
            security["memory_guard"] = status
            continue
        if not isinstance(maximum, int) or maximum < 32 * 1024 * 1024:
            status.update(state="unsupported", message="容器未配置可验证的 memory.max；不对无限内存配置施加自动限额。")
            security["memory_guard"] = status
            instances.pop(key, None)
            continue
        if str(metrics.get("high")) != "max" and int(str(metrics.get("high") or 0)) <= int(_target(maximum, 1)):
            status.update(state="existing_limit_stricter", message="现有 memory.high 已不高于第一阶目标；保留管理员限额。")
            security["memory_guard"] = status
            instances.pop(key, None)
            continue
        if host_pressure.get("status") != "ready" or cgroup_pressure.get("status") != "ready":
            status.update(state="psi_unavailable", message="宿主机或容器 memory PSI 不可用；为避免误限额，本轮不自动修改。")
            security["memory_guard"] = status
            instances.pop(key, None)
            continue
        other_guards = [security.get("cpu_guard"), security.get("io_guard")]
        if any(isinstance(item, dict) and item.get("state") in {"active", "limited", "restore_failed", "restoring", "escalating"} for item in other_guards):
            status.update(state="waiting_for_other_limit", message="该容器已有 CPU 或磁盘 I/O 保护；暂不叠加内存 high 限额。")
            security["memory_guard"] = status
            instances.pop(key, None)
            continue
        qualifies = (used_percent >= start_usage and host_some >= host_pressure_threshold
                     and cgroup_some >= container_pressure_threshold)
        if not qualifies:
            instances.pop(key, None)
            status["state"] = "waiting_for_pressure" if used_percent >= start_usage else "normal"
            security["memory_guard"] = status
            continue
        candidate = record if isinstance(record, dict) and record.get("stage") == "candidate" else {
            "stage": "candidate", "high_samples": 0, "high_since": 0, "last_high": 0, "last_attempt": 0,
        }
        previous_high = int(candidate.get("last_high") or 0)
        if previous_high <= 0 or timestamp <= previous_high or timestamp - previous_high > max_gap:
            candidate["high_samples"], candidate["high_since"] = 1, timestamp
        else:
            candidate["high_samples"] = int(candidate.get("high_samples") or 0) + 1
        candidate.update(last_high=timestamp, last_seen=timestamp, cgroup_path=str(cgroup_path),
                         memory_current_bytes=current_bytes, memory_max_bytes=maximum,
                         host_psi_some_avg10=host_some, container_psi_some_avg10=cgroup_some)
        instances[key] = candidate
        status.update(state="watching", high_samples=int(candidate["high_samples"]), required_samples=min_samples,
                      confirmed_duration_seconds=max(0, timestamp - int(candidate.get("high_since") or timestamp)),
                      message="内存用量与主机、容器 PSI 同时偏高，继续采样；需连续确认后才调整可回滚的 memory.high。")
        security["memory_guard"] = status
        if int(candidate["high_samples"]) >= min_samples and timestamp - int(candidate.get("high_since") or timestamp) >= required_duration:
            if any(other_key != key for other_key in reserved):
                status.update(state="waiting_for_other_limit", message="另一容器的内存保护限额仍在生效；当前容器继续等待。")
                continue
            original = str(metrics.get("high") or "max")
            target = _target(maximum, 1)
            if original != "max" and int(target) >= int(original):
                status.update(state="existing_limit_stricter", message="现有 memory.high 不高于自动保护目标；未改写管理员配置。")
                continue
            record = {"stage": "applying", "cgroup_path": str(cgroup_path), "original": original,
                      "applied": target, "tier": 0, "pending_tier": 1, "high_samples": candidate["high_samples"],
                      "high_since": candidate["high_since"], "confirmed_duration": timestamp - int(candidate["high_since"]),
                      "required_samples": min_samples, "recovery_samples_required": recovery_samples,
                      "recovery_duration_seconds": recovery_duration, "memory_current_bytes": current_bytes,
                      "memory_max_bytes": maximum, "host_psi_some_avg10": host_some,
                      "container_psi_some_avg10": cgroup_some, "last_seen": timestamp, "applied_at": timestamp}
            instances[key] = record
            reserved.add(key)
            try:
                _write_state(path, state)
            except OSError as exc:
                record.update(stage="candidate", last_error=f"无法保存 memory.high 回滚状态（{type(exc).__name__}）；未写入限额。")
                reserved.discard(key)
            else:
                before = (cgroup_path / "memory.high").read_text(encoding="ascii").strip()
                if before != original:
                    record.update(stage="manual_override", last_error="执行前 memory.high 已发生变化；未覆盖管理员配置。")
                else:
                    ok, output = _write_high(cgroup_path, target)
                    try:
                        readback = (cgroup_path / "memory.high").read_text(encoding="ascii").strip()
                    except OSError:
                        readback = None
                    if readback == target:
                        record.update(stage="active", tier=1, applied=target, last_error="")
                    elif readback == original:
                        message = output or "应用后的 memory.high 未改变；本次限额未生效。"
                        record.update(stage="candidate", applied=None, pending=None, pending_tier=None, tier=0, last_error=message)
                    else:
                        record.update(stage="apply_unverified", pending=target, pending_tier=1,
                                      last_error=output or "应用后的 memory.high 暂不可读；等待下一轮核验。")
                status.update(state=record.get("stage"), tier=int(record.get("tier") or 1), tier_percent_of_max=90,
                              original_limit=original, active_limit=record.get("applied"),
                              message=record.get("last_error") or "已读回确认第一阶 memory.high；只触发内存回收，不修改 hard memory.max。")
                security["memory_guard"] = status
                alerts.append(_alert(container, record, record.get("stage") == "active", status["message"]))

    for key, record in list(instances.items()):
        if key not in seen and isinstance(record, dict):
            if record.get("stage") in {"candidate", "cooldown"}:
                if record.get("stage") == "cooldown" and int(record.get("cooldown_until") or 0) > timestamp:
                    continue
                instances.pop(key, None)
            elif record.get("stage") in _ACTIVE_STAGES:
                old_path = Path(str(record.get("cgroup_path") or "/nonexistent"))
                try:
                    populated = (old_path / "cgroup.events").read_text(encoding="ascii", errors="ignore")
                    if not re.search(r"(?m)^populated 1\s*$", populated):
                        instances.pop(key, None)
                        reserved.discard(key)
                except OSError:
                    instances.pop(key, None)
                    reserved.discard(key)
            elif timestamp - int(record.get("last_seen") or timestamp) > 30 * 86400:
                instances.pop(key, None)
    if not state_error:
        try:
            _write_state(path, state)
        except OSError as exc:
            print(f"memory guard state could not be saved: {type(exc).__name__}")
    return {
        "enabled": bool(enabled and allow_new_limits),
        "state": "ready" if host_pressure.get("status") == "ready" else host_pressure.get("status", "unavailable"),
        "limited_containers": sum(1 for item in instances.values() if isinstance(item, dict) and item.get("stage") in {"active", "restore_failed"}),
        "reserved_containers": len(reserved),
        "host_pressure": host_pressure,
        "state_error": state_error,
        "policy": {"memory_usage_percent": start_usage, "host_psi_some_avg10_percent": host_pressure_threshold,
                   "container_psi_some_avg10_percent": container_pressure_threshold,
                   "required_duration_seconds": required_duration, "tier_percent_of_max": [90, 80, 70],
                   "escalation_duration_seconds": escalation_duration, "recovery_psi_some_avg10_percent": recovery_pressure,
                   "recovery_duration_seconds": recovery_duration, "cooldown_seconds": cooldown_seconds,
                   "max_simultaneous_container_limits": 1},
        "alerts": alerts,
    }
