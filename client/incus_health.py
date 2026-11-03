"""Bounded Incus runtime health checks and fail-closed lifecycle guards."""

import json
import os
import re
import subprocess
import time
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlsplit


ALERT_TYPES = (
    "incus_instance_error",
    "incus_lifecycle_operation_stuck",
    "incus_lifecycle_operation_unverified",
    "incus_api_unavailable",
    "incus_operation_inventory_unavailable",
    "incus_api_slow",
)


def _bounded_float(name, default, minimum, maximum):
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = float(default)
    return min(maximum, max(minimum, value))


def command_timeout_seconds():
    return _bounded_float("INCUS_HEALTH_COMMAND_TIMEOUT_SECONDS", 8, 3, 15)


def stuck_operation_seconds():
    return _bounded_float("INCUS_STUCK_OPERATION_SECONDS", 300, 60, 3600)


def slow_api_milliseconds():
    return _bounded_float("INCUS_SLOW_API_MILLISECONDS", 3000, 500, 10000)


def _all_projects(project):
    return not str(project or "").strip() or str(project).strip().lower() in {"all", "*"}


def _base(runtime, project):
    command = [runtime]
    if project:
        command.extend(["--project", str(project)])
    return command


def _run_json(runtime, project, args, timeout=None):
    command = _base(runtime, project) + list(args)
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=command_timeout_seconds() if timeout is None else timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "items": [], "latency_ms": round((time.monotonic() - started) * 1000, 1), "error": "timeout"}
    except FileNotFoundError:
        return {"ok": False, "items": [], "latency_ms": round((time.monotonic() - started) * 1000, 1), "error": "command_unavailable"}
    except OSError:
        return {"ok": False, "items": [], "latency_ms": round((time.monotonic() - started) * 1000, 1), "error": "command_failed"}

    latency_ms = round((time.monotonic() - started) * 1000, 1)
    if result.returncode != 0:
        return {"ok": False, "items": [], "latency_ms": latency_ms, "error": "command_failed"}
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError):
        return {"ok": False, "items": [], "latency_ms": latency_ms, "error": "invalid_json"}
    if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
        return {"ok": False, "items": [], "latency_ms": latency_ms, "error": "invalid_shape"}
    return {"ok": True, "items": payload, "latency_ms": latency_ms, "error": ""}


def list_instances(runtime, project="all", name_pattern=""):
    all_projects = _all_projects(project)
    selected_project = "" if all_projects else (str(project).strip() or "default")
    args = ["list"]
    if name_pattern:
        args.append(name_pattern)
    if all_projects:
        args.append("--all-projects")
    args.extend(["type=container", "--format=json"])
    return _run_json(runtime, selected_project, args)


def list_operations(runtime, project="all"):
    all_projects = _all_projects(project)
    selected_project = "" if all_projects else (str(project).strip() or "default")
    args = ["operation", "list"]
    if all_projects:
        args.append("--all-projects")
    args.append("--format=json")
    return _run_json(runtime, selected_project, args)


def _instance_project(instance, default_project="default"):
    project = str(instance.get("project") or default_project).strip()
    return project or "default"


def _instance_name(instance):
    return str(instance.get("name") or "").strip()


def _instance_status(instance):
    return str(instance.get("status") or "unknown").strip().lower()


def _instance_uuid(instance):
    config = instance.get("config") if isinstance(instance.get("config"), dict) else {}
    return str(config.get("volatile.uuid") or "").strip()[:100]


def _operation_is_running(operation):
    status = str(operation.get("status") or "").strip().lower()
    if status == "running":
        return True
    try:
        return int(operation.get("status_code")) == 103
    except (TypeError, ValueError):
        return False


def _lifecycle_action(operation):
    metadata = operation.get("metadata") if isinstance(operation.get("metadata"), dict) else {}
    text = " ".join(
        str(value or "")
        for value in (operation.get("description"), metadata.get("action"), metadata.get("name"))
    ).lower()
    for action, pattern in (
        ("restart", r"\b(restart|restarting|reboot|rebooting)\b"),
        ("stop", r"\b(stop|stopping)\b"),
        ("start", r"\b(start|starting)\b"),
        ("delete", r"\b(delete|deleting|remove|removing)\b"),
    ):
        if re.search(pattern, text):
            return action
    return ""


def _operation_targets(operation, default_project="default"):
    resources = operation.get("resources") if isinstance(operation.get("resources"), dict) else {}
    urls = resources.get("instances") or resources.get("containers") or []
    if isinstance(urls, str):
        urls = [urls]
    targets = []
    for resource in urls if isinstance(urls, list) else []:
        if not isinstance(resource, str):
            continue
        parsed = urlsplit(resource)
        components = [unquote(part) for part in parsed.path.split("/") if part]
        name = ""
        for kind in ("instances", "containers"):
            if kind in components:
                index = components.index(kind)
                if index + 1 < len(components):
                    name = components[index + 1]
                    break
        if not name:
            continue
        query = parse_qs(parsed.query)
        project = str((query.get("project") or [default_project])[0] or default_project)
        targets.append({"name": name[:200], "project": project[:100]})
    return targets


def _created_epoch(operation):
    raw = str(operation.get("created_at") or "").strip()
    if not raw:
        return 0
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0


def _alert(alert_type, severity, title, message, project="", name="", alert_key="", **details):
    result = {
        "type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "value": float(details.get("value") or 0),
        "threshold": float(details.get("threshold") or 0),
        "runtime": "incus",
        "project": str(project or "")[:100],
        "container_name": str(name or "")[:200],
        "alert_key": str(alert_key or "")[:240],
        "observation": {
            key: value
            for key, value in details.items()
            if key not in {"value", "threshold"} and isinstance(value, (str, int, float, bool))
        },
    }
    if details.get("instance_id"):
        result["instance_id"] = str(details["instance_id"])[:100]
    return result


def build_snapshot(instance_scan, operation_scan, project="all", now=None):
    now = time.time() if now is None else float(now)
    instance_scan = instance_scan if isinstance(instance_scan, dict) else {"ok": False, "items": [], "error": "not_checked"}
    operation_scan = operation_scan if isinstance(operation_scan, dict) else {"ok": False, "items": [], "error": "not_checked"}
    instance_ok = instance_scan.get("ok") is True
    operation_ok = operation_scan.get("ok") is True
    scan_status = "complete" if instance_ok and operation_ok else "partial" if instance_ok or operation_ok else "unavailable"
    selected_all = _all_projects(project)
    selected_project = "" if selected_all else (str(project).strip() or "default")
    instances = [item for item in instance_scan.get("items", []) if isinstance(item, dict)] if instance_ok else []
    container_targets = {
        (_instance_project(item), _instance_name(item))
        for item in instances
        if _instance_name(item)
    }
    error_instances = []
    alerts = []
    for instance in instances:
        if _instance_status(instance) != "error":
            continue
        name = _instance_name(instance)
        if not name:
            continue
        item_project = _instance_project(instance)
        identity = _instance_uuid(instance)
        state = instance.get("state") if isinstance(instance.get("state"), dict) else {}
        pid = state.get("pid")
        entry = {"name": name, "project": item_project, "status": str(instance.get("status") or "Error"), "pid": pid, "instance_id": identity}
        error_instances.append(entry)
        log_hint = f"/var/log/incus/{identity}/lxc.log" if identity else f"/var/log/incus/<instance-id>/lxc.log"
        alerts.append(
            _alert(
                "incus_instance_error",
                "critical",
                "Incus 实例进入 ERROR，自动停止已暂停",
                f"Incus 报告 {item_project}/{name} 状态为 ERROR（PID={pid if pid is not None else 'unknown'}）。Watcher 不会再次提交 stop/restart/delete；保留实例现场并人工检查 {log_hint}、forkexec.log、控制台日志及对应 Incus 操作。",
                item_project,
                name,
                f"instance:{item_project}:{name}:{identity or 'unknown'}",
                status="error",
                pid=pid if isinstance(pid, (int, float)) else str(pid or "unknown"),
                instance_id=identity,
                automatic_action="alert_only",
            )
        )

    operation_rows = [item for item in operation_scan.get("items", []) if isinstance(item, dict)] if operation_ok else []
    active_lifecycle = []
    stuck_operations = []
    stuck_after = stuck_operation_seconds()
    for operation in operation_rows:
        if not _operation_is_running(operation):
            continue
        action = _lifecycle_action(operation)
        if not action:
            continue
        targets = _operation_targets(operation, "default" if selected_all else selected_project)
        # Incus operation resources are normally populated. If a lifecycle operation
        # has no target, keep it as a host-wide guard so no other stop is enqueued.
        matched_targets = [target for target in targets if (target["project"], target["name"]) in container_targets]
        if not matched_targets and targets:
            continue
        created = _created_epoch(operation)
        age = max(0, int(now - created)) if created else None
        op_id = str(operation.get("id") or "unknown")[:100]
        description = str(operation.get("description") or action)[:200]
        for target in matched_targets or [{"name": "", "project": ""}]:
            summary = {
                "id": op_id,
                "name": target["name"],
                "project": target["project"],
                "action": action,
                "description": description,
                "created_at": str(operation.get("created_at") or "")[:80],
                "age_seconds": age,
                "may_cancel": operation.get("may_cancel") is True,
                "target_known": bool(target["name"]),
            }
            active_lifecycle.append(summary)
            target_label = f"{target['project']}/{target['name']}" if target["name"] else "目标实例未知"
            if age is None:
                alerts.append(
                    _alert(
                        "incus_lifecycle_operation_unverified",
                        "warning",
                        "Incus 生命周期操作时长无法核实",
                        f"Incus 操作 {op_id}（{description}）仍在运行，但创建时间缺失或无法解析，目标为 {target_label}。自动停止已暂停；先核对操作状态和实例日志。",
                        target["project"],
                        target["name"],
                        f"operation:{op_id}:age-unknown",
                        operation_id=op_id,
                        operation_action=action,
                        target_known=summary["target_known"],
                        may_cancel=summary["may_cancel"],
                    )
                )
                continue
            if age < stuck_after:
                continue
            stuck_operations.append(summary)
            cancel_label = "可取消" if summary["may_cancel"] else "不可取消"
            alerts.append(
                _alert(
                    "incus_lifecycle_operation_stuck",
                    "critical",
                    "Incus 实例状态变更操作长时间未完成",
                    f"Incus 操作 {op_id}（{description}）已运行约 {age} 秒，目标为 {target_label}，状态显示{cancel_label}。Watcher 不会重复提交停止/重启；不要用 operation delete 当作强制解锁，也不会自动重启 Incus 守护进程。",
                    target["project"],
                    target["name"],
                    f"operation:{op_id}",
                    age_seconds=age,
                    operation_id=op_id,
                    operation_action=action,
                    may_cancel=summary["may_cancel"],
                    threshold=stuck_after,
                )
            )

    if not instance_ok:
        alerts.append(
            _alert(
                "incus_api_unavailable",
                "warning",
                "Incus 实例状态读取失败",
                "Watcher 未能在限定时间内取得完整 Incus 容器清单；容器状态保持未知，已暂停本轮 Incus 自动停机判断。检查 incus CLI/守护进程和 systemd 状态。",
                alert_key="api:instances",
                command_status=str(instance_scan.get("error") or "unavailable"),
            )
        )
    if not operation_ok:
        alerts.append(
            _alert(
                "incus_operation_inventory_unavailable",
                "warning",
                "Incus 后台操作清单读取失败",
                "Watcher 无法确认 Incus 是否已有启动、停止、重启或删除操作；本轮会暂停所有 Incus 自动停机，不会冒险重复提交。检查 Incus API 与 incus.service。",
                alert_key="api:operations",
                command_status=str(operation_scan.get("error") or "unavailable"),
            )
        )

    latency_values = []
    for label, scan in (("instances", instance_scan), ("operations", operation_scan)):
        try:
            latency = float(scan.get("latency_ms") or 0)
        except (TypeError, ValueError):
            latency = 0.0
        latency_values.append((label, latency, scan.get("ok") is True))
        if scan.get("ok") is True and latency >= slow_api_milliseconds():
            alerts.append(
                _alert(
                    "incus_api_slow",
                    "warning",
                    "Incus 管理 API 响应变慢",
                    f"Incus {label} 查询耗时约 {latency:.0f} ms。Watcher 只记录与告警，不会重启 Incus 服务。",
                    alert_key=f"api:slow:{label}",
                    latency_ms=latency,
                    threshold=slow_api_milliseconds(),
                    query=label,
                )
            )

    if scan_status == "unavailable":
        status = "unavailable"
    elif alerts:
        status = "degraded"
    elif scan_status != "complete":
        status = "partial"
    else:
        status = "healthy"
    return {
        "status": status,
        "scan_status": scan_status,
        "observed_at": int(now),
        "project_scope": "all" if selected_all else selected_project,
        "instance_count": len(instances),
        "error_instance_count": len(error_instances),
        "error_instances": error_instances[:100],
        "operation_count": len(operation_rows),
        "active_lifecycle_operation_count": len(active_lifecycle),
        "stuck_lifecycle_operation_count": len(stuck_operations),
        "active_lifecycle_operations": active_lifecycle[:100],
        "stuck_lifecycle_operations": stuck_operations[:100],
        "api_latency_ms": {label: latency for label, latency, _ in latency_values},
        "command_timeout_seconds": command_timeout_seconds(),
        "stuck_operation_threshold_seconds": stuck_after,
        "automatic_recovery": {
            "error_instance": "alert_only",
            "duplicate_lifecycle_actions": "blocked",
            "incus_daemon_restart": "manual_only",
        },
        "alerts": alerts[:200],
    }


def stop_preflight(runtime, project, name):
    """Allow a targeted Incus stop only after fresh state and operation checks."""
    project = str(project or "default").strip() or "default"
    name = str(name or "").strip()
    if _all_projects(project) or not name:
        return False, "Incus stop skipped: exact project and instance identity are required"
    inventory = list_instances(runtime, project, "^" + re.escape(name) + "$")
    if inventory.get("ok") is not True:
        return False, "Incus stop skipped: current instance state could not be verified"
    if float(inventory.get("latency_ms") or 0) >= slow_api_milliseconds():
        return False, "Incus stop skipped: instance query is slow; leave lifecycle state untouched"
    matches = [item for item in inventory.get("items", []) if _instance_name(item) == name]
    if len(matches) != 1:
        return False, "Incus stop skipped: the exact instance could not be identified"
    instance = matches[0]
    if str(instance.get("type") or "container").lower() not in {"container", ""}:
        return False, "Incus stop skipped: target is not a container"
    if _instance_status(instance) != "running":
        return False, f"Incus stop skipped: target state is {instance.get('status') or 'unknown'}; no repeated stop submitted"

    operations = list_operations(runtime, project)
    if operations.get("ok") is not True:
        return False, "Incus stop skipped: pending lifecycle operations could not be checked"
    if float(operations.get("latency_ms") or 0) >= slow_api_milliseconds():
        return False, "Incus stop skipped: operation query is slow; leave lifecycle state untouched"
    target_key = (project, name)
    for operation in operations.get("items", []):
        if not _operation_is_running(operation) or not _lifecycle_action(operation):
            continue
        targets = _operation_targets(operation, project)
        if not targets or any((target["project"], target["name"]) == target_key for target in targets):
            operation_id = str(operation.get("id") or "unknown")
            return False, f"Incus stop skipped: lifecycle operation {operation_id} is already running for this target or has an unknown target"
    return True, ""
