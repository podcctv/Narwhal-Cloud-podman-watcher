"""Shared fail-closed health gate for managed Agent upgrades."""

import json


def post_upgrade_observation(conn, host_id, node_id, version, action_updated_at, now=None, soak_seconds=120):
    """Require a fresh, healthy host and service sample after an upgrade soak."""
    import time

    now = int(time.time()) if now is None else int(now)
    action_updated_at = int(action_updated_at or 0)
    if action_updated_at <= 0:
        return False, ["缺少已确认的升级完成时间"]
    minimum_ts = action_updated_at + max(0, int(soak_seconds))
    host = conn.execute(
        "SELECT node_id,last_seen,agent_version FROM hosts WHERE host_id=?", (host_id,)
    ).fetchone()
    if not host or not node_id or host["node_id"] != node_id or host["agent_version"] != version:
        return False, ["节点身份或 Agent 目标版本不匹配"]
    if not minimum_ts <= int(host["last_seen"] or 0) <= now:
        return False, ["升级后的主机心跳尚未覆盖观察窗口"]
    if now - int(host["last_seen"] or 0) > 900:
        return False, ["主机心跳已过期"]

    ops_row = conn.execute(
        "SELECT ts,payload FROM ops_hosts WHERE host_id=? AND node=?",
        (host_id, node_id),
    ).fetchone()
    if not ops_row:
        return False, ["缺少升级后的运维采样"]
    ops_ts = int(ops_row["ts"] or 0)
    if ops_ts < minimum_ts or ops_ts > now or now - ops_ts > 900:
        return False, ["升级后的运维采样尚未覆盖观察窗口或已过期"]
    try:
        operations = json.loads(ops_row["payload"] or "{}")
    except (TypeError, ValueError):
        return False, ["运维采样格式无效"]
    if not isinstance(operations, dict):
        return False, ["运维采样格式无效"]

    has_reports = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='reports'"
    ).fetchone()
    report_row = conn.execute(
        "SELECT ts,payload_json FROM reports WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
        (host_id,),
    ).fetchone() if has_reports else None
    report = {}
    if report_row:
        report_ts = int(report_row["ts"] or 0)
        if report_ts < minimum_ts or report_ts > now or now - report_ts > 900:
            return False, ["升级后的容器采样尚未覆盖观察窗口或已过期"]
        try:
            report = json.loads(report_row["payload_json"] or "{}")
        except (TypeError, ValueError):
            return False, ["容器采样格式无效"]
        if not isinstance(report, dict):
            return False, ["容器采样格式无效"]
    else:
        inventory = operations.get("runtime_inventory")
        if not (
            isinstance(inventory, dict)
            and inventory.get("state") == "empty"
            and inventory.get("runtimes") == []
            and inventory.get("container_count") == 0
        ):
            return False, ["缺少升级后的容器采样"]
        report = {"containers": []}

    healthy, failed_sources = check(operations, report)
    return healthy, failed_sources


def check(operations, report=None):
    """Return ``(healthy, failed_sources)`` for an upgrade health report.

    Probe-only hosts with no container runtime can pass the security part only
    when the Agent explicitly reports an empty runtime inventory and no
    containers. Missing or disabled security data on a host with a runtime
    remains a hard failure.
    """
    operations = operations if isinstance(operations, dict) else {}
    health = operations.get("health") if isinstance(operations.get("health"), list) else []
    by_source = {
        str(item.get("source") or ""): str(item.get("status") or "")
        for item in health if isinstance(item, dict)
    }
    failed = []

    if by_source.get("network_counters") not in {"healthy", "idle"}:
        failed.append("network_counters")

    inventory = operations.get("runtime_inventory")
    inventory = inventory if isinstance(inventory, dict) else {}
    runtimes = inventory.get("runtimes") if isinstance(inventory.get("runtimes"), list) else None
    try:
        container_count = int(inventory.get("container_count", -1))
    except (TypeError, ValueError, OverflowError):
        container_count = -1
    empty_runtime_scope = (
        inventory.get("state") == "empty"
        and runtimes == []
        and container_count == 0
    )

    report_security = report.get("security") if isinstance(report, dict) else None
    report_security = report_security if isinstance(report_security, dict) else None
    report_containers = report.get("containers") if isinstance(report, dict) else None
    if report_containers is not None and not isinstance(report_containers, list):
        report_containers = None

    security_status = by_source.get("security")
    security_ok = security_status in {"healthy", "idle"}
    # Container reports may put per-container evidence in ``security`` without
    # the host-level ``enabled`` flag. In that schema, rely on the fresh ops
    # health status above; only an explicit host-level flag can override it.
    if (
        security_ok
        and report_security is not None
        and "enabled" in report_security
        and report_security.get("enabled") is not True
    ):
        security_ok = False
    if (
        not security_ok
        and security_status == "not_applicable"
        and empty_runtime_scope
        and (report_security is None or report_security.get("enabled") is False)
        and (report_containers is None or report_containers == [])
    ):
        security_ok = True
    if not security_ok:
        failed.append("security")

    services = operations.get("services") if isinstance(operations.get("services"), list) else []
    if any(not isinstance(item, dict) or item.get("status") != "healthy" for item in services):
        failed.append("service health check failed")

    return not failed, failed
