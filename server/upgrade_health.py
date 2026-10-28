"""Shared fail-closed health gate for managed Agent upgrades."""


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
    if security_ok and report_security is not None and report_security.get("enabled") is not True:
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
