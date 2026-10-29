"""Small, evidence-based summary of the latest rule readbacks per host."""
from __future__ import annotations

from typing import Any


_ACTIVE_GUARD_STATES = {"active", "limited", "restore_failed", "enforced"}
_ISSUE_GUARD_STATES = {
    "unverified", "limit_unverified", "limited_unverified", "apply_unverified",
    "limit_failed", "restore_failed", "state_unavailable", "readback_unavailable",
    "stale", "unavailable", "failed", "retry_wait", "orphaned_cgroup",
    "applying", "escalating", "restoring",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def build_control_reconciliation(
    host_report: dict[str, Any],
    container_reports: list[dict[str, Any]],
    firewall_policy: dict[str, Any] | None,
    firewall_readback: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """Report desired/current state without claiming success from a command alone."""
    controls: list[dict[str, Any]] = []
    issues = 0
    host_is_stale = now - int(host_report.get("observed_at") or 0) > 900

    tc = _mapping(host_report.get("manual_bandwidth_limits"))
    tc_state = str(tc.get("state") or "unconfigured")
    tc_active = tc.get("active_limits") if isinstance(tc.get("active_limits"), list) else []
    tc_items = tc.get("items") if isinstance(tc.get("items"), list) else []
    tc_failures = [item for item in tc_items if isinstance(item, dict) and item.get("state") in {"failed", "rejected"}]
    tc_status = "stale" if host_is_stale else "failed" if tc_state in {"failed", "rejected"} or tc_failures else "verified" if tc_state == "applied" else "unconfigured"
    tc_reason = "；".join(str(item.get("message") or "tc 策略读回失败")[:180] for item in tc_failures[:3]) or str(tc.get("message") or "")
    controls.append({
        "control": "tc", "status": tc_status,
        "expected": {"revision": tc.get("revision"), "targets": len(tc_items)},
        "actual": {"active_limits": len(tc_active), "limits": tc_active[:8]},
        "last_confirmed_at": max((int(item.get("last_confirmed_at") or 0) for item in tc_active if isinstance(item, dict)), default=0),
        "reason": "最近宿主机样本已过期" if host_is_stale else tc_reason,
    })
    if tc_status in {"failed", "stale"}:
        issues += 1

    guard_summary: dict[str, dict[str, Any]] = {
        "cgroup_cpu": {"active": 0, "unverified": 0, "manual_override": 0, "samples": []},
        "cgroup_io": {"active": 0, "unverified": 0, "manual_override": 0, "samples": []},
        "nftables_admission": {"active": 0, "unverified": 0, "manual_override": 0, "samples": []},
    }
    for report in container_reports:
        security = _mapping(report.get("security"))
        identity = "/".join(str(report.get(key) or "") for key in ("runtime", "project", "container_name") if report.get(key))[:180]
        for field, control in (("cpu_guard", "cgroup_cpu"), ("io_guard", "cgroup_io"), ("admission", "nftables_admission")):
            guard = _mapping(security.get(field))
            state = str(guard.get("state") or "")
            if not state or state in {"normal", "watching", "disabled", "cooldown", "limit_not_needed", "warming"}:
                continue
            bucket = guard_summary[control]
            if state in _ISSUE_GUARD_STATES:
                bucket["unverified"] += 1
            elif state == "manual_override":
                bucket["manual_override"] += 1
            elif state in _ACTIVE_GUARD_STATES:
                verified = guard.get("readback_confirmed") is True if field in {"cpu_guard", "io_guard"} else state == "enforced"
                if verified:
                    bucket["active"] += 1
                else:
                    bucket["unverified"] += 1
            elif state not in {"restored", "manual_override", "waiting_for_other_limit", "candidate"}:
                bucket["unverified"] += 1
            if len(bucket["samples"]) < 5:
                bucket["samples"].append({
                    "container": identity or str(report.get("container_name") or "未知容器"),
                    "state": state,
                    "expected": guard.get("expected_limit") or guard.get("active_limit"),
                    "actual": guard.get("actual_limit"),
                    "reason": str(guard.get("message") or guard.get("error") or "")[:180],
                    "readback_confirmed": guard.get("readback_confirmed") is True or state == "enforced",
                })
    for control, summary in guard_summary.items():
        if summary["active"] or summary["unverified"] or summary["manual_override"]:
            status = "attention" if summary["unverified"] or summary["manual_override"] else "verified"
            controls.append({"control": control, "status": status, "expected": None,
                             "actual": {"verified_active": summary["active"], "unverified": summary["unverified"], "manual_override": summary["manual_override"]},
                             "samples": summary["samples"],
                             "reason": "检测到人工改动或有容器规则尚未完成读回确认。" if summary["unverified"] or summary["manual_override"] else "活动规则均有对应读回证据。"})
            if summary["unverified"] or summary["manual_override"]:
                issues += 1

    policy = _mapping(firewall_policy)
    live = _mapping(firewall_readback)
    if not policy:
        rfw_status = "unconfigured"
    elif host_is_stale or live.get("status") != "ready" or live.get("stale"):
        rfw_status = "unverified"
        issues += 1
    elif int(live.get("drift_count") or 0) or int(live.get("missing_count") or 0):
        rfw_status = "drift"
        issues += 1
    else:
        rfw_status = "verified"
    controls.append({
        "control": "rfw", "status": rfw_status,
        "expected": {"revision": policy.get("revision"), "rules": len(policy.get("rules") or []) if isinstance(policy.get("rules"), list) else 0},
        "actual": {"status": live.get("sync_status"), "rule_count": live.get("rule_count"),
                   "managed_rule_count": live.get("managed_rule_count"), "drift_count": live.get("drift_count"), "missing_count": live.get("missing_count")},
        "last_confirmed_at": live.get("last_success_at") or 0,
        "reason": ("RFW 当前没有保存策略" if not policy else "RFW 读回过期或不可用" if rfw_status == "unverified" else "期望规则与运行规则存在差异" if rfw_status == "drift" else "策略版本与 RFW 运行状态已读回一致"),
    })

    if any(item["status"] in {"failed", "stale", "attention", "unverified", "drift"} for item in controls):
        overall = "attention"
    elif any(item["status"] == "verified" for item in controls):
        overall = "verified"
    else:
        overall = "unconfigured"
    return {"status": overall, "issue_count": issues, "observed_at": int(host_report.get("observed_at") or 0), "controls": controls}
