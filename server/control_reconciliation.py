"""Evidence-based reconciliation of desired rules and live readbacks."""
from __future__ import annotations

from typing import Any


_ACTIVE_GUARD_STATES = {"active", "limited", "restore_failed", "enforced"}
_ISSUE_GUARD_STATES = {
    "unverified", "limit_unverified", "limited_unverified", "apply_unverified",
    "limit_failed", "restore_failed", "state_unavailable", "readback_unavailable",
    "limit_readback_unavailable", "stale", "unavailable", "failed", "retry_wait",
    "orphaned_cgroup", "applying", "escalating", "restoring",
}
_RETRY_ON_NEXT_SAMPLE = {
    "applying", "escalating", "restoring", "restore_failed", "apply_unverified",
    "limit_unverified", "limited_unverified", "retry_wait", "limit_failed",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or_none(value: Any) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if result >= 0 else None


def _tc_item_matches(item: dict[str, Any], limits: list[dict[str, Any]]) -> bool:
    direction = str(item.get("direction") or "")
    try:
        rate = int(item.get("rate_mbps") or 0)
    except (TypeError, ValueError):
        return False
    if direction not in {"upload", "download"} or rate <= 0:
        return False
    for actual in limits:
        if not isinstance(actual, dict) or actual.get("scope") != item.get("scope"):
            continue
        if item.get("scope") == "host":
            identity_matches = actual.get("interface") == item.get("interface")
        else:
            identity_matches = (
                actual.get("runtime") == item.get("runtime")
                and str(actual.get("project") or "") == str(item.get("project") or "")
                and str(actual.get("container_id") or "") == str(item.get("container_id") or "")
                and str(actual.get("container_name") or "") == str(item.get("container_name") or "")
            )
        if not identity_matches:
            continue
        try:
            actual_rate = int(actual.get(f"{direction}_mbps") or 0)
        except (TypeError, ValueError):
            continue
        if actual_rate == rate:
            return True
    return False


def _guard_retry(guard: dict[str, Any], state: str) -> dict[str, Any]:
    remaining = _int_or_none(guard.get("retry_after_seconds"))
    attempts = _int_or_none(guard.get("attempts", guard.get("retry_count")))
    if remaining is not None and remaining > 0:
        return {"state": "waiting", "after_seconds": remaining, "attempts": attempts}
    if state in _RETRY_ON_NEXT_SAMPLE:
        return {"state": "next_agent_sample", "after_seconds": None, "attempts": attempts}
    return {"state": "not_scheduled", "after_seconds": None, "attempts": attempts}


def _guard_rollback(guard: dict[str, Any], state: str) -> dict[str, Any]:
    original = guard.get("original_limit", guard.get("original"))
    active = guard.get("active_limit", guard.get("applied"))
    if state == "restored":
        rollback_state = "verified"
    elif state in {"restoring", "applying", "escalating"}:
        rollback_state = "in_progress" if state == "restoring" else "available"
    elif state == "restore_failed":
        rollback_state = "failed"
    elif original is not None and state in _ACTIVE_GUARD_STATES:
        rollback_state = "available"
    elif state in {"manual_override", "manual_reset"}:
        rollback_state = "manual_change"
    else:
        rollback_state = "not_started"
    return {"state": rollback_state, "target": original, "current_limit": active}


def _action_retry(action: dict[str, Any]) -> dict[str, Any]:
    state = str(action.get("status") or "unknown")
    attempts = _int_or_none(action.get("attempts"))
    if state in {"queued", "dispatched", "running"}:
        return {"state": "pending_agent", "attempts": attempts, "after_seconds": None}
    if state == "failed":
        return {"state": "exhausted_or_failed", "attempts": attempts, "after_seconds": None}
    return {"state": "not_scheduled", "attempts": attempts, "after_seconds": None}


def _rfw_rollback(action: dict[str, Any], live: dict[str, Any], revision: Any) -> dict[str, Any]:
    rollback = _mapping(action.get("rollback"))
    if not rollback.get("requested"):
        return {"state": "not_requested"}
    action_state = str(action.get("status") or "unknown")
    snapshot = _mapping(live.get("snapshot"))
    drift_count = _int_or_none(live.get("drift_count"))
    missing_count = _int_or_none(live.get("missing_count"))
    if (action_state == "succeeded" and live.get("stale") is False
            and live.get("sync_status") == "in_sync"
            and drift_count == 0
            and missing_count == 0
            and snapshot.get("policy_revision") == revision):
        state = "verified"
    elif action_state == "failed":
        state = "failed"
    elif action_state in {"queued", "dispatched", "running", "succeeded"}:
        state = "in_progress" if action_state != "succeeded" else "awaiting_readback"
    else:
        state = "unverified"
    return {"state": state, "target_revision": rollback.get("target_revision")}


def build_control_reconciliation(
    host_report: dict[str, Any],
    container_reports: list[dict[str, Any]],
    firewall_policy: dict[str, Any] | None,
    firewall_readback: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    """Report desired/current state, retry, and restoration evidence."""
    controls: list[dict[str, Any]] = []
    issues = 0
    observed_at = _int_or_none(host_report.get("observed_at")) or 0
    host_is_stale = now - observed_at > 900

    tc = _mapping(host_report.get("manual_bandwidth_limits"))
    tc_state = str(tc.get("state") or "unconfigured")
    tc_active = [item for item in tc.get("active_limits", []) if isinstance(item, dict)] if isinstance(tc.get("active_limits"), list) else []
    tc_items = [item for item in tc.get("items", []) if isinstance(item, dict)] if isinstance(tc.get("items"), list) else []
    tc_failures = [item for item in tc_items if item.get("state") in {"failed", "rejected", "cleanup_failed"}]
    tc_expected = [item for item in tc_items if item.get("state") == "applied" and _int_or_none(item.get("rate_mbps"))]
    tc_unmatched = [item for item in tc_expected if not _tc_item_matches(item, tc_active)]
    tc_actual_unexpected = not tc_expected and bool(tc_active) and tc_state == "unconfigured"
    if host_is_stale:
        tc_status = "stale"
    elif tc_state in {"failed", "rejected"} or tc_failures:
        tc_status = "failed"
    elif tc_unmatched or tc_actual_unexpected:
        tc_status = "drift"
    elif tc_state == "applied" and len(tc_expected) == 0 and tc_active:
        tc_status = "drift"
    elif tc_state == "applied":
        tc_status = "verified"
    else:
        tc_status = "unconfigured"
    tc_reason = "；".join(str(item.get("message") or "tc 应用或读回失败")[:180] for item in tc_failures[:3])
    if not tc_reason and tc_unmatched:
        tc_reason = f"{len(tc_unmatched)} 条期望限额没有对应的实际限额读回。"
    if not tc_reason and tc_actual_unexpected:
        tc_reason = "策略显示未配置，但仍读到活动限额。"
    rollback = _mapping(tc.get("rollback")) or {"state": "not_reported"}
    tc_retry = _mapping(tc.get("retry"))
    if not tc_retry:
        tc_retry = {"state": "next_agent_cycle" if tc_status in {"failed", "drift", "stale"} else "not_scheduled",
                    "after_seconds": None, "attempts": None}
    controls.append({
        "control": "tc", "status": tc_status,
        "expected": {"revision": tc.get("revision"), "targets": len(tc_expected), "limits": tc_expected[:8]},
        "actual": {"active_limits": len(tc_active), "limits": tc_active[:8]},
        "retry": tc_retry,
        "rollback": rollback,
        "last_confirmed_at": max((int(item.get("last_confirmed_at") or 0) for item in tc_active), default=0),
        "reason": "最近宿主机样本已过期" if host_is_stale else tc_reason or str(tc.get("message") or ""),
    })
    if tc_status in {"failed", "stale", "drift"}:
        issues += 1

    guard_summary: dict[str, dict[str, Any]] = {
        control: {"active": 0, "unverified": 0, "manual_override": 0, "restore_failed": 0,
                  "retry_pending": 0, "retry_waiting": [], "rollback_failed": 0, "samples": []}
        for control in ("cgroup_cpu", "cgroup_memory", "cgroup_io", "nftables_admission")
    }
    for report in container_reports:
        security = _mapping(report.get("security"))
        identity = "/".join(str(report.get(key) or "") for key in ("runtime", "project", "container_name") if report.get(key))[:180]
        for field, control in (("cpu_guard", "cgroup_cpu"), ("memory_guard", "cgroup_memory"),
                               ("io_guard", "cgroup_io"), ("admission", "nftables_admission")):
            guard = _mapping(security.get(field))
            state = str(guard.get("state") or "")
            if not state or state in {"normal", "watching", "disabled", "cooldown", "limit_not_needed", "warming", "candidate"}:
                continue
            bucket = guard_summary[control]
            if state == "manual_override":
                bucket["manual_override"] += 1
            if state == "restore_failed":
                bucket["restore_failed"] += 1
            if state in _ACTIVE_GUARD_STATES:
                verified = guard.get("readback_confirmed") is True if field != "admission" else state == "enforced"
                if verified:
                    bucket["active"] += 1
                else:
                    bucket["unverified"] += 1
            elif state in _ISSUE_GUARD_STATES:
                bucket["unverified"] += 1
            elif state not in {"restored", "manual_override", "manual_reset", "waiting_for_other_limit"}:
                bucket["unverified"] += 1
            retry = _guard_retry(guard, state)
            if retry["state"] == "waiting":
                bucket["retry_waiting"].append(retry.get("after_seconds"))
            elif retry["state"] != "not_scheduled":
                bucket["retry_pending"] += 1
            restore = _guard_rollback(guard, state) if field != "admission" else {"state": "not_applicable"}
            if restore.get("state") == "failed":
                bucket["rollback_failed"] += 1
            if len(bucket["samples"]) < 5:
                bucket["samples"].append({
                    "container": identity or str(report.get("container_name") or "未知容器"),
                    "state": state,
                    "expected": guard.get("expected_limit") or guard.get("active_limit"),
                    "actual": guard.get("actual_limit"),
                    "retry": retry,
                    "rollback": restore,
                    "reason": str(guard.get("message") or guard.get("last_error") or guard.get("error") or "")[:180],
                    "readback_confirmed": guard.get("readback_confirmed") is True or state == "enforced",
                })
    for control, summary in guard_summary.items():
        if summary["active"] or summary["unverified"] or summary["manual_override"] or summary["restore_failed"] or summary["retry_pending"] or summary["retry_waiting"]:
            needs_attention = bool(summary["unverified"] or summary["manual_override"] or summary["restore_failed"] or summary["retry_pending"] or summary["retry_waiting"])
            retry_after = min((value for value in summary["retry_waiting"] if isinstance(value, int) and value > 0), default=None)
            controls.append({
                "control": control, "status": "attention" if needs_attention else "verified", "expected": None,
                "actual": {"verified_active": summary["active"], "unverified": summary["unverified"],
                           "manual_override": summary["manual_override"], "restore_failed": summary["restore_failed"]},
                "samples": summary["samples"],
                "retry": {"state": "waiting" if retry_after is not None else "next_agent_sample" if summary["retry_pending"] else "not_scheduled",
                          "after_seconds": retry_after, "pending": summary["retry_pending"] + len(summary["retry_waiting"])},
                "rollback": {"state": "failed" if summary["rollback_failed"] else "available_or_per_sample",
                             "failed": summary["rollback_failed"]},
                "reason": "存在读回待核实、人工改动或原限额恢复失败。" if needs_attention else "活动规则均有对应读回证据。",
            })
            if needs_attention:
                issues += 1

    policy = _mapping(firewall_policy)
    live = _mapping(firewall_readback)
    action = _mapping(live.get("latest_action"))
    revision = policy.get("revision")
    # Do not let a failed or pending action for an older policy version mask
    # the readback for the current desired state.
    if action.get("policy_revision") != revision:
        action = {}
    action_state = str(action.get("status") or "")
    if not policy:
        rfw_status = "unconfigured"
    elif host_is_stale or live.get("status") != "ready" or live.get("stale"):
        rfw_status = "unverified"
        issues += 1
    elif action_state in {"queued", "dispatched", "running"}:
        rfw_status = "applying"
        issues += 1
    elif action_state == "failed":
        rfw_status = "failed"
        issues += 1
    elif _int_or_none(live.get("drift_count")) is None or _int_or_none(live.get("missing_count")) is None:
        rfw_status = "unverified"
        issues += 1
    elif _int_or_none(live.get("drift_count")) or _int_or_none(live.get("missing_count")):
        rfw_status = "drift"
        issues += 1
    elif live.get("sync_status") != "in_sync":
        rfw_status = "unverified"
        issues += 1
    elif _mapping(live.get("snapshot")).get("policy_revision") != revision:
        rfw_status = "drift"
        issues += 1
    else:
        rfw_status = "verified"
    controls.append({
        "control": "rfw", "status": rfw_status,
        "expected": {"revision": revision, "rules": len(policy.get("rules") or []) if isinstance(policy.get("rules"), list) else 0},
        "actual": {"revision": _mapping(live.get("snapshot")).get("policy_revision"), "status": live.get("sync_status"),
                   "rule_count": live.get("rule_count"), "managed_rule_count": live.get("managed_rule_count"),
                   "drift_count": live.get("drift_count"), "missing_count": live.get("missing_count")},
        "retry": _action_retry(action) if action else {"state": "not_scheduled", "attempts": None},
        "rollback": _rfw_rollback(action, live, revision),
        "last_confirmed_at": live.get("last_success_at") or 0,
        "reason": ("RFW 当前没有保存策略" if not policy
                   else str(action.get("result_message") or "防火墙策略操作等待 Agent 回执")[:180] if rfw_status in {"applying", "failed"}
                   else "RFW 读回过期或不可用" if rfw_status == "unverified"
                   else "期望规则与运行规则存在差异" if rfw_status == "drift"
                   else "策略版本与 RFW 运行状态已读回一致"),
    })

    if any(item["status"] in {"failed", "stale", "attention", "unverified", "drift", "applying"} for item in controls):
        overall = "attention"
    elif any(item["status"] == "verified" for item in controls):
        overall = "verified"
    else:
        overall = "unconfigured"
    return {"status": overall, "issue_count": issues, "observed_at": int(host_report.get("observed_at") or 0), "controls": controls}
