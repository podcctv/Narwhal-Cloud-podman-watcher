"""Generation-bound restart policy for sustained Runman resource pressure.

Only fresh Runman reports with a canonical instance UUID are eligible. CPU
pressure requires a fresh Runman history sample; memory pressure requires a
non-zero reported limit. Missing, stale, replayed, or replaced samples break
the continuous window.
"""
import json
import math
import re
import time
import uuid


ACTION_TYPE = "restart_container"
ACTION_REASON = "sustained_resource_overload"
METRIC_NAMES = ("cpu_percent", "memory_percent")
MINIMUM_AGENT_VERSION = (1, 8, 28)


def initialize(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS resource_overload_windows(
        host_id TEXT NOT NULL,
        runtime TEXT NOT NULL,
        project TEXT NOT NULL,
        container_name TEXT NOT NULL,
        payload TEXT NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY(host_id,runtime,project,container_name))""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_resource_overload_windows_last_seen "
        "ON resource_overload_windows(last_seen)"
    )


def _number(value):
    if type(value) not in (int, float):
        return None
    result = float(value)
    return result if math.isfinite(result) and result >= 0 else None


def _generation(container):
    if not isinstance(container, dict) or str(container.get("runtime") or "").lower() != "runman":
        return ""
    if str(container.get("project") or "") != "default" or str(container.get("status") or "").lower() != "running":
        return ""
    name = str(container.get("name") or "").lower()
    stable_id = str(container.get("stable_id") or container.get("id") or "").lower()
    generation = str(container.get("instance_id") or "").lower()
    try:
        parsed_name = uuid.UUID(name)
        parsed_stable = uuid.UUID(stable_id)
        parsed_generation = uuid.UUID(generation)
    except (AttributeError, TypeError, ValueError):
        return ""
    if (
        str(parsed_name) != name or str(parsed_stable) != stable_id
        or str(parsed_generation) != generation or stable_id != name
        or parsed_generation.version != 4 or parsed_generation.variant != uuid.RFC_4122
    ):
        return ""
    return generation


def _resource_values(container, now):
    """Return independently validated percentages and a reason for missing data."""
    values = {"cpu_percent": None, "memory_percent": None}
    reasons = {}
    security = container.get("security") if isinstance(container.get("security"), dict) else {}
    metrics = security.get("runman_metrics") if isinstance(security.get("runman_metrics"), dict) else {}
    sampled_at = metrics.get("sampled_at")
    cpu = _number(metrics.get("cpu_percent"))
    cpu_fresh = (
        metrics.get("available") is True
        and metrics.get("source") == "runman_history"
        and type(sampled_at) is int and sampled_at > 0
        and sampled_at <= now + 30 and now - sampled_at <= 180
        and cpu is not None and cpu <= 1000
    )
    if cpu_fresh:
        values["cpu_percent"] = cpu
    else:
        reasons["cpu_percent"] = "Runman CPU 历史采样不可用或已过期"

    memory = container.get("mem_bytes")
    limit = container.get("mem_limit_bytes")
    if type(memory) is int and memory >= 0 and type(limit) is int and limit > 0:
        value = 100.0 * memory / limit
        if math.isfinite(value) and value <= 10000:
            values["memory_percent"] = value
    if values["memory_percent"] is None:
        reasons["memory_percent"] = "Runman 内存用量或有效限额缺失"
    return values, reasons


def _load_payload(row):
    try:
        value = json.loads(row[0]) if row else {}
    except (TypeError, ValueError):
        value = {}
    return value if isinstance(value, dict) else {}


def _supports_restart_agent(version):
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$", str(version or "").strip())
    if not match:
        return False
    return tuple(int(part) for part in match.groups()) >= MINIMUM_AGENT_VERSION


def observe(
    conn,
    host_id,
    node_id,
    report_ts,
    containers,
    *,
    now=None,
    enabled=True,
    cpu_threshold=90.0,
    memory_threshold=90.0,
    required_duration=3600,
    max_gap=900,
    cooldown=3600,
    min_samples=5,
    stale_seconds=900,
):
    """Attach window status to reports and queue at most one exact-generation restart."""
    now = int(time.time()) if now is None else int(now)
    report_ts = int(report_ts or 0)
    queued = 0
    config_matches = bool(node_id)
    try:
        host = conn.execute("SELECT node_id,agent_version FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        config_matches = (
            config_matches and host is not None and str(host[0] or "") == str(node_id)
            and _supports_restart_agent(host[1])
        )
    except Exception:
        config_matches = False

    for container in containers:
        if not isinstance(container, dict) or str(container.get("runtime") or "").lower() != "runman":
            continue
        key = (
            str(host_id)[:200], "runman", "default",
            str(container.get("name") or "unknown")[:200],
        )
        existing_row = conn.execute(
            "SELECT payload FROM resource_overload_windows "
            "WHERE host_id=? AND runtime=? AND project=? AND container_name=?", key,
        ).fetchone()
        old = _load_payload(existing_row)
        old_last = int(old.get("last") or 0)
        old_generation = str(old.get("generation") or "")
        generation = _generation(container)
        fresh_report = (
            type(report_ts) is int and report_ts > 0
            and report_ts <= now + 30 and now - report_ts <= stale_seconds
        )
        identity_valid = bool(generation and fresh_report and config_matches)
        if identity_valid and generation == old_generation and report_ts <= old_last:
            previous_policy = old.get("policy") if isinstance(old.get("policy"), dict) else {}
            container["resource_overload_policy"] = {
                **previous_policy,
                "status": "out_of_order",
                "reason": "重复或乱序报告不计入连续资源占用时长",
            }
            continue
        values, value_reasons = _resource_values(container, now) if identity_valid else (
            {"cpu_percent": None, "memory_percent": None},
            {"cpu_percent": "Runman 身份、节点或报告时间未通过校验",
             "memory_percent": "Runman 身份、节点或报告时间未通过校验"},
        )
        policy = {
            "enabled": bool(enabled),
            "status": "monitoring" if identity_valid else "unverified",
            "reason": "连续资源占用尚未达到自动重启条件" if identity_valid else "节点绑定、Agent 版本、代次或报告证据未通过校验；仅采集",
            "required_duration_seconds": int(required_duration),
            "max_gap_seconds": int(max_gap),
            "cooldown_seconds": int(cooldown),
            "min_sample_count": int(min_samples),
            "metrics": {},
        }
        thresholds = {"cpu_percent": float(cpu_threshold), "memory_percent": float(memory_threshold)}
        for metric in METRIC_NAMES:
            threshold = thresholds[metric]
            value = values.get(metric)
            previous = old.get("metrics", {}).get(metric, {}) if isinstance(old.get("metrics"), dict) else {}
            previous = previous if isinstance(previous, dict) else {}
            continuous = (
                identity_valid and old_generation == generation
                and old.get("policy_key") == f"{cpu_threshold}:{memory_threshold}:{required_duration}:{max_gap}:{min_samples}"
                and report_ts > old_last and 0 < report_ts - old_last <= max_gap
            )
            above = value is not None and value >= threshold
            since = int(previous.get("since") or 0) if continuous and above else report_ts if above else 0
            samples = int(previous.get("samples") or 0) + 1 if continuous and above else 1 if above else 0
            duration = max(0, report_ts - since) if above else 0
            verified = bool(above and duration > 0 and samples >= min_samples)
            policy["metrics"][metric] = {
                "valid": value is not None,
                "value_percent": round(value, 3) if value is not None else None,
                "threshold_percent": threshold,
                "duration_seconds": duration,
                "sample_count": samples,
                "duration_verified": verified,
                "reason": value_reasons.get(metric, ""),
            }
        if any(
            item["valid"] and item["value_percent"] is not None
            and item["value_percent"] >= item["threshold_percent"]
            for item in policy["metrics"].values()
        ):
            policy.update(
                status="waiting_duration",
                reason=f"资源占用已达到门槛，等待连续有效采样满 {int(required_duration) // 60} 分钟",
            )

        if not identity_valid:
            state = {
                "last": max(old_last, report_ts), "generation": "", "metrics": {},
                "policy_key": "", "retries": 0,
                "last_restart_at": int(old.get("last_restart_at") or 0),
                "last_restart_generation": str(old.get("last_restart_generation") or ""),
                "last_restart_action_id": int(old.get("last_restart_action_id") or 0),
            }
        else:
            policy_key = f"{cpu_threshold}:{memory_threshold}:{required_duration}:{max_gap}:{min_samples}"
            same_window = old_generation == generation and old.get("policy_key") == policy_key
            state_metrics = {}
            for metric in METRIC_NAMES:
                observed = policy["metrics"][metric]
                state_metrics[metric] = {
                    "since": report_ts - observed["duration_seconds"] if observed["duration_seconds"] else 0,
                    "samples": observed["sample_count"],
                }
            state = {
                "last": report_ts, "generation": generation, "metrics": state_metrics,
                "policy_key": policy_key,
                "retries": int(old.get("retries") or 0) if same_window and any(
                    policy["metrics"][metric]["valid"]
                    and policy["metrics"][metric]["value_percent"] is not None
                    and policy["metrics"][metric]["value_percent"] >= thresholds[metric]
                    for metric in METRIC_NAMES
                ) else 0,
                "last_restart_at": int(old.get("last_restart_at") or 0),
                "last_restart_generation": str(old.get("last_restart_generation") or ""),
                "last_restart_action_id": int(old.get("last_restart_action_id") or 0),
            }

            latest_action = conn.execute(
                "SELECT id,status,updated_at,attempts,params_json FROM security_actions "
                "WHERE host_id=? AND runtime='runman' AND project='default' AND container_name=? "
                "AND action_type=? ORDER BY id DESC LIMIT 1", (key[0], key[3], ACTION_TYPE),
            ).fetchone()
            if latest_action:
                params = _load_payload((latest_action["params_json"],))
                if latest_action["status"] in ("queued", "dispatched", "running") and params.get("instance_id") != generation:
                    conn.execute(
                        "UPDATE security_actions SET status='failed',result_message=?,updated_at=? "
                        "WHERE id=? AND status IN ('queued','dispatched','running')",
                        ("Runman 实例代次已变化，旧资源重启动作已取消", now, latest_action["id"]),
                    )
                    latest_action = None

            candidates = [
                (metric, values[metric], thresholds[metric], policy["metrics"][metric])
                for metric in METRIC_NAMES
                if values[metric] is not None
                and policy["metrics"][metric]["duration_seconds"] >= required_duration
                and policy["metrics"][metric]["sample_count"] >= min_samples
            ]
            ready = bool(candidates)
            if latest_action and latest_action["status"] in ("queued", "dispatched", "running"):
                policy.update(status=latest_action["status"], action_id=latest_action["id"], reason="资源过载重启动作已下发，等待节点读回")
            elif state["last_restart_at"] and now - state["last_restart_at"] < cooldown:
                policy.update(status="cooldown", reason="最近一次重启仍在冷却期内，继续监测")
            elif latest_action and latest_action["status"] == "failed" and ready and (
                int(state["retries"] or 0) >= 3 or now - int(latest_action["updated_at"] or 0) < 900
            ):
                policy.update(status="failed", action_id=latest_action["id"], reason="资源过载重启失败；限制重试并保留现场")
            elif ready and int(state["retries"] or 0) >= 3:
                policy.update(status="failed", reason="本次连续过载窗口已达到 3 次自动重启上限；需人工排查")
            elif not enabled:
                policy.update(status="disabled", reason="自动资源重启已暂停；继续监测")
            elif not config_matches:
                policy.update(status="unverified", reason="节点代次未匹配；不下发重启")
            elif ready:
                metric, value, threshold, metric_policy = max(candidates, key=lambda item: item[3]["duration_seconds"])
                params = {
                    "reason": ACTION_REASON,
                    "metric_schema": 1,
                    "metric": metric,
                    "observed_percent": round(value, 3),
                    "threshold_percent": threshold,
                    "duration_seconds": metric_policy["duration_seconds"],
                    "required_duration_seconds": int(required_duration),
                    "sample_count": metric_policy["sample_count"],
                    "max_gap_seconds": int(max_gap),
                    "duration_verified": True,
                    "observed_at": report_ts,
                    "expires_at": now + int(max_gap),
                    "instance_id": generation,
                    "expected_node_id": str(node_id),
                    "notice_best_effort": True,
                }
                action_id = conn.execute(
                    "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
                    "VALUES(0,?,'runman','default',?,? ,?,'queued','system:resource-guard',?,?)",
                    (key[0], key[3], ACTION_TYPE, json.dumps(params, ensure_ascii=False), now, now),
                ).lastrowid
                state["retries"] = int(state.get("retries") or 0) + 1
                state["last_restart_action_id"] = action_id
                policy.update(status="queued", action_id=action_id, reason="资源占用达到持续阈值；已下发精确实例重启并等待回执")
                queued += 1

        container["resource_overload_policy"] = policy
        state["policy"] = policy
        conn.execute(
            "INSERT INTO resource_overload_windows(host_id,runtime,project,container_name,payload,last_seen) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(host_id,runtime,project,container_name) "
            "DO UPDATE SET payload=excluded.payload,last_seen=excluded.last_seen",
            (*key, json.dumps(state, ensure_ascii=False), now),
        )

    # Retain enough history for a cooldown, but bound state for deleted guests.
    conn.execute("DELETE FROM resource_overload_windows WHERE last_seen<?", (now - 90 * 86400,))
    return queued


def record_action(conn, action_id, ts):
    """Persist the exact restart receipt and classify it as a non-abuse signal."""
    row = conn.execute("SELECT * FROM security_actions WHERE id=?", (action_id,)).fetchone()
    if not row or row["action_type"] != ACTION_TYPE or row["status"] not in {"succeeded", "failed"}:
        return
    params = _load_payload((row["params_json"],))
    if params.get("reason") != ACTION_REASON:
        return
    key = (row["host_id"], row["runtime"], row["project"], row["container_name"])
    state_row = conn.execute(
        "SELECT payload FROM resource_overload_windows WHERE host_id=? AND runtime=? AND project=? AND container_name=?", key,
    ).fetchone()
    state = _load_payload(state_row)
    if row["status"] == "succeeded":
        state["last_restart_at"] = int(ts)
        state["last_restart_generation"] = str(params.get("instance_id") or "")
        state["last_restart_action_id"] = int(action_id)
    conn.execute(
        "INSERT INTO resource_overload_windows(host_id,runtime,project,container_name,payload,last_seen) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(host_id,runtime,project,container_name) "
        "DO UPDATE SET payload=excluded.payload,last_seen=MAX(resource_overload_windows.last_seen,excluded.last_seen)",
        (*key, json.dumps(state, ensure_ascii=False), int(ts)),
    )
    fingerprint = "resource-overload-action-" + str(action_id)
    details = {
        "observation": params,
        "automatic_remediation": {
            "attempted": True,
            "succeeded": row["status"] == "succeeded",
            "action_type": ACTION_TYPE,
            "message": str(row["result_message"] or "")[:1000],
        },
    }
    conn.execute(
        "INSERT OR IGNORE INTO security_alerts(fingerprint,host_id,runtime,project,container_name,alert_type,severity,title,message,value,threshold,first_seen,last_seen,status,details_json) "
        "VALUES(?,?,?,?,?,'ops_resource_guard','critical','持续资源占用自动重启回执',?,?,?,?,?,?,?)",
        (
            fingerprint, row["host_id"], row["runtime"], row["project"], row["container_name"],
            str(row["result_message"] or "")[:2000],
            _number(params.get("observed_percent")) or 0,
            _number(params.get("threshold_percent")) or 0,
            int(row["created_at"]), int(ts),
            "remediated" if row["status"] == "succeeded" else "active",
            json.dumps(details, ensure_ascii=False),
        ),
    )
    alert = conn.execute("SELECT id FROM security_alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
    if alert:
        conn.execute("UPDATE security_actions SET alert_id=? WHERE id=?", (alert[0], action_id))
