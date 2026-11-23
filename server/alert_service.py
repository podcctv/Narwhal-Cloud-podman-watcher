"""Security alert lifecycle, evidence extraction, disposition, action queuing, and history service."""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

try:
    from server import buyer_notifications, connection_policy, investigation
except ImportError:
    import buyer_notifications  # type: ignore[no-redef]
    import connection_policy  # type: ignore[no-redef]
    import investigation  # type: ignore[no-redef]

_app: Any = None
_service: "AlertService | None" = None


class AlertService:
    """Alert ingestion, evidence inspection, disposition, and history bound to an app module."""

    def __init__(self, app_mod: Any) -> None:
        self._app = app_mod

    def _alert_fingerprint(self, host_id: str, alert: Dict[str, Any]) -> str:
        parts = [
            host_id,
            str(alert.get("runtime") or ""),
            str(alert.get("project") or ""),
            str(alert.get("container_name") or ""),
            str(alert.get("type") or "unknown"),
        ]
        alert_key = str(alert.get("alert_key") or "").strip()
        if alert_key:
            parts.append(alert_key[:240])
        if alert.get("type") == "prohibited_activity":
            parts.append(str(alert.get("instance_id") or ""))
        if str(alert.get("type") or "") == "unauthorized_panel_pairing":
            domains = alert.get("unapproved_domains")
            domain_values = (
                [str(item).strip().lower().rstrip(".") for item in domains if isinstance(item, str) and item.strip()]
                if isinstance(domains, list)
                else []
            )
            if not domain_values:
                match = re.search(r"未授权面板域名\s*([^；;]+)", str(alert.get("message") or ""))
                domain_values = [
                    item.strip().lower().rstrip(".")
                    for item in (match.group(1).split(",") if match else [])
                    if item.strip()
                ]
            parts.append(",".join(sorted(set(domain_values))))
        identity = "|".join(parts)
        return hashlib.sha256(identity.encode()).hexdigest()

    def process_security_alerts(
        self,
        conn: sqlite3.Connection,
        host_id: str,
        ts: int,
        alerts: List[Dict[str, Any]],
        partial: bool = False,
        preserve_active_types: Optional[List[str]] = None,
        resolve_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        severity_rank = self._app._SEVERITY_RANK
        active_fingerprints: List[str] = []
        notifications: List[Dict[str, Any]] = []
        for raw_alert in alerts:
            if not isinstance(raw_alert, dict):
                continue
            alert_type = str(raw_alert.get("type") or "unknown")[:80]
            if alert_type == "ops_traffic_quota":
                continue
            if alert_type == "admission_unverified":
                continue
            severity = str(raw_alert.get("severity") or "warning").lower()
            if severity not in severity_rank:
                severity = "warning"
            normalized = {
                "host_id": host_id,
                "runtime": str(raw_alert.get("runtime") or "")[:40],
                "project": str(raw_alert.get("project") or "")[:100],
                "container_name": str(raw_alert.get("container_name") or "")[:200],
                "type": alert_type,
                "severity": severity,
                "title": str(raw_alert.get("title") or alert_type)[:200],
                "message": str(raw_alert.get("message") or "")[:2000],
                "value": float(raw_alert.get("value") or 0),
                "threshold": float(raw_alert.get("threshold") or 0),
            }
            fingerprint_source = dict(normalized)
            fingerprint_source["unapproved_domains"] = raw_alert.get("unapproved_domains")
            fingerprint_source["instance_id"] = raw_alert.get("instance_id")
            fingerprint_source["alert_key"] = raw_alert.get("alert_key")
            fingerprint = self._app._alert_fingerprint(host_id, fingerprint_source)
            active_fingerprints.append(fingerprint)
            existing = conn.execute(
                "SELECT id, status, severity, occurrence_count,details_json FROM security_alerts WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
            allow_policy = (
                conn.execute(
                    "SELECT 1 FROM security_alert_policies WHERE fingerprint=? AND mode='allow_silent'",
                    (fingerprint,),
                ).fetchone()
                is not None
            )
            automatic_remediation = raw_alert.get("automatic_remediation")
            ongoing_protection = raw_alert.get("ongoing_protection") is True
            automatically_remediated = (
                isinstance(automatic_remediation, dict)
                and automatic_remediation.get("attempted") is True
                and automatic_remediation.get("succeeded") is True
                and not ongoing_protection
            )
            next_status = (
                "suppressed"
                if allow_policy
                else "remediated" if automatically_remediated else "active"
            )
            should_notify = existing is None and not allow_policy and not automatically_remediated
            if existing is not None:
                previous_status = str(existing["status"])
                verification = conn.execute("SELECT state FROM buyer_checks WHERE alert_id=?", (existing["id"],)).fetchone()
                restart_episode = previous_status == "resolved" or (
                    previous_status == "remediated"
                    and (next_status == "active" or (verification and verification[0] == "verified"))
                )
                if allow_policy:
                    should_notify = False
                elif automatically_remediated:
                    should_notify = False
                elif previous_status == "remediated" and alert_type == "socket_abuse_suspected":
                    recent_freeze = conn.execute(
                        "SELECT status, updated_at FROM security_actions WHERE alert_id=? AND action_type='freeze_container' ORDER BY id DESC LIMIT 1",
                        (existing["id"],),
                    ).fetchone()
                    if (
                        recent_freeze
                        and str(recent_freeze["status"]) in ("queued", "dispatched", "running", "succeeded")
                        and (ts - int(recent_freeze["updated_at"] or 0)) <= 86400
                    ):
                        next_status = "remediated"
                        restart_episode = False
                        should_notify = False
                elif previous_status == "dismissed":
                    dismiss_decision = conn.execute(
                        "SELECT created_at FROM security_alert_decisions WHERE alert_id=? AND decision='dismiss_once' ORDER BY id DESC LIMIT 1",
                        (existing["id"],),
                    ).fetchone()
                    dismiss_ts = int(dismiss_decision["created_at"]) if dismiss_decision else 0
                    if dismiss_ts > 0 and (ts - dismiss_ts) > 3600:
                        next_status = "active"
                        should_notify = True
                    else:
                        next_status = "dismissed"
                        should_notify = False
                else:
                    should_notify = previous_status == "resolved" or severity_rank[severity] > severity_rank.get(
                        str(existing["severity"]), 0
                    )
                    previous_details = self._app._alert_details(existing["details_json"])
                    previous_remediation = previous_details.get("automatic_remediation")
                    if (
                        ongoing_protection
                        and isinstance(previous_remediation, dict)
                        and previous_remediation.get("attempted") is True
                        and previous_remediation.get("succeeded") is not True
                        and isinstance(automatic_remediation, dict)
                        and automatic_remediation.get("attempted") is True
                        and automatic_remediation.get("succeeded") is True
                    ):
                        should_notify = True
                    if alert_type == "container_connection_count":
                        was_escalated = (
                            self._app._alert_details(existing["details_json"]).get("connection_policy", {}).get("escalated")
                        )
                        should_notify = should_notify or bool(
                            raw_alert.get("connection_policy", {}).get("escalated") and not was_escalated
                        )
                    if alert_type in {"cpu_pressure_protection", "io_pressure_protection", "memory_pressure_protection"}:
                        previous_details = self._app._alert_details(existing["details_json"])
                        guard_key = {
                            "cpu_pressure_protection": "cpu_guard",
                            "io_pressure_protection": "io_guard",
                            "memory_pressure_protection": "memory_guard",
                        }[alert_type]
                        try:
                            previous_tier = int((previous_details.get(guard_key) or {}).get("tier") or 0)
                            current_tier = int((raw_alert.get(guard_key) or {}).get("tier") or 0)
                        except (TypeError, ValueError, OverflowError):
                            previous_tier = current_tier = 0
                        if current_tier > previous_tier and current_tier > 1:
                            should_notify = True
                    if alert_type in {"host_vulnerability", "host_security_finding"}:
                        previous_details = self._app._alert_details(existing["details_json"])
                        previous_ids = previous_details.get("finding_keys") or previous_details.get("finding_ids")
                        current_ids = raw_alert.get("finding_keys") or raw_alert.get("finding_ids")
                        if isinstance(previous_ids, list) and isinstance(current_ids, list):
                            should_notify = should_notify or bool(set(map(str, current_ids)) - set(map(str, previous_ids)))
                conn.execute(
                    """
                    UPDATE security_alerts
                    SET severity=?, title=?, message=?, value=?, threshold=?, last_seen=?,
                        first_seen=CASE WHEN ? THEN ? ELSE first_seen END,
                        occurrence_count=CASE WHEN ? THEN 1 ELSE occurrence_count+1 END,
                        status=?, details_json=?
                    WHERE fingerprint=?
                    """,
                    (
                        severity,
                        normalized["title"],
                        normalized["message"],
                        normalized["value"],
                        normalized["threshold"],
                        ts,
                        bool(restart_episode),
                        ts,
                        bool(restart_episode),
                        next_status,
                        json.dumps(raw_alert, ensure_ascii=False),
                        fingerprint,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO security_alerts(
                        fingerprint, host_id, runtime, project, container_name, alert_type,
                        severity, title, message, value, threshold, first_seen, last_seen,
                        occurrence_count, status, details_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)
                    """,
                    (
                        fingerprint,
                        host_id,
                        normalized["runtime"],
                        normalized["project"],
                        normalized["container_name"],
                        alert_type,
                        severity,
                        normalized["title"],
                        normalized["message"],
                        normalized["value"],
                        normalized["threshold"],
                        ts,
                        ts,
                        next_status,
                        json.dumps(raw_alert, ensure_ascii=False),
                    ),
                )
            if should_notify:
                notification = dict(normalized)
                row = conn.execute("SELECT id,first_seen FROM security_alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                notification["id"] = int(row["id"]) if row is not None else 0
                notification["event_id"] = f"NW-{row['id']}-{row['first_seen']}" if row is not None else ""
                notifications.append(notification)

        if partial:
            return notifications
        preserve_types = sorted({str(item).strip()[:80] for item in (preserve_active_types or []) if str(item).strip()})
        if preserve_types:
            placeholders = ",".join("?" for _ in preserve_types)
            preserved = conn.execute(
                f"SELECT fingerprint FROM security_alerts WHERE host_id=? AND alert_type IN ({placeholders}) AND status IN ('active','dismissed')",
                (host_id, *preserve_types),
            ).fetchall()
            active_fingerprints.extend(str(row["fingerprint"]) for row in preserved)
        pending_network_review = (
            "NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.alert_id=security_alerts.id AND q.status NOT IN ('released','replaced'))"
        )
        resolve_type_values = sorted({str(item).strip()[:80] for item in (resolve_types or []) if str(item).strip()})
        if resolve_type_values:
            type_placeholders = ",".join("?" for _ in resolve_type_values)
            type_filter = f" AND alert_type IN ({type_placeholders})"
            if active_fingerprints:
                fingerprint_placeholders = ",".join("?" for _ in active_fingerprints)
                conn.execute(
                    f"UPDATE security_alerts SET status='resolved', last_seen=? "
                    f"WHERE host_id=? AND status IN ('active','dismissed'){type_filter} "
                    f"AND fingerprint NOT IN ({fingerprint_placeholders}) AND {pending_network_review}",
                    (ts, host_id, *resolve_type_values, *active_fingerprints),
                )
            else:
                conn.execute(
                    f"UPDATE security_alerts SET status='resolved', last_seen=? "
                    f"WHERE host_id=? AND status IN ('active','dismissed'){type_filter} AND {pending_network_review}",
                    (ts, host_id, *resolve_type_values),
                )
        elif active_fingerprints:
            placeholders = ",".join("?" for _ in active_fingerprints)
            conn.execute(
                f"UPDATE security_alerts SET status='resolved', last_seen=? "
                f"WHERE host_id=? AND status IN ('active','dismissed') AND fingerprint NOT IN ({placeholders}) AND {pending_network_review}",
                (ts, host_id, *active_fingerprints),
            )
        else:
            conn.execute(
                f"UPDATE security_alerts SET status='resolved', last_seen=? WHERE host_id=? AND status IN ('active','dismissed') AND {pending_network_review}",
                (ts, host_id),
            )
        return notifications

    def queue_connection_alert_deep_samples(self, conn: sqlite3.Connection, host_id: str, now: int) -> int:
        """Refresh bounded connection evidence for connection and inbound-fanout alerts."""
        stale_seconds = self._app.STALE_SECONDS
        queued = 0
        alerts = conn.execute(
            """
            SELECT * FROM security_alerts
            WHERE host_id=? AND alert_type IN (
                  'container_connection_count','inbound_ip_fanout','socks_inbound_fanout','socket_abuse_suspected'
              )
              AND status='active' AND last_seen=?
            """,
            (host_id, now),
        ).fetchall()
        for alert in alerts:
            if queued >= 10:
                break
            runtime = str(alert["runtime"] or "")
            if runtime not in ("incus", "podman", "runman"):
                continue
            alert_id = int(alert["id"])
            existing = conn.execute(
                """
                SELECT id,status,created_at,params_json FROM security_actions
                WHERE alert_id=? AND action_type='request_deep_sample' AND created_at>=?
                ORDER BY id DESC LIMIT 1
                """,
                (alert_id, int(alert["first_seen"])),
            ).fetchone()
            stage = (
                str(alert["alert_type"])
                + ":"
                + str(alert["severity"])
                + (
                    ":escalated"
                    if self._app._alert_details(alert["details_json"]).get("connection_policy", {}).get("escalated")
                    else ""
                )
            )
            params: Dict[str, Any] = {
                "sample_seconds": 1.0,
                "process_limit": 100,
                "socket_limit": 250,
                "evidence_schema": 5,
                "stage": stage,
            }
            if runtime == "runman":
                latest = conn.execute(
                    "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime='runman' AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
                    (host_id, str(alert["project"] or ""), str(alert["container_name"] or "")),
                ).fetchone()
                try:
                    latest_payload = json.loads(latest["payload_json"] or "{}") if latest is not None else {}
                except (TypeError, ValueError):
                    latest_payload = {}
                stable_id = (
                    str(latest_payload.get("stable_id") or latest_payload.get("id") or "").lower()
                    if isinstance(latest_payload, dict)
                    else ""
                )
                generation = str(latest_payload.get("instance_id") or "").lower() if isinstance(latest_payload, dict) else ""
                if (
                    str(alert["project"] or "") != "default"
                    or stable_id != str(alert["container_name"] or "").lower()
                    or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stable_id)
                    or not re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", generation
                    )
                    or latest is None
                    or int(latest["ts"] or 0) > now + 30
                    or now - int(latest["ts"] or 0) > stale_seconds
                ):
                    continue
                params["instance_id"] = generation
            if existing is not None:
                previous_params = self._app._alert_details(existing["params_json"])
                if runtime == "runman" and previous_params.get("instance_id") != params.get("instance_id"):
                    if existing["status"] in ("queued", "dispatched", "running"):
                        conn.execute(
                            "UPDATE security_actions SET status='failed',result_message='Runman 实例代次已变化，旧深度采样已取消',updated_at=? WHERE id=?",
                            (now, existing["id"]),
                        )
                    existing = None
                if existing is not None and existing["status"] in ("queued", "dispatched", "running"):
                    if now - int(existing["created_at"]) > 900:
                        conn.execute(
                            "UPDATE security_actions SET status='failed',result_message='深度取证等待超过15分钟，需要重新采样',updated_at=? WHERE id=?",
                            (now, existing["id"]),
                        )
                    continue
                if (
                    existing is not None
                    and now - int(existing["created_at"]) < 900
                    and (previous_params.get("stage") == stage or existing["status"] == "failed")
                ):
                    continue
            conn.execute(
                """
                INSERT INTO security_actions(
                    alert_id,host_id,runtime,project,container_name,action_type,params_json,
                    status,requested_by,created_at,updated_at
                ) VALUES(?,?,?,?,?,? ,?,'queued','automatic:connection-alert',?,?)
                """,
                (
                    alert_id,
                    str(alert["host_id"]),
                    str(alert["runtime"]),
                    str(alert["project"]),
                    str(alert["container_name"]),
                    "request_deep_sample",
                    json.dumps(params),
                    now,
                    now,
                ),
            )
            queued += 1
        return queued

    def _action_item(self, row: sqlite3.Row) -> Dict[str, Any]:
        try:
            params = json.loads(row["params_json"] or "{}")
        except (TypeError, ValueError):
            params = {}
        if row["action_type"] in {"apply_container_connlimit", "release_container_connlimit"}:
            params = {key: params[key] for key in ("max_connections", "lease_expires_at") if key in params}
        elif row["action_type"] == "delete_host_firewall_rule":
            rule = params.get("rule") if isinstance(params, dict) else None
            rule_id = rule.get("id") if isinstance(rule, dict) else None
            params = {"rule_id": rule_id if type(rule_id) is int and rule_id > 0 else 0}
        elif row["action_type"] == "apply_host_firewall_policy":
            policy = params.get("policy") if isinstance(params.get("policy"), dict) else {}
            fleet_revision = params.get("fleet_revision")
            params = {
                "revision": int(policy.get("revision") or 0),
                "rule_count": len(policy.get("rules") or []) if isinstance(policy.get("rules"), list) else 0,
            }
            if type(fleet_revision) is int:
                params["fleet_revision"] = fleet_revision
        return {
            "id": int(row["id"]),
            "alert_id": int(row["alert_id"]),
            "host_id": row["host_id"],
            "runtime": row["runtime"],
            "project": row["project"],
            "container_name": row["container_name"],
            "action_type": row["action_type"],
            "params": params,
            "status": row["status"],
            "requested_by": row["requested_by"],
            "result_message": row["result_message"],
            "attempts": int(row["attempts"]),
            "created_at": int(row["created_at"]),
            "created_at_utc8": self._app.format_utc8(int(row["created_at"])),
            "updated_at": int(row["updated_at"]),
            "updated_at_utc8": self._app.format_utc8(int(row["updated_at"])),
        }

    def _decision_item(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": int(row["id"]),
            "alert_id": int(row["alert_id"]),
            "decision": row["decision"],
            "requested_by": row["requested_by"],
            "created_at": int(row["created_at"]),
            "created_at_utc8": self._app.format_utc8(int(row["created_at"])),
        }

    def _security_alert_item(self, conn: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
        buyer_mod = getattr(self._app, "buyer_notifications", buyer_notifications)
        recovery = buyer_mod.recovery(conn, row)
        for field in ("recovered_at", "closed_at"):
            recovery[field + "_utc8"] = self._app.format_utc8(recovery[field]) if recovery[field] else None
        latest_action = self._app._latest_action_for_alert(conn, row)
        latest_decision = conn.execute(
            "SELECT * FROM security_alert_decisions WHERE alert_id=? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        evidence_row = conn.execute(
            "SELECT captured_at,evidence_json FROM security_alert_evidence WHERE alert_id=? ORDER BY captured_at DESC,id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        deep_evidence = None
        if evidence_row is not None:
            deep_evidence = self._app._alert_details(evidence_row["evidence_json"])
            deep_evidence["captured_at"] = int(evidence_row["captured_at"])
            deep_evidence["captured_at_utc8"] = self._app.format_utc8(int(evidence_row["captured_at"]))
        return {
            "id": int(row["id"]),
            "host_id": row["host_id"],
            "runtime": row["runtime"],
            "project": row["project"],
            "container_name": row["container_name"],
            "type": row["alert_type"],
            "protection_only": buyer_mod.is_protection_only_alert(row),
            "severity": row["severity"],
            "title": row["title"],
            "message": row["message"],
            "value": float(row["value"] or 0),
            "threshold": float(row["threshold"] or 0),
            "first_seen": int(row["first_seen"]),
            "first_seen_utc8": self._app.format_utc8(int(row["first_seen"])),
            "last_seen": int(row["last_seen"]),
            "last_seen_utc8": self._app.format_utc8(int(row["last_seen"])),
            "occurrence_count": int(row["occurrence_count"]),
            "status": row["status"],
            "recovery": recovery,
            "details": self._app._alert_action_evidence(row),
            "deep_evidence": deep_evidence,
            "latest_action": self._app._action_item(latest_action) if latest_action is not None else None,
            "latest_decision": self._app._decision_item(latest_decision) if latest_decision is not None else None,
        }

    def _remediation_changed(self, message: str) -> bool:
        counts = {
            key: int(value)
            for key, value in re.findall(
                r"\b(killed_processes|removed_services|removed_configs|removed_binaries|cleanup_errors|matched_processes|signal_errors|host_matched_processes|host_killed_processes|host_kill_errors|checked_configs)=(\d+)\b",
                message,
            )
        }
        no_process_targets = re.search(r"\bno_process_targets=1\b", message) is not None
        process_scan = (
            ("matched_processes" in counts or "host_matched_processes" in counts) and not no_process_targets
        ) or (no_process_targets and counts.get("checked_configs", 0) > 0)
        remaining_zero = re.search(r"\bremaining_processes=0\b", message) is not None
        if (
            "cleanup_errors" not in counts
            or "signal_errors" not in counts
            or not process_scan
            or not remaining_zero
        ):
            return False
        cleanup_errors = counts.get("cleanup_errors", 0)
        signal_errors = counts.get("signal_errors", 0)
        host_killed = counts.get("host_killed_processes", 0)
        host_matched = counts.get("host_matched_processes", 0)
        host_errors = counts.get("host_kill_errors", 0)
        signal_recovered = signal_errors == 0 or (
            "host_matched_processes" in counts
            and "host_killed_processes" in counts
            and "host_kill_errors" in counts
            and host_matched >= signal_errors
            and host_killed >= signal_errors
            and host_errors == 0
            and remaining_zero
        )
        errors = cleanup_errors + host_errors + (0 if signal_recovered else signal_errors)
        changed = (
            sum(
                counts.get(key, 0)
                for key in ("killed_processes", "removed_services", "removed_configs", "removed_binaries")
            )
            > 0
        )
        if errors > 0:
            return False
        if changed:
            return True
        return (
            process_scan
            and "cleanup_errors" in counts
            and counts["cleanup_errors"] == 0
            and "signal_errors" in counts
            and counts["signal_errors"] == 0
            and remaining_zero
        )

    def _alert_details(self, raw: str) -> Dict[str, Any]:
        try:
            value = json.loads(raw or "{}")
            return value if isinstance(value, dict) else {}
        except (TypeError, ValueError):
            return {}

    def _alert_action_evidence(self, alert: sqlite3.Row) -> Dict[str, Any]:
        """Return structured evidence, including alerts reported by older agents."""
        details = self._app._alert_details(alert["details_json"])
        message = str(alert["message"] or "")

        def clean(items: Any, *, domains: bool = False) -> List[str]:
            if not isinstance(items, list):
                return []
            values = []
            for item in items:
                if not isinstance(item, str) or not item.strip():
                    continue
                value = item.strip()
                if domains:
                    value = value.lower().rstrip(".")
                values.append(value)
            return sorted(set(values))

        domains = clean(details.get("unapproved_domains"), domains=True)
        process_patterns = clean(details.get("process_patterns"))
        config_files = clean(details.get("config_files"))
        process_pids = (
            sorted(
                {
                    int(item)
                    for item in details.get("process_pids", [])
                    if isinstance(item, int) and 1 < item <= 4194304
                }
            )
            if isinstance(details.get("process_pids"), list)
            else []
        )
        if not domains:
            match = re.search(r"未授权面板域名\s*([^；;]+)", message)
            domains = clean(match.group(1).split(",") if match else [], domains=True)
        if not process_patterns:
            match = re.search(r"节点程序特征\s*([^；;]+)", message)
            process_patterns = clean(match.group(1).split(",") if match else [])
        if not config_files:
            match = re.search(r"配置文件\s*([^；;]+)", message)
            config_files = clean(match.group(1).split(",") if match else [])
        details["unapproved_domains"] = domains
        details["process_patterns"] = process_patterns
        details["process_pids"] = process_pids
        details["config_files"] = config_files
        raw_auth_mode = (
            str(details.get("socks_auth_mode") or details.get("socks_auth_state") or "unknown")
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )
        auth_mode_aliases = {
            "weak": "weak_password",
            "weak_auth": "weak_password",
            "weak_password": "weak_password",
            "noauth": "no_auth",
            "no_auth": "no_auth",
            "none": "no_auth",
            "configured": "configured",
            "unknown": "unknown",
        }
        details["socks_auth_mode"] = auth_mode_aliases.get(raw_auth_mode, "unknown")
        allowed_socks_processes = {
            "microsocks", "sockd", "danted", "srelay", "hev-socks5-server",
            "3proxy", "gost", "xray", "v2ray", "sing-box",
        }
        socks_config_files = clean(details.get("socks_config_files"))
        socks_processes = [
            item.lower() for item in clean(details.get("socks_processes")) if item.lower() in allowed_socks_processes
        ]
        legacy_matches = details.get("socks_process_matches")
        if isinstance(legacy_matches, list) and not details.get("socks_action_scope_verified"):
            for item in legacy_matches:
                if not isinstance(item, dict):
                    continue
                process = str(item.get("process") or "").strip().lower()
                state = str(item.get("auth_state") or item.get("auth_mode") or details["socks_auth_mode"])
                state = auth_mode_aliases.get(state.strip().lower().replace("-", "_").replace(" ", "_"), "unknown")
                if process in allowed_socks_processes and state in ("no_auth", "weak_password"):
                    socks_processes.append(process)
        socks_processes = sorted(set(socks_processes))
        if (
            not socks_processes
            and details["socks_auth_mode"] in ("no_auth", "weak_password")
            and not details.get("socks_action_scope_verified")
        ):
            process_match = re.search(
                r"(?:^|[；;，,\n])\s*(?:进程|process)\s*(?:[:=：])?\s*([^；;，,\n]+)",
                message,
                flags=re.IGNORECASE,
            )
            message_processes = re.split(r"[,，\s]+", process_match.group(1).strip()) if process_match else []
            socks_processes = sorted({item.lower() for item in message_processes if item.lower() in allowed_socks_processes})
        details["socks_processes"] = socks_processes
        details["socks_process_pids"] = (
            sorted(
                {
                    int(item)
                    for item in details.get("socks_process_pids", [])
                    if isinstance(item, int) and 1 < item <= 4194304
                }
            )
            if isinstance(details.get("socks_process_pids"), list)
            else []
        )
        details["socks_config_files"] = socks_config_files
        malicious_processes = []
        raw_malicious_processes = details.get("malicious_processes")
        if isinstance(raw_malicious_processes, list):
            for item in raw_malicious_processes:
                if not isinstance(item, dict):
                    continue
                process = str(item.get("process") or "").strip().lower()
                try:
                    pid = int(item.get("pid") or 0)
                except (TypeError, ValueError):
                    pid = 0
                if process == "xmrig":
                    start_ticks = str(item.get("start_ticks") or "").strip()
                    malicious_processes.append(
                        {
                            "process": process,
                            "pid": pid if 1 < pid <= 4194304 else 0,
                            "start_ticks": start_ticks if re.fullmatch(r"[0-9]{1,24}", start_ticks) else "",
                            "pattern": str(item.get("pattern") or "")[:120],
                        }
                    )
        if not malicious_processes and alert["alert_type"] == "malicious_process":
            legacy_match = re.search(
                r"首个特征\s*(xmrig)\s*[，,]\s*PID\s*(\d+)",
                message,
                flags=re.IGNORECASE,
            )
            if legacy_match:
                legacy_pid = int(legacy_match.group(2))
                malicious_processes.append(
                    {
                        "process": legacy_match.group(1).lower(),
                        "pid": legacy_pid if 1 < legacy_pid <= 4194304 else 0,
                    }
                )
        details["malicious_processes"] = malicious_processes[:20]

        process_targets = []
        raw_process_targets = details.get("process_targets")
        if isinstance(raw_process_targets, list):
            for item in raw_process_targets[:64]:
                if not isinstance(item, dict):
                    continue
                pid = item.get("pid")
                process = str(item.get("process") or "").strip().lower()
                pattern = str(item.get("pattern") or "").strip().lower()
                start_ticks = str(item.get("start_ticks") or "").strip()
                if (
                    type(pid) is int
                    and 1 < pid <= 4194304
                    and re.fullmatch(r"[a-zA-Z0-9_.@+-]{1,80}", process)
                    and re.fullmatch(r"[a-zA-Z0-9_.@-]{2,80}", pattern)
                    and re.fullmatch(r"[0-9]{1,24}", start_ticks)
                    and int(start_ticks) > 0
                ):
                    process_targets.append(
                        {"pid": pid, "process": process, "pattern": pattern, "start_ticks": start_ticks}
                    )
        details["process_targets"] = process_targets

        file_targets = []
        raw_file_targets = details.get("file_targets")
        if isinstance(raw_file_targets, list):
            for item in raw_file_targets[:128]:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                generation = item.get("generation")
                kind = item.get("kind")
                if (
                    isinstance(path, str)
                    and len(path) <= 256
                    and re.fullmatch(r"/[A-Za-z0-9_./@:+-]{1,255}", path)
                    and posixpath.normpath(path) == path
                    and isinstance(generation, str)
                    and re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}", generation)
                    and isinstance(kind, str)
                    and kind in {"config", "service", "binary"}
                ):
                    file_targets.append({"path": path, "generation": generation, "kind": kind})
        details["file_targets"] = file_targets
        details["instance_id"] = str(details.get("instance_id") or "").strip().lower()[:36]
        return details

    def _runman_alert_generation_current(
        self,
        conn: sqlite3.Connection,
        alert: sqlite3.Row,
        details: Dict[str, Any],
        now: int | None = None,
    ) -> tuple[bool, str]:
        """Require a fresh latest report with the alert's exact Runman identity."""
        stale_seconds = self._app.STALE_SECONDS
        now = int(time.time()) if now is None else int(now)
        vm_uuid = str(alert["container_name"] or "").lower()
        instance_id = str(details.get("instance_id") or "").lower()
        if (
            alert["runtime"] != "runman"
            or alert["project"] != "default"
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", vm_uuid)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", instance_id)
        ):
            return False, "Runman alert target identity is invalid"
        latest = conn.execute(
            "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime='runman' AND project='default' AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
            (alert["host_id"], alert["container_name"]),
        ).fetchone()
        try:
            payload = json.loads(latest["payload_json"] or "{}") if latest is not None else {}
        except (TypeError, ValueError):
            payload = {}
        stable_id = str(payload.get("stable_id") or payload.get("id") or "").lower() if isinstance(payload, dict) else ""
        current_id = str(payload.get("instance_id") or "").lower() if isinstance(payload, dict) else ""
        report_at = int(latest["ts"] or 0) if latest is not None else 0
        if (
            stable_id != vm_uuid
            or current_id != instance_id
            or report_at <= 0
            or report_at > now + 30
            or now - report_at > stale_seconds
        ):
            return False, "Runman instance generation is stale or has changed"
        return True, instance_id

    def _queue_security_action_row(
        self,
        conn: sqlite3.Connection,
        alert: sqlite3.Row,
        action_type: str,
        params: Dict[str, Any],
        requested_by: str,
    ) -> tuple[sqlite3.Row, bool]:
        existing = conn.execute(
            """
            SELECT * FROM security_actions
            WHERE alert_id=? AND action_type=? AND status IN ('queued','dispatched','running')
            ORDER BY id DESC LIMIT 1
            """,
            (alert["id"], action_type),
        ).fetchone()
        if existing is not None:
            return existing, False
        now = int(time.time())
        cur = conn.execute(
            """
            INSERT INTO security_actions(
                alert_id, host_id, runtime, project, container_name, action_type, params_json,
                status, requested_by, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,'queued',?,?,?)
            """,
            (
                alert["id"],
                alert["host_id"],
                alert["runtime"],
                alert["project"],
                alert["container_name"],
                action_type,
                json.dumps(params, ensure_ascii=False),
                requested_by[:100],
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
        return row, True

    def _fresh_connlimit_identity(
        self, conn: sqlite3.Connection, alert: sqlite3.Row, now: int, max_connections: int
    ) -> tuple[str, str, Dict[str, Any]]:
        stale_seconds = self._app.STALE_SECONDS
        conn_policy = getattr(self._app, "connection_policy", connection_policy)
        runtime = str(alert["runtime"] or "").lower()
        if runtime not in {"incus", "runman"}:
            raise HTTPException(status_code=409, detail="该运行时没有已核验的 TCP 限额适配器；未下发")
        host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (alert["host_id"],)).fetchone()
        if host is None or not str(host["node_id"] or "") or now - int(host["last_seen"] or 0) > stale_seconds:
            raise HTTPException(status_code=409, detail="该节点尚未注册可校验的 Client 身份")
        latest = conn.execute(
            "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
            (alert["host_id"], runtime, alert["project"], alert["container_name"]),
        ).fetchone()
        if latest is None or now - int(latest["ts"] or 0) > stale_seconds:
            raise HTTPException(status_code=409, detail="节点或容器采样已过期；为避免对错误实例执行防火墙操作，未下发")
        try:
            payload = json.loads(latest["payload_json"] or "{}")
        except (TypeError, ValueError):
            payload = {}
        stable_id = str(payload.get("stable_id") or "") if isinstance(payload, dict) else ""
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", stable_id):
            raise HTTPException(status_code=409, detail="最新采样没有有效的 Incus 实例 UUID；未下发")
        instance_generation = str(payload.get("instance_id") or "") if isinstance(payload, dict) else ""
        if runtime == "runman" and not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", instance_generation
        ):
            raise HTTPException(status_code=409, detail="最新 Runman 采样没有有效实例代次；未下发")
        metrics = conn_policy.metrics(payload, now) if isinstance(payload, dict) else None
        if not isinstance(metrics, dict):
            raise HTTPException(status_code=409, detail="最新连接证据未通过完整性校验；未下发")
        sampled_at = metrics.get("sampled_at")
        epoch = metrics.get("epoch")
        tcp_established = metrics.get("tcp_established")
        tcp_pending = metrics.get("tcp_pending")
        if (
            type(sampled_at) is not int
            or sampled_at > now + 30
            or now - sampled_at > stale_seconds
            or not isinstance(epoch, str)
            or not epoch
            or len(epoch) > 200
            or type(tcp_established) is not int
            or type(tcp_pending) is not int
            or tcp_established < 0
            or tcp_pending < 0
        ):
            raise HTTPException(status_code=409, detail="TCP 连接证据缺失或过期；未下发")
        observed_tcp = tcp_established + tcp_pending
        if observed_tcp <= max_connections:
            raise HTTPException(
                status_code=409,
                detail=f"当前已建立/待建立 TCP 连接为 {observed_tcp}，未超过限额 {max_connections}；该规则不限制 UDP，未下发",
            )
        return (
            str(host["node_id"]),
            (instance_generation if runtime == "runman" else stable_id).lower(),
            {
                "metric_epoch": epoch,
                "observed_tcp_connections": observed_tcp,
                "observed_at": sampled_at,
                "action_expires_at": now + 300,
            },
        )

    def _latest_action_for_alert(self, conn: sqlite3.Connection, alert: sqlite3.Row) -> sqlite3.Row | None:
        latest = conn.execute(
            "SELECT * FROM security_actions WHERE alert_id=? ORDER BY id DESC LIMIT 1",
            (alert["id"],),
        ).fetchone()
        if latest is not None or alert["alert_type"] != "unauthorized_panel_pairing":
            return latest
        return conn.execute(
            """
            SELECT * FROM security_actions
            WHERE host_id=? AND runtime=? AND project=? AND container_name=?
              AND action_type IN ('remediate_panel_pairing','allow_panel_domains')
            ORDER BY id DESC LIMIT 1
            """,
            (alert["host_id"], alert["runtime"], alert["project"], alert["container_name"]),
        ).fetchone()

    def _refresh_remediation_process_pids(self, conn: sqlite3.Connection, action: sqlite3.Row) -> Dict[str, Any]:
        try:
            params = json.loads(action["params_json"] or "{}")
        except (TypeError, ValueError):
            params = {}
        if action["action_type"] != "remediate_panel_pairing" or not isinstance(params, dict):
            return params if isinstance(params, dict) else {}
        if action["runtime"] == "runman":
            return params
        alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (action["alert_id"],)).fetchone()
        if alert is None:
            return params
        evidence = self._app._alert_action_evidence(alert)
        approved_patterns = {
            str(item).strip().lower()
            for item in params.get("process_patterns", [])
            if isinstance(item, str) and item.strip()
        }
        current_patterns = {
            str(item).strip().lower()
            for item in evidence.get("process_patterns", [])
            if isinstance(item, str) and item.strip()
        }
        if approved_patterns & current_patterns:
            params["process_pids"] = evidence.get("process_pids") or []
        return params

    async def queue_security_action(self, alert_id: int, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        requested_action = str(payload.get("action") or "").strip().lower()
        if requested_action == "allow" and getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以修改长期放行策略")
        action_type = {"remediate": "remediate_panel_pairing", "allow": "allow_panel_domains"}.get(requested_action)
        if not action_type:
            raise HTTPException(status_code=400, detail="action must be remediate or allow")

        inv_mod = getattr(self._app, "investigation", investigation)
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
            if alert is None:
                raise HTTPException(status_code=404, detail="alert not found")
            if alert["status"] != "active":
                raise HTTPException(status_code=409, detail="alert is no longer active")
            if alert["alert_type"] != "unauthorized_panel_pairing":
                raise HTTPException(status_code=400, detail="this action only supports panel-pairing alerts")
            if alert["runtime"] not in ("podman", "incus", "runman"):
                raise HTTPException(status_code=400, detail="Docker and unknown runtimes are notice-only")
            if not alert["container_name"]:
                raise HTTPException(status_code=400, detail="alert has no container target")

            details = self._app._alert_action_evidence(alert)
            unapproved_domains = [
                str(item).strip().lower().rstrip(".")
                for item in details.get("unapproved_domains", [])
                if isinstance(item, str) and item.strip()
            ]
            process_patterns = [
                str(item).strip().lower()
                for item in details.get("process_patterns", [])
                if isinstance(item, str) and item.strip()
            ]
            config_files = [
                str(item).strip()
                for item in details.get("config_files", [])
                if isinstance(item, str) and item.strip()
            ]
            process_pids = details.get("process_pids") or []
            if action_type == "allow_panel_domains":
                if not unapproved_domains:
                    raise HTTPException(status_code=400, detail="alert has no exact domains to allow")
                params: Dict[str, Any] = {"domains": sorted(set(unapproved_domains))}
            else:
                if not process_patterns and not config_files:
                    raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
                params = {
                    "domains": sorted(set(unapproved_domains)),
                    "process_patterns": sorted(set(process_patterns)),
                    "process_pids": process_pids,
                    "config_files": sorted(set(config_files)),
                }
                if alert["runtime"] == "runman":
                    identity_ok, instance_id = self._app._runman_alert_generation_current(conn, alert, details)
                    if not identity_ok:
                        raise HTTPException(status_code=409, detail=instance_id)
                    process_targets = details.get("process_targets") or []
                    file_targets = details.get("file_targets") or []
                    if not process_targets and not file_targets:
                        raise HTTPException(
                            status_code=409, detail="Runman alert has no generation-bound process or file targets"
                        )
                    params.update(
                        {"instance_id": instance_id, "process_targets": process_targets, "file_targets": file_targets}
                    )

            requested_by = str(
                getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard")
            )[:100]
            row, queued = self._app._queue_security_action_row(conn, alert, action_type, params, requested_by)
            inv_mod.sync_states(conn, alert["host_id"], int(time.time()), alert_id=alert["id"])
            host_id = str(alert["host_id"])
            conn.commit()
        finally:
            conn.close()
        self._app.publish_live_event("alert", host_id)
        return JSONResponse(
            status_code=202 if queued else 200,
            content={"ok": True, "queued": queued, "action": self._app._action_item(row)},
        )

    async def set_security_alert_disposition(self, alert_id: int, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        decision = str(payload.get("decision") or "").strip().lower()
        if decision in ("allow_silent", "freeze_container", "unfreeze_container") and getattr(
            request.state, "dashboard_role", "admin"
        ) != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以修改长期放行策略或执行容器封禁操作")
        if decision not in (
            "deny", "allow_silent", "dismiss_once", "reopen", "resolve",
            "release_udp_throttle", "apply_udp_throttle", "stop_reviewed_socks",
            "apply_container_connlimit", "release_container_connlimit",
            "freeze_container", "unfreeze_container",
        ):
            raise HTTPException(status_code=400, detail="unsupported alert disposition")

        inv_mod = getattr(self._app, "investigation", investigation)
        stale_seconds = self._app.STALE_SECONDS
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
            if alert is None:
                raise HTTPException(status_code=404, detail="alert not found")
            if alert["alert_type"] == "prohibited_activity" and decision != "reopen":
                raise HTTPException(
                    status_code=409,
                    detail="隔离事件必须由管理员复核后，通过解除隔离入口处理；不能用忽略、静默或标记恢复替代。",
                )
            if alert["status"] != "active" and decision not in (
                "deny", "reopen", "allow_silent", "resolve", "release_udp_throttle",
                "apply_udp_throttle", "release_container_connlimit", "freeze_container", "unfreeze_container",
            ):
                raise HTTPException(status_code=409, detail="alert is no longer active")

            requested_by = str(
                getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard")
            )[:100]
            now = int(time.time())
            action = None
            queued = False
            if decision == "stop_reviewed_socks":
                if alert["runtime"] == "runman" and getattr(request.state, "dashboard_role", "admin") != "admin":
                    raise HTTPException(status_code=403, detail="Runman 人工停止操作仅限管理员")
                details = json.loads(alert["details_json"])
                reviews = details.get("password_review", [])
                observed = details.get("review_observed_at", 0)
                token = details.get("review_token", "")
                runman_generation = ""
                runman_identity_ok = True
                if alert["runtime"] == "runman":
                    runman_generation = str(details.get("instance_id") or "").lower()
                    latest = conn.execute(
                        "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime='runman' AND project='default' AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
                        (alert["host_id"], alert["container_name"]),
                    ).fetchone()
                    try:
                        latest_payload = json.loads(latest["payload_json"] or "{}") if latest is not None else {}
                    except (TypeError, ValueError):
                        latest_payload = {}
                    stable_id = (
                        str(latest_payload.get("stable_id") or latest_payload.get("id") or "").lower()
                        if isinstance(latest_payload, dict)
                        else ""
                    )
                    latest_generation = (
                        str(latest_payload.get("instance_id") or "").lower()
                        if isinstance(latest_payload, dict)
                        else ""
                    )
                    report_at = int(latest["ts"] or 0) if latest is not None else 0
                    runman_identity_ok = (
                        alert["project"] == "default"
                        and bool(
                            re.fullmatch(
                                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                alert["container_name"].lower(),
                            )
                        )
                        and bool(
                            re.fullmatch(
                                r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                                runman_generation,
                            )
                        )
                        and stable_id == alert["container_name"].lower()
                        and latest_generation == runman_generation
                        and report_at > 0
                        and report_at <= now + 30
                        and 0 <= now - report_at <= stale_seconds
                    )
                if (
                    alert["alert_type"] != "socks_password_review"
                    or alert["status"] != "active"
                    or alert["runtime"] not in {"incus", "podman", "runman"}
                    or not isinstance(observed, (int, float))
                    or not 0 <= now - observed <= 900
                    or not 0 <= now - alert["last_seen"] <= 900
                    or not isinstance(reviews, list)
                    or not reviews
                    or not all(isinstance(r, dict) and r.get("action_safe") is True for r in reviews)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(token))
                    or payload.get("review_token") != token
                    or not runman_identity_ok
                ):
                    raise HTTPException(
                        status_code=409, detail="证据过期、目标不明确或包含混合业务；请刷新后重新审核，未停止服务"
                    )
                reviewed_params = {"manual_review": True, "review_token": token, "review_observed_at": observed}
                if alert["runtime"] == "runman":
                    reviewed_params["instance_id"] = runman_generation
                action, queued = self._app._queue_security_action_row(
                    conn, alert, "stop_reviewed_socks", reviewed_params, requested_by
                )
            elif decision == "deny":
                if alert["alert_type"] not in self._app._ACTIONABLE_ALERT_TYPES:
                    raise HTTPException(
                        status_code=400,
                        detail="deny supports panel-pairing, confirmed no-auth SOCKS, and exact XMRig alerts",
                    )
                if alert["runtime"] not in ("podman", "incus", "runman"):
                    raise HTTPException(status_code=400, detail="Docker is notice-only and cannot be denied")
                if not alert["container_name"]:
                    raise HTTPException(status_code=400, detail="alert has no container target")
                conn.execute("DELETE FROM security_alert_policies WHERE fingerprint=?", (alert["fingerprint"],))
                conn.execute("UPDATE security_alerts SET status='active' WHERE id=?", (alert_id,))
                details = self._app._alert_action_evidence(alert)
                runman_instance_id = ""
                if alert["runtime"] == "runman":
                    if alert["alert_type"] not in ("unauthorized_panel_pairing", "malicious_process"):
                        raise HTTPException(
                            status_code=400,
                            detail="Runman deny supports only generation-bound panel or XMRig remediation",
                        )
                    identity_ok, runman_instance_id = self._app._runman_alert_generation_current(conn, alert, details, now)
                    if not identity_ok:
                        raise HTTPException(status_code=409, detail=runman_instance_id)
                if alert["alert_type"] == "socks_weak_auth":
                    if details.get("socks_auth_mode") not in ("no_auth", "weak_password"):
                        raise HTTPException(status_code=400, detail="仅可处置已确认空密码或弱密码的 SOCKS 服务")
                    process_names = details.get("socks_processes") or []
                    if not process_names:
                        raise HTTPException(status_code=400, detail="alert has no safe SOCKS process evidence")
                    params = {
                        "auth_mode": details["socks_auth_mode"],
                        "process_names": process_names,
                        "process_pids": details.get("socks_process_pids") or [],
                        "config_files": details.get("socks_config_files") or [],
                    }
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "enforce_socks_auth", params, requested_by
                    )
                elif alert["alert_type"] == "unauthorized_panel_pairing":
                    process_patterns = details.get("process_patterns") or []
                    process_pids = details.get("process_pids") or []
                    config_files = details.get("config_files") or []
                    if not process_patterns and not config_files:
                        raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
                    params = {
                        "domains": details.get("unapproved_domains") or [],
                        "process_patterns": process_patterns,
                        "process_pids": process_pids,
                        "config_files": config_files,
                    }
                    if alert["runtime"] == "runman":
                        process_targets = details.get("process_targets") or []
                        file_targets = details.get("file_targets") or []
                        if not process_targets and not file_targets:
                            raise HTTPException(
                                status_code=409, detail="Runman alert has no generation-bound process or file targets"
                            )
                        params.update(
                            {
                                "instance_id": runman_instance_id,
                                "process_targets": process_targets,
                                "file_targets": file_targets,
                            }
                        )
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "remediate_panel_pairing", params, requested_by
                    )
                else:
                    malicious_processes = details.get("malicious_processes") or []
                    exact_xmrig = [
                        item
                        for item in malicious_processes
                        if isinstance(item, dict) and item.get("process") == "xmrig"
                    ]
                    if not exact_xmrig:
                        raise HTTPException(status_code=400, detail="alert has no exact XMRig process evidence")
                    process_pids = []
                    for item in exact_xmrig:
                        try:
                            process_pid = int(item.get("pid") or 0)
                        except (TypeError, ValueError):
                            continue
                        if 1 < process_pid <= 4194304:
                            process_pids.append(process_pid)
                    process_targets = [
                        item
                        for item in (details.get("process_targets") or [])
                        if item.get("process") == "xmrig"
                        and item.get("pattern") == "xmrig"
                        and any(
                            malware.get("pid") == item.get("pid")
                            and malware.get("start_ticks") == item.get("start_ticks")
                            for malware in exact_xmrig
                        )
                    ]
                    if alert["runtime"] == "runman" and not process_targets:
                        raise HTTPException(status_code=409, detail="Runman XMRig alert lacks exact process-start evidence")
                    params = {"process_names": ["xmrig"], "process_pids": sorted(set(process_pids))}
                    if alert["runtime"] == "runman":
                        params.update(
                            {
                                "instance_id": runman_instance_id,
                                "process_targets": process_targets,
                                "file_targets": details.get("file_targets") or [],
                            }
                        )
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "remediate_malicious_process", params, requested_by
                    )
            elif decision == "allow_silent":
                conn.execute(
                    """
                    INSERT INTO security_alert_policies(
                        fingerprint, mode, requested_by, created_at, updated_at
                    ) VALUES(?,'allow_silent',?,?,?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        mode='allow_silent', requested_by=excluded.requested_by,
                        updated_at=excluded.updated_at
                    """,
                    (alert["fingerprint"], requested_by, now, now),
                )
                conn.execute("UPDATE security_alerts SET status='suppressed' WHERE id=?", (alert_id,))
                if alert["alert_type"] == "unauthorized_panel_pairing" and alert["runtime"] in (
                    "podman",
                    "incus",
                    "runman",
                ):
                    details = self._app._alert_action_evidence(alert)
                    domains = details.get("unapproved_domains") or []
                    if domains:
                        action, queued = self._app._queue_security_action_row(
                            conn, alert, "allow_panel_domains", {"domains": domains}, requested_by
                        )
                elif alert["alert_type"] == "socks_weak_auth" and alert["runtime"] in ("podman", "incus"):
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "release_socks_auth", {}, requested_by
                    )
            elif decision == "dismiss_once":
                conn.execute("UPDATE security_alerts SET status='dismissed' WHERE id=?", (alert_id,))
            elif decision == "resolve":
                conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (alert_id,))
            elif decision == "release_udp_throttle":
                conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (alert_id,))
                action, queued = self._app._queue_security_action_row(
                    conn, alert, "release_udp_throttle", {}, requested_by
                )
            elif decision == "apply_udp_throttle":
                action, queued = self._app._queue_security_action_row(
                    conn, alert, "apply_udp_throttle", {"rate_mbps": 10, "duration": 3600}, requested_by
                )
            elif decision in ("freeze_container", "unfreeze_container"):
                if alert["runtime"] not in ("podman", "incus", "runman") or not alert["container_name"]:
                    raise HTTPException(status_code=400, detail="当前运行时或目标实例不支持封禁/冻结操作")
                details = self._app._alert_action_evidence(alert)
                freeze_params: Dict[str, Any] = {}
                if details.get("instance_id"):
                    freeze_params["instance_id"] = str(details.get("instance_id"))
                if details.get("pid") and str(details.get("pid")).isdigit():
                    freeze_params["pid"] = int(details["pid"])
                if decision == "freeze_container":
                    conn.execute("UPDATE security_alerts SET status='remediated' WHERE id=?", (alert_id,))
                action, queued = self._app._queue_security_action_row(
                    conn, alert, decision, freeze_params, requested_by
                )
            elif decision in ("apply_container_connlimit", "release_container_connlimit"):
                if getattr(request.state, "dashboard_role", "admin") != "admin":
                    raise HTTPException(status_code=403, detail="只有管理员可以修改容器连接限制")
                if (
                    alert["alert_type"] != "container_connection_count"
                    or alert["runtime"] not in {"incus", "runman"}
                    or alert["project"] != "default"
                    or not alert["container_name"]
                ):
                    raise HTTPException(
                        status_code=400, detail="临时 TCP 限额仅适用于 default 项目内已接入的 Incus/Runman 连接数告警"
                    )
                if decision == "apply_container_connlimit":
                    raw_limit = payload.get("max_connections", 500)
                    raw_duration = payload.get("duration_seconds", 1800)
                    if type(raw_limit) is not int or not 100 <= raw_limit <= 10000:
                        raise HTTPException(status_code=400, detail="TCP 连接限额必须在 100–10000 之间")
                    if type(raw_duration) is not int or not 300 <= raw_duration <= 3600:
                        raise HTTPException(status_code=400, detail="限额有效期必须在 300–3600 秒之间")
                    node_id, instance_id, evidence = self._app._fresh_connlimit_identity(
                        conn, alert, now, raw_limit
                    )
                    active = conn.execute(
                        "SELECT params_json,status FROM security_actions WHERE host_id=? AND runtime=? AND project='default' AND container_name=? AND action_type='apply_container_connlimit' AND status='succeeded' ORDER BY id DESC LIMIT 1",
                        (alert["host_id"], alert["runtime"], alert["container_name"]),
                    ).fetchone()
                    if active is not None:
                        try:
                            active_params = json.loads(active["params_json"] or "{}")
                        except (TypeError, ValueError):
                            active_params = {}
                        if not isinstance(active_params, dict) or not active_params.get("instance_id"):
                            raise HTTPException(
                                status_code=409, detail="已有连接限制记录无法核实；为避免重复应用，请等待其自动过期"
                            )
                        active_lease = active_params.get("lease_expires_at")
                        if active_params.get("instance_id") == instance_id and type(active_lease) is not int:
                            raise HTTPException(status_code=409, detail="已有连接限制的过期时间无法核实；请等待节点自动清理")
                        if active_params.get("instance_id") == instance_id and active_lease > now:
                            raise HTTPException(
                                status_code=409, detail="该实例已有未过期的连接限制；请先解除或等待自动过期"
                            )
                    params = {
                        **evidence,
                        "expected_node_id": node_id,
                        "instance_id": instance_id,
                        "policy_id": secrets.token_hex(16),
                        "max_connections": raw_limit,
                        "lease_expires_at": now + raw_duration,
                        "reason": "admin_requested_connection_limit",
                    }
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "apply_container_connlimit", params, requested_by
                    )
                else:
                    latest = conn.execute(
                        "SELECT * FROM security_actions WHERE alert_id=? AND action_type IN ('apply_container_connlimit','release_container_connlimit') ORDER BY id DESC LIMIT 1",
                        (alert_id,),
                    ).fetchone()
                    if latest is None or latest["action_type"] != "apply_container_connlimit" or latest["status"] != "succeeded":
                        raise HTTPException(status_code=409, detail="没有可解除的已生效 TCP 限额")
                    try:
                        applied = json.loads(latest["params_json"] or "{}")
                    except (TypeError, ValueError):
                        applied = {}
                    applied_lease = applied.get("lease_expires_at") if isinstance(applied, dict) else None
                    if type(applied_lease) is not int or applied_lease <= now:
                        raise HTTPException(status_code=409, detail="该 TCP 限额已自动过期")
                    host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (alert["host_id"],)).fetchone()
                    if host is None or not host["node_id"] or now - int(host["last_seen"] or 0) > stale_seconds:
                        raise HTTPException(status_code=409, detail="节点离线或身份不可校验；现有限额仍会由节点自动过期")
                    params = {
                        "expected_node_id": str(host["node_id"]),
                        "instance_id": str(applied.get("instance_id") or ""),
                        "policy_id": str(applied.get("policy_id") or ""),
                        "action_expires_at": now + 300,
                        "lease_expires_at": applied_lease,
                    }
                    if not re.fullmatch(r"[0-9a-f]{32}", params["policy_id"]) or not params["instance_id"]:
                        raise HTTPException(status_code=409, detail="已生效限额缺少安全撤销标识；等待自动过期")
                    action, queued = self._app._queue_security_action_row(
                        conn, alert, "release_container_connlimit", params, requested_by
                    )
            else:
                conn.execute("DELETE FROM security_alert_policies WHERE fingerprint=?", (alert["fingerprint"],))
                conn.execute("UPDATE security_alerts SET status='active' WHERE id=?", (alert_id,))
                if alert["alert_type"] == "unauthorized_panel_pairing" and alert["runtime"] in (
                    "podman",
                    "incus",
                    "runman",
                ):
                    domains = self._app._alert_action_evidence(alert).get("unapproved_domains") or []
                    if domains:
                        action, queued = self._app._queue_security_action_row(
                            conn, alert, "disallow_panel_domains", {"domains": domains}, requested_by
                        )

            conn.execute(
                """
                INSERT INTO security_alert_decisions(
                    alert_id, fingerprint, decision, requested_by, created_at
                ) VALUES(?,?,?,?,?)
                """,
                (alert_id, alert["fingerprint"], decision, requested_by, now),
            )
            inv_mod.sync_states(conn, alert["host_id"], now, alert_id=alert["id"])
            host_id = str(alert["host_id"])
            conn.commit()
        finally:
            conn.close()
        self._app.publish_live_event("alert", host_id)
        try:
            self._app.sync_configured_bot_alert_messages(alert_id=alert_id)
        except Exception as exc:
            print(f"telegram sync on disposition {alert_id} failed: {exc}")
        return JSONResponse(
            status_code=202 if action is not None and queued else 200,
            content={
                "ok": True,
                "decision": decision,
                "queued": queued,
                "action": self._app._action_item(action) if action is not None else None,
            },
        )

    async def set_container_disposition(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        host_id = str(payload.get("host_id") or "").strip()[:200]
        runtime = str(payload.get("runtime") or "").strip()[:80]
        project = str(payload.get("project") or "").strip()[:100]
        container_name = str(payload.get("container_name") or "").strip()[:200]
        decision = str(payload.get("decision") or "").strip().lower()
        raw_alert_id = payload.get("alert_id")
        alert_id = None
        if raw_alert_id not in (None, ""):
            try:
                alert_id = int(raw_alert_id)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="alert_id must be an integer")
            if alert_id <= 0:
                raise HTTPException(status_code=400, detail="alert_id must be positive")
        if not host_id or not runtime or not container_name:
            raise HTTPException(status_code=400, detail="host_id, runtime, and container_name are required")
        if decision not in (
            "deny", "allow_silent", "dismiss_once", "reopen", "resolve",
            "release_udp_throttle", "apply_udp_throttle", "freeze_container", "unfreeze_container",
            "apply_udp_blackhole", "release_udp_blackhole", "apply_anti_spoof", "release_anti_spoof",
        ):
            raise HTTPException(status_code=400, detail="invalid decision")

        conn = self._app.db()
        try:
            identity = (host_id, runtime, project, container_name)
            selected_alert_id = None
            if alert_id is not None:
                alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
                if alert is None:
                    raise HTTPException(status_code=404, detail="alert not found")
                alert_identity = (
                    str(alert["host_id"] or ""),
                    str(alert["runtime"] or ""),
                    str(alert["project"] or ""),
                    str(alert["container_name"] or ""),
                )
                if (
                    alert_identity[0] != identity[0]
                    or alert_identity[1] != identity[1]
                    or alert_identity[3] != identity[3]
                    or (alert_identity[2] and identity[2] and alert_identity[2] != identity[2])
                ):
                    raise HTTPException(
                        status_code=409, detail="alert_id 与目标主机、运行时、项目或容器不匹配"
                    )
                selected_alert_id = int(alert["id"])
            else:
                actionable_types = tuple(sorted(self._app._ACTIONABLE_ALERT_TYPES))
                placeholders = ",".join("?" for _ in actionable_types)
                alert = conn.execute(
                    f"""
                    SELECT * FROM security_alerts
                    WHERE host_id=? AND runtime=?
                      AND (project=? OR project='' OR ?='')
                      AND container_name=?
                      AND status='active' AND alert_type IN ({placeholders})
                    ORDER BY id DESC LIMIT 1
                    """,
                    (host_id, runtime, project, project, container_name, *actionable_types),
                ).fetchone()
                if alert is None and decision == "resolve":
                    alert = conn.execute(
                        """
                        SELECT * FROM security_alerts
                        WHERE host_id=? AND runtime=?
                          AND (project=? OR project='' OR ?='')
                          AND container_name=?
                          AND status='active'
                        ORDER BY id DESC LIMIT 1
                        """,
                        (host_id, runtime, project, project, container_name),
                    ).fetchone()
                if alert is not None:
                    selected_alert_id = int(alert["id"])

            if selected_alert_id is not None:
                conn.close()
                return await self._app.set_security_alert_disposition(selected_alert_id, request)

            if decision in (
                "release_udp_throttle", "apply_udp_throttle", "freeze_container", "unfreeze_container",
                "apply_udp_blackhole", "release_udp_blackhole", "apply_anti_spoof", "release_anti_spoof",
            ):
                now = int(time.time())
                action_type = decision
                params = {"rate_mbps": 10, "duration": 3600} if decision == "apply_udp_throttle" else {}
                requested_by = str(
                    getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard")
                )[:100]
                cur = conn.execute(
                    """
                    INSERT INTO security_actions(
                        alert_id, host_id, runtime, project, container_name, action_type, params_json,
                        status, requested_by, created_at, updated_at
                    ) VALUES(0,?,?,?,?,?,?,'queued',?,?,?)
                    """,
                    (
                        host_id,
                        runtime,
                        project,
                        container_name,
                        action_type,
                        json.dumps(params, ensure_ascii=False),
                        requested_by,
                        now,
                        now,
                    ),
                )
                action_row = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
                conn.commit()
                conn.close()
                self._app.publish_live_event("alert", host_id)
                return JSONResponse(
                    status_code=202,
                    content={
                        "ok": True,
                        "decision": decision,
                        "queued": True,
                        "action": self._app._action_item(action_row) if action_row is not None else None,
                    },
                )
            if alert is None:
                raise HTTPException(status_code=404, detail="未找到该容器对应的可处置活动安全告警记录")
            selected_alert_id = int(alert["id"])
        finally:
            conn.close()
        return await self._app.set_security_alert_disposition(selected_alert_id, request)

    def security_actions(self, limit: int = 200) -> JSONResponse:
        limit = max(1, min(limit, 1000))
        conn = self._app.db()
        rows = conn.execute("SELECT * FROM security_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return JSONResponse(content={"items": [self._app._action_item(row) for row in rows]})

    def security_alerts(self, active_only: bool = True, limit: int = 200) -> JSONResponse:
        limit = max(1, min(limit, 1000))
        stale_seconds = self._app.STALE_SECONDS
        conn = self._app.db()
        if active_only:
            rows = conn.execute(
                """
                SELECT a.* FROM security_alerts a
                LEFT JOIN hosts h ON h.host_id=a.host_id
                WHERE a.status='active'
                  AND a.alert_type<>'admission_unverified'
                  AND a.alert_type <> 'speedtest_attempt_blocked'
                  AND (a.container_name<>'' OR h.host_id IS NULL OR h.last_seen>=?)
                ORDER BY a.last_seen DESC, a.id DESC LIMIT ?
                """,
                (int(time.time()) - stale_seconds, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM security_alerts ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        items = [self._app._security_alert_item(conn, row) for row in rows]
        conn.close()
        active_count = sum(1 for item in items if item["status"] == "active") if not active_only else len(items)
        return JSONResponse(content={"items": items, "active_count": active_count})

    def security_alert_history(
        self,
        status: str = "all",
        severity: str = "all",
        alert_type: str = "all",
        host_id: str = "",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> JSONResponse:
        valid_statuses = {"active", "suppressed", "dismissed", "resolved", "remediated"}
        valid_severities = {"info", "warning", "critical"}
        status = status.strip().lower()
        severity = severity.strip().lower()
        alert_type = alert_type.strip()[:80]
        host_id = host_id.strip()[:200]
        query = query.strip()[:200]
        if status != "all" and status not in valid_statuses:
            raise HTTPException(status_code=400, detail="invalid alert status")
        if severity != "all" and severity not in valid_severities:
            raise HTTPException(status_code=400, detail="invalid alert severity")
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        clauses: List[str] = []
        params: List[Any] = []
        if status != "all":
            clauses.append("status=?")
            params.append(status)
        if severity != "all":
            clauses.append("severity=?")
            params.append(severity)
        if alert_type and alert_type != "all":
            clauses.append("alert_type=?")
            params.append(alert_type)
        if host_id:
            clauses.append("host_id=?")
            params.append(host_id)
        if query:
            like_query = f"%{query}%"
            clauses.append(
                "(host_id LIKE ? OR container_name LIKE ? OR title LIKE ? OR message LIKE ? OR details_json LIKE ?)"
            )
            params.extend([like_query, like_query, like_query, like_query, like_query])
        where_sql = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = self._app.db()
        total = int(conn.execute(f"SELECT COUNT(*) FROM security_alerts{where_sql}", params).fetchone()[0])
        rows = conn.execute(
            f"SELECT * FROM security_alerts{where_sql} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        counts = {item: 0 for item in ("all", *sorted(valid_statuses))}
        for count_row in conn.execute("SELECT status, COUNT(*) AS count FROM security_alerts GROUP BY status").fetchall():
            current_status = str(count_row["status"])
            counts[current_status] = int(count_row["count"])
            counts["all"] += int(count_row["count"])
        alert_types = [
            str(item["alert_type"])
            for item in conn.execute("SELECT DISTINCT alert_type FROM security_alerts ORDER BY alert_type").fetchall()
        ]
        hosts = [
            str(item["host_id"])
            for item in conn.execute("SELECT DISTINCT host_id FROM security_alerts ORDER BY host_id").fetchall()
        ]
        items = [self._app._security_alert_item(conn, row) for row in rows]
        conn.close()
        return JSONResponse(
            content={
                "items": items,
                "total": total,
                "limit": limit,
                "offset": offset,
                "counts": counts,
                "alert_types": alert_types,
                "hosts": hosts,
            }
        )


def bind(app_mod: Any) -> AlertService:
    global _app, _service
    _app = app_mod
    _service = AlertService(app_mod)
    return _service


def attach(app: FastAPI, app_mod: Any) -> AlertService:
    svc = bind(app_mod)
    router = APIRouter()
    router.add_api_route("/api/v1/security/alerts/{alert_id}/actions", svc.queue_security_action, methods=["POST"])
    router.add_api_route(
        "/api/v1/security/alerts/{alert_id}/disposition", svc.set_security_alert_disposition, methods=["POST"]
    )
    router.add_api_route("/api/v1/containers/disposition", svc.set_container_disposition, methods=["POST"])
    router.add_api_route("/api/v1/security/actions", svc.security_actions, methods=["GET"])
    router.add_api_route("/api/v1/security/alerts", svc.security_alerts, methods=["GET"])
    router.add_api_route("/api/v1/security/history", svc.security_alert_history, methods=["GET"])
    app.include_router(router)
    return svc


def __getattr__(name: str) -> Any:
    if _service is not None and hasattr(_service, name):
        return getattr(_service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
