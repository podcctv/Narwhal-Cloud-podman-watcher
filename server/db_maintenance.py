"""Database retention, bounded cleanup, and offline host pruning."""
from __future__ import annotations

import json
import logging
import math
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict

try:
    from server import gfw_monitor, tcping
except ImportError:
    import gfw_monitor  # type: ignore[no-redef]
    import tcping  # type: ignore[no-redef]


_REPORT_COMPACT_KEYS = (
    "_agent_version",
    "id",
    "stable_id",
    "instance_id",
    "name",
    "runtime",
    "project",
    "mem_limit_bytes",
    "cpu_effective_cpus",
    "tcp_rx_bps",
    "tcp_tx_bps",
    "udp_rx_bps",
    "udp_tx_bps",
    "monitor_mode",
)
_REPORT_DISK_SCALAR_KEYS = (
    "root_device",
    "root_total_bytes",
    "root_used_percent",
    "root_avail_bytes",
    "data_total_bytes",
    "data_avail_bytes",
    "data_requested_path",
    "data_mountpoint",
    "file",
    "size_bytes",
    "used_percent",
)
_REPORT_SECURITY_KEYS = (
    "inbound_unique_ips",
    "outbound_unique_ips",
    "udp_throttle",
    "hy2_protocol",
)
_HOST_SECURITY_COMPACT_KEYS = (
    "enabled",
    "interval_seconds",
    "total_rx_bps",
    "total_tx_bps",
    "total_rx_pps",
    "total_tx_pps",
    "syn_recv_count",
    "active_alerts_in_sample",
)


def _compact_aged_payloads(
    conn: Any,
    now: int,
    *,
    aged_cutoff: int,
    batch_size: int,
    deadline: float,
) -> int:
    """Compact large non-latest JSON payloads older than aged_cutoff within budget."""
    if batch_size <= 0 or time.monotonic() >= deadline:
        return 0
    compacted = 0

    reports_limit = min(int(batch_size), 400)
    report_rows = conn.execute(
        "SELECT id, payload_json FROM reports "
        "WHERE ts < ? AND length(payload_json) > 2048 "
        "AND payload_json NOT LIKE '%\"_compacted\":true%' "
        "AND EXISTS (SELECT 1 FROM reports newer WHERE newer.host_id=reports.host_id "
        "AND newer.runtime=reports.runtime AND newer.project=reports.project "
        "AND newer.container_name=reports.container_name AND newer.id > reports.id) "
        "LIMIT ?",
        (aged_cutoff, reports_limit),
    ).fetchall()
    reports_dirty = False
    for row in report_rows:
        if time.monotonic() >= deadline:
            break
        try:
            payload = json.loads(row[1] or "")
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        compact: Dict[str, Any] = {"_compacted": True}
        for key in _REPORT_COMPACT_KEYS:
            if key in payload:
                compact[key] = payload[key]
        raw_disk = payload.get("disk")
        if isinstance(raw_disk, dict):
            compact_disk = {
                key: raw_disk[key]
                for key in _REPORT_DISK_SCALAR_KEYS
                if key in raw_disk and (raw_disk[key] is None or isinstance(raw_disk[key], (str, int, float, bool)))
            }
            if compact_disk:
                compact["disk"] = compact_disk
        raw_sec = payload.get("security")
        if isinstance(raw_sec, dict):
            compact_sec = {
                key: raw_sec[key]
                for key in _REPORT_SECURITY_KEYS
                if key in raw_sec
            }
            if compact_sec:
                compact["security"] = compact_sec
        conn.execute(
            "UPDATE reports SET payload_json=? WHERE id=?",
            (json.dumps(compact, ensure_ascii=False, separators=(",", ":")), row[0]),
        )
        compacted += 1
        reports_dirty = True
    if reports_dirty:
        conn.commit()

    if time.monotonic() >= deadline:
        return compacted

    hs_limit = min(int(batch_size), 200)
    hs_rows = conn.execute(
        "SELECT id, payload_json FROM host_security "
        "WHERE ts < ? AND length(payload_json) > 4096 "
        "AND payload_json NOT LIKE '%\"_compacted\":true%' "
        "AND EXISTS (SELECT 1 FROM host_security newer WHERE newer.host_id=host_security.host_id "
        "AND newer.id > host_security.id) "
        "LIMIT ?",
        (aged_cutoff, hs_limit),
    ).fetchall()
    hs_dirty = False
    for row in hs_rows:
        if time.monotonic() >= deadline:
            break
        try:
            payload = json.loads(row[1] or "")
        except (TypeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        compact_hs: Dict[str, Any] = {"_compacted": True}
        for key in _HOST_SECURITY_COMPACT_KEYS:
            if key in payload:
                compact_hs[key] = payload[key]
        raw_access_log = payload.get("access_log")
        if isinstance(raw_access_log, dict):
            compact_access_log = {
                key: value
                for key, value in raw_access_log.items()
                if value is None or isinstance(value, (str, int, float, bool))
            }
            if compact_access_log:
                compact_hs["access_log"] = compact_access_log
        conn.execute(
            "UPDATE host_security SET payload_json=? WHERE id=?",
            (json.dumps(compact_hs, ensure_ascii=False, separators=(",", ":")), row[0]),
        )
        compacted += 1
        hs_dirty = True
    if hs_dirty:
        conn.commit()

    return compacted


def _safe_int(value: Any) -> int:
    if value is None or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else 0
    try:
        if isinstance(value, float) and not math.isfinite(value):
            return 0
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_float(value: Any) -> float:
    if value is None or isinstance(value, bool):
        return float(int(value)) if isinstance(value, bool) else 0.0
    try:
        num = float(value)
        return num if math.isfinite(num) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _table_columns(conn: Any, table: str) -> set[str]:
    return {str(r[1]) for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _has_missing_peak_columns(conn: Any) -> bool:
    report_cols = _table_columns(conn, "reports")
    if {"inbound_unique_ips", "outbound_unique_ips"} <= report_cols:
        if conn.execute(
            "SELECT 1 FROM reports WHERE inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL LIMIT 1"
        ).fetchone():
            return True
    hs_cols = _table_columns(conn, "host_security")
    if {"total_rx_bps", "total_tx_bps"} <= hs_cols:
        if conn.execute(
            "SELECT 1 FROM host_security WHERE total_rx_bps IS NULL OR total_tx_bps IS NULL LIMIT 1"
        ).fetchone():
            return True
    return False


def _backfill_missing_peak_columns(
    conn: Any,
    batch_size: int = 5000,
    deadline: float | None = None,
) -> int:
    """Backfill legacy NULL peak columns in reports and host_security within budget."""
    budget = max(0, int(batch_size))
    if budget <= 0:
        return 0
    if deadline is None:
        deadline = time.monotonic() + 5.0
    if time.monotonic() >= deadline:
        return 0

    report_cols = _table_columns(conn, "reports")
    hs_cols = _table_columns(conn, "host_security")
    can_reports = {"inbound_unique_ips", "outbound_unique_ips"} <= report_cols
    can_hs = {"total_rx_bps", "total_tx_bps"} <= hs_cols
    updated_total = 0

    def backfill_host_security(limit: int) -> int:
        if not can_hs or limit <= 0:
            return 0
        done = 0
        while done < limit and time.monotonic() < deadline:
            chunk_limit = min(limit - done, 250)
            rows = conn.execute(
                "SELECT id, payload_json, total_rx_bps, total_tx_bps "
                "FROM host_security "
                "WHERE total_rx_bps IS NULL OR total_tx_bps IS NULL "
                "LIMIT ?",
                (chunk_limit,),
            ).fetchall()
            if not rows:
                break
            updates = []
            for row in rows:
                try:
                    payload = json.loads(row[1] or "")
                except (TypeError, ValueError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                rx_bps = row[2] if row[2] is not None else _safe_float(payload.get("total_rx_bps"))
                tx_bps = row[3] if row[3] is not None else _safe_float(payload.get("total_tx_bps"))
                updates.append((rx_bps, tx_bps, row[0]))
            conn.executemany(
                "UPDATE host_security SET total_rx_bps=?, total_tx_bps=? WHERE id=?",
                updates,
            )
            conn.commit()
            done += len(updates)
        return done

    def backfill_reports(limit: int) -> int:
        if not can_reports or limit <= 0:
            return 0
        done = 0
        while done < limit and time.monotonic() < deadline:
            chunk_limit = min(limit - done, 250)
            rows = conn.execute(
                "SELECT id, payload_json, inbound_unique_ips, outbound_unique_ips "
                "FROM reports "
                "WHERE inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL "
                "LIMIT ?",
                (chunk_limit,),
            ).fetchall()
            if not rows:
                break
            updates = []
            for row in rows:
                try:
                    payload = json.loads(row[1] or "")
                except (TypeError, ValueError):
                    payload = {}
                sec = payload.get("security") if isinstance(payload, dict) else None
                if not isinstance(sec, dict):
                    sec = {}
                in_ips = row[2] if row[2] is not None else _safe_int(sec.get("inbound_unique_ips"))
                out_ips = row[3] if row[3] is not None else _safe_int(sec.get("outbound_unique_ips"))
                updates.append((in_ips, out_ips, row[0]))
            conn.executemany(
                "UPDATE reports SET inbound_unique_ips=?, outbound_unique_ips=? WHERE id=?",
                updates,
            )
            conn.commit()
            done += len(updates)
        return done

    hs_first_limit = budget // 2 if can_reports and budget >= 2 else budget
    hs_done = backfill_host_security(hs_first_limit)
    updated_total += hs_done
    reports_done = backfill_reports(budget - updated_total)
    updated_total += reports_done
    if updated_total < budget and can_hs and hs_done == hs_first_limit and time.monotonic() < deadline:
        updated_total += backfill_host_security(budget - updated_total)
    return updated_total


def run_cleanup(
    *,
    db_fn: Callable[[], Any],
    db_path: str,
    investigation_maintain_fn: Callable[[Any, int], Any],
    cleanup_status: Dict[str, Any],
    purge_seconds: int,
    raw_retention_seconds: int,
    offline_host_purge_seconds: int,
    report_cleanup_batch_size: int,
    report_max_rows: int,
    host_security_max_rows: int,
    cleanup_time_budget_seconds: float,
    now_ts: int | None = None,
) -> tuple[int, bool]:
    """Run bounded retention cleanup across monitoring tables and return (removed_reports, backlog)."""
    conn = None
    removed_reports = 0
    removed_total = 0
    backlog = False
    try:
        now = int(time.time()) if now_ts is None else now_ts
        cutoff = now - purge_seconds
        raw_cutoff = now - min(purge_seconds, raw_retention_seconds)
        deadline = time.monotonic() + cleanup_time_budget_seconds
        conn = db_fn()
        investigation_maintain_fn(conn, now)
        tcping.expire(conn, now)
        conn.commit()

        # Complete each small transaction before starting the next; never hold
        # the API writer lock across a whole retention backlog.
        def prune(table: str, predicate: str, params: tuple = ()) -> int:
            nonlocal removed_reports, removed_total
            cur = conn.execute(
                f"DELETE FROM {table} WHERE rowid IN "
                f"(SELECT rowid FROM {table} WHERE {predicate} LIMIT ?)",
                (*params, report_cleanup_batch_size),
            )
            count = max(0, cur.rowcount)
            conn.commit()
            removed_total += count
            if table == "reports":
                removed_reports += count
            return count

        disk_pressure = False
        try:
            du = shutil.disk_usage(Path(db_path).resolve().parent)
            free_pct = (du.free / du.total * 100.0) if du.total > 0 else 100.0
            disk_pressure = free_pct < 15.0 or du.free < 2 * 1024 * 1024 * 1024
        except OSError:
            disk_pressure = False
        effective_report_cap = min(report_max_rows, 15000) if disk_pressure else report_max_rows
        effective_host_sec_cap = min(host_security_max_rows, 8000) if disk_pressure else host_security_max_rows
        effective_raw_cutoff = max(raw_cutoff, now - 48 * 3600) if disk_pressure else raw_cutoff
        gfw_batch = min(report_cleanup_batch_size, 1000)

        for loop_idx in range(20):
            progress = 0
            jobs = [
                ("reports", "ts < ?", (effective_raw_cutoff,)),
                ("host_security", "ts < ?", (effective_raw_cutoff,)),
                ("admission_states", "observed_at < ?", (now - 86400,)),
                ("ops_rollups", "bucket < ?", (cutoff,)),
                ("host_reachability_history", "checked_at < ?", (now - min(purge_seconds, 14 * 86400),)),
                ("gfw_probe_results", "NOT EXISTS (SELECT 1 FROM gfw_probe_jobs j WHERE j.id=gfw_probe_results.job_id)", ()),
                ("host_collection_health_hourly", "bucket_start < ?", (now - 30 * 86400,)),
                ("security_alerts", "status IN ('resolved','remediated','dismissed','suppressed') AND last_seen < ? AND NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.alert_id=security_alerts.id AND q.status NOT IN ('released','replaced'))", (cutoff,)),
                ("security_actions", "status IN ('succeeded','failed','cancelled') AND updated_at < ?", (cutoff,)),
                ("security_alert_decisions", "created_at < ? OR NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", (cutoff,)),
                ("security_alert_evidence", "captured_at < ? OR NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", (cutoff,)),
                ("telegram_alert_messages", "NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", ()),
                ("network_quarantines", "status IN ('released','replaced') AND updated_at < ?", (cutoff,)),
                ("connection_overloads", "last_seen < ?", (now - offline_host_purge_seconds,)),
            ]
            for table, predicate, params in jobs:
                progress += prune(table, predicate, params)
            gfw_removed = gfw_monitor.prune_history(conn, now, batch_size=gfw_batch)
            if gfw_removed:
                conn.commit()
                removed_total += gfw_removed
                progress += gfw_removed
            # A row budget also bounds high-frequency raw history within the
            # retention period. Preserve each identity's newest sample.
            for table, cap, identity in (
                ("reports", effective_report_cap, ("host_id", "runtime", "project", "container_name")),
                ("host_security", effective_host_sec_cap, ("host_id",)),
            ):
                boundary = conn.execute(f"SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?", (cap - 1,)).fetchone()
                if boundary:
                    same = " AND ".join(f"newer.{column}={table}.{column}" for column in identity)
                    progress += prune(table, f"id < ? AND EXISTS (SELECT 1 FROM {table} newer WHERE {same} AND newer.id > {table}.id)", (boundary[0],))
            if disk_pressure:
                for aux_table in ("ops_rollups", "gfw_probe_results"):
                    aux_boundary = conn.execute(f"SELECT rowid FROM {aux_table} ORDER BY rowid DESC LIMIT 1 OFFSET 49999").fetchone()
                    if aux_boundary:
                        progress += prune(aux_table, "rowid < ?", (aux_boundary[0],))
            # Drain offline hosts in batches before removing their identity.
            offline = conn.execute(
                "SELECT host_id FROM hosts WHERE last_seen < ? AND NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.host_id=hosts.host_id AND q.status NOT IN ('released','replaced')) LIMIT 25",
                (now - offline_host_purge_seconds,),
            ).fetchall()
            for host in offline:
                for table in ("reports", "host_security", "host_collection_health_hourly", "security_actions", "security_alerts", "connection_overloads", "host_firewall_readbacks"):
                    progress += prune(table, "host_id=?", (host[0],))
                remains = any(
                    conn.execute(f"SELECT 1 FROM {table} WHERE host_id=? LIMIT 1", (host[0],)).fetchone()
                    for table in ("reports", "host_security", "host_collection_health_hourly", "security_actions", "security_alerts")
                )
                if not remains:
                    conn.execute("DELETE FROM hosts WHERE host_id=?", (host[0],))
                    conn.commit()
            if progress == 0:
                backlog = False
                break
            if loop_idx == 19 or time.monotonic() >= deadline:
                backlog = True
                break
        compacted_rows = 0
        if time.monotonic() < deadline:
            aged_cutoff = now - (24 * 3600 if disk_pressure else 48 * 3600)
            compacted_rows = _compact_aged_payloads(
                conn,
                now,
                aged_cutoff=aged_cutoff,
                batch_size=report_cleanup_batch_size,
                deadline=deadline,
            )
        backfilled_peak_rows = _backfill_missing_peak_columns(
            conn,
            batch_size=report_cleanup_batch_size,
            deadline=deadline,
        )
        if not backlog and _has_missing_peak_columns(conn):
            backlog = True
        # Incremental mode is enabled for new DBs and by the explicit recovery
        # command for old DBs. Never run a full VACUUM in this online loop.
        if int(conn.execute("PRAGMA auto_vacuum").fetchone()[0]) == 2:
            conn.execute("PRAGMA incremental_vacuum(2048)").fetchall()
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
        cleanup_status.update(
            last_success=now,
            removed_rows=removed_total,
            compacted_rows=compacted_rows,
            backfilled_peak_rows=backfilled_peak_rows,
            backlog=backlog,
            disk_pressure=disk_pressure,
            error=None,
        )
        return removed_reports, backlog
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        cleanup_status.update(error=str(exc), last_failure=int(time.time()), backlog=True)
        logging.exception("Database cleanup failed; will retry")
        return removed_reports, True
    finally:
        if conn is not None:
            conn.close()
