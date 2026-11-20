"""Database retention, bounded cleanup, and offline host pruning."""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict


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

        for _ in range(20):
            progress = 0
            jobs = [
                ("reports", "ts < ?", (effective_raw_cutoff,)),
                ("host_security", "ts < ?", (effective_raw_cutoff,)),
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
            backlog = progress > 0
            if not backlog or time.monotonic() >= deadline:
                break
        # Incremental mode is enabled for new DBs and by the explicit recovery
        # command for old DBs. Never run a full VACUUM in this online loop.
        if int(conn.execute("PRAGMA auto_vacuum").fetchone()[0]) == 2:
            conn.execute("PRAGMA incremental_vacuum(2048)").fetchall()
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
        cleanup_status.update(last_success=now, removed_rows=removed_total, backlog=backlog, disk_pressure=disk_pressure, error=None)
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
