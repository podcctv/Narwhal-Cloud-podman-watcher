"""Bounded, hourly SQLite size history for operator diagnostics.

The measurements are intentionally kept in a small table in the monitored
database. Sampling is idempotent within an hour and old rows are pruned, so
the history cannot become another unbounded telemetry stream.
"""
from __future__ import annotations

import os
import sqlite3

SAMPLE_INTERVAL_SECONDS = 3600
HISTORY_RETENTION_SECONDS = 45 * 86400
HISTORY_RESPONSE_LIMIT = 48
TABLE_HISTORY_RETENTION_SECONDS = 45 * 86400
TABLE_HISTORY_LIMIT = 30
WARNING_GROWTH_BYTES = 256 * 1024 * 1024
WARNING_GROWTH_PERCENT = 10.0
CRITICAL_GROWTH_BYTES = 1024 * 1024 * 1024
CRITICAL_GROWTH_PERCENT = 25.0
_HISTORY_WINDOW_SECONDS = 24 * 3600
_HISTORY_WINDOW_TOLERANCE_SECONDS = 4 * 3600


def initialize(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS database_storage_samples (
            ts INTEGER PRIMARY KEY,
            database_bytes INTEGER NOT NULL,
            wal_bytes INTEGER NOT NULL,
            reusable_bytes INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            checkpoint_busy INTEGER,
            wal_log_frames INTEGER,
            wal_checkpointed_frames INTEGER
        )"""
    )
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(database_storage_samples)")}
    for name, definition in (
        ("checkpoint_busy", "INTEGER"),
        ("wal_log_frames", "INTEGER"),
        ("wal_checkpointed_frames", "INTEGER"),
    ):
        if name not in columns:
            conn.execute(f"ALTER TABLE database_storage_samples ADD COLUMN {name} {definition}")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS database_table_storage_samples (
            ts INTEGER NOT NULL,
            table_name TEXT NOT NULL,
            bytes INTEGER NOT NULL,
            PRIMARY KEY(ts,table_name)
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_database_table_storage_name_ts ON database_table_storage_samples(table_name,ts DESC)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS database_table_sample_runs (
            ts INTEGER PRIMARY KEY,
            status TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT ''
        )"""
    )


def _file_size(path: str) -> int:
    try:
        return max(0, int(os.path.getsize(path)))
    except OSError:
        return 0


def assess_growth(current_bytes: int, baseline_bytes: int | None) -> dict:
    """Require both an absolute and relative increase before raising a flag."""
    if baseline_bytes is None or baseline_bytes <= 0:
        return {"status": "warming_up", "growth_bytes": None, "growth_percent": None}
    growth_bytes = int(current_bytes) - int(baseline_bytes)
    growth_percent = growth_bytes / int(baseline_bytes) * 100.0
    if growth_bytes >= CRITICAL_GROWTH_BYTES and growth_percent >= CRITICAL_GROWTH_PERCENT:
        status = "critical"
    elif growth_bytes >= WARNING_GROWTH_BYTES and growth_percent >= WARNING_GROWTH_PERCENT:
        status = "warning"
    else:
        status = "healthy"
    return {"status": status, "growth_bytes": growth_bytes, "growth_percent": round(growth_percent, 2)}


def sample_and_summarize(
    conn: sqlite3.Connection,
    database_path: str,
    now: int,
    *,
    history_limit: int = HISTORY_RESPONSE_LIMIT,
) -> dict:
    """Record one sample per UTC hour and return bounded history plus a 24h trend."""
    initialize(conn)
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    database_bytes = max(0, page_count * page_size)
    reusable_bytes = max(0, freelist_count * page_size)
    wal_bytes = _file_size(database_path + "-wal")
    checkpoint_busy = wal_log_frames = wal_checkpointed_frames = None
    try:
        checkpoint = conn.execute("PRAGMA wal_checkpoint(NOOP)").fetchone()
        if checkpoint and int(checkpoint[1]) >= 0 and int(checkpoint[2]) >= 0:
            checkpoint_busy = int(checkpoint[0])
            wal_log_frames = int(checkpoint[1])
            wal_checkpointed_frames = int(checkpoint[2])
    except sqlite3.DatabaseError:
        # Older SQLite builds can still report WAL file size and growth; the
        # checkpoint frame counters remain explicitly unavailable.
        pass
    bucket = int(now // SAMPLE_INTERVAL_SECONDS * SAMPLE_INTERVAL_SECONDS)
    total_bytes = database_bytes + wal_bytes
    conn.execute(
        "INSERT OR IGNORE INTO database_storage_samples(ts,database_bytes,wal_bytes,reusable_bytes,total_bytes,checkpoint_busy,wal_log_frames,wal_checkpointed_frames) VALUES(?,?,?,?,?,?,?,?)",
        (bucket, database_bytes, wal_bytes, reusable_bytes, total_bytes, checkpoint_busy, wal_log_frames, wal_checkpointed_frames),
    )
    conn.execute(
        "DELETE FROM database_storage_samples WHERE ts < ?",
        (int(now) - HISTORY_RETENTION_SECONDS,),
    )
    conn.commit()

    lower = int(now) - _HISTORY_WINDOW_SECONDS - _HISTORY_WINDOW_TOLERANCE_SECONDS
    upper = int(now) - _HISTORY_WINDOW_SECONDS + _HISTORY_WINDOW_TOLERANCE_SECONDS
    baseline = conn.execute(
        "SELECT ts,total_bytes FROM database_storage_samples WHERE ts BETWEEN ? AND ? ORDER BY ABS(ts-?) LIMIT 1",
        (lower, upper, int(now) - _HISTORY_WINDOW_SECONDS),
    ).fetchone()
    pending_frames = max(0, wal_log_frames - wal_checkpointed_frames) if wal_log_frames is not None and wal_checkpointed_frames is not None else None
    pending_bytes = pending_frames * page_size if pending_frames is not None else None
    checkpoint_status = "unavailable" if wal_log_frames is None else "healthy"
    if checkpoint_busy:
        checkpoint_status = "blocked"
    elif pending_bytes is not None and pending_bytes >= 256 * 1024 * 1024:
        checkpoint_status = "backlog"
    trend = {
        "status": "warming_up",
        "sampled_at": bucket,
        "database_bytes": database_bytes,
        "wal_bytes": wal_bytes,
        "total_bytes": total_bytes,
        "baseline_at": int(baseline[0]) if baseline else 0,
        "baseline_bytes": int(baseline[1]) if baseline else 0,
        "growth_bytes": None,
        "growth_percent": None,
        "window_seconds": _HISTORY_WINDOW_SECONDS,
        "warning_threshold_bytes": WARNING_GROWTH_BYTES,
        "warning_threshold_percent": WARNING_GROWTH_PERCENT,
        "critical_threshold_bytes": CRITICAL_GROWTH_BYTES,
        "critical_threshold_percent": CRITICAL_GROWTH_PERCENT,
        "wal_checkpoint": {
            "status": checkpoint_status,
            "busy": checkpoint_busy,
            "log_frames": wal_log_frames,
            "checkpointed_frames": wal_checkpointed_frames,
            "pending_frames": pending_frames,
            "pending_bytes": pending_bytes,
        },
    }
    if baseline:
        trend.update(assess_growth(total_bytes, int(baseline[1])))

    rows = conn.execute(
        "SELECT ts,database_bytes,wal_bytes,reusable_bytes,total_bytes,checkpoint_busy,wal_log_frames,wal_checkpointed_frames FROM database_storage_samples ORDER BY ts DESC LIMIT ?",
        (max(2, min(168, int(history_limit))),),
    ).fetchall()
    trend["history"] = [
        {
            "ts": int(row[0]),
            "database_bytes": int(row[1]),
            "wal_bytes": int(row[2]),
            "reusable_bytes": int(row[3]),
            "total_bytes": int(row[4]),
            "checkpoint_busy": int(row[5]) if row[5] is not None else None,
            "wal_log_frames": int(row[6]) if row[6] is not None else None,
            "wal_checkpointed_frames": int(row[7]) if row[7] is not None else None,
        }
        for row in reversed(rows)
    ]
    trend["retention_days"] = HISTORY_RETENTION_SECONDS // 86400
    trend["sample_interval_seconds"] = SAMPLE_INTERVAL_SECONDS
    return trend


def sample_table_sizes(conn: sqlite3.Connection, now: int) -> dict:
    """Capture bounded per-table dbstat sizes once per hour; skip unsupported/slow scans."""
    initialize(conn)
    bucket = int(now // SAMPLE_INTERVAL_SECONDS * SAMPLE_INTERVAL_SECONDS)
    previous = conn.execute("SELECT status,reason FROM database_table_sample_runs WHERE ts=?", (bucket,)).fetchone()
    if previous:
        return {"status": str(previous[0]), "sampled_at": bucket, "reason": str(previous[1] or "")}
    import time
    deadline = time.monotonic() + 3.0
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 2000)
    try:
        rows = conn.execute(
            "SELECT s.tbl_name AS name,SUM(d.pgsize) AS bytes "
            "FROM dbstat AS d JOIN sqlite_schema AS s ON s.name=d.name "
            "WHERE s.type IN ('table','index') "
            "AND s.tbl_name NOT LIKE 'sqlite_%' "
            "AND s.tbl_name NOT IN ('database_storage_samples','database_table_storage_samples','database_table_sample_runs') "
            "GROUP BY s.tbl_name ORDER BY bytes DESC LIMIT 100"
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        reason = f"dbstat unavailable or scan interrupted: {type(exc).__name__}"
        conn.execute("INSERT OR REPLACE INTO database_table_sample_runs(ts,status,reason) VALUES(?, 'unavailable', ?)", (bucket, reason))
        conn.execute("DELETE FROM database_table_sample_runs WHERE ts < ?", (int(now) - TABLE_HISTORY_RETENTION_SECONDS,))
        conn.commit()
        return {"status": "unavailable", "sampled_at": bucket, "reason": reason}
    finally:
        conn.set_progress_handler(None, 0)
    if not rows:
        reason = "dbstat returned no table sizes"
        conn.execute("INSERT OR REPLACE INTO database_table_sample_runs(ts,status,reason) VALUES(?, 'unavailable', ?)", (bucket, reason))
        conn.execute("DELETE FROM database_table_sample_runs WHERE ts < ?", (int(now) - TABLE_HISTORY_RETENTION_SECONDS,))
        conn.commit()
        return {"status": "unavailable", "sampled_at": bucket, "reason": reason}
    conn.executemany(
        "INSERT OR REPLACE INTO database_table_storage_samples(ts,table_name,bytes) VALUES(?,?,?)",
        [(bucket, str(row[0])[:200], max(0, int(row[1] or 0))) for row in rows],
    )
    conn.execute("DELETE FROM database_table_storage_samples WHERE ts < ?", (int(now) - TABLE_HISTORY_RETENTION_SECONDS,))
    conn.execute("INSERT OR REPLACE INTO database_table_sample_runs(ts,status,reason) VALUES(?, 'sampled', '')", (bucket,))
    conn.execute("DELETE FROM database_table_sample_runs WHERE ts < ?", (int(now) - TABLE_HISTORY_RETENTION_SECONDS,))
    conn.commit()
    return {"status": "sampled", "sampled_at": bucket, "table_count": len(rows)}


def table_growth(conn: sqlite3.Connection, now: int, *, limit: int = TABLE_HISTORY_LIMIT) -> dict:
    initialize(conn)
    latest = conn.execute("SELECT MAX(ts) FROM database_table_storage_samples").fetchone()
    sampled_at = int(latest[0] or 0) if latest else 0
    if not sampled_at:
        return {"status": "warming_up", "sampled_at": 0, "retention_days": TABLE_HISTORY_RETENTION_SECONDS // 86400, "tables": []}
    target = int(now) - 86400
    baseline = conn.execute(
        "SELECT ts FROM database_table_storage_samples WHERE ts BETWEEN ? AND ? ORDER BY ABS(ts-?) LIMIT 1",
        (target - 4 * 3600, target + 4 * 3600, target),
    ).fetchone()
    baseline_ts = int(baseline[0]) if baseline else 0
    candidate_limit = max(1, min(100, int(limit)))
    rows = conn.execute(
        """SELECT cur.table_name,cur.bytes,old.bytes
           FROM database_table_storage_samples cur
           LEFT JOIN database_table_storage_samples old ON old.table_name=cur.table_name AND old.ts=?
           WHERE cur.ts=? ORDER BY cur.bytes DESC LIMIT 100""",
        (baseline_ts or -1, sampled_at),
    ).fetchall()
    tables = []
    for row in rows:
        size = int(row[1] or 0)
        old_size = int(row[2]) if row[2] is not None else None
        growth = size - old_size if old_size is not None else None
        percent = round(growth * 100.0 / old_size, 2) if growth is not None and old_size else None
        growth_status = assess_growth(size, old_size)
        tables.append({"name": str(row[0]), "bytes": size, "baseline_bytes": old_size,
                       "growth_24h_bytes": growth, "growth_24h_percent": percent,
                       "status": growth_status["status"]})
    tables.sort(key=lambda item: item["growth_24h_bytes"] if item["growth_24h_bytes"] is not None else -1, reverse=True)
    tables = tables[:candidate_limit]
    sample_run = conn.execute("SELECT status,reason FROM database_table_sample_runs WHERE ts=?", (sampled_at,)).fetchone()
    return {"status": "ready" if baseline_ts else "warming_up", "sampled_at": sampled_at,
            "baseline_at": baseline_ts, "window_seconds": 86400,
            "retention_days": TABLE_HISTORY_RETENTION_SECONDS // 86400, "tables": tables,
            "sample_status": str(sample_run[0]) if sample_run else "unknown",
            "sample_reason": str(sample_run[1] or "") if sample_run else ""}
