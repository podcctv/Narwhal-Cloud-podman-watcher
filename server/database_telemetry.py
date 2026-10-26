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
            total_bytes INTEGER NOT NULL
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
    bucket = int(now // SAMPLE_INTERVAL_SECONDS * SAMPLE_INTERVAL_SECONDS)
    total_bytes = database_bytes + wal_bytes
    conn.execute(
        "INSERT OR IGNORE INTO database_storage_samples(ts,database_bytes,wal_bytes,reusable_bytes,total_bytes) VALUES(?,?,?,?,?)",
        (bucket, database_bytes, wal_bytes, reusable_bytes, total_bytes),
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
    }
    if baseline:
        trend.update(assess_growth(total_bytes, int(baseline[1])))

    rows = conn.execute(
        "SELECT ts,database_bytes,wal_bytes,reusable_bytes,total_bytes FROM database_storage_samples ORDER BY ts DESC LIMIT ?",
        (max(2, min(168, int(history_limit))),),
    ).fetchall()
    trend["history"] = [
        {
            "ts": int(row[0]),
            "database_bytes": int(row[1]),
            "wal_bytes": int(row[2]),
            "reusable_bytes": int(row[3]),
            "total_bytes": int(row[4]),
        }
        for row in reversed(rows)
    ]
    trend["retention_days"] = HISTORY_RETENTION_SECONDS // 86400
    trend["sample_interval_seconds"] = SAMPLE_INTERVAL_SECONDS
    return trend
