import asyncio
import base64
import binascii
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
import secrets
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import socks
except ImportError:
    socks = None

from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

STATIC_DIR = Path(__file__).resolve().parent / "static"
ASSETS_DIR = STATIC_DIR / "assets"

DB_PATH = os.getenv("DB_PATH", "/data/monitor.db")
SHARED_SECRET = os.getenv("SHARED_SECRET", "change-me")
ALERT_DISK_THRESHOLD_PERCENT = int(os.getenv("ALERT_DISK_THRESHOLD_PERCENT", "80"))
ALERT_CPU_THRESHOLD_PERCENT = float(os.getenv("ALERT_CPU_THRESHOLD_PERCENT", "80"))
ALERT_CONN_WARNING_THRESHOLD = int(
    os.getenv("ALERT_CONN_WARNING_THRESHOLD", os.getenv("ALERT_CONN_THRESHOLD", "500"))
)
ALERT_CONN_CRITICAL_THRESHOLD = int(os.getenv("ALERT_CONN_CRITICAL_THRESHOLD", "1000"))
CONNECTION_STOP_THRESHOLD = int(os.getenv("CONNECTION_STOP_THRESHOLD", "2000"))
CONNECTION_AUTO_STOP_ENABLED = os.getenv('CONNECTION_AUTO_STOP_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on')
CONNECTION_STOP_DURATION_SECONDS = max(60, int(os.getenv("CONNECTION_STOP_DURATION_SECONDS", "300")))
CONNECTION_STOP_MAX_GAP_SECONDS = max(1, min(600, int(os.getenv("CONNECTION_STOP_MAX_GAP_SECONDS", "360"))))
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))
RFW_APPLICATION_PROTOCOLS = ("http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto")
RFW_CN_ALERT_PROTOCOLS = {"socks", "fet", "wireguard", "mtproto", "openvpn"}
OFFLINE_HIDE_SECONDS = int(os.getenv("OFFLINE_HIDE_SECONDS", str(7 * 24 * 3600)))
OFFLINE_HOST_PURGE_SECONDS = int(os.getenv("OFFLINE_HOST_PURGE_SECONDS", str(7 * 24 * 3600)))
PURGE_SECONDS = int(os.getenv("PURGE_SECONDS", str(30 * 24 * 3600)))
DB_BUSY_TIMEOUT_MS = max(1000, int(os.getenv("DB_BUSY_TIMEOUT_MS", "30000")))
REPORT_CLEANUP_INTERVAL_SECONDS = max(
    60, int(os.getenv("REPORT_CLEANUP_INTERVAL_SECONDS", "300"))
)
REPORT_CLEANUP_BATCH_SIZE = max(100, int(os.getenv("REPORT_CLEANUP_BATCH_SIZE", "5000")))
RAW_RETENTION_SECONDS = max(3600, int(os.getenv("RAW_RETENTION_SECONDS", str(7 * 86400))))
REPORT_MAX_ROWS = max(1000, int(os.getenv("REPORT_MAX_ROWS", "50000")))
HOST_SECURITY_MAX_ROWS = max(1000, int(os.getenv("HOST_SECURITY_MAX_ROWS", "20000")))
CLEANUP_TIME_BUDGET_SECONDS = max(1, float(os.getenv("CLEANUP_TIME_BUDGET_SECONDS", "5")))
_cleanup_status: Dict[str, Any] = {}
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
ALERT_WEBHOOK_MIN_SEVERITY = os.getenv("ALERT_WEBHOOK_MIN_SEVERITY", "warning").strip().lower()
TLS_CA_CERT_PATH = os.getenv("TLS_CA_CERT_PATH", "/tls-ca/root.crt")
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
TELEGRAM_PROXY_URL = os.getenv("TELEGRAM_PROXY_URL", "").strip()


def get_telegram_proxy_url() -> str:
    """Return effective Telegram proxy URL, respecting module variable, env, or standard proxy envs."""
    proxy = (
        (TELEGRAM_PROXY_URL or "").strip()
        or os.getenv("TELEGRAM_PROXY_URL", "").strip()
        or os.getenv("ALL_PROXY", "").strip()
        or os.getenv("all_proxy", "").strip()
        or os.getenv("HTTPS_PROXY", "").strip()
        or os.getenv("https_proxy", "").strip()
        or os.getenv("HTTP_PROXY", "").strip()
        or os.getenv("http_proxy", "").strip()
    )
    if proxy and "://" not in proxy:
        proxy = f"http://{proxy}"
    return proxy


def _normalize_telegram_token(raw_token: Any) -> str:
    token = str(raw_token or "").strip().strip("'\"")
    if token.lower().startswith("bot") and len(token) > 3 and token[3].isdigit():
        token = token[3:]
    return token


def _parse_telegram_target(target: str) -> tuple[str, int | None]:
    """Parse chat target and optional forum thread ID from target string."""
    raw = str(target or "").strip().strip("'\"")
    if raw.startswith("https://t.me/"):
        raw = "@" + raw.removeprefix("https://t.me/").strip("/")
    elif raw.startswith("t.me/"):
        raw = "@" + raw.removeprefix("t.me/").strip("/")
    for sep in (":", "/"):
        if sep in raw and not raw.startswith("@"):
            parts = raw.split(sep, 1)
            if parts[0] and parts[1].isdigit():
                return parts[0].strip(), int(parts[1])
    return raw, None
APP_VERSION = os.getenv("NARWHAL_VERSION", "dev").strip() or "dev"
UTC8 = timezone(timedelta(hours=8))
_cleanup_lock = threading.Lock()
_next_cleanup_monotonic = 0.0
_telegram_poll_offsets: Dict[int, int] = {}


def format_utc8(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=UTC8).strftime("%Y-%m-%d %H:%M:%S")


def report_agent_version(payload_json: str | None) -> str:
    try:
        payload = json.loads(payload_json or "{}")
    except (TypeError, ValueError):
        return "unknown"
    return str(payload.get("_agent_version") or "unknown")


app = FastAPI(title="Narwhal Container Monitor")

try:
    from server import operations, operations_api, buyer_notifications, investigation, dashboard_auth, commerce, tcping, gfw_monitor, disk_cleanup, connection_policy, ip_reputation, inbound_assessment, database_telemetry
except ImportError:
    import operations
    import connection_policy
    import operations_api
    import disk_cleanup
    import investigation
    import buyer_notifications
    import dashboard_auth
    import commerce
    import tcping
    import gfw_monitor
    import ip_reputation
    import inbound_assessment
    import database_telemetry

try:
    from server import abuse_api, admission_api
except ImportError:
    import abuse_api
    import admission_api

_AGENT_ONLY_PATHS = {
    "/api/v1/abuse/events",
    "/api/v1/admission/events",
    "/api/v1/admission/status",
    "/api/v1/report",
    "/api/v1/tls/ca",
    "/api/v1/actions/poll",
    "/api/v1/actions/result",
    "/api/v1/tcp-probe/report",
    "/api/v1/gfw-probe/report",
    "/api/v1/gfw-probe/failure",
    "/api/v1/update/version",
}

# Telegram sends updates without the dashboard's Basic credentials.  The opaque
# per-bot path secret below is the authentication boundary for this endpoint.
_BOT_CALLBACK_PREFIX = "/api/v1/notifications/telegram/"


def dashboard_user_from_authorization(authorization: str) -> str | None:
    if not DASHBOARD_USERNAME or not DASHBOARD_PASSWORD or not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    user_ok = hmac.compare_digest(username.encode(), DASHBOARD_USERNAME.encode())
    password_ok = hmac.compare_digest(password.encode(), DASHBOARD_PASSWORD.encode())
    return username if user_ok and password_ok else None


dashboard_auth.attach(app, lambda: db(), lambda: (DASHBOARD_USERNAME, DASHBOARD_PASSWORD),
                      _AGENT_ONLY_PATHS, _BOT_CALLBACK_PREFIX, STATIC_DIR)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=DB_BUSY_TIMEOUT_MS / 1000.0)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    global _latest_cache, _latest_cache_time
    # Tests and administrative recovery may point DB_PATH at a fresh database.
    # Never serve a short-lived snapshot from the previous database in that case.
    _latest_cache = None
    _latest_cache_time = 0.0
    conn = db()
    # WAL lets dashboard reads coexist with frequent agent writes.  This is
    # especially important once monitor.db contains large JSON payloads.
    # Existing NONE-mode databases require an explicit offline VACUUM migration;
    # never rebuild a multi-GB database while starting the API.
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            container_name TEXT NOT NULL,
            runtime TEXT NOT NULL DEFAULT 'podman',
            project TEXT NOT NULL DEFAULT '',
            cpu_percent REAL NOT NULL,
            mem_bytes INTEGER NOT NULL,
            mem_percent REAL NOT NULL DEFAULT 0,
            net_rx_bps REAL NOT NULL,
            net_tx_bps REAL NOT NULL,
            conn_count INTEGER NOT NULL,
            disk_file TEXT,
            disk_size_bytes INTEGER,
            disk_used_percent REAL,
            podman_network_ok_v4 INTEGER NOT NULL,
            podman_network_ok_v6 INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reports_host_ts ON reports(host_id, ts);
        CREATE INDEX IF NOT EXISTS idx_reports_host_container_ts ON reports(host_id, container_name, ts);
        CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts);
        CREATE TABLE IF NOT EXISTS container_user_notes (
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL,
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL,
            container_id TEXT NOT NULL,
            user_email TEXT NOT NULL DEFAULT '',
            user_note TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            updated_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(host_id, runtime, project, container_name, container_id)
        );
        CREATE INDEX IF NOT EXISTS idx_container_user_notes_email ON container_user_notes(user_email);
        CREATE TABLE IF NOT EXISTS hosts (
            host_id TEXT PRIMARY KEY,
            last_seen INTEGER NOT NULL,
            agent_version TEXT NOT NULL DEFAULT 'unknown',
            node_id TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen);
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL DEFAULT '',
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL DEFAULT '',
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            value REAL NOT NULL DEFAULT 0,
            threshold REAL NOT NULL DEFAULT 0,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',
            details_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_security_alerts_status_last_seen
            ON security_alerts(status, last_seen);
        CREATE INDEX IF NOT EXISTS idx_security_alerts_host_last_seen
            ON security_alerts(host_id, last_seen);
        CREATE TABLE IF NOT EXISTS host_security (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_host_security_host_ts ON host_security(host_id, ts);
        CREATE INDEX IF NOT EXISTS idx_host_security_ts ON host_security(ts);
        CREATE TABLE IF NOT EXISTS host_firewall_event_state (
            host_id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL,
            sequence INTEGER NOT NULL DEFAULT 0,
            cursor TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_firewall_readbacks (
            host_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'unknown',
            observed_at INTEGER NOT NULL DEFAULT 0,
            last_success_at INTEGER NOT NULL DEFAULT 0,
            snapshot_json TEXT NOT NULL DEFAULT '{}',
            readback_reason TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS security_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL,
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            requested_by TEXT NOT NULL,
            result_message TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_actions_host_status_updated
            ON security_actions(host_id, status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_security_actions_alert_created
            ON security_actions(alert_id, created_at);
        CREATE TABLE IF NOT EXISTS host_firewall_policies (
            host_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL,
            policy_json TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            source_fleet_revision INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS host_firewall_policy_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            policy_json TEXT NOT NULL,
            updated_by TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            source_fleet_revision INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_host_firewall_policy_history_host_revision
            ON host_firewall_policy_history(host_id, revision DESC);
        CREATE TABLE IF NOT EXISTS fleet_firewall_policy (
            id INTEGER PRIMARY KEY CHECK(id=1),
            revision INTEGER NOT NULL,
            policy_json TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_alert_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            mode TEXT NOT NULL DEFAULT 'allow_silent',
            requested_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_alert_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            decision TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_alert_decisions_alert_created
            ON security_alert_decisions(alert_id, created_at);
        CREATE TABLE IF NOT EXISTS security_alert_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            action_id INTEGER NOT NULL UNIQUE,
            captured_at INTEGER NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_security_alert_evidence_alert_captured
            ON security_alert_evidence(alert_id, captured_at DESC);
        CREATE TABLE IF NOT EXISTS connection_overloads (
            host_id TEXT NOT NULL,
            runtime TEXT NOT NULL,
            project TEXT NOT NULL DEFAULT '',
            container_name TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            sample_count INTEGER NOT NULL DEFAULT 1,
            stop_action_id INTEGER,
            PRIMARY KEY(host_id, runtime, project, container_name)
        );
        CREATE INDEX IF NOT EXISTS idx_connection_overloads_last_seen
            ON connection_overloads(last_seen);
        CREATE TABLE IF NOT EXISTS notification_bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'telegram',
            token TEXT NOT NULL,
            target TEXT NOT NULL,
            min_severity TEXT NOT NULL DEFAULT 'critical',
            enabled INTEGER NOT NULL DEFAULT 1,
            callback_secret TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS telegram_alert_messages (
            bot_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            chat_id TEXT NOT NULL,
            message_id INTEGER NOT NULL,
            last_status TEXT NOT NULL DEFAULT 'active',
            last_severity TEXT NOT NULL DEFAULT '',
            last_evidence_action_id INTEGER NOT NULL DEFAULT 0,
            content_hash TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(bot_id, alert_id)
        );
        CREATE INDEX IF NOT EXISTS idx_telegram_alert_messages_updated
            ON telegram_alert_messages(updated_at);
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        """
    )
    cols = conn.execute("PRAGMA table_info(reports)").fetchall()
    col_names = {str(c["name"]) for c in cols}
    if "mem_percent" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN mem_percent REAL NOT NULL DEFAULT 0")
    if "runtime" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN runtime TEXT NOT NULL DEFAULT 'podman'")
    if "project" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN project TEXT NOT NULL DEFAULT ''")
    host_cols = {str(c["name"]) for c in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    if "node_id" not in host_cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN node_id TEXT NOT NULL DEFAULT ''")
    if "config_json" not in host_cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}'")
    firewall_policy_cols = {
        str(c["name"]) for c in conn.execute("PRAGMA table_info(host_firewall_policies)").fetchall()
    }
    if "source_fleet_revision" not in firewall_policy_cols:
        conn.execute(
            "ALTER TABLE host_firewall_policies ADD COLUMN source_fleet_revision INTEGER NOT NULL DEFAULT 0"
        )
    firewall_readback_cols = {
        str(c["name"]) for c in conn.execute("PRAGMA table_info(host_firewall_readbacks)").fetchall()
    }
    if "readback_reason" not in firewall_readback_cols:
        conn.execute("ALTER TABLE host_firewall_readbacks ADD COLUMN readback_reason TEXT NOT NULL DEFAULT ''")
    bot_cols = {str(c["name"]) for c in conn.execute("PRAGMA table_info(notification_bots)").fetchall()}
    if "last_delivery_status" not in bot_cols:
        conn.execute("ALTER TABLE notification_bots ADD COLUMN last_delivery_status TEXT NOT NULL DEFAULT 'never'")
    if "last_delivery_error" not in bot_cols:
        conn.execute("ALTER TABLE notification_bots ADD COLUMN last_delivery_error TEXT NOT NULL DEFAULT ''")
    if "last_sent_at" not in bot_cols:
        conn.execute("ALTER TABLE notification_bots ADD COLUMN last_sent_at INTEGER NOT NULL DEFAULT 0")
    telegram_message_cols = {
        str(c["name"]) for c in conn.execute("PRAGMA table_info(telegram_alert_messages)").fetchall()
    }
    if "last_evidence_action_id" not in telegram_message_cols:
        conn.execute("ALTER TABLE telegram_alert_messages ADD COLUMN last_evidence_action_id INTEGER NOT NULL DEFAULT 0")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_node_id_unique ON hosts(node_id) WHERE node_id <> ''")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_host_runtime_project_container_ts "
        "ON reports(host_id, runtime, project, container_name, ts)"
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO hosts(host_id, last_seen, agent_version)
        SELECT host_id, MAX(ts), 'unknown' FROM reports GROUP BY host_id
        """
    )
    operations.initialize(conn)
    connection_policy.initialize(conn)
    buyer_notifications.initialize(conn)
    investigation.initialize(conn)
    commerce.initialize(conn)
    tcping.initialize(conn)
    gfw_monitor.initialize(conn)
    abuse_api.initialize(conn)
    admission_api.initialize(conn)
    ip_reputation.initialize(conn)
    database_telemetry.initialize(conn)
    conn.commit()
    conn.close()


async def _cleanup_background_loop() -> None:
    # Allow uvicorn to start serving requests before beginning heavy cleanup
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.to_thread(cleanup_old_reports, force=True)
            await asyncio.to_thread(operations_maintenance)
            # Collect hourly growth history even if operators do not open the
            # storage page; sampling itself is idempotent within each hour.
            await asyncio.to_thread(database_storage_status)
        except Exception:
            logging.exception("Database retention worker failed")
        await asyncio.sleep(5 if _cleanup_status.get("backlog") else REPORT_CLEANUP_INTERVAL_SECONDS)


@app.on_event("startup")
async def startup() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    init_db()
    try:
        from server import fleet_updates
    except ImportError:
        import fleet_updates
    asyncio.create_task(fleet_updates.run(db, lambda: APP_VERSION))
    asyncio.create_task(_buyer_background_loop())
    asyncio.create_task(_cleanup_background_loop())
    if not PUBLIC_BASE_URL:
        asyncio.create_task(_telegram_polling_loop())


async def _buyer_background_loop():
    # Startup never replays historical reports or sends migration test messages.
    await asyncio.sleep(20)
    while True:
        try:
            await asyncio.to_thread(buyer_notifications.sync_mappings, db)
            await asyncio.to_thread(buyer_notifications.work_once, db)
        except Exception:
            logging.exception("Buyer outbox worker failed")
        await asyncio.sleep(10)


buyer_notifications.attach(app, db)


def database_storage_status() -> Dict[str, Any]:
    conn = db()
    try:
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        pages = int(conn.execute("PRAGMA page_count").fetchone()[0])
        free = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
        return {
            "database_bytes": pages * page_size,
            "reusable_bytes": free * page_size,
            "live_bytes": (pages - free) * page_size,
            "wal_bytes": os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0,
            "auto_vacuum": int(conn.execute("PRAGMA auto_vacuum").fetchone()[0]),
            "growth": database_telemetry.sample_and_summarize(conn, DB_PATH, int(time.time())),
            "cleanup": dict(_cleanup_status),
            "raw_retention_seconds": min(PURGE_SECONDS, RAW_RETENTION_SECONDS),
            "report_max_rows": REPORT_MAX_ROWS,
            "host_security_max_rows": HOST_SECURITY_MAX_ROWS,
        }
    finally:
        conn.close()


@app.get("/api/v1/database/status")
def database_status() -> JSONResponse:
    return JSONResponse(content=database_storage_status())


def operations_maintenance():
    drill_path = None
    drill_attempted_at = 0
    conn = db()
    try:
        now = int(time.time())
        operations.maintain(conn, now)
        row = conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
        settings = operations.loads(row[0]) if row else {}
        due = settings.get("enabled") and now-settings.get("last_attempt", 0) >= settings.get("interval_hours", 24)*3600
        if due:
            settings["last_attempt"] = now
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)", (json.dumps(settings),))
            conn.commit()
            try:
                settings["last_result"] = operations.backup(DB_PATH, settings.get("retention", 7))
                settings["last_success"] = now
                settings.pop("error", None)
            except Exception as e:
                settings["error"] = str(e)[:500]
                logging.exception("Scheduled backup failed")
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)", (json.dumps(settings),))
            conn.commit()
        drill_due = settings.get("enabled") and settings.get("drill_enabled") and now-settings.get("last_drill_attempt", 0) >= 7*86400
        if drill_due:
            folder = Path(DB_PATH).parent / "backups"
            candidates = sorted(folder.glob("monitor-*.db"), key=lambda item: item.stat().st_mtime, reverse=True)
            if candidates:
                drill_path = str(candidates[0])
                drill_attempted_at = now
                settings["last_drill_attempt"] = now
                conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)", (json.dumps(settings),))
                conn.commit()
    finally:
        conn.close()
    if drill_path:
        try:
            result = operations.restore_drill(drill_path)
        except Exception as exc:
            result = {"backup_name": Path(drill_path).name, "started_at": drill_attempted_at,
                      "finished_at": int(time.time()), "duration_ms": 0, "status": "failed",
                      "message": str(exc)[:400] or type(exc).__name__, "bytes": 0, "sha256": "", "details": {}}
        conn = db()
        try:
            operations.record_backup_drill(conn, result)
            row = conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            settings = operations.loads(row[0]) if row else {}
            settings["last_drill"] = {key: result[key] for key in ("backup_name", "started_at", "finished_at", "duration_ms", "status", "message", "bytes", "sha256")}
            settings["last_drill_at"] = result["finished_at"]
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)", (json.dumps(settings, ensure_ascii=False),))
            conn.commit()
        finally:
            conn.close()


def cleanup_old_reports(now_ts: int | None = None, force: bool = False) -> int:
    """Bound each transaction, catch up backlog, and expose failures."""
    global _next_cleanup_monotonic
    scheduled = now_ts is None and not force
    if scheduled and time.monotonic() < _next_cleanup_monotonic:
        return 0
    if not _cleanup_lock.acquire(blocking=not scheduled):
        return 0
    conn = None
    removed_reports = 0
    removed_total = 0
    backlog = False
    try:
        if scheduled and time.monotonic() < _next_cleanup_monotonic:
            return 0
        now = int(time.time()) if now_ts is None else now_ts
        cutoff = now - PURGE_SECONDS
        raw_cutoff = now - min(PURGE_SECONDS, RAW_RETENTION_SECONDS)
        deadline = time.monotonic() + CLEANUP_TIME_BUDGET_SECONDS
        conn = db()
        investigation.maintain(conn, now)
        conn.commit()
        # Complete this small transaction before starting the next; never hold
        # the API writer lock across a whole retention backlog.
        def prune(table: str, predicate: str, params: tuple = ()) -> int:
            nonlocal removed_reports, removed_total
            cur = conn.execute(
                f"DELETE FROM {table} WHERE rowid IN "
                f"(SELECT rowid FROM {table} WHERE {predicate} LIMIT ?)",
                (*params, REPORT_CLEANUP_BATCH_SIZE),
            )
            count = max(0, cur.rowcount)
            conn.commit()
            removed_total += count
            if table == "reports":
                removed_reports += count
            return count

        for _ in range(20):
            progress = 0
            jobs = [
                ("reports", "ts < ?", (raw_cutoff,)),
                ("host_security", "ts < ?", (raw_cutoff,)),
                ("security_alerts", "status IN ('resolved','remediated','dismissed','suppressed') AND last_seen < ? AND NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.alert_id=security_alerts.id AND q.status<>'released')", (cutoff,)),
                ("security_actions", "status IN ('succeeded','failed','cancelled') AND updated_at < ?", (cutoff,)),
                ("security_alert_decisions", "created_at < ? OR NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", (cutoff,)),
                ("security_alert_evidence", "captured_at < ? OR NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", (cutoff,)),
                ("telegram_alert_messages", "NOT EXISTS (SELECT 1 FROM security_alerts a WHERE a.id=alert_id)", ()),
                ("network_quarantines", "status='released' AND updated_at < ?", (cutoff,)),
                ("connection_overloads", "last_seen < ?", (now - OFFLINE_HOST_PURGE_SECONDS,)),
            ]
            for table, predicate, params in jobs:
                progress += prune(table, predicate, params)
            # A row budget also bounds high-frequency raw history within the
            # retention period. Preserve each identity's newest sample.
            for table, cap, identity in (
                ("reports", REPORT_MAX_ROWS, ("host_id", "runtime", "project", "container_name")),
                ("host_security", HOST_SECURITY_MAX_ROWS, ("host_id",)),
            ):
                boundary = conn.execute(f"SELECT id FROM {table} ORDER BY id DESC LIMIT 1 OFFSET ?", (cap - 1,)).fetchone()
                if boundary:
                    same = " AND ".join(f"newer.{column}={table}.{column}" for column in identity)
                    progress += prune(table, f"id < ? AND EXISTS (SELECT 1 FROM {table} newer WHERE {same} AND newer.id > {table}.id)", (boundary[0],))
            # Drain offline hosts in batches before removing their identity.
            offline = conn.execute("SELECT host_id FROM hosts WHERE last_seen < ? AND NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.host_id=hosts.host_id AND q.status<>'released') LIMIT 25", (now - OFFLINE_HOST_PURGE_SECONDS,)).fetchall()
            for host in offline:
                for table in ("reports", "host_security", "security_actions", "security_alerts", "connection_overloads", "host_firewall_readbacks"):
                    progress += prune(table, "host_id=?", (host[0],))
                remains = any(conn.execute(f"SELECT 1 FROM {table} WHERE host_id=? LIMIT 1", (host[0],)).fetchone()
                              for table in ("reports", "host_security", "security_actions", "security_alerts"))
                if not remains:
                    conn.execute("DELETE FROM hosts WHERE host_id=?", (host[0],))
                    conn.commit()
            backlog = progress > 0
            if not backlog or time.monotonic() >= deadline:
                break
        # Incremental mode is enabled for new DBs and by the explicit recovery
        # command for old DBs. Never run a full VACUUM in this online loop.
        if int(conn.execute("PRAGMA auto_vacuum").fetchone()[0]) == 2:
            conn.execute("PRAGMA incremental_vacuum(512)").fetchall()
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
        _cleanup_status.update(last_success=now, removed_rows=removed_total, backlog=backlog, error=None)
        _next_cleanup_monotonic = time.monotonic() + (5 if backlog else REPORT_CLEANUP_INTERVAL_SECONDS)
        return removed_reports
    except Exception as exc:
        if conn is not None:
            conn.rollback()
        _cleanup_status.update(error=str(exc), last_failure=int(time.time()), backlog=True)
        logging.exception("Database cleanup failed; will retry")
        _next_cleanup_monotonic = time.monotonic() + 5
        return removed_reports
    finally:
        if conn is not None:
            conn.close()
        _cleanup_lock.release()


def verify_signature(body: bytes, x_timestamp: str, x_signature: str) -> None:
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=401, detail="missing auth headers")
    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="bad timestamp")
    now = int(time.time())
    if abs(now - ts) > 300:
        raise HTTPException(status_code=401, detail="stale timestamp")

    digest = hmac.new(SHARED_SECRET.encode(), body + x_timestamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest, x_signature):
        raise HTTPException(status_code=401, detail="bad signature")


def signed_json_response(payload: Dict[str, Any], request_timestamp: str, status_code: int = 200) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    signature = hmac.new(
        SHARED_SECRET.encode(), body + request_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return Response(
        content=body,
        status_code=status_code,
        media_type="application/json",
        headers={"X-Narwhal-Response-Signature": signature, "Cache-Control": "no-store"},
    )


@app.get("/api/v1/tls/ca")
def tls_ca(
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    """Return the public internal-CA certificate with an authenticated response."""
    verify_signature(b"", x_timestamp, x_signature)
    try:
        with open(TLS_CA_CERT_PATH, "rb") as ca_file:
            certificate = ca_file.read(65537)
    except OSError:
        raise HTTPException(status_code=503, detail="internal TLS CA is not available")
    if len(certificate) > 65536 or not certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise HTTPException(status_code=500, detail="invalid internal TLS CA certificate")
    response_signature = hmac.new(
        SHARED_SECRET.encode(), certificate + x_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return Response(
        content=certificate,
        media_type="application/x-pem-file",
        headers={
            "Cache-Control": "no-store",
            "X-Narwhal-CA-Signature": response_signature,
        },
    )


_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
_ACTIONABLE_ALERT_TYPES = {
    "unauthorized_panel_pairing",
    "socks_weak_auth",
    "malicious_process",
}


def _alert_fingerprint(host_id: str, alert: Dict[str, Any]) -> str:
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
    if alert.get('type') == 'prohibited_activity':
        parts.append(str(alert.get('instance_id') or ''))
    if str(alert.get("type") or "") == "unauthorized_panel_pairing":
        domains = alert.get("unapproved_domains")
        domain_values = [
            str(item).strip().lower().rstrip(".")
            for item in domains if isinstance(item, str) and item.strip()
        ] if isinstance(domains, list) else []
        if not domain_values:
            match = re.search(r"未授权面板域名\s*([^；;]+)", str(alert.get("message") or ""))
            domain_values = [
                item.strip().lower().rstrip(".")
                for item in (match.group(1).split(",") if match else []) if item.strip()
            ]
        parts.append(",".join(sorted(set(domain_values))))
    identity = "|".join(parts)
    return hashlib.sha256(identity.encode()).hexdigest()


def process_security_alerts(
    conn: sqlite3.Connection,
    host_id: str,
    ts: int,
    alerts: List[Dict[str, Any]],
    partial: bool = False,
    preserve_active_types: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    active_fingerprints: List[str] = []
    notifications: List[Dict[str, Any]] = []
    for raw_alert in alerts:
        if not isinstance(raw_alert, dict):
            continue
        alert_type = str(raw_alert.get("type") or "unknown")[:80]
        if alert_type == "ops_traffic_quota":
            continue  # Usage accounting remains available; never notify quota usage.
        if alert_type == "admission_unverified":
            # The current protection state is delivered separately through
            # /api/v1/admission/status and rendered on each container. It is
            # not a security incident and should not create active alerts.
            continue
        severity = str(raw_alert.get("severity") or "warning").lower()
        if severity not in _SEVERITY_RANK:
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
        fingerprint_source['instance_id'] = raw_alert.get('instance_id')
        fingerprint_source["alert_key"] = raw_alert.get("alert_key")
        fingerprint = _alert_fingerprint(host_id, fingerprint_source)
        active_fingerprints.append(fingerprint)
        existing = conn.execute(
            "SELECT id, status, severity, occurrence_count,details_json FROM security_alerts WHERE fingerprint=?",
            (fingerprint,),
        ).fetchone()
        allow_policy = conn.execute(
            "SELECT 1 FROM security_alert_policies WHERE fingerprint=? AND mode='allow_silent'",
            (fingerprint,),
        ).fetchone() is not None
        automatic_remediation = raw_alert.get("automatic_remediation")
        ongoing_protection = raw_alert.get("ongoing_protection") is True
        automatically_remediated = (
            isinstance(automatic_remediation, dict)
            and automatic_remediation.get("attempted") is True
            and automatic_remediation.get("succeeded") is True
            and not ongoing_protection
        )
        next_status = (
            "suppressed" if allow_policy
            else "remediated" if automatically_remediated
            else "active"
        )
        should_notify = existing is None and not allow_policy and not automatically_remediated
        if existing is not None:
            previous_status = str(existing["status"])
            verification = conn.execute("SELECT state FROM buyer_checks WHERE alert_id=?", (existing["id"],)).fetchone()
            restart_episode = previous_status == "resolved" or (previous_status == "remediated" and (next_status == "active" or (verification and verification[0] == "verified")))
            if allow_policy:
                should_notify = False
            elif automatically_remediated:
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
                should_notify = previous_status == "resolved" or _SEVERITY_RANK[severity] > _SEVERITY_RANK.get(str(existing["severity"]), 0)
                previous_details = _alert_details(existing["details_json"])
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
                if alert_type == 'container_connection_count':
                    was_escalated = _alert_details(existing['details_json']).get('connection_policy', {}).get('escalated')
                    should_notify = should_notify or bool(raw_alert.get('connection_policy', {}).get('escalated') and not was_escalated)
                if alert_type in {"cpu_pressure_protection", "io_pressure_protection"}:
                    previous_details = _alert_details(existing["details_json"])
                    guard_key = "cpu_guard" if alert_type == "cpu_pressure_protection" else "io_guard"
                    try:
                        previous_tier = int((previous_details.get(guard_key) or {}).get("tier") or 0)
                        current_tier = int((raw_alert.get(guard_key) or {}).get("tier") or 0)
                    except (TypeError, ValueError, OverflowError):
                        previous_tier = current_tier = 0
                    if current_tier > previous_tier and current_tier > 1:
                        should_notify = True
                if alert_type in {"host_vulnerability", "host_security_finding"}:
                    previous_details = _alert_details(existing["details_json"])
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
    preserve_types = sorted({
        str(item).strip()[:80] for item in (preserve_active_types or []) if str(item).strip()
    })
    if preserve_types:
        placeholders = ",".join("?" for _ in preserve_types)
        preserved = conn.execute(
            f"SELECT fingerprint FROM security_alerts WHERE host_id=? AND alert_type IN ({placeholders}) AND status IN ('active','dismissed')",
            (host_id, *preserve_types),
        ).fetchall()
        active_fingerprints.extend(str(row["fingerprint"]) for row in preserved)
    pending_network_review = "NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.alert_id=security_alerts.id AND q.status<>'released')"
    if active_fingerprints:
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


def queue_connection_alert_deep_samples(
    conn: sqlite3.Connection, host_id: str, now: int
) -> int:
    """Refresh bounded connection evidence for connection and inbound-fanout alerts."""
    queued = 0
    alerts = conn.execute(
        """
        SELECT * FROM security_alerts
        WHERE host_id=? AND alert_type IN (
              'container_connection_count','inbound_ip_fanout','socks_inbound_fanout'
          )
          AND status='active' AND last_seen=?
        """,
        (host_id, now),
    ).fetchall()
    for alert in alerts:
        if queued >= 10:
            break  # Avoid a large incident fan-out starving the report transaction.
        if str(alert["runtime"]) not in ("incus", "podman"):
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
        stage = str(alert['alert_type']) + ':' + str(alert['severity']) + (
            ':escalated'
            if _alert_details(alert['details_json']).get('connection_policy', {}).get('escalated')
            else ''
        )
        if existing is not None:
            previous_params = _alert_details(existing['params_json'])
            if existing['status'] in ('queued', 'dispatched', 'running'):
                if now - int(existing['created_at']) > 900:
                    conn.execute("UPDATE security_actions SET status='failed',result_message='深度取证等待超过15分钟，需要重新采样',updated_at=? WHERE id=?", (now, existing['id']))
                continue
            if now - int(existing['created_at']) < 900 and (previous_params.get('stage') == stage or existing['status'] == 'failed'):
                continue
        conn.execute(
            """
            INSERT INTO security_actions(
                alert_id,host_id,runtime,project,container_name,action_type,params_json,
                status,requested_by,created_at,updated_at
            ) VALUES(?,?,?,?,?,? ,?,'queued','automatic:connection-alert',?,?)
            """,
            (
                alert_id, str(alert["host_id"]), str(alert["runtime"]),
                str(alert["project"]), str(alert["container_name"]), "request_deep_sample",
                json.dumps({"sample_seconds": 1.0, "process_limit": 100, "socket_limit": 250, "evidence_schema": 5, 'stage': stage}),
                now, now,
            ),
        )
        queued += 1
    return queued


def send_alert_webhook(alert: Dict[str, Any]) -> None:
    if not ALERT_WEBHOOK_URL:
        return
    severity = str(alert.get("severity") or "warning")
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK.get(ALERT_WEBHOOK_MIN_SEVERITY, 1):
        return
    payload = json.dumps({"event": "narwhal.security_alert", "alert": alert}, ensure_ascii=False).encode()
    request = urllib.request.Request(
        ALERT_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read(1)
    except Exception as exc:
        print(f"alert webhook failed: {exc}")


def _notification_bot_item(row: sqlite3.Row) -> Dict[str, Any]:
    """Return a dashboard-safe notification profile; bot tokens never leave the server."""
    return {
        "id": int(row["id"]), "name": str(row["name"]), "kind": str(row["kind"]),
        "target": str(row["target"]), "min_severity": str(row["min_severity"]),
        "enabled": bool(row["enabled"]), "token_configured": bool(row["token"]),
        "created_at_utc8": format_utc8(int(row["created_at"])),
        "updated_at_utc8": format_utc8(int(row["updated_at"])),
        "last_delivery_status": str(row["last_delivery_status"]),
        "last_delivery_error": str(row["last_delivery_error"]),
        "last_sent_at_utc8": format_utc8(int(row["last_sent_at"])) if int(row["last_sent_at"]) else "",
    }


def _telegram_api_call(token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode()
    proxy_url = get_telegram_proxy_url()
    proxy_scheme = urllib.parse.urlsplit(proxy_url).scheme.lower() if proxy_url else ""
    if proxy_scheme in ("socks5", "socks5h"):
        try:
            result = _telegram_api_socks5(token, method, data, proxy_url)
        except Exception as exc:
            raise RuntimeError(f"Telegram SOCKS5 代理连接失败：{exc}") from exc
        if not result.get("ok"):
            raise RuntimeError(str(result.get("description") or "Telegram rejected the request"))
        return result
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
        method="POST",
    )
    try:
        if proxy_url:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
            response_context = opener.open(request, timeout=10)
        else:
            response_context = urllib.request.urlopen(request, timeout=10)
        with response_context as response:
            result = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read(1024 * 1024).decode("utf-8")).get("description")
        except Exception:
            detail = ""
        raise RuntimeError(str(detail or f"Telegram HTTP {exc.code}")) from exc
    except urllib.error.URLError as exc:
        if proxy_url:
            raise RuntimeError(f"Telegram 代理连接失败：{exc.reason}") from exc
        try:
            result = _telegram_api_ipv4(token, method, data)
        except Exception as ipv4_exc:
            raise RuntimeError(
                f"Telegram 网络不可达（常规连接：{exc.reason}；IPv4 回退：{ipv4_exc}）。"
                "请检查 Server 容器出站网络，或配置 TELEGRAM_PROXY_URL。"
            ) from ipv4_exc
    if not result.get("ok"):
        raise RuntimeError(str(result.get("description") or "Telegram rejected the request"))
    return result


def _telegram_api(token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return _telegram_api_call(token, method, payload)
    except RuntimeError as exc:
        err_msg = str(exc).lower()
        if ("can't parse entities" in err_msg or "entity" in err_msg) and payload.get("parse_mode"):
            fallback_payload = dict(payload)
            fallback_payload.pop("parse_mode", None)
            raw_text = str(fallback_payload.get("text") or "")
            fallback_payload["text"] = re.sub(r"<[^>]+>", "", raw_text)
            try:
                return _telegram_api_call(token, method, fallback_payload)
            except Exception:
                pass
        raise


def _telegram_api_socks5(token: str, method: str, data: bytes, proxy_url: str) -> Dict[str, Any]:
    if socks is None:
        raise RuntimeError("PySocks 未安装，无法使用 SOCKS5 代理。请运行 pip install PySocks 或配置 HTTP/HTTPS 代理。")
    parsed = urllib.parse.urlsplit(proxy_url)
    if not parsed.hostname:
        raise ValueError("代理地址缺少主机名")
    proxy_rdns = True
    proxy_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        proxy_sock.set_proxy(
            socks.SOCKS5,
            parsed.hostname,
            parsed.port or 1080,
            rdns=proxy_rdns,
            username=urllib.parse.unquote(parsed.username) if parsed.username else None,
            password=urllib.parse.unquote(parsed.password) if parsed.password else None,
        )
        proxy_sock.settimeout(10)
        proxy_sock.connect(("api.telegram.org", 443))
        tls_sock = ssl.create_default_context().wrap_socket(proxy_sock, server_hostname="api.telegram.org")
        conn = http.client.HTTPSConnection("api.telegram.org", 443, timeout=10)
        conn.sock = tls_sock
        conn.request(
            "POST", f"/bot{token}/{method}", body=data,
            headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
        )
        response = conn.getresponse()
        body = response.read(1024 * 1024)
        conn.close()
        result = json.loads(body.decode("utf-8"))
        if response.status >= 400:
            raise RuntimeError(str(result.get("description") or f"Telegram HTTP {response.status}"))
        return result
    except Exception:
        try:
            proxy_sock.close()
        except Exception:
            pass
        raise


def _telegram_api_ipv4(token: str, method: str, data: bytes) -> Dict[str, Any]:
    host = "api.telegram.org"
    last_error: Exception | None = None
    for family, socktype, proto, _, sockaddr in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
        raw_sock = socket.socket(family, socktype, proto)
        try:
            raw_sock.settimeout(8)
            raw_sock.connect(sockaddr)
            tls_sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
            conn = http.client.HTTPSConnection(host, 443, timeout=8)
            conn.sock = tls_sock
            conn.request(
                "POST", f"/bot{token}/{method}", body=data,
                headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
            )
            response = conn.getresponse()
            body = response.read(1024 * 1024)
            conn.close()
            result = json.loads(body.decode("utf-8"))
            if response.status >= 400:
                raise RuntimeError(str(result.get("description") or f"Telegram HTTP {response.status}"))
            return result
        except Exception as exc:
            last_error = exc
            try:
                raw_sock.close()
            except Exception:
                pass
    raise RuntimeError(str(last_error or "没有可用的 Telegram IPv4 地址"))


def _record_bot_delivery(bot_id: int, succeeded: bool, error: str = "") -> None:
    conn = db()
    try:
        conn.execute(
            "UPDATE notification_bots SET last_delivery_status=?, last_delivery_error=?, last_sent_at=? WHERE id=?",
            ("succeeded" if succeeded else "failed", "" if succeeded else str(error)[:1000], int(time.time()) if succeeded else 0, bot_id),
        )
        conn.commit()
    finally:
        conn.close()


def _telegram_chat_allowed(bot: sqlite3.Row, chat: Dict[str, Any]) -> bool:
    target, _ = _parse_telegram_target(str(bot["target"] or "").strip())
    chat_id = str(chat.get("id") or "")
    username = str(chat.get("username") or "").strip().lower()
    if target.startswith("@"):
        return bool(username) and username == target[1:].lower()
    return bool(chat_id) and hmac.compare_digest(chat_id, target)


def _telegram_active_alerts(severity: str = "all", offset: int = 0, limit: int = 5) -> tuple[List[sqlite3.Row], int]:
    conn = db()
    try:
        where = "status='active'"
        params: List[Any] = []
        if severity in ("critical", "warning", "info"):
            where += " AND severity=?"
            params.append(severity)
        total = int(conn.execute(f"SELECT COUNT(*) FROM security_alerts WHERE {where}", params).fetchone()[0])
        rows = conn.execute(
            f"SELECT * FROM security_alerts WHERE {where} ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END DESC, last_seen DESC LIMIT ? OFFSET ?",
            (*params, limit, max(0, offset)),
        ).fetchall()
        return rows, total
    finally:
        conn.close()


def _telegram_actionable(alert: sqlite3.Row) -> bool:
    if alert["runtime"] not in ("podman", "incus"):
        return False
    if alert["alert_type"] not in ("unauthorized_panel_pairing", "socks_weak_auth", "malicious_process"):
        return False
    details = _alert_action_evidence(alert)
    if alert["alert_type"] == "unauthorized_panel_pairing":
        return bool(details.get("process_patterns") or details.get("config_files"))
    if alert["alert_type"] == "socks_weak_auth":
        return details.get("socks_auth_mode") in ("no_auth", "weak_password") and bool(details.get("socks_processes"))
    return any(isinstance(item, dict) and item.get("process") == "xmrig" for item in details.get("malicious_processes", []))


def _telegram_menu() -> tuple[str, Dict[str, Any]]:
    conn = db()
    try:
        counts = {row["severity"]: int(row["count"]) for row in conn.execute(
            "SELECT severity, COUNT(*) AS count FROM security_alerts WHERE status='active' GROUP BY severity"
        ).fetchall()}
    finally:
        conn.close()
    total = sum(counts.values())
    text = (
        "<b>Narwhal 告警控制台</b>\n"
        f"活动告警：<b>{total}</b>\n"
        f"严重：<b>{counts.get('critical', 0)}</b>　警告：<b>{counts.get('warning', 0)}</b>　信息：<b>{counts.get('info', 0)}</b>\n\n"
        "请选择要查看的范围。"
    )
    keyboard = {"inline_keyboard": [
        [{"text": f"全部活动告警 ({total})", "callback_data": "n:l:all:0"}],
        [
            {"text": f"严重 ({counts.get('critical', 0)})", "callback_data": "n:l:critical:0"},
            {"text": f"警告 ({counts.get('warning', 0)})", "callback_data": "n:l:warning:0"},
        ],
        [{"text": "刷新", "callback_data": "n:m"}],
    ]}
    return text, keyboard


def _telegram_alert_list(severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    severity = severity if severity in ("all", "critical", "warning", "info") else "all"
    offset = max(0, offset)
    rows, total = _telegram_active_alerts(severity, offset)
    label = {"all": "全部", "critical": "严重", "warning": "警告", "info": "信息"}[severity]
    text = f"<b>{label}活动告警</b>\n共 {total} 条，第 {offset + 1 if total else 0}-{min(offset + len(rows), total)} 条。"
    buttons: List[List[Dict[str, str]]] = []
    severity_label = {"critical": "严重", "warning": "警告", "info": "信息"}
    for row in rows:
        title = str(row["title"] or row["alert_type"] or "告警")
        buttons.append([{"text": f"{severity_label.get(row['severity'], '告警')} #{row['id']} {title[:26]}", "callback_data": f"n:d:{row['id']}:{severity}:{offset}"}])
    nav: List[Dict[str, str]] = []
    if offset > 0:
        nav.append({"text": "上一页", "callback_data": f"n:l:{severity}:{max(0, offset - 5)}"})
    if offset + len(rows) < total:
        nav.append({"text": "下一页", "callback_data": f"n:l:{severity}:{offset + 5}"})
    if nav:
        buttons.append(nav)
    buttons.append([{"text": "刷新", "callback_data": f"n:l:{severity}:{offset}"}, {"text": "返回主菜单", "callback_data": "n:m"}])
    return text, {"inline_keyboard": buttons}


def _telegram_alert_detail(alert_id: int, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    conn = db()
    try:
        alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
    finally:
        conn.close()
    if alert is None:
        return "该告警不存在或已被清理。", {"inline_keyboard": [[{"text": "返回列表", "callback_data": f"n:l:{severity}:{offset}"}]]}
    scope = "/".join(x for x in (str(alert["runtime"] or ""), str(alert["project"] or "")) if x) or "-"
    raw_message = str(alert['message'] or '')[:1000]
    text = (
        f"<b>{html.escape(str(alert['title'] or alert['alert_type']))}</b>\n"
        f"事件：<code>NW-{alert['id']}-{alert['first_seen']}</code>\n"
        f"状态：<b>{html.escape(str(alert['status']))}</b>　级别：<b>{html.escape(str(alert['severity']))}</b>\n"
        f"主机：<code>{html.escape(str(alert['host_id']))}</code>\n"
        f"容器：<code>{html.escape(scope)} {html.escape(str(alert['container_name'] or '-'))}</code>\n"
        f"出现次数：{int(alert['occurrence_count'])}\n"
        f"最近出现：{format_utc8(int(alert['last_seen']))}\n\n"
        f"{html.escape(raw_message)}"
    )
    buttons: List[List[Dict[str, str]]] = []
    if alert['alert_type'] == 'prohibited_activity':
        text += '\n\n请先通过宿主机控制台排查，再由网页管理员复核解除隔离。解除不等于风险已恢复。'
        if PUBLIC_BASE_URL:
            buttons.append([{'text': '打开管理员隔离面板', 'url': PUBLIC_BASE_URL.rstrip('/')+'/'}])
    elif alert["status"] == "active":
        buttons.append([
            {"text": "本次忽略", "callback_data": f"n:c:{alert_id}:dismiss_once:{severity}:{offset}"},
            {"text": "标记已处理", "callback_data": f"n:c:{alert_id}:resolve:{severity}:{offset}"},
        ])
        buttons.append([{"text": "永久不再提醒", "callback_data": f"n:c:{alert_id}:allow_silent:{severity}:{offset}"}])
        if _telegram_actionable(alert):
            buttons.append([{"text": "定向处置", "callback_data": f"n:c:{alert_id}:deny:{severity}:{offset}"}])
    buttons.append([{"text": "返回列表", "callback_data": f"n:l:{severity}:{offset}"}, {"text": "主菜单", "callback_data": "n:m"}])
    return text, {"inline_keyboard": buttons}


async def _telegram_apply_decision(alert_id: int, decision: str, bot_id: int) -> str:
    class TelegramRequest:
        def __init__(self) -> None:
            self.state = type("State", (), {"dashboard_user": f"telegram:{bot_id}"})()
        async def json(self) -> Dict[str, str]:
            return {"decision": decision}
    response = await set_security_alert_disposition(alert_id, TelegramRequest())
    body = json.loads(response.body)
    if decision == "deny":
        return "定向处置已排队，等待节点执行。" if body.get("queued") else "已有相同处置正在执行。"
    return {"dismiss_once": "已忽略本次告警。", "resolve": "已标记为已处理。", "allow_silent": "已设置为永久不再提醒。"}.get(decision, "处理完成。")


def _telegram_confirm(alert_id: int, decision: str, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    descriptions = {
        "dismiss_once": "只隐藏本次连续事件；以后再次发生仍会提醒。",
        "resolve": "将当前记录标记为已处理；若风险仍存在，下次上报会重新出现。",
        "allow_silent": "永久抑制此告警指纹，并可能同步放行节点策略。",
        "deny": "向节点下发定向处置动作，仅处理告警明确识别的目标。",
    }
    text = f"<b>确认操作</b>\n告警 #{alert_id}\n\n{descriptions.get(decision, '确认执行此操作？')}"
    keyboard = {"inline_keyboard": [
        [{"text": "确认执行", "callback_data": f"n:x:{alert_id}:{decision}:{severity}:{offset}"}],
        [{"text": "取消并返回", "callback_data": f"n:d:{alert_id}:{severity}:{offset}"}],
    ]}
    return text, keyboard


def _telegram_send_view(bot: sqlite3.Row, update: Dict[str, Any], text: str, keyboard: Dict[str, Any]) -> None:
    callback = update.get("callback_query") if isinstance(update.get("callback_query"), dict) else None
    message = callback.get("message") if callback and isinstance(callback.get("message"), dict) else None
    if message:
        try:
            _telegram_api(str(bot["token"]), "editMessageText", {
                "chat_id": str(message.get("chat", {}).get("id")), "message_id": int(message.get("message_id") or 0),
                "text": text, "parse_mode": "HTML", "reply_markup": keyboard, "disable_web_page_preview": True,
            })
        except RuntimeError as exc:
            # Refreshing an unchanged view is successful from the user's point of view.
            if "message is not modified" not in str(exc).lower():
                raise
    else:
        incoming = update.get("message") if isinstance(update.get("message"), dict) else {}
        _telegram_api(str(bot["token"]), "sendMessage", {
            "chat_id": str(incoming.get("chat", {}).get("id")), "text": text,
            "parse_mode": "HTML", "reply_markup": keyboard, "disable_web_page_preview": True,
        })


async def _handle_telegram_update(bot: sqlite3.Row, update: Dict[str, Any]) -> None:
    callback = update.get("callback_query") if isinstance(update.get("callback_query"), dict) else None
    message = callback.get("message") if callback and isinstance(callback.get("message"), dict) else update.get("message")
    if not isinstance(message, dict) or not _telegram_chat_allowed(bot, message.get("chat") or {}):
        if callback:
            _telegram_api(str(bot["token"]), "answerCallbackQuery", {"callback_query_id": str(callback.get("id") or ""), "text": "此聊天未获授权"})
        return
    if callback:
        data = str(callback.get("data") or "")
        legacy = re.fullmatch(r"narwhal:(\d+):(dismiss|resolve)", data)
        if legacy:
            decision = "dismiss_once" if legacy.group(2) == "dismiss" else "resolve"
            try:
                message_text = await _telegram_apply_decision(int(legacy.group(1)), decision, int(bot["id"]))
            except HTTPException as exc:
                message_text = str(exc.detail)
            _telegram_api(str(bot["token"]), "answerCallbackQuery", {"callback_query_id": str(callback.get("id") or ""), "text": message_text[:180]})
            return
        parts = data.split(":")
        try:
            if data == "n:m":
                text, keyboard = _telegram_menu()
            elif len(parts) == 4 and parts[:2] == ["n", "l"]:
                text, keyboard = _telegram_alert_list(parts[2], int(parts[3]))
            elif len(parts) == 5 and parts[:2] == ["n", "d"]:
                text, keyboard = _telegram_alert_detail(int(parts[2]), parts[3], int(parts[4]))
            elif len(parts) == 6 and parts[:2] == ["n", "c"]:
                text, keyboard = _telegram_confirm(int(parts[2]), parts[3], parts[4], int(parts[5]))
            elif len(parts) == 6 and parts[:2] == ["n", "x"]:
                result = await _telegram_apply_decision(int(parts[2]), parts[3], int(bot["id"]))
                detail, keyboard = _telegram_alert_detail(int(parts[2]), parts[4], int(parts[5]))
                text = f"<b>{html.escape(result)}</b>\n\n{detail}"
            else:
                text, keyboard = _telegram_menu()
            _telegram_send_view(bot, update, text, keyboard)
            _telegram_api(str(bot["token"]), "answerCallbackQuery", {"callback_query_id": str(callback.get("id") or "")})
        except (ValueError, HTTPException, RuntimeError) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            _telegram_api(str(bot["token"]), "answerCallbackQuery", {"callback_query_id": str(callback.get("id") or ""), "text": str(detail)[:180], "show_alert": True})
        return
    command = str(message.get("text") or "").split()[0].split("@", 1)[0].lower()
    if command in ("/start", "/menu", "/alerts"):
        text, keyboard = _telegram_menu() if command != "/alerts" else _telegram_alert_list("all", 0)
        _telegram_send_view(bot, update, text, keyboard)


async def _telegram_polling_loop() -> None:
    await asyncio.sleep(5)
    while True:
        if PUBLIC_BASE_URL:
            await asyncio.sleep(30)
            continue
        conn = db()
        try:
            bots = conn.execute("SELECT * FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
        finally:
            conn.close()
        for bot in bots:
            bot_id = int(bot["id"])
            try:
                if bot_id not in _telegram_poll_offsets:
                    await asyncio.to_thread(_telegram_api, str(bot["token"]), "deleteWebhook", {"drop_pending_updates": True})
                    await asyncio.to_thread(_telegram_api, str(bot["token"]), "setMyCommands", {"commands": [
                        {"command": "menu", "description": "打开交互式告警控制台"},
                        {"command": "alerts", "description": "查看活动告警"},
                    ]})
                    _telegram_poll_offsets[bot_id] = 0
                result = await asyncio.to_thread(_telegram_api, str(bot["token"]), "getUpdates", {
                    "offset": _telegram_poll_offsets[bot_id], "timeout": 0,
                    "allowed_updates": ["message", "callback_query"], "limit": 20,
                })
                for update in result.get("result") or []:
                    _telegram_poll_offsets[bot_id] = max(_telegram_poll_offsets[bot_id], int(update.get("update_id") or 0) + 1)
                    await _handle_telegram_update(bot, update)
            except Exception as exc:
                print(f"Telegram polling warning (bot {bot_id}): {exc}")
        await asyncio.sleep(3)


def _telegram_duration_text(seconds: int) -> str:
    seconds = max(0, seconds)
    if seconds < 60:
        return "不足 1 分钟"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} 分钟"
    hours, remaining = divmod(minutes, 60)
    return f"{hours} 小时 {remaining} 分钟" if remaining else f"{hours} 小时"


def _telegram_alert_status_card(
    alert: sqlite3.Row, now: int, deep_evidence: Dict[str, Any] | None = None
) -> tuple[str, Dict[str, Any]]:
    status = str(alert["status"])
    active = status == "active"
    duration_end = now if active else int(alert["last_seen"])
    duration = _telegram_duration_text(duration_end - int(alert["first_seen"]))
    scope = "/".join(x for x in (str(alert["runtime"] or ""), str(alert["project"] or "")) if x)
    container_label = f"{scope or '-'} {alert['container_name'] or '-'}"
    if active:
        heading = f"Narwhal {str(alert['severity']).upper()} 告警"
        state_line = f"状态：<b>持续中</b>　持续：<b>{duration}</b>"
    else:
        state_labels = {
            "resolved": "已恢复", "dismissed": "已忽略",
            "suppressed": "已永久静默", "remediated": "已自动处置",
        }
        heading = f"Narwhal 告警{state_labels.get(status, '已结束')}"
        state_line = f"状态：<b>{state_labels.get(status, '已结束')}</b>　持续：<b>{duration}</b>"
    details = _alert_details(alert["details_json"])
    if alert['alert_type'] == 'container_connection_count':
        state_line = state_line.replace('持续：', '事件跨度：')
    automatic_remediation = details.get("automatic_remediation") if isinstance(details, dict) else None
    remediation_text = ""
    if alert['alert_type'] == 'prohibited_activity':
        network_state = str((details.get('network_quarantine') or {}).get('status') or 'unknown')
        heading = 'Narwhal 严重安全告警 · 违规活动'
        states = {'isolated':'已双向隔离，等待管理员复核', 'failed':'隔离未能完整验证，需立即人工处理',
                  'release_failed':'解除隔离未验证成功，需人工检查', 'released':'管理员已解除隔离，正在重新监测（非恢复证明）'}
        state_line = '状态：<b>'+states.get(network_state, '当前隔离状态待确认')+'</b>'
        proofs = []
        for item in (details.get('abuse_evidence') or [])[:5]:
            if not isinstance(item, dict):
                continue
            features = item.get('features') or {}
            proofs.append('PID '+str(item.get('pid') or '-')+' · 连续佐证 '+str(features.get('corroborating_samples') or '-')+' 次'
                          + (' · 工具 '+str(item['tool']) if item.get('tool') else '')
                          + (' · 并发配置 '+str(features['concurrency']) if features.get('concurrency') else '')
                          + (' · SYN 待连接 '+str(item['pending_attempts']) if item.get('pending_attempts') else '')
                          + (' · 纵向端口 '+str(item['vertical_ports']) if item.get('vertical_ports') else '')
                          + (' · 横向目标 '+str(item['horizontal_targets']) if item.get('horizontal_targets') else '')
                          + (' · 待连接占比 '+str(round(float(item.get('pending_ratio',item.get('failed_ratio',0)))*100))+'%' if item.get('pending_ratio') is not None or item.get('failed_ratio') is not None else '')
                          + (' · 文件 SHA256 '+str(item['source_sha256'])[:12] if item.get('source_sha256') else ''))
        remediation_text = '\n<b>特征证据</b>\n'+html.escape('\n'.join(proofs))+'\n<b>容器与磁盘保留；隔离会阻断 SSH，请通过宿主机控制台排查。</b>\n'
    if isinstance(automatic_remediation, dict) and automatic_remediation.get("attempted") is True:
        remediation_result = str(
            automatic_remediation.get("message")
            or automatic_remediation.get("result_message")
            or "节点已执行定向处置"
        )[:300]
        remediation_text = (
            "\n<b>自动处置</b>："
            f"<b>{'已完成' if automatic_remediation.get('succeeded') is True else '未完成'}</b>\n"
            f"{html.escape(remediation_result)}\n"
        )
    evidence_text = ""
    if isinstance(deep_evidence, dict):
        inbound_ips = int(deep_evidence.get("inbound_unique_ips") or 0)
        outbound_ips = int(deep_evidence.get("outbound_unique_ips") or 0)
        inbound_processes = int(deep_evidence.get("inbound_process_count") or 0)
        outbound_processes = int(deep_evidence.get("outbound_process_count") or 0)
        all_ips = deep_evidence.get("connection_ips") if isinstance(deep_evidence.get("connection_ips"), list) else []
        inbound_items = deep_evidence.get("inbound_ips") if isinstance(deep_evidence.get("inbound_ips"), list) else [
            item for item in all_ips if isinstance(item, dict) and int(item.get("inbound") or 0) > 0
        ]
        outbound_items = deep_evidence.get("outbound_ips") if isinstance(deep_evidence.get("outbound_ips"), list) else [
            item for item in all_ips if isinstance(item, dict) and int(item.get("outbound") or 0) > 0
        ]
        # Legacy counts may include private/proxy peers absent from public lists.
        inbound_ips = len(inbound_items)
        outbound_ips = len(outbound_items)
        captured = int(deep_evidence.get('sampled_at') or 0)
        age = max(0, now - captured) if captured else None
        evidence_time = datetime.fromtimestamp(captured, timezone(timedelta(hours=8))).strftime('%m-%d %H:%M:%S') if 0 < captured < 253402271999 else '时间未知'
        evidence_note = f'采集时间：{evidence_time}（UTC+8）；'
        evidence_note += '历史快照，已过期，不能代表当前状态。' if age is None or age > 900 else '近期快照，不代表完整流量。'
        if deep_evidence.get('socket_snapshot_truncated'):
            evidence_note += ' 明细已截断，仅展示部分连接和进程。'
        if not inbound_items and int(deep_evidence.get('observed_inbound_unique_ips', deep_evidence.get('inbound_unique_ips', 0)) or 0):
            evidence_note += ' 检测到入站来源，但公网源 IP 尚未映射。'
        def ip_lines(items: List[Dict[str, Any]], direction: str) -> str:
            """Telegram-friendly, one public endpoint per line, safely HTML escaped."""
            label = "入站连接" if direction == "inbound" else "出站连接"
            lines: List[str] = []
            for item in items[:10]:
                if not isinstance(item, dict) or not item.get("ip"):
                    continue
                location_parts = [
                    str(item.get(key) or "").strip()
                    for key in ("country", "region", "city")
                    if str(item.get(key) or "").strip()
                ]
                location = " ".join(location_parts) or "未知归属地"
                carrier = str(item.get("isp") or item.get("org") or item.get("asn") or "未知运营商")
                count = int(item.get(direction) or item.get("connections") or 0)
                lines.append(
                    f"<code>{html.escape(str(item['ip'])[:45])}</code> ｜归属地：{html.escape(location[:50])} ｜运营商：{html.escape(carrier[:50])} ｜{label}：{count}"
                )
            return "\n".join(lines) or "-"
        attribution = deep_evidence.get("connection_attribution")
        attribution_text = ""
        attribution_unavailable = not isinstance(attribution, dict)
        if isinstance(attribution, dict):
            captured_sockets = attribution.get("captured_sockets")
            try:
                expected_connections = max(
                    int(deep_evidence.get("connection_count") or 0),
                    int(attribution.get("expected_connection_count") or 0),
                )
                captured_count = int(captured_sockets or 0)
            except (TypeError, ValueError, OverflowError):
                expected_connections, captured_count = 0, 0
            attribution_unavailable = (
                attribution.get("evidence_status") == "unavailable"
                or captured_sockets is None
                or (expected_connections > 0 and captured_count == 0)
            )
            if attribution_unavailable:
                attribution_text = (
                    "\n<b>连接发起方核验（单次快照）</b>\n"
                    "未采集到逐连接来源/PID 数据，发起方向未知；不能把缺失数据当作 0 条。"
                )
            else:
                attribution_text = (
                    "\n<b>连接发起方核验（单次快照）</b>\n"
                    f"本机进程发起：已确认 {int(attribution.get('confirmed_local_initiated') or 0)} / 推定 {int(attribution.get('probable_local_initiated') or 0)}；"
                    f"外部远端发起：已确认 {int(attribution.get('confirmed_remote_initiated') or 0)} / 推定 {int(attribution.get('probable_remote_initiated') or 0)}；"
                    f"方向未知 {int(attribution.get('unknown_direction') or 0)}。"
                    f"PID 归属 {int(attribution.get('process_attributed_sockets') or 0)}/{captured_count} 条，"
                    f"conntrack 五元组匹配 {int(attribution.get('conntrack_confirmed_sockets') or 0)} 条。"
                )
            if not attribution.get("conntrack_available"):
                attribution_text += "\nconntrack 不可用；推定方向不能视为已确认。"
        signal_counts = {
            "possible_multiport_probe": 0,
            "bidirectional_tcp_observed": 0,
            "mixed_connection_evidence": 0,
            "unreplied_tcp_observed": 0,
        }
        probe_ips: List[str] = []
        for item in inbound_items:
            if not isinstance(item, dict):
                continue
            signal = item.get("network_evidence")
            if not isinstance(signal, dict):
                continue
            classification = str(signal.get("classification") or "")
            if classification in signal_counts:
                signal_counts[classification] += 1
                if classification == "possible_multiport_probe" and item.get("ip"):
                    probe_ips.append(str(item["ip"])[:45])
        signal_text = ""
        if any(signal_counts.values()):
            signal_text = (
                "\n<b>入站行为线索（非恶意定论）</b>："
                f"多端口探测迹象 {signal_counts['possible_multiport_probe']} IP"
                + (f"（{html.escape('、'.join(probe_ips[:3]))}）" if probe_ips else "")
                + f"；双向 TCP {signal_counts['bidirectional_tcp_observed']} IP；"
                + f"混合/未应答 {signal_counts['mixed_connection_evidence'] + signal_counts['unreplied_tcp_observed']} IP。"
                "这些只是单次 conntrack 传输线索，需结合应用访问日志判断是否为正常用户请求。"
            )
        inbound_ip_summary = "未采集" if attribution_unavailable and not inbound_items else str(inbound_ips)
        outbound_ip_summary = "未采集" if attribution_unavailable and not outbound_items else str(outbound_ips)
        inbound_process_summary = "未采集" if attribution_unavailable and not inbound_items else str(inbound_processes)
        outbound_process_summary = "未采集" if attribution_unavailable and not outbound_items else str(outbound_processes)
        evidence_text = (
            f"\n<b>自动深度取证</b>\n"
            f"{html.escape(evidence_note)}\n"
            f"入站：{inbound_ip_summary} IP / {inbound_process_summary} 进程\n"
            f"出站：{outbound_ip_summary} IP / {outbound_process_summary} 进程\n"
            f"{attribution_text}{signal_text}\n"
            f"<b>入站 IP（每行一个）</b>\n{ip_lines(inbound_items, 'inbound')}\n"
            f"<b>出站 IP（每行一个）</b>\n{ip_lines(outbound_items, 'outbound')}\n"
        )
    raw_msg = str(alert['message'] or '')[:400]
    msg_escaped = html.escape(raw_msg)
    if alert['alert_type'] == 'container_connection_count':
        msg_escaped += '\n' + html.escape(connection_policy.text(details.get('connection_policy')))
        metric = details.get('connection_metrics') or {}
        if metric.get('valid') is True:
            msg_escaped += html.escape(f"\nTCP已建立 {metric.get('tcp_established', 0)} · 待连接 {metric.get('tcp_pending', 0)} · TIME_WAIT {metric.get('tcp_time_wait', 0)} · UDP socket {metric.get('udp_sockets', 0)}")
    text = (
        f"<b>{heading}</b>\n"
        f"<b>{html.escape(str(alert['title'] or alert['alert_type'] or '-'))}</b>\n"
        f"{state_line}\n"
        f"主机：<code>{html.escape(str(alert['host_id'] or '-'))}</code>\n"
        f"容器：<code>{html.escape(container_label)}</code>\n"
        f"出现次数：{int(alert['occurrence_count'])}\n"
        f"{remediation_text}"
        f"{evidence_text}"
        f"{msg_escaped}"
    )
    keyboard = {"inline_keyboard": [[
        {"text": "查看并处理" if active else "查看历史", "callback_data": f"n:d:{alert['id']}:all:0"},
        {"text": "活动告警", "callback_data": "n:l:all:0"},
    ]]}
    return text, keyboard


def sync_configured_bot_alert_messages(
    host_id: str | None = None,
    observed_at: int | None = None,
    alert_id: int | None = None,
) -> None:
    """Create or refresh one Telegram status card per alert, retaining recovery history."""
    now = int(time.time())
    conn = db()
    try:
        bots = conn.execute("SELECT * FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
        if not bots:
            return
        if alert_id is not None:
            alerts = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchall()
        elif host_id is not None and observed_at is not None:
            alerts = conn.execute(
                "SELECT * FROM security_alerts WHERE host_id=? AND last_seen=? AND status IN ('active','resolved','dismissed','suppressed','remediated')",
                (host_id, observed_at),
            ).fetchall()
        elif host_id is not None:
            alerts = conn.execute(
                "SELECT * FROM security_alerts WHERE host_id=? AND status IN ('active','resolved','dismissed','suppressed','remediated') ORDER BY id DESC LIMIT 50",
                (host_id,),
            ).fetchall()
        else:
            alerts = []
        for bot in bots:
            bot_id = int(bot["id"])
            chat_target, thread_id = _parse_telegram_target(str(bot["target"] or ""))
            for alert in alerts:
                severity = str(alert["severity"])
                mapping = conn.execute(
                    "SELECT * FROM telegram_alert_messages WHERE bot_id=? AND alert_id=?",
                    (bot_id, int(alert["id"])),
                ).fetchone()
                # Automatic remediation is itself a security event worth
                # notifying: the operator needs the evidence and result even
                # though the alert is no longer active. Suppressed/dismissed
                # alerts are explicit user choices; a never-sent recovery is
                # only historical state and must not create a new message.
                pending_quarantine = alert['alert_type'] == 'prohibited_activity' and (_alert_details(alert['details_json']).get('network_quarantine') or {}).get('status') in {'isolated', 'failed', 'release_failed'}
                if mapping is None and str(alert["status"]) in ("suppressed", "dismissed", "resolved") and not pending_quarantine:
                    continue
                if mapping is None and _SEVERITY_RANK.get(severity, 1) < _SEVERITY_RANK.get(str(bot["min_severity"]), 2):
                    continue
                evidence_row = conn.execute(
                    "SELECT action_id,evidence_json FROM security_alert_evidence WHERE alert_id=? ORDER BY captured_at DESC,id DESC LIMIT 1",
                    (int(alert["id"]),),
                ).fetchone()
                deep_evidence = _alert_details(evidence_row["evidence_json"]) if evidence_row is not None else None
                evidence_action_id = int(evidence_row["action_id"]) if evidence_row is not None else 0
                text, keyboard = _telegram_alert_status_card(alert, now, deep_evidence)
                content_hash = hashlib.sha256((text + json.dumps(keyboard, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
                if mapping is not None:
                    status_changed = str(mapping["last_status"]) != str(alert["status"])
                    severity_changed = str(mapping["last_severity"]) != severity
                    evidence_changed = int(mapping["last_evidence_action_id"]) != evidence_action_id
                    if not status_changed and not severity_changed and not evidence_changed and now - int(mapping["updated_at"]) < 60:
                        continue
                    if str(mapping["content_hash"]) == content_hash:
                        continue
                try:
                    if mapping is None:
                        send_payload = {
                            "chat_id": chat_target, "text": text, "parse_mode": "HTML",
                            "reply_markup": keyboard, "disable_web_page_preview": True,
                        }
                        if thread_id is not None:
                            send_payload["message_thread_id"] = thread_id
                        result = _telegram_api(str(bot["token"]), "sendMessage", send_payload)
                        message_id = int((result.get("result") or {}).get("message_id") or 0)
                        if message_id <= 0:
                            raise RuntimeError("Telegram did not return a message id")
                        conn.execute(
                            "INSERT INTO telegram_alert_messages(bot_id,alert_id,chat_id,message_id,last_status,last_severity,last_evidence_action_id,content_hash,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                            (bot_id, int(alert["id"]), chat_target, message_id, str(alert["status"]), severity, evidence_action_id, content_hash, now),
                        )
                    else:
                        edit_chat_id, _ = _parse_telegram_target(str(mapping["chat_id"]))
                        try:
                            _telegram_api(str(bot["token"]), "editMessageText", {
                                "chat_id": edit_chat_id, "message_id": int(mapping["message_id"]),
                                "text": text, "parse_mode": "HTML", "reply_markup": keyboard,
                                "disable_web_page_preview": True,
                            })
                        except RuntimeError as edit_exc:
                            err_str = str(edit_exc).lower()
                            if "message is not modified" in err_str:
                                pass
                            elif "message to edit not found" in err_str or "message can't be edited" in err_str:
                                send_payload = {
                                    "chat_id": chat_target, "text": text, "parse_mode": "HTML",
                                    "reply_markup": keyboard, "disable_web_page_preview": True,
                                }
                                if thread_id is not None:
                                    send_payload["message_thread_id"] = thread_id
                                resend_res = _telegram_api(str(bot["token"]), "sendMessage", send_payload)
                                new_msg_id = int((resend_res.get("result") or {}).get("message_id") or 0)
                                if new_msg_id > 0:
                                    conn.execute(
                                        "UPDATE telegram_alert_messages SET message_id=?,chat_id=?,last_status=?,last_severity=?,last_evidence_action_id=?,content_hash=?,updated_at=? WHERE bot_id=? AND alert_id=?",
                                        (new_msg_id, chat_target, str(alert["status"]), severity, evidence_action_id, content_hash, now, bot_id, int(alert["id"])),
                                    )
                                    conn.commit()
                                    _record_bot_delivery(bot_id, True)
                                    continue
                            else:
                                raise
                        conn.execute(
                            "UPDATE telegram_alert_messages SET last_status=?,last_severity=?,last_evidence_action_id=?,content_hash=?,updated_at=? WHERE bot_id=? AND alert_id=?",
                            (str(alert["status"]), severity, evidence_action_id, content_hash, now, bot_id, int(alert["id"])),
                        )
                    conn.commit()
                    _record_bot_delivery(bot_id, True)
                except Exception as exc:
                    _record_bot_delivery(bot_id, False, str(exc))
                    print(f"telegram dynamic alert {bot_id}/{alert['id']} failed: {exc}")
    finally:
        conn.close()


@app.get("/api/v1/notifications/bots")
def notification_bots() -> JSONResponse:
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM notification_bots ORDER BY id DESC").fetchall()
        proxy_url = get_telegram_proxy_url()
        return JSONResponse(content={
            "items": [_notification_bot_item(row) for row in rows],
            "callback_ready": bool(PUBLIC_BASE_URL),
            "proxy_configured": bool(proxy_url),
            "proxy_scheme": urllib.parse.urlsplit(proxy_url).scheme.lower() if proxy_url else "",
        })
    finally:
        conn.close()


@app.post("/api/v1/notifications/bots")
async def save_notification_bot(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    name = str(payload.get("name") or "Telegram 通知").strip()[:80]
    token = _normalize_telegram_token(payload.get("token"))
    raw_target = str(payload.get("target") or "").strip()[:200]
    chat_target, target_thread_id = _parse_telegram_target(raw_target)
    severity = str(payload.get("min_severity") or "critical").lower()
    if not token or len(token) > 256 or not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token):
        raise HTTPException(status_code=400, detail="请输入有效的 Telegram Bot Token（格式如 123456789:ABCdef...）")
    if not raw_target or not chat_target or severity not in _SEVERITY_RANK:
        raise HTTPException(status_code=400, detail="目标（Chat ID 或 @频道）和最低告警级别是必填项")
    now = int(time.time())
    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO notification_bots(name,kind,token,target,min_severity,enabled,callback_secret,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?,?)",
            (name, "telegram", token, raw_target, severity, secrets.token_urlsafe(32), now, now),
        )
        bot_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
        conn.commit()
    finally:
        conn.close()
    try:
        send_payload = {
            "chat_id": chat_target,
            "text": "Narwhal 通知机器人已配置成功。后续将按设定的严重级别推送新告警。",
        }
        if target_thread_id is not None:
            send_payload["message_thread_id"] = target_thread_id
        _telegram_api(token, "sendMessage", send_payload)
        _record_bot_delivery(bot_id, True)
    except Exception as exc:
        conn = db()
        try:
            conn.execute("DELETE FROM notification_bots WHERE id=?", (bot_id,))
            conn.commit()
        finally:
            conn.close()
        raise HTTPException(status_code=502, detail=f"Telegram 配置验证失败：{exc}")
    callback_error = ""
    if PUBLIC_BASE_URL:
        try:
            _telegram_api(token, "setWebhook", {"url": f"{PUBLIC_BASE_URL}{_BOT_CALLBACK_PREFIX}{bot_id}/{row['callback_secret']}", "allowed_updates": ["message", "callback_query"]})
            _telegram_api(token, "setMyCommands", {"commands": [{"command": "menu", "description": "打开交互式告警控制台"}, {"command": "alerts", "description": "查看活动告警"}]})
        except Exception as exc:
            callback_error = str(exc)[:500]
    conn = db()
    try:
        row = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
        return JSONResponse(status_code=201, content={"item": _notification_bot_item(row), "callback_ready": bool(PUBLIC_BASE_URL) and not callback_error, "callback_error": callback_error})
    finally:
        conn.close()


@app.delete("/api/v1/notifications/bots/{bot_id}")
def delete_notification_bot(bot_id: int) -> JSONResponse:
    conn = db()
    try:
        cur = conn.execute("DELETE FROM notification_bots WHERE id=?", (bot_id,))
        conn.commit()
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="notification bot not found")
        return JSONResponse(content={"ok": True})
    finally:
        conn.close()


@app.post("/api/v1/notifications/bots/{bot_id}/test")
def test_notification_bot(bot_id: int) -> JSONResponse:
    conn = db()
    try:
        bot = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
    finally:
        conn.close()
    if bot is None:
        raise HTTPException(status_code=404, detail="notification bot not found")
    chat_target, target_thread_id = _parse_telegram_target(str(bot["target"] or ""))
    try:
        send_payload = {"chat_id": chat_target, "text": "Narwhal 通知机器人连接测试成功。"}
        if target_thread_id is not None:
            send_payload["message_thread_id"] = target_thread_id
        _telegram_api(str(bot["token"]), "sendMessage", send_payload)
        if PUBLIC_BASE_URL:
            _telegram_api(str(bot["token"]), "setWebhook", {"url": f"{PUBLIC_BASE_URL}{_BOT_CALLBACK_PREFIX}{bot_id}/{bot['callback_secret']}", "allowed_updates": ["message", "callback_query"]})
        _telegram_api(str(bot["token"]), "setMyCommands", {"commands": [{"command": "menu", "description": "打开交互式告警控制台"}, {"command": "alerts", "description": "查看活动告警"}]})
        _record_bot_delivery(bot_id, True)
    except Exception as exc:
        _record_bot_delivery(bot_id, False, str(exc))
        raise HTTPException(status_code=502, detail=f"Telegram 测试失败：{exc}")
    return JSONResponse(content={"ok": True, "callback_ready": bool(PUBLIC_BASE_URL)})


def _get_system_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    if row is not None and row["value"] is not None:
        return str(row["value"])
    return default


def _set_system_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    now = int(time.time())
    conn.execute(
        "INSERT OR REPLACE INTO system_settings(key, value, updated_at) VALUES(?,?,?)",
        (key, str(value), now),
    )


def _mask_secret(secret: str) -> str:
    s = (secret or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def format_buyer_notification(node_name: str, container_id: str, alert_issue: str) -> tuple[str, str]:
    subject = f"⚠️【节点安全告警】{node_name}"
    message = (
        f"🚨【容器安全告警】\n\n"
        f"📦 容器 ID ：{container_id}\n"
        f"⚠️ 异常问题：{alert_issue}\n\n"
        f"💡 处置提示：请及时登录排查。已记录日志，如有持续滥用会导致删鸡。"
    )
    return subject, message


@app.get("/api/v1/settings/push")
def get_push_settings() -> JSONResponse:
    conn = db()
    try:
        api_url = _get_system_setting(conn, "narwhal_api_url", os.getenv("NARWHAL_API_URL", "https://api.fuckip.me/api/v1"))
        stored_key = _get_system_setting(conn, "narwhal_api_key", os.getenv("NARWHAL_API_KEY", ""))
        machine_id = _get_system_setting(conn, "narwhal_machine_id", os.getenv("NARWHAL_MACHINE_ID", ""))
        node_name = _get_system_setting(conn, "narwhal_node_name", os.getenv("NARWHAL_NODE_NAME", ""))
        buyer_notify_val = _get_system_setting(conn, "buyer_notify_enabled", os.getenv("NARWHAL_BUYER_NOTIFY_ENABLED", "true"))
        buyer_notify_enabled = buyer_notify_val.strip().lower() not in ("0", "false", "no", "off")

        bots = conn.execute("SELECT * FROM notification_bots ORDER BY id DESC").fetchall()
        proxy_url = get_telegram_proxy_url()

        return JSONResponse(content={
            "narwhal_api_url": api_url,
            "narwhal_api_key_configured": bool(stored_key.strip()),
            "narwhal_api_key_masked": _mask_secret(stored_key),
            "narwhal_machine_id": machine_id,
            "narwhal_node_name": node_name,
            "buyer_notify_enabled": buyer_notify_enabled,
            "buyer_min_severity": buyer_notifications.setting(conn, "buyer_min_severity", "warning"),
            "buyer_recovery_enabled": buyer_notifications.setting(conn, "buyer_recovery_enabled", "true") == "true",
            "buyer_sender": "server",
            "telegram_bots_count": len(bots),
            "callback_ready": bool(PUBLIC_BASE_URL),
            "proxy_configured": bool(proxy_url),
            "proxy_scheme": urllib.parse.urlsplit(proxy_url).scheme.lower() if proxy_url else "",
        })
    finally:
        conn.close()


@app.post("/api/v1/settings/push")
async def save_push_settings(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be an object")

    conn = db()
    try:
        if "narwhal_api_url" in payload:
            url = str(payload["narwhal_api_url"] or "").strip().rstrip("/")
            try:
                buyer_notifications.validate_url(url)
            except ValueError as exc:
                raise HTTPException(400, str(exc))
            _set_system_setting(conn, "narwhal_api_url", url)

        if "narwhal_api_key" in payload:
            key = str(payload["narwhal_api_key"] or "").strip()
            # If user provided a new key and not the masked placeholder
            if key and not (key.startswith("sk_***") or "*" in key):
                _set_system_setting(conn, "narwhal_api_key", key)

        if "narwhal_machine_id" in payload:
            mid = str(payload["narwhal_machine_id"] or "").strip()
            _set_system_setting(conn, "narwhal_machine_id", mid)

        if "narwhal_node_name" in payload:
            nname = str(payload["narwhal_node_name"] or "").strip()
            _set_system_setting(conn, "narwhal_node_name", nname)

        if "buyer_notify_enabled" in payload:
            if type(payload["buyer_notify_enabled"]) is not bool:
                raise HTTPException(400, "buyer_notify_enabled 必须是布尔值")
            b_val = "true" if bool(payload["buyer_notify_enabled"]) else "false"
            _set_system_setting(conn, "buyer_notify_enabled", b_val)

        if "buyer_min_severity" in payload:
            if payload["buyer_min_severity"] not in ("warning", "critical"):
                raise HTTPException(400, "不支持的严重等级")
            _set_system_setting(conn, "buyer_min_severity", payload["buyer_min_severity"])
        if "buyer_recovery_enabled" in payload:
            if type(payload["buyer_recovery_enabled"]) is not bool:
                raise HTTPException(400, "buyer_recovery_enabled 必须是布尔值")
            _set_system_setting(conn, "buyer_recovery_enabled", str(payload["buyer_recovery_enabled"]).lower())

        conn.commit()
        return JSONResponse({"ok": True, "message": "推送与 API 设置已保存"})
    finally:
        conn.close()


@app.post("/api/v1/settings/push/test")
async def test_push_settings(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
        result = await asyncio.to_thread(buyer_notifications.test_notification, db, payload)
        return JSONResponse(result)
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/v1/notifications/telegram/{bot_id}/{callback_secret}")
async def telegram_callback(bot_id: int, callback_secret: str, request: Request) -> JSONResponse:
    conn = db()
    try:
        bot = conn.execute("SELECT * FROM notification_bots WHERE id=? AND callback_secret=? AND enabled=1", (bot_id, callback_secret)).fetchone()
        if bot is None:
            raise HTTPException(status_code=404, detail="unknown notification bot")
        payload = await request.json()
    finally:
        conn.close()
    if isinstance(payload, dict):
        await _handle_telegram_update(bot, payload)
    return JSONResponse(content={"ok": True})


def process_connection_overloads(
    conn: sqlite3.Connection,
    host_id: str,
    ts: int,
    containers: List[Dict[str, Any]],
) -> int:
    """Count only fresh, comparable samples; legacy agents remain alert-only."""
    return connection_policy.observe(conn, host_id, ts, containers,
        ALERT_CONN_CRITICAL_THRESHOLD, CONNECTION_STOP_THRESHOLD,
        CONNECTION_STOP_DURATION_SECONDS, CONNECTION_STOP_MAX_GAP_SECONDS,
        auto_stop=CONNECTION_AUTO_STOP_ENABLED, before_stop=buyer_notifications.connection_stop_gate)


_latest_cache: Dict[str, Any] | None = None
_latest_cache_time = 0.0
_security_status_cache: Dict[str, Any] | None = None
_security_status_cache_time = 0.0


def invalidate_security_status_cache() -> None:
    global _security_status_cache, _security_status_cache_time
    _security_status_cache = None
    _security_status_cache_time = 0.0


def _purge_host(conn: sqlite3.Connection, host_id: str) -> None:
    if conn.execute("SELECT 1 FROM network_quarantines WHERE host_id=? AND status<>'released' LIMIT 1", (host_id,)).fetchone():
        raise HTTPException(409, '存在待复核的网络隔离；请先核实并解除隔离，避免丢失恢复入口。')
    invalidate_security_status_cache()
    operations.purge_host(conn,host_id)
    conn.execute('DELETE FROM connection_windows WHERE host_id=?', (host_id,))
    investigation.purge_host(conn,host_id)
    conn.execute("DELETE FROM security_alert_decisions WHERE alert_id IN (SELECT id FROM security_alerts WHERE host_id=?)", (host_id,))
    conn.execute("DELETE FROM security_alert_evidence WHERE alert_id IN (SELECT id FROM security_alerts WHERE host_id=?)", (host_id,))
    conn.execute("DELETE FROM security_alert_policies WHERE fingerprint IN (SELECT fingerprint FROM security_alerts WHERE host_id=?)", (host_id,))
    for table in ("reports", "security_alerts", "host_security", "security_actions", "connection_overloads", "buyer_user_notices", "host_firewall_policies", "host_firewall_policy_history", "host_firewall_readbacks"):
        conn.execute(f"DELETE FROM {table} WHERE host_id=?", (host_id,))
    conn.execute("DELETE FROM hosts WHERE host_id=?", (host_id,))


def _validate_host_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {"host_id", "report_interval", "action_poll_interval", "container_runtimes", "docker_monitor_mode", "incus_project", "security_monitor_enabled", "security_access_log_paths"}
    config = {key: value for key, value in payload.items() if key in allowed}
    if not config:
        raise HTTPException(status_code=400, detail="没有可更新的配置")
    if "host_id" in config:
        value = str(config["host_id"]).strip()
        if not value or len(value) > 200 or any(char in value for char in "\r\n=\\\"'"):
            raise HTTPException(status_code=400, detail="主机名称无效")
        config["host_id"] = value
    for key, lower, upper in (("report_interval", 60, 3600), ("action_poll_interval", 5, 300)):
        if key in config:
            try:
                config[key] = int(config[key])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} 必须为整数")
            if not lower <= config[key] <= upper:
                raise HTTPException(status_code=400, detail=f"{key} 必须在 {lower}-{upper} 秒之间")
    if "container_runtimes" in config:
        value = str(config["container_runtimes"]).lower().replace(" ", "")
        if not value or any(item not in {"auto", "incus", "podman", "docker"} for item in value.split(",")):
            raise HTTPException(status_code=400, detail="运行时仅支持 auto/incus/podman/docker")
        config["container_runtimes"] = value
    if "docker_monitor_mode" in config:
        value = str(config["docker_monitor_mode"]).lower()
        if value not in {"notice", "full", "off"}:
            raise HTTPException(status_code=400, detail="Docker 模式仅支持 notice/full/off")
        config["docker_monitor_mode"] = value
    if "incus_project" in config:
        value = str(config["incus_project"]).strip()
        if len(value) > 100 or any(char in value for char in "\r\n=\\\"'"):
            raise HTTPException(status_code=400, detail="Incus 项目无效")
        config["incus_project"] = value or "all"
    if "security_monitor_enabled" in config:
        config["security_monitor_enabled"] = bool(config["security_monitor_enabled"])
    if "security_access_log_paths" in config:
        paths = config["security_access_log_paths"]
        if not isinstance(paths, list) or not 1 <= len(paths) <= 20 or any(not isinstance(p, str) or not re.fullmatch(r"/var/log/[A-Za-z0-9_./-]{1,200}", p) or ".." in p for p in paths):
            raise HTTPException(status_code=400, detail="日志路径必须是 /var/log 内的明确文件")
        config["security_access_log_paths"] = paths
    return config


def _validate_host_firewall_policy(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) - {"rules", "abuse"}:
        raise HTTPException(status_code=400, detail="防火墙配置只允许 rules 和 abuse 字段")
    raw_rules = payload.get("rules", [])
    if not isinstance(raw_rules, list) or len(raw_rules) > 64:
        raise HTTPException(status_code=400, detail="RFW 规则最多支持 64 条（受 eBPF 规则表容量限制）")
    protocols = {"all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto"}
    rules = []
    seen_keys = set()
    for index, raw in enumerate(raw_rules):
        allowed = {"key", "priority", "direction", "protocol", "action", "enabled", "port_start", "port_end", "ip_type", "ip", "countries"}
        if not isinstance(raw, dict) or set(raw) - allowed:
            raise HTTPException(status_code=400, detail=f"第 {index + 1} 条 RFW 规则字段无效")
        key = str(raw.get("key") or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", key) or key in seen_keys:
            raise HTTPException(status_code=400, detail=f"第 {index + 1} 条 RFW 规则标识无效或重复")
        seen_keys.add(key)
        direction = str(raw.get("direction") or "").lower()
        protocol = str(raw.get("protocol") or "").lower()
        action = str(raw.get("action") or "").lower()
        ip_type = str(raw.get("ip_type") or "").lower()
        if direction not in {"in", "out"} or protocol not in protocols or action not in {"block", "pass"}:
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的方向、协议或动作不支持")
        if direction == "out" and protocol not in {"all", "tcp", "udp", "socks", "fet", "wireguard", "mtproto"}:
            raise HTTPException(status_code=400, detail=f"RFW 协议 {protocol} 暂不支持出站匹配")
        priority = raw.get("priority")
        port_start = raw.get("port_start")
        port_end = raw.get("port_end")
        if type(priority) is not int or not 0 <= priority <= 100000:
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的优先级无效")
        if type(port_start) is not int or not 0 <= port_start <= 65535:
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的起始端口无效")
        if port_end is not None and (type(port_end) is not int or not port_start <= port_end <= 65535):
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的结束端口无效")
        if type(raw.get("enabled")) is not bool:
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的 enabled 必须是布尔值")
        if ip_type not in {"any", "cidr", "geoip"}:
            raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的 IP 匹配类型无效")
        rule = {
            "key": key,
            "priority": priority,
            "direction": direction,
            "protocol": protocol,
            "action": action,
            "enabled": raw["enabled"],
            "port_start": port_start,
            "ip_type": ip_type,
        }
        if port_end is not None:
            rule["port_end"] = port_end
        if ip_type == "cidr":
            try:
                rule["ip"] = str(ipaddress.ip_network(str(raw.get("ip") or "").strip(), strict=False))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 需要有效的 IPv4/IPv6 CIDR") from None
        elif ip_type == "geoip":
            countries = raw.get("countries")
            if not isinstance(countries, list) or not 1 <= len(countries) <= 30:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 需要 1 到 30 个国家代码")
            normalized = []
            for country in countries:
                code = str(country).strip().upper()
                if not re.fullmatch(r"[A-Z]{2}", code):
                    raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 包含无效国家代码")
                if code not in normalized:
                    normalized.append(code)
            rule["countries"] = sorted(normalized)
        rules.append(rule)

    raw_abuse = payload.get("abuse", {})
    categories = {"speedtest", "mining", "bt"}
    if not isinstance(raw_abuse, dict) or set(raw_abuse) - (categories | {"interfaces", "runtimes"}):
        raise HTTPException(status_code=400, detail="防滥用策略只支持固定端口规则、容器桥接网卡或 Incus/Podman 运行时")
    abuse = {}
    for category in sorted(categories):
        value = raw_abuse.get(category, False)
        if type(value) is not bool:
            raise HTTPException(status_code=400, detail=f"防滥用策略 {category} 必须是布尔值")
        abuse[category] = value
    raw_interfaces = raw_abuse.get("interfaces", [])
    if not isinstance(raw_interfaces, list) or len(raw_interfaces) > 16:
        raise HTTPException(status_code=400, detail="容器桥接网卡必须是最多 16 项的列表")
    interfaces = []
    for interface in raw_interfaces:
        name = str(interface).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            raise HTTPException(status_code=400, detail="容器桥接网卡名称无效")
        if name not in interfaces:
            interfaces.append(name)
    raw_runtimes = raw_abuse.get("runtimes", [])
    if not isinstance(raw_runtimes, list) or len(raw_runtimes) > 2:
        raise HTTPException(status_code=400, detail="容器运行时必须从 Incus / Podman 中选择，最多两项")
    runtimes = []
    for runtime in raw_runtimes:
        name = str(runtime).strip().lower()
        if name not in {"incus", "podman"}:
            raise HTTPException(status_code=400, detail="容器运行时只支持 Incus 或 Podman")
        if name not in runtimes:
            runtimes.append(name)
    if interfaces and runtimes:
        raise HTTPException(status_code=400, detail="请使用具体网卡或运行时作为目标，不要混合填写")
    if any(abuse.values()) and not interfaces and not runtimes:
        raise HTTPException(status_code=400, detail="启用容器防滥用前必须选择已采集的容器网卡或运行时")
    abuse["interfaces"] = interfaces
    abuse["runtimes"] = runtimes
    return {"rules": rules, "abuse": abuse}


def _empty_host_firewall_policy() -> Dict[str, Any]:
    return {"rules": [], "abuse": {"speedtest": False, "mining": False, "bt": False, "interfaces": [], "runtimes": []}}


HOST_FIREWALL_READBACK_REASONS = {
    "platform_unsupported", "unknown", "response_too_large", "readback_endpoint_missing",
    "readback_http_error", "invalid_json", "invalid_payload", "socket_missing",
    "socket_permission_denied", "socket_refused", "socket_timeout", "socket_error",
}


def _validate_host_firewall_readback(payload: Any, report_ts: int) -> Dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    status = str(payload.get("status") or "")
    if status not in {"ready", "unavailable", "unsupported"}:
        return None
    raw_reason = payload.get("reason")
    reason = raw_reason if isinstance(raw_reason, str) and raw_reason in HOST_FIREWALL_READBACK_REASONS else ""
    clean: Dict[str, Any] = {
        "status": status, "observed_at": report_ts, "snapshot": None,
        "reason": "" if status == "ready" else reason or "unknown",
    }
    if status != "ready":
        return clean
    snapshot = payload.get("snapshot")
    if not isinstance(snapshot, dict):
        return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
    sync_status = snapshot.get("status")
    policy_revision = snapshot.get("policy_revision")
    rule_count = snapshot.get("rule_count")
    managed_count = snapshot.get("managed_rule_count")
    drift_count = snapshot.get("drift_count")
    missing_count = snapshot.get("missing_count")
    raw_rules = snapshot.get("rules")
    raw_expected = snapshot.get("expected_rules")
    rfw_api_version = snapshot.get("rfw_api_version", "")
    capabilities_known = snapshot.get("capabilities_known", False)
    raw_supported_protocols = snapshot.get("supported_protocols", [])
    if (
        sync_status not in {"in_sync", "drifted"}
        or type(policy_revision) is not int or not 0 <= policy_revision <= 2**63 - 1
        or type(rule_count) is not int or not 0 <= rule_count <= 256
        or type(managed_count) is not int or not 0 <= managed_count <= rule_count
        or type(drift_count) is not int or not 0 <= drift_count <= 320
        or type(missing_count) is not int or not 0 <= missing_count <= 64
        or not isinstance(raw_rules, list) or len(raw_rules) != rule_count
        or not isinstance(raw_expected, list) or len(raw_expected) > 64
        or not isinstance(rfw_api_version, str) or len(rfw_api_version) > 64
        or type(capabilities_known) is not bool
        or not isinstance(raw_supported_protocols, list) or len(raw_supported_protocols) > 32
    ):
        return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
    protocols = {"all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto"}
    supported_protocols = [str(protocol).strip().lower() for protocol in raw_supported_protocols]
    if (len(set(supported_protocols)) != len(supported_protocols)
            or any(protocol not in protocols for protocol in supported_protocols)
            or (capabilities_known and not supported_protocols)):
        return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
    rules: List[Dict[str, Any]] = []
    seen_ids = set()
    for raw in raw_rules:
        if not isinstance(raw, dict):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        rule_id = raw.get("id")
        priority = raw.get("priority")
        port_start = raw.get("port_start")
        port_end = raw.get("port_end")
        if (
            type(rule_id) is not int or not 1 <= rule_id <= 2**63 - 1 or rule_id in seen_ids
            or type(priority) is not int or not 0 <= priority <= 100000
            or raw.get("direction") not in {"in", "out"}
            or raw.get("protocol") not in protocols or raw.get("action") not in {"block", "pass"}
            or type(raw.get("enabled")) is not bool
            or type(port_start) is not int or not 0 <= port_start <= 65535
            or type(port_end) is not int or not port_start <= port_end <= 65535
            or raw.get("ip_type") not in {"any", "cidr", "geoip"}
            or raw.get("origin") not in {"platform", "manual"}
            or raw.get("sync_state") not in {"manual", "in_sync", "drifted", "orphaned"}
        ):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        seen_ids.add(rule_id)
        item: Dict[str, Any] = {
            "id": rule_id, "priority": priority, "direction": raw["direction"],
            "protocol": raw["protocol"], "action": raw["action"], "enabled": raw["enabled"],
            "port_start": port_start, "port_end": port_end, "ip_type": raw["ip_type"],
            "origin": raw["origin"], "sync_state": raw["sync_state"],
        }
        managed_key = raw.get("managed_key")
        if raw["origin"] == "platform":
            if not isinstance(managed_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", managed_key):
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            item["managed_key"] = managed_key
        if raw["ip_type"] == "cidr":
            try:
                item["ip"] = str(ipaddress.ip_network(str(raw.get("ip") or "").strip(), strict=False))
            except ValueError:
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        elif raw["ip_type"] == "geoip":
            countries = raw.get("countries")
            if not isinstance(countries, list) or not 1 <= len(countries) <= 30:
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            codes = sorted({str(code).strip().upper() for code in countries})
            if any(not re.fullmatch(r"[A-Z]{2}", code) for code in codes):
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            item["countries"] = codes
        rules.append(item)
    expected_rules: List[Dict[str, Any]] = []
    expected_keys = set()
    for raw in raw_expected:
        if (
            not isinstance(raw, dict)
            or not isinstance(raw.get("key"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", raw["key"])
            or raw["key"] in expected_keys
            or raw.get("sync_state") not in {"in_sync", "drifted", "missing"}
        ):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        expected_keys.add(raw["key"])
        item = {"key": raw["key"], "sync_state": raw["sync_state"]}
        if "id" in raw:
            if type(raw["id"]) is not int or not 1 <= raw["id"] <= 2**63 - 1:
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            item["id"] = raw["id"]
        expected_rules.append(item)
    clean["snapshot"] = {
        "status": sync_status,
        "observed_at": report_ts,
        "policy_revision": policy_revision,
        "rule_count": rule_count,
        "managed_rule_count": managed_count,
        "drift_count": drift_count,
        "missing_count": missing_count,
        "rfw_api_version": rfw_api_version,
        "capabilities_known": capabilities_known,
        "supported_protocols": sorted(supported_protocols),
        "rules": rules,
        "expected_rules": expected_rules,
    }
    return clean


def _store_host_firewall_readback(
    conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], report_ts: int
) -> None:
    host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
    if not isinstance(host_firewall, dict) or not isinstance(host_firewall.get("readback"), dict):
        return
    readback = _validate_host_firewall_readback(host_firewall["readback"], report_ts)
    if readback is None:
        return
    if readback["status"] == "ready":
        snapshot_json = json.dumps(readback["snapshot"], ensure_ascii=False, separators=(",", ":"))
        conn.execute(
            "INSERT INTO host_firewall_readbacks(host_id,status,observed_at,last_success_at,snapshot_json,readback_reason) VALUES(?,?,?,?,?,'') "
            "ON CONFLICT(host_id) DO UPDATE SET status=excluded.status,observed_at=excluded.observed_at,"
            "last_success_at=excluded.last_success_at,snapshot_json=excluded.snapshot_json,readback_reason=''",
            (host_id, "ready", report_ts, report_ts, snapshot_json),
        )
    else:
        conn.execute(
            "INSERT INTO host_firewall_readbacks(host_id,status,observed_at,last_success_at,snapshot_json,readback_reason) VALUES(?,?,?,0,'{}',?) "
            "ON CONFLICT(host_id) DO UPDATE SET status=excluded.status,observed_at=excluded.observed_at,readback_reason=excluded.readback_reason",
            (host_id, readback["status"], report_ts, readback["reason"]),
        )


def _host_firewall_live_readback(conn: sqlite3.Connection, host_id: str, now: int | None = None) -> Dict[str, Any]:
    row = conn.execute(
        "SELECT status,observed_at,last_success_at,snapshot_json,readback_reason FROM host_firewall_readbacks WHERE host_id=?",
        (host_id,),
    ).fetchone()
    if row is None:
        return {
            "status": "unknown", "observed_at": 0, "last_success_at": 0, "stale": True,
            "reason": "unknown",
            "sync_status": "unknown", "rule_count": 0, "managed_rule_count": 0,
            "drift_count": 0, "missing_count": 0, "rfw_api_version": "",
            "capabilities_known": False, "supported_protocols": [],
            "protocol_capabilities": {protocol: "unknown" for protocol in RFW_APPLICATION_PROTOCOLS},
            "mtproto_support": "unknown", "snapshot": None,
        }
    try:
        snapshot = json.loads(row["snapshot_json"] or "{}")
    except (TypeError, ValueError):
        snapshot = None
    if not isinstance(snapshot, dict) or not snapshot:
        snapshot = None
    observed_at = int(row["observed_at"] or 0)
    last_success_at = int(row["last_success_at"] or 0)
    now = int(time.time()) if now is None else int(now)
    status = str(row["status"] or "unknown")
    if status not in {"ready", "unavailable", "unsupported"}:
        status = "unknown"
    fresh = status == "ready" and observed_at > 0 and 0 <= now - observed_at <= STALE_SECONDS
    capabilities_known = bool(snapshot and snapshot.get("capabilities_known")) and fresh
    supported_protocols = list(snapshot.get("supported_protocols") or []) if capabilities_known else []
    protocol_capabilities = {
        protocol: _protocol_capability_state(
            {"status": status, "stale": not fresh, "capabilities_known": capabilities_known,
             "supported_protocols": supported_protocols},
            protocol,
        )
        for protocol in RFW_APPLICATION_PROTOCOLS
    }
    mtproto_support = "unknown"
    if capabilities_known:
        mtproto_support = "supported" if "mtproto" in supported_protocols else "unsupported"
    return {
        "status": status,
        "reason": str(row["readback_reason"] or "unknown") if status != "ready" else "",
        "observed_at": observed_at,
        "last_success_at": last_success_at,
        "age_seconds": max(0, now - observed_at) if observed_at else None,
        "stale": not fresh,
        "sync_status": str(snapshot.get("status") or "unknown") if snapshot else "unknown",
        "rule_count": int(snapshot.get("rule_count") or 0) if snapshot else 0,
        "managed_rule_count": int(snapshot.get("managed_rule_count") or 0) if snapshot else 0,
        "drift_count": int(snapshot.get("drift_count") or 0) if snapshot else 0,
        "missing_count": int(snapshot.get("missing_count") or 0) if snapshot else 0,
        "rfw_api_version": str(snapshot.get("rfw_api_version") or "") if capabilities_known else "",
        "capabilities_known": capabilities_known,
        "supported_protocols": supported_protocols,
        "protocol_capabilities": protocol_capabilities,
        "mtproto_support": mtproto_support,
        "snapshot": snapshot,
    }


def _policy_required_protocols(policy: Dict[str, Any]) -> List[str]:
    rules = policy.get("rules") if isinstance(policy, dict) else None
    return sorted({
        str(rule.get("protocol"))
        for rule in (rules if isinstance(rules, list) else [])
        if isinstance(rule, dict) and rule.get("protocol") in RFW_APPLICATION_PROTOCOLS
    })


def _policy_protocol_compatibility(
    policy: Dict[str, Any], live_readback: Dict[str, Any]
) -> Dict[str, List[str]]:
    required = _policy_required_protocols(policy)
    states = {protocol: _protocol_capability_state(live_readback, protocol) for protocol in required}
    return {
        "required_protocols": required,
        "unsupported_protocols": sorted(protocol for protocol, state in states.items() if state == "unsupported"),
        "unknown_protocols": sorted(protocol for protocol, state in states.items() if state == "unknown"),
    }


def _protocol_capability_state(live_readback: Dict[str, Any], protocol: str) -> str:
    """Return support only from a fresh, explicit RFW capability report."""
    if (
        not isinstance(live_readback, dict)
        or live_readback.get("status") != "ready"
        or live_readback.get("stale") is not False
        or live_readback.get("capabilities_known") is not True
    ):
        return "unknown"
    supported = live_readback.get("supported_protocols")
    if not isinstance(supported, list):
        return "unknown"
    return "supported" if protocol in supported else "unsupported"


def _host_firewall_runtime_status(
    conn: sqlite3.Connection, host_id: str, now: int | None = None
) -> Dict[str, Any]:
    now = int(time.time()) if now is None else int(now)
    row = conn.execute(
        "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    if row is None:
        return {
            "control_api": "unknown",
            "control_api_reason": "no_report",
            "control_api_http_status": None,
            "observed_at": 0,
            "stale": True,
        }
    try:
        security = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError):
        security = {}
    runtime = security.get("host_firewall") if isinstance(security, dict) else None
    if not isinstance(runtime, dict):
        observed_at = int(row["ts"] or 0)
        return {
            "control_api": "unknown",
            "control_api_reason": "no_capability_report",
            "control_api_http_status": None,
            "observed_at": observed_at,
            "stale": observed_at <= 0 or now - observed_at > STALE_SECONDS or observed_at > now + 30,
        }
    control_api = str(runtime.get("control_api") or "unknown")
    if control_api not in {"ready", "unsupported", "unavailable", "unknown"}:
        control_api = "unknown"
    observed_at = int(runtime.get("observed_at") or row["ts"] or 0)
    allowed_reasons = {
        "ok", "platform_unsupported", "api_endpoint_missing", "unexpected_http", "http_error",
        "socket_missing", "socket_permission_denied", "socket_refused", "socket_timeout", "socket_error",
        "no_report", "no_capability_report", "legacy_report",
    }
    reason = str(runtime.get("control_api_reason") or "")
    if reason not in allowed_reasons:
        if control_api == "ready":
            reason = "ok"
        elif control_api in {"unavailable", "unsupported"}:
            reason = "legacy_report"
        else:
            reason = "no_capability_report"
    raw_http_status = runtime.get("control_api_http_status")
    http_status = raw_http_status if type(raw_http_status) is int and 100 <= raw_http_status <= 599 else None
    return {
        "control_api": control_api,
        "control_api_reason": reason,
        "control_api_http_status": http_status,
        "observed_at": observed_at,
        "stale": observed_at <= 0 or now - observed_at > STALE_SECONDS or observed_at > now + 30,
    }


def _host_firewall_interface_inventory(
    conn: sqlite3.Connection, host_id: str, now: int | None = None
) -> Dict[str, Any]:
    now = int(time.time()) if now is None else int(now)
    row = conn.execute(
        "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    empty = {"status": "unknown", "observed_at": 0, "stale": True, "interfaces": []}
    if row is None:
        return empty
    try:
        security = json.loads(row["payload_json"] or "{}")
    except (TypeError, ValueError):
        return {**empty, "status": "unavailable", "observed_at": int(row["ts"] or 0)}
    host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
    source = host_firewall.get("interface_inventory") if isinstance(host_firewall, dict) else None
    if not isinstance(source, dict):
        return {**empty, "observed_at": int(row["ts"] or 0)}
    observed_at = int(row["ts"] or 0)
    stale = observed_at <= 0 or now - observed_at > STALE_SECONDS
    if source.get("status") != "ready" or not isinstance(source.get("interfaces"), list):
        return {
            "status": "unavailable" if source.get("status") == "unavailable" else "unknown",
            "observed_at": observed_at,
            "stale": stale,
            "interfaces": [],
        }

    interfaces = []
    seen = set()
    for raw in source["interfaces"][:64]:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name) or name in seen:
            continue
        seen.add(name)
        raw_addresses = raw.get("addresses") if isinstance(raw.get("addresses"), list) else []
        addresses = []
        for value in raw_addresses[:16]:
            try:
                address = str(ipaddress.ip_interface(str(value).strip()))
            except ValueError:
                continue
            if address not in addresses:
                addresses.append(address)
        raw_runtimes = raw.get("runtimes") if isinstance(raw.get("runtimes"), list) else []
        runtimes = sorted({str(value).lower() for value in raw_runtimes if str(value).lower() in {"incus", "podman"}})
        raw_kind = str(raw.get("kind") or "unknown")[:32]
        kernel_kind = str(raw.get("kernel_kind") or raw_kind)[:32]
        raw_networks = raw.get("network_names") if isinstance(raw.get("network_names"), list) else []
        networks = list(dict.fromkeys(
            str(value)[:100] for value in raw_networks[:16]
            if isinstance(value, str) and value.strip()
        ))
        mtu = raw.get("mtu")
        interfaces.append({
            "name": name,
            "kind": "bridge" if runtimes else raw_kind,
            "kernel_kind": kernel_kind,
            "state": str(raw.get("state") or "unknown")[:16].lower(),
            "mtu": mtu if type(mtu) is int and 0 < mtu <= 65535 else None,
            "addresses": addresses,
            "is_default_route": raw.get("is_default_route") is True,
            "runtimes": runtimes,
            "network_names": networks,
            # Older agents can label a runtime-confirmed bridge as `ether`
            # and set firewall_eligible=false because `ip address show`
            # omits linkinfo. Runtime labels only come from explicit Incus /
            # Podman bridge metadata, so preserve that verified mapping.
            "firewall_eligible": bool(runtimes),
        })
    return {
        "status": "ready",
        "observed_at": observed_at,
        "stale": stale,
        "interfaces": interfaces,
    }


def _host_firewall_policy_targets(
    conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
) -> Tuple[List[str] | None, str]:
    """Resolve a logical runtime selection to fresh, agent-discovered bridge names."""
    abuse = policy.get("abuse") if isinstance(policy, dict) else None
    if not isinstance(abuse, dict) or not any(abuse.get(key) is True for key in ("speedtest", "mining", "bt")):
        return [], "not_required"

    inventory = _host_firewall_interface_inventory(conn, host_id, now)
    if inventory["status"] != "ready" or inventory["stale"]:
        return None, "inventory_unavailable"

    eligible = [item for item in inventory["interfaces"] if item["firewall_eligible"]]
    runtimes = abuse.get("runtimes") if isinstance(abuse.get("runtimes"), list) else []
    requested_interfaces = abuse.get("interfaces") if isinstance(abuse.get("interfaces"), list) else []
    if runtimes:
        selected = [
            item["name"] for item in eligible
            if set(item["runtimes"]).intersection(runtimes)
        ]
        if not selected:
            return None, "runtime_not_found"
        return list(dict.fromkeys(selected)), "ready"

    eligible_names = {item["name"] for item in eligible}
    if not requested_interfaces or any(name not in eligible_names for name in requested_interfaces):
        return None, "interface_not_found"
    return list(dict.fromkeys(requested_interfaces)), "ready"


def _materialize_host_firewall_policy(
    conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
) -> Tuple[Dict[str, Any] | None, str]:
    """Build the host-local policy sent to Runman; never send logical runtime selectors."""
    targets, status = _host_firewall_policy_targets(conn, host_id, policy, now)
    if targets is None:
        return None, status
    materialized = dict(policy)
    abuse = dict(policy.get("abuse") or {})
    abuse.pop("runtimes", None)
    if any(abuse.get(key) is True for key in ("speedtest", "mining", "bt")):
        abuse["interfaces"] = targets
    materialized["abuse"] = abuse
    validated = _validate_host_firewall_policy(materialized)
    validated["abuse"].pop("runtimes", None)
    return validated, status


def _latest_host_firewall_action(conn: sqlite3.Connection, host_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id,status,result_message,updated_at,params_json FROM security_actions "
        "WHERE host_id=? AND action_type IN ('apply_host_firewall_policy','delete_host_firewall_rule') ORDER BY id DESC LIMIT 1",
        (host_id,),
    ).fetchone()


def _enqueue_host_firewall_policy(
    conn: sqlite3.Connection,
    host_id: str,
    node_id: str,
    policy: Dict[str, Any],
    requested_by: str,
    now: int,
    fleet_revision: int,
) -> int:
    existing = conn.execute(
        "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    revision = (int(existing["revision"]) if existing else 0) + 1
    policy_with_revision = {"revision": revision, **policy}
    policy_json = json.dumps(policy, ensure_ascii=False, separators=(",", ":"))
    if existing and str(existing["policy_json"] or "") != policy_json:
        conn.execute(
            "INSERT INTO host_firewall_policy_history(host_id,revision,policy_json,updated_by,updated_at,source_fleet_revision) VALUES(?,?,?,?,?,?)",
            (host_id, int(existing["revision"]), str(existing["policy_json"] or "{}"), str(existing["updated_by"] or ""), int(existing["updated_at"] or 0), int(existing["source_fleet_revision"] or 0)),
        )
        conn.execute(
            "DELETE FROM host_firewall_policy_history WHERE host_id=? AND id NOT IN (SELECT id FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 20)",
            (host_id, host_id),
        )
    conn.execute(
        "INSERT INTO host_firewall_policies(host_id,revision,policy_json,updated_by,updated_at,source_fleet_revision) "
        "VALUES(?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET revision=excluded.revision,"
        "policy_json=excluded.policy_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at,"
        "source_fleet_revision=excluded.source_fleet_revision",
        (host_id, revision, policy_json, requested_by, now, fleet_revision),
    )
    conn.execute(
        "UPDATE security_actions SET status='cancelled',result_message='已被更新的母机防火墙策略取代',updated_at=? "
        "WHERE host_id=? AND action_type='apply_host_firewall_policy' AND status IN ('queued','dispatched')",
        (now, host_id),
    )
    action_params = {"expected_node_id": node_id, "policy": policy_with_revision}
    if fleet_revision > 0:
        action_params["fleet_revision"] = int(fleet_revision)
    cur = conn.execute(
        "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
        "VALUES(0,?,'host','','__host__','apply_host_firewall_policy',?,'queued',?,?,?)",
        (
            host_id,
            json.dumps(action_params, ensure_ascii=False),
            requested_by,
            now,
            now,
        ),
    )
    return int(cur.lastrowid)


def _maybe_queue_fleet_firewall_policy(
    conn: sqlite3.Connection,
    host_id: str,
    node_id: str,
    ts: int,
    security: Dict[str, Any],
) -> bool:
    runtime = security.get("host_firewall") if isinstance(security, dict) else None
    if not node_id or not isinstance(runtime, dict) or runtime.get("control_api") != "ready":
        return False
    fleet = conn.execute("SELECT revision,policy_json FROM fleet_firewall_policy WHERE id=1").fetchone()
    if fleet is None or int(fleet["revision"] or 0) < 1:
        return False
    fleet_revision = int(fleet["revision"])
    state = conn.execute(
        "SELECT source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    already_on_fleet_revision = (
        state is not None and int(state["source_fleet_revision"] or 0) >= fleet_revision
    )
    live_readback = _host_firewall_live_readback(conn, host_id, ts)
    drift_repair_needed = (
        already_on_fleet_revision
        and live_readback.get("status") == "ready"
        and live_readback.get("stale") is False
        and live_readback.get("sync_status") == "drifted"
    )
    if already_on_fleet_revision and not drift_repair_needed:
        return False
    latest = _latest_host_firewall_action(conn, host_id)
    if latest is not None:
        try:
            latest_params = json.loads(latest["params_json"] or "{}")
        except (TypeError, ValueError):
            latest_params = {}
        same_fleet_revision = int(latest_params.get("fleet_revision") or 0) == fleet_revision
        if same_fleet_revision and latest["status"] in {"queued", "dispatched", "running"}:
            return False
        if same_fleet_revision and latest["status"] == "failed" and ts - int(latest["updated_at"] or 0) < 900:
            return False
        # A fresh drift readback must have been observed after the previous
        # successful apply before scheduling another repair. This prevents the
        # same pre-apply snapshot from causing an action loop.
        if (
            same_fleet_revision
            and latest["status"] == "succeeded"
            and drift_repair_needed
            and int(live_readback.get("observed_at") or 0) <= int(latest["updated_at"] or 0)
        ):
            return False
    try:
        policy = _validate_host_firewall_policy(json.loads(fleet["policy_json"] or "{}"))
    except (HTTPException, TypeError, ValueError):
        return False
    if _policy_required_protocols(policy):
        compatibility = _policy_protocol_compatibility(policy, live_readback)
        if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
            return False
    host_policy, _target_status = _materialize_host_firewall_policy(conn, host_id, policy, ts)
    if host_policy is None:
        return False
    _enqueue_host_firewall_policy(
        conn, host_id, node_id, host_policy, "fleet-policy-reconcile", ts, fleet_revision
    )
    return True


def _ingest_host_firewall_events(
    conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], ts: int
) -> Tuple[List[Dict[str, Any]], str]:
    """Validate, deduplicate, and turn bounded RFW event pages into grouped alerts."""
    host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
    if not isinstance(host_firewall, dict) or host_firewall.get("events_api") != "ready":
        return [], ""
    instance_id = str(host_firewall.get("instance_id") or "")
    next_cursor = str(host_firewall.get("next_cursor") or "")
    events = host_firewall.get("events")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", instance_id):
        return [], ""
    cursor_match = re.fullmatch(r"([A-Za-z0-9_-]{1,80}):(\d{1,20})", next_cursor)
    if not cursor_match or cursor_match.group(1) != instance_id or not isinstance(events, list) or len(events) > 100:
        return [], ""
    try:
        page_sequence = int(cursor_match.group(2))
    except ValueError:
        return [], ""

    normalized_events: List[Dict[str, Any]] = []
    last_page_sequence = 0
    for event in events:
        if not isinstance(event, dict):
            return [], ""
        sequence = event.get("sequence")
        observed_at = event.get("observed_at")
        if type(sequence) is not int or sequence < 1 or type(observed_at) is not int or observed_at <= 0:
            return [], ""
        if event.get("cursor") != f"{instance_id}:{sequence}" or sequence <= last_page_sequence:
            return [], ""
        last_page_sequence = sequence
        try:
            source_ip = str(ipaddress.ip_address(str(event.get("source_ip") or "")))
            destination_ip = str(ipaddress.ip_address(str(event.get("destination_ip") or "")))
        except ValueError:
            return [], ""
        source_port = event.get("source_port")
        destination_port = event.get("destination_port")
        if type(source_port) is not int or not 0 <= source_port <= 65535 or type(destination_port) is not int or not 0 <= destination_port <= 65535:
            return [], ""
        transport = str(event.get("transport") or "")
        app_protocol = str(event.get("app_protocol") or "")
        direction = str(event.get("direction") or "")
        action = str(event.get("action") or "")
        if transport not in {"tcp", "udp", "unknown"} or app_protocol not in {"http", "tls", "socks", "fet", "wireguard", "ssh", "openvpn", "quic", "mtproto", "unknown"} or direction not in {"in", "out"} or action not in {"pass", "block"}:
            return [], ""
        countries = event.get("rule_countries")
        if not isinstance(countries, list) or len(countries) > 30:
            return [], ""
        normalized_countries = sorted({str(code).strip().upper() for code in countries})
        if any(not re.fullmatch(r"[A-Z]{2}", code) for code in normalized_countries):
            return [], ""
        normalized_events.append({
            "sequence": sequence,
            "observed_at": observed_at,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "transport": transport,
            "app_protocol": app_protocol,
            "direction": direction,
            "action": action,
            "rule_id": event.get("rule_id") if type(event.get("rule_id")) is int else None,
            "rule_countries": normalized_countries,
        })
    if page_sequence < last_page_sequence:
        return [], ""

    previous = conn.execute(
        "SELECT instance_id,sequence FROM host_firewall_event_state WHERE host_id=?", (host_id,)
    ).fetchone()
    previous_instance = str(previous["instance_id"]) if previous is not None else ""
    previous_sequence = int(previous["sequence"]) if previous is not None else 0
    same_instance = previous_instance == instance_id
    last_sequence = previous_sequence if same_instance else 0
    gap_reasons: List[str] = []
    dropped = max(0, min(int(host_firewall.get("dropped") or 0), 1_000_000))
    if previous_instance and not same_instance:
        gap_reasons.append("RFW 实例已重启或替换")
    if host_firewall.get("cursor_reset") is True:
        gap_reasons.append("事件游标被重置")
    if dropped > 0:
        gap_reasons.append(f"RFW 环形缓冲区丢弃 {dropped} 条")

    fresh_events = []
    for event in normalized_events:
        sequence = int(event["sequence"])
        if same_instance and sequence <= previous_sequence:
            continue
        if same_instance and last_sequence > 0 and sequence > last_sequence + 1:
            gap_reasons.append(f"事件序号从 {last_sequence} 跳至 {sequence}")
        fresh_events.append(event)
        last_sequence = max(last_sequence, sequence)

    grouped: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = {}
    for event in fresh_events:
        if event["app_protocol"] not in RFW_CN_ALERT_PROTOCOLS or "CN" not in event["rule_countries"]:
            continue
        # RFW currently reports the matched rule's country scope, not the
        # individual GeoIP country. A CN-only rule is exact; a mixed-country
        # rule is deliberately marked as scope-only rather than asserted as CN.
        country_confidence = "exact_cn_rule" if event["rule_countries"] == ["CN"] else "rule_scope_includes_cn"
        key = (event["app_protocol"], event["direction"], event["action"], country_confidence)
        grouped.setdefault(key, []).append(event)

    alerts: List[Dict[str, Any]] = []
    for (app_protocol, direction, action, country_confidence), group in grouped.items():
        is_pass = action == "pass"
        protocol_label = {
            "wireguard": "WireGuard",
            "socks": "SOCKS",
            "fet": "FET（高熵加密特征，可能含 SS 类）",
            "mtproto": "MTProto（混淆传输特征）",
            "openvpn": "OpenVPN",
        }.get(app_protocol, app_protocol)
        if country_confidence == "exact_cn_rule":
            direction_label = "出站到 CN" if direction == "out" else "来自 CN 的入站"
        else:
            direction_label = (
                "出站命中包含 CN 的 GeoIP 范围（实际国家未知）"
                if direction == "out"
                else "入站命中包含 CN 的 GeoIP 范围（实际国家未知）"
            )
        action_label = "被放行" if is_pass else "已阻断"
        scope_note = "规则仅包含 CN，国家范围精确。" if country_confidence == "exact_cn_rule" else "规则国家范围包含 CN，但 RFW 事件未携带实际命中国家，需人工复核。"
        protocol_note = {
            "fet": "FET 依首包高熵特征识别，不能确证 Shadowsocks；其他非 TLS 加密流量也可能命中，存在误报。",
            "mtproto": "MTProto 仅依据已知混淆初始化标记识别，覆盖不完整，不代表确认了完整会话。",
            "wireguard": "WireGuard 识别主要基于可见的初始握手；协议命中不代表恶意或未授权。",
            "socks": "SOCKS 协议命中不代表服务未授权或存在滥用。",
            "openvpn": "OpenVPN 是常见 VPN 协议；协议命中不代表服务未授权或存在滥用。",
        }.get(app_protocol, "")
        samples = [
            f"{event['source_ip']}:{event['source_port']} → {event['destination_ip']}:{event['destination_port']}"
            for event in group[:10]
        ]
        rule_ids = sorted({int(event["rule_id"]) for event in group if event.get("rule_id") is not None})
        alert_type = f"rfw_cn_{app_protocol}_{direction}_{action}"
        title = f"RFW {protocol_label} 连接{action_label}"
        message = (
            f"RFW 检测到 {direction_label} 的 {protocol_label} 流量，共 {len(group)} 条事件，已{action_label}。"
            f"样例：{'；'.join(samples) if samples else '无端点样例'}。{scope_note}{protocol_note}"
        )
        alerts.append({
            "type": alert_type,
            "severity": "critical" if is_pass else "warning",
            "runtime": "host",
            "project": "",
            "container_name": "__host__",
            "title": title,
            "message": message[:2000],
            "value": float(len(group)),
            "threshold": 1.0,
            "instance_id": instance_id,
            "rfw_evidence": {
                "event_count": len(group),
                "app_protocol": app_protocol,
                "direction": direction,
                "packet_action": action,
                "country_confidence": country_confidence,
                "rule_ids": rule_ids[:20],
                "samples": samples,
                "first_observed_at": min(int(event["observed_at"]) for event in group),
                "last_observed_at": max(int(event["observed_at"]) for event in group),
            },
        })

    if gap_reasons:
        alerts.append({
            "type": "rfw_event_gap",
            "severity": "warning",
            "runtime": "host",
            "project": "",
            "container_name": "__host__",
            "title": "RFW 连接事件存在采集缺口",
            "message": "；".join(sorted(set(gap_reasons))) + "。事件统计可能不完整，不能据此推断未发生连接。",
            "value": float(dropped),
            "threshold": 0.0,
            "instance_id": instance_id,
            "rfw_evidence": {"dropped": dropped, "cursor_reset": host_firewall.get("cursor_reset") is True},
        })

    last_sequence = max(last_sequence, page_sequence)
    conn.execute(
        "INSERT INTO host_firewall_event_state(host_id,instance_id,sequence,cursor,updated_at) VALUES(?,?,?,?,?) "
        "ON CONFLICT(host_id) DO UPDATE SET instance_id=excluded.instance_id,sequence=excluded.sequence,cursor=excluded.cursor,updated_at=excluded.updated_at",
        (host_id, instance_id, last_sequence, next_cursor, ts),
    )
    return alerts, next_cursor


def _fleet_firewall_node_state(
    conn: sqlite3.Connection,
    host: sqlite3.Row,
    fleet_revision: int,
    now: int,
    required_protocols: List[str] | None = None,
    required_policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    host_id = str(host["host_id"])
    node_id = str(host["node_id"] or "")
    last_seen = int(host["last_seen"] or 0)
    online = bool(node_id) and now - last_seen <= STALE_SECONDS
    runtime = _host_firewall_runtime_status(conn, host_id, now)
    live_readback = _host_firewall_live_readback(conn, host_id, now)
    interface_inventory = _host_firewall_interface_inventory(conn, host_id, now)
    container_interfaces = {
        runtime_name: [
            item["name"] for item in interface_inventory["interfaces"]
            if item["firewall_eligible"] and runtime_name in item["runtimes"]
        ]
        for runtime_name in ("incus", "podman")
    }
    _targets, target_status = _host_firewall_policy_targets(conn, host_id, required_policy or {}, now)
    protocol_status = _policy_protocol_compatibility(
        {"rules": [{"protocol": protocol} for protocol in (required_protocols or [])]}, live_readback
    )
    policy_abuse = (required_policy or {}).get("abuse") or {}
    container_policy_enabled = any(policy_abuse.get(key) is True for key in ("speedtest", "mining", "bt"))
    policy_row = conn.execute(
        "SELECT revision,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    local_revision = int(policy_row["revision"] or 0) if policy_row is not None else 0
    applied_fleet_revision = int(policy_row["source_fleet_revision"] or 0) if policy_row is not None else 0
    action = _latest_host_firewall_action(conn, host_id)
    status = "unregistered"
    if node_id:
        status = "offline" if not online else "awaiting_capability"
        if online and not runtime["stale"] and runtime["control_api"] == "unsupported":
            status = "runman_update_required"
        elif online and not runtime["stale"] and runtime["control_api"] == "unavailable":
            status = "runman_unavailable"
        elif online and not live_readback["stale"] and protocol_status["unsupported_protocols"]:
            status = "rfw_protocol_update_required"
        elif online and runtime["stale"]:
            status = (
                "awaiting_interfaces"
                if container_policy_enabled and target_status == "inventory_unavailable"
                else "firewall_status_stale"
            )
        elif online and runtime["control_api"] == "ready" and protocol_status["unknown_protocols"]:
            status = "awaiting_rfw_capability"
        elif runtime["control_api"] == "ready":
            if container_policy_enabled and target_status == "inventory_unavailable":
                status = "awaiting_interfaces"
            elif container_policy_enabled and target_status in {"runtime_not_found", "interface_not_found"}:
                status = "interfaces_not_found"
            elif action is not None and action["status"] in {"queued", "dispatched", "running"}:
                status = "queued"
            elif action is not None and action["status"] == "failed":
                status = "apply_failed"
            elif (
                live_readback["status"] == "ready"
                and not live_readback["stale"]
                and live_readback["sync_status"] == "drifted"
            ):
                status = "drifted"
            elif fleet_revision > 0 and applied_fleet_revision == fleet_revision and action is not None and action["status"] == "succeeded":
                status = "last_apply_succeeded"
            elif fleet_revision > 0:
                status = "not_synced"
            else:
                status = "ready"
    return {
        "host_id": host_id,
        "registered": bool(node_id),
        "online": online,
        "agent_version": str(host["agent_version"] or "unknown"),
        "control_api": runtime["control_api"],
        "control_api_reason": runtime["control_api_reason"],
        "control_api_http_status": runtime["control_api_http_status"],
        "control_api_stale": runtime["stale"],
        "observed_at": runtime["observed_at"],
        "live_readback": {key: value for key, value in live_readback.items() if key != "snapshot"},
        "local_revision": local_revision,
        "fleet_revision": applied_fleet_revision,
        "state": status,
        "required_protocols": protocol_status["required_protocols"],
        "unsupported_protocols": protocol_status["unsupported_protocols"],
        "unknown_protocols": protocol_status["unknown_protocols"],
        "container_interfaces": {
            "status": interface_inventory["status"],
            "observed_at": interface_inventory["observed_at"],
            "stale": interface_inventory["stale"],
            "by_runtime": container_interfaces,
        },
        "last_action": None if action is None else {
            "id": int(action["id"]),
            "status": str(action["status"]),
            "message": str(action["result_message"] or ""),
            "updated_at_utc8": format_utc8(int(action["updated_at"] or 0)),
        },
    }


def _reconcile_host(conn: sqlite3.Connection, host_id: str, node_id: str, ts: int, agent_version: str, config: Dict[str, Any]) -> str:
    host_id = host_id[:200] or "unknown"
    node_id = node_id[:128]
    if node_id:
        previous = conn.execute("SELECT host_id FROM hosts WHERE node_id=?", (node_id,)).fetchone()
        collision = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if collision is not None and str(collision["node_id"] or "") not in ("", node_id):
            host_id = f"{host_id[:150]} [{node_id[:12]}]"
        if previous is not None and previous["host_id"] != host_id:
            old = str(previous["host_id"])
            # Fingerprints include the display host name. Preserve alert history,
            # suppressions and remediation policy when the label is corrected.
            alerts = conn.execute("SELECT * FROM security_alerts WHERE host_id=?", (old,)).fetchall()
            for alert in alerts:
                try:
                    details = json.loads(alert["details_json"] or "{}")
                except (TypeError, ValueError):
                    details = {}
                fingerprint = _alert_fingerprint(host_id, {
                    "runtime": alert["runtime"], "project": alert["project"],
                    "container_name": alert["container_name"], "type": alert["alert_type"],
                    "message": alert["message"], "unapproved_domains": details.get("unapproved_domains"),
                    "alert_key": details.get("alert_key"),
                })
                existing = conn.execute("SELECT id FROM security_alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                old_fingerprint = str(alert["fingerprint"])
                if existing is not None:
                    conn.execute("UPDATE security_actions SET alert_id=? WHERE alert_id=?", (existing["id"], alert["id"]))
                    conn.execute("UPDATE security_alert_decisions SET alert_id=? WHERE alert_id=?", (existing["id"], alert["id"]))
                    conn.execute("DELETE FROM security_alerts WHERE id=?", (alert["id"],))
                else:
                    conn.execute("UPDATE security_alerts SET fingerprint=? WHERE id=?", (fingerprint, alert["id"]))
                conn.execute("UPDATE OR IGNORE security_alert_policies SET fingerprint=? WHERE fingerprint=?", (fingerprint, old_fingerprint))
                conn.execute("DELETE FROM security_alert_policies WHERE fingerprint=?", (old_fingerprint,))
                conn.execute("UPDATE security_alert_decisions SET fingerprint=? WHERE fingerprint=?", (fingerprint, old_fingerprint))
            for table in ("reports", "security_alerts", "host_security", "security_actions", "connection_overloads", "host_firewall_policies", "host_firewall_readbacks", "ops_service_inventory", "ops_service_inventory_changes"):
                conn.execute(f"UPDATE {table} SET host_id=? WHERE host_id=?", (host_id, old))
            investigation.rename_host(conn, old, host_id)
            conn.execute("DELETE FROM hosts WHERE host_id=?", (old,))
    conn.execute(
        "INSERT INTO hosts(host_id,last_seen,agent_version,node_id,config_json) VALUES(?,?,?,?,?) "
        "ON CONFLICT(host_id) DO UPDATE SET last_seen=excluded.last_seen,agent_version=excluded.agent_version,"
        "node_id=CASE WHEN excluded.node_id<>'' THEN excluded.node_id ELSE hosts.node_id END,config_json=excluded.config_json",
        (host_id, ts, agent_version, node_id, json.dumps(config, ensure_ascii=False)),
    )
    tcping.reconcile_host(conn, host_id, node_id, ts)
    return host_id


def dispatch_buyer_notifications_for_alerts(host_id: str, alerts: list) -> None:
    """Compatibility entry point: enqueue only, never send in the report request."""
    conn = db()
    try:
        buyer_notifications.reconcile(conn, host_id, int(time.time()))
        conn.commit()
    finally:
        conn.close()


@app.post("/api/v1/report")
async def report(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Dict[str, Any]:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    data = json.loads(body)

    host_id = str(data.get("host_id") or "unknown")[:200]
    node_id = str(data.get("node_id") or "")[:128]
    client_config = data.get("client_config") if isinstance(data.get("client_config"), dict) else {}
    agent_version = str(data.get("agent_version") or "unknown").strip() or "unknown"
    ts = int(data.get("timestamp", time.time()))
    network_status = data.get("container_network") or data.get("podman_network") or {}
    podman_v4 = 1 if network_status.get("ipv4_ok") else 0
    podman_v6 = 1 if network_status.get("ipv6_ok") else 0

    containers: List[Dict[str, Any]] = data.get("containers", [])
    conn = db()
    notifications: List[Dict[str, Any]] = []
    firewall_event_cursor = ""
    automatic_stops_queued = 0
    automatic_deep_samples_queued = 0
    try:
        host_id = _reconcile_host(conn, host_id, node_id, ts, agent_version, client_config)
        automatic_stops_queued = process_connection_overloads(conn, host_id, ts, containers)
        for c in containers:
            stored_payload = dict(c)
            stored_payload["_agent_version"] = agent_version
            conn.execute(
                """
                INSERT INTO reports(
                    host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps,
                    conn_count, disk_file, disk_size_bytes, disk_used_percent,
                    podman_network_ok_v4, podman_network_ok_v6, ts, payload_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    host_id,
                    c.get("name", "unknown"),
                    c.get("runtime", "podman"),
                    c.get("project", ""),
                    float(c.get("cpu_percent", 0)),
                    int(c.get("mem_bytes", 0)),
                    float(c.get("mem_percent", 0)),
                    float(c.get("net_rx_bps", 0)),
                    float(c.get("net_tx_bps", 0)),
                    int(c.get("conn_count", 0)),
                    c.get("disk", {}).get("file"),
                    c.get("disk", {}).get("size_bytes"),
                    c.get("disk", {}).get("used_percent"),
                    podman_v4,
                    podman_v6,
                    ts,
                    json.dumps(stored_payload, ensure_ascii=False),
                ),
            )
            deep_sample = c.get("deep_sample") if isinstance(c.get("deep_sample"), dict) else None
            if deep_sample is not None:
                try:
                    deep_action_id = int(deep_sample.get("action_id") or 0)
                except (TypeError, ValueError):
                    deep_action_id = 0
                if deep_action_id > 0:
                    conn.execute(
                        """
                        UPDATE security_actions
                        SET status='succeeded', result_message='deep sample received', updated_at=?
                        WHERE id=? AND action_type='request_deep_sample'
                          AND host_id=? AND runtime=? AND project=? AND container_name=?
                          AND status IN ('queued','dispatched')
                        """,
                        (
                            ts,
                            deep_action_id,
                            host_id,
                            str(c.get("runtime") or "")[:40],
                            str(c.get("project") or "")[:100],
                            str(c.get("name") or "")[:200],
                        ),
                    )
                    evidence_action = conn.execute(
                        "SELECT alert_id FROM security_actions WHERE id=? AND action_type='request_deep_sample'",
                        (deep_action_id,),
                    ).fetchone()
                    if evidence_action is not None and int(evidence_action["alert_id"]) > 0:
                        conn.execute(
                            """
                            INSERT INTO security_alert_evidence(alert_id,action_id,captured_at,evidence_json)
                            VALUES(?,?,?,?)
                            ON CONFLICT(action_id) DO UPDATE SET
                                captured_at=excluded.captured_at,evidence_json=excluded.evidence_json
                            """,
                            (
                                int(evidence_action["alert_id"]), deep_action_id, ts,
                                json.dumps(deep_sample, ensure_ascii=False),
                            ),
                        )
        operations_alerts = operations.ingest(conn, host_id, node_id, ts, data)
        security = data.get("security")
        if isinstance(security, dict):
            security_alerts = security.get("alerts") if isinstance(security.get("alerts"), list) else []
            firewall_event_alerts, firewall_event_cursor = _ingest_host_firewall_events(conn, host_id, security, ts)
            combined_alerts = connection_policy.enrich_alerts(security_alerts + firewall_event_alerts + operations_alerts, containers)
            previous_sample = conn.execute("SELECT MAX(ts) FROM host_security WHERE host_id=?", (host_id,)).fetchone()[0] or 0
            if security.get("enabled", True) and ts > previous_sample:
                host_audit = security.get("host_audit") if isinstance(security.get("host_audit"), dict) else {}
                vulnerability_scan = host_audit.get("vulnerability_scan") if isinstance(host_audit.get("vulnerability_scan"), dict) else {}
                indicator_scan = host_audit.get("security_indicator_scan") if isinstance(host_audit.get("security_indicator_scan"), dict) else {}
                preserve_types = []
                # Child Agents intentionally perform SSH-only checks. Their
                # not-applicable scans must not keep old container-scoped
                # package/indicator alerts active as if they were host checks.
                if host_audit.get("scope") != "agent_container":
                    if vulnerability_scan.get("coverage") != "complete":
                        preserve_types.append("host_vulnerability")
                    if indicator_scan.get("coverage") != "complete":
                        preserve_types.append("host_security_finding")
                notifications = process_security_alerts(
                    conn, host_id, ts, combined_alerts,
                    preserve_active_types=preserve_types,
                )
                buyer_notifications.observe(conn, host_id, ts, containers, combined_alerts)
            automatic_deep_samples_queued = queue_connection_alert_deep_samples(conn, host_id, ts)
            _store_host_firewall_readback(conn, host_id, security, ts)
            historical_security = dict(security)
            host_firewall_history = security.get("host_firewall")
            if isinstance(host_firewall_history, dict) and "readback" in host_firewall_history:
                historical_firewall = dict(host_firewall_history)
                historical_firewall.pop("readback", None)
                historical_security["host_firewall"] = historical_firewall
            conn.execute(
                "INSERT INTO host_security(host_id, ts, payload_json) VALUES(?,?,?)",
                (host_id, ts, json.dumps(historical_security, ensure_ascii=False)),
            )
            _maybe_queue_fleet_firewall_policy(conn, host_id, node_id, ts, security)
        fingerprints = None
        if isinstance(security, dict) and security.get("enabled", True) and ts > previous_sample:
            fingerprints = {r[0] for r in conn.execute("SELECT fingerprint FROM security_alerts WHERE host_id=? AND last_seen=? AND status<>'resolved'", (host_id, ts))}
        investigation.observe(conn, host_id, node_id, ts, containers, fingerprints)
        conn.commit()
    finally:
        conn.close()

    for alert in notifications:
        send_alert_webhook(alert)
    sync_configured_bot_alert_messages(host_id, ts)
    dispatch_buyer_notifications_for_alerts(host_id, notifications)
    conn = db()
    try:
        motd_states = buyer_notifications.banner_states(conn, host_id)
    finally:
        conn.close()
    return {
        "ok": True,
        "server_version": APP_VERSION,
        "records": len(containers),
        "new_alerts": len(notifications),
        "firewall_event_cursor": firewall_event_cursor,
        "automatic_deep_samples_queued": automatic_deep_samples_queued,
        "automatic_stops_queued": automatic_stops_queued,
        "narwhal_buyer_push": {"owner": "server", "enabled": False},
        "motd_states": motd_states,
    }


@app.get("/api/v1/latest")
def latest(include_stale: bool = False, request: Request = None) -> JSONResponse:
    global _latest_cache, _latest_cache_time
    can_view_user_notes = request is None or getattr(request.state, "dashboard_role", "admin") in {"admin", "operator"}

    conn = db()
    try:
        admission_rows={(r['host_id'],r['runtime'],r['project'],r['container_name']):dict(r)
                        for r in conn.execute('SELECT * FROM admission_states')}
        container_notes = {
            (r["host_id"], r["runtime"], r["project"], r["container_name"], r["container_id"]): dict(r)
            for r in conn.execute("SELECT * FROM container_user_notes")
        }
        host_heartbeats = {
            str(row["host_id"]): int(row["last_seen"])
            for row in conn.execute("SELECT host_id, last_seen FROM hosts").fetchall()
        }
        rows = conn.execute(
            """
            SELECT r.* FROM reports r
            JOIN (
                SELECT host_id, runtime, project, container_name, MAX(ts) AS max_ts
                FROM reports
                GROUP BY host_id, runtime, project, container_name
            ) m ON r.host_id=m.host_id AND r.runtime=m.runtime AND r.project=m.project
                AND r.container_name=m.container_name AND r.ts=m.max_ts
            ORDER BY r.host_id, r.runtime, r.project, r.container_name
            """
        ).fetchall()

        host_rows = conn.execute(
            """
            SELECT r.host_id, r.payload_json, r.ts
            FROM reports r
            JOIN (
                SELECT host_id, MAX(ts) AS max_ts
                FROM reports
                GROUP BY host_id
            ) m ON r.host_id=m.host_id AND r.ts=m.max_ts
            """
        ).fetchall()
    finally:
        conn.close()

    host_disk_map: Dict[str, Dict[str, Any]] = {}
    for h in host_rows:
        payload = json.loads(h["payload_json"]) if h["payload_json"] else {}
        candidate_disk=payload.get('disk',{})
        if isinstance(candidate_disk,dict) and candidate_disk.get('root_total_bytes'):
            host_disk_map[h['host_id']]=candidate_disk

    now = int(time.time())
    out = []
    for r in rows:
        payload = json.loads(r["payload_json"]) if r["payload_json"] else {}
        current_container_id = str(payload.get("id") or "")
        note = container_notes.get((r["host_id"], r["runtime"], r["project"], r["container_name"], current_container_id), {})
        admission=admission_rows.get((r['host_id'],r['runtime'],r['project'],r['container_name']))
        reported_identity=(payload.get('security') or {}).get('admission',{}).get('instance_id') or payload.get('stable_id') or payload.get('id') or ''
        if admission and (not admission['instance_id'] or (len(reported_identity)>=12 and admission['instance_id'].startswith(reported_identity))):
            security=payload.setdefault('security',{})
            if admission['observed_at']>security.get('admission',{}).get('observed_at',0):
                security['admission']=json.loads(admission['payload'])
        disk = payload.get("disk", {})
        host_disk = host_disk_map.get(r["host_id"], {})
        alert_disk = (r["disk_used_percent"] or 0) >= ALERT_DISK_THRESHOLD_PERCENT
        alert_cpu = float(r["cpu_percent"] or 0) >= ALERT_CPU_THRESHOLD_PERCENT
        conn_count = int(r["conn_count"] or 0)
        conn_severity = (
            "critical"
            if conn_count > ALERT_CONN_CRITICAL_THRESHOLD
            else "warning"
            if conn_count > ALERT_CONN_WARNING_THRESHOLD
            else ""
        )
        stale_seconds = max(0, now - r["ts"])
        stale = stale_seconds > STALE_SECONDS
        hidden_offline = stale_seconds > OFFLINE_HIDE_SECONDS
        host_last_seen = host_heartbeats.get(str(r["host_id"]), int(r["ts"]))
        host_stale = now - host_last_seen > STALE_SECONDS
        # include_stale keeps a short diagnostic window for offline hosts and
        # disappeared containers, but must not bypass the configured panel
        # retention limit. Otherwise deleted containers remain visible until
        # the much longer database retention cleanup runs.
        if hidden_offline:
            continue
        if host_stale and not include_stale:
            continue
        container_disk = payload.get("container_disk", {})
        top_cpu_process = payload.get("top_cpu_process", {})
        offline_hours = stale_seconds // 3600
        rx_bps = float(r["net_rx_bps"] or 0)
        tx_bps = float(r["net_tx_bps"] or 0)
        tcp_rx_bps = float(payload.get("tcp_rx_bps", rx_bps) or 0.0)
        tcp_tx_bps = float(payload.get("tcp_tx_bps", tx_bps) or 0.0)
        udp_rx_bps = float(payload.get("udp_rx_bps", 0.0) or 0.0)
        udp_tx_bps = float(payload.get("udp_tx_bps", 0.0) or 0.0)

        max_bps = max(rx_bps, tx_bps)
        min_bps = min(rx_bps, tx_bps)
        eff_min = max(min_bps, 1024.0)
        imb_ratio = max_bps / eff_min
        imbalance_min_bps = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_MIN_BPS", "2097152"))
        imbalance_warn_ratio = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_RATIO_WARN", "10.0"))
        traffic_imbalance = max_bps >= imbalance_min_bps and imb_ratio >= imbalance_warn_ratio
        traffic_direction = "outbound_heavy" if tx_bps > rx_bps else "inbound_heavy" if rx_bps > tx_bps else "balanced"

        sec_data = payload.get("security", {})
        hy2_data = sec_data.get("hy2_protocol", {}) if isinstance(sec_data, dict) else {}
        hy2_detected = bool(hy2_data.get("detected"))
        hy2_concurrency = int(hy2_data.get("udp_concurrency") or 0)
        udp_throttle = sec_data.get("udp_throttle", {}) if isinstance(sec_data, dict) else {}
        udp_throttled = bool(udp_throttle.get("throttled"))
        udp_throttle_rate_mbps = int(udp_throttle.get("rate_mbps") or 10)
        udp_throttle_remaining_seconds = int(udp_throttle.get("remaining_seconds") or 0)
        udp_throttle_violation_count = int(udp_throttle.get("violation_count") or 0)

        out.append({
            "host_id": r["host_id"],
            "agent_version": str(payload.get("_agent_version") or "unknown"),
            "container_id": payload.get("id", ""),
            "user_email": note.get("user_email", "") if can_view_user_notes else "",
            "user_note": note.get("user_note", "") if can_view_user_notes else "",
            "container_name": r["container_name"],
            "runtime": r["runtime"],
            "project": r["project"],
            "monitor_mode": str(payload.get("monitor_mode") or "full"),
            "cpu_percent": r["cpu_percent"],
            "mem_bytes": r["mem_bytes"],
            "mem_limit_bytes": int(payload.get("mem_limit_bytes") or 0),
            "mem_percent": float(r["mem_percent"] or 0),
            "cpu_effective_cpus": float(payload.get("cpu_effective_cpus") or 0),
            "net_rx_bps": rx_bps,
            "net_tx_bps": tx_bps,
            "tcp_rx_bps": tcp_rx_bps,
            "tcp_tx_bps": tcp_tx_bps,
            "udp_rx_bps": udp_rx_bps,
            "udp_tx_bps": udp_tx_bps,
            "conn_count": conn_count,
            "tcp_country_stats": payload.get("tcp_country_stats", []),
            "udp_country_stats": payload.get("udp_country_stats", []),
            "security": payload.get("security", {}),
            "disk_file": r["disk_file"],
            "disk_used_percent": r["disk_used_percent"],
            "disk_root_device": host_disk.get("root_device") or disk.get("root_device", ""),
            "disk_root_total_bytes": host_disk.get("root_total_bytes") or disk.get("root_total_bytes", 0),
            "disk_root_used_percent": host_disk.get('root_used_percent',disk.get('root_used_percent')),
            "disk_root_avail_bytes": host_disk.get("root_avail_bytes") or disk.get("root_avail_bytes", 0),
            "disk_data_total_bytes": host_disk.get("data_total_bytes") or disk.get("data_total_bytes", 0),
            "disk_data_avail_bytes": host_disk.get("data_avail_bytes") or disk.get("data_avail_bytes", 0),
            "disk_data_requested_path": host_disk.get("data_requested_path") or disk.get("data_requested_path", "/"),
            "disk_data_mountpoint": host_disk.get("data_mountpoint") or disk.get("data_mountpoint", "/"),
            "container_disk_rw_bytes": container_disk.get("rw_bytes", 0),
            "container_disk_rootfs_bytes": container_disk.get("rootfs_bytes", 0),
            "container_fs_root_total_bytes": container_disk.get("fs", {}).get("root", {}).get("total_bytes", 0),
            "container_fs_root_avail_bytes": container_disk.get("fs", {}).get("root", {}).get("avail_bytes", 0),
            "container_fs_data_total_bytes": container_disk.get("fs", {}).get("data", {}).get("total_bytes", 0),
            "container_fs_data_avail_bytes": container_disk.get("fs", {}).get("data", {}).get("avail_bytes", 0),
            "top_cpu_process_pid": int(top_cpu_process.get("pid") or 0),
            "top_cpu_process_cpu_percent": float(top_cpu_process.get("cpu_percent") or 0),
            "top_cpu_process_command": str(top_cpu_process.get("command") or ""),
            "podman_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "podman_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "container_network_ok_v4": bool(r["podman_network_ok_v4"]),
            "container_network_ok_v6": bool(r["podman_network_ok_v6"]),
            "timestamp": r["ts"],
            "timestamp_iso": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(),
            "timestamp_iso_utc8": format_utc8(r["ts"]),
            "host_last_seen": host_last_seen,
            "host_last_seen_iso_utc8": format_utc8(host_last_seen),
            "host_offline_seconds": max(0, now - host_last_seen),
            "offline_seconds": stale_seconds,
            "offline_hours": offline_hours,
            "alerts": {
                "disk": alert_disk,
                "cpu": alert_cpu,
                "conn": bool(conn_severity),
                "conn_severity": conn_severity,
                "conn_warning_threshold": ALERT_CONN_WARNING_THRESHOLD,
                "conn_critical_threshold": ALERT_CONN_CRITICAL_THRESHOLD,
                "traffic_imbalance": traffic_imbalance,
                "traffic_imbalance_ratio": round(imb_ratio, 1),
                "traffic_imbalance_direction": traffic_direction,
                "hy2_detected": hy2_detected,
                "hy2_concurrency": hy2_concurrency,
                "udp_throttled": udp_throttled,
                "udp_throttle_rate_mbps": udp_throttle_rate_mbps,
                "udp_throttle_remaining_seconds": udp_throttle_remaining_seconds,
                "udp_throttle_violation_count": udp_throttle_violation_count,
                "stale": stale,
                "host_stale": host_stale,
                "hidden_offline": hidden_offline,
                "network": (not r["podman_network_ok_v4"]) or (not r["podman_network_ok_v6"]),
            },
        })
    res_content = {"server_version": APP_VERSION, "items": out}
    return JSONResponse(content=res_content)


@app.get("/api/v1/containers/user-note")
def get_container_user_note(
    request: Request,
    host_id: str,
    runtime: str,
    container_name: str,
    container_id: str,
    project: str = "",
) -> JSONResponse:
    """Read private lookup metadata for one exact container instance."""
    if getattr(request.state, "dashboard_role", "") not in {"admin", "operator"}:
        raise HTTPException(status_code=403, detail="仅管理员或运维人员可查询用户邮箱与备注")

    host_id = str(host_id or "").strip()
    runtime = str(runtime or "").strip().lower()
    project = str(project or "").strip()
    container_name = str(container_name or "").strip()
    container_id = str(container_id or "").strip()
    if runtime not in {"incus", "podman"}:
        raise HTTPException(status_code=400, detail="仅支持 Incus 和 Podman 容器")
    if (not host_id or len(host_id) > 255 or not container_name or len(container_name) > 255
            or not container_id or len(container_id) > 255 or len(project) > 255):
        raise HTTPException(status_code=400, detail="主机或容器实例标识无效")

    conn = db()
    try:
        row = conn.execute(
            """
            SELECT user_email, user_note, updated_at
            FROM container_user_notes
            WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND container_id=?
            """,
            (host_id, runtime, project, container_name, container_id),
        ).fetchone()
    finally:
        conn.close()

    return JSONResponse({
        "ok": True,
        "found": row is not None,
        "host_id": host_id,
        "runtime": runtime,
        "project": project,
        "container_name": container_name,
        "container_id": container_id,
        "user_email": row["user_email"] if row else "",
        "user_note": row["user_note"] if row else "",
        "updated_at": int(row["updated_at"] or 0) if row else 0,
    })


@app.post("/api/v1/containers/user-note")
async def save_container_user_note(request: Request) -> JSONResponse:
    """Save private dashboard lookup metadata for the current Incus/Podman instance."""
    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="请求内容不是有效 JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求内容格式无效")

    host_id = str(payload.get("host_id") or "").strip()
    runtime = str(payload.get("runtime") or "").strip().lower()
    project = str(payload.get("project") or "").strip()
    container_name = str(payload.get("container_name") or "").strip()
    container_id = str(payload.get("container_id") or "").strip()
    user_email = str(payload.get("user_email") or "").strip()
    user_note = str(payload.get("user_note") or "").strip()

    if runtime not in {"incus", "podman"}:
        raise HTTPException(status_code=400, detail="仅支持 Incus 和 Podman 容器")
    if not host_id or len(host_id) > 255 or not container_name or len(container_name) > 255:
        raise HTTPException(status_code=400, detail="主机或容器标识无效")
    if len(project) > 255 or not container_id or len(container_id) > 255:
        raise HTTPException(status_code=400, detail="容器实例 ID 无效，请刷新容器详情后重试")
    if len(user_email) > 254 or (user_email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+", user_email)):
        raise HTTPException(status_code=400, detail="请输入有效的用户邮箱（最多 254 个字符）")
    if len(user_note) > 500:
        raise HTTPException(status_code=400, detail="备注不能超过 500 个字符")

    now = int(time.time())
    conn = db()
    try:
        host = conn.execute("SELECT last_seen FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        row = conn.execute(
            """
            SELECT ts, payload_json FROM reports
            WHERE host_id=? AND runtime=? AND project=? AND container_name=?
            ORDER BY ts DESC, id DESC LIMIT 1
            """,
            (host_id, runtime, project, container_name),
        ).fetchone()
        if not row or now - int(row["ts"]) > STALE_SECONDS:
            raise HTTPException(status_code=409, detail="容器数据已过期或不存在，请刷新后重试")
        if host and now - int(host["last_seen"]) > STALE_SECONDS:
            raise HTTPException(status_code=409, detail="主机已离线，请恢复上报后再编辑备注")
        current_payload = json.loads(row["payload_json"] or "{}")
        if str(current_payload.get("id") or "") != container_id:
            raise HTTPException(status_code=409, detail="容器实例已变化，请刷新详情后重新编辑，避免备注错配")

        note_key = (host_id, runtime, project, container_name, container_id)
        if not user_email and not user_note:
            conn.execute(
                "DELETE FROM container_user_notes WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND container_id=?",
                note_key,
            )
        else:
            conn.execute(
                """
                INSERT INTO container_user_notes(
                    host_id, runtime, project, container_name, container_id,
                    user_email, user_note, updated_at, updated_by
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(host_id, runtime, project, container_name, container_id)
                DO UPDATE SET user_email=excluded.user_email, user_note=excluded.user_note,
                    updated_at=excluded.updated_at, updated_by=excluded.updated_by
                """,
                (*note_key, user_email, user_note, now,
                 str(getattr(request.state, "dashboard_user", "dashboard"))[:100]),
            )
        conn.commit()
    finally:
        conn.close()

    return JSONResponse({"ok": True, "user_email": user_email, "user_note": user_note})


@app.get("/api/v1/history")
def history(host_id: str, container_name: str, runtime: str = "", project: str = "", minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 1440))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
    if runtime:
        rows = conn.execute(
            """
            SELECT ts, cpu_percent, mem_percent, net_rx_bps, net_tx_bps, conn_count, payload_json
            FROM reports
            WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND ts>=?
            ORDER BY ts ASC
            """,
            (host_id, runtime, project, container_name, start_ts),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT ts, cpu_percent, mem_percent, net_rx_bps, net_tx_bps, conn_count, payload_json
            FROM reports
            WHERE host_id=? AND container_name=? AND ts>=?
            ORDER BY ts ASC
            """,
            (host_id, container_name, start_ts),
        ).fetchall()
    conn.close()

    items = []
    for r in rows:
        rx = float(r["net_rx_bps"] or 0)
        tx = float(r["net_tx_bps"] or 0)
        payload = json.loads(r["payload_json"]) if r["payload_json"] else {}
        items.append({
            "timestamp": r["ts"],
            "timestamp_iso_utc8": format_utc8(r["ts"]),
            "agent_version": report_agent_version(r["payload_json"]),
            "cpu_percent": r["cpu_percent"],
            "mem_percent": r["mem_percent"],
            "net_rx_bps": rx,
            "net_tx_bps": tx,
            "tcp_rx_bps": float(payload.get("tcp_rx_bps", rx) or 0.0),
            "tcp_tx_bps": float(payload.get("tcp_tx_bps", tx) or 0.0),
            "udp_rx_bps": float(payload.get("udp_rx_bps", 0.0) or 0.0),
            "udp_tx_bps": float(payload.get("udp_tx_bps", 0.0) or 0.0),
            "conn_count": r["conn_count"],
        })
    return JSONResponse(content={"items": items})


def _latest_deep_sample(
    conn: sqlite3.Connection,
    host_id: str,
    runtime: str,
    project: str,
    container_name: str,
) -> Dict[str, Any] | None:
    rows = conn.execute(
        """
        SELECT ts, payload_json FROM reports
        WHERE host_id=? AND runtime=? AND project=? AND container_name=?
        ORDER BY ts DESC LIMIT 100
        """,
        (host_id, runtime, project, container_name),
    ).fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            continue
        sample = payload.get("deep_sample") if isinstance(payload, dict) else None
        if isinstance(sample, dict):
            result = dict(sample)
            result["report_timestamp"] = int(row["ts"])
            result["report_timestamp_utc8"] = format_utc8(int(row["ts"]))
            result["agent_version"] = str(payload.get("_agent_version") or "unknown")
            return result
    return None


@app.post("/api/v1/containers/diagnostics")
async def request_container_diagnostic(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid JSON body")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    host_id = str(payload.get("host_id") or "")[:200]
    runtime = str(payload.get("runtime") or "")[:40].lower()
    project = str(payload.get("project") or "")[:100]
    container_name = str(payload.get("container_name") or "")[:200]
    if not host_id or not container_name or runtime not in ("incus", "podman"):
        raise HTTPException(status_code=400, detail="Incus or Podman container identity is required")

    conn = db()
    latest = conn.execute(
        """
        SELECT ts, payload_json FROM reports
        WHERE host_id=? AND runtime=? AND project=? AND container_name=?
        ORDER BY ts DESC LIMIT 1
        """,
        (host_id, runtime, project, container_name),
    ).fetchone()
    if latest is None:
        conn.close()
        raise HTTPException(status_code=404, detail="container not found")
    sample_age = max(0, int(time.time()) - int(latest["ts"] or 0))
    if sample_age > STALE_SECONDS:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail=(
                f"容器采样已过期（{sample_age // 60} 分钟未上报），"
                "无法下发深度采样；请确认容器仍在运行并恢复监控后重试"
            ),
        )
    try:
        latest_payload = json.loads(latest["payload_json"] or "{}")
    except (TypeError, ValueError):
        latest_payload = {}
    if str(latest_payload.get("monitor_mode") or "full") != "full":
        conn.close()
        raise HTTPException(status_code=409, detail="container is not in full monitoring mode")

    existing = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE alert_id=0 AND host_id=? AND runtime=? AND project=? AND container_name=?
          AND action_type='request_deep_sample' AND status IN ('queued','dispatched')
        ORDER BY id DESC LIMIT 1
        """,
        (host_id, runtime, project, container_name),
    ).fetchone()
    queued = existing is None
    if existing is None:
        now = int(time.time())
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
                "request_deep_sample",
                json.dumps({"sample_seconds": 1.0, "process_limit": 100, "socket_limit": 250, "evidence_schema": 5}),
                str(getattr(request.state, "dashboard_user", "dashboard"))[:100],
                now,
                now,
            ),
        )
        existing = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
        conn.commit()
    result = _action_item(existing)
    conn.close()
    return JSONResponse(status_code=202 if queued else 200, content={"ok": True, "queued": queued, "action": result})


@app.get("/api/v1/containers/diagnostics")
def container_diagnostic_status(
    host_id: str, runtime: str, container_name: str, project: str = ""
) -> JSONResponse:
    conn = db()
    action = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE alert_id=0 AND host_id=? AND runtime=? AND project=? AND container_name=?
          AND action_type='request_deep_sample'
        ORDER BY id DESC LIMIT 1
        """,
        (host_id[:200], runtime[:40].lower(), project[:100], container_name[:200]),
    ).fetchone()
    sample = _latest_deep_sample(conn, host_id[:200], runtime[:40].lower(), project[:100], container_name[:200])
    now = int(time.time())
    history_reference = now
    if isinstance(sample, dict):
        try:
            candidate = int(sample.get("sampled_at") or sample.get("report_timestamp") or now)
            if 0 < candidate <= now:
                history_reference = candidate
        except (TypeError, ValueError, OverflowError):
            pass
    history_rows = conn.execute(
        """
        SELECT ts, payload_json FROM reports
        WHERE host_id=? AND runtime=? AND project=? AND container_name=?
          AND ts>=? AND ts<=?
        ORDER BY ts DESC LIMIT ?
        """,
        (
            host_id[:200],
            runtime[:40].lower(),
            project[:100],
            container_name[:200],
            history_reference - inbound_assessment.LOOKBACK_SECONDS,
            history_reference,
            inbound_assessment.MAX_REPORTS,
        ),
    ).fetchall()
    source_history = inbound_assessment.assess(history_rows, now=history_reference)
    source_history["reference_sample_at"] = history_reference
    if sample is not None:
        sample["inbound_source_history"] = source_history
    conn.close()
    return JSONResponse(content={"action": _action_item(action) if action is not None else None, "sample": sample})


def _action_item(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        params = json.loads(row["params_json"] or "{}")
    except (TypeError, ValueError):
        params = {}
    if row["action_type"] in {"apply_container_connlimit", "release_container_connlimit"}:
        # Stable IDs, node identities, metric epochs and release capabilities
        # are sent only through the signed agent channel, never to browsers.
        params = {
            key: params[key]
            for key in ("max_connections", "lease_expires_at")
            if key in params
        }
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
        "created_at_utc8": format_utc8(int(row["created_at"])),
        "updated_at": int(row["updated_at"]),
        "updated_at_utc8": format_utc8(int(row["updated_at"])),
    }


def _decision_item(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": int(row["id"]),
        "alert_id": int(row["alert_id"]),
        "decision": row["decision"],
        "requested_by": row["requested_by"],
        "created_at": int(row["created_at"]),
        "created_at_utc8": format_utc8(int(row["created_at"])),
    }


def _security_alert_item(conn: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
    recovery = buyer_notifications.recovery(conn, row)
    for field in ('recovered_at', 'closed_at'):
        recovery[field + '_utc8'] = format_utc8(recovery[field]) if recovery[field] else None
    latest_action = _latest_action_for_alert(conn, row)
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
        deep_evidence = _alert_details(evidence_row["evidence_json"])
        deep_evidence["captured_at"] = int(evidence_row["captured_at"])
        deep_evidence["captured_at_utc8"] = format_utc8(int(evidence_row["captured_at"]))
    return {
        "id": int(row["id"]),
        "host_id": row["host_id"],
        "runtime": row["runtime"],
        "project": row["project"],
        "container_name": row["container_name"],
        "type": row["alert_type"],
        "protection_only": buyer_notifications.is_protection_only_alert(row),
        "severity": row["severity"],
        "title": row["title"],
        "message": row["message"],
        "value": float(row["value"] or 0),
        "threshold": float(row["threshold"] or 0),
        "first_seen": int(row["first_seen"]),
        "first_seen_utc8": format_utc8(int(row["first_seen"])),
        "last_seen": int(row["last_seen"]),
        "last_seen_utc8": format_utc8(int(row["last_seen"])),
        "occurrence_count": int(row["occurrence_count"]),
        "status": row["status"],
        "recovery": recovery,
        "details": _alert_action_evidence(row),
        "deep_evidence": deep_evidence,
        "latest_action": _action_item(latest_action) if latest_action is not None else None,
        "latest_decision": (
            _decision_item(latest_decision) if latest_decision is not None else None
        ),
    }


def _remediation_changed(message: str) -> bool:
    counts = {
        key: int(value)
        for key, value in re.findall(
            r"\b(killed_processes|removed_services|removed_configs|removed_binaries|cleanup_errors|matched_processes|signal_errors|host_matched_processes|host_killed_processes|host_kill_errors|checked_configs)=(\d+)\b",
            message,
        )
    }
    no_process_targets = re.search(r"\bno_process_targets=1\b", message) is not None
    process_scan = (
        ("matched_processes" in counts or "host_matched_processes" in counts)
        and not no_process_targets
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
    changed = sum(
        counts.get(key, 0)
        for key in (
            "killed_processes", "removed_services", "removed_configs", "removed_binaries"
        )
    ) > 0
    if errors > 0:
        return False
    if changed:
        return True
    no_process_targets = re.search(r"\bno_process_targets=1\b", message) is not None
    process_scan = (
        ("matched_processes" in counts or "host_matched_processes" in counts)
        and not no_process_targets
    ) or (no_process_targets and counts.get("checked_configs", 0) > 0)
    return (
        process_scan
        and "cleanup_errors" in counts
        and counts["cleanup_errors"] == 0
        and "signal_errors" in counts
        and counts["signal_errors"] == 0
        and remaining_zero
    )


def _alert_details(raw: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _alert_action_evidence(alert: sqlite3.Row) -> Dict[str, Any]:
    """Return structured evidence, including alerts reported by older agents."""
    details = _alert_details(alert["details_json"])
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
    process_pids = sorted(
        {
            int(item)
            for item in details.get("process_pids", [])
            if isinstance(item, int) and 1 < item <= 4194304
        }
    ) if isinstance(details.get("process_pids"), list) else []
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
    # Older clients used ``weak``/``weak-auth`` and some reports called this
    # field ``socks_auth_state``.  Keep the enforcement contract canonical so
    # those alerts can still be handled safely without accepting arbitrary
    # user supplied process names.
    raw_auth_mode = str(
        details.get("socks_auth_mode") or details.get("socks_auth_state") or "unknown"
    ).strip().lower().replace("-", "_").replace(" ", "_")
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
        item.lower()
        for item in clean(details.get("socks_processes"))
        if item.lower() in allowed_socks_processes
    ]
    # A short-lived compatibility window for pre-1.6 clients which retained
    # process_matches but did not copy the safe process list into the alert.
    # Only allowlisted executable names and confirmed weak states are retained.
    legacy_matches = details.get("socks_process_matches")
    if isinstance(legacy_matches, list) and not details.get('socks_action_scope_verified'):
        for item in legacy_matches:
            if not isinstance(item, dict):
                continue
            process = str(item.get("process") or "").strip().lower()
            state = str(item.get("auth_state") or item.get("auth_mode") or details["socks_auth_mode"])
            state = auth_mode_aliases.get(
                state.strip().lower().replace("-", "_").replace(" ", "_"), "unknown"
            )
            if process in allowed_socks_processes and state in ("no_auth", "weak_password"):
                socks_processes.append(process)
    socks_processes = sorted(set(socks_processes))
    if (
        not socks_processes
        and details["socks_auth_mode"] in ("no_auth", "weak_password")
        and not details.get('socks_action_scope_verified')
    ):
        process_match = re.search(
            r"(?:^|[；;，,\n])\s*(?:进程|process)\s*(?:[:=：])?\s*([^；;，,\n]+)",
            message,
            flags=re.IGNORECASE,
        )
        message_processes = (
            re.split(r"[,，\s]+", process_match.group(1).strip())
            if process_match
            else []
        )
        socks_processes = sorted(
            {
                item.lower()
                for item in message_processes
                if item.lower() in allowed_socks_processes
            }
        )
    details["socks_processes"] = socks_processes
    details["socks_process_pids"] = sorted(
        {
            int(item)
            for item in details.get("socks_process_pids", [])
            if isinstance(item, int) and 1 < item <= 4194304
        }
    ) if isinstance(details.get("socks_process_pids"), list) else []
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
                malicious_processes.append(
                    {"process": process, "pid": pid if 1 < pid <= 4194304 else 0}
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
    return details


@app.post("/api/v1/update/version")
async def agent_update_version(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    """Return the running Server version to an authenticated Client updater."""
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    try:
        payload = json.loads(body or b"{}")
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid JSON body")
    expected_version = str(payload.get("expected_version") or "")[:80]
    if expected_version and not re.fullmatch(
        r"\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?", expected_version
    ):
        raise HTTPException(status_code=400, detail="invalid expected version")
    return signed_json_response(
        {
            "ok": True,
            "server_version": APP_VERSION,
            "expected_version": expected_version,
            "ready": not expected_version or APP_VERSION == expected_version,
        },
        x_timestamp,
    )


def _queue_security_action_row(
    conn: sqlite3.Connection,
    alert: sqlite3.Row,
    action_type: str,
    params: Dict[str, Any],
    requested_by: str,
) -> tuple[sqlite3.Row, bool]:
    existing = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE alert_id=? AND action_type=? AND status IN ('queued','dispatched')
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
            alert["id"], alert["host_id"], alert["runtime"], alert["project"],
            alert["container_name"], action_type, json.dumps(params, ensure_ascii=False),
            requested_by[:100], now, now,
        ),
    )
    row = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
    return row, True


def _fresh_connlimit_identity(
    conn: sqlite3.Connection, alert: sqlite3.Row, now: int, max_connections: int
) -> tuple[str, str, Dict[str, Any]]:
    host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (alert["host_id"],)).fetchone()
    if host is None or not str(host["node_id"] or "") or now - int(host["last_seen"] or 0) > STALE_SECONDS:
        raise HTTPException(status_code=409, detail="该节点尚未注册可校验的 Client 身份")
    latest = conn.execute(
        "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime='incus' AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
        (alert["host_id"], alert["project"], alert["container_name"]),
    ).fetchone()
    if latest is None or now - int(latest["ts"] or 0) > STALE_SECONDS:
        raise HTTPException(status_code=409, detail="节点或容器采样已过期；为避免对错误实例执行防火墙操作，未下发")
    try:
        payload = json.loads(latest["payload_json"] or "{}")
    except (TypeError, ValueError):
        payload = {}
    stable_id = str(payload.get("stable_id") or "") if isinstance(payload, dict) else ""
    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", stable_id):
        raise HTTPException(status_code=409, detail="最新采样没有有效的 Incus 实例 UUID；未下发")
    metrics = connection_policy.metrics(payload, now) if isinstance(payload, dict) else None
    if not isinstance(metrics, dict):
        raise HTTPException(status_code=409, detail="最新连接证据未通过完整性校验；未下发")
    sampled_at = metrics.get("sampled_at")
    epoch = metrics.get("epoch")
    tcp_established = metrics.get("tcp_established")
    tcp_pending = metrics.get("tcp_pending")
    if (
        type(sampled_at) is not int or sampled_at > now + 30 or now - sampled_at > STALE_SECONDS
        or not isinstance(epoch, str) or not epoch or len(epoch) > 200
        or type(tcp_established) is not int or type(tcp_pending) is not int
        or tcp_established < 0 or tcp_pending < 0
    ):
        raise HTTPException(status_code=409, detail="TCP 连接证据缺失或过期；未下发")
    observed_tcp = tcp_established + tcp_pending
    if observed_tcp <= max_connections:
        raise HTTPException(
            status_code=409,
            detail=f"当前已建立/待建立 TCP 连接为 {observed_tcp}，未超过限额 {max_connections}；该规则不限制 UDP，未下发",
        )
    return str(host["node_id"]), stable_id.lower(), {
        "metric_epoch": epoch,
        "observed_tcp_connections": observed_tcp,
        "observed_at": sampled_at,
        "action_expires_at": now + 300,
    }


def _latest_action_for_alert(
    conn: sqlite3.Connection, alert: sqlite3.Row
) -> sqlite3.Row | None:
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
        (
            alert["host_id"],
            alert["runtime"],
            alert["project"],
            alert["container_name"],
        ),
    ).fetchone()


def _refresh_remediation_process_pids(
    conn: sqlite3.Connection, action: sqlite3.Row
) -> Dict[str, Any]:
    try:
        params = json.loads(action["params_json"] or "{}")
    except (TypeError, ValueError):
        params = {}
    if action["action_type"] != "remediate_panel_pairing" or not isinstance(params, dict):
        return params if isinstance(params, dict) else {}
    alert = conn.execute(
        "SELECT * FROM security_alerts WHERE id=?", (action["alert_id"],)
    ).fetchone()
    if alert is None:
        return params
    evidence = _alert_action_evidence(alert)
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


@app.post("/api/v1/security/alerts/{alert_id}/actions")
async def queue_security_action(alert_id: int, request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    requested_action = str(payload.get("action") or "").strip().lower()
    if requested_action == "allow" and getattr(request.state,"dashboard_role","admin") != "admin":
        raise HTTPException(status_code=403,detail="只有管理员可以修改长期放行策略")
    action_type = {"remediate": "remediate_panel_pairing", "allow": "allow_panel_domains"}.get(
        requested_action
    )
    if not action_type:
        raise HTTPException(status_code=400, detail="action must be remediate or allow")

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        raise HTTPException(status_code=404, detail="alert not found")
    if alert["status"] != "active":
        conn.close()
        raise HTTPException(status_code=409, detail="alert is no longer active")
    if alert["alert_type"] != "unauthorized_panel_pairing":
        conn.close()
        raise HTTPException(status_code=400, detail="this action only supports panel-pairing alerts")
    if alert["runtime"] not in ("podman", "incus"):
        conn.close()
        raise HTTPException(status_code=400, detail="Docker and unknown runtimes are notice-only")
    if not alert["container_name"]:
        conn.close()
        raise HTTPException(status_code=400, detail="alert has no container target")

    details = _alert_action_evidence(alert)
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
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no exact domains to allow")
        params = {"domains": sorted(set(unapproved_domains))}
    else:
        if not process_patterns and not config_files:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
        params = {
            "domains": sorted(set(unapproved_domains)),
            "process_patterns": sorted(set(process_patterns)),
            "process_pids": process_pids,
            "config_files": sorted(set(config_files)),
        }

    requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
    row, queued = _queue_security_action_row(conn, alert, action_type, params, requested_by)
    investigation.sync_states(conn, alert['host_id'], int(time.time()), alert_id=alert['id'])
    conn.commit()
    conn.close()
    return JSONResponse(
        status_code=202 if queued else 200,
        content={"ok": True, "queued": queued, "action": _action_item(row)},
    )


@app.post("/api/v1/security/alerts/{alert_id}/disposition")
async def set_security_alert_disposition(alert_id: int, request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")
    decision = str(payload.get("decision") or "").strip().lower()
    if decision == "allow_silent" and getattr(request.state,"dashboard_role","admin") != "admin":
        raise HTTPException(status_code=403,detail="只有管理员可以修改长期放行策略")
    if decision not in ("deny", "allow_silent", "dismiss_once", "reopen", "resolve", "release_udp_throttle", "apply_udp_throttle", "stop_reviewed_socks", "apply_container_connlimit", "release_container_connlimit"):
        raise HTTPException(
            status_code=400,
            detail="unsupported alert disposition",
        )

    conn = db()
    conn.execute("BEGIN IMMEDIATE")
    alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        raise HTTPException(status_code=404, detail="alert not found")
    if alert['alert_type'] == 'prohibited_activity' and decision != 'reopen':
        conn.close()
        raise HTTPException(status_code=409, detail='隔离事件必须由管理员复核后，通过解除隔离入口处理；不能用忽略、静默或标记恢复替代。')
    if alert["status"] != "active" and decision not in ("deny", "reopen", "allow_silent", "resolve", "release_udp_throttle", "apply_udp_throttle", "release_container_connlimit"):
        conn.close()
        raise HTTPException(status_code=409, detail="alert is no longer active")

    requested_by = str(
        getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard")
    )[:100]
    now = int(time.time())
    action = None
    queued = False
    if decision == 'stop_reviewed_socks':
        details = json.loads(alert['details_json'])
        reviews = details.get('password_review', [])
        observed = details.get('review_observed_at', 0)
        token = details.get('review_token', '')
        if (alert['alert_type'] != 'socks_password_review' or alert['status'] != 'active'
            or alert['runtime'] not in {'incus', 'podman'} or not isinstance(observed, (int, float))
            or not 0 <= now-observed <= 900 or not 0 <= now-alert['last_seen'] <= 900
            or not isinstance(reviews, list) or not reviews or not all(isinstance(r, dict) and r.get('action_safe') is True for r in reviews)
            or not re.fullmatch(r'[0-9a-f]{64}', str(token)) or payload.get('review_token') != token):
            conn.close()
            raise HTTPException(status_code=409, detail='证据过期、目标不明确或包含混合业务；请刷新后重新审核，未停止服务')
        action, queued = _queue_security_action_row(conn, alert, 'stop_reviewed_socks',
            {'manual_review': True, 'review_token': token, 'review_observed_at': observed}, requested_by)
    elif decision == "deny":
        if alert["alert_type"] not in _ACTIONABLE_ALERT_TYPES:
            conn.close()
            raise HTTPException(
                status_code=400,
                detail=(
                    "deny supports panel-pairing, confirmed no-auth SOCKS, "
                    "and exact XMRig alerts"
                ),
            )
        if alert["runtime"] not in ("podman", "incus"):
            conn.close()
            raise HTTPException(status_code=400, detail="Docker is notice-only and cannot be denied")
        if not alert["container_name"]:
            conn.close()
            raise HTTPException(status_code=400, detail="alert has no container target")
        conn.execute(
            "DELETE FROM security_alert_policies WHERE fingerprint=?",
            (alert["fingerprint"],),
        )
        conn.execute("UPDATE security_alerts SET status='active' WHERE id=?", (alert_id,))
        details = _alert_action_evidence(alert)
        if alert["alert_type"] == "socks_weak_auth":
            if details.get("socks_auth_mode") not in ("no_auth", "weak_password"):
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="仅可处置已确认空密码或弱密码的 SOCKS 服务",
                )
            process_names = details.get("socks_processes") or []
            if not process_names:
                conn.close()
                raise HTTPException(status_code=400, detail="alert has no safe SOCKS process evidence")
            params = {
                "auth_mode": details["socks_auth_mode"],
                "process_names": process_names,
                "process_pids": details.get("socks_process_pids") or [],
                "config_files": details.get("socks_config_files") or [],
            }
            action, queued = _queue_security_action_row(
                conn, alert, "enforce_socks_auth", params, requested_by
            )
        elif alert["alert_type"] == "unauthorized_panel_pairing":
            process_patterns = details.get("process_patterns") or []
            process_pids = details.get("process_pids") or []
            config_files = details.get("config_files") or []
            if not process_patterns and not config_files:
                conn.close()
                raise HTTPException(status_code=400, detail="alert has no safe remediation evidence")
            params = {
                "domains": details.get("unapproved_domains") or [],
                "process_patterns": process_patterns,
                "process_pids": process_pids,
                "config_files": config_files,
            }
            action, queued = _queue_security_action_row(
                conn, alert, "remediate_panel_pairing", params, requested_by
            )
        else:
            malicious_processes = details.get("malicious_processes") or []
            exact_xmrig = [
                item for item in malicious_processes
                if isinstance(item, dict) and item.get("process") == "xmrig"
            ]
            if not exact_xmrig:
                conn.close()
                raise HTTPException(
                    status_code=400,
                    detail="alert has no exact XMRig process evidence",
                )
            process_pids = []
            for item in exact_xmrig:
                try:
                    process_pid = int(item.get("pid") or 0)
                except (TypeError, ValueError):
                    continue
                if 1 < process_pid <= 4194304:
                    process_pids.append(process_pid)
            params = {
                "process_names": ["xmrig"],
                "process_pids": sorted(set(process_pids)),
            }
            action, queued = _queue_security_action_row(
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
        if alert["alert_type"] == "unauthorized_panel_pairing" and alert["runtime"] in ("podman", "incus"):
            details = _alert_action_evidence(alert)
            domains = details.get("unapproved_domains") or []
            if domains:
                action, queued = _queue_security_action_row(
                    conn, alert, "allow_panel_domains", {"domains": domains}, requested_by
                )
        elif alert["alert_type"] == "socks_weak_auth" and alert["runtime"] in ("podman", "incus"):
            action, queued = _queue_security_action_row(
                conn, alert, "release_socks_auth", {}, requested_by
            )
    elif decision == "dismiss_once":
        conn.execute("UPDATE security_alerts SET status='dismissed' WHERE id=?", (alert_id,))
    elif decision == "resolve":
        conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (alert_id,))
    elif decision == "release_udp_throttle":
        conn.execute("UPDATE security_alerts SET status='resolved' WHERE id=?", (alert_id,))
        action, queued = _queue_security_action_row(
            conn, alert, "release_udp_throttle", {}, requested_by
        )
    elif decision == "apply_udp_throttle":
        action, queued = _queue_security_action_row(
            conn, alert, "apply_udp_throttle", {"rate_mbps": 10, "duration": 3600}, requested_by
        )
    elif decision in ("apply_container_connlimit", "release_container_connlimit"):
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            conn.close()
            raise HTTPException(status_code=403, detail="只有管理员可以修改容器连接限制")
        if (
            alert["alert_type"] != "container_connection_count"
            or alert["runtime"] != "incus"
            or alert["project"] != "default"
            or not alert["container_name"]
        ):
            conn.close()
            raise HTTPException(status_code=400, detail="临时 TCP 限额仅适用于 default 项目内的 Incus 连接数告警")
        if decision == "apply_container_connlimit":
            raw_limit = payload.get("max_connections", 500)
            raw_duration = payload.get("duration_seconds", 1800)
            if type(raw_limit) is not int or not 100 <= raw_limit <= 10000:
                conn.close()
                raise HTTPException(status_code=400, detail="TCP 连接限额必须在 100–10000 之间")
            if type(raw_duration) is not int or not 300 <= raw_duration <= 3600:
                conn.close()
                raise HTTPException(status_code=400, detail="限额有效期必须在 300–3600 秒之间")
            try:
                node_id, instance_id, evidence = _fresh_connlimit_identity(conn, alert, now, raw_limit)
            except HTTPException:
                conn.close()
                raise
            active = conn.execute(
                "SELECT params_json,status FROM security_actions WHERE host_id=? AND runtime='incus' AND project='default' AND container_name=? AND action_type='apply_container_connlimit' AND status='succeeded' ORDER BY id DESC LIMIT 1",
                (alert["host_id"], alert["container_name"]),
            ).fetchone()
            if active is not None:
                try:
                    active_params = json.loads(active["params_json"] or "{}")
                except (TypeError, ValueError):
                    active_params = {}
                if not isinstance(active_params, dict) or not active_params.get("instance_id"):
                    conn.close()
                    raise HTTPException(status_code=409, detail="已有连接限制记录无法核实；为避免重复应用，请等待其自动过期")
                active_lease = active_params.get("lease_expires_at")
                if active_params.get("instance_id") == instance_id and type(active_lease) is not int:
                    conn.close()
                    raise HTTPException(status_code=409, detail="已有连接限制的过期时间无法核实；请等待节点自动清理")
                if active_params.get("instance_id") == instance_id and active_lease > now:
                    conn.close()
                    raise HTTPException(status_code=409, detail="该实例已有未过期的连接限制；请先解除或等待自动过期")
            params = {
                **evidence,
                "expected_node_id": node_id,
                "instance_id": instance_id,
                "policy_id": secrets.token_hex(16),
                "max_connections": raw_limit,
                "lease_expires_at": now + raw_duration,
                "reason": "admin_requested_connection_limit",
            }
            action, queued = _queue_security_action_row(
                conn, alert, "apply_container_connlimit", params, requested_by
            )
        else:
            latest = conn.execute(
                "SELECT * FROM security_actions WHERE alert_id=? AND action_type IN ('apply_container_connlimit','release_container_connlimit') ORDER BY id DESC LIMIT 1",
                (alert_id,),
            ).fetchone()
            if latest is None or latest["action_type"] != "apply_container_connlimit" or latest["status"] != "succeeded":
                conn.close()
                raise HTTPException(status_code=409, detail="没有可解除的已生效 TCP 限额")
            try:
                applied = json.loads(latest["params_json"] or "{}")
            except (TypeError, ValueError):
                applied = {}
            applied_lease = applied.get("lease_expires_at") if isinstance(applied, dict) else None
            if type(applied_lease) is not int or applied_lease <= now:
                conn.close()
                raise HTTPException(status_code=409, detail="该 TCP 限额已自动过期")
            host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (alert["host_id"],)).fetchone()
            if host is None or not host["node_id"] or now - int(host["last_seen"] or 0) > STALE_SECONDS:
                conn.close()
                raise HTTPException(status_code=409, detail="节点离线或身份不可校验；现有限额仍会由节点自动过期")
            params = {
                "expected_node_id": str(host["node_id"]),
                "instance_id": str(applied.get("instance_id") or ""),
                "policy_id": str(applied.get("policy_id") or ""),
                "action_expires_at": now + 300,
                "lease_expires_at": applied_lease,
            }
            if not re.fullmatch(r"[0-9a-f]{32}", params["policy_id"]) or not params["instance_id"]:
                conn.close()
                raise HTTPException(status_code=409, detail="已生效限额缺少安全撤销标识；等待自动过期")
            action, queued = _queue_security_action_row(
                conn, alert, "release_container_connlimit", params, requested_by
            )
    else:
        conn.execute(
            "DELETE FROM security_alert_policies WHERE fingerprint=?",
            (alert["fingerprint"],),
        )
        conn.execute("UPDATE security_alerts SET status='active' WHERE id=?", (alert_id,))
        if (
            alert["alert_type"] == "unauthorized_panel_pairing"
            and alert["runtime"] in ("podman", "incus")
        ):
            domains = _alert_action_evidence(alert).get("unapproved_domains") or []
            if domains:
                action, queued = _queue_security_action_row(
                    conn,
                    alert,
                    "disallow_panel_domains",
                    {"domains": domains},
                    requested_by,
                )

    conn.execute(
        """
        INSERT INTO security_alert_decisions(
            alert_id, fingerprint, decision, requested_by, created_at
        ) VALUES(?,?,?,?,?)
        """,
        (alert_id, alert["fingerprint"], decision, requested_by, now),
    )
    investigation.sync_states(conn, alert['host_id'], now, alert_id=alert['id'])
    conn.commit()
    conn.close()
    try:
        sync_configured_bot_alert_messages(alert_id=alert_id)
    except Exception as exc:
        print(f"telegram sync on disposition {alert_id} failed: {exc}")
    return JSONResponse(
        status_code=202 if action is not None and queued else 200,
        content={
            "ok": True,
            "decision": decision,
            "queued": queued,
            "action": _action_item(action) if action is not None else None,
        },
    )


@app.post("/api/v1/containers/disposition")
async def set_container_disposition(request: Request) -> JSONResponse:
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
        raise HTTPException(
            status_code=400, detail="host_id, runtime, and container_name are required"
        )
    if decision not in ("deny", "allow_silent", "dismiss_once", "reopen", "resolve", "release_udp_throttle", "apply_udp_throttle"):
        raise HTTPException(status_code=400, detail="invalid decision")

    conn = db()
    try:
        identity = (host_id, runtime, project, container_name)
        selected_alert_id = None
        if alert_id is not None:
            alert = conn.execute(
                "SELECT * FROM security_alerts WHERE id=?", (alert_id,)
            ).fetchone()
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
                or (
                    alert_identity[2]
                    and identity[2]
                    and alert_identity[2] != identity[2]
                )
            ):
                raise HTTPException(
                    status_code=409,
                    detail="alert_id 与目标主机、运行时、项目或容器不匹配",
                )
            selected_alert_id = int(alert["id"])
        else:
            # Never let a generic DDoS/connection alert win just because it is
            # newer than the actionable SOCKS/panel alert the user clicked.
            # The frontend normally sends alert_id; this fallback keeps the
            # drawer compatible with older clients.
            actionable_types = tuple(sorted(_ACTIONABLE_ALERT_TYPES))
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
                # Resolve is a generic acknowledgement action; it may be used
                # for a non-remediable telemetry alert from the drawer.
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
            return await set_security_alert_disposition(selected_alert_id, request)

        if decision in ("release_udp_throttle", "apply_udp_throttle"):
            now = int(time.time())
            action_type = decision
            params = {"rate_mbps": 10, "duration": 3600} if decision == "apply_udp_throttle" else {}
            requested_by = str(
                getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard")
            )[:100]
            cur = conn.execute(
                """
                INSERT INTO security_actions(
                    alert_id, host_id, runtime, project, container_name, action_type, params_json,
                    status, requested_by, created_at, updated_at
                ) VALUES(0,?,?,?,?,?,?,'queued',?,?,?)
                """,
                (host_id, runtime, project, container_name, action_type, json.dumps(params, ensure_ascii=False), requested_by, now, now),
            )
            action_row = conn.execute("SELECT * FROM security_actions WHERE id=?", (cur.lastrowid,)).fetchone()
            conn.commit()
            conn.close()
            return JSONResponse(
                status_code=202,
                content={
                    "ok": True,
                    "decision": decision,
                    "queued": True,
                    "action": _action_item(action_row) if action_row is not None else None,
                },
            )
        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="未找到该容器对应的可处置活动安全告警记录",
            )
        selected_alert_id = int(alert["id"])
    finally:
        conn.close()
    return await set_security_alert_disposition(selected_alert_id, request)


@app.get("/api/v1/hosts/{host_id:path}/firewall-policy")
def get_host_firewall_policy(host_id: str) -> JSONResponse:
    if not host_id or len(host_id) > 200:
        raise HTTPException(status_code=400, detail="主机标识无效")
    conn = db()
    try:
        now = int(time.time())
        host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        row = conn.execute("SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()
        if row is None:
            revision, policy, updated_by, updated_at, source_fleet_revision = 0, _empty_host_firewall_policy(), "", 0, 0
        else:
            try:
                policy = json.loads(row["policy_json"] or "{}")
            except (TypeError, ValueError):
                policy = _empty_host_firewall_policy()
            revision, updated_by, updated_at, source_fleet_revision = int(row["revision"]), str(row["updated_by"] or ""), int(row["updated_at"] or 0), int(row["source_fleet_revision"] or 0)
        action = _latest_host_firewall_action(conn, host_id)
        latest = None if action is None else {
            "id": int(action["id"]), "status": str(action["status"]),
            "message": str(action["result_message"] or ""),
            "updated_at_utc8": format_utc8(int(action["updated_at"] or 0)),
        }
        return JSONResponse({
            "host_id": host_id,
            "agent_ready": bool(str(host["node_id"] or "")),
            "revision": revision,
            "source_fleet_revision": source_fleet_revision,
            "policy": policy,
            "runtime_status": _host_firewall_runtime_status(conn, host_id, now),
            "interface_inventory": _host_firewall_interface_inventory(conn, host_id, now),
            "live_readback": _host_firewall_live_readback(conn, host_id, now),
            "updated_by": updated_by,
            "updated_at_utc8": format_utc8(updated_at) if updated_at else "",
            "latest_action": latest,
            "policy_history": [
                {
                    "revision": int(item["revision"]),
                    "policy": json.loads(item["policy_json"] or "{}"),
                    "updated_by": str(item["updated_by"] or ""),
                    "updated_at_utc8": format_utc8(int(item["updated_at"] or 0)),
                    "source_fleet_revision": int(item["source_fleet_revision"] or 0),
                }
                for item in conn.execute(
                    "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 20",
                    (host_id,),
                ).fetchall()
            ],
        })
    finally:
        conn.close()


def _prepare_host_firewall_recovery(conn: sqlite3.Connection, host_id: str, now: int):
    """Fail closed unless a single online host has fresh, compatible RFW readback."""
    host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (host_id,)).fetchone()
    if host is None:
        raise HTTPException(status_code=404, detail="主机不存在")
    node_id = str(host["node_id"] or "")
    if not node_id or now - int(host["last_seen"] or 0) > STALE_SECONDS:
        raise HTTPException(status_code=409, detail="母机离线或上报过期，未下发防火墙操作")
    fleet = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
    if fleet is not None and int(fleet["revision"] or 0) > 0:
        raise HTTPException(status_code=409, detail="全局策略模板已启用；请从全局策略入口处理，避免单机状态分叉")
    runtime = _host_firewall_runtime_status(conn, host_id, now)
    if runtime.get("stale"):
        raise HTTPException(status_code=409, detail="Runman 防火墙能力状态已过期；等待 Agent 重新上报后再操作")
    if runtime.get("control_api") != "ready":
        raise HTTPException(status_code=409, detail="Runman 防火墙控制接口尚未确认可用")
    readback = _host_firewall_live_readback(conn, host_id, now)
    if readback.get("status") != "ready" or readback.get("stale") or not isinstance(readback.get("snapshot"), dict):
        raise HTTPException(status_code=409, detail="RFW 实时读回缺失或已过期，未下发操作")
    if conn.execute(
        "SELECT 1 FROM security_actions WHERE host_id=? AND action_type IN ('apply_host_firewall_policy','delete_host_firewall_rule') AND status IN ('queued','dispatched','running') LIMIT 1",
        (host_id,),
    ).fetchone():
        raise HTTPException(status_code=409, detail="该主机已有防火墙操作正在执行")
    return node_id, readback


@app.post("/api/v1/firewall/host-policy/retry")
async def retry_host_firewall_policy(request: Request) -> JSONResponse:
    if getattr(request.state, "dashboard_role", "admin") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以重试母机防火墙策略")
    try:
        payload = json.loads(await request.body())
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="请求必须是有效 JSON") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求必须是 JSON 对象")
    host_id = str(payload.get("host_id") or "")[:200]
    if not host_id:
        raise HTTPException(status_code=400, detail="需要指定主机")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        action = _latest_host_firewall_action(conn, host_id)
        readback = _host_firewall_live_readback(conn, host_id, int(time.time()))
        if not action or (action["status"] != "failed" and not (readback.get("sync_status") == "drifted" and not readback.get("stale"))):
            raise HTTPException(status_code=409, detail="仅当最近应用失败或新鲜读回显示策略偏差时可重试")
        now = int(time.time())
        node_id, readback = _prepare_host_firewall_recovery(conn, host_id, now)
        current = conn.execute("SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()
        policy = _validate_host_firewall_policy(json.loads(current["policy_json"] or "{}")) if current else _empty_host_firewall_policy()
        materialized, target_state = _materialize_host_firewall_policy(conn, host_id, policy, now)
        if materialized is None:
            raise HTTPException(status_code=409, detail=f"目标网卡/运行时已不可验证（{target_state}），未下发重试")
        compatibility = _policy_protocol_compatibility(materialized, readback)
        if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
            raise HTTPException(status_code=409, detail="RFW 实时协议能力不满足当前策略，未下发重试")
        requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
        action_id = _enqueue_host_firewall_policy(conn, host_id, node_id, materialized, requested_by, now, 0)
        revision = int(conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()[0])
        conn.commit()
        return JSONResponse(status_code=202, content={"ok": True, "revision": revision, "action_id": action_id, "queued": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/api/v1/firewall/host-policy/rollback")
async def rollback_host_firewall_policy(request: Request) -> JSONResponse:
    if getattr(request.state, "dashboard_role", "admin") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以回滚母机防火墙策略")
    try:
        payload = json.loads(await request.body())
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="请求必须是有效 JSON") from None
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求必须是 JSON 对象")
    host_id = str(payload.get("host_id") or "")[:200]
    if not host_id:
        raise HTTPException(status_code=400, detail="需要指定主机")
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        history = conn.execute(
            "SELECT revision,policy_json FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if not history:
            raise HTTPException(status_code=409, detail="没有可回滚的历史策略")
        now = int(time.time())
        node_id, readback = _prepare_host_firewall_recovery(conn, host_id, now)
        try:
            previous = _validate_host_firewall_policy(json.loads(history["policy_json"] or "{}"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=409, detail="历史策略记录无效，未下发回滚") from None
        materialized, target_state = _materialize_host_firewall_policy(conn, host_id, previous, now)
        if materialized is None:
            raise HTTPException(status_code=409, detail=f"历史策略引用的网卡已无法验证（{target_state}），未下发回滚")
        compatibility = _policy_protocol_compatibility(materialized, readback)
        if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
            raise HTTPException(status_code=409, detail="RFW 实时协议能力不满足历史策略，未下发回滚")
        requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
        action_id = _enqueue_host_firewall_policy(conn, host_id, node_id, materialized, requested_by, now, 0)
        revision = int(conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()[0])
        conn.commit()
        return JSONResponse(status_code=202, content={"ok": True, "revision": revision, "restored_revision": int(history["revision"]), "action_id": action_id, "queued": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/api/v1/hosts/{host_id:path}/firewall-policy")
async def update_host_firewall_policy(host_id: str, request: Request) -> JSONResponse:
    if getattr(request.state, "dashboard_role", "admin") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以修改母机防火墙策略")
    if not host_id or len(host_id) > 200:
        raise HTTPException(status_code=400, detail="主机标识无效")
    raw_body = await request.body()
    if len(raw_body) > 128 * 1024:
        raise HTTPException(status_code=413, detail="防火墙配置超过 128 KiB")
    try:
        payload = json.loads(raw_body)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="防火墙配置必须是有效 JSON") from None
    policy = _validate_host_firewall_policy(payload)
    now = int(time.time())
    requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        fleet_template = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
        if fleet_template is not None and int(fleet_template["revision"] or 0) > 0:
            raise HTTPException(status_code=409, detail="全局防火墙模板已启用；请编辑全局模板，避免单机配置与统一期望策略冲突")
        host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        node_id = str(host["node_id"] or "")
        if not node_id:
            raise HTTPException(status_code=409, detail="该主机尚未注册可校验身份的 Watcher Agent")
        host_policy, target_status = _materialize_host_firewall_policy(conn, host_id, policy, now)
        if host_policy is None:
            message = "网卡清单尚未就绪或已过期，请刷新并等待母机重新上报后再应用。" if target_status == "inventory_unavailable" else "所选运行时/网卡未出现在母机最新采集到的 Incus / Podman bridge 中，请重新选择。"
            raise HTTPException(status_code=409, detail=message)
        policy = host_policy
        if _policy_required_protocols(policy):
            live_readback = _host_firewall_live_readback(conn, host_id, now)
            compatibility = _policy_protocol_compatibility(policy, live_readback)
            if compatibility["unsupported_protocols"]:
                names = ", ".join(compatibility["unsupported_protocols"])
                raise HTTPException(status_code=409, detail=f"该节点当前 RFW 不支持所选应用协议（运行中能力清单未包含）：{names}；请部署包含对应协议检测能力的 RFW 版本并更新节点，等待新鲜能力读回后再应用。仅更新 Watcher Agent 不会增加 RFW 协议支持")
            if compatibility["unknown_protocols"]:
                names = ", ".join(compatibility["unknown_protocols"])
                raise HTTPException(status_code=409, detail=f"该节点尚无所选应用协议的新鲜 RFW 能力读回：{names}；请先刷新并等待节点上报。若读回仍显示不支持，需部署包含对应协议检测能力的 RFW 版本")
        action_id = _enqueue_host_firewall_policy(conn, host_id, node_id, policy, requested_by, now, 0)
        revision_row = conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()
        revision = int(revision_row["revision"])
        conn.commit()
        return JSONResponse(status_code=202, content={"ok": True, "revision": revision, "action_id": action_id, "queued": True})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.delete("/api/v1/hosts/{host_id:path}/firewall-rules/{rule_id}")
async def delete_host_firewall_rule(host_id: str, rule_id: int, request: Request) -> JSONResponse:
    if getattr(request.state, "dashboard_role", "admin") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以删除母机 RFW 规则")
    if not host_id or len(host_id) > 200 or not 1 <= rule_id <= 2**63 - 1:
        raise HTTPException(status_code=400, detail="主机或 RFW 规则标识无效")

    now = int(time.time())
    requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        node_id = str(host["node_id"] or "")
        if not node_id:
            raise HTTPException(status_code=409, detail="该主机尚未注册可校验身份的 Watcher Agent")

        readback = _host_firewall_live_readback(conn, host_id, now)
        if readback.get("status") != "ready" or readback.get("stale") is not False:
            raise HTTPException(status_code=409, detail="RFW 规则读回已过期或不可用；刷新并等待母机重新上报后再删除")
        snapshot = readback.get("snapshot")
        if not isinstance(snapshot, dict):
            raise HTTPException(status_code=409, detail="没有可验证的当前 RFW 规则快照")
        rules = snapshot.get("rules") if isinstance(snapshot.get("rules"), list) else []
        target = next((
            rule for rule in rules
            if isinstance(rule, dict) and type(rule.get("id")) is int and rule["id"] == rule_id
        ), None)
        if target is None:
            raise HTTPException(status_code=404, detail="该规则已不在最近一次 RFW 读回中，请刷新列表")
        if target.get("origin") != "manual" or target.get("sync_state") != "manual":
            raise HTTPException(status_code=409, detail="平台管理规则请先在期望规则列表中移除，再保存并应用")

        expected_rule = {
            key: target[key]
            for key in (
                "id", "priority", "direction", "protocol", "action", "enabled",
                "port_start", "port_end", "ip_type", "origin", "sync_state",
            )
            if key in target
        }
        if "ip" in target:
            expected_rule["ip"] = target["ip"]
        if "countries" in target:
            expected_rule["countries"] = target["countries"]

        pending_rows = conn.execute(
            "SELECT id,params_json FROM security_actions WHERE host_id=? AND action_type='delete_host_firewall_rule' "
            "AND status IN ('queued','dispatched','running')",
            (host_id,),
        ).fetchall()
        for pending_row in pending_rows:
            try:
                pending_params = json.loads(pending_row["params_json"] or "{}")
            except (TypeError, ValueError):
                pending_params = {}
            pending_rule = pending_params.get("rule") if isinstance(pending_params, dict) else None
            if isinstance(pending_rule, dict) and pending_rule.get("id") == rule_id:
                conn.commit()
                return JSONResponse(status_code=202, content={
                    "ok": True, "rule_id": rule_id, "action_id": int(pending_row["id"]), "queued": True,
                })

        params = {"expected_node_id": node_id, "rule": expected_rule}
        cur = conn.execute(
            "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
            "VALUES(0,?,'host','','__host__','delete_host_firewall_rule',?,'queued',?,?,?)",
            (host_id, json.dumps(params, ensure_ascii=False), requested_by, now, now),
        )
        conn.commit()
        return JSONResponse(status_code=202, content={
            "ok": True, "rule_id": rule_id, "action_id": int(cur.lastrowid), "queued": True,
        })
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.get("/api/v1/firewall/fleet-policy")
def get_fleet_firewall_policy() -> JSONResponse:
    now = int(time.time())
    conn = db()
    try:
        template = conn.execute(
            "SELECT revision,policy_json,updated_by,updated_at FROM fleet_firewall_policy WHERE id=1"
        ).fetchone()
        if template is None:
            revision, policy, updated_by, updated_at = 0, _empty_host_firewall_policy(), "", 0
        else:
            try:
                policy = _validate_host_firewall_policy(json.loads(template["policy_json"] or "{}"))
            except (HTTPException, TypeError, ValueError):
                policy = _empty_host_firewall_policy()
            revision = int(template["revision"] or 0)
            updated_by = str(template["updated_by"] or "")
            updated_at = int(template["updated_at"] or 0)
        hosts = conn.execute(
            "SELECT host_id,node_id,last_seen,agent_version FROM hosts ORDER BY host_id"
        ).fetchall()
        required_protocols = _policy_required_protocols(policy)
        nodes = [
            _fleet_firewall_node_state(conn, host, revision, now, required_protocols, policy)
            for host in hosts
        ]
        readback_current = sum(1 for item in nodes if item["live_readback"]["status"] == "ready" and not item["live_readback"]["stale"])
        readback_drifted = sum(
            1 for item in nodes
            if item["live_readback"]["status"] == "ready"
            and not item["live_readback"]["stale"]
            and item["live_readback"]["sync_status"] == "drifted"
        )
        readback_unavailable = sum(1 for item in nodes if item["live_readback"]["status"] in {"unavailable", "unsupported", "unknown"} or item["live_readback"]["stale"])
        return JSONResponse({
            "revision": revision,
            "policy": policy,
            "updated_by": updated_by,
            "updated_at_utc8": format_utc8(updated_at) if updated_at else "",
            "hosts": nodes,
            "counts": {
                "total": len(nodes),
                "registered": sum(1 for item in nodes if item["registered"]),
                "online": sum(1 for item in nodes if item["online"]),
                "control_ready": sum(
                    1 for item in nodes
                    if item["control_api"] == "ready" and item["online"] and not item["control_api_stale"]
                ),
                "last_apply_succeeded": sum(1 for item in nodes if item["state"] == "last_apply_succeeded"),
                "deferred": sum(1 for item in nodes if item["state"] not in {"last_apply_succeeded", "ready"}),
                "network_deferred": sum(1 for item in nodes if item["state"] in {"awaiting_interfaces", "interfaces_not_found"}),
                "live_readback_current": readback_current,
                "drifted_hosts": readback_drifted,
                "readback_unavailable": readback_unavailable,
                "mtproto_supported_hosts": sum(1 for item in nodes if item["live_readback"]["mtproto_support"] == "supported"),
                "mtproto_unsupported_hosts": sum(1 for item in nodes if item["live_readback"]["mtproto_support"] == "unsupported"),
                "mtproto_capability_unknown_hosts": sum(1 for item in nodes if item["live_readback"]["mtproto_support"] == "unknown"),
                "required_protocols_supported_hosts": sum(1 for item in nodes if item["required_protocols"] and not item["unsupported_protocols"] and not item["unknown_protocols"]),
                "required_protocols_unsupported_hosts": sum(1 for item in nodes if item["unsupported_protocols"]),
                "required_protocols_unknown_hosts": sum(1 for item in nodes if item["unknown_protocols"]),
            },
            # Rules are read from the running RFW userspace API and compared
            # with Runman's ownership map; this is not a direct eBPF map dump.
            "live_rule_readback_supported": True,
        })
    finally:
        conn.close()


@app.post("/api/v1/firewall/fleet-policy")
async def update_fleet_firewall_policy(request: Request) -> JSONResponse:
    if getattr(request.state, "dashboard_role", "admin") != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以修改全局母机防火墙策略")
    raw_body = await request.body()
    if len(raw_body) > 128 * 1024:
        raise HTTPException(status_code=413, detail="防火墙配置超过 128 KiB")
    try:
        payload = json.loads(raw_body)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="防火墙配置必须是有效 JSON") from None
    policy = _validate_host_firewall_policy(payload)
    now = int(time.time())
    requested_by = str(getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard"))[:100]
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
        revision = (int(existing["revision"]) if existing else 0) + 1
        conn.execute(
            "INSERT INTO fleet_firewall_policy(id,revision,policy_json,updated_by,updated_at) VALUES(1,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,policy_json=excluded.policy_json,"
            "updated_by=excluded.updated_by,updated_at=excluded.updated_at",
            (revision, json.dumps(policy, ensure_ascii=False, separators=(",", ":")), requested_by, now),
        )
        hosts = conn.execute("SELECT host_id,node_id FROM hosts ORDER BY host_id").fetchall()
        queued = 0
        deferred = 0
        network_deferred = 0
        policy_abuse = policy.get("abuse") if isinstance(policy, dict) else None
        container_policy_enabled = isinstance(policy_abuse, dict) and any(
            policy_abuse.get(key) is True for key in ("speedtest", "mining", "bt")
        )
        for host in hosts:
            host_id = str(host["host_id"])
            node_id = str(host["node_id"] or "")
            runtime = _host_firewall_runtime_status(conn, host_id, now)
            if node_id and runtime["control_api"] == "ready" and not runtime["stale"]:
                if _policy_required_protocols(policy):
                    live_readback = _host_firewall_live_readback(conn, host_id, now)
                    compatibility = _policy_protocol_compatibility(policy, live_readback)
                    if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
                        deferred += 1
                        continue
                host_policy, target_status = _materialize_host_firewall_policy(conn, host_id, policy, now)
                if host_policy is None:
                    deferred += 1
                    network_deferred += 1
                    continue
                _enqueue_host_firewall_policy(conn, host_id, node_id, host_policy, requested_by, now, revision)
                queued += 1
            else:
                deferred += 1
                if container_policy_enabled:
                    _targets, target_status = _host_firewall_policy_targets(conn, host_id, policy, now)
                    if target_status in {"inventory_unavailable", "runtime_not_found", "interface_not_found"}:
                        network_deferred += 1
        conn.commit()
        return JSONResponse(status_code=202, content={
            "ok": True,
            "revision": revision,
            "queued_hosts": queued,
            "deferred_hosts": deferred,
            "network_deferred_hosts": network_deferred,
            "total_hosts": len(hosts),
        })
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.post("/api/v1/hosts/{host_id}/config")
async def update_host_config(host_id: str, request: Request) -> JSONResponse:
    payload = await request.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="配置必须为 JSON 对象")
    config = _validate_host_config(payload)
    now = int(time.time())
    conn = db()
    try:
        host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        if not host["node_id"]:
            raise HTTPException(status_code=409, detail="该主机需要先升级 Client，才能远程配置")
        cur = conn.execute(
            "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,'host','','__host__','update_host_config',?,'queued',?,?,?)",
            (host_id, json.dumps({"config": config, "expected_node_id": host["node_id"]}, ensure_ascii=False), getattr(request.state, "dashboard_user", "dashboard"), now, now),
        )
        conn.commit()
        invalidate_security_status_cache()
        return JSONResponse({"ok": True, "action_id": cur.lastrowid})
    finally:
        conn.close()


@app.post("/api/v1/hosts/{host_id}/delete")
async def delete_host(host_id: str, request: Request) -> JSONResponse:
    payload = await request.json()
    mode = str(payload.get("mode") or "uninstall") if isinstance(payload, dict) else ""
    if mode not in {"uninstall", "records_only"}:
        raise HTTPException(status_code=400, detail="无效删除方式")
    conn = db()
    try:
        host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        if mode == "records_only":
            _purge_host(conn, host_id); conn.commit()
            invalidate_security_status_cache()
            return JSONResponse({"ok": True})
        if not host["node_id"]:
            raise HTTPException(status_code=409, detail="该主机需要先升级 Client，才能远程卸载")
        now = int(time.time())
        cur = conn.execute(
            "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,'host','','__host__','self_uninstall',?,'queued',?,?,?)",
            (host_id, json.dumps({"expected_node_id": host["node_id"]}), getattr(request.state, "dashboard_user", "dashboard"), now, now),
        )
        conn.commit()
        return JSONResponse({"ok": True, "action_id": cur.lastrowid})
    finally:
        conn.close()


@app.post("/api/v1/actions/poll")
async def poll_security_actions(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid JSON body")
    host_id = str(payload.get("host_id") or "")[:200]
    node_id = str(payload.get("node_id") or "")[:128]
    if not host_id:
        raise HTTPException(status_code=400, detail="host_id is required")
    now = int(time.time())
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE security_actions
            SET status='failed', result_message='agent did not confirm action after 3 attempts', updated_at=?
            WHERE host_id=? AND status='dispatched' AND attempts>=3 AND updated_at < ?
            """,
            (now, host_id, now - 120),
        )
        rows = conn.execute(
            """
            SELECT * FROM security_actions
            WHERE host_id=? AND attempts < 3
              AND (status='queued' OR (status='dispatched' AND updated_at < ?))
            ORDER BY id LIMIT 10
            """,
            (host_id, now - 120),
        ).fetchall()
        actions = []
        for row in rows:
            stored = json.loads(row["params_json"] or "{}")
            if (row["runtime"] == "host" and row["action_type"] in {"update_host_config", "self_uninstall", "discover_access_logs", "host_security_rescan", "managed_upgrade", "managed_rollback",'disk_cleanup_scan','disk_cleanup_execute', 'apply_host_firewall_policy', 'delete_host_firewall_rule'} or row['action_type'] in {'release_network_quarantine', 'apply_container_connlimit', 'release_container_connlimit'}) and stored.get("expected_node_id") != node_id:
                continue
            params = _refresh_remediation_process_pids(conn, row)
            conn.execute(
                "UPDATE security_actions SET status='dispatched', attempts=attempts+1, updated_at=?, params_json=? WHERE id=?",
                (now, json.dumps(params, ensure_ascii=False), row["id"]),
            )
            action = _action_item(row)
            action["params"] = params
            action["status"] = "dispatched"
            action["attempts"] += 1
            actions.append(action)
        conn.commit()
        ops_services = [{"id": r["id"], **operations.loads(r["payload"])} for r in conn.execute("SELECT id,payload FROM ops_services WHERE host_id=? AND enabled=1 LIMIT 20", (host_id,)).fetchall()]
        cleanup_policy=disk_cleanup.node_config(conn,node_id)
        bandwidth_row = conn.execute("SELECT payload FROM ops_settings WHERE key=?", (f"manual_bandwidth:{host_id}",)).fetchone()
        saved_bandwidth_policy = operations.loads(bandwidth_row[0], {}) if bandwidth_row else {}
        bandwidth_policy = saved_bandwidth_policy
        if (not isinstance(bandwidth_policy, dict)
                or bandwidth_policy.get("host_id") != host_id
                or bandwidth_policy.get("expected_node_id") != node_id):
            bandwidth_policy = {"schema": 1, "host_id": host_id,
                                "expected_node_id": node_id, "revision": 0, "limits": []}
        else:
            bandwidth_policy = {key: bandwidth_policy.get(key) for key in
                                ("schema", "host_id", "expected_node_id", "revision", "limits")}
        bandwidth_limits = bandwidth_policy.get("limits")
        if not isinstance(bandwidth_limits, list):
            bandwidth_limits = []
            bandwidth_policy["limits"] = bandwidth_limits
        host_bandwidth_configured = any(
            isinstance(item, dict) and item.get("scope") == "host"
            and (item.get("upload_mbps", 0) or item.get("download_mbps", 0))
            for item in bandwidth_limits
        )
        stored_auto_throttle = (
            saved_bandwidth_policy.get("auto_throttle")
            if isinstance(saved_bandwidth_policy, dict) else None
        )
        auto_throttle_enabled = (
            stored_auto_throttle.get("enabled") if isinstance(stored_auto_throttle, dict)
            and type(stored_auto_throttle.get("enabled")) is bool else host_bandwidth_configured
        )
        bandwidth_policy["auto_throttle"] = {
            "enabled": bool(auto_throttle_enabled and host_bandwidth_configured),
            "threshold_percent": 80,
            "trigger_seconds": 300,
            "tier_percentages": [50, 25, 5],
            "minimum_mbps": 1,
            "recovery_percent": 50,
            "recovery_seconds": 600,
        }
        try:
            conn.execute("BEGIN IMMEDIATE")
            tcp_probe = tcping.lease_jobs(conn, host_id, node_id, now)
            gfw_probe = gfw_monitor.lease_job(conn, host_id, node_id, now)
            conn.commit()
        except Exception:
            conn.rollback()
            logging.exception("TCP probe queue failed; signed security polling continues")
            tcp_probe = {"job": None, "cancelled": []}
            gfw_probe = {"job": None}
    finally:
        conn.close()
    return signed_json_response({"ok": True, "actions": actions, "operations": {"services": ops_services,'disk_cleanup':cleanup_policy,'bandwidth_limits':bandwidth_policy}, "tcp_probe": tcp_probe, "gfw_probe": gfw_probe}, x_timestamp)


@app.post("/api/v1/actions/result")
async def security_action_result(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    try:
        payload = json.loads(body)
        action_id = int(payload.get("action_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid action result")
    host_id = str(payload.get("host_id") or "")[:200]
    node_id = str(payload.get("node_id") or "")[:128]
    status = str(payload.get("status") or "").lower()
    if status not in ("succeeded", "failed", "running"):
        raise HTTPException(status_code=400, detail="status must be succeeded, failed, or running")
    message = str(payload.get("message") or "")[:2000]
    receipt_items = buyer_notifications.buyer_content.receipt_items(payload.get('items'))
    now = int(time.time())
    conn = db()
    try:
        row = conn.execute(
            "SELECT host_id, status, action_type, alert_id, params_json FROM security_actions WHERE id=?",
            (action_id,),
        ).fetchone()
        if row is None or row["host_id"] != host_id:
            raise HTTPException(status_code=404, detail="action not found for host")
        params = json.loads(row["params_json"] or "{}")
        if row["action_type"] in {"update_host_config", "self_uninstall", "discover_access_logs", "host_security_rescan", "managed_upgrade", "managed_rollback", "release_network_quarantine",'disk_cleanup_scan','disk_cleanup_execute', 'apply_container_connlimit', 'release_container_connlimit', 'apply_host_firewall_policy', 'delete_host_firewall_rule'} and params.get("expected_node_id") != node_id:
            raise HTTPException(status_code=403, detail="action belongs to another node")
        if row["action_type"] in ("remediate_panel_pairing", "remediate_malicious_process") and status in {"succeeded", "failed"}:
            if _remediation_changed(message):
                if not any(
                    int(value) > 0
                    for value in re.findall(
                        r"\b(?:killed_processes|removed_services|removed_configs|removed_binaries)=(\d+)\b",
                        message,
                    )
                ):
                    status = "succeeded"
                    if "target_state=already_absent" not in message:
                        message = f"target_state=already_absent; target process verified absent, no repeated cleanup needed; {message}"
                    message = message[:2000]
            elif status == "succeeded":
                status = "failed"
                message = f"remediation could not be verified; no process, service or config change was confirmed; {message}"[:2000]
        if row["status"] not in ("succeeded", "failed"):
            if row['action_type'] in disk_cleanup.TYPES:
                disk_cleanup.record(conn,host_id,node_id,payload.get('cleanup_run'))
            conn.execute(
                "UPDATE security_actions SET status=?, result_message=?, updated_at=? WHERE id=?",
                (status, message, now, action_id),
            )
            if receipt_items and status in {'succeeded','failed'}:
                conn.execute("INSERT INTO security_action_receipts VALUES(?,?,?) ON CONFLICT(action_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at", (action_id,json.dumps(receipt_items,ensure_ascii=False),now))
            if status in {'succeeded','failed'} and row['action_type'] == 'stop_container':
                operations.record_connection_guard(conn,action_id,now)
                buyer_notifications.reconcile(conn,host_id,now)
            if status == "succeeded" and row["action_type"] == "self_uninstall":
                _purge_host(conn, host_id)
                invalidate_security_status_cache()
            if status == "succeeded" and row["action_type"] in (
                "remediate_panel_pairing", "remediate_malicious_process", "enforce_socks_auth", "stop_reviewed_socks"
            ):
                conn.execute(
                    "UPDATE security_alerts SET status='remediated' WHERE id=? AND status='active'",
                    (row["alert_id"],),
                )
                operations.track_recheck(conn, action_id, now)
            if row['alert_id'] is not None:
                investigation.sync_states(conn, host_id, now, alert_id=row['alert_id'])
            abuse_api.record_release_result(conn, row, params, status, now)
            conn.commit()
    finally:
        conn.close()
    if row['action_type'] == 'release_network_quarantine' and status in {'succeeded', 'failed'}:
        # A resolved release result may not appear in the next live sample;
        # update the existing Telegram card now, never leave "isolated" forever.
        sync_configured_bot_alert_messages(host_id, alert_id=row['alert_id'])
    return signed_json_response({"ok": True, "action_id": action_id}, x_timestamp)


operations_api.attach(app, db, lambda: DB_PATH, database_storage_status, cleanup_old_reports, lambda: APP_VERSION, lambda: DASHBOARD_USERNAME)
disk_cleanup.attach(app,db)
commerce.attach(app, db, lambda: DB_PATH, lambda: (DASHBOARD_USERNAME, DASHBOARD_PASSWORD))
tcping.attach(app, db, STATIC_DIR, verify_signature, signed_json_response)
gfw_monitor.attach(app, db, verify_signature, signed_json_response)
abuse_api.attach(app, db, verify_signature, signed_json_response, process_security_alerts, sync_configured_bot_alert_messages, _queue_security_action_row)
admission_api.attach(app, db, verify_signature, signed_json_response, process_security_alerts, sync_configured_bot_alert_messages, buyer_notifications.reconcile)
ip_reputation.attach(app, db, lambda: DB_PATH, commerce.cipher)


@app.get("/api/v1/security/actions")
def security_actions(limit: int = 200) -> JSONResponse:
    limit = max(1, min(limit, 1000))
    conn = db()
    rows = conn.execute("SELECT * FROM security_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return JSONResponse(content={"items": [_action_item(row) for row in rows]})


@app.get("/api/v1/security/alerts")
def security_alerts(active_only: bool = True, limit: int = 200) -> JSONResponse:
    limit = max(1, min(limit, 1000))
    conn = db()
    if active_only:
        rows = conn.execute(
            """
            SELECT a.* FROM security_alerts a
            LEFT JOIN hosts h ON h.host_id=a.host_id
            WHERE a.status='active'
              AND a.alert_type<>'admission_unverified'
              AND (a.container_name<>'' OR h.host_id IS NULL OR h.last_seen>=?)
            ORDER BY a.last_seen DESC, a.id DESC LIMIT ?
            """,
            (int(time.time()) - STALE_SECONDS, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM security_alerts ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
    items = [_security_alert_item(conn, row) for row in rows]
    conn.close()
    active_count = sum(1 for item in items if item["status"] == "active") if not active_only else len(items)
    return JSONResponse(content={"items": items, "active_count": active_count})


@app.get("/api/v1/security/investigation")
def user_investigation(host_id: str = "", days: int = 30, query: str = "",
                       user_id: str | None = None, identity_key: str = "", offset: int = 0,
                       limit: int = 30) -> JSONResponse:
    if days not in {7, 30, 90}:
        raise HTTPException(status_code=400, detail="历史范围必须是 7、30 或 90 天")
    now = int(time.time())
    conn = db()
    try:
        result = investigation.overview(conn, host_id.strip()[:200], now - days * 86400, now,
                                        query[:200], user_id[:128] if user_id is not None else None,
                                        identity_key[:64], max(0, offset), max(1, min(limit, 100)))
        result.update(window={"start": now - days * 86400, "end": now}, host_id=host_id, days=days)
        return JSONResponse(content=result)
    finally:
        conn.close()


@app.get("/api/v1/security/history")
def security_alert_history(
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
    conn = db()
    total = int(
        conn.execute(
            f"SELECT COUNT(*) FROM security_alerts{where_sql}", params
        ).fetchone()[0]
    )
    rows = conn.execute(
        f"SELECT * FROM security_alerts{where_sql} "
        "ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall()
    counts = {item: 0 for item in ("all", *sorted(valid_statuses))}
    for count_row in conn.execute(
        "SELECT status, COUNT(*) AS count FROM security_alerts GROUP BY status"
    ).fetchall():
        current_status = str(count_row["status"])
        counts[current_status] = int(count_row["count"])
        counts["all"] += int(count_row["count"])
    alert_types = [
        str(item["alert_type"])
        for item in conn.execute(
            "SELECT DISTINCT alert_type FROM security_alerts ORDER BY alert_type"
        ).fetchall()
    ]
    hosts = [
        str(item["host_id"])
        for item in conn.execute(
            "SELECT DISTINCT host_id FROM security_alerts ORDER BY host_id"
        ).fetchall()
    ]
    items = [_security_alert_item(conn, row) for row in rows]
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


@app.get("/api/v1/security/status")
def security_status() -> JSONResponse:
    global _security_status_cache, _security_status_cache_time
    now_mono = time.monotonic()
    if _security_status_cache is not None and now_mono - _security_status_cache_time < 5.0:
        return JSONResponse(content=_security_status_cache)

    conn = db()
    try:
        now_utc8 = datetime.now(tz=UTC8)
        today_start_ts = int(now_utc8.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

        try:
            rows = conn.execute(
                """
                SELECT hosts.host_id, COALESCE(h.ts, hosts.last_seen) AS ts, hosts.node_id, hosts.config_json, h.payload_json
                FROM hosts
                LEFT JOIN host_security h ON h.id = (
                    SELECT hs.id FROM host_security hs WHERE hs.host_id=hosts.host_id ORDER BY hs.id DESC LIMIT 1
                )
                ORDER BY hosts.host_id
                """
            ).fetchall()
        except sqlite3.OperationalError:
            # Keep a rolling upgrade readable if an old database is queried
            # before the application startup migration has run.
            rows = conn.execute(
                """
                SELECT hosts.host_id, COALESCE(h.ts, hosts.last_seen) AS ts, '' AS node_id, '{}' AS config_json, h.payload_json
                FROM hosts
                LEFT JOIN host_security h ON h.id = (
                    SELECT hs.id FROM host_security hs WHERE hs.host_id=hosts.host_id ORDER BY hs.id DESC LIMIT 1
                ) ORDER BY hosts.host_id
                """
            ).fetchall()

        container_peaks_rows = conn.execute(
            """
            SELECT
                host_id,
                MAX(sum_conn) AS peak_conn_count,
                MAX(max_conn) AS peak_container_conn_count,
                MAX(sum_rx) AS peak_rx_bps,
                MAX(sum_tx) AS peak_tx_bps,
                MAX(max_inbound_ips) AS peak_inbound_ips,
                MAX(max_outbound_ips) AS peak_outbound_ips
            FROM (
                SELECT
                    host_id,
                    ts,
                    SUM(conn_count) AS sum_conn,
                    MAX(conn_count) AS max_conn,
                    SUM(net_rx_bps) AS sum_rx,
                    SUM(net_tx_bps) AS sum_tx,
                    MAX(COALESCE(CAST(json_extract(payload_json, '$.security.inbound_unique_ips') AS INTEGER), 0)) AS max_inbound_ips,
                    MAX(COALESCE(CAST(json_extract(payload_json, '$.security.outbound_unique_ips') AS INTEGER), 0)) AS max_outbound_ips
                FROM reports
                WHERE ts >= ?
                GROUP BY host_id, ts
            )
            GROUP BY host_id
            """,
            (today_start_ts,),
        ).fetchall()

        host_sec_peaks_rows = conn.execute(
            """
            SELECT
                host_id,
                MAX(COALESCE(CAST(json_extract(payload_json, '$.total_rx_bps') AS REAL), 0)) AS peak_rx_bps,
                MAX(COALESCE(CAST(json_extract(payload_json, '$.total_tx_bps') AS REAL), 0)) AS peak_tx_bps
            FROM host_security
            WHERE ts >= ?
            GROUP BY host_id
            """,
            (today_start_ts,),
        ).fetchall()
        gfw_by_host = gfw_monitor.status_map(conn, int(time.time()))
    finally:
        conn.close()

    peaks_by_host: Dict[str, Dict[str, Any]] = {}
    for r in container_peaks_rows:
        peaks_by_host[r["host_id"]] = {
            "peak_conn_count": int(r["peak_conn_count"] or 0),
            "peak_container_conn_count": int(r["peak_container_conn_count"] or 0),
            "peak_rx_bps": float(r["peak_rx_bps"] or 0.0),
            "peak_tx_bps": float(r["peak_tx_bps"] or 0.0),
            "peak_inbound_ips": int(r["peak_inbound_ips"] or 0),
            "peak_outbound_ips": int(r["peak_outbound_ips"] or 0),
        }

    for r in host_sec_peaks_rows:
        h = r["host_id"]
        if h not in peaks_by_host:
            peaks_by_host[h] = {
                "peak_conn_count": 0,
                "peak_rx_bps": float(r["peak_rx_bps"] or 0.0),
                "peak_tx_bps": float(r["peak_tx_bps"] or 0.0),
                "peak_inbound_ips": 0,
                "peak_outbound_ips": 0,
            }
        else:
            peaks_by_host[h]["peak_rx_bps"] = max(
                peaks_by_host[h]["peak_rx_bps"], float(r["peak_rx_bps"] or 0.0)
            )
            peaks_by_host[h]["peak_tx_bps"] = max(
                peaks_by_host[h]["peak_tx_bps"], float(r["peak_tx_bps"] or 0.0)
            )

    items = []
    for row in rows:
        host_id = row["host_id"]
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:
            payload = {}
        cur_rx = float(payload.get("total_rx_bps") or 0)
        cur_tx = float(payload.get("total_tx_bps") or 0)
        p = peaks_by_host.get(host_id, {})
        items.append(
            {
                "host_id": host_id,
                "gfw_reachability": gfw_by_host.get(host_id, {"status": "unassessed"}),
                "node_id": str(row["node_id"] or ""),
                "host_config": json.loads(row["config_json"] or "{}"),
                "timestamp": int(row["ts"]),
                "timestamp_utc8": format_utc8(int(row["ts"])),
                "enabled": bool(payload.get("enabled")),
                "stale": time.time() - int(row["ts"]) > STALE_SECONDS,
                "interval_seconds": payload.get("interval_seconds"),
                "thresholds": payload.get("thresholds") or {},
                "sample_alerts": payload.get("alerts") or [],
                "host_audit": payload.get("host_audit") if isinstance(payload.get("host_audit"), dict) else {},
                "access_sources": payload.get("access_sources") or [],
                "total_rx_bps": cur_rx,
                "total_tx_bps": cur_tx,
                "total_rx_pps": float(payload.get("total_rx_pps") or 0),
                "total_tx_pps": float(payload.get("total_tx_pps") or 0),
                "syn_recv_count": int(payload.get("syn_recv_count") or 0),
                "access_log": payload.get("access_log") if isinstance(payload.get("access_log"), dict) else {},
                "active_alerts_in_sample": len(payload.get("alerts") or []),
                "today_peak_inbound_ips": int(p.get("peak_inbound_ips", 0)),
                "today_peak_outbound_ips": int(p.get("peak_outbound_ips", 0)),
                "today_peak_conn_count": int(p.get("peak_conn_count", 0)),
                "today_peak_container_conn_count": int(p.get("peak_container_conn_count", 0)),
                "today_peak_rx_bps": max(float(p.get("peak_rx_bps", 0.0)), cur_rx),
                "today_peak_tx_bps": max(float(p.get("peak_tx_bps", 0.0)), cur_tx),
            }
        )
    res_content = {"items": items}
    _security_status_cache = res_content
    _security_status_cache_time = time.monotonic()
    return JSONResponse(content=res_content)



@app.get("/api/v1/stats")
def stats(minutes: int = 720) -> JSONResponse:
    minutes = max(5, min(minutes, 10080))
    start_ts = int(time.time()) - (minutes * 60)
    conn = db()
    rows = conn.execute(
        """
        SELECT host_id, runtime, project, container_name, ts, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps, conn_count, payload_json
        FROM reports
        WHERE ts>=?
        ORDER BY host_id, runtime, project, container_name, ts ASC
        """,
        (start_ts,),
    ).fetchall()
    conn.close()

    grouped: Dict[tuple[str, str, str, str], List[sqlite3.Row]] = {}
    for row in rows:
        key = (str(row["host_id"]), str(row["runtime"]), str(row["project"]), str(row["container_name"]))
        grouped.setdefault(key, []).append(row)

    items: List[Dict[str, Any]] = []
    host_totals: Dict[str, Dict[str, float]] = {}
    total_samples = 0
    for (host_id, runtime, project, container_name), series in grouped.items():
        if not series:
            continue
        latest_agent_version = report_agent_version(series[-1]["payload_json"])
        if latest_agent_version != "unknown":
            series = [
                row for row in series if report_agent_version(row["payload_json"]) == latest_agent_version
            ]
        cpu_values = [float(x["cpu_percent"] or 0) for x in series]
        mem_values = [int(x["mem_bytes"] or 0) for x in series]
        mem_percent_values = [float(x["mem_percent"] or 0) for x in series]
        conn_values = [int(x["conn_count"] or 0) for x in series]
        rx_values = [float(x["net_rx_bps"] or 0) for x in series]
        tx_values = [float(x["net_tx_bps"] or 0) for x in series]
        timestamps = [int(x["ts"]) for x in series]
        intervals = [max(1, timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
        estimated_interval = round(sum(intervals) / len(intervals), 2) if intervals else 0

        rx_bytes = 0.0
        tx_bytes = 0.0
        for i, row in enumerate(series):
            step = 0
            if i > 0:
                step = max(1, int(row["ts"]) - int(series[i - 1]["ts"]))
            elif estimated_interval > 0:
                step = max(1, int(round(estimated_interval)))
            rx_bytes += float(row["net_rx_bps"] or 0) * step
            tx_bytes += float(row["net_tx_bps"] or 0) * step

        latest = series[-1]
        try:
            latest_payload = json.loads(latest["payload_json"] or "{}")
        except (TypeError, ValueError):
            latest_payload = {}
        item = {
            "host_id": host_id,
            "runtime": runtime,
            "project": project,
            "container_name": container_name,
            "samples": len(series),
            "estimated_interval_seconds": estimated_interval,
            "latest": {
                "timestamp": int(latest["ts"]),
                "agent_version": str(latest_payload.get("_agent_version") or "unknown"),
                "cpu_percent": float(latest["cpu_percent"] or 0),
                "mem_bytes": int(latest["mem_bytes"] or 0),
                "mem_limit_bytes": int(latest_payload.get("mem_limit_bytes") or 0),
                "mem_percent": float(latest["mem_percent"] or 0),
                "net_rx_bps": float(latest["net_rx_bps"] or 0),
                "net_tx_bps": float(latest["net_tx_bps"] or 0),
                "conn_count": int(latest["conn_count"] or 0),
            },
            "avg": {
                "cpu_percent": round(sum(cpu_values) / len(cpu_values), 4),
                "mem_bytes": int(sum(mem_values) / len(mem_values)),
                "mem_percent": round(sum(mem_percent_values) / len(mem_percent_values), 4),
                "net_rx_bps": round(sum(rx_values) / len(rx_values), 4),
                "net_tx_bps": round(sum(tx_values) / len(tx_values), 4),
                "conn_count": round(sum(conn_values) / len(conn_values), 2),
            },
            "max": {
                "cpu_percent": max(cpu_values),
                "mem_bytes": max(mem_values),
                "mem_percent": max(mem_percent_values),
                "net_rx_bps": max(rx_values),
                "net_tx_bps": max(tx_values),
                "conn_count": max(conn_values),
            },
            "traffic_bytes": {
                "rx": int(rx_bytes),
                "tx": int(tx_bytes),
                "total": int(rx_bytes + tx_bytes),
            },
        }
        items.append(item)

        host_total = host_totals.setdefault(host_id, {"rx": 0.0, "tx": 0.0, "samples": 0.0})
        host_total["rx"] += rx_bytes
        host_total["tx"] += tx_bytes
        host_total["samples"] += len(series)
        total_samples += len(series)

    rank_cpu = sorted(items, key=lambda x: x["avg"]["cpu_percent"], reverse=True)[:10]
    rank_conn = sorted(items, key=lambda x: x["avg"]["conn_count"], reverse=True)[:10]
    rank_traffic = sorted(items, key=lambda x: x["traffic_bytes"]["total"], reverse=True)[:10]
    host_summary = [
        {
            "host_id": host,
            "traffic_rx_bytes": int(vals["rx"]),
            "traffic_tx_bytes": int(vals["tx"]),
            "traffic_total_bytes": int(vals["rx"] + vals["tx"]),
            "samples": int(vals["samples"]),
        }
        for host, vals in host_totals.items()
    ]
    host_summary.sort(key=lambda x: x["traffic_total_bytes"], reverse=True)
    return JSONResponse(
        content={
            "server_version": APP_VERSION,
            "window_minutes": minutes,
            "container_count": len(items),
            "samples": total_samples,
            "containers": items,
            "ranks": {
                "avg_cpu_top10": rank_cpu,
                "avg_conn_top10": rank_conn,
                "traffic_top10": rank_traffic,
            },
            "hosts": host_summary,
            "recommendation": {
                "suggested_interval_seconds": 60,
                "reason": "当前容器 CPU 使用率整体低，建议从 300 秒降低到 60 秒，兼顾实时性与开销。",
            },
        }
    )


@app.api_route("/assets/{path:path}", methods=["GET", "HEAD"])
def serve_static_asset(path: str):
    file_path = (ASSETS_DIR / path).resolve()
    if file_path.is_file() and ASSETS_DIR in file_path.parents:
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Asset not found")



@app.api_route("/alerts/history", methods=["GET", "HEAD"], response_class=HTMLResponse)
def security_alert_history_page(request: Request = None) -> Any:
    spa_index = STATIC_DIR / "index.html"
    if request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>告警历史 · Narwhal Monitor</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface2:#172033;--surface3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--warning:#f59e0b;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}.skip-link{position:fixed;top:-70px;left:12px;z-index:1000;padding:10px 14px;border-radius:8px;background:var(--accent);color:#082f49;font-weight:750}.skip-link:focus{top:12px}.shell{width:min(1500px,100%);margin:auto;padding:20px}.header{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;padding:18px 20px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,#0f172a,#111d34)}h1{margin:0;font-size:22px}.subtitle{margin:5px 0 0;color:var(--muted);font-size:13px}.header-actions,.actions,.status-tabs{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.btn,.nav-link{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface3);color:var(--text);font:inherit;text-decoration:none;cursor:pointer;touch-action:manipulation;transition:filter 180ms ease,opacity 180ms ease}.btn:hover,.nav-link:hover{filter:brightness(1.13)}.btn:focus-visible,.nav-link:focus-visible,input:focus-visible,select:focus-visible,.status-chip:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.btn:disabled{opacity:.55;cursor:wait}.btn-danger{border-color:#b91c1c;background:#7f1d1d}.btn-secondary{background:#334155}.panel{margin-top:16px;border:1px solid var(--border);border-radius:14px;background:var(--surface);overflow:hidden}.panel-head{padding:14px 16px;border-bottom:1px solid var(--border);background:var(--surface2)}.panel-head h2{margin:0;font-size:17px}.filters{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;padding:16px}.field{min-width:0}.field label{display:block;margin-bottom:5px;color:#cbd5e1;font-size:12px;font-weight:650}.field input,.field select{width:100%;min-height:44px;padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:var(--text);font:inherit}.filter-actions{display:flex;align-items:end;gap:8px}.status-tabs{padding:12px 16px;border-top:1px solid var(--border)}.status-chip{min-height:44px;padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#111827;color:#cbd5e1;cursor:pointer;touch-action:manipulation}.status-chip.active{border-color:#0ea5e9;background:#082f49;color:#bae6fd}.alert-list{display:grid;gap:12px;padding:16px}.alert-card{min-width:0;border:1px solid var(--border);border-left:4px solid var(--warning);border-radius:12px;background:#0b1220;padding:15px}.alert-card.critical{border-left-color:var(--danger)}.alert-card.info{border-left-color:var(--accent)}.alert-top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.alert-title{min-width:0}.alert-title h3{margin:0;font-size:16px;overflow-wrap:anywhere}.meta{display:flex;gap:7px;flex-wrap:wrap;margin-top:7px}.pill{display:inline-flex;align-items:center;min-height:28px;padding:3px 9px;border:1px solid var(--border);border-radius:999px;background:#111827;color:#cbd5e1;font-size:12px;overflow-wrap:anywhere}.pill.active{border-color:#b91c1c;background:#450a0a;color:#fca5a5}.pill.suppressed{border-color:#166534;background:#052e16;color:#86efac}.pill.dismissed{border-color:#92400e;background:#451a03;color:#fcd34d}.pill.remediated{border-color:#0369a1;background:#082f49;color:#7dd3fc}.pill.resolved{color:#cbd5e1}.message{margin:13px 0;color:#e2e8f0;overflow-wrap:anywhere}.evidence{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.evidence-block{min-width:0;padding:10px;border:1px solid #26364e;border-radius:9px;background:#0f172a}.evidence-block span{display:block;color:var(--muted);font-size:11px}.evidence-block strong{display:block;margin-top:4px;font-size:13px;font-weight:600;overflow-wrap:anywhere}.result{margin-top:10px;padding:10px;border-radius:8px;background:#111827;color:#cbd5e1;font-size:12px;overflow-wrap:anywhere}.card-footer{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin-top:12px}.timestamps{color:var(--muted);font-size:12px}.empty{padding:36px;text-align:center;color:var(--muted)}.load-more{display:flex;justify-content:center;padding:0 16px 18px}.toast{position:fixed;right:18px;bottom:18px;z-index:10;max-width:min(440px,calc(100% - 36px));padding:12px 14px;border:1px solid #166534;border-radius:10px;background:#052e16;color:#bbf7d0;box-shadow:0 12px 35px #0008}.toast.error{border-color:#991b1b;background:#450a0a;color:#fecaca}[hidden]{display:none!important}
@media(max-width:1000px){.filters{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence{grid-template-columns:1fr}.filter-actions{align-items:center}.card-footer{align-items:flex-start;flex-direction:column}}
@media(max-width:640px){.shell{padding:8px}.header{padding:14px;flex-direction:column}.filters{grid-template-columns:1fr;padding:10px}.alert-list{padding:10px}.alert-top{flex-direction:column}.actions{width:100%}.actions .btn{flex:1 1 100%}.status-tabs{padding:10px}.status-chip{flex:1 1 calc(50% - 8px)}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head><body><a class='skip-link' href='#history-main'>跳到主要内容</a><main id='history-main' class='shell'>
<header class='header'><div><h1>安全告警历史</h1><p class='subtitle'>保留活动、已忽略、已处理和已恢复事件；可重新禁止或恢复提醒。</p></div><div class='header-actions'><span id='server-version' class='pill'>Server</span><a class='nav-link' href='/'>返回总览</a><button class='btn' type='button' onclick='loadHistory(true)'>刷新</button></div></header>
<section class='panel' aria-labelledby='filter-title'><header class='panel-head'><h2 id='filter-title'>检索与筛选</h2></header><div class='filters'>
<div class='field'><label for='severity'>级别</label><select id='severity'><option value='all'>全部级别</option><option value='critical'>Critical</option><option value='warning'>Warning</option><option value='info'>Info</option></select></div>
<div class='field'><label for='alert-type'>告警类型</label><select id='alert-type'><option value='all'>全部类型</option></select></div>
<div class='field'><label for='host-id'>主机</label><select id='host-id'><option value=''>全部主机</option></select></div>
<div class='field'><label for='query'>关键词</label><input id='query' type='search' placeholder='容器、主机、说明'></div>
<div class='filter-actions'><button class='btn' type='button' onclick='applyFilters()'>应用筛选</button><button class='btn btn-secondary' type='button' onclick='resetFilters()'>重置</button></div>
</div><div id='status-tabs' class='status-tabs' aria-label='处理状态'></div></section>
<section class='panel' aria-labelledby='history-title'><header class='panel-head'><h2 id='history-title'>告警记录 <span id='result-count' class='pill'>0</span></h2></header><div id='alert-list' class='alert-list' aria-live='polite'><div class='empty'>正在加载告警历史…</div></div><div class='load-more'><button id='load-more' class='btn' type='button' hidden onclick='loadMore()'>加载更多</button></div></section>
</main><div id='toast' class='toast' role='status' aria-live='polite' hidden></div>
<script>
const state={status:'all',offset:0,limit:50,total:0,loading:false};
const labels={active:'活动',suppressed:'允许且不再提醒',dismissed:'本次取消提醒',resolved:'已恢复',remediated:'已处理'};
const decisions={deny:'禁止/处理',allow_silent:'允许且不再提醒',dismiss_once:'本次取消提醒',reopen:'恢复提醒'};
function esc(value){return String(value??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));}
function showToast(message,error=false){const toast=document.getElementById('toast');toast.textContent=message;toast.className=`toast${error?' error':''}`;toast.hidden=false;setTimeout(()=>{toast.hidden=true},4500)}
function actionable(alert){const details=alert.details||{};const supported=alert.runtime==='incus'||alert.runtime==='podman';if(!supported)return false;if(alert.type==='unauthorized_panel_pairing')return (details.process_patterns||[]).length>0||(details.config_files||[]).length>0;if(alert.type==='socks_weak_auth')return ['no_auth','weak_password'].includes(details.socks_auth_mode)&&(details.socks_processes||[]).length>0;if(alert.type==='malicious_process')return (details.malicious_processes||[]).some(x=>x.process==='xmrig');return false;}
function evidenceText(alert){const d=alert.details||{};if(alert.type==='unauthorized_panel_pairing')return [`域名：${(d.unapproved_domains||[]).join(', ')||'-'}`,`进程：${(d.process_patterns||[]).join(', ')||'-'}`,`配置：${(d.config_files||[]).join(', ')||'-'}`];if(alert.type==='socks_weak_auth')return [`认证：${d.socks_auth_mode||'unknown'}`,`进程：${(d.socks_processes||[]).join(', ')||'-'}`,`配置：${(d.socks_config_files||[]).join(', ')||'-'}`];if(alert.type==='malicious_process')return [`进程：${(d.malicious_processes||[]).map(x=>x.process).join(', ')||'-'}`,`PID：${(d.malicious_processes||[]).map(x=>x.pid||'-').join(', ')||'-'}`,'策略：仅精确匹配 XMRig'];return [`指标：${alert.value||0}`,`阈值：${alert.threshold||0}`,`类型：${alert.type}`];}
function resultText(alert){const automatic=alert.details?.automatic_remediation;const action=alert.latest_action;const decision=alert.latest_decision;const parts=[];if(automatic?.attempted)parts.push(`自动处置：${automatic.succeeded?'成功':'失败'} · ${automatic.message||'-'}`);if(action)parts.push(`节点操作：${action.status} · ${action.result_message||action.action_type}`);if(decision)parts.push(`人工决定：${decisions[decision.decision]||decision.decision} · ${decision.requested_by} · ${decision.created_at_utc8}`);return parts.join('<br>');}
function card(alert){const runtime=alert.project?`${alert.runtime}/${alert.project}`:(alert.runtime||'-');const evidence=evidenceText(alert);const canAct=actionable(alert);const historical=alert.status!=='active';const controls=[];if(canAct)controls.push(`<button class='btn btn-danger' type='button' data-action-id='${alert.id}' onclick="decide(${alert.id},'deny')">${historical?'重新禁止/处理':'禁止/处理'}</button>`);if(alert.status==='suppressed'||alert.status==='dismissed')controls.push(`<button class='btn btn-secondary' type='button' data-action-id='${alert.id}' onclick="decide(${alert.id},'reopen')">恢复提醒</button>`);const result=resultText(alert);return `<article class='alert-card ${esc(alert.severity)}'><div class='alert-top'><div class='alert-title'><h3>${esc(alert.title||alert.type)}</h3><div class='meta'><span class='pill ${esc(alert.status)}'>${esc(labels[alert.status]||alert.status)}</span><span class='pill'>${esc(alert.severity)}</span><span class='pill'>${esc(alert.host_id)}</span><span class='pill'>${esc(runtime)}</span><span class='pill'>${esc(alert.container_name||'-')}</span></div></div><span class='pill'>出现 ${Number(alert.occurrence_count||0)} 次</span></div><p class='message'>${esc(alert.message)}</p><div class='evidence'>${evidence.map((x,i)=>`<div class='evidence-block'><span>${['关键证据','关联对象','处置范围'][i]||'证据'}</span><strong>${esc(x)}</strong></div>`).join('')}</div>${result?`<div class='result'>${result}</div>`:''}<footer class='card-footer'><div class='timestamps'>首次 ${esc(alert.first_seen_utc8)} · 最近 ${esc(alert.last_seen_utc8)}</div><div class='actions'>${controls.join('')}</div></footer></article>`;}
function fillOptions(id,values,current,allLabel){const select=document.getElementById(id);select.innerHTML=`<option value='${id==='host-id'?'':'all'}'>${allLabel}</option>`+values.map(v=>`<option value='${esc(v)}'>${esc(v)}</option>`).join('');select.value=current||'';}
function renderTabs(counts){const tabs=document.getElementById('status-tabs');tabs.innerHTML=['all','active','suppressed','dismissed','remediated','resolved'].map(status=>`<button type='button' class='status-chip ${state.status===status?'active':''}' onclick="selectStatus('${status}')">${status==='all'?'全部':labels[status]} ${Number(counts?.[status]||0)}</button>`).join('');}
async function loadHistory(reset=false){if(state.loading)return;if(reset)state.offset=0;state.loading=true;const params=new URLSearchParams({status:state.status,severity:document.getElementById('severity').value,alert_type:document.getElementById('alert-type').value,host_id:document.getElementById('host-id').value,query:document.getElementById('query').value,limit:String(state.limit),offset:String(state.offset)});try{const response=await fetch(`/api/v1/security/history?${params}`);const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);state.total=Number(data.total||0);document.getElementById('server-version').textContent='Server 已连接';document.getElementById('result-count').textContent=`${state.total} 条`;renderTabs(data.counts);if(reset){fillOptions('alert-type',data.alert_types||[],document.getElementById('alert-type').value,'全部类型');fillOptions('host-id',data.hosts||[],document.getElementById('host-id').value,'全部主机');document.getElementById('alert-list').innerHTML='';}const list=document.getElementById('alert-list');if(reset)list.innerHTML='';list.insertAdjacentHTML('beforeend',(data.items||[]).map(card).join(''));state.offset+=(data.items||[]).length;if(state.total===0)list.innerHTML='<div class="empty">没有符合条件的告警记录</div>';document.getElementById('load-more').hidden=state.offset>=state.total;}catch(error){showToast(`加载失败：${error.message||error}`,true)}finally{state.loading=false}}
function selectStatus(status){state.status=status;loadHistory(true)}function applyFilters(){loadHistory(true)}function resetFilters(){state.status='all';document.getElementById('severity').value='all';document.getElementById('alert-type').value='all';document.getElementById('host-id').value='';document.getElementById('query').value='';loadHistory(true)}function loadMore(){loadHistory(false)}
async function decide(id,decision){const warning=decision==='deny'?'确认重新执行定向处置？只会处理已识别的进程、服务和配置，不会停止容器。':'确认撤销忽略策略并恢复提醒？';if(!confirm(warning))return;document.querySelectorAll(`[data-action-id="${id}"]`).forEach(x=>x.disabled=true);try{const response=await fetch(`/api/v1/security/alerts/${id}/disposition`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})});const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);showToast(data.queued?'操作已排队，等待节点执行':'状态已更新');await loadHistory(true)}catch(error){showToast(`操作失败：${error.message||error}`,true);document.querySelectorAll(`[data-action-id="${id}"]`).forEach(x=>x.disabled=false)}}
document.getElementById('query').addEventListener('keydown',event=>{if(event.key==='Enter')loadHistory(true)});loadHistory(true);setInterval(()=>loadHistory(true),30000);
</script></body></html>
"""


@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def dashboard(request: Request = None) -> Any:
    spa_index = STATIC_DIR / "index.html"
    if request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Narwhal Container Monitor</title>
<style>
*{box-sizing:border-box}
html,body{max-width:100%;overflow-x:hidden}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:1rem;background:#0f1a2e;color:#dbe7ff;line-height:1.5}
table{border-collapse:collapse;width:100%;max-width:100%;table-layout:fixed;background:#13213b;color:#dbe7ff}
th,td{border:1px solid #233b61;padding:8px;vertical-align:middle;text-align:center;overflow-wrap:anywhere;word-break:break-word}
th{background:#1a2c4e}
.bad{color:#ff6b78;font-weight:bold}
.ok{color:#72dfa7}
.severity-critical{color:#ff5f6d;font-weight:bold}
.severity-warning{color:#ffbf4b;font-weight:bold}
.btn{border:1px solid #4b6fa8;min-height:44px;padding:7px 11px;border-radius:8px;background:#1a2c4e;color:#dbe7ff;cursor:pointer;touch-action:manipulation}
.btn-danger{background:#7c2330;border-color:#d94b61;margin-right:6px}
.btn-allow{background:#185d4a;border-color:#36a77f;margin-right:6px}
.btn-dismiss{background:#34445e;border-color:#6e85a8}
.btn:disabled{opacity:.55;cursor:not-allowed}
.security-action-state{display:flex;align-items:center;justify-content:center;min-height:28px;margin-bottom:7px;font-weight:650}
.security-action-buttons{display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:wrap}
.security-action-buttons .btn{margin-right:0}
.action-status{font-size:12px;margin-top:7px;color:#a9bddc}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.35);display:none;align-items:center;justify-content:center}
#card{background:#0d1730;border-radius:12px;padding:16px;width:min(1380px,96vw);max-height:94vh;overflow-y:auto}
.legend{display:flex;gap:14px;align-items:center;margin:8px 0 4px 0;font-size:14px}
.legend-item{display:flex;align-items:center;gap:6px}
.dot{width:10px;height:10px;border-radius:50%}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.panel{background:#13213b;border:1px solid #233b61;border-radius:10px;padding:10px}
.panel h4{margin:0 0 6px 0}
svg{width:100%;height:220px;border-top:1px solid #28436c}
#traffic{height:280px}
.snapshot-grid{display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:10px;margin-top:12px}
.snapshot-list{margin:6px 0 0 18px;padding:0;text-align:left;max-height:180px;overflow:auto}
#security-alerts th:nth-child(6){width:28%}
#security-alerts th:nth-child(9){width:25%}
.host-list{display:grid;gap:12px;width:100%;min-width:0}
.host-group{min-width:0;overflow:hidden;border:1px solid #29466f;border-radius:14px;background:#111f38;box-shadow:0 8px 24px rgba(3,10,24,.18)}
.host-toggle{width:100%;min-height:76px;border:0;background:#172844;color:#dbe7ff;display:grid;grid-template-columns:24px minmax(0,1fr) minmax(240px,auto);align-items:center;gap:12px;padding:14px 16px;text-align:left;cursor:pointer;touch-action:manipulation}
.host-toggle:hover{background:#1b3153}
.host-toggle:focus-visible,.btn:focus-visible{outline:3px solid #8cc7ff;outline-offset:-3px}
.host-chevron{width:20px;height:20px;transition:transform 180ms ease;color:#8cc7ff}
.host-group.is-open .host-chevron{transform:rotate(90deg)}
.host-title{min-width:0}
.host-name{font-size:18px;font-weight:750;overflow-wrap:anywhere}
.host-subtitle{display:block;margin-top:3px;color:#9fb5d5;font-size:13px}
.host-summary{display:flex;justify-content:flex-end;align-items:center;gap:7px;flex-wrap:wrap;min-width:0}
.pill{display:inline-flex;align-items:center;min-height:28px;padding:3px 9px;border:1px solid #365680;border-radius:999px;background:#10213c;color:#c9dbf5;font-size:12px;white-space:normal}
.pill-ok{border-color:#2f8568;background:#123e35;color:#8ee6c2}
.pill-warn{border-color:#b78035;background:#49371b;color:#ffd58c}
.pill-bad{border-color:#a84655;background:#4f202a;color:#ffadb8}
.host-panel{padding:14px;border-top:1px solid #29466f}
.host-panel[hidden]{display:none}
.containers-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(520px,100%),1fr));gap:14px;min-width:0}
.container-card{min-width:0;border:1px solid #2a456d;border-radius:12px;background:#13213b;padding:14px;box-shadow:0 5px 16px rgba(4,11,26,.16)}
.container-card:hover{border-color:#4472aa;box-shadow:0 8px 24px rgba(4,11,26,.26)}
.container-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:12px}
.container-name{font-size:17px;font-weight:750;overflow-wrap:anywhere}
.container-meta{margin-top:2px;color:#9fb5d5;font-size:12px;overflow-wrap:anywhere}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:10px}
.metric{min-width:0;border:1px solid #274365;border-radius:9px;background:#0f1c33;padding:8px}
.metric-label{display:block;color:#91a9cb;font-size:11px;line-height:1.25}
.metric-value{display:block;margin-top:4px;font-size:15px;font-weight:700;overflow-wrap:anywhere}
.container-info-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}
.info-block{min-width:0;border:1px solid #274365;border-radius:9px;background:#101e36;padding:10px}
.info-block h4{margin:0 0 7px;font-size:13px;color:#9fc8ff}
.kv{display:grid;grid-template-columns:minmax(76px,auto) minmax(0,1fr);gap:5px 8px;margin:0;font-size:12px}
.kv dt{color:#8fa8ca}
.kv dd{min-width:0;margin:0;text-align:right;overflow-wrap:anywhere}
.container-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin-top:12px}
.empty-state{border:1px dashed #365680;border-radius:12px;padding:22px;text-align:center;color:#9fb5d5}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--warning:#f59e0b;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text)}
.skip-link{position:fixed;left:12px;top:-60px;z-index:1000;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.app-shell{width:min(1600px,100%);margin:0 auto;padding:20px}
.app-header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px;padding:18px 20px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,#0f172a,#111d34)}
.brand{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;display:grid;place-items:center;border:1px solid #0ea5e9;border-radius:10px;background:#082f49;color:#7dd3fc;font:800 16px ui-monospace,monospace}.brand h1{font-size:22px;line-height:1.2;margin:0}.brand p{margin:5px 0 0;color:var(--muted);font-size:13px}
.header-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.nav-link{display:inline-flex;align-items:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;color:var(--text);text-decoration:none;background:var(--surface-3)}
.nav-link:hover,.btn:hover{filter:brightness(1.12)}.nav-link:focus-visible,.btn:focus-visible,.host-toggle:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.refresh-time{color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}.kpi-card{padding:14px 16px;border:1px solid var(--border);border-radius:12px;background:var(--surface)}.kpi-label{color:var(--muted);font-size:12px}.kpi-value{display:block;margin-top:5px;font-size:24px;font-weight:750;font-variant-numeric:tabular-nums}.kpi-value.danger{color:#fca5a5}
.section-card{margin-bottom:18px;border:1px solid var(--border);border-radius:14px;background:var(--surface);overflow:hidden}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding:15px 16px;border-bottom:1px solid var(--border);background:var(--surface-2)}.section-head h2{margin:0;font-size:17px}.section-head p{margin:4px 0 0;color:var(--muted);font-size:12px}.section-body{padding:14px;min-width:0}
table{background:var(--surface);color:var(--text)}th,td{border-color:var(--border)}th{background:var(--surface-3);color:#cbd5e1;font-size:12px;letter-spacing:.02em}td{font-size:13px}.bad,.severity-critical{color:#fca5a5}.ok{color:#86efac}.severity-warning{color:#fcd34d}
.host-group,.container-card,.panel{background:var(--surface);border-color:var(--border);box-shadow:none}.host-toggle{background:var(--surface-2);color:var(--text)}.host-toggle:hover{background:#1e293b}.metric,.info-block{background:#0b1220;border-color:var(--border)}.host-subtitle,.metric-label,.kv dt,.action-status{color:var(--muted)}
.pill{border-color:var(--border);background:#111827;color:#cbd5e1}.pill-ok{border-color:#166534;background:#052e16;color:#86efac}.pill-warn{border-color:#92400e;background:#451a03;color:#fcd34d}.pill-bad{border-color:#991b1b;background:#450a0a;color:#fca5a5}.version-dot{width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:6px;flex:none}
#modal{background:rgba(2,6,23,.82);backdrop-filter:blur(3px)}#card{background:var(--surface);border:1px solid var(--border)}
@media (max-width:1000px){
  .host-toggle{grid-template-columns:24px minmax(0,1fr)}
  .host-summary{grid-column:2;justify-content:flex-start}
  .container-info-grid{grid-template-columns:1fr}
  .snapshot-grid,.detail-grid{grid-template-columns:1fr}
}
@media (max-width:680px){
  .app-shell{padding:8px}.app-header{padding:14px;flex-direction:column}.header-actions{justify-content:flex-start}.kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.section-body{padding:8px}
  th,td{padding:6px;font-size:12px}
  .host-toggle{padding:12px 10px;gap:8px}
  .host-panel{padding:9px}
  .metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .container-head{flex-direction:column}
  .host-summary{gap:5px}
  #security-alerts th:nth-child(4),#security-alerts td:nth-child(4),#security-alerts th:nth-child(7),#security-alerts td:nth-child(7),#security-alerts th:nth-child(8),#security-alerts td:nth-child(8){display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style>
</head><body>
<a class='skip-link' href='#main-content'>跳到主要内容</a>
<main id='main-content' class='app-shell'>
<header class='app-header'><div class='brand'><span class='brand-mark' aria-hidden='true'>NW</span><div><h1>Narwhal Monitor</h1><p>容器安全与运行状态中心</p></div></div><div class='header-actions'><span id='server-version' class='pill'>Server 正在连接</span><span id='last-refresh' class='refresh-time'>尚未刷新</span><a class='nav-link' href='/alerts/history'>告警历史</a><a class='nav-link' href='/stats'>数据统计</a></div></header>
<section class='kpi-grid' aria-label='运行概览'><article class='kpi-card'><span class='kpi-label'>在线主机</span><strong id='kpi-hosts' class='kpi-value'>0</strong></article><article class='kpi-card'><span class='kpi-label'>监控容器</span><strong id='kpi-containers' class='kpi-value'>0</strong></article><article class='kpi-card'><span class='kpi-label'>活动告警</span><strong id='kpi-alerts' class='kpi-value danger'>0</strong></article><article class='kpi-card'><span class='kpi-label'>离线容器</span><strong id='kpi-offline' class='kpi-value'>0</strong></article></section>
<section class='section-card'><header class='section-head'><div><h2>安全告警 <span class='pill pill-bad'>活动 <span id='active-alert-count'>0</span></span></h2><p>机场组件禁止操作执行定向清理；无认证 SOCKS 操作只停止对应服务并持续拦截，均不会停止容器。</p></div></header><div class='section-body'><table id='security-alerts'><thead><tr><th>级别</th><th>主机</th><th>运行时/项目</th><th>容器</th><th>类型</th><th>说明</th><th>最近出现</th><th>次数</th><th>操作</th></tr></thead><tbody></tbody></table></div></section>
<section class='section-card'><header class='section-head'><div><h2>主机安全遥测</h2><p>低开销汇总网络与连接状态。</p></div></header><div class='section-body'><table id='security-status'><thead><tr><th>主机</th><th>RX Mbps</th><th>RX pps</th><th>SYN_RECV</th><th>HTTP RPS</th><th>最高单IP RPS</th><th>采样时间</th></tr></thead><tbody></tbody></table></div></section>
<section class='section-card'><header class='section-head'><div><h2>容器状态</h2><p>按主机折叠；版本、在线状态与运行时分布集中显示。</p></div></header><div class='section-body'><div id='host-containers' class='host-list' aria-live='polite'><div class='empty-state'>正在加载节点数据…</div></div></div></section>
</main>
<div id='modal'><div id='card'>
  <h3 id='detail-title'></h3>
  <div class='detail-grid'>
    <div class='panel'>
      <h4>负载详情</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>CPU%</span>
        <span class='legend-item'><span class='dot' style='background:#16a085'></span>内存%</span>
        <span class='legend-item'><span class='dot' style='background:#9b59b6'></span>连接数</span>
        <span class='legend-item'><span class='dot' style='background:#f39c12'></span>总网速 Mbps</span>
      </div>
      <svg id='chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
    <div class='panel'>
      <h4>带宽监控</h4>
      <div class='legend'>
        <span class='legend-item'><span class='dot' style='background:#2ecc71'></span>下行 RX Mbps</span>
        <span class='legend-item'><span class='dot' style='background:#4a90e2'></span>上行 TX Mbps</span>
      </div>
      <svg id='bandwidth' viewBox='0 0 900 220' preserveAspectRatio='none'></svg>
    </div>
  </div>
  <div class='snapshot-grid'>
    <div class='panel'><h4>当前速率与资源</h4><div id='detail-current'></div></div>
    <div class='panel'><h4>进程排查</h4><div id='detail-processes'></div></div>
    <div class='panel'><h4>安全与暴露面</h4><div id='detail-risks'></div></div>
  </div>
  <div class='panel' style='margin-top:12px'>
    <h4>流量统计（累计字节）</h4>
    <svg id='traffic' viewBox='0 0 1200 280' preserveAspectRatio='none'></svg>
  </div>
  <p><button class='btn' onclick='closeDetail()'>关闭</button></p>
</div></div>
<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)}${units[i]}`;
}
function bpsToMbps(v){
  return (Number(v||0) * 8) / 1000 / 1000;
}
function formatSmallNumber(v, digits=2){
  const n = Number(v||0);
  if (!Number.isFinite(n)) return '0.00';
  const threshold = 1 / Math.pow(10, digits);
  if (n > 0 && n < threshold) return `<${threshold.toFixed(digits)}`;
  return n.toFixed(digits);
}
function formatCountryLine(protocol, stats){
  const arr = Array.isArray(stats) ? stats : [];
  if(!arr.length) return `${protocol} - -`;
  const top3 = arr.slice(0,3).map(x=>`${x.country||'UN'} (${Number(x.connections||0)})`).join('  ');
  return `${protocol} - ${top3}`;
}
function formatCountryStats(tcpStats, udpStats){
  return `${formatCountryLine('TCP', tcpStats)}<br/>${formatCountryLine('UDP', udpStats)}`;
}
function formatCapacity(total, avail){
  return Number(total||0)>0 ? `${fmtBytes(total)} / ${fmtBytes(avail)}` : '采集不可用';
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
const alertsById=new Map();
const submittingAlertActions=new Set();
function remediationChanged(action){
  if(!action||!['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)||action.status!=='succeeded'||!remediationReceipt(action))return false;
  const text=String(action.result_message||'');
  const values=[...text.matchAll(/\\b(?:killed_processes|removed_services|removed_configs|removed_binaries)=(\\d+)\\b/g)].map(x=>Number(x[1]||0));
  return values.some(x=>x>0);
}
function remediationReceipt(action){
  const text=String(action?.result_message||'');
  const has=key=>new RegExp('\\\\b'+key+'=\\\\d+\\\\b').test(text);
  const count=key=>Number((text.match(new RegExp('\\\\b'+key+'=(\\\\d+)\\\\b'))||[])[1]||0);
  const noProcessTargets=/\\bno_process_targets=1\\b/.test(text);
  const hasProcessScan=(has('matched_processes')||has('host_matched_processes'))&&!noProcessTargets;
  const hasConfigScan=noProcessTargets&&count('checked_configs')>0;
  if(!has('cleanup_errors')||!has('signal_errors')||(!hasProcessScan&&!hasConfigScan)||!/\\bremaining_processes=0\\b/.test(text))return false;
  const signalErrors=count('signal_errors'),hostMatched=count('host_matched_processes'),hostKilled=count('host_killed_processes'),hostErrors=count('host_kill_errors');
  const signalRecovered=signalErrors===0||(has('host_matched_processes')&&has('host_killed_processes')&&has('host_kill_errors')&&hostMatched>=signalErrors&&hostKilled>=signalErrors&&hostErrors===0);
  return count('cleanup_errors')===0&&hostErrors===0&&signalRecovered;
}
function remediationComplete(action){
  if(!action||!['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)||action.status!=='succeeded')return false;
  const text=String(action.result_message||'');
  if(!remediationReceipt(action))return false;
  if(remediationChanged(action))return true;
  return /\\btarget_state=already_absent\\b/.test(text)||/\\b(?:matched_processes|host_matched_processes)=0\\b/.test(text)||/\\bchecked_configs=\\d+\\b/.test(text);
}
function actionStatusText(action){
  if(!action)return '';
  if(action.status==='queued')return '等待节点领取（正常情况下约 10 秒内）';
  if(action.status==='dispatched')return action.action_type==='enforce_socks_auth'?'节点已领取，正在停止无认证 SOCKS':(action.action_type==='release_socks_auth'?'节点已领取，正在解除 SOCKS 持续拦截':'节点已领取，正在执行清理');
  if(['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)&&action.status==='succeeded'&&!remediationChanged(action)&&remediationComplete(action)){
    return '目标进程已复查为不在运行，本次无需重复清理；等待后续采样确认。';
  }
  if(['remediate_panel_pairing','remediate_malicious_process'].includes(action.action_type)&&action.status==='succeeded'&&!remediationComplete(action)){
    return `处置结果未验证：${action.result_message||'节点未确认目标进程已停止'}`;
  }
  const labels={succeeded:'已完成',failed:'失败'};
  const result=action.result_message?`：${action.result_message}`:'';
  return `${labels[action.status]||action.status}${result}`;
}
async function setAlertDisposition(alertId, decision){
  const alert=alertsById.get(Number(alertId)); if(!alert)return;
  if(submittingAlertActions.has(Number(alertId)))return;
  const details=alert.details||{};
  const latestAction=alert.latest_action||null;
  const socksPolicyActive=alert.type==='socks_weak_auth'&&latestAction?.action_type==='enforce_socks_auth'&&latestAction?.status==='succeeded'&&['no_auth','weak_password'].includes(details.socks_auth_mode);
  let promptText='';
  if(decision==='deny'){
    if(alert.type==='socks_weak_auth'){
      const processes=(details.socks_processes||[]).join(', ')||'无';
      promptText=`确认停止 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内的无认证 SOCKS 服务并启用持续拦截？\n\n目标进程：${processes}\n不会停止容器，不会删除配置或服务文件。以后检测到该容器再次以无认证/空密码方式运行时会自动停止；检测到非空认证后会自动解除拦截，允许服务恢复。`;
    }else if(alert.type==='malicious_process'){
      const processes=(details.malicious_processes||[]).map(item=>`${item.process}${item.pid?` (PID ${item.pid})`:''}`).join(', ')||'无';
      promptText=`确认清理 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内精确识别的 XMRig 挖矿程序？\n\n目标：${processes}\n将终止进程、停用对应服务并删除明确的 XMRig 配置和二进制文件；不会停止容器。`;
    }else{
      const processes=(details.process_patterns||[]).join(', ')||'无';
      const files=(details.config_files||[]).join(', ')||'无';
      promptText=`确认禁止并清理 ${alert.host_id} / ${alert.runtime} / ${alert.container_name} 内的机场对接组件？\n\n将终止进程特征：${processes}\n停用并删除对应服务，删除配置：${files}\n容器本身不会停止。成功后同一面板域名再次出现会自动清理且不再提醒。`;
    }
  }else if(decision==='allow_silent'){
    if(socksPolicyActive){
      promptText=`确认解除持续拦截并永久允许此 SOCKS 服务？\n\n节点会删除持续拦截策略，此告警以后不再提醒。即使服务仍然无认证并对公网/NAT 暴露，也不会再次自动停止。`;
    }else if(alert.type==='socks_weak_auth'){
      promptText=`确认允许此 SOCKS 告警且以后不再提醒？\n\n该告警指纹会被永久抑制，节点不会为这条告警启用持续拦截。`;
    }else{
      promptText=`确认允许此告警且以后不再提醒？\n\n该告警指纹会被永久抑制；机场面板域名还会同步加入节点放行名单。`;
    }
  }else{
    promptText=socksPolicyActive
      ?`确认仅隐藏本次告警并保留持续拦截？\n\n节点侧拦截策略不会解除；无认证 SOCKS 再次启动时仍会被自动停止。事件消失后如果再次出现，仍会重新告警。`
      :`确认仅取消本次提醒？\n\n当前连续出现期间不再显示；事件消失后如果再次出现，仍会重新告警。`;
  }
  if(!confirm(promptText))return;
  submittingAlertActions.add(Number(alertId));
  document.querySelectorAll(`[data-alert-action="${Number(alertId)}"]`).forEach(button=>{button.disabled=true;});
  const status=document.querySelector(`[data-alert-status="${Number(alertId)}"]`);
  if(status)status.textContent='正在提交操作…';
  try{
    const response=await fetch(`/api/v1/security/alerts/${Number(alertId)}/disposition`,{
      method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision})
    });
    const result=await response.json();
    if(!response.ok)throw new Error(result.detail||`HTTP ${response.status}`);
    await loadAlerts();
  }catch(error){window.alert(`操作提交失败：${error.message||error}`);}
  finally{submittingAlertActions.delete(Number(alertId));}
}
async function loadAlerts(){
  const response=await fetch('/api/v1/security/alerts?active_only=true&limit=100');
  const data=await response.json();
  document.getElementById('active-alert-count').innerText=Number(data.active_count||0);
  document.getElementById('kpi-alerts').innerText=Number(data.active_count||0);
  const body=document.querySelector('#security-alerts tbody'); body.innerHTML='';
  alertsById.clear();
  for(const alert of (data.items||[])){
    alertsById.set(Number(alert.id),alert);
    const tr=document.createElement('tr');
    const runtime=alert.project?`${alert.runtime}/${alert.project}`:(alert.runtime||'-');
    const supportedRuntime=alert.runtime==='podman'||alert.runtime==='incus';
    const canPanelRemediate=supportedRuntime&&alert.type==='unauthorized_panel_pairing'&&((alert.details?.process_patterns||[]).length>0||(alert.details?.config_files||[]).length>0);
    const canSocksRemediate=supportedRuntime&&alert.type==='socks_weak_auth'&&['no_auth','weak_password'].includes(alert.details?.socks_auth_mode)&&(alert.details?.socks_processes||[]).length>0;
    const canMaliciousRemediate=supportedRuntime&&alert.type==='malicious_process'&&(alert.details?.malicious_processes||[]).some(item=>item.process==='xmrig');
    const pending=alert.latest_action&&(alert.latest_action.status==='queued'||alert.latest_action.status==='dispatched');
    const lastRemediation=['remediate_panel_pairing','remediate_malicious_process'].includes(alert.latest_action?.action_type)?alert.latest_action:null;
    const lastSocksEnforcement=alert.latest_action?.action_type==='enforce_socks_auth'?alert.latest_action:null;
    const changed=remediationChanged(lastRemediation);
    const completed=remediationComplete(lastRemediation);
    const recurred=completed&&Number(alert.last_seen||0)>Number(lastRemediation?.updated_at||0);
    const denyLabel=pending?'禁止处理中':((lastRemediation&&(lastRemediation.status==='failed'||!completed))?'重试禁止':(recurred?'再次禁止':'禁止'));
    const socksPolicyActive=lastSocksEnforcement?.status==='succeeded'&&['no_auth','weak_password'].includes(alert.details?.socks_auth_mode);
    const socksReleased=alert.details?.socks_auth_enforcement?.released===true;
    let denyControl='';
    if(canSocksRemediate){
      const socksLabel=pending?'正在启用持续拦截':(lastSocksEnforcement?.status==='failed'?'重试停止并持续拦截':'停止并持续拦截');
      denyControl=socksPolicyActive?`<span class='ok'>持续拦截已启用</span>`:`<button class='btn btn-danger' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'deny')">${socksLabel}</button>`;
    }else if(canPanelRemediate||canMaliciousRemediate){
      denyControl=completed&&!recurred?`<span class='ok'>${changed?'已处置，等待复检':'目标进程已不存在，等待复检'}</span>`:`<button class='btn btn-danger' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'deny')">${denyLabel}</button>`;
    }else if(socksReleased){denyControl=`<span class='ok'>已检测到非空认证，持续拦截已解除</span>`;}
    const allowLabel=socksPolicyActive?'解除拦截并允许（不再提醒）':'允许且不再提醒';
    const dismissLabel=socksPolicyActive?'仅隐藏本次告警（保留拦截）':'本次取消提醒';
    const actions=`<div class='security-action-state'>${denyControl}</div><div class='security-action-buttons'>`+
      `<button class='btn btn-allow' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'allow_silent')">${allowLabel}</button>`+
      `<button class='btn btn-dismiss' data-alert-action="${Number(alert.id)}" ${pending?'disabled':''} onclick="setAlertDisposition(${Number(alert.id)},'dismiss_once')">${dismissLabel}</button></div>`;
    tr.innerHTML=`<td class='severity-${escapeHtml(alert.severity)}'>${escapeHtml(alert.severity)}</td>`+
      `<td>${escapeHtml(alert.host_id)}</td><td>${escapeHtml(runtime)}</td>`+
      `<td>${escapeHtml(alert.container_name||'-')}</td><td>${escapeHtml(alert.type)}</td>`+
      `<td>${escapeHtml(alert.message)}</td><td>${escapeHtml(alert.last_seen_utc8)}</td>`+
      `<td>${Number(alert.occurrence_count||0)}</td><td>${actions}<div class='action-status' data-alert-status="${Number(alert.id)}">${escapeHtml(socksReleased?'非空认证已确认，节点已自动解除持续拦截':actionStatusText(alert.latest_action))}</div></td>`;
    body.appendChild(tr);
  }
  const statusResponse=await fetch('/api/v1/security/status');
  const statusData=await statusResponse.json();
  const statusBody=document.querySelector('#security-status tbody'); statusBody.innerHTML='';
  for(const item of (statusData.items||[])){
    const access=item.access_log||{};
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${escapeHtml(item.host_id)}</td>`+
      `<td>${formatSmallNumber(bpsToMbps(item.total_rx_bps),2)}</td>`+
      `<td>${formatSmallNumber(item.total_rx_pps,1)}</td><td>${Number(item.syn_recv_count||0)}</td>`+
      `<td>${formatSmallNumber(access.requests_per_second,1)}</td>`+
      `<td>${formatSmallNumber(access.top_ip_requests_per_second,1)} ${escapeHtml(access.top_ip||'')}</td>`+
      `<td>${escapeHtml(item.timestamp_utc8)}</td>`;
    statusBody.appendChild(tr);
  }
}
function groupByHost(items){
  const m=new Map();
  for(const x of items){
    if(!m.has(x.host_id))m.set(x.host_id,[]);
    m.get(x.host_id).push(x);
  }
  return [...m.entries()];
}
function containerDetailUrl(host,runtime,project,container){
  const q=new URLSearchParams({host,runtime,project:project||'',container});
  return `/container-detail?${q.toString()}`;
}
const expandedHosts=new Set();
function versionBadge(agentVersion,serverVersion){
  const client=String(agentVersion||'unknown'),server=String(serverVersion||'dev');
  if(client==='unknown'||client==='dev')return `<span class='pill pill-warn'><i class='version-dot'></i>Client 版本未知</span>`;
  if(server==='dev')return `<span class='pill pill-warn'><i class='version-dot'></i>Client v${escapeHtml(client)} · Server dev</span>`;
  if(client===server)return `<span class='pill pill-ok'><i class='version-dot'></i>v${escapeHtml(client)} · 最新</span>`;
  return `<span class='pill pill-bad'><i class='version-dot'></i>Client v${escapeHtml(client)} · 应为 v${escapeHtml(server)}</span>`;
}
function setHostExpanded(host, group, button, panel, expanded){
  if(expanded)expandedHosts.add(host);else expandedHosts.delete(host);
  group.classList.toggle('is-open',expanded);
  button.setAttribute('aria-expanded',String(expanded));
  panel.hidden=!expanded;
}
async function load(){
  const r=await fetch('/api/v1/latest'); const d=await r.json();
  const hostList=document.getElementById('host-containers'); hostList.innerHTML='';
  const groups=groupByHost(d.items||[]);
  const offlineTotal=(d.items||[]).filter(x=>x.alerts?.stale).length;
  document.getElementById('server-version').className=`pill ${d.server_version&&d.server_version!=='dev'?'pill-ok':'pill-warn'}`;
  document.getElementById('server-version').innerHTML=`<i class='version-dot'></i>Server ${d.server_version&&d.server_version!=='dev'?`v${escapeHtml(d.server_version)}`:'dev'}`;
  document.getElementById('last-refresh').innerText=`最近刷新 ${new Date().toLocaleTimeString('zh-CN',{hour12:false})}`;
  document.getElementById('kpi-hosts').innerText=groups.length;
  document.getElementById('kpi-containers').innerText=(d.items||[]).length;
  document.getElementById('kpi-offline').innerText=offlineTotal;
  if(!groups.length){
    hostList.innerHTML="<div class='empty-state'>暂未收到容器上报</div>";
    return;
  }
  groups.forEach(([host, rows],hostIndex)=>{
    rows.sort((a,b)=>a.container_name.localeCompare(b.container_name));
    const latest=rows.reduce((best,item)=>Number(item.timestamp||0)>Number(best.timestamp||0)?item:best,rows[0]);
    const offlineCount=rows.filter(x=>x.alerts?.stale).length;
    const runtimeCounts=new Map();
    rows.forEach(x=>{
      const runtimeBase=x.project&&x.runtime==='incus'?`${x.runtime}/${x.project}`:(x.runtime||'podman');
      runtimeCounts.set(runtimeBase,(runtimeCounts.get(runtimeBase)||0)+1);
    });
    const hostMount=latest.disk_data_mountpoint||latest.disk_data_requested_path||'/';
    const hostDiskText=`${hostMount}: ${formatCapacity(latest.disk_data_total_bytes,latest.disk_data_avail_bytes)}`;
    const panelId=`host-panel-${hostIndex}`;
    const toggleId=`host-toggle-${hostIndex}`;
    const group=document.createElement('section');
    group.className='host-group';
    const toggle=document.createElement('button');
    toggle.type='button';
    toggle.id=toggleId;
    toggle.className='host-toggle';
    toggle.setAttribute('aria-controls',panelId);
    toggle.innerHTML=`<svg class='host-chevron' viewBox='0 0 24 24' aria-hidden='true'><path d='m9 5 7 7-7 7' fill='none' stroke='currentColor' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/></svg>`+
      `<span class='host-title'><span class='host-name'>${escapeHtml(host)}</span><span class='host-subtitle'>${rows.length} 个容器 · 主盘 ${escapeHtml(hostDiskText)} · 最近上报 ${escapeHtml(latest.timestamp_iso_utc8||'-')}</span></span>`+
      `<span class='host-summary'>${[...runtimeCounts.entries()].map(([name,count])=>`<span class='pill'>${escapeHtml(name)} ${count}</span>`).join('')}`+
      `${versionBadge(latest.agent_version,d.server_version)}`+
      `<span class='pill ${offlineCount?'pill-bad':'pill-ok'}'>${offlineCount?`${offlineCount} 个离线`:'全部在线'}</span>`+
      `<span class='pill ${latest.container_network_ok_v4?'pill-ok':'pill-bad'}'>主机 IPv4 ${latest.container_network_ok_v4?'正常':'异常'}</span>`+
      `<span class='pill ${latest.container_network_ok_v6?'pill-ok':'pill-warn'}'>主机 IPv6 ${latest.container_network_ok_v6?'正常':'不可用'}</span></span>`;
    const panel=document.createElement('div');
    panel.id=panelId;
    panel.className='host-panel';
    panel.setAttribute('role','region');
    panel.setAttribute('aria-labelledby',toggleId);
    const grid=document.createElement('div');
    grid.className='containers-grid';
    rows.forEach(x=>{
      const cpuCls=x.alerts.cpu?'bad':'';
      const connSeverity=x.alerts?.conn_severity||'';
      const connCls=connSeverity==='critical'?'bad':(connSeverity==='warning'?'severity-warning':'');
      const connWarningThreshold=Number(x.alerts?.conn_warning_threshold||500),connCriticalThreshold=Number(x.alerts?.conn_critical_threshold||1000);
      const connHint=connSeverity==='critical'?`严重告警：连接数超过 ${connCriticalThreshold}`:(connSeverity==='warning'?`告警：连接数超过 ${connWarningThreshold}`:'连接数正常');
      const containerDiskText = formatCapacity(x.container_fs_root_total_bytes, x.container_fs_root_avail_bytes);
      const offlineText=x.alerts.stale?`离线 ${Number(x.offline_hours||0)} 小时`:'在线';
      const runtimeBase = x.project && x.runtime==='incus' ? `${x.runtime}/${x.project}` : (x.runtime||'podman');
      const runtimeText = x.monitor_mode==='notice' ? `${runtimeBase}（仅提醒）` : runtimeBase;
      const security=x.security||{};
      const inboundUniqueIps=Number(security.inbound_unique_ips||0);
      const inboundThreshold=Number(security.inbound_unique_ip_threshold||10);
      const inboundCls=inboundUniqueIps>inboundThreshold?'bad':'';
      const protocolRates=security.protocol_rates||{};
      const panelPairing=security.panel_pairing||{};
      const pairingText=panelPairing.detected?(panelPairing.approved?'白名单':((panelPairing.unapproved_domains||[]).join(',')||'发现特征')):'-';
      const listeningPorts=Array.isArray(security.listening_ports)?security.listening_ports.slice(0,8).join(','):'-';
      const exposureText=Array.isArray(security.network_exposure)&&security.network_exposure.length?security.network_exposure.slice(0,6).map(item=>`${item.listen||'?'}→${item.target||'?'}`).join(', '):'-';
      const suspiciousCount=Array.isArray(security.suspicious_processes)?security.suspicious_processes.length:0;
      const riskCount=Array.isArray(security.configuration_risks)?security.configuration_risks.length:0;
      const card=document.createElement('article');
      card.className='container-card';
      card.innerHTML=`<div class='container-head'><div><div class='container-name'>${escapeHtml(x.container_name||'-')}</div>`+
        `<div class='container-meta'>${escapeHtml(runtimeText)} · ID ${escapeHtml(x.container_id||'-')}</div></div>`+
        `<span class='pill ${x.alerts.stale?'pill-bad':'pill-ok'}'>${escapeHtml(offlineText)}</span></div>`+
        `<div class='metric-grid'>`+
        `<div class='metric'><span class='metric-label'>CPU</span><strong class='metric-value ${cpuCls}'>${formatSmallNumber(x.cpu_percent,2)}%</strong></div>`+
        `<div class='metric'><span class='metric-label'>内存</span><strong class='metric-value'>${formatSmallNumber(x.mem_percent,2)}%</strong></div>`+
        `<div class='metric'><span class='metric-label'>入站去重 IP</span><strong class='metric-value ${inboundCls}'>${inboundUniqueIps}</strong></div>`+
        `<div class='metric' title='${escapeHtml(connHint)}'><span class='metric-label'>连接数${connSeverity==='critical'?' · 严重':(connSeverity==='warning'?' · 告警':'')}</span><strong class='metric-value ${connCls}'>${Number(x.conn_count||0)}</strong></div>`+
        `<div class='metric'><span class='metric-label'>进程数</span><strong class='metric-value'>${Number(security.process_count||0)}</strong></div>`+
        `<div class='metric'><span class='metric-label'>RX</span><strong class='metric-value'>${formatSmallNumber(bpsToMbps(x.net_rx_bps),2)} Mbps</strong></div>`+
        `<div class='metric'><span class='metric-label'>TX</span><strong class='metric-value'>${formatSmallNumber(bpsToMbps(x.net_tx_bps),2)} Mbps</strong></div>`+
        `<div class='metric'><span class='metric-label'>容器根盘 总量/可用</span><strong class='metric-value'>${escapeHtml(containerDiskText)}</strong></div></div>`+
        `<div class='container-info-grid'>`+
        `<section class='info-block'><h4>流量与连接</h4><dl class='kv'><dt>RX pps</dt><dd>${formatSmallNumber(security.net_rx_pps,1)}</dd><dt>SYN_RECV</dt><dd>${Number(security.syn_recv_count||0)}</dd><dt>入站 IP</dt><dd class='${inboundCls}'>${inboundUniqueIps} / 阈值 ${inboundThreshold}</dd><dt>入站连接</dt><dd>${Number(security.incoming_established||0)}</dd><dt>出站 IP</dt><dd>${Number(security.outbound_unique_ips||0)}</dd><dt>TCP 建连/s</dt><dd>${formatSmallNumber(protocolRates.Tcp_ActiveOpens_per_second,1)}</dd><dt>TCP 失败/s</dt><dd>${formatSmallNumber(protocolRates.Tcp_AttemptFails_per_second,1)}</dd></dl></section>`+
        `<section class='info-block'><h4>端口与网络</h4><dl class='kv'><dt>监听端口</dt><dd>${escapeHtml(listeningPorts||'-')}</dd><dt>NAT/代理</dt><dd>${escapeHtml(exposureText)}</dd><dt>来源 Top3</dt><dd>${formatCountryStats(x.tcp_country_stats,x.udp_country_stats)}</dd></dl></section>`+
        `<section class='info-block'><h4>安全检查</h4><dl class='kv'><dt>面板对接</dt><dd class='${panelPairing.detected&&!panelPairing.approved?'bad':''}'>${escapeHtml(pairingText)}</dd><dt>可疑进程</dt><dd class='${suspiciousCount?'bad':''}'>${suspiciousCount}</dd><dt>配置风险</dt><dd class='${riskCount?'bad':''}'>${riskCount}</dd><dt>采样时间</dt><dd>${escapeHtml(x.timestamp_iso_utc8||'-')}</dd></dl></section></div>`+
        `<div class='container-actions'><button type='button' class='btn detail-button'>查看容器详情</button></div>`;
      card.querySelector('.detail-button').addEventListener('click',()=>{
        location.href=containerDetailUrl(host,x.runtime,x.project||'',x.container_name);
      });
      grid.appendChild(card);
    });
    panel.appendChild(grid);
    group.appendChild(toggle);
    group.appendChild(panel);
    hostList.appendChild(group);
    const isExpanded=expandedHosts.has(host);
    setHostExpanded(host,group,toggle,panel,isExpanded);
    toggle.addEventListener('click',()=>setHostExpanded(host,group,toggle,panel,!expandedHosts.has(host)));
  });
}
function closeDetail(){ document.getElementById('modal').style.display='none'; }
function buildPolyline(vals,maxv,w,h,pad){
  const useMax=Math.max(1,maxv);
  return vals.map((v,i)=>`${i*(w/Math.max(1,vals.length-1))},${(h-pad)-((v/useMax)*(h-pad*2))}`).join(' ');
}
function drawAxes(svg,w,h){
  const lines=[];
  for(let i=0;i<=5;i++){
    const y=(h-20)-(i*((h-40)/5));
    lines.push(`<line x1='0' y1='${y}' x2='${w}' y2='${y}' stroke='#29466f' stroke-width='1' />`);
  }
  svg.innerHTML=lines.join('');
}
function estimateStepSeconds(points){
  if(!points || points.length < 2) return 0;
  const intervals=[];
  for(let i=1;i<points.length;i++){
    intervals.push(Math.max(1, Number(points[i].timestamp||0)-Number(points[i-1].timestamp||0)));
  }
  return intervals.reduce((a,b)=>a+b,0)/intervals.length;
}
async function openDetail(host, runtime, project, container){
  const latestRes=await fetch('/api/v1/latest');
  const latestData=await latestRes.json();
  const target=(latestData.items||[]).find(x=>x.host_id===host&&x.runtime===runtime&&(x.project||'')===project&&x.container_name===container);
  const countryTop=formatCountryStats(target?.tcp_country_stats||[], target?.udp_country_stats||[]);
  const res=await fetch(`/api/v1/history?host_id=${encodeURIComponent(host)}&runtime=${encodeURIComponent(runtime)}&project=${encodeURIComponent(project)}&container_name=${encodeURIComponent(container)}`);
  const data=await res.json();
  const runtimeLabel=project ? `${runtime}/${project}` : runtime;
  document.getElementById('detail-title').innerText=`${host} / ${runtimeLabel} / ${container} 历史数据（TCP国家：${countryTop.replaceAll('<br/>', ', ')}）`;
  const pts=data.items||[];
  const recent=pts.slice(-80);
  const svg=document.getElementById('chart');
  const bandwidthSvg=document.getElementById('bandwidth');
  const trafficSvg=document.getElementById('traffic');
  const security=target?.security||{};
  const rates=security.protocol_rates||{};
  const topProcess=target?.top_cpu_process_command?
    `PID ${Number(target.top_cpu_process_pid||0)} · CPU ${formatSmallNumber(target.top_cpu_process_cpu_percent,2)}% · ${escapeHtml(target.top_cpu_process_command)}`:'未采集到高 CPU 进程';
  const suspicious=Array.isArray(security.suspicious_processes)?security.suspicious_processes:[];
  const risks=Array.isArray(security.configuration_risks)?security.configuration_risks:[];
  const exposures=Array.isArray(security.network_exposure)?security.network_exposure:[];
  document.getElementById('detail-current').innerHTML=`CPU ${formatSmallNumber(target?.cpu_percent,2)}% · 内存 ${formatSmallNumber(target?.mem_percent,2)}%<br/>连接 ${Number(target?.conn_count||0)} · 进程 ${Number(security.process_count||0)}<br/>入站去重 IP ${Number(security.inbound_unique_ips||0)} / 阈值 ${Number(security.inbound_unique_ip_threshold||10)}<br/>RX ${formatSmallNumber(bpsToMbps(target?.net_rx_bps),2)} Mbps / ${formatSmallNumber(security.net_rx_pps,1)} pps<br/>TX ${formatSmallNumber(bpsToMbps(target?.net_tx_bps),2)} Mbps<br/>TCP 建连 ${formatSmallNumber(rates.Tcp_ActiveOpens_per_second,1)}/s · 失败 ${formatSmallNumber(rates.Tcp_AttemptFails_per_second,1)}/s`;
  document.getElementById('detail-processes').innerHTML=`<div>${topProcess}</div>`+
    (suspicious.length?`<ul class='snapshot-list'>${suspicious.map(x=>`<li>PID ${Number(x.pid||0)} · ${escapeHtml(x.pattern||x.command||'可疑进程')}</li>`).join('')}</ul>`:'<div class="ok">未发现可疑进程特征</div>');
  document.getElementById('detail-risks').innerHTML=`监听端口：${escapeHtml((security.listening_ports||[]).join(', ')||'-')}<br/>`+
    `NAT/代理：${escapeHtml(exposures.map(x=>`${x.listen||'?'}→${x.target||'?'}`).join(', ')||'-')}`+
    (risks.length?`<ul class='snapshot-list'>${risks.map(x=>`<li>${escapeHtml(x.message||x.type||JSON.stringify(x))}</li>`).join('')}</ul>`:'<div class="ok">未发现配置风险</div>');
  if(!recent.length){
    svg.innerHTML = '';
    bandwidthSvg.innerHTML = '';
    trafficSvg.innerHTML = '';
    document.getElementById('modal').style.display='flex';
    return;
  }
  const cpuVals=recent.map(x=>Number(x.cpu_percent||0));
  const memVals=recent.map(x=>Number(x.mem_percent||0));
  const connVals=recent.map(x=>Number(x.conn_count||0));
  const rxMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_rx_bps||0)));
  const txMbpsVals=recent.map(x=>bpsToMbps(Number(x.net_tx_bps||0)));
  const speedVals=rxMbpsVals.map((v,i)=>v+txMbpsVals[i]);
  const step=estimateStepSeconds(recent) || 300;
  let rxTotal=0; let txTotal=0;
  const rxBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    rxTotal+=Number(x.net_rx_bps||0)*currentStep;
    return rxTotal;
  });
  const txBytesCum=recent.map((x,i)=>{
    const currentStep=i===0?step:Math.max(1, Number(recent[i].timestamp||0)-Number(recent[i-1].timestamp||0));
    txTotal+=Number(x.net_tx_bps||0)*currentStep;
    return txTotal;
  });

  drawAxes(svg,900,220);
  const cpuPoints=buildPolyline(cpuVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const memPoints=buildPolyline(memVals, Math.max(100, ...cpuVals, ...memVals), 900, 220, 20);
  const connPoints=buildPolyline(connVals, Math.max(1, ...connVals), 900, 220, 20);
  const speedPoints=buildPolyline(speedVals, Math.max(1, ...speedVals), 900, 220, 20);
  svg.innerHTML += `
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${cpuPoints}' />
    <polyline fill='none' stroke='#16a085' stroke-width='2.5' points='${memPoints}' />
    <polyline fill='none' stroke='#9b59b6' stroke-width='2.5' points='${connPoints}' />
    <polyline fill='none' stroke='#f39c12' stroke-width='2.5' points='${speedPoints}' />
  `;

  drawAxes(bandwidthSvg,900,220);
  const rxPoints=buildPolyline(rxMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  const txPoints=buildPolyline(txMbpsVals, Math.max(1, ...rxMbpsVals, ...txMbpsVals), 900, 220, 20);
  bandwidthSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txPoints}' />
  `;

  drawAxes(trafficSvg,1200,280);
  const rxCumPoints=buildPolyline(rxBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  const txCumPoints=buildPolyline(txBytesCum, Math.max(1, ...rxBytesCum, ...txBytesCum), 1200, 280, 20);
  trafficSvg.innerHTML += `
    <polyline fill='none' stroke='#2ecc71' stroke-width='2.5' points='${rxCumPoints}' />
    <polyline fill='none' stroke='#4a90e2' stroke-width='2.5' points='${txCumPoints}' />
  `;
  document.getElementById('modal').style.display='flex';
}
let openedFromUrl=false;
async function loadAndOpenRequestedDetail(){
  await load();
  if(openedFromUrl)return;
  const q=new URLSearchParams(location.search);
  if(q.get('detail')==='1'&&q.get('host')&&q.get('runtime')&&q.get('container')){
    openedFromUrl=true;
    await openDetail(q.get('host'),q.get('runtime'),q.get('project')||'',q.get('container'));
  }
}
loadAndOpenRequestedDetail(); loadAlerts(); setInterval(()=>{load();loadAlerts();}, 15000);
</script>
</body></html>
"""


@app.api_route("/container-detail", methods=["GET", "HEAD"], response_class=HTMLResponse)
def container_detail_page(request: Request = None) -> Any:
    spa_index = STATIC_DIR / "index.html"
    if request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Container Detail</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--danger:#ef4444;--focus:#7dd3fc}
body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5}.skip-link{position:fixed;left:12px;top:-60px;z-index:10;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.page{width:min(1500px,100%);margin:auto;padding:20px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px;padding:17px 18px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,var(--surface),#111d34)}
h1{margin:0;font-size:24px;overflow-wrap:anywhere}.subtitle{color:var(--muted);margin-top:4px;overflow-wrap:anywhere}.actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
    .btn{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface-3);color:var(--text);text-decoration:none;cursor:pointer;font:inherit}.btn.primary{border-color:#0284c7;background:#075985}.btn:disabled{cursor:not-allowed;opacity:.58}
    .btn:not(:disabled):hover{filter:brightness(1.12)}.btn:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.status{border:1px solid var(--border);border-radius:10px;background:var(--surface-2);padding:10px 12px;margin-bottom:14px;color:#cbd5e1}
.status.bad{border-color:#a84655;color:#ffadb8}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
.metric,.panel{min-width:0;border:1px solid var(--border);border-radius:12px;background:var(--surface);padding:13px}.metric span{display:block;color:var(--muted);font-size:12px}.metric strong{display:block;margin-top:4px;font-size:20px;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
.metric.metric-alert{border-color:#b91c1c;background:#2b0b12}.metric.metric-alert strong{color:#fca5a5}
.charts,.details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:14px}.panel h2{font-size:16px;margin:0 0 10px}.panel h3{font-size:14px;margin:12px 0 6px;color:#9fc8ff}
.legend{display:flex;gap:14px;flex-wrap:wrap;color:#9fb5d5;font-size:12px;margin-bottom:7px}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
svg{width:100%;height:220px;border-top:1px solid #29466f}.kv{display:grid;grid-template-columns:minmax(115px,auto) minmax(0,1fr);gap:6px 10px;margin:0}.kv dt{color:#91a9cb}.kv dd{margin:0;text-align:right;overflow-wrap:anywhere}
.list{margin:6px 0 0 18px;padding:0}.ok{color:#72dfa7}.bad-text{color:#ff6b78}.samples{display:grid;gap:7px}.sample{display:grid;grid-template-columns:1.4fr repeat(5,minmax(75px,1fr));gap:8px;padding:8px;border:1px solid #274365;border-radius:8px;background:#101e36;font-size:12px}.sample span{overflow-wrap:anywhere}
.source,.version-pill{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:3px 9px;background:#111827;color:#cbd5e1;font-size:12px}.version-pill.ok{border-color:#166534;background:#052e16;color:#86efac}.version-pill.bad{border-color:#991b1b;background:#450a0a;color:#fca5a5}.version-pill.warn{border-color:#92400e;background:#451a03;color:#fcd34d}
    .comm-process-grid,.socket-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:9px}.comm-process,.socket-card{min-width:0;border:1px solid #274365;border-radius:9px;background:#0b1220;padding:10px}.comm-process strong,.socket-head strong{overflow-wrap:anywhere}.comm-meta,.socket-meta{margin-top:4px;color:var(--muted);font-size:12px;overflow-wrap:anywhere}.socket-head{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}.direction{display:inline-flex;border-radius:999px;padding:2px 7px;font-size:11px;border:1px solid var(--border)}.direction.inbound{border-color:#b91c1c;background:#450a0a;color:#fca5a5}.direction.outbound{border-color:#075985;background:#082f49;color:#7dd3fc}.comm-note{margin:0 0 10px;color:var(--muted);font-size:12px}
    .diagnostic{margin-bottom:14px;border-color:#315574;background:linear-gradient(135deg,#0f172a,#0b1d31)}.diagnostic-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.diagnostic-head p{margin:3px 0 0;color:var(--muted);font-size:12px}.diagnostic-state{margin:12px 0;padding:9px 11px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:#cbd5e1}.diagnostic-state.ok{border-color:#166534}.diagnostic-state.warn{border-color:#92400e;color:#fcd34d}.diagnostic-state.bad{border-color:#991b1b;color:#fca5a5}.deep-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-bottom:10px}.deep-metric{min-width:0;padding:9px;border:1px solid #274365;border-radius:8px;background:#101e36}.deep-metric span{display:block;color:var(--muted);font-size:11px}.deep-metric strong{display:block;margin-top:3px;overflow-wrap:anywhere}.deep-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.deep-section{min-width:0;border-top:1px solid #274365;padding-top:9px}.deep-section h3{margin:0 0 7px}.deep-list{display:grid;gap:6px}.deep-row{min-width:0;padding:8px;border:1px solid #253b59;border-radius:7px;background:#0b1220;font-size:12px;overflow-wrap:anywhere}.deep-row strong{color:#dbeafe}.deep-errors{margin-top:9px;color:#fca5a5;font-size:12px}
    @media(max-width:900px){.top{flex-direction:column}.charts,.details,.deep-grid{grid-template-columns:1fr}.sample{grid-template-columns:repeat(2,minmax(0,1fr))}.diagnostic-head{flex-direction:column}}
@media(max-width:520px){.page{padding:10px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric strong{font-size:17px}.kv{grid-template-columns:1fr}.kv dd{text-align:left}.actions{width:100%}.btn{flex:1}}
</style></head><body><a class='skip-link' href='#detail-main'>跳到主要内容</a><main id='detail-main' class='page'>
    <header class='top'><div><h1 id='title'>容器详情</h1><div id='subtitle' class='subtitle'>正在读取容器内部指标…</div></div><nav class='actions'><span id='detail-version' class='version-pill warn'>版本检查中</span><a class='btn' href='/stats'>返回统计页</a><a class='btn' href='/'>返回总览</a></nav></header>
    <div id='status' class='status'>正在加载最新采样与历史数据…</div>
    <section class='panel diagnostic' aria-labelledby='diagnostic-title'><div class='diagnostic-head'><div><h2 id='diagnostic-title'>按需深度上报</h2><p>仅在下一周期对当前 Incus/Podman 容器做一次有界快照；不抓包、不扫描文件，上报成功后自动恢复普通采集。</p></div><button id='request-diagnostic' class='btn primary' type='button' aria-label='请求当前容器在下一周期上报深度详情' onclick='requestDeepSample()'>请求深度上报</button></div><div id='diagnostic-state' class='diagnostic-state'>尚未请求深度上报。</div><div id='diagnostic-report'><div class='comm-note'>收到报告后将在这里显示瞬时流量、详细进程、连接 IP 和进程归属。</div></div></section>
<section id='metrics' class='metrics'></section>
<section class='charts'><article class='panel'><h2>容器 CPU / 内存历史</h2><div class='legend'><span><i class='dot' style='background:#4a90e2'></i>CPU%</span><span><i class='dot' style='background:#16a085'></i>内存%</span></div><svg id='resource-chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg></article><article class='panel'><h2>容器网络速率历史</h2><div class='legend'><span><i class='dot' style='background:#2ecc71'></i>RX Mbps</span><span><i class='dot' style='background:#f39c12'></i>TX Mbps</span></div><svg id='network-chart' viewBox='0 0 900 220' preserveAspectRatio='none'></svg></article></section>
<section class='details'><article class='panel'><h2>容器内部进程</h2><div id='processes'></div></article><article class='panel'><h2>容器网络命名空间</h2><dl id='network' class='kv'></dl></article><article class='panel'><h2>安全与面板检查</h2><div id='security'></div></article><article class='panel'><h2>容器文件系统</h2><dl id='filesystem' class='kv'></dl></article></section>
<section class='panel'><h2>通信进程与连接明细</h2><div id='communications'></div></section>
<section class='panel'><h2>最近采样</h2><div id='samples' class='samples'></div></section>
</main><script>
function esc(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]))}
function fmtBytes(n){const x=Number(n||0);if(x<=0)return '0 B';const u=['B','KB','MB','GB','TB'];let i=0,v=x;while(v>=1024&&i<u.length-1){v/=1024;i++}return `${v.toFixed(v>=100?0:1)} ${u[i]}`}
function mbps(v){return Number(v||0)*8/1000000}function num(v,d=2){const n=Number(v||0);return Number.isFinite(n)?n.toFixed(d):'0.00'}
function linePoints(values,max,w=900,h=220,pad=18){return values.map((v,i)=>`${i*(w/Math.max(1,values.length-1))},${(h-pad)-(Number(v||0)/Math.max(1,max))*(h-pad*2)}`).join(' ')}
function drawChart(id,series){const svg=document.getElementById(id);const values=series.flatMap(x=>x.values);const max=Math.max(1,...values);let grid='';for(let i=0;i<=4;i++){const y=18+i*46;grid+=`<line x1='0' y1='${y}' x2='900' y2='${y}' stroke='#29466f' stroke-width='1'/>`}svg.innerHTML=grid+series.map(x=>`<polyline fill='none' stroke='${x.color}' stroke-width='2.5' points='${linePoints(x.values,max)}'/>`).join('')}
    function sourceText(runtime){if(runtime==='incus')return 'Incus 容器级 cgroup/OpenMetrics 与网络命名空间';if(runtime==='podman')return 'Podman 容器 stats 与网络命名空间';return 'Docker 仅提醒模式（不执行深度采集）'}
    function listHtml(items,empty,mapper){return items.length?`<ul class='list'>${items.map(mapper).join('')}</ul>`:`<div class='ok'>${esc(empty)}</div>`}
    let diagnosticSubmitting=false;
    function detailIdentity(){const q=new URLSearchParams(location.search);return {host_id:q.get('host')||'',runtime:q.get('runtime')||'',project:q.get('project')||'',container_name:q.get('container')||''}}
    function renderDiagnostic(data,runtime){
     const action=data?.action||null,sample=data?.sample||null,state=document.getElementById('diagnostic-state'),button=document.getElementById('request-diagnostic');
     const active=action&&['queued','dispatched'].includes(action.status);button.disabled=diagnosticSubmitting||active||!['incus','podman'].includes(runtime);
     button.innerText=diagnosticSubmitting?'正在提交…':active?'等待上报中':'请求深度上报';
     if(!['incus','podman'].includes(runtime)){state.className='diagnostic-state warn';state.innerText='Docker 默认仅提醒，不执行深度采集。'}
     else if(diagnosticSubmitting){state.className='diagnostic-state warn';state.innerText='正在提交一次性采样任务，请稍候…'}
     else if(action?.status==='queued'){state.className='diagnostic-state warn';state.innerText=`任务 #${action.id} 已排队，等待节点领取（通常 10 秒内）。`}
     else if(action?.status==='dispatched'){state.className='diagnostic-state warn';state.innerText=`任务 #${action.id} 已由节点领取，正在等待下一次上报。`}
     else if(action?.status==='succeeded'){state.className='diagnostic-state ok';state.innerText=`任务 #${action.id} 已完成 · ${action.updated_at_utc8||'-'}`}
     else if(action?.status==='failed'){state.className='diagnostic-state bad';state.innerText=`任务 #${action.id} 失败：${action.result_message||'节点未返回报告，可重试。'}`}
     else{state.className='diagnostic-state';state.innerText='尚未请求深度上报。'}
     const target=document.getElementById('diagnostic-report');if(!sample){target.innerHTML=`<div class='comm-note'>收到报告后将在这里显示瞬时流量、详细进程、连接 IP 和进程归属。</div>`;return}
      const rates=sample.network_rates||{},processes=sample.processes?.items||[],sockets=sample.communication_sockets||[],errors=sample.errors||[];
      const ipMap=new Map();for(const item of [...(sample.connection_ips||[]),...(sample.inbound_ips||[]),...(sample.outbound_ips||[])]){if(!item?.ip)continue;ipMap.set(item.ip,{...(ipMap.get(item.ip)||{}),...item})}const ips=[...ipMap.values()].sort((a,b)=>Math.max(Number(b.connections||0),Number(b.inbound||0),Number(b.outbound||0))-Math.max(Number(a.connections||0),Number(a.inbound||0),Number(a.outbound||0)));
     const metrics=[['报告时间',sample.report_timestamp_utc8||'-'],['瞬时 RX',`${num(mbps(rates.rx_bps))} Mbps`],['瞬时 TX',`${num(mbps(rates.tx_bps))} Mbps`],['RX / TX pps',`${num(rates.rx_pps,1)} / ${num(rates.tx_pps,1)}`],['进程数',Number(sample.process_count||0)],['连接 IP',Number(sample.unique_connection_ips||0)],['连接明细',Number(sample.connection_count||0)],['采样窗口',`${num(rates.sample_seconds,2)} 秒`]];
     const attribution=sample.connection_attribution||{};const expectedConnections=Math.max(Number(sample.connection_count||0),Number(attribution.expected_connection_count||0));const capturedSockets=attribution.captured_sockets==null?null:Number(attribution.captured_sockets);const attributionUnavailable=attribution.evidence_status==='unavailable'||(expectedConnections>0&&(capturedSockets===null||capturedSockets===0));const attributionSummary=Object.keys(attribution).length?`<section class='deep-section'><h3>连接发起方深度核验</h3><div class='comm-note'>${attributionUnavailable?'连接总数非零，但未采集到逐连接来源/PID 数据；发起方向未知，不能按 0 条判断。':`本机发起已确认 ${Number(attribution.confirmed_local_initiated||0)} 条 / 推定 ${Number(attribution.probable_local_initiated||0)} 条；外部发起已确认 ${Number(attribution.confirmed_remote_initiated||0)} 条；方向未知 ${Number(attribution.unknown_direction||0)} 条。进程/PID 已归属 ${Number(attribution.process_attributed_sockets||0)}/${Number(attribution.captured_sockets||0)} 条；conntrack 五元组确认 ${Number(attribution.conntrack_confirmed_sockets||0)} 条。`}${attribution.conntrack_available?'':'本次没有 conntrack 数据，已确认方向可能较少。'}${attribution.conntrack_snapshot_truncated||attribution.socket_snapshot_truncated?'采样达到上限，非全量结果。':''}</div></section>`:'';
      const processRows=processes.length?processes.map(x=>`<div class='deep-row'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)}</strong><br/>用户 ${esc(x.user||'-')} · CPU ${num(x.cpu_percent)}% · RSS ${fmtBytes(x.rss_bytes)} · 状态 ${esc(x.state||'-')}<br/>${esc(x.command||'-')}</div>`).join(''):`<div class='deep-row'>未采集到进程明细。</div>`;
      const evidenceLabel=value=>({confirmed_conntrack_original_initiator:'conntrack 原始方向：本机进程发起',confirmed_conntrack_reply_acceptor:'conntrack 回复方向：远端发起',confirmed_syn_sent:'TCP SYN-SENT：本机发起',confirmed_syn_recv:'TCP SYN-RECV：远端发起',probable_local_listener_match:'匹配本地监听端口：推定远端入站',probable_established_non_listener:'已建立且本地非监听：推定本机发起',probable_connected_udp_listener_match:'匹配 UDP 监听端口：推定远端到达',probable_connected_udp_non_listener:'UDP 非监听 socket：推定本机发起'})[value]||value||'方向证据不足';
      const signalLabel=value=>({possible_multiport_probe:'疑似多端口探测（仅行为线索）',mixed_connection_evidence:'已建立与未应答连接并存',bidirectional_tcp_observed:'观察到 TCP 双向数据',unreplied_tcp_observed:'存在未应答 TCP 尝试',insufficient_transport_evidence:'传输层证据不足'})[value]||value||'';
      const confidenceLabel=value=>({confirmed:'方向已确认',probable:'方向推定',mixed:'证据冲突',unknown:'方向未知'})[value]||'方向未知';
      const ipRows=ips.length?ips.map(x=>{const network=x.network_evidence||{},proofs=[...(x.inbound_direction_evidence||[]),...(x.outbound_direction_evidence||[])],owners=(x.inbound_processes||[]).map(p=>`${p.process||'unknown'}${Number(p.pid||0)?` (PID ${Number(p.pid)})`:''}`);const signal=network.classification?`${signalLabel(network.classification)} · 已建立 ${Number(network.tcp_established_flows||0)} / 未应答 ${Number(network.tcp_unreplied_flows||0)} / 握手待完成 ${Number(network.tcp_handshake_pending_flows||0)} · 目标端口 ${(network.public_ports||[]).slice(0,12).join(', ')||'-'} · 回包 ${Number(network.reply_packets||0)}`:'';const evidenceSources=(network.evidence_sources||[]).join('、');return `<div class='deep-row'><strong>${esc(x.ip||'-')}</strong> · 连接 ${Number(x.connections||0)} · 入站 ${Number(x.inbound||0)} · 出站 ${Number(x.outbound||0)}<br/>入站发起方：${Number(x.inbound||0)?confidenceLabel(x.inbound_origin_confidence):'无入站 socket 记录'} · 接收进程：${esc(owners.join('、')||(x.processes||[]).join('、')||'未归属')}<br/>方向证据：${esc([...new Set(proofs)].map(evidenceLabel).join('；')||'未取得逐连接证据')}${signal?`<br/>扫描/握手线索：${esc(signal)} · 来源 ${esc(evidenceSources||'conntrack')}`:''}</div>`}).join(''):`<div class='deep-row'>采样瞬间没有可见的公网连接 IP。</div>`;
      const socketRows=sockets.length?sockets.slice(0,250).map(x=>{const origin=x.origin==='local_process'?'本机进程发起':x.origin==='remote_peer'?'远端发起':'发起方未知';const confidence=confidenceLabel(x.origin_confidence);const role=x.process_role==='initiator'?'本机进程角色：发起连接':x.process_role==='acceptor'?'本机进程角色：接受连接':'本机进程角色未知';return `<div class='deep-row'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong> · ${esc(String(x.proto||'').toUpperCase())} · ${esc(x.state||'-')} · ${origin}（${confidence}）<br/>本地 ${esc(x.local||'-')} → 远端 ${esc(x.remote||'-')}<br/>${role} · 判定证据：${esc(evidenceLabel(x.direction_evidence))} · 进程归属：${Number(x.pid||0)>0?'已获得 PID':'不可用'}</div>`}).join(''):`<div class='deep-row'>采样瞬间没有活动连接明细。</div>`;
      const portEvidence=sample.inbound_port_evidence||[];const portRows=portEvidence.length?portEvidence.slice(0,50).map(x=>`<div class='deep-row'><strong>容器端口 ${Number(x.container_port||0)}</strong> · ${Number(x.connections||0)} 条聚合连接 · ${Number(x.source_ip_count||0)} 个来源 IP<br/>来源：${esc((x.source_ips||[]).join('、')||'-')}<br/>监听进程：${esc((x.process_listeners||[]).map(p=>`${p.process||'unknown'} (PID ${Number(p.pid||0)})`).join('、')||'未归属')} · 证据范围：同端口聚合，非逐连接匹配</div>`).join(''):`<div class='deep-row'>没有可用的 NAT/代理端口级来源关联。</div>`;
      target.innerHTML=`<div class='deep-metrics'>${metrics.map(x=>`<div class='deep-metric'><span>${esc(x[0])}</span><strong>${esc(x[1])}</strong></div>`).join('')}</div>${attributionSummary}<div class='comm-note'>本机 PID 说明容器内哪个进程持有 socket；conntrack 原始/回复五元组用于确认发起方向。发起方不等于善恶判断；“疑似探测”不会自动处罚客户。</div><div class='deep-grid'><section class='deep-section'><h3>进程快照（${processes.length}）</h3><div class='deep-list'>${processRows}</div></section><section class='deep-section'><h3>连接 IP 与网络行为（${ips.length}）</h3><div class='deep-list'>${ipRows}</div></section></div><section class='deep-section'><h3>逐连接方向与进程归属（${sockets.length}）</h3><div class='deep-list'>${socketRows}</div></section><section class='deep-section'><h3>端口级公网来源关联（${portEvidence.length}）</h3><p class='comm-note'>NAT/代理会隐藏原始来源时，按宿主机连接与容器目标端口聚合；这不是单条 socket 的精确对应。</p><div class='deep-list'>${portRows}</div></section>${errors.length?`<div class='deep-errors'>部分数据不可用：${esc(errors.join('；'))}</div>`:''}<p class='comm-note'>报告为单次有界元数据快照，进程最多 100 条、连接最多 250 条；命令行中的常见凭据字段已脱敏。</p>`;
    }
    async function requestDeepSample(){
     if(diagnosticSubmitting)return;const identity=detailIdentity(),button=document.getElementById('request-diagnostic'),state=document.getElementById('diagnostic-state');diagnosticSubmitting=true;button.disabled=true;button.innerText='正在提交…';state.className='diagnostic-state warn';state.innerText='正在提交一次性采样任务，请稍候…';
     try{const response=await fetch('/api/v1/containers/diagnostics',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(identity)});const data=await response.json();if(!response.ok)throw new Error(data.detail||`HTTP ${response.status}`);diagnosticSubmitting=false;renderDiagnostic({action:data.action,sample:null},identity.runtime);await loadDetail()}
     catch(error){diagnosticSubmitting=false;button.disabled=false;button.innerText='重试深度上报';state.className='diagnostic-state bad';state.innerText=`提交失败：${error.message||error}`}
    }
    async function loadDetail(){
 const q=new URLSearchParams(location.search),host=q.get('host')||'',runtime=q.get('runtime')||'',project=q.get('project')||'',container=q.get('container')||'';
 if(!host||!runtime||!container){document.getElementById('status').className='status bad';document.getElementById('status').innerText='详情参数不完整，请从总览或统计页重新进入。';return}
 document.getElementById('title').innerText=container;document.getElementById('subtitle').innerText=`${host} · ${project?`${runtime}/${project}`:runtime}`;
     const params=new URLSearchParams({host_id:host,runtime,project,container_name:container,minutes:'1440'}),diagnosticParams=new URLSearchParams({host_id:host,runtime,project,container_name:container});
     try{
      const [latestData,historyData,diagnosticData]=await Promise.all([fetch('/api/v1/latest?include_stale=true').then(r=>r.json()),fetch(`/api/v1/history?${params}`).then(r=>r.json()),fetch(`/api/v1/containers/diagnostics?${diagnosticParams}`).then(r=>r.json())]);
  const current=(latestData.items||[]).find(x=>x.host_id===host&&x.runtime===runtime&&(x.project||'')===project&&x.container_name===container);const allPts=historyData.items||[];const currentVersion=String(current?.agent_version||'unknown');const pts=currentVersion==='unknown'?allPts:allPts.filter(x=>String(x.agent_version||'unknown')===currentVersion);const excludedSamples=allPts.length-pts.length;
  const status=document.getElementById('status'),version=document.getElementById('detail-version');
  const clientVersion=String(current?.agent_version||'unknown'),serverVersion=String(latestData.server_version||'dev');
  if(clientVersion!=='unknown'&&clientVersion!=='dev'&&clientVersion===serverVersion){version.className='version-pill ok';version.innerText=`Client / Server v${serverVersion}`}
  else if(clientVersion==='unknown'||clientVersion==='dev'){version.className='version-pill warn';version.innerText=`Client 版本未知 · Server ${serverVersion==='dev'?'dev':`v${serverVersion}`}`}
      else{version.className='version-pill bad';version.innerText=`Client v${clientVersion} · Server v${serverVersion}`}
      renderDiagnostic(diagnosticData,runtime);
  if(current){status.innerHTML=`<span class='source'>${esc(sourceText(runtime))}</span>　最新采样 ${esc(current.timestamp_iso_utc8||'-')}${excludedSamples?`　已忽略 ${excludedSamples} 条旧版本口径样本`:''}${current.alerts?.stale?'　<span class="bad-text">当前离线或上报已过期</span>':''}`}
  else{status.className='status bad';status.innerText='未找到该容器的当前采样，仅显示保留的历史数据。'}
  const sec=current?.security||{},limit=Number(current?.mem_limit_bytes||0),used=Number(current?.mem_bytes||0),rootTotal=Number(current?.container_fs_root_total_bytes||0),rootAvail=Number(current?.container_fs_root_avail_bytes||0);
  const inboundUniqueIps=Number(sec.inbound_unique_ips||0),inboundThreshold=Number(sec.inbound_unique_ip_threshold||10),inboundAlert=inboundUniqueIps>inboundThreshold;
  const cards=[['CPU',`${num(current?.cpu_percent)}%`],['内存',`${num(current?.mem_percent)}%`],['内存 已用/总量',`${fmtBytes(used)} / ${fmtBytes(limit)}`],['RX',`${num(mbps(current?.net_rx_bps))} Mbps`],['TX',`${num(mbps(current?.net_tx_bps))} Mbps`],['入站去重 IP',`${inboundUniqueIps} / 阈值 ${inboundThreshold}`,inboundAlert?'metric-alert':''],['连接数',Number(current?.conn_count||0)],['进程数',Number(sec.process_count||0)],['有效 CPU',Number(current?.cpu_effective_cpus||0)||'未限制']];
  document.getElementById('metrics').innerHTML=cards.map(x=>`<article class='metric ${x[2]||''}'><span>${esc(x[0])}</span><strong>${esc(x[1])}</strong></article>`).join('');
  const recent=pts.slice(-80);drawChart('resource-chart',[{values:recent.map(x=>Number(x.cpu_percent||0)),color:'#4a90e2'},{values:recent.map(x=>Number(x.mem_percent||0)),color:'#16a085'}]);drawChart('network-chart',[{values:recent.map(x=>mbps(x.net_rx_bps)),color:'#2ecc71'},{values:recent.map(x=>mbps(x.net_tx_bps)),color:'#f39c12'}]);
  const suspicious=Array.isArray(sec.suspicious_processes)?sec.suspicious_processes:[];const top=current?.top_cpu_process_command?`PID ${Number(current.top_cpu_process_pid||0)} · CPU ${num(current.top_cpu_process_cpu_percent)}% · ${esc(current.top_cpu_process_command)}`:'未采集到高 CPU 进程';document.getElementById('processes').innerHTML=`<div>${top}</div>`+listHtml(suspicious,'未发现可疑进程',x=>`<li>PID ${Number(x.pid||0)} · ${esc(x.command||x.pattern||'')}</li>`);
  const countries=(arr)=>(Array.isArray(arr)&&arr.length?arr.slice(0,5).map(x=>`${x.country||'UN'} (${Number(x.connections||0)})`).join('、'):'-');const exposure=Array.isArray(sec.network_exposure)?sec.network_exposure:[];const inboundMode=sec.inbound_ip_observation==='host_conntrack'?'宿主机 NAT/conntrack 还原':'容器 socket 观察';const inboundTop=Array.isArray(sec.inbound_top_ips)?sec.inbound_top_ips:[];document.getElementById('network').innerHTML=`<dt>监听端口</dt><dd>${esc((sec.listening_ports||[]).join(', ')||'-')}</dd><dt>NAT/代理</dt><dd>${esc(exposure.map(x=>`${x.listen||'?'} → ${x.target||'?'}`).join(', ')||'-')}</dd><dt>入站去重 IP</dt><dd class='${inboundAlert?'bad-text':''}'>${inboundUniqueIps} / 阈值 ${inboundThreshold}</dd><dt>入站来源口径</dt><dd>${esc(inboundMode)}</dd><dt>主要入站来源</dt><dd>${esc(inboundTop.slice(0,10).map(x=>`${x.ip||'?'} (${Number(x.connections||0)})`).join('、')||'-')}</dd><dt>入站连接</dt><dd>${Number(sec.incoming_established||0)}</dd><dt>出站去重 IP</dt><dd>${Number(sec.outbound_unique_ips||0)}</dd><dt>TCP 来源</dt><dd>${esc(countries(current?.tcp_country_stats))}</dd><dt>UDP 来源</dt><dd>${esc(countries(current?.udp_country_stats))}</dd><dt>RX pps</dt><dd>${num(sec.net_rx_pps,1)}</dd><dt>SYN_RECV</dt><dd>${Number(sec.syn_recv_count||0)}</dd>`;
  const risks=Array.isArray(sec.configuration_risks)?sec.configuration_risks:[],pair=sec.panel_pairing||{},socks=sec.socks_proxy||{};const socksAuth={no_auth:'无认证',weak_password:'弱密码',configured:'已配置认证',unknown:'认证未知'}[socks.auth_mode||'unknown'];document.getElementById('security').innerHTML=`<div>面板对接：<strong class='${pair.detected&&!pair.approved?'bad-text':'ok'}'>${pair.detected?(pair.approved?'已放行':'检测到特征'):'未发现'}</strong></div><div>SOCKS 代理：<strong class='${socks.detected&&['no_auth','weak_password'].includes(socks.auth_mode)?'bad-text':'ok'}'>${socks.detected?`已识别 · ${esc(socksAuth)}${socks.public_exposure?' · 公网/NAT 暴露':''}`:'未发现'}</strong></div>`+listHtml(risks,'未发现配置风险',x=>`<li>${esc(x.message||x.code||'配置风险')}</li>`);
  document.getElementById('filesystem').innerHTML=`<dt>根盘 已用/总量</dt><dd>${fmtBytes(Math.max(0,rootTotal-rootAvail))} / ${fmtBytes(rootTotal)}</dd><dt>根盘可用</dt><dd>${fmtBytes(rootAvail)}</dd><dt>镜像可写层</dt><dd>${fmtBytes(current?.container_disk_rw_bytes)}</dd>`;
   const communicationProcesses=Array.isArray(sec.communication_processes)?sec.communication_processes:[],communicationSockets=Array.isArray(sec.communication_sockets)?sec.communication_sockets:[];
   const processCards=communicationProcesses.length?`<div class='comm-process-grid'>${communicationProcesses.map(x=>`<article class='comm-process'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong><div class='comm-meta'>入站 ${Number(x.inbound_connections||0)} · 出站 ${Number(x.outbound_connections||0)} · 远端 IP ${Number(x.unique_remote_ips||0)}</div></article>`).join('')}</div>`:`<div class='ok'>${sec.communication_detail_available?'当前没有可归属的活动通信':'容器内缺少 ss，暂时无法归属到具体进程'}</div>`;
   const originName=x=>x.origin==='local_process'?'本机进程发起':x.origin==='remote_peer'?'远端发起':'发起方未知',originConfidence=x=>({confirmed:'已确认',probable:'推定',mixed:'证据冲突',unknown:'未知'})[x.origin_confidence]||'未知';
   const socketCards=communicationSockets.length?`<h3>活动连接（最多展示 ${communicationSockets.length} 条）</h3><div class='socket-grid'>${communicationSockets.slice(0,100).map(x=>`<article class='socket-card'><div class='socket-head'><strong>${esc(x.process||'unknown')} · PID ${Number(x.pid||0)||'-'}</strong><span class='direction ${x.direction==='inbound'?'inbound':'outbound'}'>${x.direction==='inbound'?'入站':x.direction==='outbound'?'出站':'未知'} · ${originConfidence(x)}</span></div><div class='socket-meta'>${esc(String(x.proto||'').toUpperCase())} · ${esc(x.state||'-')} · ${originName(x)}<br/>本地 ${esc(x.local||'-')}<br/>远端 ${esc(x.remote||'-')}<br/>证据：${esc(x.direction_evidence||'无')} · PID ${Number(x.pid||0)>0?'已归属':'不可用'}</div></article>`).join('')}</div>`:'';
   const sourceSignals=Array.isArray(sec.inbound_source_signals)?sec.inbound_source_signals:[],sourceLabel=x=>({possible_multiport_probe:'疑似多端口探测（线索）',mixed_connection_evidence:'已建立与未应答并存',bidirectional_tcp_observed:'观察到 TCP 双向数据',unreplied_tcp_observed:'未应答 TCP 尝试',insufficient_transport_evidence:'传输层证据不足'})[x]||x||'未知';
   const sourceSignalCards=sourceSignals.length?`<h3>入站来源行为线索</h3><div class='deep-list'>${sourceSignals.slice(0,20).map(x=>`<div class='deep-row'><strong>${esc(x.ip||'-')}</strong> · ${esc(sourceLabel(x.classification))}<br/>TCP 已建立 ${Number(x.tcp_established_flows||0)} · 未应答 ${Number(x.tcp_unreplied_flows||0)} · SYN_RECV ${Number(x.tcp_handshake_pending_flows||0)} · 回包 ${Number(x.reply_packets||0)}<br/>目标端口 ${(x.public_ports||[]).slice(0,16).map(v=>Number(v)).join(', ')||'-'} · 证据 ${esc((x.evidence_sources||[]).join('、')||'未知')} · ${esc(x.scope||'单次快照')}</div>`).join('')}</div>`:'';
   const inboundPortEvidence=Array.isArray(sec.inbound_port_evidence)?sec.inbound_port_evidence:[];
   const inboundPortCards=inboundPortEvidence.length?`<h3>端口级公网来源关联</h3><p class='comm-note'>NAT/代理恢复出的来源按容器目标端口聚合，不等于逐条 socket 精确关联。</p><div class='deep-list'>${inboundPortEvidence.slice(0,20).map(x=>`<div class='deep-row'><strong>容器端口 ${Number(x.container_port||0)}</strong> · ${Number(x.connections||0)} 条 · ${Number(x.source_ip_count||0)} 个来源<br/>${esc((x.source_ips||[]).join('、')||'-')}<br/>监听进程：${esc((x.process_listeners||[]).map(p=>`${p.process||'unknown'} PID ${Number(p.pid||0)}`).join('、')||'未归属')} · 端口聚合</div>`).join('')}</div>`:'';
   document.getElementById('communications').innerHTML=`<p class='comm-note'>宿主机 conntrack 读取 ${Number(sec.host_conntrack_snapshot_count||0)} 条${sec.host_conntrack_snapshot_truncated?'（已达到安全上限）':''}；容器 socket 读取 ${Number(sec.communication_snapshot_count||0)} 条${sec.communication_snapshot_truncated?'（已达到安全上限）':''}。均为单次有界元数据快照，不持续抓包。进程归属和连接发起方是两项不同证据；发起方向也不代表用户意图。</p>${processCards}${socketCards}${sourceSignalCards}${inboundPortCards}`;
  document.getElementById('samples').innerHTML=pts.length?pts.slice(-20).reverse().map(x=>`<div class='sample'><span>${esc(x.timestamp_iso_utc8||'-')}</span><span>CPU ${num(x.cpu_percent)}%</span><span>内存 ${num(x.mem_percent)}%</span><span>RX ${num(mbps(x.net_rx_bps))}M</span><span>TX ${num(mbps(x.net_tx_bps))}M</span><span>连接 ${Number(x.conn_count||0)}</span></div>`).join(''):`<div class='ok'>暂无历史采样</div>`;
 }catch(error){const status=document.getElementById('status');status.className='status bad';status.innerText=`详情加载失败：${error.message||error}`}
}
loadDetail();setInterval(loadDetail,15000);
</script></body></html>
"""


@app.api_route("/stats", methods=["GET", "HEAD"], response_class=HTMLResponse)
def stats_page(request: Request = None) -> Any:
    spa_index = STATIC_DIR / "index.html"
    if request is not None and spa_index.is_file():
        return FileResponse(spa_index)
    return """
<!doctype html>
<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Container Stats</title>
<style>
*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}
:root{color-scheme:dark;--bg:#020617;--surface:#0f172a;--surface-2:#172033;--surface-3:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--accent:#38bdf8;--focus:#7dd3fc}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:var(--bg);color:var(--text);line-height:1.5}.page{width:min(1600px,100%);margin:auto;padding:20px}.skip-link{position:fixed;left:12px;top:-60px;z-index:10;background:var(--accent);color:#082f49;padding:10px 14px;border-radius:8px;font-weight:700}.skip-link:focus{top:12px}
.page-header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:18px 20px;margin-bottom:16px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,var(--surface),#111d34)}.page-header h1{margin:0;font-size:22px}.page-header p{margin:4px 0 0;color:var(--muted);font-size:13px}
.topbar{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap}.topbar label{color:var(--muted);font-size:13px}.topbar input{width:110px;min-height:44px;padding:7px 9px;border:1px solid var(--border);border-radius:8px;background:#0b1220;color:var(--text)}.btn-link,.topbar button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:8px 13px;border:1px solid var(--border);border-radius:8px;background:var(--surface-3);color:var(--text);text-decoration:none;cursor:pointer}.btn-link:hover,.topbar button:hover{filter:brightness(1.12)}.btn-link:focus-visible,.topbar button:focus-visible,.topbar input:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.card-grid{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));gap:10px;margin-bottom:12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;color:var(--muted);font-size:12px}
.value{font-size:22px;font-weight:700;margin-top:6px}
.value{color:var(--text);font-variant-numeric:tabular-nums}.section{margin:14px 0;border:1px solid var(--border);border-radius:12px;background:var(--surface);overflow:hidden}.section h2{margin:0;padding:13px 15px;border-bottom:1px solid var(--border);background:var(--surface-2);font-size:16px}
table{border-collapse:collapse;width:100%;max-width:100%;table-layout:fixed;background:var(--surface);color:var(--text)}
th,td{border:1px solid var(--border);padding:8px;text-align:center;overflow-wrap:anywhere;word-break:break-word;font-size:12px}th{background:var(--surface-3);color:#cbd5e1}
a{color:#7dd3fc}.detail-link{display:inline-flex;align-items:center;justify-content:center;min-height:40px;border:1px solid var(--border);border-radius:7px;padding:5px 9px;text-decoration:none;background:var(--surface-3);color:var(--text)}.version-pill{display:inline-flex;align-items:center;border:1px solid #166534;border-radius:999px;padding:4px 9px;background:#052e16;color:#86efac;font-size:12px}.version-pill.warn{border-color:#92400e;background:#451a03;color:#fcd34d}
@media(max-width:800px){.page{padding:8px}.page-header{flex-direction:column;padding:14px}.topbar{justify-content:flex-start}.card-grid{grid-template-columns:repeat(2,minmax(0,1fr))}th,td{padding:5px;font-size:11px}#all-containers th:nth-child(6),#all-containers td:nth-child(6),#all-containers th:nth-child(7),#all-containers td:nth-child(7),#all-containers th:nth-child(9),#all-containers td:nth-child(9){display:none}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
</style>
</head><body><a class='skip-link' href='#stats-main'>跳到主要内容</a><main id='stats-main' class='page'>
<header class='page-header'><div><h1>数据统计</h1><p>资源、连接与累计流量分析；点击排查进入独立容器详情。</p></div><div class='topbar'>
  <span id='stats-server-version' class='version-pill warn'>Server 版本检查中</span>
  <label>统计窗口(分钟)：<input id='minutes' type='number' value='720' min='5' max='10080' /></label>
  <button onclick='loadStats()'>刷新</button>
  <a class='btn-link' href='/'>返回总览</a>
</div></header>
<div class='card-grid'>
  <div class='card'><div>容器数</div><div class='value' id='kpi-containers'>0</div></div>
  <div class='card'><div>样本数</div><div class='value' id='kpi-samples'>0</div></div>
  <div class='card'><div>建议采样间隔</div><div class='value' id='kpi-interval'>--</div></div>
  <div class='card'><div>窗口</div><div class='value' id='kpi-window'>--</div></div>
</div>

<section class='section'><h2>Top10：平均 CPU</h2>
  <table id='cpu-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均 CPU%</th><th>峰值 CPU%</th><th>估算间隔(秒)</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>Top10：平均连接数</h2>
  <table id='conn-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>平均连接</th><th>峰值连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>Top10：累计流量</h2>
  <table id='traffic-top'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>全部容器</h2>
<table id='all-containers'><thead><tr><th>主机</th><th>运行时</th><th>容器</th><th>当前 CPU%</th><th>当前内存%</th><th>当前 RX</th><th>当前 TX</th><th>当前连接</th><th>样本数</th><th>排查</th></tr></thead><tbody></tbody></table>
</section>

<section class='section'><h2>主机汇总</h2>
<table id='host-summary'><thead><tr><th>主机</th><th>累计 RX</th><th>累计 TX</th><th>累计总流量</th><th>样本数</th></tr></thead><tbody></tbody></table>
</section>

<script>
function fmtBytes(n){
  const x = Number(n||0); if (x<=0) return '0 B';
  const units=['B','KB','MB','GB','TB']; let i=0; let v=x;
  while(v>=1024 && i<units.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=100?0:1)} ${units[i]}`;
}
function escapeHtml(value){
  return String(value??'').replace(/[&<>'"]/g, ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}
function detailHref(x){
  const q=new URLSearchParams({host:x.host_id,runtime:x.runtime,project:x.project||'',container:x.container_name});
  return `/container-detail?${q.toString()}`;
}
function detailCell(x){
  return `<a class='detail-link' href='${escapeHtml(detailHref(x))}'>容器详情</a>`;
}
function renderRows(id, rows, mapper){
  const tb=document.querySelector(`#${id} tbody`);
  tb.innerHTML='';
  for(const row of rows){
    const tr=document.createElement('tr');
    tr.innerHTML=mapper(row);
    tb.appendChild(tr);
  }
}
async function loadStats(){
  const minutes=Math.max(5, Math.min(10080, Number(document.getElementById('minutes').value||720)));
  const res=await fetch(`/api/v1/stats?minutes=${minutes}`);
  const data=await res.json();
  const version=document.getElementById('stats-server-version'),serverVersion=String(data.server_version||'dev');
  version.className=`version-pill ${serverVersion==='dev'?'warn':''}`;
  version.innerText=serverVersion==='dev'?'Server dev':`Server v${serverVersion}`;
  document.getElementById('kpi-containers').innerText=data.container_count||0;
  document.getElementById('kpi-samples').innerText=data.samples||0;
  document.getElementById('kpi-interval').innerText=(data.recommendation?.suggested_interval_seconds||'--') + 's';
  document.getElementById('kpi-window').innerText=(data.window_minutes||minutes)+'m';

  renderRows('cpu-top', data.ranks?.avg_cpu_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.max.cpu_percent||0).toFixed(2)}</td>
    <td>${Number(x.estimated_interval_seconds||0).toFixed(2)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('conn-top', data.ranks?.avg_conn_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${Number(x.avg.conn_count||0).toFixed(2)}</td>
    <td>${Number(x.max.conn_count||0)}</td>
    <td>${x.samples||0}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('traffic-top', data.ranks?.traffic_top10||[], x=>`
    <td>${x.host_id}</td><td>${x.project?`${x.runtime}/${x.project}`:x.runtime}</td><td>${x.container_name}</td>
    <td>${fmtBytes(x.traffic_bytes.rx)}</td>
    <td>${fmtBytes(x.traffic_bytes.tx)}</td>
    <td>${fmtBytes(x.traffic_bytes.total)}</td>
    <td>${detailCell(x)}</td>
  `);
  renderRows('all-containers', data.containers||[], x=>`
    <td>${escapeHtml(x.host_id)}</td><td>${escapeHtml(x.project?`${x.runtime}/${x.project}`:x.runtime)}</td><td>${escapeHtml(x.container_name)}</td>
    <td>${Number(x.latest?.cpu_percent||0).toFixed(2)}</td><td>${Number(x.latest?.mem_percent||0).toFixed(2)}<br/><small>${fmtBytes(x.latest?.mem_bytes)} / ${fmtBytes(x.latest?.mem_limit_bytes)}</small></td>
    <td>${fmtBytes(x.latest?.net_rx_bps)}/s</td><td>${fmtBytes(x.latest?.net_tx_bps)}/s</td>
    <td>${Number(x.latest?.conn_count||0)}</td><td>${Number(x.samples||0)}</td><td>${detailCell(x)}</td>
  `);
  renderRows('host-summary', data.hosts||[], x=>`
    <td>${x.host_id}</td>
    <td>${fmtBytes(x.traffic_rx_bytes)}</td>
    <td>${fmtBytes(x.traffic_tx_bytes)}</td>
    <td>${fmtBytes(x.traffic_total_bytes)}</td>
    <td>${x.samples}</td>
  `);
}
loadStats();
</script>
</main></body></html>
"""
