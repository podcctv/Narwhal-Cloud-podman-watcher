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
import posixpath
import re
import shutil
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
CLIENT_BINS_DIR = Path(__file__).resolve().parent / "client_bins"

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
RESOURCE_AUTO_RESTART_ENABLED = os.getenv('RESOURCE_AUTO_RESTART_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on')
RESOURCE_RESTART_CPU_THRESHOLD_PERCENT = max(1.0, min(100.0, float(os.getenv('RESOURCE_RESTART_CPU_THRESHOLD_PERCENT', '90'))))
RESOURCE_RESTART_MEMORY_THRESHOLD_PERCENT = max(1.0, min(100.0, float(os.getenv('RESOURCE_RESTART_MEMORY_THRESHOLD_PERCENT', '90'))))
RESOURCE_RESTART_DURATION_SECONDS = max(3600, min(86400, int(os.getenv('RESOURCE_RESTART_DURATION_SECONDS', '3600'))))
RESOURCE_RESTART_MAX_GAP_SECONDS = max(60, min(1800, int(os.getenv('RESOURCE_RESTART_MAX_GAP_SECONDS', '900'))))
RESOURCE_RESTART_COOLDOWN_SECONDS = max(3600, min(86400, int(os.getenv('RESOURCE_RESTART_COOLDOWN_SECONDS', '3600'))))
RESOURCE_RESTART_MIN_SAMPLES = max(5, min(100, int(os.getenv('RESOURCE_RESTART_MIN_SAMPLES', '5'))))
STALE_SECONDS = int(os.getenv("STALE_SECONDS", "900"))
RFW_APPLICATION_PROTOCOLS = ("http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto")
RFW_CN_ALERT_PROTOCOLS = {"socks", "fet", "wireguard", "mtproto", "openvpn"}
INCUS_RUNTIME_ALERT_TYPES = ("incus_instance_error", "incus_lifecycle_operation_stuck", "incus_lifecycle_operation_unverified", "incus_api_unavailable", "incus_operation_inventory_unavailable", "incus_api_slow")
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
    from server import operations, operations_api, security_routes, buyer_notifications, investigation, dashboard_auth, commerce, tcping, gfw_monitor, disk_cleanup, connection_policy, resource_overload_policy, ip_reputation, inbound_assessment, database_telemetry, control_reconciliation, db_maintenance
except ImportError:
    import operations
    import connection_policy
    import resource_overload_policy
    import operations_api
    import security_routes
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
    import control_reconciliation
    import db_maintenance

try:
    from server import abuse_api, admission_api, legacy_pages, reach_monitor
except ImportError:
    import abuse_api
    import admission_api
    import legacy_pages
    import reach_monitor

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
    "/api/v1/update/probe/sha256",
    "/api/v1/update/probe/amd64",
    "/api/v1/update/probe/arm64",
    "/api/v1/update/agent/amd64",
    "/api/v1/update/agent/arm64",
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
    conn = sqlite3.connect(DB_PATH, timeout=DB_BUSY_TIMEOUT_MS / 1000.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-16384")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db() -> None:
    global _latest_cache, _latest_cache_time
    # Tests and administrative recovery may point DB_PATH at a fresh database.
    # Never serve a short-lived snapshot from the previous database in that case.
    _latest_cache = None
    _latest_cache_time = 0.0
    invalidate_security_status_cache()
    conn = db()
    # WAL lets dashboard reads coexist with frequent agent writes.  This is
    # especially important once monitor.db contains large JSON payloads.
    # Existing NONE-mode databases require an explicit offline VACUUM migration;
    # never rebuild a multi-GB database while starting the API.
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=2000")
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
        CREATE TABLE IF NOT EXISTS host_collection_health_hourly (
            host_id TEXT NOT NULL,
            bucket_start INTEGER NOT NULL,
            total_samples INTEGER NOT NULL DEFAULT 0,
            healthy_samples INTEGER NOT NULL DEFAULT 0,
            last_sample_at INTEGER NOT NULL DEFAULT 0,
            last_status TEXT NOT NULL DEFAULT 'unknown',
            last_missing_count INTEGER NOT NULL DEFAULT 0,
            agent_version TEXT NOT NULL DEFAULT 'unknown',
            PRIMARY KEY(host_id, bucket_start)
        );
        CREATE INDEX IF NOT EXISTS idx_collection_health_bucket ON host_collection_health_hourly(bucket_start, host_id);
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
    if "inbound_unique_ips" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN inbound_unique_ips INTEGER")
    if "outbound_unique_ips" not in col_names:
        conn.execute("ALTER TABLE reports ADD COLUMN outbound_unique_ips INTEGER")
    hs_cols = {str(c["name"]) for c in conn.execute("PRAGMA table_info(host_security)").fetchall()}
    if "total_rx_bps" not in hs_cols:
        conn.execute("ALTER TABLE host_security ADD COLUMN total_rx_bps REAL")
    if "total_tx_bps" not in hs_cols:
        conn.execute("ALTER TABLE host_security ADD COLUMN total_tx_bps REAL")
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
        "CREATE INDEX IF NOT EXISTS idx_security_alerts_active_host_type "
        "ON security_alerts(host_id, alert_type) WHERE status='active'"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_ts_host_peaks "
        "ON reports(ts, host_id, conn_count, net_rx_bps, net_tx_bps, inbound_unique_ips, outbound_unique_ips)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_security_ts_peaks "
        "ON host_security(ts, host_id, total_rx_bps, total_tx_bps)"
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO hosts(host_id, last_seen, agent_version)
        SELECT host_id, MAX(ts), 'unknown' FROM reports GROUP BY host_id
        """
    )
    operations.initialize(conn)
    connection_policy.initialize(conn)
    resource_overload_policy.initialize(conn)
    buyer_notifications.initialize(conn)
    investigation.initialize(conn)
    commerce.initialize(conn)
    tcping.initialize(conn)
    gfw_monitor.initialize(conn)
    abuse_api.initialize(conn)
    admission_api.initialize(conn)
    ip_reputation.initialize(conn)
    database_telemetry.initialize(conn)
    reach_monitor.init_db(conn)
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
    asyncio.create_task(reach_monitor.run_loop(db))
    if not PUBLIC_BASE_URL:
        asyncio.create_task(_telegram_polling_loop())


async def _buyer_background_loop():
    # Startup never replays historical reports or sends migration test messages.
    await asyncio.sleep(5)
    while True:
        try:
            def _should_force_sync():
                conn = db()
                try:
                    return buyer_notifications.buyer_mapping.needs_urgent_sync(conn)
                finally:
                    conn.close()

            force_sync = await asyncio.to_thread(_should_force_sync)
            await asyncio.to_thread(buyer_notifications.sync_mappings, db, force_sync)
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
        now = int(time.time())
        table_sample = database_telemetry.sample_table_sizes(conn, now)
        growth = database_telemetry.sample_and_summarize(conn, DB_PATH, now)
        growth["table_growth"] = database_telemetry.table_growth(conn, now)
        growth["table_sample"] = table_sample
        return {
            "database_bytes": pages * page_size,
            "reusable_bytes": free * page_size,
            "live_bytes": (pages - free) * page_size,
            "wal_bytes": os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0,
            "auto_vacuum": int(conn.execute("PRAGMA auto_vacuum").fetchone()[0]),
            "growth": growth,
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
        drill_due = settings.get("enabled") and operations.restore_drill_enabled(settings) and now-settings.get("last_drill_attempt", 0) >= 7*86400
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
    try:
        if scheduled and time.monotonic() < _next_cleanup_monotonic:
            return 0
        removed_reports, backlog = db_maintenance.run_cleanup(
            db_fn=db,
            db_path=DB_PATH,
            investigation_maintain_fn=investigation.maintain,
            cleanup_status=_cleanup_status,
            purge_seconds=PURGE_SECONDS,
            raw_retention_seconds=RAW_RETENTION_SECONDS,
            offline_host_purge_seconds=OFFLINE_HOST_PURGE_SECONDS,
            report_cleanup_batch_size=REPORT_CLEANUP_BATCH_SIZE,
            report_max_rows=REPORT_MAX_ROWS,
            host_security_max_rows=HOST_SECURITY_MAX_ROWS,
            cleanup_time_budget_seconds=CLEANUP_TIME_BUDGET_SECONDS,
            now_ts=now_ts,
        )
        _next_cleanup_monotonic = time.monotonic() + (5 if backlog else REPORT_CLEANUP_INTERVAL_SECONDS)
        return removed_reports
    finally:
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
    resolve_types: Optional[List[str]] = None,
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
            elif previous_status == "remediated" and alert_type == "socket_abuse_suspected":
                recent_freeze = conn.execute(
                    "SELECT status, updated_at FROM security_actions WHERE alert_id=? AND action_type='freeze_container' ORDER BY id DESC LIMIT 1",
                    (existing["id"],),
                ).fetchone()
                if recent_freeze and str(recent_freeze["status"]) in ("queued", "dispatched", "running", "succeeded") and (ts - int(recent_freeze["updated_at"] or 0)) <= 86400:
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
                if alert_type in {"cpu_pressure_protection", "io_pressure_protection", "memory_pressure_protection"}:
                    previous_details = _alert_details(existing["details_json"])
                    guard_key = {"cpu_pressure_protection": "cpu_guard", "io_pressure_protection": "io_guard",
                                 "memory_pressure_protection": "memory_guard"}[alert_type]
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
    pending_network_review = "NOT EXISTS (SELECT 1 FROM network_quarantines q WHERE q.alert_id=security_alerts.id AND q.status NOT IN ('released','replaced'))"
    resolve_type_values = sorted({
        str(item).strip()[:80] for item in (resolve_types or []) if str(item).strip()
    })
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


def queue_connection_alert_deep_samples(
    conn: sqlite3.Connection, host_id: str, now: int
) -> int:
    """Refresh bounded connection evidence for connection and inbound-fanout alerts."""
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
            break  # Avoid a large incident fan-out starving the report transaction.
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
        stage = str(alert['alert_type']) + ':' + str(alert['severity']) + (
            ':escalated'
            if _alert_details(alert['details_json']).get('connection_policy', {}).get('escalated')
            else ''
        )
        params = {
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
            stable_id = str(latest_payload.get("stable_id") or latest_payload.get("id") or "").lower() if isinstance(latest_payload, dict) else ""
            generation = str(latest_payload.get("instance_id") or "").lower() if isinstance(latest_payload, dict) else ""
            if (
                str(alert["project"] or "") != "default"
                or stable_id != str(alert["container_name"] or "").lower()
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stable_id)
                or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", generation)
                or latest is None
                or int(latest["ts"] or 0) > now + 30
                or now - int(latest["ts"] or 0) > STALE_SECONDS
            ):
                continue
            params["instance_id"] = generation
        if existing is not None:
            previous_params = _alert_details(existing['params_json'])
            if runtime == "runman" and previous_params.get("instance_id") != params.get("instance_id"):
                if existing['status'] in ('queued', 'dispatched', 'running'):
                    conn.execute(
                        "UPDATE security_actions SET status='failed',result_message='Runman 实例代次已变化，旧深度采样已取消',updated_at=? WHERE id=?",
                        (now, existing['id']),
                    )
                existing = None
            if existing is not None and existing['status'] in ('queued', 'dispatched', 'running'):
                if now - int(existing['created_at']) > 900:
                    conn.execute("UPDATE security_actions SET status='failed',result_message='深度取证等待超过15分钟，需要重新采样',updated_at=? WHERE id=?", (now, existing['id']))
                continue
            if existing is not None and now - int(existing['created_at']) < 900 and (previous_params.get('stage') == stage or existing['status'] == 'failed'):
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
                json.dumps(params),
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
    if alert["runtime"] not in ("podman", "incus", "runman"):
        return False
    if alert["alert_type"] not in ("unauthorized_panel_pairing", "socks_weak_auth", "malicious_process"):
        return False
    details = _alert_action_evidence(alert)
    if alert["runtime"] == "runman":
        if (
            alert["alert_type"] not in ("unauthorized_panel_pairing", "malicious_process")
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", details.get("instance_id", ""))
            or not (details.get("process_targets") or details.get("file_targets"))
        ):
            return False
    if alert["alert_type"] == "unauthorized_panel_pairing":
        return bool(details.get("process_patterns") or details.get("config_files"))
    if alert["alert_type"] == "socks_weak_auth":
        return details.get("socks_auth_mode") in ("no_auth", "weak_password") and bool(details.get("socks_processes"))
    has_xmrig = any(isinstance(item, dict) and item.get("process") == "xmrig" for item in details.get("malicious_processes", []))
    if alert["runtime"] == "runman":
        has_xmrig = has_xmrig and any(
            item.get("process") == "xmrig" and item.get("pattern") == "xmrig"
            and re.fullmatch(r"[0-9]{1,24}", item.get("start_ticks", ""))
            for item in details.get("process_targets", [])
        )
    return has_xmrig


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
    incus_runtime_health: Optional[Dict[str, Any]] = None,
) -> int:
    """Count only fresh, comparable samples; Incus stop decisions require a full health scan."""
    return connection_policy.observe(conn, host_id, ts, containers,
        ALERT_CONN_CRITICAL_THRESHOLD, CONNECTION_STOP_THRESHOLD,
        CONNECTION_STOP_DURATION_SECONDS, CONNECTION_STOP_MAX_GAP_SECONDS,
        auto_stop=CONNECTION_AUTO_STOP_ENABLED, before_stop=buyer_notifications.connection_stop_gate,
        runtime_health=incus_runtime_health)


_latest_cache: Dict[str, Any] | None = None
_latest_cache_time = 0.0
_security_status_cache: Dict[str, Any] | None = None
_security_status_cache_time = 0.0
_security_status_cache_lock = threading.Lock()
_security_status_compute_lock = threading.Lock()


def invalidate_security_status_cache() -> None:
    global _security_status_cache, _security_status_cache_time
    with _security_status_cache_lock:
        _security_status_cache = None
        _security_status_cache_time = 0.0


def _purge_host(conn: sqlite3.Connection, host_id: str) -> None:
    if conn.execute("SELECT 1 FROM network_quarantines WHERE host_id=? AND status NOT IN ('released','replaced') LIMIT 1", (host_id,)).fetchone():
        raise HTTPException(409, '存在待复核的网络隔离；请先核实并解除隔离，避免丢失恢复入口。')
    invalidate_security_status_cache()
    operations.purge_host(conn,host_id)
    conn.execute('DELETE FROM connection_windows WHERE host_id=?', (host_id,))
    investigation.purge_host(conn,host_id)
    conn.execute("DELETE FROM security_alert_decisions WHERE alert_id IN (SELECT id FROM security_alerts WHERE host_id=?)", (host_id,))
    conn.execute("DELETE FROM security_alert_evidence WHERE alert_id IN (SELECT id FROM security_alerts WHERE host_id=?)", (host_id,))
    conn.execute("DELETE FROM security_alert_policies WHERE fingerprint IN (SELECT fingerprint FROM security_alerts WHERE host_id=?)", (host_id,))
    for table in ("reports", "security_alerts", "host_security", "security_actions", "connection_overloads", "resource_overload_windows", "buyer_user_notices", "host_firewall_policies", "host_firewall_policy_history", "host_firewall_readbacks"):
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
        if not value or any(item not in {"auto", "incus", "podman", "docker", "runman"} for item in value.split(",")):
            raise HTTPException(status_code=400, detail="运行时仅支持 auto/incus/podman/docker/runman")
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
    allowed_services = {"ookla", "cloudflare", "fast", "tcpquality", "iperf3_server", "librespeed", "openspeedtest", "ookla_server"}
    if not isinstance(raw_abuse, dict) or set(raw_abuse) - (categories | {"services", "service_runtimes", "interfaces", "runtimes"}):
        raise HTTPException(status_code=400, detail="防火墙策略包含不支持的字段")
    abuse = {}
    for category in sorted(categories):
        value = raw_abuse.get(category, False)
        if type(value) is not bool:
            raise HTTPException(status_code=400, detail=f"防滥用策略 {category} 必须是布尔值")
        # The old `speedtest` flag only blocked destination port 5201. Keep
        # accepting it while reading old clients, but never reapply that
        # port-only rule; new matching is service/domain/process based.
        abuse[category] = False if category == "speedtest" else value
    raw_services = raw_abuse.get("services", [])
    if not isinstance(raw_services, list) or len(raw_services) > len(allowed_services):
        raise HTTPException(status_code=400, detail="测速服务列表无效")
    services = []
    for service in raw_services:
        name = str(service).strip().lower()
        if name not in allowed_services:
            raise HTTPException(status_code=400, detail="测速服务选择包含不支持的类型")
        if name not in services:
            services.append(name)
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
    if not isinstance(raw_runtimes, list) or len(raw_runtimes) > 3:
        raise HTTPException(status_code=400, detail="容器网桥运行时必须从 Incus / Podman / Runman 中选择，最多三项")
    runtimes = []
    for runtime in raw_runtimes:
        name = str(runtime).strip().lower()
        if name not in {"incus", "podman", "runman"}:
            raise HTTPException(status_code=400, detail="容器网桥运行时只支持 Incus、Podman 或 Runman")
        if name not in runtimes:
            runtimes.append(name)
    raw_service_runtimes = raw_abuse.get("service_runtimes", [])
    if not isinstance(raw_service_runtimes, list) or len(raw_service_runtimes) > 3:
        raise HTTPException(status_code=400, detail="测速服务运行时必须从 Incus / Podman / Runman 中选择，最多三项")
    service_runtimes = []
    for runtime in raw_service_runtimes:
        name = str(runtime).strip().lower()
        if name not in {"incus", "podman", "runman"}:
            raise HTTPException(status_code=400, detail="测速服务范围只支持 Incus、Podman 或 Runman")
        if name not in service_runtimes:
            service_runtimes.append(name)
    if interfaces and runtimes:
        # Fixed-port RFW templates need bridge names; service guards need
        # logical runtime scope. They may coexist in one policy.
        if not services or not any(abuse.get(key) for key in ("mining", "bt")):
            raise HTTPException(status_code=400, detail="测速服务范围和固定端口规则的目标不能混用")
    fixed_rules = any(abuse.get(key) is True for key in ("mining", "bt"))
    if fixed_rules and not interfaces and not runtimes:
        raise HTTPException(status_code=400, detail="启用固定端口规则前必须选择已采集的容器网卡或运行时")
    if services and not service_runtimes:
        raise HTTPException(status_code=400, detail="启用测速服务识别前必须选择 Incus、Podman 或 Runman")
    abuse["interfaces"] = interfaces
    abuse["runtimes"] = runtimes
    abuse["services"] = sorted(services)
    abuse["service_runtimes"] = service_runtimes
    return {"rules": rules, "abuse": abuse}


def _empty_host_firewall_policy() -> Dict[str, Any]:
    # Default speed-test protections target isolated Incus and Podman
    # containers. The report reconciler automatically applies this policy only
    # when the host has no saved policy and no authoritative fleet template.
    # Host processes and Docker are never in this scope.
    return {
        "rules": [],
        "abuse": {
            "speedtest": False,
            "mining": False,
            "bt": False,
            "services": [
                "cloudflare", "fast", "iperf3_server", "librespeed",
                "ookla", "ookla_server", "openspeedtest", "tcpquality",
            ],
            "service_runtimes": ["incus", "podman", "runman"],
            "interfaces": [],
            "runtimes": [],
        },
    }


SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY = "speedtest-auto-default"
SPEEDTEST_POLICY_MIN_AGENT_VERSION = (1, 7, 136)
SPEEDTEST_AUTO_RETRY_INTERVAL = 15 * 60
SPEEDTEST_AUTO_RETRY_WINDOW = 24 * 60 * 60
SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW = 3


def _agent_version_tuple(value: Any) -> Tuple[int, int, int] | None:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:$|[-+])", str(value or "").strip())
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.groups())
    except (TypeError, ValueError, OverflowError):
        return None


def _agent_supports_speedtest_policy(agent_version: Any) -> bool:
    version = _agent_version_tuple(agent_version)
    return version is not None and version >= SPEEDTEST_POLICY_MIN_AGENT_VERSION


def _maybe_queue_default_speedtest_policy(
    conn: sqlite3.Connection,
    host_id: str,
    node_id: str,
    agent_version: str,
    ts: int,
) -> bool:
    """Automatically apply the container-only service guard without replacing saved policy."""
    if not node_id or not _agent_supports_speedtest_policy(agent_version):
        return False
    fleet = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
    if fleet is not None and int(fleet["revision"] or 0) > 0:
        # An administrator-owned fleet policy is authoritative; its own report
        # reconciler will apply exactly those selections.
        return False

    existing = conn.execute(
        "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision "
        "FROM host_firewall_policies WHERE host_id=?", (host_id,),
    ).fetchone()
    if existing is not None and str(existing["updated_by"] or "") != SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY:
        # Any saved single-host policy is an intentional choice, including an
        # explicit empty/disabled speed-test selection.
        return False

    desired = _validate_host_firewall_policy(_empty_host_firewall_policy())
    materialized, _target_status = _materialize_host_firewall_policy(conn, host_id, desired, ts)
    if materialized is None:
        return False

    if existing is not None:
        try:
            saved = _validate_host_firewall_policy(json.loads(existing["policy_json"] or "{}"))
        except (HTTPException, TypeError, ValueError):
            return False
        if (
            saved.get("abuse", {}).get("services") != desired.get("abuse", {}).get("services")
            or saved.get("abuse", {}).get("service_runtimes") != desired.get("abuse", {}).get("service_runtimes")
            or saved.get("rules")
        ):
            return False
        latest = _latest_host_firewall_action(conn, host_id)
        if latest is not None:
            if (
                str(latest["action_type"] or "") != "apply_host_firewall_policy"
                or str(latest["requested_by"] or "") != SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY
            ):
                return False
            if latest["status"] in {"queued", "dispatched", "running", "succeeded", "cancelled"}:
                return False
            if latest["status"] == "failed":
                if ts - int(latest["updated_at"] or 0) < SPEEDTEST_AUTO_RETRY_INTERVAL:
                    return False
                failures = int(conn.execute(
                    "SELECT COUNT(*) FROM security_actions WHERE host_id=? "
                    "AND action_type='apply_host_firewall_policy' AND requested_by=? "
                    "AND status='failed' AND created_at>=?",
                    (host_id, SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY, ts - SPEEDTEST_AUTO_RETRY_WINDOW),
                ).fetchone()[0] or 0)
                if failures >= SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW:
                    return False

    _enqueue_host_firewall_policy(
        conn, host_id, node_id, materialized,
        SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY, ts, 0,
    )
    return True


def _policy_has_rfw_effect(policy: Dict[str, Any] | None) -> bool:
    if not isinstance(policy, dict):
        return False
    rules = policy.get("rules")
    abuse = policy.get("abuse") if isinstance(policy.get("abuse"), dict) else {}
    return bool(
        isinstance(rules, list) and rules
        or any(abuse.get(key) is True for key in ("speedtest", "mining", "bt"))
    )


def _stored_policy_has_rfw_effect(raw: str) -> bool:
    try:
        policy = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return False
    # Inspect the persisted shape before validation so legacy port-5201
    # policies can still be sent to Runman once to remove their owned rule.
    return _policy_has_rfw_effect(policy)


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
            "drift_count": 0, "missing_count": 0, "policy_revision": None, "rfw_api_version": "",
            "capabilities_known": False, "supported_protocols": [], "supported_protocol_count": 0,
            "active_blocked_protocols": [], "active_blocked_protocol_count": 0,
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
    raw_rules = snapshot.get("rules") if isinstance(snapshot, dict) and isinstance(snapshot.get("rules"), list) else []
    active_blocked_protocols = sorted({
        str(rule.get("protocol"))
        for rule in raw_rules
        if isinstance(rule, dict)
        and rule.get("enabled", True) is True
        and str(rule.get("action") or "block") == "block"
        and str(rule.get("protocol") or "").strip()
    }) if fresh else []
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
        "policy_revision": int(snapshot.get("policy_revision") or 0) if snapshot else None,
        "rfw_api_version": str(snapshot.get("rfw_api_version") or "") if capabilities_known else "",
        "capabilities_known": capabilities_known,
        "supported_protocols": supported_protocols,
        "supported_protocol_count": len(supported_protocols),
        "active_blocked_protocols": active_blocked_protocols,
        "active_blocked_protocol_count": len(active_blocked_protocols),
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
        runtimes = sorted({str(value).lower() for value in raw_runtimes if str(value).lower() in {"incus", "podman", "runman"}})
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
    if not isinstance(abuse, dict) or not any(abuse.get(key) is True for key in ("mining", "bt")):
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
    if any(abuse.get(key) is True for key in ("mining", "bt")):
        abuse["interfaces"] = targets
    # Runtime selectors are only a fleet/single-host input. Resolve them to
    # discovered bridges before validating the host-local policy, otherwise
    # derived interfaces conflict with the selector.
    abuse.pop("runtimes", None)
    materialized["abuse"] = abuse
    validated = _validate_host_firewall_policy(materialized)
    # Normalization adds an empty runtime selector to every policy. Keep the
    # node-local payload free of fleet-only fields after validation as well.
    validated["abuse"].pop("runtimes", None)
    return validated, status


def _latest_host_firewall_action(conn: sqlite3.Connection, host_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id,status,result_message,created_at,updated_at,attempts,params_json,action_type,requested_by FROM security_actions "
        "WHERE host_id=? AND action_type IN ('apply_host_firewall_policy','delete_host_firewall_rule') ORDER BY id DESC LIMIT 1",
        (host_id,),
    ).fetchone()


def _host_firewall_action_summary(conn: sqlite3.Connection, host_id: str) -> Dict[str, Any]:
    row = _latest_host_firewall_action(conn, host_id)
    if row is None:
        return {}
    try:
        params = json.loads(row["params_json"] or "{}")
    except (TypeError, ValueError):
        params = {}
    params = params if isinstance(params, dict) else {}
    rollback = params.get("rollback") if isinstance(params.get("rollback"), dict) else {}
    action_policy = params.get("policy") if isinstance(params.get("policy"), dict) else {}
    policy_revision = action_policy.get("revision")
    rollback_revision = rollback.get("target_revision") if rollback.get("requested") is True else None
    return {
        "id": int(row["id"]),
        "status": str(row["status"] or "unknown"),
        "action_type": str(row["action_type"] or ""),
        "attempts": int(row["attempts"] or 0),
        "created_at": int(row["created_at"] or 0),
        "updated_at": int(row["updated_at"] or 0),
        "result_message": str(row["result_message"] or "")[:240],
        "policy_revision": policy_revision if type(policy_revision) is int and policy_revision >= 0 else None,
        "rollback": {
            "requested": rollback.get("requested") is True,
            "target_revision": rollback_revision if type(rollback_revision) is int and rollback_revision >= 0 else None,
        },
    }


def _enqueue_host_firewall_policy(
    conn: sqlite3.Connection,
    host_id: str,
    node_id: str,
    policy: Dict[str, Any],
    requested_by: str,
    now: int,
    fleet_revision: int,
    rollback_target_revision: int | None = None,
) -> int:
    existing = conn.execute(
        "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    revision = (int(existing["revision"]) if existing else 0) + 1
    policy_with_revision = {"revision": revision, **policy}
    policy_json = json.dumps(policy, ensure_ascii=False, separators=(",", ":"))
    requires_rfw = _policy_has_rfw_effect(policy)
    if existing and _stored_policy_has_rfw_effect(str(existing["policy_json"] or "{}")):
        requires_rfw = True
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
    action_params = {"expected_node_id": node_id, "policy": policy_with_revision, "requires_rfw": requires_rfw}
    if fleet_revision > 0:
        action_params["fleet_revision"] = int(fleet_revision)
    if rollback_target_revision is not None:
        action_params["rollback"] = {"requested": True, "target_revision": int(rollback_target_revision)}
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
    if not node_id:
        return False
    fleet = conn.execute("SELECT revision,policy_json FROM fleet_firewall_policy WHERE id=1").fetchone()
    if fleet is None or int(fleet["revision"] or 0) < 1:
        return False
    try:
        policy = _validate_host_firewall_policy(json.loads(fleet["policy_json"] or "{}"))
    except (HTTPException, TypeError, ValueError):
        return False
    local_policy = conn.execute(
        "SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    requires_rfw = _policy_has_rfw_effect(policy) or (
        local_policy is not None and _stored_policy_has_rfw_effect(str(local_policy["policy_json"] or "{}"))
    )
    if requires_rfw and (not isinstance(runtime, dict) or runtime.get("control_api") != "ready"):
        return False
    fleet_revision = int(fleet["revision"])
    state = conn.execute(
        "SELECT revision,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    already_on_fleet_revision = (
        state is not None and int(state["source_fleet_revision"] or 0) >= fleet_revision
    )
    live_readback = _host_firewall_live_readback(conn, host_id, ts) if requires_rfw else {"status": "unavailable", "stale": True}
    drift_repair_needed = (
        already_on_fleet_revision
        and live_readback.get("status") == "ready"
        and live_readback.get("stale") is False
        and live_readback.get("sync_status") == "drifted"
    )
    latest = _latest_host_firewall_action(conn, host_id)
    same_fleet_revision = False
    retry_failed_unverified = False
    if latest is not None:
        try:
            latest_params = json.loads(latest["params_json"] or "{}")
        except (TypeError, ValueError):
            latest_params = {}
        same_fleet_revision = int(latest_params.get("fleet_revision") or 0) == fleet_revision
        if same_fleet_revision and latest["status"] in {"queued", "dispatched", "running"}:
            return False
        if same_fleet_revision and latest["status"] == "failed":
            if ts - int(latest["updated_at"] or 0) < 900:
                return False
            failed_for_revision = int(conn.execute(
                """SELECT COUNT(*) FROM security_actions
                   WHERE host_id=? AND action_type='apply_host_firewall_policy' AND status='failed'
                     AND json_valid(params_json)
                     AND CAST(json_extract(params_json,'$.fleet_revision') AS INTEGER)=?""",
                (host_id, fleet_revision),
            ).fetchone()[0] or 0)
            snapshot = live_readback.get("snapshot") if isinstance(live_readback.get("snapshot"), dict) else {}
            readback_matches_policy = (
                live_readback.get("status") == "ready"
                and live_readback.get("stale") is False
                and live_readback.get("sync_status") == "in_sync"
                and live_readback.get("drift_count") == 0
                and live_readback.get("missing_count") == 0
                and state is not None
                and snapshot.get("policy_revision") == int(state["revision"] or 0)
            )
            retry_failed_unverified = failed_for_revision < 3 and not readback_matches_policy
    if already_on_fleet_revision and not drift_repair_needed and not retry_failed_unverified:
        return False
    # A fresh drift readback must have been observed after the previous
    # successful apply before scheduling another repair. This prevents the
    # same pre-apply snapshot from causing an action loop.
    if (
        latest is not None
        and same_fleet_revision
        and latest["status"] == "succeeded"
        and drift_repair_needed
        and int(live_readback.get("observed_at") or 0) <= int(latest["updated_at"] or 0)
    ):
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
        for runtime_name in ("incus", "podman", "runman")
    }
    policy_row = conn.execute(
        "SELECT revision,source_fleet_revision,policy_json,updated_by FROM host_firewall_policies WHERE host_id=?", (host_id,)
    ).fetchone()
    local_revision = int(policy_row["revision"] or 0) if policy_row is not None else 0
    applied_fleet_revision = int(policy_row["source_fleet_revision"] or 0) if policy_row is not None else 0
    stored_policy_raw = str(policy_row["policy_json"] or "{}") if policy_row is not None else "{}"
    try:
        local_policy = _validate_host_firewall_policy(json.loads(stored_policy_raw)) if policy_row is not None else _empty_host_firewall_policy()
    except (HTTPException, TypeError, ValueError):
        local_policy = _empty_host_firewall_policy()
    # A configured fleet template is authoritative. Otherwise the node-local
    # policy is authoritative; when none exists, the default container-only
    # service protection is the desired policy and is reported separately.
    effective_policy = (
        required_policy if fleet_revision > 0 and isinstance(required_policy, dict)
        else local_policy
    )
    _targets, target_status = _host_firewall_policy_targets(conn, host_id, effective_policy, now)
    protocol_status = _policy_protocol_compatibility(effective_policy, live_readback)
    policy_abuse = effective_policy.get("abuse") if isinstance(effective_policy.get("abuse"), dict) else {}
    container_policy_enabled = any(policy_abuse.get(key) is True for key in ("mining", "bt"))
    rfw_required = _policy_has_rfw_effect(effective_policy) or (
        policy_row is not None and _stored_policy_has_rfw_effect(stored_policy_raw)
    )
    action = _latest_host_firewall_action(conn, host_id)
    try:
        action_params = json.loads(action["params_json"] or "{}") if action is not None else {}
    except (TypeError, ValueError):
        action_params = {}
    action_params = action_params if isinstance(action_params, dict) else {}
    action_policy = action_params.get("policy") if isinstance(action_params.get("policy"), dict) else {}
    action_requires_rfw = (
        action_params.get("requires_rfw") is True
        or str(action["action_type"] or "") == "delete_host_firewall_rule"
        # Older queued actions predate the explicit requires_rfw flag. Their
        # own policy payload still proves whether they target RFW.
        or (
            str(action["action_type"] or "") == "apply_host_firewall_policy"
            and _policy_has_rfw_effect(action_policy)
        )
    ) if action is not None else False
    rfw_action = action if action_requires_rfw else None
    auto_speedtest_default = bool(
        policy_row is not None
        and str(policy_row["updated_by"] or "") == SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY
    )
    rfw_status = _host_firewall_component_status(
        registered=bool(node_id), online=online, configured=rfw_required,
        runtime=runtime, live_readback=live_readback, protocol_status=protocol_status,
        target_status=target_status, container_policy_enabled=container_policy_enabled,
        action=rfw_action, local_revision=local_revision,
        expected_fleet_revision=fleet_revision, applied_fleet_revision=applied_fleet_revision,
    )
    container_protection_status = _host_container_protection_status(
        conn, host_id=host_id, now=now, online=online,
        agent_version=str(host["agent_version"] or "unknown"),
        policy=effective_policy, policy_row_exists=policy_row is not None,
        policy_revision=local_revision, auto_default=(fleet_revision == 0 and policy_row is None) or auto_speedtest_default,
        latest_action=action, fleet_revision=fleet_revision,
        applied_fleet_revision=applied_fleet_revision,
    )
    status = "unregistered"
    if node_id:
        status = "offline" if not online else "awaiting_capability"
        if online and not rfw_required:
            if action is not None and action["status"] in {"queued", "dispatched", "running"}:
                status = "queued"
            elif action is not None and action["status"] == "failed":
                status = "apply_failed"
            elif auto_speedtest_default and action is not None and action["status"] == "succeeded":
                status = "last_apply_succeeded"
            elif fleet_revision > 0 and applied_fleet_revision == fleet_revision and action is not None and action["status"] == "succeeded":
                status = "last_apply_succeeded"
            elif fleet_revision > 0:
                status = "not_synced"
            elif policy_row is None and not _agent_supports_speedtest_policy(host["agent_version"]):
                status = "speedtest_agent_update_required"
            elif policy_row is None:
                status = "speedtest_auto_pending"
            else:
                status = "ready"
        elif online and not runtime["stale"] and runtime["control_api"] == "unsupported":
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
        "speedtest_auto_default": auto_speedtest_default,
        "speedtest_policy_supported": _agent_supports_speedtest_policy(host["agent_version"]),
        "state": status,
        "rfw_status": rfw_status,
        "rfw_configured": rfw_required,
        "container_protection_status": container_protection_status,
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


def _host_firewall_component_status(
    *, registered: bool, online: bool, configured: bool, runtime: Dict[str, Any],
    live_readback: Dict[str, Any], protocol_status: Dict[str, List[str]],
    target_status: str, container_policy_enabled: bool, action: sqlite3.Row | None,
    local_revision: int, expected_fleet_revision: int, applied_fleet_revision: int,
) -> str:
    """Classify RFW from current RFW evidence only, never from Agent file persistence."""
    if not registered:
        return "unregistered"
    if not online:
        return "offline"
    if not configured:
        return "not_configured"
    if runtime.get("stale"):
        return "status_stale"
    if runtime.get("control_api") == "unsupported":
        return "runman_update_required"
    if runtime.get("control_api") == "unavailable":
        return "runman_unavailable"
    if runtime.get("control_api") != "ready":
        return "awaiting_capability"
    if live_readback.get("status") == "ready" and not live_readback.get("stale"):
        if protocol_status.get("unsupported_protocols"):
            return "rfw_protocol_update_required"
        if protocol_status.get("unknown_protocols"):
            return "awaiting_rfw_capability"
    if live_readback.get("status") != "ready" or live_readback.get("stale"):
        return "readback_unavailable"
    if live_readback.get("sync_status") == "drifted":
        return "drifted"
    observed_revision = live_readback.get("policy_revision")
    if (
        live_readback.get("sync_status") == "in_sync"
        and int(live_readback.get("drift_count") or 0) == 0
        and int(live_readback.get("missing_count") or 0) == 0
        and type(observed_revision) is int
        and observed_revision == local_revision
        and (expected_fleet_revision == 0 or applied_fleet_revision == expected_fleet_revision)
    ):
        return "verified"
    if container_policy_enabled and target_status == "inventory_unavailable":
        return "awaiting_interfaces"
    if container_policy_enabled and target_status in {"runtime_not_found", "interface_not_found"}:
        return "interfaces_not_found"
    if action is not None and action["status"] in {"queued", "dispatched", "running"}:
        return "queued"
    if action is not None and action["status"] == "failed":
        return "apply_failed"
    return "not_synced"


def _host_container_protection_status(
    conn: sqlite3.Connection, *, host_id: str, now: int, online: bool,
    agent_version: str, policy: Dict[str, Any], policy_row_exists: bool,
    policy_revision: int, auto_default: bool, latest_action: sqlite3.Row | None,
    fleet_revision: int, applied_fleet_revision: int,
) -> Dict[str, Any]:
    """Aggregate per-container Agent readbacks for Incus/Podman protection."""
    abuse = policy.get("abuse") if isinstance(policy, dict) and isinstance(policy.get("abuse"), dict) else {}
    services = sorted({str(item).strip().lower() for item in abuse.get("services", []) if isinstance(item, str) and item.strip()})
    runtimes = sorted({str(item).strip().lower() for item in abuse.get("service_runtimes", []) if item in {"incus", "podman", "runman"}})
    configured = bool(services and runtimes)
    result: Dict[str, Any] = {
        "configured": configured, "state": "not_configured", "services": services,
        "runtimes": runtimes, "policy_revision": policy_revision,
        "observed_at": 0, "age_seconds": None, "containers_seen": 0,
        "containers_fresh": 0, "containers_verified": 0,
        "containers_waiting_revision": 0, "containers_unverified": 0,
        "containers_stale": 0, "reason": "",
    }
    if not configured:
        return result
    if not online:
        result.update(state="node_offline", reason="node_offline")
        return result
    if not _agent_supports_speedtest_policy(agent_version):
        result.update(state="agent_update_required", reason="agent_update_required")
        return result
    if not policy_row_exists or policy_revision < 1:
        state = "waiting_policy" if auto_default or fleet_revision > 0 else "policy_not_applied"
        result.update(state=state, reason="policy_not_applied")
        return result

    action = latest_action
    if action is not None:
        try:
            params = json.loads(action["params_json"] or "{}")
        except (TypeError, ValueError):
            params = {}
        action_policy = params.get("policy") if isinstance(params, dict) and isinstance(params.get("policy"), dict) else {}
        action_revision = action_policy.get("revision")
        action_is_current = type(action_revision) is int and action_revision == policy_revision
        if action_is_current and action["status"] in {"queued", "dispatched", "running"}:
            result.update(state="applying", reason="policy_action_pending")
            return result
        if action_is_current and action["status"] == "failed":
            result.update(state="apply_failed", reason="policy_action_failed")
            return result
    if fleet_revision > 0 and applied_fleet_revision != fleet_revision:
        result.update(state="waiting_policy", reason="fleet_policy_not_applied")
        return result

    placeholders = ",".join("?" for _ in runtimes)
    rows = conn.execute(
        "SELECT runtime,project,container_name,ts,payload_json FROM ("
        "SELECT runtime,project,container_name,ts,payload_json,"
        "ROW_NUMBER() OVER (PARTITION BY runtime,project,container_name ORDER BY ts DESC,id DESC) AS row_number "
        f"FROM reports WHERE host_id=? AND runtime IN ({placeholders}) AND ts>=?"
        ") WHERE row_number=1 ORDER BY runtime,project,container_name",
        (host_id, *runtimes, now - 24 * 60 * 60),
    ).fetchall()
    result["containers_seen"] = len(rows)
    if not rows:
        result.update(state="waiting_samples", reason="no_container_reports")
        return result

    latest_at = max(int(row["ts"] or 0) for row in rows)
    result["observed_at"] = latest_at
    result["age_seconds"] = max(0, now - latest_at) if latest_at else None
    verified = waiting_revision = unverified = stale = fresh = 0
    for row in rows:
        sampled_at = int(row["ts"] or 0)
        if sampled_at <= 0 or sampled_at > now + 30 or now - sampled_at > STALE_SECONDS:
            stale += 1
            continue
        fresh += 1
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            payload = {}
        security = payload.get("security") if isinstance(payload, dict) and isinstance(payload.get("security"), dict) else {}
        guard = security.get("speedtest_guard") if isinstance(security.get("speedtest_guard"), dict) else None
        if guard is None:
            unverified += 1
            continue
        reported_revision = guard.get("policy_revision")
        if type(reported_revision) is not int or reported_revision != policy_revision:
            waiting_revision += 1
            continue
        reported_services = sorted({str(item).strip().lower() for item in guard.get("services", []) if isinstance(item, str) and item.strip()})
        expected_services = services if row["runtime"] in runtimes else []
        guard_state = str(guard.get("state") or "")
        if reported_services == expected_services and guard_state in {"blocked", "not_detected"}:
            verified += 1
        else:
            unverified += 1

    result.update({
        "containers_fresh": fresh, "containers_verified": verified,
        "containers_waiting_revision": waiting_revision,
        "containers_unverified": unverified, "containers_stale": stale,
    })
    if fresh == 0:
        result.update(state="samples_stale", reason="container_samples_stale")
    elif verified == fresh and waiting_revision == 0 and unverified == 0 and stale == 0:
        result.update(state="active", reason="all_fresh_samples_verified")
    elif verified:
        result.update(state="partial", reason="some_container_samples_unverified")
    elif waiting_revision:
        result.update(state="waiting_revision", reason="agent_has_not_reported_desired_revision")
    else:
        result.update(state="unverified", reason="guard_readback_missing_or_failed")
    return result


def _reconcile_host(conn: sqlite3.Connection, host_id: str, node_id: str, ts: int, agent_version: str, config: Dict[str, Any], client_ip: str = "") -> str:
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
    if client_ip:
        reach_monitor.record_client_ip(conn, host_id, client_ip, ts)
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


def _process_report_sync(data: Dict[str, Any], client_ip: str) -> Dict[str, Any]:
    host_id = str(data.get("host_id") or "unknown")[:200]
    node_id = str(data.get("node_id") or "")[:128]
    client_config = data.get("client_config") if isinstance(data.get("client_config"), dict) else {}
    agent_version = str(data.get("agent_version") or "unknown").strip() or "unknown"
    ts = int(data.get("timestamp", time.time()))
    network_status = data.get("container_network") or data.get("podman_network") or {}
    podman_v4 = 1 if network_status.get("ipv4_ok") else 0
    podman_v6 = 1 if network_status.get("ipv6_ok") else 0

    containers: List[Dict[str, Any]] = data.get("containers", [])
    report_security = data.get("security") if isinstance(data.get("security"), dict) else {}
    incus_runtime_health = report_security.get("incus_runtime") if isinstance(report_security.get("incus_runtime"), dict) else None
    conn = db()
    notifications: List[Dict[str, Any]] = []
    firewall_event_cursor = ""
    automatic_stops_queued = 0
    automatic_deep_samples_queued = 0
    try:
        host_id = _reconcile_host(conn, host_id, node_id, ts, agent_version, client_config, client_ip)
        _maybe_queue_default_speedtest_policy(conn, host_id, node_id, agent_version, int(time.time()))
        automatic_stops_queued = process_connection_overloads(conn, host_id, ts, containers, incus_runtime_health)
        resource_overload_policy.observe(
            conn, host_id, node_id, ts, containers,
            now=int(time.time()),
            enabled=RESOURCE_AUTO_RESTART_ENABLED,
            cpu_threshold=RESOURCE_RESTART_CPU_THRESHOLD_PERCENT,
            memory_threshold=RESOURCE_RESTART_MEMORY_THRESHOLD_PERCENT,
            required_duration=RESOURCE_RESTART_DURATION_SECONDS,
            max_gap=RESOURCE_RESTART_MAX_GAP_SECONDS,
            cooldown=RESOURCE_RESTART_COOLDOWN_SECONDS,
            min_samples=RESOURCE_RESTART_MIN_SAMPLES,
            stale_seconds=STALE_SECONDS,
        )
        for c in containers:
            stored_payload = dict(c)
            stored_payload["_agent_version"] = agent_version
            c_sec = c.get("security") if isinstance(c.get("security"), dict) else {}
            try:
                inbound_ips = int(c_sec.get("inbound_unique_ips") or 0)
            except (TypeError, ValueError):
                inbound_ips = 0
            try:
                outbound_ips = int(c_sec.get("outbound_unique_ips") or 0)
            except (TypeError, ValueError):
                outbound_ips = 0
            conn.execute(
                """
                INSERT INTO reports(
                    host_id, container_name, runtime, project, cpu_percent, mem_bytes, mem_percent, net_rx_bps, net_tx_bps,
                    conn_count, disk_file, disk_size_bytes, disk_used_percent,
                    podman_network_ok_v4, podman_network_ok_v6, ts, payload_json,
                    inbound_unique_ips, outbound_unique_ips
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                    (c.get("disk") or {}).get("file") if isinstance(c.get("disk"), dict) else None,
                    (c.get("disk") or {}).get("size_bytes") if isinstance(c.get("disk"), dict) else None,
                    (c.get("disk") or {}).get("used_percent") if isinstance(c.get("disk"), dict) else None,
                    podman_v4,
                    podman_v6,
                    ts,
                    json.dumps(stored_payload, ensure_ascii=False),
                    inbound_ips,
                    outbound_ips,
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
                if incus_runtime_health is None or incus_runtime_health.get("scan_status") != "complete":
                    preserve_types.extend(INCUS_RUNTIME_ALERT_TYPES)
                notifications = process_security_alerts(
                    conn, host_id, ts, combined_alerts,
                    preserve_active_types=preserve_types,
                )
                buyer_notifications.observe(conn, host_id, ts, containers, combined_alerts)
                security_routes.maybe_enqueue_auto_compliance_connlimit(conn, host_id, ts, combined_alerts)
            elif ts > previous_sample and incus_runtime_health is not None:
                runtime_alerts = [
                    alert for alert in security_alerts
                    if isinstance(alert, dict) and str(alert.get("type") or "") in INCUS_RUNTIME_ALERT_TYPES
                ]
                scan_complete = incus_runtime_health.get("scan_status") == "complete"
                notifications = process_security_alerts(
                    conn, host_id, ts, runtime_alerts,
                    partial=not scan_complete,
                    resolve_types=list(INCUS_RUNTIME_ALERT_TYPES) if scan_complete else None,
                )
            automatic_deep_samples_queued = queue_connection_alert_deep_samples(conn, host_id, ts)
            _store_host_firewall_readback(conn, host_id, security, ts)
            historical_security = dict(security)
            host_firewall_history = security.get("host_firewall")
            if isinstance(host_firewall_history, dict) and "readback" in host_firewall_history:
                historical_firewall = dict(host_firewall_history)
                historical_firewall.pop("readback", None)
                historical_security["host_firewall"] = historical_firewall
            try:
                hs_rx_bps = float(historical_security.get("total_rx_bps") or 0.0)
            except (TypeError, ValueError):
                hs_rx_bps = 0.0
            try:
                hs_tx_bps = float(historical_security.get("total_tx_bps") or 0.0)
            except (TypeError, ValueError):
                hs_tx_bps = 0.0
            conn.execute(
                "INSERT INTO host_security(host_id, ts, payload_json, total_rx_bps, total_tx_bps) VALUES(?,?,?,?,?)",
                (host_id, ts, json.dumps(historical_security, ensure_ascii=False), hs_rx_bps, hs_tx_bps),
            )
            if ts > int(previous_sample or 0):
                sample_health = _security_collection_health(
                    security, {}, ts, ts, agent_version, ts, False, include_gfw=False
                )
                bucket_start = ts - (ts % 3600)
                healthy_sample = int(sample_health.get("status") == "healthy")
                conn.execute(
                    """
                    INSERT INTO host_collection_health_hourly(
                        host_id,bucket_start,total_samples,healthy_samples,last_sample_at,
                        last_status,last_missing_count,agent_version
                    ) VALUES(?,?,1,?,?,?,?,?)
                    ON CONFLICT(host_id,bucket_start) DO UPDATE SET
                        total_samples=host_collection_health_hourly.total_samples+1,
                        healthy_samples=host_collection_health_hourly.healthy_samples+excluded.healthy_samples,
                        last_sample_at=CASE WHEN excluded.last_sample_at>=host_collection_health_hourly.last_sample_at THEN excluded.last_sample_at ELSE host_collection_health_hourly.last_sample_at END,
                        last_status=CASE WHEN excluded.last_sample_at>=host_collection_health_hourly.last_sample_at THEN excluded.last_status ELSE host_collection_health_hourly.last_status END,
                        last_missing_count=CASE WHEN excluded.last_sample_at>=host_collection_health_hourly.last_sample_at THEN excluded.last_missing_count ELSE host_collection_health_hourly.last_missing_count END,
                        agent_version=CASE WHEN excluded.last_sample_at>=host_collection_health_hourly.last_sample_at THEN excluded.agent_version ELSE host_collection_health_hourly.agent_version END
                    """,
                    (host_id, bucket_start, healthy_sample, ts, sample_health.get("status", "unknown"),
                     int(sample_health.get("missing_count") or 0), agent_version),
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
        security_policy = security_routes.get_dynamic_security_policy(conn)
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
        "security_policy": security_policy,
    }


@app.post("/api/v1/report")
async def report(
    request: Request,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Dict[str, Any]:
    body = await request.body()
    verify_signature(body, x_timestamp, x_signature)
    data = json.loads(body)
    client_ip = reach_monitor.extract_client_ip(request)
    return await asyncio.to_thread(_process_report_sync, data, client_ip)


def _candidate_vm_ids(runtime: str, container_name: str, container_id: str) -> tuple[str, ...]:
    cid = str(container_id or "").strip()[:200]
    cname = str(container_name or "").strip()[:200]
    if not cid:
        return ()
    uuid_name = buyer_notifications.buyer_mapping.identifier(cname)
    if uuid_name and "replacement" not in cid.lower():
        return (cid, uuid_name) if cid != uuid_name else (cid,)
    return (cid,)


def _upstream_container_email(conn, identity, container_id, now=None):
    """Return a fresh upstream email only for the exact mapped VM instance."""
    candidates = _candidate_vm_ids(str(identity[1] or ""), str(identity[3] or ""), container_id)
    if not candidates:
        return "", 0
    now = int(time.time()) if now is None else int(now)
    placeholders = ",".join("?" for _ in candidates)
    row = conn.execute(
        f"""
        SELECT user_email, verified_at FROM buyer_targets
        WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND vm_id IN ({placeholders})
          AND source='upstream' AND enabled=1 AND scope='user' AND user_email<>''
          AND verified_at>=?
        ORDER BY verified_at DESC LIMIT 1
        """,
        (*identity, *candidates, now - buyer_notifications.buyer_mapping.TTL),
    ).fetchone()
    return (str(row["user_email"] or ""), int(row["verified_at"] or 0)) if row else ("", 0)


def _buyer_mapping_issue(conn, identity, container_id="", now=None):
    row = conn.execute(
        "SELECT reason FROM buyer_mapping_issues WHERE host_id=? AND runtime=? AND project=? AND container_name=?",
        tuple(identity),
    ).fetchone()
    if row:
        return str(row["reason"] or "")
    candidates = _candidate_vm_ids(str(identity[1] or ""), str(identity[3] or ""), container_id)
    if not candidates:
        return ""
    now = int(time.time()) if now is None else int(now)
    placeholders = ",".join("?" for _ in candidates)
    mapping = conn.execute(
        f"""
        SELECT user_email, user_name, verified_at, enabled FROM buyer_targets
        WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND vm_id IN ({placeholders})
          AND source='upstream' AND scope='user'
        ORDER BY verified_at DESC LIMIT 1
        """,
        (*identity, *candidates),
    ).fetchone()
    if not mapping:
        return ""
    if not int(mapping["enabled"] or 0):
        return "上游实例映射当前未启用，不显示历史邮箱；请确认实例仍由上游 API 管理并重新核对 UUID。"
    if int(mapping["verified_at"] or 0) < now - buyer_notifications.buyer_mapping.TTL:
        return "上游邮箱映射已过期，暂不显示旧邮箱；容器重新上报并成功匹配后会自动刷新。"
    if not buyer_notifications.buyer_mapping.normalize_email(mapping["user_email"]):
        uname = str(mapping["user_name"] or "").strip() if "user_name" in mapping.keys() else ""
        if uname:
            return f"上游已匹配此实例（买家账号：{uname}），但 API 未提供有效邮箱；可手工补充邮箱。"
        return "上游已匹配此实例，但 API 未提供有效邮箱；可手工补充邮箱。"
    return ""


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
        buyer_emails = {}
        buyer_email_issues = {}
        buyer_email_mapping_states = {}
        mapped_after = int(time.time()) - buyer_notifications.buyer_mapping.TTL
        if can_view_user_notes:
            for r in conn.execute(
                """
                SELECT host_id,runtime,project,container_name,vm_id,user_email,user_name,verified_at,enabled
                FROM buyer_targets WHERE source='upstream' AND scope='user'
                """
            ):
                email_val = str(r["user_email"] or "")
                uname_val = str(r["user_name"] or "").strip() if "user_name" in r.keys() else ""
                verified_at = int(r["verified_at"] or 0)
                enabled_val = int(r["enabled"] or 0)
                t_key = (r["host_id"], r["runtime"], r["project"], r["container_name"], r["vm_id"])
                state_val = (email_val, verified_at, enabled_val, uname_val)
                buyer_email_mapping_states[t_key] = state_val
                is_active_email = enabled_val == 1 and email_val != "" and verified_at >= mapped_after
                if is_active_email:
                    buyer_emails[t_key] = email_val
                if r["runtime"] in ("incus", "podman", "container"):
                    alias_key = (r["host_id"], "runman", r["project"], r["container_name"], r["vm_id"])
                    buyer_email_mapping_states.setdefault(alias_key, state_val)
                    if is_active_email:
                        buyer_emails.setdefault(alias_key, email_val)
                elif r["runtime"] == "runman":
                    alias_key = (r["host_id"], "incus", r["project"], r["container_name"], r["vm_id"])
                    buyer_email_mapping_states.setdefault(alias_key, state_val)
                    if is_active_email:
                        buyer_emails.setdefault(alias_key, email_val)
            buyer_email_issues = {
                (r["host_id"], r["runtime"], r["project"], r["container_name"]): str(r["reason"] or "")
                for r in conn.execute(
                    "SELECT host_id,runtime,project,container_name,reason FROM buyer_mapping_issues"
                )
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
    finally:
        conn.close()

    host_report_timestamps: Dict[str, int] = {}
    for r in rows:
        hid = str(r["host_id"])
        r_ts = int(r["ts"])
        if r_ts > host_report_timestamps.get(hid, -1):
            host_report_timestamps[hid] = r_ts

    imbalance_min_bps = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_MIN_BPS", "2097152"))
    imbalance_warn_ratio = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_RATIO_WARN", "10.0"))

    now = int(time.time())
    host_disk_map: Dict[str, Dict[str, Any]] = {}
    parsed_rows = []
    for r in rows:
        hid = str(r["host_id"])
        stale_seconds = max(0, now - r["ts"])
        hidden_offline = stale_seconds > OFFLINE_HIDE_SECONDS
        host_last_seen = host_heartbeats.get(hid, int(r["ts"]))
        host_stale = now - host_last_seen > STALE_SECONDS
        is_latest_host_row = int(r["ts"]) == host_report_timestamps.get(hid, -1)
        if hidden_offline or (host_stale and not include_stale):
            if is_latest_host_row and hid not in host_disk_map:
                payload = json.loads(r["payload_json"]) if r["payload_json"] else {}
                candidate_disk = payload.get("disk", {})
                if isinstance(candidate_disk, dict) and candidate_disk.get("root_total_bytes"):
                    host_disk_map[hid] = candidate_disk
            continue
        payload = json.loads(r["payload_json"]) if r["payload_json"] else {}
        if is_latest_host_row:
            candidate_disk = payload.get("disk", {})
            if isinstance(candidate_disk, dict) and candidate_disk.get("root_total_bytes"):
                host_disk_map[hid] = candidate_disk
        parsed_rows.append((r, payload, stale_seconds, host_last_seen, host_stale))

    out = []
    for r, payload, stale_seconds, host_last_seen, host_stale in parsed_rows:
        stale = stale_seconds > STALE_SECONDS
        hidden_offline = False
        current_container_id = str(payload.get("id") or "")
        note = container_notes.get((r["host_id"], r["runtime"], r["project"], r["container_name"], current_container_id), {})
        manual_email = str(note.get("user_email") or "") if can_view_user_notes else ""
        candidate_ids = _candidate_vm_ids(str(r["runtime"] or ""), str(r["container_name"] or ""), current_container_id)
        upstream_email = ""
        mapping_state = None
        if can_view_user_notes:
            for cid in candidate_ids:
                m_key = (r["host_id"], r["runtime"], r["project"], r["container_name"], cid)
                if not upstream_email and m_key in buyer_emails:
                    upstream_email = buyer_emails[m_key]
                if mapping_state is None and m_key in buyer_email_mapping_states:
                    mapping_state = buyer_email_mapping_states[m_key]
        mapping_issue = buyer_email_issues.get((r["host_id"], r["runtime"], r["project"], r["container_name"]), "") if can_view_user_notes else ""
        if not mapping_issue and not (manual_email or upstream_email) and mapping_state:
            mapped_email, mapped_at, mapping_enabled, mapped_name = mapping_state
            if not mapping_enabled:
                mapping_issue = "上游实例映射当前未启用，不显示历史邮箱；请确认实例仍由上游 API 管理并重新核对 UUID。"
            elif mapped_at < mapped_after:
                mapping_issue = "上游邮箱映射已过期，暂不显示旧邮箱；容器重新上报并成功匹配后会自动刷新。"
            elif not buyer_notifications.buyer_mapping.normalize_email(mapped_email):
                if mapped_name:
                    mapping_issue = f"上游已匹配此实例（买家账号：{mapped_name}），但 API 未提供有效邮箱；可手工补充邮箱。"
                else:
                    mapping_issue = "上游已匹配此实例，但 API 未提供有效邮箱；可手工补充邮箱。"
        admission=admission_rows.get((r['host_id'],r['runtime'],r['project'],r['container_name']))
        reported_identity=(payload.get('security') or {}).get('admission',{}).get('instance_id') or payload.get('stable_id') or payload.get('id') or ''
        if admission and (not admission['instance_id'] or (len(reported_identity)>=12 and admission['instance_id'].startswith(reported_identity))):
            security=payload.setdefault('security',{})
            if admission['observed_at']>security.get('admission',{}).get('observed_at',0):
                security['admission']=json.loads(admission['payload'])
        disk = payload.get("disk") if isinstance(payload.get("disk"), dict) else {}
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
        container_disk = payload.get("container_disk", {})
        container_disk = container_disk if isinstance(container_disk, dict) else {}
        backing_image = container_disk.get("backing_image", {})
        backing_image = backing_image if isinstance(backing_image, dict) else {}
        backing_image_available = (
            r["runtime"] == "runman"
            and backing_image.get("available") is True
            and backing_image.get("source") == "runman_sparse_disk_image"
            and type(backing_image.get("logical_bytes")) is int
            and backing_image["logical_bytes"] >= 0
            and type(backing_image.get("allocated_bytes")) is int
            and 0 <= backing_image["allocated_bytes"] <= backing_image["logical_bytes"]
            and type(backing_image.get("sampled_at")) is int
            and 0 < backing_image["sampled_at"] <= now + 30
            and now - backing_image["sampled_at"] <= 300
        )
        rw_bytes = container_disk.get("rw_bytes") if isinstance(container_disk, dict) else None
        rw_sampled_at = container_disk.get("rw_sampled_at") if isinstance(container_disk, dict) else None
        if r["runtime"] == "runman":
            rw_available = (
                container_disk.get("rw_available") is True
                and container_disk.get("rw_source") == "runman_overlay_upperdir_allocated"
                and type(rw_bytes) is int
                and rw_bytes >= 0
                and type(rw_sampled_at) is int
                and 0 < rw_sampled_at <= now + 30
                and now - rw_sampled_at <= 180
            )
        else:
            rw_available = container_disk.get("rw_available") is True or (
                type(rw_bytes) is int and rw_bytes >= 0
            )
        rw_logical_file_bytes = container_disk.get("rw_logical_file_bytes")
        rw_regular_files = container_disk.get("rw_regular_files")
        rw_logical_available = (
            r["runtime"] == "runman"
            and rw_available
            and container_disk.get("rw_logical_available") is True
            and container_disk.get("rw_logical_source") == "runman_overlay_upperdir_logical_file_bytes"
            and type(rw_logical_file_bytes) is int
            and rw_logical_file_bytes >= 0
            and type(rw_regular_files) is int
            and 0 <= rw_regular_files <= 50_000
        )
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
            "container_instance_id": str(payload.get("stable_id") or ""),
            "container_generation_id": str(payload.get("instance_id") or ""),
            "user_email": manual_email or upstream_email,
            "user_email_source": "manual" if manual_email else "upstream" if upstream_email else "unmatched" if mapping_issue else "",
            "user_email_status": mapping_issue if not (manual_email or upstream_email) else "",
            "user_note": note.get("user_note", "") if can_view_user_notes else "",
            "container_name": r["container_name"],
            "runtime": r["runtime"],
            "project": r["project"],
            "network_addresses": payload.get("network_addresses", []),
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
            "container_disk_rw_available": rw_available,
            "container_disk_rw_source": container_disk.get("rw_source", "runtime_size_rw"),
            "container_disk_rw_sampled_at": rw_sampled_at if rw_available else 0,
            "container_disk_rw_logical_available": rw_logical_available,
            "container_disk_rw_logical_source": (
                container_disk.get("rw_logical_source", "") if rw_logical_available else ""
            ),
            "container_disk_rw_logical_file_bytes": (
                rw_logical_file_bytes if rw_logical_available else None
            ),
            "container_disk_rw_regular_files": rw_regular_files if rw_logical_available else None,
            "container_disk_rootfs_bytes": container_disk.get("rootfs_bytes", 0),
            "container_disk_backing_image_available": backing_image_available,
            "container_disk_backing_image_logical_bytes": backing_image.get("logical_bytes") if backing_image_available else None,
            "container_disk_backing_image_allocated_bytes": backing_image.get("allocated_bytes") if backing_image_available else None,
            "container_disk_backing_image_sampled_at": backing_image.get("sampled_at") if backing_image_available else 0,
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
            "host_report_timestamp": host_report_timestamps.get(str(r["host_id"]), int(r["ts"])),
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
    if runtime not in {"incus", "podman", "runman"}:
        raise HTTPException(status_code=400, detail="仅支持 Incus、Podman 和 Runman 容器")
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
        mapped_email, mapped_at = _upstream_container_email(
            conn, (host_id, runtime, project, container_name), container_id
        )
        mapping_issue = _buyer_mapping_issue(conn, (host_id, runtime, project, container_name), container_id)
    finally:
        conn.close()

    manual_email = str(row["user_email"] or "") if row else ""
    return JSONResponse({
        "ok": True,
        "found": row is not None or bool(mapped_email),
        "host_id": host_id,
        "runtime": runtime,
        "project": project,
        "container_name": container_name,
        "container_id": container_id,
        "user_email": manual_email or mapped_email,
        "user_email_source": "manual" if manual_email else "upstream" if mapped_email else "unmatched" if mapping_issue else "",
        "user_email_status": mapping_issue if not (manual_email or mapped_email) else "",
        "user_note": row["user_note"] if row else "",
        "updated_at": int(row["updated_at"] or 0) if row else mapped_at,
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

    if runtime not in {"incus", "podman", "runman"}:
        raise HTTPException(status_code=400, detail="仅支持 Incus、Podman 和 Runman 容器")
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
            if user_email:
                target_row = conn.execute(
                    """
                    SELECT user_id, user_name FROM buyer_targets
                    WHERE host_id=? AND container_name=?
                      AND (runtime=? OR runtime IN ('incus','podman','runman','container'))
                    ORDER BY (runtime=?) DESC, verified_at DESC LIMIT 1
                    """,
                    (host_id, container_name, runtime, runtime),
                ).fetchone()
                if target_row and str(target_row["user_id"] or "").strip():
                    buyer_notifications.buyer_mapping.record_user_email(
                        conn,
                        str(target_row["user_id"]),
                        user_email,
                        str(target_row["user_name"] or "") if "user_name" in target_row.keys() else "",
                        now,
                    )
        conn.commit()
        mapped_email, _mapped_at = _upstream_container_email(
            conn, note_key[:4], container_id, now
        )
    finally:
        conn.close()

    # Preserve the established POST response shape; clients can read source and
    # mapping diagnostics from the GET endpoint without breaking older callers.
    return JSONResponse({"ok": True, "user_email": user_email or mapped_email, "user_note": user_note})


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
    if not host_id or not container_name or runtime not in ("incus", "podman", "runman"):
        raise HTTPException(status_code=400, detail="Incus, Podman or Runman container identity is required")

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
    monitor_mode = str(latest_payload.get("monitor_mode") or "full").strip().lower()
    if monitor_mode in ("notice", "off", "disabled"):
        conn.close()
        raise HTTPException(status_code=409, detail="container is not in full monitoring mode")

    deep_sample_params = {"sample_seconds": 1.0, "process_limit": 100, "socket_limit": 250, "evidence_schema": 5}
    if runtime == "runman":
        stable_id = str(latest_payload.get("stable_id") or latest_payload.get("id") or "").lower()
        generation = str(latest_payload.get("instance_id") or "").lower()
        if (
            project != "default"
            or stable_id != container_name.lower()
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stable_id)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", generation)
        ):
            conn.close()
            raise HTTPException(status_code=409, detail="Runman 实例身份或代次未通过校验；未下发深度采样")
        deep_sample_params["instance_id"] = generation

    existing = conn.execute(
        """
        SELECT * FROM security_actions
        WHERE alert_id=0 AND host_id=? AND runtime=? AND project=? AND container_name=?
          AND action_type='request_deep_sample' AND status IN ('queued','dispatched')
        ORDER BY id DESC LIMIT 1
        """,
        (host_id, runtime, project, container_name),
    ).fetchone()
    if existing is not None and runtime == "runman":
        existing_params = _alert_details(existing["params_json"])
        if existing_params.get("instance_id") != deep_sample_params.get("instance_id"):
            conn.execute(
                "UPDATE security_actions SET status='failed',result_message='Runman 实例代次已变化，旧深度采样已取消',updated_at=? WHERE id=?",
                (int(time.time()), existing["id"]),
            )
            existing = None
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
                json.dumps(deep_sample_params),
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
                type(pid) is int and 1 < pid <= 4194304
                and re.fullmatch(r"[a-zA-Z0-9_.@+-]{1,80}", process)
                and re.fullmatch(r"[a-zA-Z0-9_.@-]{2,80}", pattern)
                and re.fullmatch(r"[0-9]{1,24}", start_ticks)
                and int(start_ticks) > 0
            ):
                process_targets.append({
                    "pid": pid, "process": process, "pattern": pattern,
                    "start_ticks": start_ticks,
                })
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
                isinstance(path, str) and len(path) <= 256
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
    conn: sqlite3.Connection, alert: sqlite3.Row, details: Dict[str, Any], now: int | None = None,
) -> tuple[bool, str]:
    """Require a fresh latest report with the alert's exact Runman identity."""
    now = int(time.time()) if now is None else int(now)
    vm_uuid = str(alert["container_name"] or "").lower()
    instance_id = str(details.get("instance_id") or "").lower()
    if (
        alert["runtime"] != "runman" or alert["project"] != "default"
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
        stable_id != vm_uuid or current_id != instance_id
        or report_at <= 0 or report_at > now + 30 or now - report_at > STALE_SECONDS
    ):
        return False, "Runman instance generation is stale or has changed"
    return True, instance_id


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


def _resolve_client_bins_dir() -> Path:
    override = os.getenv("NARWHAL_CLIENT_BINS_DIR", "").strip()
    return Path(override) if override else CLIENT_BINS_DIR


@app.get("/api/v1/update/probe/sha256")
def agent_update_probe_sha256(
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> Response:
    """Return bundled narwhal-probe SHA256SUMS to an authenticated Client updater."""
    verify_signature(b"", x_timestamp, x_signature)
    checksums_path = _resolve_client_bins_dir() / "SHA256SUMS"
    if not checksums_path.is_file():
        raise HTTPException(status_code=404, detail="probe checksums not bundled")
    content = checksums_path.read_bytes()
    if len(content) > 65536:
        raise HTTPException(status_code=500, detail="probe checksums file too large")
    response_signature = hmac.new(
        SHARED_SECRET.encode(), content + x_timestamp.encode(), hashlib.sha256
    ).hexdigest()
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={
            "X-Narwhal-Response-Signature": response_signature,
            "Cache-Control": "no-store",
        },
    )


def _serve_client_binary(
    binary_prefix: str,
    arch: str,
    x_timestamp: str,
    x_signature: str,
) -> FileResponse:
    """Verify HMAC signature and serve a bundled static client binary for amd64/arm64."""
    verify_signature(b"", x_timestamp, x_signature)
    if arch not in {"amd64", "arm64"}:
        raise HTTPException(status_code=404, detail=f"unsupported {binary_prefix} architecture")
    filename = f"{binary_prefix}-{arch}"
    bin_path = _resolve_client_bins_dir() / filename
    if not bin_path.is_file():
        raise HTTPException(status_code=404, detail=f"{binary_prefix} binary not bundled")
    return FileResponse(
        path=bin_path,
        media_type="application/octet-stream",
        filename=filename,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/v1/update/probe/{arch}")
def agent_update_probe_binary(
    arch: str,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> FileResponse:
    """Return the bundled static narwhal-probe binary for an authenticated Client updater."""
    return _serve_client_binary("narwhal-probe", arch, x_timestamp, x_signature)


@app.get("/api/v1/update/agent/{arch}")
def agent_update_agent_binary(
    arch: str,
    x_timestamp: str = Header(default=""),
    x_signature: str = Header(default=""),
) -> FileResponse:
    """Return the bundled static narwhal-agent binary for an authenticated Client updater."""
    return _serve_client_binary("narwhal-agent", arch, x_timestamp, x_signature)


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
    runtime = str(alert["runtime"] or "").lower()
    if runtime not in {"incus", "runman"}:
        raise HTTPException(status_code=409, detail="该运行时没有已核验的 TCP 限额适配器；未下发")
    host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (alert["host_id"],)).fetchone()
    if host is None or not str(host["node_id"] or "") or now - int(host["last_seen"] or 0) > STALE_SECONDS:
        raise HTTPException(status_code=409, detail="该节点尚未注册可校验的 Client 身份")
    latest = conn.execute(
        "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
        (alert["host_id"], runtime, alert["project"], alert["container_name"]),
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
    instance_generation = str(payload.get("instance_id") or "") if isinstance(payload, dict) else ""
    if runtime == "runman" and not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", instance_generation):
        raise HTTPException(status_code=409, detail="最新 Runman 采样没有有效实例代次；未下发")
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
    return str(host["node_id"]), (instance_generation if runtime == "runman" else stable_id).lower(), {
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
    if action["runtime"] == "runman":
        # Preserve the exact process start ticks and file fingerprints from the alert.
        return params
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
    if alert["runtime"] not in ("podman", "incus", "runman"):
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
        if alert["runtime"] == "runman":
            identity_ok, instance_id = _runman_alert_generation_current(conn, alert, details)
            if not identity_ok:
                conn.close()
                raise HTTPException(status_code=409, detail=instance_id)
            process_targets = details.get("process_targets") or []
            file_targets = details.get("file_targets") or []
            if not process_targets and not file_targets:
                conn.close()
                raise HTTPException(status_code=409, detail="Runman alert has no generation-bound process or file targets")
            params.update({
                "instance_id": instance_id,
                "process_targets": process_targets,
                "file_targets": file_targets,
            })

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
    if decision in ("allow_silent", "freeze_container", "unfreeze_container") and getattr(request.state,"dashboard_role","admin") != "admin":
        raise HTTPException(status_code=403,detail="只有管理员可以修改长期放行策略或执行容器封禁操作")
    if decision not in ("deny", "allow_silent", "dismiss_once", "reopen", "resolve", "release_udp_throttle", "apply_udp_throttle", "stop_reviewed_socks", "apply_container_connlimit", "release_container_connlimit", "freeze_container", "unfreeze_container"):
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
    if alert["status"] != "active" and decision not in ("deny", "reopen", "allow_silent", "resolve", "release_udp_throttle", "apply_udp_throttle", "release_container_connlimit", "freeze_container", "unfreeze_container"):
        conn.close()
        raise HTTPException(status_code=409, detail="alert is no longer active")

    requested_by = str(
        getattr(request.state, "dashboard_user", DASHBOARD_USERNAME or "dashboard")
    )[:100]
    now = int(time.time())
    action = None
    queued = False
    if decision == 'stop_reviewed_socks':
        if alert['runtime'] == 'runman' and getattr(request.state, 'dashboard_role', 'admin') != 'admin':
            conn.close()
            raise HTTPException(status_code=403, detail='Runman 人工停止操作仅限管理员')
        details = json.loads(alert['details_json'])
        reviews = details.get('password_review', [])
        observed = details.get('review_observed_at', 0)
        token = details.get('review_token', '')
        runman_generation = ''
        runman_identity_ok = True
        if alert['runtime'] == 'runman':
            runman_generation = str(details.get('instance_id') or '').lower()
            latest = conn.execute(
                "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime='runman' AND project='default' AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
                (alert['host_id'], alert['container_name']),
            ).fetchone()
            try:
                latest_payload = json.loads(latest['payload_json'] or '{}') if latest is not None else {}
            except (TypeError, ValueError):
                latest_payload = {}
            stable_id = str(latest_payload.get('stable_id') or latest_payload.get('id') or '').lower() if isinstance(latest_payload, dict) else ''
            latest_generation = str(latest_payload.get('instance_id') or '').lower() if isinstance(latest_payload, dict) else ''
            report_at = int(latest['ts'] or 0) if latest is not None else 0
            runman_identity_ok = (
                alert['project'] == 'default'
                and bool(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', alert['container_name'].lower()))
                and bool(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', runman_generation))
                and stable_id == alert['container_name'].lower()
                and latest_generation == runman_generation
                and report_at > 0 and report_at <= now + 30 and 0 <= now - report_at <= STALE_SECONDS
            )
        if (alert['alert_type'] != 'socks_password_review' or alert['status'] != 'active'
            or alert['runtime'] not in {'incus', 'podman', 'runman'} or not isinstance(observed, (int, float))
            or not 0 <= now-observed <= 900 or not 0 <= now-alert['last_seen'] <= 900
            or not isinstance(reviews, list) or not reviews or not all(isinstance(r, dict) and r.get('action_safe') is True for r in reviews)
            or not re.fullmatch(r'[0-9a-f]{64}', str(token)) or payload.get('review_token') != token
            or not runman_identity_ok):
            conn.close()
            raise HTTPException(status_code=409, detail='证据过期、目标不明确或包含混合业务；请刷新后重新审核，未停止服务')
        reviewed_params = {'manual_review': True, 'review_token': token, 'review_observed_at': observed}
        if alert['runtime'] == 'runman':
            reviewed_params['instance_id'] = runman_generation
        action, queued = _queue_security_action_row(conn, alert, 'stop_reviewed_socks', reviewed_params, requested_by)
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
        if alert["runtime"] not in ("podman", "incus", "runman"):
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
        runman_instance_id = ""
        if alert["runtime"] == "runman":
            if alert["alert_type"] not in ("unauthorized_panel_pairing", "malicious_process"):
                conn.close()
                raise HTTPException(status_code=400, detail="Runman deny supports only generation-bound panel or XMRig remediation")
            identity_ok, runman_instance_id = _runman_alert_generation_current(conn, alert, details, now)
            if not identity_ok:
                conn.close()
                raise HTTPException(status_code=409, detail=runman_instance_id)
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
            if alert["runtime"] == "runman":
                process_targets = details.get("process_targets") or []
                file_targets = details.get("file_targets") or []
                if not process_targets and not file_targets:
                    conn.close()
                    raise HTTPException(status_code=409, detail="Runman alert has no generation-bound process or file targets")
                params.update({
                    "instance_id": runman_instance_id,
                    "process_targets": process_targets,
                    "file_targets": file_targets,
                })
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
            process_targets = [
                item for item in (details.get("process_targets") or [])
                if item.get("process") == "xmrig" and item.get("pattern") == "xmrig"
                and any(
                    malware.get("pid") == item.get("pid")
                    and malware.get("start_ticks") == item.get("start_ticks")
                    for malware in exact_xmrig
                )
            ]
            if alert["runtime"] == "runman" and not process_targets:
                conn.close()
                raise HTTPException(status_code=409, detail="Runman XMRig alert lacks exact process-start evidence")
            params = {
                "process_names": ["xmrig"],
                "process_pids": sorted(set(process_pids)),
            }
            if alert["runtime"] == "runman":
                params.update({
                    "instance_id": runman_instance_id,
                    "process_targets": process_targets,
                    "file_targets": details.get("file_targets") or [],
                })
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
        if alert["alert_type"] == "unauthorized_panel_pairing" and alert["runtime"] in ("podman", "incus", "runman"):
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
    elif decision in ("freeze_container", "unfreeze_container"):
        if alert["runtime"] not in ("podman", "incus", "runman") or not alert["container_name"]:
            conn.close()
            raise HTTPException(status_code=400, detail="当前运行时或目标实例不支持封禁/冻结操作")
        details = _alert_action_evidence(alert)
        freeze_params: Dict[str, Any] = {}
        if details.get("instance_id"):
            freeze_params["instance_id"] = str(details.get("instance_id"))
        if details.get("pid") and str(details.get("pid")).isdigit():
            freeze_params["pid"] = int(details["pid"])
        if decision == "freeze_container":
            conn.execute("UPDATE security_alerts SET status='remediated' WHERE id=?", (alert_id,))
        action, queued = _queue_security_action_row(
            conn, alert, decision, freeze_params, requested_by
        )
    elif decision in ("apply_container_connlimit", "release_container_connlimit"):
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            conn.close()
            raise HTTPException(status_code=403, detail="只有管理员可以修改容器连接限制")
        if (
            alert["alert_type"] != "container_connection_count"
            or alert["runtime"] not in {"incus", "runman"}
            or alert["project"] != "default"
            or not alert["container_name"]
        ):
            conn.close()
            raise HTTPException(status_code=400, detail="临时 TCP 限额仅适用于 default 项目内已接入的 Incus/Runman 连接数告警")
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
                "SELECT params_json,status FROM security_actions WHERE host_id=? AND runtime=? AND project='default' AND container_name=? AND action_type='apply_container_connlimit' AND status='succeeded' ORDER BY id DESC LIMIT 1",
                (alert["host_id"], alert["runtime"], alert["container_name"]),
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
            and alert["runtime"] in ("podman", "incus", "runman")
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
    if decision not in ("deny", "allow_silent", "dismiss_once", "reopen", "resolve", "release_udp_throttle", "apply_udp_throttle", "freeze_container", "unfreeze_container", "apply_udp_blackhole", "release_udp_blackhole", "apply_anti_spoof", "release_anti_spoof"):
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

        if decision in ("release_udp_throttle", "apply_udp_throttle", "freeze_container", "unfreeze_container", "apply_udp_blackhole", "release_udp_blackhole", "apply_anti_spoof", "release_anti_spoof"):
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
        host = conn.execute("SELECT node_id,agent_version FROM hosts WHERE host_id=?", (host_id,)).fetchone()
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
            try:
                policy = _validate_host_firewall_policy(policy)
            except HTTPException:
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
            "speedtest_auto_default": updated_by == SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY,
            "speedtest_policy_supported": _agent_supports_speedtest_policy(host["agent_version"]),
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
        action_id = _enqueue_host_firewall_policy(
            conn, host_id, node_id, materialized, requested_by, now, 0,
            rollback_target_revision=int(history["revision"]),
        )
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
            "automatic_speedtest_default": revision == 0,
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
                "rfw_configured_hosts": sum(1 for item in nodes if item["rfw_configured"]),
                "rfw_verified_hosts": sum(1 for item in nodes if item["rfw_status"] == "verified"),
                "rfw_attention_hosts": sum(1 for item in nodes if item["rfw_configured"] and item["rfw_status"] != "verified"),
                "container_protection_configured_hosts": sum(1 for item in nodes if item["container_protection_status"]["configured"]),
                "container_protection_active_hosts": sum(1 for item in nodes if item["container_protection_status"]["configured"] and item["container_protection_status"]["state"] == "active"),
                "container_protection_attention_hosts": sum(1 for item in nodes if item["container_protection_status"]["configured"] and item["container_protection_status"]["state"] != "active"),
                "container_protection_containers_seen": sum(int(item["container_protection_status"]["containers_seen"] or 0) for item in nodes),
                "container_protection_containers_verified": sum(int(item["container_protection_status"]["containers_verified"] or 0) for item in nodes),
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
        hosts = conn.execute("SELECT host_id,node_id,last_seen FROM hosts ORDER BY host_id").fetchall()
        queued = 0
        deferred = 0
        network_deferred = 0
        policy_abuse = policy.get("abuse") if isinstance(policy, dict) else None
        container_policy_enabled = isinstance(policy_abuse, dict) and any(
            policy_abuse.get(key) is True for key in ("mining", "bt")
        )
        for host in hosts:
            host_id = str(host["host_id"])
            node_id = str(host["node_id"] or "")
            host_online = bool(node_id) and now - int(host["last_seen"] or 0) <= STALE_SECONDS
            existing_policy_row = conn.execute(
                "SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)
            ).fetchone()
            requires_rfw = _policy_has_rfw_effect(policy) or (
                existing_policy_row is not None
                and _stored_policy_has_rfw_effect(str(existing_policy_row["policy_json"] or "{}"))
            )
            runtime = _host_firewall_runtime_status(conn, host_id, now)
            if host_online and (
                not requires_rfw
                or (runtime["control_api"] == "ready" and not runtime["stale"])
            ):
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
                if container_policy_enabled or requires_rfw:
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


def _poll_security_actions_sync(
    host_id: str,
    node_id: str,
    client_ip: str,
    gfw_probe_capabilities: Any,
    now: int,
) -> Dict[str, Any]:
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE hosts SET last_seen=? WHERE host_id=?", (now, host_id))
        if client_ip:
            reach_monitor.record_client_ip(conn, host_id, client_ip, now)
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
            if (row["runtime"] == "host" and row["action_type"] in {"update_host_config", "self_uninstall", "discover_access_logs", "host_security_rescan", "managed_upgrade", "managed_rollback",'disk_cleanup_scan','disk_cleanup_execute', 'apply_host_firewall_policy', 'delete_host_firewall_rule'} or row['action_type'] in {'release_network_quarantine', 'confirm_replaced_network_quarantine', 'apply_container_connlimit', 'release_container_connlimit'}) and stored.get("expected_node_id") != node_id:
                continue
            if row["action_type"] == "restart_container" and stored.get("expected_node_id") != node_id:
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

        tcp_probe = {"job": None, "cancelled": []}
        gfw_probe = {"job": None}
        conn.execute("SAVEPOINT probe_lease")
        try:
            tcp_probe = tcping.lease_jobs(conn, host_id, node_id, now)
            gfw_probe = gfw_monitor.lease_job(conn, host_id, node_id, now, gfw_probe_capabilities)
            conn.execute("RELEASE SAVEPOINT probe_lease")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT probe_lease")
            conn.execute("RELEASE SAVEPOINT probe_lease")
            logging.exception("TCP probe queue failed; signed security polling continues")
            tcp_probe = {"job": None, "cancelled": []}
            gfw_probe = {"job": None}
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
    finally:
        conn.close()
    return {"ok": True, "actions": actions, "operations": {"services": ops_services,'disk_cleanup':cleanup_policy,'bandwidth_limits':bandwidth_policy}, "tcp_probe": tcp_probe, "gfw_probe": gfw_probe}


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
    gfw_probe_capabilities = payload.get("gfw_probe_capabilities")
    if not host_id:
        raise HTTPException(status_code=400, detail="host_id is required")
    now = int(time.time())
    client_ip = reach_monitor.extract_client_ip(request)
    res_payload = await asyncio.to_thread(
        _poll_security_actions_sync, host_id, node_id, client_ip, gfw_probe_capabilities, now
    )
    return signed_json_response(res_payload, x_timestamp)


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
        if row["action_type"] in {"update_host_config", "self_uninstall", "discover_access_logs", "host_security_rescan", "managed_upgrade", "managed_rollback", "release_network_quarantine", "confirm_replaced_network_quarantine",'disk_cleanup_scan','disk_cleanup_execute', 'apply_container_connlimit', 'release_container_connlimit', 'apply_host_firewall_policy', 'delete_host_firewall_rule', "restart_container"} and params.get("expected_node_id") != node_id:
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
        if row["status"] not in ("succeeded", "failed", "cancelled"):
            if row['action_type'] in disk_cleanup.TYPES:
                disk_cleanup.record(conn,host_id,node_id,payload.get('cleanup_run'))
            conn.execute(
                "UPDATE security_actions SET status=?, result_message=?, updated_at=? WHERE id=?",
                (status, message, now, action_id),
            )
            if (row["action_type"] == "managed_upgrade" and status == "failed"
                    and not operations.retry_transient_upgrade_failure(conn, params, message)):
                operations.pause_upgrade_campaign_for_failure(
                    conn, action_id, host_id, now, message, "install_failure"
                )
            if receipt_items and status in {'succeeded','failed'}:
                conn.execute("INSERT INTO security_action_receipts VALUES(?,?,?) ON CONFLICT(action_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at", (action_id,json.dumps(receipt_items,ensure_ascii=False),now))
            if status in {'succeeded','failed'} and row['action_type'] == 'stop_container':
                operations.record_connection_guard(conn,action_id,now)
                buyer_notifications.reconcile(conn,host_id,now)
            if status in {'succeeded','failed'} and row['action_type'] == 'restart_container':
                resource_overload_policy.record_action(conn, action_id, now)
                buyer_notifications.reconcile(conn, host_id, now)
                alert_row = conn.execute("SELECT alert_id FROM security_actions WHERE id=?", (action_id,)).fetchone()
                if alert_row and int(alert_row[0] or 0) > 0:
                    investigation.sync_states(conn, host_id, now, alert_id=int(alert_row[0]))
            if status == "succeeded" and row["action_type"] == "self_uninstall":
                _purge_host(conn, host_id)
                invalidate_security_status_cache()
            if status == "succeeded" and row["action_type"] in (
                "remediate_panel_pairing", "remediate_malicious_process", "enforce_socks_auth", "stop_reviewed_socks", "freeze_container"
            ):
                conn.execute(
                    "UPDATE security_alerts SET status='remediated' WHERE id=? AND status='active'",
                    (row["alert_id"],),
                )
                operations.track_recheck(conn, action_id, now)
            if row['alert_id'] is not None:
                investigation.sync_states(conn, host_id, now, alert_id=row['alert_id'])
            abuse_api.record_release_result(conn, row, params, status, now, message)
            abuse_api.record_replacement_result(conn, row, params, status, now, message)
            conn.commit()
    finally:
        conn.close()
    if row['action_type'] in {'release_network_quarantine', 'confirm_replaced_network_quarantine'} and status in {'succeeded', 'failed'}:
        # A resolved release result may not appear in the next live sample;
        # update the existing Telegram card now, never leave "isolated" forever.
        sync_configured_bot_alert_messages(host_id, alert_id=row['alert_id'])
    return signed_json_response({"ok": True, "action_id": action_id}, x_timestamp)


def broadcast_commerce_telegram(text: str, parse_mode: str = "HTML") -> int:
    conn = db()
    try:
        bots = conn.execute("SELECT id, token, target FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
    finally:
        conn.close()
    sent_count = 0
    for bot in bots:
        try:
            target_chat_id, thread_id = _parse_telegram_target(bot["target"])
            payload = {"chat_id": target_chat_id, "text": text, "parse_mode": parse_mode}
            if thread_id is not None:
                payload["message_thread_id"] = thread_id
            _telegram_api(bot["token"], "sendMessage", payload)
            sent_count += 1
        except Exception as exc:
            logger.warning("Failed to send commerce notification via bot %s: %s", bot["id"], exc)
    return sent_count


operations_api.attach(app, db, lambda: DB_PATH, database_storage_status, cleanup_old_reports, lambda: APP_VERSION, lambda: DASHBOARD_USERNAME)
disk_cleanup.attach(app,db)
commerce.attach(app, db, lambda: DB_PATH, lambda: (DASHBOARD_USERNAME, DASHBOARD_PASSWORD), broadcast_commerce_telegram)
tcping.attach(app, db, STATIC_DIR, verify_signature, signed_json_response)
security_routes.attach(app, db, STALE_SECONDS, lambda: APP_VERSION)
gfw_monitor.attach(app, db, verify_signature, signed_json_response)
abuse_api.attach(app, db, verify_signature, signed_json_response, process_security_alerts, sync_configured_bot_alert_messages, _queue_security_action_row)
admission_api.attach(app, db, verify_signature, signed_json_response, process_security_alerts, sync_configured_bot_alert_messages, buyer_notifications.reconcile)
ip_reputation.attach(app, db, lambda: DB_PATH, commerce.cipher)
reach_monitor.attach(app, db, verify_signature, signed_json_response)


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
              AND a.alert_type <> 'speedtest_attempt_blocked'
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


def sni_and_node_health(limit: int = 100) -> JSONResponse:
    conn = db()
    try:
        return JSONResponse(
            content=security_routes.collect_sni_and_node_health(
                conn,
                now=int(time.time()),
                stale_seconds=STALE_SECONDS,
                app_version=APP_VERSION,
                limit=limit,
            )
        )
    finally:
        conn.close()


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


def _security_collection_capabilities(payload: Dict[str, Any]) -> List[str]:
    """List capabilities actually present in the latest security payload."""
    capabilities: List[str] = []
    if payload.get("enabled") is True:
        capabilities.append("主机安全采样")
    audit = payload.get("host_audit") if isinstance(payload.get("host_audit"), dict) else {}
    if audit.get("enabled") is True:
        capabilities.append("主机审计")
    for key, label in (("cpu_guard", "CPU 保护"), ("memory_guard", "内存保护"), ("io_guard", "磁盘 I/O 保护")):
        if isinstance(payload.get(key), dict):
            capabilities.append(label)
    firewall = payload.get("host_firewall") if isinstance(payload.get("host_firewall"), dict) else {}
    readback = firewall.get("readback") if isinstance(firewall.get("readback"), dict) else {}
    if readback.get("status") == "ready":
        capabilities.append("RFW 规则读回")
    if firewall.get("events_api") == "ready":
        capabilities.append("RFW 事件")
    if isinstance(payload.get("rfw_service_health"), dict):
        capabilities.append("RFW 服务状态")
    sources = payload.get("access_sources") if isinstance(payload.get("access_sources"), list) else []
    if any(isinstance(source, dict) and source.get("enabled") is not False for source in sources):
        capabilities.append("访问日志")
    cpu = payload.get("host_cpu") if isinstance(payload.get("host_cpu"), dict) else {}
    psi = cpu.get("psi") if isinstance(cpu.get("psi"), dict) else {}
    if all(isinstance(psi.get(name), dict) and psi[name].get("status") == "ready" for name in ("cpu", "memory", "io")):
        capabilities.append("宿主机 PSI")
    return capabilities


def _security_rfw_service_health(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Expose only the small, bounded RFW service-health contract."""
    raw = payload.get("rfw_service_health")
    if not isinstance(raw, dict):
        return {}
    allowed_statuses = {"healthy", "stopped", "restart_loop", "not_installed", "not_applicable", "unavailable", "unknown"}
    status = str(raw.get("status") or "unknown")[:32]
    if status not in allowed_statuses:
        status = "unknown"

    def bounded_int(value: Any, maximum: int) -> int | None:
        if type(value) is not int or value < 0:
            return None
        return min(value, maximum)

    active_state = str(raw.get("active_state") or "")[:32]
    sub_state = str(raw.get("sub_state") or "")[:32]
    reason = str(raw.get("reason") or "")[:48]
    return {
        "status": status,
        "checked_at": bounded_int(raw.get("checked_at"), 2**63 - 1),
        "active_state": active_state,
        "sub_state": sub_state,
        "restart_count": bounded_int(raw.get("restart_count"), 2**31 - 1),
        "restarts_5m": bounded_int(raw.get("restarts_5m"), 32),
        "active_seconds": bounded_int(raw.get("active_seconds"), 2**31 - 1),
        "reason": reason,
    }


def _security_collection_health(
    payload: Dict[str, Any],
    gfw: Dict[str, Any],
    last_seen: int,
    report_ts: int,
    agent_version: str,
    now: int,
    stale: bool,
    include_gfw: bool = True,
) -> Dict[str, Any]:
    """Summarize missing host telemetry with the reason and next action."""
    issues: List[Dict[str, str]] = []

    def issue(component: str, state: str, reason: str, guidance: str) -> None:
        issues.append({"component": component, "state": state, "reason": reason[:240], "guidance": guidance[:240]})

    if last_seen and now - last_seen > STALE_SECONDS:
        issue("Agent 上报", "stale", "节点心跳已超过数据有效期", "检查 narwhal-agent 服务、出站网络和主控地址；恢复后等待下一次上报。")
    if not report_ts:
        issue("主机安全遥测", "missing", "没有收到主机安全采样", "确认 Agent 已升级并启用安全采集，再检查 Agent 日志。")
    elif now - report_ts > STALE_SECONDS:
        issue("主机安全遥测", "stale", "最近一次安全采样已超过数据有效期", "检查安全采集任务是否持续运行；等待 Agent 上传新安全采样后再判断当前状态。")
    if report_ts and payload.get("enabled") is not True:
        issue("主机安全遥测", "disabled", "节点未启用安全采集", "在系统设置中启用主机安全采集，并等待 Agent 下一次上报。")

    audit = payload.get("host_audit") if isinstance(payload.get("host_audit"), dict) else {}
    if payload.get("enabled") is True:
        if not audit.get("enabled"):
            issue("主机审计", "missing", "Agent 未返回主机审计数据", "升级 Agent，并确认其有权限读取主机基线与安全日志。")
        else:
            snapshot = str(audit.get("snapshot_status") or "unavailable")
            if snapshot in {"partial", "unavailable"}:
                issue("主机基线", snapshot, str(audit.get("snapshot_error") or "主机文件/账户基线未能完整读取"), "检查 Agent root 权限、审计目录权限及该项扫描错误，然后请求只读复扫。")
            ssh_status = str(audit.get("ssh_log_status") or "unavailable")
            if ssh_status in {"partial", "unavailable"}:
                issue("SSH 登录日志", ssh_status, str(audit.get("ssh_log_error") or "journald 或认证日志不可完整读取"), "检查 journald/auth.log 是否启用及 Agent 读取权限，然后等待新样本。")
            for key, label in (("vulnerability_scan", "漏洞扫描"), ("security_indicator_scan", "威胁指标扫描")):
                scan = audit.get(key) if isinstance(audit.get(key), dict) else {}
                coverage = str(scan.get("coverage") or "unavailable")
                if coverage in {"partial", "unavailable"}:
                    detail = str(scan.get("error") or f"覆盖状态为 {coverage}")
                    guidance = "检查软件包数据库、依赖清单和扫描器可用性；修复后请求只读复扫。"
                    issue(label, coverage, detail, guidance)

        access_sources = payload.get("access_sources") if isinstance(payload.get("access_sources"), list) else []
        for source in access_sources[:12]:
            if not isinstance(source, dict):
                continue
            label = str(source.get("label") or "访问日志")[:80]
            try:
                readable = int(source.get("readable_files") or 0) + int(source.get("container_readable_files") or 0)
                missing = int(source.get("missing_files") or 0)
                unreadable = int(source.get("unreadable_files") or 0)
                parse_errors = int(source.get("parse_errors") or 0)
            except (TypeError, ValueError, OverflowError):
                readable = missing = unreadable = parse_errors = 0
            if unreadable:
                issue(label, "permission_denied", f"{unreadable} 个日志文件不可读", "检查日志文件权限、挂载路径和 Agent 读取权限。")
            elif readable == 0 and source.get("enabled") is not False:
                reason = f"配置的日志文件不存在 ({missing} 个)" if missing else "没有可读的访问日志文件"
                issue(label, "missing", reason, "在主机配置中填写真实 access log 路径；无 HTTP 服务时可忽略此项。")
            elif parse_errors:
                issue(label, "partial", f"{parse_errors} 行日志解析失败", "核对 access log 格式与解析器设置；请求统计可能不完整。")

        for key, label in (("cpu_guard", "CPU 压力保护"), ("memory_guard", "内存压力保护"), ("io_guard", "磁盘 I/O 保护")):
            guard = payload.get(key) if isinstance(payload.get(key), dict) else None
            if guard is None:
                issue(label, "missing", "Agent 未上报保护采样", "升级 Agent 到支持该采集项的版本，并检查服务运行状态。")
            elif str(guard.get("state") or "") in {"unavailable", "sampling_unavailable", "state_unavailable"}:
                issue(label, "unavailable", str(guard.get("message") or "采样数据不可用"), "检查 cgroup v2、容器宿主机 PID 和 Agent 对 /sys/fs/cgroup 的读取权限。")

        host_cpu = payload.get("host_cpu") if isinstance(payload.get("host_cpu"), dict) else {}
        psi = host_cpu.get("psi") if isinstance(host_cpu.get("psi"), dict) else {}
        unavailable_psi = [name for name in ("cpu", "memory", "io")
                           if not isinstance(psi.get(name), dict) or psi[name].get("status") != "ready"]
        if unavailable_psi:
            labels = {"cpu": "CPU", "memory": "内存", "io": "磁盘 I/O"}
            missing = "、".join(labels[name] for name in unavailable_psi)
            issue("PSI 资源压力", "partial" if psi else "missing",
                  f"宿主机 PSI 指标不可用：{missing}",
                  "确认 Linux 内核启用了 PSI 并可读取 /proc/pressure；cgroup PSI 缺失时不能按容器维度判断等待压力。")

    if include_gfw:
        gfw_status = str(gfw.get("status") or "unassessed")
        if gfw_status in {"unassessed", "stale", "investigating"}:
            issue("国内 TCP 连通性", gfw_status, str(gfw.get("reason") or "探测样本不足"), "检查是否存在公网 TCP 映射，并保证至少有独立国内与海外探针在线。")

    if stale:
        status = "stale"
    elif any(item["state"] not in {"normal", "healthy"} for item in issues):
        status = "partial" if report_ts else "unavailable"
    elif not issues:
        status = "healthy"
    else:
        status = "partial"
    return {
        "status": status,
        "last_report_at": report_ts,
        "last_seen": last_seen,
        "report_age_seconds": max(0, now - last_seen) if last_seen else None,
        "agent_version": agent_version,
        "capabilities": _security_collection_capabilities(payload),
        "missing_count": len(issues),
        "issues": issues[:20],
    }


@app.get("/api/v1/security/status")
def security_status() -> JSONResponse:
    global _security_status_cache, _security_status_cache_time
    now_mono = time.monotonic()
    with _security_status_cache_lock:
        if _security_status_cache is not None and now_mono - _security_status_cache_time < 10.0:
            return JSONResponse(content=_security_status_cache)

    with _security_status_compute_lock:
        now_mono = time.monotonic()
        with _security_status_cache_lock:
            if _security_status_cache is not None and now_mono - _security_status_cache_time < 10.0:
                return JSONResponse(content=_security_status_cache)

        res_content = _compute_security_status()
        with _security_status_cache_lock:
            _security_status_cache = res_content
            _security_status_cache_time = time.monotonic()
        return JSONResponse(content=res_content)


def _compute_security_status() -> Dict[str, Any]:
    conn = db()
    try:
        now_utc8 = datetime.now(tz=UTC8)
        today_start_ts = int(now_utc8.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

        try:
            rows = conn.execute(
                """
                SELECT hosts.host_id, COALESCE(h.ts, hosts.last_seen) AS ts, h.ts AS security_ts,
                       hosts.last_seen, hosts.agent_version,
                       hosts.node_id, hosts.config_json, h.payload_json
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
                SELECT hosts.host_id, COALESCE(h.ts, hosts.last_seen) AS ts, h.ts AS security_ts,
                       hosts.last_seen, hosts.agent_version,
                       '' AS node_id, '{}' AS config_json, h.payload_json
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
                    MAX(COALESCE(inbound_unique_ips, CAST(json_extract(payload_json, '$.security.inbound_unique_ips') AS INTEGER), 0)) AS max_inbound_ips,
                    MAX(COALESCE(outbound_unique_ips, CAST(json_extract(payload_json, '$.security.outbound_unique_ips') AS INTEGER), 0)) AS max_outbound_ips
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
                MAX(COALESCE(total_rx_bps, CAST(json_extract(payload_json, '$.total_rx_bps') AS REAL), 0)) AS peak_rx_bps,
                MAX(COALESCE(total_tx_bps, CAST(json_extract(payload_json, '$.total_tx_bps') AS REAL), 0)) AS peak_tx_bps
            FROM host_security
            WHERE ts >= ?
            GROUP BY host_id
            """,
            (today_start_ts,),
        ).fetchall()
        health_now = int(time.time())
        health_cutoff = health_now - 86400
        health_bucket_cutoff = health_cutoff - (health_cutoff % 3600)
        collection_health_rows = conn.execute(
            """
            SELECT host_id,SUM(total_samples) AS total_samples,
                   SUM(healthy_samples) AS healthy_samples,MAX(last_sample_at) AS last_sample_at
            FROM host_collection_health_hourly WHERE bucket_start>=? GROUP BY host_id
            """,
            (health_bucket_cutoff,),
        ).fetchall()
        gfw_by_host = gfw_monitor.status_map(conn, health_now)
        latest_container_rows = conn.execute(
            """SELECT host_id,runtime,project,container_name,ts,payload_json FROM (
                   SELECT host_id,runtime,project,container_name,ts,payload_json,
                          ROW_NUMBER() OVER (PARTITION BY host_id,runtime,project,container_name ORDER BY ts DESC,id DESC) AS row_number
                   FROM reports WHERE ts>=?
               ) WHERE row_number=1""",
            (health_now - STALE_SECONDS,),
        ).fetchall()
        container_controls_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for report_row in latest_container_rows:
            try:
                container_payload = json.loads(report_row["payload_json"] or "{}")
            except (TypeError, ValueError):
                container_payload = {}
            container_controls_by_host.setdefault(str(report_row["host_id"]), []).append({
                "runtime": str(report_row["runtime"] or ""), "project": str(report_row["project"] or ""),
                "container_name": str(report_row["container_name"] or ""), "ts": int(report_row["ts"] or 0),
                "security": container_payload.get("security") if isinstance(container_payload.get("security"), dict) else {},
            })
        firewall_policy_by_host = {}
        for policy_row in conn.execute("SELECT host_id,revision,policy_json FROM host_firewall_policies"):
            try:
                policy_value = json.loads(policy_row["policy_json"] or "{}")
            except (TypeError, ValueError):
                policy_value = {}
            if isinstance(policy_value, dict):
                policy_value.setdefault("revision", int(policy_row["revision"] or 0))
                firewall_policy_by_host[str(policy_row["host_id"])] = policy_value
        reconciliation_by_host = {}
        firewall_readback_by_host = {}
        for host_row in rows:
            host_key = str(host_row["host_id"])
            try:
                host_payload = json.loads(host_row["payload_json"] or "{}")
            except (TypeError, ValueError):
                host_payload = {}
            firewall_readback = _host_firewall_live_readback(conn, host_key, health_now)
            firewall_readback["latest_action"] = _host_firewall_action_summary(conn, host_key)
            firewall_readback_by_host[host_key] = firewall_readback
            reconciliation_by_host[host_key] = control_reconciliation.build_control_reconciliation(
                {**(host_payload if isinstance(host_payload, dict) else {}), "observed_at": int(host_row["security_ts"] or 0)},
                container_controls_by_host.get(host_key, []),
                firewall_policy_by_host.get(host_key),
                firewall_readback,
                health_now,
            )
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

    collection_samples_by_host: Dict[str, Dict[str, Any]] = {}
    for sample_row in collection_health_rows:
        sample_total = max(0, int(sample_row["total_samples"] or 0))
        sample_healthy = max(0, min(sample_total, int(sample_row["healthy_samples"] or 0)))
        collection_samples_by_host[str(sample_row["host_id"])] = {
            "samples_24h": sample_total,
            "healthy_samples_24h": sample_healthy,
            "failed_samples_24h": max(0, sample_total - sample_healthy),
            "healthy_rate_percent_24h": round(100 * sample_healthy / sample_total, 1) if sample_total else None,
            "last_sample_at": max(0, int(sample_row["last_sample_at"] or 0)),
        }

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
        gfw_status = gfw_by_host.get(host_id, {"status": "unassessed"})
        host_last_seen = int(row["last_seen"] or 0)
        sample_timestamp = int(row["security_ts"] or 0)
        report_timestamp = int(row["ts"] or 0)
        host_agent_version = str(row["agent_version"] or "unknown")[:80]
        stale = time.time() - report_timestamp > STALE_SECONDS
        collection_health = _security_collection_health(
            payload, gfw_status, host_last_seen, sample_timestamp, host_agent_version, int(time.time()), stale
        )
        collection_health.update(collection_samples_by_host.get(host_id, {
            "samples_24h": 0, "healthy_samples_24h": 0, "failed_samples_24h": 0,
            "healthy_rate_percent_24h": None, "last_sample_at": 0,
        }))
        rfw_live = firewall_readback_by_host.get(host_id) or {
            "status": "unknown", "stale": True, "sync_status": "unknown",
            "rule_count": 0, "managed_rule_count": 0, "capabilities_known": False,
            "supported_protocols": [], "supported_protocol_count": 0,
            "active_blocked_protocols": [], "active_blocked_protocol_count": 0,
        }
        items.append(
            {
                "host_id": host_id,
                "gfw_reachability": gfw_status,
                "node_id": str(row["node_id"] or ""),
                "host_config": json.loads(row["config_json"] or "{}"),
                "timestamp": report_timestamp,
                "timestamp_utc8": format_utc8(report_timestamp),
                "last_seen": host_last_seen,
                "last_seen_utc8": format_utc8(host_last_seen),
                "agent_version": host_agent_version,
                "collection_health": collection_health,
                "control_reconciliation": reconciliation_by_host.get(host_id, {"status": "unconfigured", "issue_count": 0, "controls": []}),
                "enabled": bool(payload.get("enabled")),
                "stale": stale,
                "interval_seconds": payload.get("interval_seconds"),
                "thresholds": payload.get("thresholds") or {},
                "sample_alerts": payload.get("alerts") or [],
                "host_audit": payload.get("host_audit") if isinstance(payload.get("host_audit"), dict) else {},
                "rfw_service_health": _security_rfw_service_health(payload),
                "rfw_readback": {
                    "status": rfw_live["status"],
                    "stale": rfw_live["stale"],
                    "sync_status": rfw_live["sync_status"],
                    "rule_count": rfw_live["rule_count"],
                    "managed_rule_count": rfw_live["managed_rule_count"],
                    "capabilities_known": rfw_live["capabilities_known"],
                    "supported_protocols": rfw_live["supported_protocols"],
                    "supported_protocol_count": rfw_live["supported_protocol_count"],
                    "active_blocked_protocols": rfw_live["active_blocked_protocols"],
                    "active_blocked_protocol_count": rfw_live["active_blocked_protocol_count"],
                },
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
    return {"items": items}



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
        return FileResponse(file_path, headers={"Cache-Control": "public, max-age=31536000, immutable"})
    raise HTTPException(status_code=404, detail="Asset not found")



def security_alert_history_page(request: Request = None) -> Any:
    return legacy_pages.security_alert_history_page(request, STATIC_DIR)


def dashboard(request: Request = None) -> Any:
    return legacy_pages.dashboard(request, STATIC_DIR)


def container_detail_page(request: Request = None) -> Any:
    return legacy_pages.container_detail_page(request, STATIC_DIR)


def stats_page(request: Request = None) -> Any:
    return legacy_pages.stats_page(request, STATIC_DIR)


legacy_pages.attach(app, lambda: STATIC_DIR)
