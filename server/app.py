import asyncio
import base64
import binascii
from collections import OrderedDict
import gzip
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
import sys
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
    from server import (
        abuse_api,
        admission_api,
        alert_service,
        firewall_service,
        legacy_pages,
        live_events,
        reach_monitor,
        server_metrics,
        telegram_service,
    )
except ImportError:
    import abuse_api
    import admission_api
    import alert_service
    import firewall_service
    import legacy_pages
    import live_events
    import reach_monitor
    import server_metrics
    import telegram_service

POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS = max(
    0, min(120, int(os.getenv("POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS", "25")))
)
_poll_heartbeat_lock = threading.Lock()
_poll_heartbeat_by_db: Dict[tuple[str, str], tuple[int, str]] = {}


def _db_file_key(conn: sqlite3.Connection) -> str:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        return str(row[2] or "") if row else ""
    except Exception:
        return ""


def publish_live_event(topic: str, host_id: str = "", detail: dict | None = None) -> int:
    seq = live_events.bus.publish(topic, host_id, detail)
    server_metrics.metrics.inc("sse_events_published")
    return seq


def _strip_volatile_keys(value: Any, volatile_set: frozenset[str]) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_volatile_keys(item, volatile_set)
            for key, item in value.items()
            if key not in volatile_set
        }
    if isinstance(value, list):
        return [_strip_volatile_keys(item, volatile_set) for item in value]
    return value


def _compute_etag(payload: Any, salt: str = "", volatile_keys: tuple[str, ...] = ()) -> str:
    cleaned = _strip_volatile_keys(payload, frozenset(volatile_keys)) if volatile_keys else payload
    raw = json.dumps(
        {"salt": salt, "payload": cleaned} if salt else cleaned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f'W/"{digest[:24]}"'


def _if_none_match_matches(request: Request | None, etag: str) -> bool:
    if request is None or not etag:
        return False
    headers = getattr(request, "headers", None)
    if headers is None:
        return False
    raw = headers.get("if-none-match")
    if not raw:
        return False
    target_strong = etag[2:] if etag.startswith("W/") else etag
    for part in str(raw).split(","):
        candidate = part.strip()
        if not candidate:
            continue
        if candidate == "*" or candidate == etag:
            return True
        candidate_strong = candidate[2:].strip() if candidate.startswith("W/") else candidate
        if candidate_strong == target_strong:
            return True
    return False

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
    # Tests and administrative recovery may point DB_PATH at a fresh database.
    # Never serve a short-lived snapshot from the previous database in that case.
    invalidate_latest_caches()
    invalidate_security_status_cache()
    with _poll_heartbeat_lock:
        _poll_heartbeat_by_db.clear()
    admission_api.reset_throttle()
    gfw_monitor.reset_schedule_throttle()
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
        "CREATE INDEX IF NOT EXISTS idx_reports_null_peaks "
        "ON reports(ts) WHERE inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_security_null_peaks "
        "ON host_security(ts) WHERE total_rx_bps IS NULL OR total_tx_bps IS NULL"
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

class _ModuleNamespace:
    """Proxy bound directly to this module's globals dict, even under spec_from_file_location."""

    def __init__(self, ns: Dict[str, Any]) -> None:
        self.__dict__ = ns


_self_mod = sys.modules.get(__name__)
if _self_mod is None or getattr(_self_mod, "__dict__", None) is not globals():
    _self_mod = _ModuleNamespace(globals())
_tg_svc = telegram_service.bind(_self_mod)
_fw_svc = firewall_service.bind(_self_mod)
_alert_svc = alert_service.bind(_self_mod)


def _alert_fingerprint(host_id: str, alert: Dict[str, Any]) -> str:
    return _alert_svc._alert_fingerprint(host_id, alert)


def process_security_alerts(
    conn: sqlite3.Connection,
    host_id: str,
    ts: int,
    alerts: List[Dict[str, Any]],
    partial: bool = False,
    preserve_active_types: Optional[List[str]] = None,
    resolve_types: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    return _alert_svc.process_security_alerts(
        conn, host_id, ts, alerts, partial=partial,
        preserve_active_types=preserve_active_types, resolve_types=resolve_types,
    )


def queue_connection_alert_deep_samples(conn: sqlite3.Connection, host_id: str, now: int) -> int:
    return _alert_svc.queue_connection_alert_deep_samples(conn, host_id, now)


def send_alert_webhook(alert: Dict[str, Any]) -> None:
    return _tg_svc.send_alert_webhook(alert)


def _notification_bot_item(row: sqlite3.Row) -> Dict[str, Any]:
    return _tg_svc._notification_bot_item(row)


def _telegram_api_call(token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return _tg_svc._telegram_api_call(token, method, payload)


def _telegram_api(token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return _tg_svc._telegram_api(token, method, payload)


def _telegram_api_socks5(token: str, method: str, data: bytes, proxy_url: str) -> Dict[str, Any]:
    return _tg_svc._telegram_api_socks5(token, method, data, proxy_url)


def _telegram_api_ipv4(token: str, method: str, data: bytes) -> Dict[str, Any]:
    return _tg_svc._telegram_api_ipv4(token, method, data)


def _record_bot_delivery(bot_id: int, succeeded: bool, error: str = "") -> None:
    return _tg_svc._record_bot_delivery(bot_id, succeeded, error)


def _telegram_chat_allowed(bot: sqlite3.Row, chat: Dict[str, Any]) -> bool:
    return _tg_svc._telegram_chat_allowed(bot, chat)


def _telegram_active_alerts(
    severity: str = "all", offset: int = 0, limit: int = 5
) -> tuple[List[sqlite3.Row], int]:
    return _tg_svc._telegram_active_alerts(severity, offset, limit)


def _telegram_actionable(alert: sqlite3.Row) -> bool:
    return _tg_svc._telegram_actionable(alert)


def _telegram_menu() -> tuple[str, Dict[str, Any]]:
    return _tg_svc._telegram_menu()


def _telegram_alert_list(severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    return _tg_svc._telegram_alert_list(severity, offset)


def _telegram_alert_detail(alert_id: int, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    return _tg_svc._telegram_alert_detail(alert_id, severity, offset)


async def _telegram_apply_decision(alert_id: int, decision: str, bot_id: int) -> str:
    return await _tg_svc._telegram_apply_decision(alert_id, decision, bot_id)


def _telegram_confirm(alert_id: int, decision: str, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
    return _tg_svc._telegram_confirm(alert_id, decision, severity, offset)


def _telegram_send_view(bot: sqlite3.Row, update: Dict[str, Any], text: str, keyboard: Dict[str, Any]) -> None:
    return _tg_svc._telegram_send_view(bot, update, text, keyboard)


async def _handle_telegram_update(bot: sqlite3.Row, update: Dict[str, Any]) -> None:
    return await _tg_svc._handle_telegram_update(bot, update)


async def _telegram_polling_loop() -> None:
    return await _tg_svc._telegram_polling_loop()


def _telegram_duration_text(seconds: int) -> str:
    return _tg_svc._telegram_duration_text(seconds)


def _telegram_alert_status_card(
    alert: sqlite3.Row, now: int, deep_evidence: Dict[str, Any] | None = None
) -> tuple[str, Dict[str, Any]]:
    return _tg_svc._telegram_alert_status_card(alert, now, deep_evidence)


def sync_configured_bot_alert_messages(
    host_id: str | None = None,
    observed_at: int | None = None,
    alert_id: int | None = None,
) -> None:
    return _tg_svc.sync_configured_bot_alert_messages(host_id, observed_at, alert_id)


@app.get("/api/v1/notifications/bots")
def notification_bots() -> JSONResponse:
    return _tg_svc.notification_bots()


@app.post("/api/v1/notifications/bots")
async def save_notification_bot(request: Request) -> JSONResponse:
    return await _tg_svc.save_notification_bot(request)


@app.delete("/api/v1/notifications/bots/{bot_id}")
def delete_notification_bot(bot_id: int) -> JSONResponse:
    return _tg_svc.delete_notification_bot(bot_id)


@app.post("/api/v1/notifications/bots/{bot_id}/test")
def test_notification_bot(bot_id: int) -> JSONResponse:
    return _tg_svc.test_notification_bot(bot_id)


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
    return await _tg_svc.telegram_callback(bot_id, callback_secret, request)


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


_REPORT_PAYLOAD_CACHE_MAX = 1024
_report_payload_cache: OrderedDict[int, tuple[str, bytes, Dict[str, Any]]] = OrderedDict()
_report_payload_cache_lock = threading.Lock()

_LATEST_RESPONSE_CACHE_MAX = 4
_LATEST_RESPONSE_CACHE_TTL_SECONDS = 2.0
_latest_response_cache: OrderedDict[tuple[str, str], tuple[float, bytes, bytes]] = OrderedDict()
_latest_response_cache_lock = threading.Lock()

_security_status_cache: Dict[str, Any] | None = None
_security_status_cache_time = 0.0
_security_status_etag = ""
_security_status_cache_lock = threading.Lock()
_security_status_compute_lock = threading.Lock()


def invalidate_latest_caches() -> None:
    with _report_payload_cache_lock:
        _report_payload_cache.clear()
    with _latest_response_cache_lock:
        _latest_response_cache.clear()


def _report_payload_digest(report_id: Any, raw: Any) -> bytes:
    if not raw:
        return b""
    raw_str = raw if isinstance(raw, str) else str(raw)
    try:
        rid = int(report_id)
    except (TypeError, ValueError):
        rid = 0
    if rid > 0:
        with _report_payload_cache_lock:
            entry = _report_payload_cache.get(rid)
            if entry is not None and entry[0] == raw_str:
                return entry[1]
    return hashlib.blake2b(raw_str.encode("utf-8"), digest_size=8).digest()


def _parse_report_payload(report_id: Any, raw: Any) -> Dict[str, Any]:
    """Return cached parsed report payload only when report_id and exact raw JSON match.

    Callers must never mutate the returned dict or any nested container in place.
    """
    if not raw:
        return {}
    raw_str = raw if isinstance(raw, str) else str(raw)
    try:
        rid = int(report_id)
    except (TypeError, ValueError):
        rid = 0
    if rid > 0:
        with _report_payload_cache_lock:
            entry = _report_payload_cache.get(rid)
            if entry is not None and entry[0] == raw_str:
                _report_payload_cache.move_to_end(rid)
                return entry[2]
    try:
        parsed = json.loads(raw_str)
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    digest = hashlib.blake2b(raw_str.encode("utf-8"), digest_size=8).digest()
    if rid > 0:
        with _report_payload_cache_lock:
            _report_payload_cache[rid] = (raw_str, digest, parsed)
            _report_payload_cache.move_to_end(rid)
            while len(_report_payload_cache) > _REPORT_PAYLOAD_CACHE_MAX:
                _report_payload_cache.popitem(last=False)
    return parsed


def _accepts_gzip(request: Request | None) -> bool:
    if request is None:
        return False
    headers = getattr(request, "headers", None)
    if headers is None:
        return False
    raw = str(headers.get("accept-encoding") or "").lower()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        coding, _, params = token.partition(";")
        if coding.strip() == "gzip":
            if "q=0" in params.replace(" ", "") and not re.search(r"q=0\.[0-9]*[1-9]", params):
                return False
            return True
    return False


def invalidate_security_status_cache() -> None:
    global _security_status_cache, _security_status_cache_time, _security_status_etag
    with _security_status_cache_lock:
        _security_status_cache = None
        _security_status_cache_time = 0.0
        _security_status_etag = ""


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


SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY = firewall_service.SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY
SPEEDTEST_POLICY_MIN_AGENT_VERSION = firewall_service.SPEEDTEST_POLICY_MIN_AGENT_VERSION
SPEEDTEST_AUTO_RETRY_INTERVAL = firewall_service.SPEEDTEST_AUTO_RETRY_INTERVAL
SPEEDTEST_AUTO_RETRY_WINDOW = firewall_service.SPEEDTEST_AUTO_RETRY_WINDOW
SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW = firewall_service.SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW
HOST_FIREWALL_READBACK_REASONS = firewall_service.HOST_FIREWALL_READBACK_REASONS


def _validate_host_firewall_policy(payload: Any) -> Dict[str, Any]:
    return _fw_svc._validate_host_firewall_policy(payload)


def _empty_host_firewall_policy() -> Dict[str, Any]:
    return _fw_svc._empty_host_firewall_policy()


def _agent_version_tuple(value: Any) -> Tuple[int, int, int] | None:
    return _fw_svc._agent_version_tuple(value)


def _agent_supports_speedtest_policy(agent_version: Any) -> bool:
    return _fw_svc._agent_supports_speedtest_policy(agent_version)


def _maybe_queue_default_speedtest_policy(
    conn: sqlite3.Connection, host_id: str, node_id: str, agent_version: str, ts: int
) -> bool:
    return _fw_svc._maybe_queue_default_speedtest_policy(conn, host_id, node_id, agent_version, ts)


def _policy_has_rfw_effect(policy: Dict[str, Any] | None) -> bool:
    return _fw_svc._policy_has_rfw_effect(policy)


def _stored_policy_has_rfw_effect(raw: str) -> bool:
    return _fw_svc._stored_policy_has_rfw_effect(raw)


def _validate_host_firewall_readback(payload: Any, report_ts: int) -> Dict[str, Any] | None:
    return _fw_svc._validate_host_firewall_readback(payload, report_ts)


def _store_host_firewall_readback(
    conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], report_ts: int
) -> None:
    return _fw_svc._store_host_firewall_readback(conn, host_id, security, report_ts)


def _host_firewall_live_readback(
    conn: sqlite3.Connection, host_id: str, now: int | None = None
) -> Dict[str, Any]:
    return _fw_svc._host_firewall_live_readback(conn, host_id, now)


def _policy_required_protocols(policy: Dict[str, Any]) -> List[str]:
    return _fw_svc._policy_required_protocols(policy)


def _policy_protocol_compatibility(
    policy: Dict[str, Any], live_readback: Dict[str, Any]
) -> Dict[str, List[str]]:
    return _fw_svc._policy_protocol_compatibility(policy, live_readback)


def _protocol_capability_state(live_readback: Dict[str, Any], protocol: str) -> str:
    return _fw_svc._protocol_capability_state(live_readback, protocol)


def _host_firewall_runtime_status(
    conn: sqlite3.Connection, host_id: str, now: int | None = None
) -> Dict[str, Any]:
    return _fw_svc._host_firewall_runtime_status(conn, host_id, now)


def _host_firewall_interface_inventory(
    conn: sqlite3.Connection, host_id: str, now: int | None = None
) -> Dict[str, Any]:
    return _fw_svc._host_firewall_interface_inventory(conn, host_id, now)


def _host_firewall_policy_targets(
    conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
) -> Tuple[List[str] | None, str]:
    return _fw_svc._host_firewall_policy_targets(conn, host_id, policy, now)


def _materialize_host_firewall_policy(
    conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
) -> Tuple[Dict[str, Any] | None, str]:
    return _fw_svc._materialize_host_firewall_policy(conn, host_id, policy, now)


def _latest_host_firewall_action(conn: sqlite3.Connection, host_id: str) -> sqlite3.Row | None:
    return _fw_svc._latest_host_firewall_action(conn, host_id)


def _host_firewall_action_summary(conn: sqlite3.Connection, host_id: str) -> Dict[str, Any]:
    return _fw_svc._host_firewall_action_summary(conn, host_id)


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
    return _fw_svc._enqueue_host_firewall_policy(
        conn, host_id, node_id, policy, requested_by, now, fleet_revision, rollback_target_revision
    )


def _maybe_queue_fleet_firewall_policy(
    conn: sqlite3.Connection, host_id: str, node_id: str, ts: int, security: Dict[str, Any]
) -> bool:
    return _fw_svc._maybe_queue_fleet_firewall_policy(conn, host_id, node_id, ts, security)


def _ingest_host_firewall_events(
    conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], ts: int
) -> Tuple[List[Dict[str, Any]], str]:
    return _fw_svc._ingest_host_firewall_events(conn, host_id, security, ts)


def _fleet_firewall_node_state(
    conn: sqlite3.Connection,
    host: sqlite3.Row,
    fleet_revision: int,
    now: int,
    required_protocols: List[str] | None = None,
    required_policy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return _fw_svc._fleet_firewall_node_state(
        conn, host, fleet_revision, now, required_protocols, required_policy
    )


def _host_firewall_component_status(
    *, registered: bool, online: bool, configured: bool, runtime: Dict[str, Any],
    live_readback: Dict[str, Any], protocol_status: Dict[str, List[str]],
    target_status: str, container_policy_enabled: bool, action: sqlite3.Row | None,
    local_revision: int, expected_fleet_revision: int, applied_fleet_revision: int,
) -> str:
    return _fw_svc._host_firewall_component_status(
        registered=registered, online=online, configured=configured, runtime=runtime,
        live_readback=live_readback, protocol_status=protocol_status,
        target_status=target_status, container_policy_enabled=container_policy_enabled,
        action=action, local_revision=local_revision,
        expected_fleet_revision=expected_fleet_revision, applied_fleet_revision=applied_fleet_revision,
    )


def _host_container_protection_status(
    conn: sqlite3.Connection, *, host_id: str, now: int, online: bool,
    agent_version: str, policy: Dict[str, Any], policy_row_exists: bool,
    policy_revision: int, auto_default: bool, latest_action: sqlite3.Row | None,
    fleet_revision: int, applied_fleet_revision: int,
) -> Dict[str, Any]:
    return _fw_svc._host_container_protection_status(
        conn, host_id=host_id, now=now, online=online, agent_version=agent_version,
        policy=policy, policy_row_exists=policy_row_exists, policy_revision=policy_revision,
        auto_default=auto_default, latest_action=latest_action,
        fleet_revision=fleet_revision, applied_fleet_revision=applied_fleet_revision,
    )


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


_DEFAULT_DISPATCH_BUYER_NOTIFICATIONS = dispatch_buyer_notifications_for_alerts


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
        motd_states = buyer_notifications.banner_states(conn, host_id)
        security_policy = security_routes.get_dynamic_security_policy(conn)
        if dispatch_buyer_notifications_for_alerts is _DEFAULT_DISPATCH_BUYER_NOTIFICATIONS:
            buyer_notifications.reconcile(conn, host_id, int(time.time()))
            conn.commit()
    finally:
        conn.close()
    invalidate_security_status_cache()
    publish_live_event("report", host_id)

    for alert in notifications:
        send_alert_webhook(alert)
    sync_configured_bot_alert_messages(host_id, ts)
    if dispatch_buyer_notifications_for_alerts is not _DEFAULT_DISPATCH_BUYER_NOTIFICATIONS:
        dispatch_buyer_notifications_for_alerts(host_id, notifications)
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


def _compute_latest_early_etag(
    *,
    rows: List[sqlite3.Row],
    host_heartbeats: Dict[str, int],
    admission_rows: Dict[tuple[str, str, str, str], Dict[str, Any]],
    container_notes: Dict[tuple[str, str, str, str, str], Dict[str, Any]],
    buyer_email_mapping_states: Dict[tuple[str, str, str, str, str], tuple[str, int, int, str]],
    buyer_email_issues: Dict[tuple[str, str, str, str], str],
    include_stale: bool,
    can_view_user_notes: bool,
    now: int,
    mapped_after: int,
    imbalance_min_bps: float,
    imbalance_warn_ratio: float,
) -> str:
    hasher = hashlib.sha256()
    header_part = (
        f"{APP_VERSION}|{int(bool(include_stale))}|{int(bool(can_view_user_notes))}|"
        f"{ALERT_DISK_THRESHOLD_PERCENT}|{ALERT_CPU_THRESHOLD_PERCENT}|"
        f"{ALERT_CONN_WARNING_THRESHOLD}|{ALERT_CONN_CRITICAL_THRESHOLD}|"
        f"{STALE_SECONDS}|{OFFLINE_HIDE_SECONDS}|{imbalance_min_bps}|{imbalance_warn_ratio}"
    )
    hasher.update(header_part.encode("utf-8"))
    for r in rows:
        hid = str(r["host_id"])
        r_ts = int(r["ts"])
        stale_seconds = max(0, now - r_ts)
        hidden_offline = stale_seconds > OFFLINE_HIDE_SECONDS
        host_last_seen = host_heartbeats.get(hid, r_ts)
        host_stale = now - host_last_seen > STALE_SECONDS
        stale = stale_seconds > STALE_SECONDS
        offline_hours = stale_seconds // 3600
        row_meta = (
            f"\nR|{r['id']}|{hid}|{r['runtime']}|{r['project']}|{r['container_name']}|{r_ts}|"
            f"{r['cpu_percent']}|{r['mem_bytes']}|{r['mem_percent']}|"
            f"{r['net_rx_bps']}|{r['net_tx_bps']}|{r['conn_count']}|"
            f"{r['disk_file']}|{r['disk_size_bytes']}|{r['disk_used_percent']}|"
            f"{r['podman_network_ok_v4']}|{r['podman_network_ok_v6']}|"
            f"{int(hidden_offline)}|{int(host_stale)}|{int(stale)}|{offline_hours}|{host_last_seen}|"
        )
        hasher.update(row_meta.encode("utf-8"))
        hasher.update(_report_payload_digest(r["id"], r["payload_json"]))
    for key in sorted(admission_rows):
        adm = admission_rows[key]
        adm_part = f"\nA|{key}|{adm.get('instance_id')}|{adm.get('observed_at')}|{adm.get('payload')}"
        hasher.update(adm_part.encode("utf-8"))
    for key in sorted(container_notes):
        note = container_notes[key]
        note_part = f"\nN|{key}|{note.get('user_email')}|{note.get('user_note')}"
        hasher.update(note_part.encode("utf-8"))
    if can_view_user_notes:
        for key in sorted(buyer_email_mapping_states):
            email_val, verified_at, enabled_val, uname_val = buyer_email_mapping_states[key]
            is_active = int(enabled_val == 1 and email_val != "" and verified_at >= mapped_after)
            is_expired = int(verified_at < mapped_after)
            buyer_part = f"\nB|{key}|{email_val}|{enabled_val}|{uname_val}|{is_active}|{is_expired}"
            hasher.update(buyer_part.encode("utf-8"))
        for key in sorted(buyer_email_issues):
            issue_part = f"\nI|{key}|{buyer_email_issues[key]}"
            hasher.update(issue_part.encode("utf-8"))
    return f'W/"{hasher.hexdigest()[:24]}"'


@app.get("/api/v1/latest")
def latest(include_stale: bool = False, request: Request = None) -> Response:
    can_view_user_notes = request is None or getattr(request.state, "dashboard_role", "admin") in {"admin", "operator"}
    now = int(time.time())
    mapped_after = now - buyer_notifications.buyer_mapping.TTL

    conn = db()
    try:
        db_file = _db_file_key(conn)
        admission_rows={(r['host_id'],r['runtime'],r['project'],r['container_name']):dict(r)
                        for r in conn.execute('SELECT * FROM admission_states')}
        container_notes = {
            (r["host_id"], r["runtime"], r["project"], r["container_name"], r["container_id"]): dict(r)
            for r in conn.execute("SELECT * FROM container_user_notes")
        }
        buyer_emails = {}
        buyer_email_issues = {}
        buyer_email_mapping_states = {}
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
            ORDER BY r.host_id, r.runtime, r.project, r.container_name, r.id
            """
        ).fetchall()
    finally:
        conn.close()

    imbalance_min_bps = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_MIN_BPS", "2097152"))
    imbalance_warn_ratio = float(os.getenv("SECURITY_TRAFFIC_IMBALANCE_RATIO_WARN", "10.0"))

    etag = _compute_latest_early_etag(
        rows=rows,
        host_heartbeats=host_heartbeats,
        admission_rows=admission_rows,
        container_notes=container_notes,
        buyer_email_mapping_states=buyer_email_mapping_states,
        buyer_email_issues=buyer_email_issues,
        include_stale=include_stale,
        can_view_user_notes=can_view_user_notes,
        now=now,
        mapped_after=mapped_after,
        imbalance_min_bps=imbalance_min_bps,
        imbalance_warn_ratio=imbalance_warn_ratio,
    )
    if _if_none_match_matches(request, etag):
        server_metrics.metrics.inc("etag_304_hits")
        return Response(
            status_code=304,
            headers={"ETag": etag, "Vary": "Accept-Encoding", "Cache-Control": "no-store"},
        )

    accepts_gzip = _accepts_gzip(request)
    use_response_cache = bool(db_file) and db_file != ":memory:"
    if use_response_cache:
        cache_key = (db_file, etag)
        now_mono = time.monotonic()
        with _latest_response_cache_lock:
            cached_entry = _latest_response_cache.get(cache_key)
            if cached_entry is not None:
                cached_mono, cached_json_bytes, cached_gzip_bytes = cached_entry
                if now_mono - cached_mono < _LATEST_RESPONSE_CACHE_TTL_SECONDS:
                    _latest_response_cache.move_to_end(cache_key)
                    if accepts_gzip:
                        return Response(
                            content=cached_gzip_bytes,
                            media_type="application/json",
                            headers={
                                "ETag": etag,
                                "Content-Encoding": "gzip",
                                "Vary": "Accept-Encoding",
                            },
                        )
                    return Response(
                        content=cached_json_bytes,
                        media_type="application/json",
                        headers={"ETag": etag, "Vary": "Accept-Encoding"},
                    )
                _latest_response_cache.pop(cache_key, None)

    host_report_timestamps: Dict[str, int] = {}
    for r in rows:
        hid = str(r["host_id"])
        r_ts = int(r["ts"])
        if r_ts > host_report_timestamps.get(hid, -1):
            host_report_timestamps[hid] = r_ts

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
                payload = _parse_report_payload(r["id"], r["payload_json"])
                candidate_disk = payload.get("disk", {})
                if isinstance(candidate_disk, dict) and candidate_disk.get("root_total_bytes"):
                    host_disk_map[hid] = candidate_disk
            continue
        payload = _parse_report_payload(r["id"], r["payload_json"])
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
        admission = admission_rows.get((r["host_id"], r["runtime"], r["project"], r["container_name"]))
        raw_sec = payload.get("security")
        sec_dict = raw_sec if isinstance(raw_sec, dict) else {}
        adm_dict = sec_dict.get("admission") if isinstance(sec_dict.get("admission"), dict) else {}
        reported_identity = adm_dict.get("instance_id") or payload.get("stable_id") or payload.get("id") or ""
        out_security: Any = dict(raw_sec) if isinstance(raw_sec, dict) else ({} if "security" not in payload else raw_sec)
        if admission and (
            not admission["instance_id"]
            or (len(reported_identity) >= 12 and admission["instance_id"].startswith(reported_identity))
        ):
            if admission["observed_at"] > adm_dict.get("observed_at", 0):
                sec_copy = dict(sec_dict)
                sec_copy["admission"] = json.loads(admission["payload"])
                out_security = sec_copy
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

        sec_data = out_security
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
            "security": out_security,
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
    json_bytes = json.dumps(
        res_content, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    gzip_bytes = gzip.compress(json_bytes, compresslevel=5)
    if use_response_cache:
        cache_key = (db_file, etag)
        now_mono = time.monotonic()
        with _latest_response_cache_lock:
            _latest_response_cache[cache_key] = (now_mono, json_bytes, gzip_bytes)
            _latest_response_cache.move_to_end(cache_key)
            while len(_latest_response_cache) > _LATEST_RESPONSE_CACHE_MAX:
                _latest_response_cache.popitem(last=False)
    if accepts_gzip:
        return Response(
            content=gzip_bytes,
            media_type="application/json",
            headers={
                "ETag": etag,
                "Content-Encoding": "gzip",
                "Vary": "Accept-Encoding",
            },
        )
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"ETag": etag, "Vary": "Accept-Encoding"},
    )


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
    return _alert_svc._action_item(row)


def _decision_item(row: sqlite3.Row) -> Dict[str, Any]:
    return _alert_svc._decision_item(row)


def _security_alert_item(conn: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
    return _alert_svc._security_alert_item(conn, row)


def _remediation_changed(message: str) -> bool:
    return _alert_svc._remediation_changed(message)


def _alert_details(raw: str) -> Dict[str, Any]:
    return _alert_svc._alert_details(raw)


def _alert_action_evidence(alert: sqlite3.Row) -> Dict[str, Any]:
    return _alert_svc._alert_action_evidence(alert)


def _runman_alert_generation_current(
    conn: sqlite3.Connection, alert: sqlite3.Row, details: Dict[str, Any], now: int | None = None
) -> tuple[bool, str]:
    return _alert_svc._runman_alert_generation_current(conn, alert, details, now)


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
    return _alert_svc._queue_security_action_row(conn, alert, action_type, params, requested_by)


def _fresh_connlimit_identity(
    conn: sqlite3.Connection, alert: sqlite3.Row, now: int, max_connections: int
) -> tuple[str, str, Dict[str, Any]]:
    return _alert_svc._fresh_connlimit_identity(conn, alert, now, max_connections)


def _latest_action_for_alert(conn: sqlite3.Connection, alert: sqlite3.Row) -> sqlite3.Row | None:
    return _alert_svc._latest_action_for_alert(conn, alert)


def _refresh_remediation_process_pids(conn: sqlite3.Connection, action: sqlite3.Row) -> Dict[str, Any]:
    return _alert_svc._refresh_remediation_process_pids(conn, action)


@app.post("/api/v1/security/alerts/{alert_id}/actions")
async def queue_security_action(alert_id: int, request: Request) -> JSONResponse:
    return await _alert_svc.queue_security_action(alert_id, request)


@app.post("/api/v1/security/alerts/{alert_id}/disposition")
async def set_security_alert_disposition(alert_id: int, request: Request) -> JSONResponse:
    return await _alert_svc.set_security_alert_disposition(alert_id, request)


@app.post("/api/v1/containers/disposition")
async def set_container_disposition(request: Request) -> JSONResponse:
    return await _alert_svc.set_container_disposition(request)


@app.get("/api/v1/hosts/{host_id:path}/firewall-policy")
def get_host_firewall_policy(host_id: str) -> JSONResponse:
    return _fw_svc.get_host_firewall_policy(host_id)


def _prepare_host_firewall_recovery(conn: sqlite3.Connection, host_id: str, now: int):
    return _fw_svc._prepare_host_firewall_recovery(conn, host_id, now)


@app.post("/api/v1/firewall/host-policy/retry")
async def retry_host_firewall_policy(request: Request) -> JSONResponse:
    return await _fw_svc.retry_host_firewall_policy(request)


@app.post("/api/v1/firewall/host-policy/rollback")
async def rollback_host_firewall_policy(request: Request) -> JSONResponse:
    return await _fw_svc.rollback_host_firewall_policy(request)


@app.post("/api/v1/hosts/{host_id:path}/firewall-policy")
async def update_host_firewall_policy(host_id: str, request: Request) -> JSONResponse:
    return await _fw_svc.update_host_firewall_policy(host_id, request)


@app.delete("/api/v1/hosts/{host_id:path}/firewall-rules/{rule_id}")
async def delete_host_firewall_rule(host_id: str, rule_id: int, request: Request) -> JSONResponse:
    return await _fw_svc.delete_host_firewall_rule(host_id, rule_id, request)


@app.get("/api/v1/firewall/fleet-policy")
def get_fleet_firewall_policy() -> JSONResponse:
    return _fw_svc.get_fleet_firewall_policy()


@app.post("/api/v1/firewall/fleet-policy")
async def update_fleet_firewall_policy(request: Request) -> JSONResponse:
    return await _fw_svc.update_fleet_firewall_policy(request)


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
        db_file = _db_file_key(conn)
        host_row = conn.execute("SELECT last_seen FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        with _poll_heartbeat_lock:
            prev = _poll_heartbeat_by_db.get((db_file, host_id)) if db_file else None
        need_heartbeat = (
            not db_file
            or POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS == 0
            or host_row is None
            or now - int(host_row["last_seen"] or 0) >= POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS
            or prev is None
            or now < prev[0]
            or now - prev[0] >= POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS
            or (bool(client_ip) and client_ip != prev[1])
        )
        has_action_work = bool(
            conn.execute(
                """
                SELECT 1 FROM security_actions
                WHERE host_id=?
                  AND ((status='dispatched' AND attempts>=3 AND updated_at < ?)
                       OR (attempts < 3 AND (status='queued' OR (status='dispatched' AND updated_at < ?))))
                LIMIT 1
                """,
                (host_id, now - 120, now - 120),
            ).fetchone()
        )
        try:
            tcp_needs_write, tcp_cancelled = tcping.has_pending_work(conn, host_id, node_id, now)
        except Exception:
            tcp_needs_write, tcp_cancelled = True, []
        try:
            gfw_needs_write = gfw_monitor.has_pending_work(conn, host_id, node_id, now, gfw_probe_capabilities)
        except Exception:
            gfw_needs_write = True

        if not (need_heartbeat or has_action_work or tcp_needs_write or gfw_needs_write):
            actions = []
            tcp_probe = {"job": None, "cancelled": tcp_cancelled}
            gfw_probe = {"job": None}
            server_metrics.metrics.inc("idle_poll_readonly_hits")
        else:
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
            server_metrics.metrics.inc("idle_poll_write_hits")
            if db_file:
                with _poll_heartbeat_lock:
                    _poll_heartbeat_by_db[(db_file, host_id)] = (now, client_ip)

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
        resource_row = conn.execute("SELECT payload FROM ops_settings WHERE key=?", (f"manual_resource_limits:{host_id}",)).fetchone()
        saved_resource_policy = operations.loads(resource_row[0], {}) if resource_row else {}
        if (not isinstance(saved_resource_policy, dict)
                or saved_resource_policy.get("host_id") != host_id
                or saved_resource_policy.get("expected_node_id") != node_id):
            resource_limits_policy = {
                "schema": 1, "host_id": host_id,
                "expected_node_id": node_id, "revision": 0, "limits": [],
            }
        else:
            raw_res_limits = saved_resource_policy.get("limits")
            resource_limits_policy = {
                "schema": 1,
                "host_id": host_id,
                "expected_node_id": node_id,
                "revision": int(saved_resource_policy.get("revision") or 0),
                "limits": raw_res_limits if isinstance(raw_res_limits, list) else [],
            }
    finally:
        conn.close()
    return {"ok": True, "actions": actions, "operations": {"services": ops_services, 'disk_cleanup': cleanup_policy, 'bandwidth_limits': bandwidth_policy, 'resource_limits': resource_limits_policy}, "tcp_probe": tcp_probe, "gfw_probe": gfw_probe}


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
        committed = False
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
            committed = True
    finally:
        conn.close()
    if committed:
        invalidate_security_status_cache()
        publish_live_event("action", host_id)
    if row['action_type'] in {'release_network_quarantine', 'confirm_replaced_network_quarantine'} and status in {'succeeded', 'failed'}:
        # A resolved release result may not appear in the next live sample;
        # update the existing Telegram card now, never leave "isolated" forever.
        sync_configured_bot_alert_messages(host_id, alert_id=row['alert_id'])
    return signed_json_response({"ok": True, "action_id": action_id}, x_timestamp)


def broadcast_commerce_telegram(text: str, parse_mode: str = "HTML") -> int:
    return _tg_svc.broadcast_commerce_telegram(text, parse_mode)


operations_api.attach(app, db, lambda: DB_PATH, database_storage_status, cleanup_old_reports, lambda: APP_VERSION, lambda: DASHBOARD_USERNAME)
disk_cleanup.attach(app,db)
commerce.attach(app, db, lambda: DB_PATH, lambda: (DASHBOARD_USERNAME, DASHBOARD_PASSWORD), broadcast_commerce_telegram)
tcping.attach(app, db, STATIC_DIR, verify_signature, signed_json_response)
security_routes.attach(app, db, STALE_SECONDS, lambda: APP_VERSION)
gfw_monitor.attach(app, db, verify_signature, signed_json_response)
abuse_api.attach(app, db, verify_signature, signed_json_response, process_security_alerts, sync_configured_bot_alert_messages, _queue_security_action_row)
admission_api.attach(
    app,
    db,
    verify_signature,
    signed_json_response,
    process_security_alerts,
    sync_configured_bot_alert_messages,
    buyer_notifications.reconcile,
    on_event=publish_live_event,
    on_metric=server_metrics.metrics.inc,
)
ip_reputation.attach(app, db, lambda: DB_PATH, commerce.cipher)
reach_monitor.attach(app, db, verify_signature, signed_json_response)


@app.get("/api/v1/security/actions")
def security_actions(limit: int = 200) -> JSONResponse:
    return _alert_svc.security_actions(limit)


@app.get("/api/v1/security/alerts")
def security_alerts(active_only: bool = True, limit: int = 200) -> JSONResponse:
    return _alert_svc.security_alerts(active_only, limit)


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
    return _alert_svc.security_alert_history(
        status=status,
        severity=severity,
        alert_type=alert_type,
        host_id=host_id,
        query=query,
        limit=limit,
        offset=offset,
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
def security_status(request: Request = None) -> Response:
    global _security_status_cache, _security_status_cache_time, _security_status_etag
    volatile = ("last_seen_age_seconds", "report_age_seconds", "duration_seconds")
    now_mono = time.monotonic()
    with _security_status_cache_lock:
        if _security_status_cache is not None and now_mono - _security_status_cache_time < 10.0:
            cached_content = _security_status_cache
            cached_etag = _security_status_etag or _compute_etag(cached_content, volatile_keys=volatile)
            _security_status_etag = cached_etag
            if _if_none_match_matches(request, cached_etag):
                server_metrics.metrics.inc("etag_304_hits")
                return Response(
                    status_code=304,
                    headers={"ETag": cached_etag, "Vary": "Accept-Encoding", "Cache-Control": "no-store"},
                )
            return JSONResponse(content=cached_content, headers={"ETag": cached_etag})

    with _security_status_compute_lock:
        now_mono = time.monotonic()
        with _security_status_cache_lock:
            if _security_status_cache is not None and now_mono - _security_status_cache_time < 10.0:
                cached_content = _security_status_cache
                cached_etag = _security_status_etag or _compute_etag(cached_content, volatile_keys=volatile)
                _security_status_etag = cached_etag
                if _if_none_match_matches(request, cached_etag):
                    server_metrics.metrics.inc("etag_304_hits")
                    return Response(
                        status_code=304,
                        headers={"ETag": cached_etag, "Vary": "Accept-Encoding", "Cache-Control": "no-store"},
                    )
                return JSONResponse(content=cached_content, headers={"ETag": cached_etag})

        res_content = _compute_security_status()
        etag = _compute_etag(res_content, volatile_keys=volatile)
        with _security_status_cache_lock:
            _security_status_cache = res_content
            _security_status_cache_time = time.monotonic()
            _security_status_etag = etag
        if _if_none_match_matches(request, etag):
            server_metrics.metrics.inc("etag_304_hits")
            return Response(
                status_code=304,
                headers={"ETag": etag, "Vary": "Accept-Encoding", "Cache-Control": "no-store"},
            )
        return JSONResponse(content=res_content, headers={"ETag": etag})


def _query_peaks_with_index_fallback(
    conn: sqlite3.Connection,
    sql_indexed: str,
    sql_plain: str,
    params: tuple[Any, ...],
) -> List[sqlite3.Row]:
    try:
        return conn.execute(sql_indexed, params).fetchall()
    except sqlite3.OperationalError:
        return conn.execute(sql_plain, params).fetchall()


def _aggregate_container_peaks_from_ts(
    non_null_ts_rows: List[sqlite3.Row],
    null_ts_rows: List[sqlite3.Row],
) -> Dict[str, Dict[str, Any]]:
    by_host_ts: Dict[tuple[str, int], list[Any]] = {}
    for r in non_null_ts_rows:
        key = (str(r["host_id"]), int(r["ts"]))
        by_host_ts[key] = [
            float(r["sum_conn"] or 0),
            float(r["max_conn"] or 0),
            float(r["sum_rx"] or 0.0),
            float(r["sum_tx"] or 0.0),
            int(r["max_inbound_ips"] or 0),
            int(r["max_outbound_ips"] or 0),
        ]
    for r in null_ts_rows:
        key = (str(r["host_id"]), int(r["ts"]))
        cur = by_host_ts.get(key)
        if cur is None:
            by_host_ts[key] = [
                float(r["sum_conn"] or 0),
                float(r["max_conn"] or 0),
                float(r["sum_rx"] or 0.0),
                float(r["sum_tx"] or 0.0),
                int(r["max_inbound_ips"] or 0),
                int(r["max_outbound_ips"] or 0),
            ]
        else:
            cur[0] += float(r["sum_conn"] or 0)
            cur[1] = max(cur[1], float(r["max_conn"] or 0))
            cur[2] += float(r["sum_rx"] or 0.0)
            cur[3] += float(r["sum_tx"] or 0.0)
            cur[4] = max(cur[4], int(r["max_inbound_ips"] or 0))
            cur[5] = max(cur[5], int(r["max_outbound_ips"] or 0))

    peaks_by_host: Dict[str, Dict[str, Any]] = {}
    for (hid, _ts), vals in by_host_ts.items():
        existing = peaks_by_host.get(hid)
        if existing is None:
            peaks_by_host[hid] = {
                "peak_conn_count": int(vals[0]),
                "peak_container_conn_count": int(vals[1]),
                "peak_rx_bps": float(vals[2]),
                "peak_tx_bps": float(vals[3]),
                "peak_inbound_ips": int(vals[4]),
                "peak_outbound_ips": int(vals[5]),
            }
        else:
            existing["peak_conn_count"] = max(existing["peak_conn_count"], int(vals[0]))
            existing["peak_container_conn_count"] = max(existing["peak_container_conn_count"], int(vals[1]))
            existing["peak_rx_bps"] = max(existing["peak_rx_bps"], float(vals[2]))
            existing["peak_tx_bps"] = max(existing["peak_tx_bps"], float(vals[3]))
            existing["peak_inbound_ips"] = max(existing["peak_inbound_ips"], int(vals[4]))
            existing["peak_outbound_ips"] = max(existing["peak_outbound_ips"], int(vals[5]))
    return peaks_by_host


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

        null_container_ts_rows = _query_peaks_with_index_fallback(
            conn,
            """
            SELECT
                host_id,
                ts,
                SUM(conn_count) AS sum_conn,
                MAX(conn_count) AS max_conn,
                SUM(net_rx_bps) AS sum_rx,
                SUM(net_tx_bps) AS sum_tx,
                MAX(COALESCE(inbound_unique_ips, CAST(json_extract(payload_json, '$.security.inbound_unique_ips') AS INTEGER), 0)) AS max_inbound_ips,
                MAX(COALESCE(outbound_unique_ips, CAST(json_extract(payload_json, '$.security.outbound_unique_ips') AS INTEGER), 0)) AS max_outbound_ips
            FROM reports INDEXED BY idx_reports_null_peaks
            WHERE ts >= ? AND (inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL)
            GROUP BY host_id, ts
            """,
            """
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
            WHERE ts >= ? AND (inbound_unique_ips IS NULL OR outbound_unique_ips IS NULL)
            GROUP BY host_id, ts
            """,
            (today_start_ts,),
        )
        if not null_container_ts_rows:
            container_peaks_rows = _query_peaks_with_index_fallback(
                conn,
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
                        MAX(inbound_unique_ips) AS max_inbound_ips,
                        MAX(outbound_unique_ips) AS max_outbound_ips
                    FROM reports INDEXED BY idx_reports_ts_host_peaks
                    WHERE ts >= ? AND inbound_unique_ips IS NOT NULL AND outbound_unique_ips IS NOT NULL
                    GROUP BY host_id, ts
                )
                GROUP BY host_id
                """,
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
                        MAX(inbound_unique_ips) AS max_inbound_ips,
                        MAX(outbound_unique_ips) AS max_outbound_ips
                    FROM reports
                    WHERE ts >= ? AND inbound_unique_ips IS NOT NULL AND outbound_unique_ips IS NOT NULL
                    GROUP BY host_id, ts
                )
                GROUP BY host_id
                """,
                (today_start_ts,),
            )
            non_null_container_ts_rows: List[sqlite3.Row] = []
        else:
            container_peaks_rows = []
            non_null_container_ts_rows = _query_peaks_with_index_fallback(
                conn,
                """
                SELECT
                    host_id,
                    ts,
                    SUM(conn_count) AS sum_conn,
                    MAX(conn_count) AS max_conn,
                    SUM(net_rx_bps) AS sum_rx,
                    SUM(net_tx_bps) AS sum_tx,
                    MAX(inbound_unique_ips) AS max_inbound_ips,
                    MAX(outbound_unique_ips) AS max_outbound_ips
                FROM reports INDEXED BY idx_reports_ts_host_peaks
                WHERE ts >= ? AND inbound_unique_ips IS NOT NULL AND outbound_unique_ips IS NOT NULL
                GROUP BY host_id, ts
                """,
                """
                SELECT
                    host_id,
                    ts,
                    SUM(conn_count) AS sum_conn,
                    MAX(conn_count) AS max_conn,
                    SUM(net_rx_bps) AS sum_rx,
                    SUM(net_tx_bps) AS sum_tx,
                    MAX(inbound_unique_ips) AS max_inbound_ips,
                    MAX(outbound_unique_ips) AS max_outbound_ips
                FROM reports
                WHERE ts >= ? AND inbound_unique_ips IS NOT NULL AND outbound_unique_ips IS NOT NULL
                GROUP BY host_id, ts
                """,
                (today_start_ts,),
            )

        host_sec_covering_rows = _query_peaks_with_index_fallback(
            conn,
            """
            SELECT
                host_id,
                MAX(total_rx_bps) AS peak_rx_bps,
                MAX(total_tx_bps) AS peak_tx_bps
            FROM host_security INDEXED BY idx_host_security_ts_peaks
            WHERE ts >= ? AND total_rx_bps IS NOT NULL AND total_tx_bps IS NOT NULL
            GROUP BY host_id
            """,
            """
            SELECT
                host_id,
                MAX(total_rx_bps) AS peak_rx_bps,
                MAX(total_tx_bps) AS peak_tx_bps
            FROM host_security
            WHERE ts >= ? AND total_rx_bps IS NOT NULL AND total_tx_bps IS NOT NULL
            GROUP BY host_id
            """,
            (today_start_ts,),
        )
        host_sec_null_rows = _query_peaks_with_index_fallback(
            conn,
            """
            SELECT
                host_id,
                MAX(COALESCE(total_rx_bps, CAST(json_extract(payload_json, '$.total_rx_bps') AS REAL), 0)) AS peak_rx_bps,
                MAX(COALESCE(total_tx_bps, CAST(json_extract(payload_json, '$.total_tx_bps') AS REAL), 0)) AS peak_tx_bps
            FROM host_security INDEXED BY idx_host_security_null_peaks
            WHERE ts >= ? AND (total_rx_bps IS NULL OR total_tx_bps IS NULL)
            GROUP BY host_id
            """,
            """
            SELECT
                host_id,
                MAX(COALESCE(total_rx_bps, CAST(json_extract(payload_json, '$.total_rx_bps') AS REAL), 0)) AS peak_rx_bps,
                MAX(COALESCE(total_tx_bps, CAST(json_extract(payload_json, '$.total_tx_bps') AS REAL), 0)) AS peak_tx_bps
            FROM host_security
            WHERE ts >= ? AND (total_rx_bps IS NULL OR total_tx_bps IS NULL)
            GROUP BY host_id
            """,
            (today_start_ts,),
        )
        host_sec_peaks_rows = host_sec_covering_rows + host_sec_null_rows
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
            """SELECT id,host_id,runtime,project,container_name,ts,payload_json FROM (
                   SELECT id,host_id,runtime,project,container_name,ts,payload_json,
                          ROW_NUMBER() OVER (PARTITION BY host_id,runtime,project,container_name ORDER BY ts DESC,id DESC) AS row_number
                   FROM reports WHERE ts>=?
               ) WHERE row_number=1""",
            (health_now - STALE_SECONDS,),
        ).fetchall()
        container_controls_by_host: Dict[str, List[Dict[str, Any]]] = {}
        for report_row in latest_container_rows:
            container_payload = _parse_report_payload(report_row["id"], report_row["payload_json"])
            raw_sec = container_payload.get("security")
            container_controls_by_host.setdefault(str(report_row["host_id"]), []).append({
                "runtime": str(report_row["runtime"] or ""), "project": str(report_row["project"] or ""),
                "container_name": str(report_row["container_name"] or ""), "ts": int(report_row["ts"] or 0),
                "security": raw_sec if isinstance(raw_sec, dict) else {},
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

    if not null_container_ts_rows:
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
    else:
        peaks_by_host = _aggregate_container_peaks_from_ts(non_null_container_ts_rows, null_container_ts_rows)

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
live_events.attach(app, server_metrics.metrics)
app.add_middleware(
    server_metrics.SelectiveGZipMiddleware,
    excluded_paths=set(_AGENT_ONLY_PATHS) | {"/api/v1/events/stream", "/api/v1/latest"},
    minimum_size=1024,
    compresslevel=5,
)
app.add_middleware(
    server_metrics.MetricsMiddleware,
    metrics_collector=server_metrics.metrics,
)
