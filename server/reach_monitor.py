import asyncio
import datetime
import ipaddress
import json
import logging
import random
import re
import sqlite3
import ssl
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("narwhal.reach_monitor")

GLOBALPING_API_URL = "https://api.globalping.io/v1"

# 18 Standard Core Regions including China 3 Major Carriers (AS4134, AS4837, AS9808)
REACH_REGIONS = [
    # China 3 Major Carriers
    {"id": "cn-telecom", "name": "中国电信", "flag": "🇨🇳", "group": "cn", "carrier": "telecom", "asn": 4134, "country": "CN", "loc": {"country": "CN", "asn": 4134}},
    {"id": "cn-unicom", "name": "中国联通", "flag": "🇨🇳", "group": "cn", "carrier": "unicom", "asn": 4837, "country": "CN", "loc": {"country": "CN", "asn": 4837}},
    {"id": "cn-mobile", "name": "中国移动", "flag": "🇨🇳", "group": "cn", "carrier": "mobile", "asn": 9808, "country": "CN", "loc": {"country": "CN", "asn": 9808}},

    # APAC
    {"id": "apac-hk", "name": "中国香港", "flag": "🇭🇰", "group": "apac", "country": "HK", "loc": {"country": "HK"}},
    {"id": "apac-tw", "name": "中国台湾", "flag": "🇨🇳", "group": "apac", "country": "TW", "loc": {"country": "TW"}},
    {"id": "apac-jp", "name": "日本东京", "flag": "🇯🇵", "group": "apac", "city": "Tokyo", "country": "JP", "loc": {"city": "Tokyo"}},
    {"id": "apac-kr", "name": "韩国首尔", "flag": "🇰🇷", "group": "apac", "country": "KR", "loc": {"country": "KR"}},
    {"id": "apac-sg", "name": "新加坡", "flag": "🇸🇬", "group": "apac", "country": "SG", "loc": {"country": "SG"}},
    {"id": "apac-in", "name": "印度孟买", "flag": "🇮🇳", "group": "apac", "country": "IN", "loc": {"country": "IN"}},
    {"id": "apac-au", "name": "澳大利亚悉尼", "flag": "🇦🇺", "group": "apac", "country": "AU", "loc": {"country": "AU"}},

    # EMEA
    {"id": "emea-gb", "name": "英国伦敦", "flag": "🇬🇧", "group": "emea", "city": "London", "country": "GB", "loc": {"city": "London"}},
    {"id": "emea-de", "name": "德国法兰克福", "flag": "🇩🇪", "group": "emea", "city": "Frankfurt", "country": "DE", "loc": {"city": "Frankfurt"}},
    {"id": "emea-ru", "name": "俄罗斯莫斯科", "flag": "🇷🇺", "group": "emea", "country": "RU", "loc": {"country": "RU"}},
    {"id": "emea-ae", "name": "阿联酋迪拜", "flag": "🇦🇪", "group": "emea", "country": "AE", "loc": {"country": "AE"}},
    {"id": "emea-za", "name": "南非约翰内斯堡", "flag": "🇿🇦", "group": "emea", "country": "ZA", "loc": {"country": "ZA"}},

    # Americas
    {"id": "am-us-la", "name": "美国洛杉矶", "flag": "🇺🇸", "group": "am", "city": "Los Angeles", "country": "US", "loc": {"city": "Los Angeles"}},
    {"id": "am-us-ny", "name": "美国纽约", "flag": "🇺🇸", "group": "am", "city": "New York", "country": "US", "loc": {"city": "New York"}},
    {"id": "am-br", "name": "巴西圣保罗", "flag": "🇧🇷", "group": "am", "city": "Sao Paulo", "country": "BR", "loc": {"city": "Sao Paulo"}},
]

_rate_limit_state: Dict[str, Any] = {
    "remaining": 250,
    "limit": 250,
    "reset_seconds": 0,
    "last_sync": 0.0,
    "is_rate_limited": False,
    "pacing_seconds": 128,
}

_ssl_context: Optional[ssl.SSLContext] = None

def _get_ssl_context() -> ssl.SSLContext:
    global _ssl_context
    if _ssl_context is None:
        try:
            import certifi
            _ssl_context = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            _ssl_context = ssl.create_default_context()
            _ssl_context.check_hostname = False
            _ssl_context.verify_mode = ssl.CERT_NONE
    return _ssl_context


def get_globalping_api_key(conn: Optional[sqlite3.Connection] = None) -> str:
    """Retrieves Globalping API Key from environment or database system_settings."""
    import os
    env_key = str(os.environ.get("GLOBALPING_API_KEY") or "").strip()
    if env_key:
        return env_key
    if conn:
        try:
            row = conn.execute("SELECT value FROM system_settings WHERE key = 'globalping_api_key'").fetchone()
            if row and row[0]:
                return str(row[0]).strip()
        except Exception:
            pass
    return ""


def sync_rate_limits(api_key: str = "", force: bool = False) -> Dict[str, Any]:
    """Queries Globalping /v1/limits endpoint to sync accurate credits and reset window."""
    global _rate_limit_state
    now = time.monotonic()
    if not force and _rate_limit_state["last_sync"] > 0 and (now - _rate_limit_state["last_sync"] < 60):
        return _rate_limit_state
    try:
        headers = {"User-Agent": "Narwhal-Watcher"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(f"{GLOBALPING_API_URL}/limits", headers=headers)
        ctx = _get_ssl_context()
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            create_lim = data.get("rateLimit", {}).get("measurements", {}).get("create", {})
            _rate_limit_state["limit"] = int(create_lim.get("limit", 250))
            _rate_limit_state["remaining"] = int(create_lim.get("remaining", 250))
            _rate_limit_state["reset_seconds"] = int(create_lim.get("reset", 0))
            _rate_limit_state["is_rate_limited"] = (_rate_limit_state["remaining"] <= 0)
            _rate_limit_state["last_sync"] = now
    except Exception as e:
        logger.debug(f"Failed to sync Globalping limits: {e}")
    return _rate_limit_state


def _update_rate_limits_from_headers(headers: Any) -> None:
    """Extracts X-Credits-Remaining, X-RateLimit-Reset, etc., from HTTP response headers."""
    global _rate_limit_state
    if not headers:
        return
    rem = headers.get("X-Credits-Remaining") or headers.get("X-RateLimit-Remaining")
    reset = headers.get("X-RateLimit-Reset") or headers.get("Retry-After")
    limit = headers.get("X-RateLimit-Limit")
    if rem is not None:
        try:
            _rate_limit_state["remaining"] = int(rem)
            _rate_limit_state["is_rate_limited"] = (_rate_limit_state["remaining"] <= 0)
        except (ValueError, TypeError):
            pass
    if reset is not None:
        try:
            _rate_limit_state["reset_seconds"] = int(reset)
        except (ValueError, TypeError):
            pass
    if limit is not None:
        try:
            _rate_limit_state["limit"] = int(limit)
        except (ValueError, TypeError):
            pass
    _rate_limit_state["last_sync"] = time.monotonic()


def init_db(conn: sqlite3.Connection) -> None:
    """Initialize schema for host automated reachability checks."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS host_reachability (
        host_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'TCP',
        verdict TEXT NOT NULL,
        verdict_label TEXT NOT NULL,
        verdict_desc TEXT NOT NULL,
        stats_json TEXT NOT NULL DEFAULT '{}',
        results_json TEXT NOT NULL DEFAULT '[]',
        checked_at INTEGER NOT NULL,
        target_v6 TEXT DEFAULT '',
        port_v6 INTEGER DEFAULT 0,
        protocol_v6 TEXT DEFAULT 'TCP',
        verdict_v6 TEXT DEFAULT '',
        verdict_label_v6 TEXT DEFAULT '',
        verdict_desc_v6 TEXT DEFAULT '',
        stats_json_v6 TEXT DEFAULT '{}',
        results_json_v6 TEXT DEFAULT '[]',
        checked_at_v6 INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS host_reachability_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id TEXT NOT NULL,
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        verdict TEXT NOT NULL,
        stats_json TEXT NOT NULL DEFAULT '{}',
        checked_at INTEGER NOT NULL,
        target_v6 TEXT DEFAULT '',
        port_v6 INTEGER DEFAULT 0,
        protocol_v6 TEXT DEFAULT 'TCP',
        verdict_v6 TEXT DEFAULT '',
        stats_json_v6 TEXT DEFAULT '{}',
        checked_at_v6 INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_reach_hist_host ON host_reachability_history(host_id, checked_at);
    CREATE TABLE IF NOT EXISTS host_client_ips (
        host_id TEXT PRIMARY KEY,
        client_ip TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    """)

    # Migrate columns if existing tables lacked dual-stack fields
    try:
        hr_cols = {row[1] for row in conn.execute("PRAGMA table_info(host_reachability)").fetchall()}
        v6_cols = [
            ("target_v6", "TEXT DEFAULT ''"),
            ("port_v6", "INTEGER DEFAULT 0"),
            ("protocol_v6", "TEXT DEFAULT 'TCP'"),
            ("verdict_v6", "TEXT DEFAULT ''"),
            ("verdict_label_v6", "TEXT DEFAULT ''"),
            ("verdict_desc_v6", "TEXT DEFAULT ''"),
            ("stats_json_v6", "TEXT DEFAULT '{}'"),
            ("results_json_v6", "TEXT DEFAULT '[]'"),
            ("checked_at_v6", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in v6_cols:
            if col_name not in hr_cols:
                conn.execute(f"ALTER TABLE host_reachability ADD COLUMN {col_name} {col_def}")

        hist_cols = {row[1] for row in conn.execute("PRAGMA table_info(host_reachability_history)").fetchall()}
        hist_v6_cols = [
            ("target_v6", "TEXT DEFAULT ''"),
            ("port_v6", "INTEGER DEFAULT 0"),
            ("protocol_v6", "TEXT DEFAULT 'TCP'"),
            ("verdict_v6", "TEXT DEFAULT ''"),
            ("stats_json_v6", "TEXT DEFAULT '{}'"),
            ("checked_at_v6", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in hist_v6_cols:
            if col_name not in hist_cols:
                conn.execute(f"ALTER TABLE host_reachability_history ADD COLUMN {col_name} {col_def}")
    except Exception as e:
        logger.debug(f"Dual-stack column migration: {e}")


def record_client_ip(conn: sqlite3.Connection, host_id: str, client_ip: str, ts: Optional[int] = None) -> None:
    """Persists host's public ingress IP cleanly in host_client_ips without modifying hosts schema."""
    if not host_id or not client_ip:
        return
    if ts is None:
        ts = int(time.time())
    try:
        conn.execute(
            "INSERT INTO host_client_ips(host_id, client_ip, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(host_id) DO UPDATE SET client_ip=excluded.client_ip, updated_at=excluded.updated_at",
            (host_id, client_ip, ts),
        )
    except Exception:
        pass


_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network(net) for net in [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
]


def is_cloudflare_ip(ip_val: Any) -> bool:
    """Checks whether an IP address belongs to Cloudflare's Anycast CDN proxy ranges."""
    if not ip_val:
        return False
    try:
        if isinstance(ip_val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip = ip_val
        else:
            ip = ipaddress.ip_address(str(ip_val).split("/")[0].strip())
        return any(ip in net for net in CLOUDFLARE_NETWORKS)
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """SSRF & Bogon protection: ensures target is not RFC 1918, CGNAT, loopback, link-local, multicast, or CDN edge."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.split("/")[0].strip()
    try:
        ip = ipaddress.ip_address(clean)
        if ip in _CGNAT_NET:
            return False
        if is_cloudflare_ip(ip):
            return False
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def extract_client_ip(request: Any) -> str:
    """Extracts the true ingress client IP, prioritizing CF-Connecting-IP, X-Real-IP, and X-Narwhal-Proxy-Peer while rejecting CDN/proxy edge IPs."""
    headers = getattr(request, "headers", None)
    if headers:
        # 1. Cloudflare provided client IP
        cf_ip = str(headers.get("cf-connecting-ip") or "").strip()
        if cf_ip and is_public_ip(cf_ip):
            return cf_ip

        # 2. X-Real-IP
        real_ip = str(headers.get("x-real-ip") or "").strip()
        if real_ip and is_public_ip(real_ip):
            return real_ip

        # 3. Caddy authenticated peer header
        proxy_peer = str(headers.get("x-narwhal-proxy-peer") or "").strip()
        if proxy_peer and is_public_ip(proxy_peer):
            return proxy_peer

        # 4. X-Forwarded-For: find the first public non-Cloudflare IP
        forwarded = headers.get("x-forwarded-for")
        if forwarded:
            for part in str(forwarded).split(","):
                cand = part.strip()
                if cand and is_public_ip(cand):
                    return cand

    client_obj = getattr(request, "client", None)
    if client_obj and client_obj.host:
        host = str(client_obj.host).strip()
        if host and is_public_ip(host):
            return host

    return ""


def discover_host_targets(conn: sqlite3.Connection, host_id: str) -> Dict[str, str]:
    """Finds verified public IPv4 and IPv6 addresses for the host.
    Returns: {"ipv4": str, "ipv6": str}
    """
    found_v4 = ""
    found_v6 = ""

    def _consider(cand: Any) -> None:
        nonlocal found_v4, found_v6
        if not cand:
            return
        clean_ip = str(cand).split("/")[0].strip()
        if not clean_ip or not is_public_ip(clean_ip):
            return
        try:
            ip = ipaddress.ip_address(clean_ip)
            if ip.version == 4 and not found_v4:
                found_v4 = clean_ip
            elif ip.version == 6 and not found_v6:
                found_v6 = clean_ip
        except ValueError:
            pass

    # 1. From host_security interface_inventory
    sec = conn.execute(
        "SELECT payload_json FROM host_security WHERE host_id=? ORDER BY ts DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    if sec:
        try:
            p = json.loads(sec["payload_json"])
            ii = p.get("host_firewall", {}).get("interface_inventory", {})
            for iface in ii.get("interfaces", []):
                # Filter out container/virtual interfaces
                name = str(iface.get("name") or "")
                if name.startswith(("docker", "br-", "veth", "tailscale", "wg", "zt")):
                    continue
                for addr in iface.get("addresses", []):
                    _consider(addr)
                    if found_v4 and found_v6:
                        return {"ipv4": found_v4, "ipv6": found_v6}
        except Exception:
            pass

    # 2. From reports network_addresses (latest row only)
    rep = conn.execute(
        "SELECT payload_json FROM reports WHERE host_id=? ORDER BY ts DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    if rep:
        try:
            p = json.loads(rep["payload_json"])
            for addr in p.get("network_addresses", []) or []:
                _consider(addr)
                if found_v4 and found_v6:
                    return {"ipv4": found_v4, "ipv6": found_v6}
        except Exception:
            pass

    # 3. From gfw_states targets
    gfw = conn.execute(
        "SELECT evidence_json FROM gfw_states WHERE host_id=?", (host_id,)
    ).fetchone()
    if gfw:
        try:
            gp = json.loads(gfw["evidence_json"])
            for t in gp.get("targets", []) or []:
                _consider(t.get("ip"))
            for bek in gp.get("blocked_endpoint_keys", []) or []:
                if bek:
                    _consider(bek[0])
            if found_v4 and found_v6:
                return {"ipv4": found_v4, "ipv6": found_v6}
        except Exception:
            pass

    # 4. From host_client_ips
    try:
        cip = conn.execute("SELECT client_ip FROM host_client_ips WHERE host_id=?", (host_id,)).fetchone()
        if cip and cip["client_ip"]:
            _consider(cip["client_ip"])
            if found_v4 and found_v6:
                return {"ipv4": found_v4, "ipv6": found_v6}
    except Exception:
        pass

    # 5. From hosts client_ip if legacy column exists
    try:
        h = conn.execute("SELECT client_ip FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if h and h["client_ip"]:
            _consider(h["client_ip"])
    except Exception:
        pass

    return {"ipv4": found_v4, "ipv6": found_v6}


def discover_host_target(conn: sqlite3.Connection, host_id: str) -> str:
    """Finds a verified public IPv4 / IPv6 address or domain name for the host."""
    targets = discover_host_targets(conn, host_id)
    return targets.get("ipv4") or targets.get("ipv6") or ""


def format_utc8(ts: int) -> str:
    """Formats unix epoch seconds into UTC+8 standard string (YYYY-MM-DD HH:mm:ss)."""
    if not ts or ts <= 0:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            ts, tz=datetime.timezone(datetime.timedelta(hours=8))
        ).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def discover_host_open_ports(conn: sqlite3.Connection, host_id: str) -> List[int]:
    """Finds all currently open public listening ports for this machine.
    Prioritizes verified endpoints from gfw_states and explicit host mappings in network_exposure.
    Container-internal unmapped ports are strictly excluded to avoid false unreachable alerts.
    """
    ports: Set[int] = set()

    # 1. From gfw_states evidence_json targets (verified endpoints)
    try:
        gfw = conn.execute(
            "SELECT evidence_json FROM gfw_states WHERE host_id=?", (host_id,)
        ).fetchone()
        if gfw and gfw["evidence_json"]:
            gp = json.loads(gfw["evidence_json"])
            for t in gp.get("targets", []) or []:
                p = t.get("port")
                if p:
                    try:
                        port = int(p)
                        if 1 <= port <= 65535 and port not in {25, 53, 5355}:
                            ports.add(port)
                    except (ValueError, TypeError):
                        pass
            for bek in gp.get("blocked_endpoint_keys", []) or []:
                if isinstance(bek, (list, tuple)) and len(bek) >= 2 and bek[1]:
                    try:
                        port = int(bek[1])
                        if 1 <= port <= 65535 and port not in {25, 53, 5355}:
                            ports.add(port)
                    except (ValueError, TypeError):
                        pass
    except Exception:
        pass

    # 2. From reports latest rows:
    try:
        rep_rows = conn.execute(
            "SELECT payload_json FROM reports WHERE host_id=? ORDER BY ts DESC LIMIT 30",
            (host_id,),
        ).fetchall()
        for rep in rep_rows:
            p = json.loads(rep["payload_json"] or "{}")
            sec_p = p.get("security", {})
            has_public_container_ip = any(
                is_public_ip(str(addr).split("/")[0].strip())
                for addr in (p.get("network_addresses", []) or [])
            )
            # If container has direct public IP or host networking, its listening ports are publicly reachable
            if has_public_container_ip:
                for lp in sec_p.get("listening_ports", []) or []:
                    try:
                        port = int(lp)
                        if 1 <= port <= 65535 and port not in {25, 53, 5355}:
                            ports.add(port)
                    except (ValueError, TypeError):
                        continue

            # Explicit host network exposures (mapped ports)
            for exp in sec_p.get("network_exposure", []) or []:
                if isinstance(exp, dict):
                    hp = exp.get("host_port")
                    if not hp and exp.get("listen"):
                        listen_str = str(exp.get("listen")).strip()
                        if ":" in listen_str:
                            hp = listen_str.split(":")[-1]
                    if hp:
                        try:
                            port = int(hp)
                            if 1 <= port <= 65535 and port not in {25, 53, 5355}:
                                ports.add(port)
                        except (ValueError, TypeError):
                            continue
    except Exception:
        pass

    # 3. From host_security host_firewall (actual host listening ports)
    try:
        sec = conn.execute(
            "SELECT payload_json FROM host_security WHERE host_id=? ORDER BY ts DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if sec:
            p = json.loads(sec["payload_json"] or "{}")
            hf = p.get("host_firewall", {})
            for lp in hf.get("listening_ports", []) or []:
                try:
                    port = int(lp)
                    if 1 <= port <= 65535 and port not in {25, 53, 5355}:
                        ports.add(port)
                except (ValueError, TypeError):
                    continue
    except Exception:
        pass

    return sorted(ports)


def choose_random_port(ports: List[int]) -> int:
    """Randomly selects an open port on the target machine, or returns 0 if no ports are open."""
    if not ports:
        return 0
    # Prefer non-internal ports if multiple are open
    filtered = [p for p in ports if p not in {25, 53, 5355}]
    if filtered:
        return random.choice(filtered)
    return random.choice(ports)


def execute_globalping_measurement(
    target: str,
    port: int,
    protocol: str = "TCP",
    regions: Optional[List[Dict[str, Any]]] = None,
    timeout_seconds: int = 25,
    api_key: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Dict[str, Any]:
    """Posts a measurement to Globalping and polls until completion. Supports TCP (HTTP probe) and ICMP (Ping probe)."""
    if api_key is None:
        api_key = get_globalping_api_key(conn)

    # Sync rate limits if never synced
    if _rate_limit_state.get("last_sync", 0.0) == 0.0:
        sync_rate_limits(api_key)

    # Credit budget guard: if unauthenticated and remaining credits exhausted or < 3
    if not api_key:
        if _rate_limit_state.get("is_rate_limited") or _rate_limit_state.get("remaining", 250) < 3:
            logger.warning(
                f"Globalping rate limit guard active: remaining={_rate_limit_state.get('remaining')} credits, "
                f"reset_seconds={_rate_limit_state.get('reset_seconds')}. Skipping request to avoid 429."
            )
            return {
                "status": "rate_limited",
                "results": [],
                "active_regions": [],
                "reset_seconds": _rate_limit_state.get("reset_seconds", 300),
            }

    if regions is not None:
        active_regions = regions
    elif api_key:
        active_regions = REACH_REGIONS
    elif _rate_limit_state.get("remaining", 250) < 8:
        # Dynamic Budget Mode: remaining points low (<8), probe China 3 carriers only (cost: 3 credits)
        active_regions = [r for r in REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile"}]
    else:
        # Default core regions when unauthenticated: 8 key probes stay strictly within 250 free credits/hour across 28 cluster hosts
        core_ids = {"cn-telecom", "cn-unicom", "cn-mobile", "apac-hk", "apac-jp", "apac-sg", "emea-gb", "am-us-la"}
        active_regions = [r for r in REACH_REGIONS if r["id"] in core_ids]

    locations = [{"limit": 1, **r["loc"]} for r in active_regions]
    is_ping = (protocol.upper() == "PING" or port <= 0)

    if is_ping:
        measurement_body = {
            "type": "ping",
            "target": target,
            "locations": locations,
            "measurementOptions": {
                "packets": 3,
            },
        }
    else:
        http_proto = "HTTPS" if port == 443 else "HTTP"
        measurement_body = {
            "type": "http",
            "target": target,
            "locations": locations,
            "measurementOptions": {
                "port": port,
                "protocol": http_proto,
            },
        }

    body_bytes = json.dumps(measurement_body).encode("utf-8")
    ctx = _get_ssl_context()
    headers = {"Content-Type": "application/json", "User-Agent": "Narwhal-Watcher"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(
        f"{GLOBALPING_API_URL}/measurements",
        data=body_bytes,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
            _update_rate_limits_from_headers(resp.headers)
            post_data = json.loads(resp.read().decode("utf-8"))
            measurement_id = post_data["id"]
    except urllib.error.HTTPError as e:
        if e.code == 429:
            _update_rate_limits_from_headers(e.headers)
            _rate_limit_state["is_rate_limited"] = True
            _rate_limit_state["remaining"] = 0
            retry_after = e.headers.get("Retry-After") or e.headers.get("X-RateLimit-Reset") or _rate_limit_state.get("reset_seconds") or 300
            try:
                _rate_limit_state["reset_seconds"] = int(retry_after)
            except (ValueError, TypeError):
                pass
            logger.warning(f"Globalping rate limit reached (HTTP 429, reset in {retry_after}s). Set GLOBALPING_API_KEY for higher quota.")
            return {"status": "rate_limited", "results": [], "active_regions": active_regions, "reset_seconds": _rate_limit_state.get("reset_seconds", 300)}
        raise

    # Poll for completion
    deadline = time.time() + timeout_seconds
    m_data: Dict[str, Any] = {"results": [], "active_regions": active_regions}
    while time.time() < deadline:
        time.sleep(1.5)
        poll_headers = {"User-Agent": "Narwhal-Watcher"}
        if api_key:
            poll_headers["Authorization"] = f"Bearer {api_key}"
        poll_req = urllib.request.Request(
            f"{GLOBALPING_API_URL}/measurements/{measurement_id}",
            headers=poll_headers,
        )
        with urllib.request.urlopen(poll_req, context=ctx, timeout=10) as poll_resp:
            _update_rate_limits_from_headers(poll_resp.headers)
            m_data = json.loads(poll_resp.read().decode("utf-8"))
            m_data["active_regions"] = active_regions
            if m_data.get("status") == "finished":
                return m_data
            results = m_data.get("results") or []
            if results and all(r.get("result", {}).get("status") in {"finished", "failed"} for r in results):
                return m_data

    return m_data


def parse_measurement_results(
    m_data: Dict[str, Any],
    target: str,
    port: int,
    protocol: str = "TCP",
    regions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Processes Globalping raw output into verdicts, latency stats, and region breakdown."""
    active_regions = regions or m_data.get("active_regions") or REACH_REGIONS
    effective_proto = "PING" if (protocol.upper() == "PING" or port <= 0 or m_data.get("type") == "ping") else "TCP"

    if m_data.get("status") == "rate_limited":
        return {
            "target": target,
            "port": port,
            "protocol": effective_proto,
            "verdict": "timeout",
            "verdict_label": "探针配额受限",
            "verdict_desc": "Globalping 公共探针免费配额已耗尽，请等待整点刷新或配置 GLOBALPING_API_KEY。",
            "stats": {
                "total": 0, "success": 0, "ok": 0, "failed": 0, "cn_success": 0, "cn_total": 3,
                "cn_avg_ms": None, "cnAverageMs": None, "global_avg_ms": None, "globalAverageMs": None,
                "min_ms": None, "max_ms": None, "cn_telecom_ms": None, "cnTelecomMs": None,
                "cn_unicom_ms": None, "cnUnicomMs": None, "cn_mobile_ms": None, "cnMobileMs": None,
            },
            "results": [],
            "checked_at": int(time.time()),
        }

    raw_results = m_data.get("results", [])
    region_results = []
    matched = set()
    is_ping = (effective_proto == "PING")

    for item in active_regions:
        # Match from raw results
        matched_res = None
        for r in raw_results:
            p_id = f"{r.get('probe', {}).get('asn')}_{r.get('probe', {}).get('country')}"
            if p_id in matched:
                continue
            probe = r.get("probe", {})
            if item.get("asn") and probe.get("asn") == item["asn"]:
                matched_res = r
                matched.add(p_id)
                break
            if item.get("city") and probe.get("city") == item["city"]:
                matched_res = r
                matched.add(p_id)
                break
            if item.get("country") and probe.get("country") == item["country"]:
                matched_res = r
                matched.add(p_id)
                break

        res_obj = matched_res.get("result", {}) if matched_res else {}

        if is_ping:
            # Parse Globalping ping probe
            ping_stats = res_obj.get("stats") or {}
            raw_output = str(res_obj.get("rawOutput") or "")
            loss = ping_stats.get("loss", 100)
            rcv = ping_stats.get("rcv", 0)
            avg_ms = ping_stats.get("avg")

            if (rcv > 0 or loss < 100) and avg_ms is not None:
                status = "ok"
                latency = round(float(avg_ms), 1)
                err_msg = ""
            elif "100% packet loss" in raw_output or loss == 100 or rcv == 0:
                status = "timeout"
                latency = 0
                err_msg = "Ping 超时 (100% Packet Loss)"
            else:
                status = "failed"
                latency = 0
                err_msg = raw_output[:120] if raw_output else "Ping 探测失败"

            tcp_ms = latency if status == "ok" else None
            dns_ms = None
            tls_ms = None
            ttfb_ms = latency if status == "ok" else None
            total_ms = latency
        else:
            # Parse Globalping http/tcp probe
            timings = res_obj.get("timings") or {}
            raw_output = str(res_obj.get("rawOutput") or "")
            tcp_ms = timings.get("tcp")
            total_ms = timings.get("total") or 0
            dns_ms = timings.get("dns")
            tls_ms = timings.get("tls")
            ttfb_ms = timings.get("firstByte")

            if tcp_ms is not None and tcp_ms >= 0:
                status = "ok"
                latency = tcp_ms
                err_msg = ""
            elif res_obj.get("statusCode") is not None:
                status = "ok"
                latency = total_ms
                err_msg = ""
            elif "timed out" in raw_output.lower():
                status = "timeout"
                latency = 0
                err_msg = "连接超时 (TCP Timeout)"
            elif "refused" in raw_output.lower():
                status = "refused"
                latency = 0
                err_msg = "端口拒绝 (Connection Refused)"
            else:
                status = "failed"
                latency = 0
                err_msg = raw_output[:120] if raw_output else "连接未完成"

        region_results.append({
            "region": item,
            "status": status,
            "timings": {
                "tcp": tcp_ms,
                "dns": dns_ms,
                "tls": tls_ms,
                "ttfb": ttfb_ms,
                "total": latency or total_ms,
            },
            "error": err_msg,
            "checkedAt": int(time.time()),
        })

    # Stats computation
    ok_results = [r for r in region_results if r["status"] == "ok"]
    cn_ok = [r for r in ok_results if r["region"]["group"] == "cn"]
    cn_total = 3
    cn_avg = round(sum(r["timings"]["total"] for r in cn_ok) / len(cn_ok), 1) if cn_ok else None
    global_avg = round(sum(r["timings"]["total"] for r in ok_results) / len(ok_results), 1) if ok_results else None
    latencies = [r["timings"]["total"] for r in ok_results if r["timings"]["total"] > 0]
    min_lat = min(latencies) if latencies else None
    max_lat = max(latencies) if latencies else None

    # Carrier specific breakdown
    cn_telecom = next((r for r in region_results if r["region"]["id"] == "cn-telecom" and r["status"] == "ok"), None)
    cn_unicom = next((r for r in region_results if r["region"]["id"] == "cn-unicom" and r["status"] == "ok"), None)
    cn_mobile = next((r for r in region_results if r["region"]["id"] == "cn-mobile" and r["status"] == "ok"), None)

    cn_telecom_ms = cn_telecom["timings"]["total"] if cn_telecom else None
    cn_unicom_ms = cn_unicom["timings"]["total"] if cn_unicom else None
    cn_mobile_ms = cn_mobile["timings"]["total"] if cn_mobile else None

    # Verdict diagnosis
    total_count = len(region_results)
    success_count = len(ok_results)
    cn_success_count = len(cn_ok)

    proto_label = "Ping" if is_ping else "TCP"
    if total_count <= 8:
        # Budget mode (8 core regions, 5 dual-stack V4 regions, or 3 V6 regions)
        if success_count == 0:
            verdict = "timeout"
            verdict_label = "全网连接超时/端口未放行"
            verdict_desc = f"所有已测探针均无法建立 {proto_label} 握手，请检查防火墙或服务监听状态。"
        elif cn_success_count == 3 and success_count == total_count:
            verdict = "ok"
            verdict_label = "三网通畅" if total_count == 3 else "三网通畅·核心可达"
            verdict_desc = f"中国电信、联通、移动及已测核心区域均可顺畅建立 {proto_label} 连接。"
        elif cn_success_count == 3 and success_count >= total_count - 1:
            verdict = "ok"
            verdict_label = "三网通畅·海外良好"
            verdict_desc = f"中国三大运营商均通畅，绝大部分已测区域可建立 {proto_label} 连接。"
        elif cn_success_count == 0 and success_count >= 2:
            verdict = "gfw_blocked"
            verdict_label = "国内受阻·疑似GFW阻断"
            verdict_desc = f"海外节点通畅，但中国大陆三大运营商探针均连接超时或握手被中断。"
        elif cn_success_count >= 1 and (total_count > 3 and success_count < 3):
            verdict = "cn_only"
            verdict_label = "仅国内可达·海外受阻"
            verdict_desc = "国内部分可连，但海外主要区域无法访问，疑似配置了海外 IP 白名单或境外出口丢包。"
        else:
            verdict = "partial"
            verdict_label = "部分区域受阻"
            verdict_desc = f"{success_count}/{total_count} 个区域可达，部分运营商或地区连接异常。"
    else:
        # Full 18-region check (with API key or full quota)
        if cn_success_count == 3 and success_count >= 14:
            verdict = "ok"
            verdict_label = "三网通畅·全球可达"
            verdict_desc = f"中国电信、联通、移动及全球各主要区域均可顺畅建立 {proto_label} 连接。"
        elif cn_success_count == 0 and success_count >= 8:
            verdict = "gfw_blocked"
            verdict_label = "国内受阻·疑似GFW阻断"
            verdict_desc = f"海外节点完全通畅，但中国大陆三大运营商探针均连接超时或握手被中断。"
        elif cn_success_count >= 1 and success_count < 6:
            verdict = "cn_only"
            verdict_label = "仅国内可达·海外受阻"
            verdict_desc = "国内部分或全部可连，但大部分海外区域无法访问，疑似配置了海外 IP 白名单或境外出口丢包。"
        elif success_count == 0:
            verdict = "timeout"
            verdict_label = "全网连接超时/端口未放行"
            verdict_desc = f"所有探针均无法建立 {proto_label} 握手，请检查防火墙或服务监听状态。"
        else:
            verdict = "partial"
            verdict_label = "部分区域受阻"
            verdict_desc = f"{success_count}/{total_count} 个区域可达，部分运营商或地区连接异常。"

    effective_proto = "PING" if is_ping else "TCP"
    stats = {
        "total": total_count,
        "success": success_count,
        "ok": success_count,
        "failed": total_count - success_count,
        "cn_success": cn_success_count,
        "cn_total": cn_total,
        "cn_avg_ms": cn_avg,
        "cnAverageMs": cn_avg,
        "global_avg_ms": global_avg,
        "globalAverageMs": global_avg,
        "min_ms": min_lat,
        "max_ms": max_lat,
        "cn_telecom_ms": cn_telecom_ms,
        "cnTelecomMs": cn_telecom_ms,
        "cn_unicom_ms": cn_unicom_ms,
        "cnUnicomMs": cn_unicom_ms,
        "cn_mobile_ms": cn_mobile_ms,
        "cnMobileMs": cn_mobile_ms,
    }

    return {
        "target": target,
        "port": port,
        "protocol": effective_proto,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "verdict_desc": verdict_desc,
        "stats": stats,
        "results": region_results,
        "checked_at": int(time.time()),
    }


def notify_reachability_state_change(conn: sqlite3.Connection, host_id: str, new_verdict: str, verdict_label: str, target: str, port: int, protocol: str, prev_verdict: str | None = None) -> None:
    """Send Telegram alert or recovery notice when reachability state transitions."""
    is_anomaly = new_verdict in ("blocked", "timeout")
    is_recovery = prev_verdict in ("blocked", "timeout") and new_verdict in ("ok", "partial")
    if not is_anomaly and not is_recovery:
        return
    try:
        bots = conn.execute("SELECT * FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
        if not bots:
            return
        import html
        from server.app import _telegram_api, _parse_telegram_target
        if is_anomaly:
            msg = (
                f"<b>🚨 母机网络可达性异常告警</b>\n\n"
                f"<b>母机:</b> <code>{html.escape(host_id)}</code>\n"
                f"<b>目标:</b> <code>{html.escape(target)}:{port} ({protocol})</code>\n"
                f"<b>判定:</b> <b>{html.escape(verdict_label)}</b>\n"
                f"<b>说明:</b> 国内三大运营商检测连接超时或握手被中断，请排查线路或端口放行。"
            )
        else:
            msg = (
                f"<b>✅ 母机网络可达性已恢复正常</b>\n\n"
                f"<b>母机:</b> <code>{html.escape(host_id)}</code>\n"
                f"<b>目标:</b> <code>{html.escape(target)}:{port} ({protocol})</code>\n"
                f"<b>判定:</b> <b>{html.escape(verdict_label)}</b>\n"
                f"<b>说明:</b> 经自动化探测验证，节点三网连通性与握手已恢复通畅。"
            )

        for bot in bots:
            try:
                chat_target, thread_id = _parse_telegram_target(str(bot["target"] or ""))
                payload = {"chat_id": chat_target, "text": msg, "parse_mode": "HTML"}
                if thread_id is not None:
                    payload["message_thread_id"] = thread_id
                _telegram_api(str(bot["token"]), "sendMessage", payload)
            except Exception as e:
                logger.warning(f"Failed to deliver reachability telegram alert via bot {bot['id']}: {e}")
    except Exception as exc:
        logger.warning(f"Reachability notification processing failed: {exc}")


def perform_host_reach_check(conn: sqlite3.Connection, host_id: str) -> Optional[Dict[str, Any]]:
    """Runs reachability check for a single host. Supports IPv4, IPv6, and dual-stack
    machines with intelligent token budgeting to prevent quota exhaustion.
    """
    targets = discover_host_targets(conn, host_id)
    target_v4 = targets.get("ipv4") or ""
    target_v6 = targets.get("ipv6") or ""

    if not target_v4 and not target_v6:
        logger.info(f"Skipping reach check for {host_id}: no public target discovered")
        return None

    open_ports = discover_host_open_ports(conn, host_id)
    if open_ports:
        port = choose_random_port(open_ports)
        protocol = "TCP"
    else:
        port = 0
        protocol = "PING"

    api_key = get_globalping_api_key(conn)
    is_dual = bool(target_v4 and target_v6)

    # Token budgeting for dual-stack vs single-stack
    if is_dual:
        if api_key:
            v4_regions = REACH_REGIONS
            v6_regions = REACH_REGIONS
        elif _rate_limit_state.get("remaining", 250) < 6:
            # Low budget fallback: 3 for V4, 3 for V6 (or skip V6 if < 3)
            v4_regions = [r for r in REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile"}]
            v6_regions = [r for r in REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile"}] if _rate_limit_state.get("remaining", 250) >= 6 else []
        else:
            # Optimized token budget: V4 gets 5 points (China 3 + HK + US), V6 gets 3 points (China 3)
            # Total consumption = 5 + 3 = 8 credits per host (strictly <= 250 credits/hr across 28 cluster hosts)
            v4_regions = [r for r in REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile", "apac-hk", "am-us-la"}]
            v6_regions = [r for r in REACH_REGIONS if r["id"] in {"cn-telecom", "cn-unicom", "cn-mobile"}]
    else:
        v4_regions = None
        v6_regions = None

    primary_target = target_v4 or target_v6
    logger.info(f"Running automated reach check for {host_id} (dual={is_dual}, v4={target_v4!r}, v6={target_v6!r}) -> {primary_target}:{port} ({protocol})")

    try:
        # 1. Primary measurement (IPv4 if dual or single V4; or IPv6 if single V6)
        m_v4_data = execute_globalping_measurement(
            primary_target, port, protocol, regions=v4_regions if is_dual else None, api_key=api_key, conn=conn
        )

        # Rate-limiting / Quota exhausted handling:
        # CRITICAL: Preserve existing healthy host reachability records and avoid overwriting with blank/empty data!
        if m_v4_data.get("status") == "rate_limited":
            logger.warning(f"Host {host_id} reach check rate limited; preserving historical records without overwriting")
            existing = conn.execute(
                "SELECT host_id, verdict_label, results_json FROM host_reachability WHERE host_id=?",
                (host_id,),
            ).fetchone()
            # Only create an entry if host has never had any reachability record or existing was already rate_limited
            if not existing or existing["results_json"] in ("[]", ""):
                summary = parse_measurement_results(m_v4_data, primary_target, port, protocol, regions=v4_regions)
                now = int(time.time())
                conn.execute("""
                    INSERT INTO host_reachability(host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(host_id) DO UPDATE SET
                        verdict=excluded.verdict, verdict_label=excluded.verdict_label,
                        verdict_desc=excluded.verdict_desc, checked_at=excluded.checked_at
                """, (
                    host_id, primary_target, port, summary["protocol"], summary["verdict"], summary["verdict_label"],
                    summary["verdict_desc"], json.dumps(summary["stats"]), json.dumps(summary["results"]), now
                ))
                conn.commit()
            return None

        summary_v4 = parse_measurement_results(m_v4_data, primary_target, port, protocol, regions=v4_regions)
        now = int(time.time())

        # Smart ICMP ping fallback: if chosen TCP port failed all probes, verify if host is alive via ICMP
        if summary_v4.get("stats", {}).get("success", 0) == 0 and protocol == "TCP":
            logger.info(f"Host {host_id} TCP port {port} unreachable; attempting ICMP ping fallback on {primary_target}...")
            try:
                m_ping_data = execute_globalping_measurement(
                    primary_target, 0, "PING", regions=v4_regions if is_dual else None, api_key=api_key, conn=conn
                )
                if m_ping_data.get("status") != "rate_limited":
                    summary_ping = parse_measurement_results(m_ping_data, primary_target, 0, "PING", regions=v4_regions)
                    if summary_ping.get("stats", {}).get("success", 0) > 0:
                        logger.info(f"Host {host_id} ICMP ping fallback succeeded: verdict={summary_ping['verdict_label']}")
                        summary_v4 = summary_ping
                        port = 0
                        protocol = "PING"
            except Exception as ping_err:
                logger.warning(f"ICMP fallback failed for {host_id}: {ping_err}")

        # 2. Secondary measurement for IPv6 if dual-stack
        summary_v6: Optional[Dict[str, Any]] = None
        if is_dual and v6_regions and target_v6:
            try:
                m_v6_data = execute_globalping_measurement(
                    target_v6, port, protocol, regions=v6_regions, api_key=api_key, conn=conn
                )
                if m_v6_data.get("status") != "rate_limited":
                    summary_v6 = parse_measurement_results(m_v6_data, target_v6, port, protocol, regions=v6_regions)
                    # ICMP ping fallback for IPv6 if TCP failed completely
                    if summary_v6.get("stats", {}).get("success", 0) == 0 and protocol == "TCP":
                        try:
                            m_v6_ping = execute_globalping_measurement(
                                target_v6, 0, "PING", regions=v6_regions, api_key=api_key, conn=conn
                            )
                            if m_v6_ping.get("status") != "rate_limited":
                                summary_v6_ping = parse_measurement_results(m_v6_ping, target_v6, 0, "PING", regions=v6_regions)
                                if summary_v6_ping.get("stats", {}).get("success", 0) > 0:
                                    summary_v6 = summary_v6_ping
                        except Exception:
                            pass
                else:
                    logger.warning(f"Host {host_id} IPv6 reach check rate limited; retaining existing IPv6 record")
            except Exception as e:
                logger.warning(f"Host {host_id} IPv6 check failed: {e}")

        # Retrieve previous records to safely preserve v6 if secondary was rate-limited or failed
        target_v6_val = target_v6 if is_dual else ""
        port_v6_val = port if summary_v6 else 0
        proto_v6_val = summary_v6["protocol"] if summary_v6 else "TCP"
        verdict_v6_val = summary_v6["verdict"] if summary_v6 else ""
        verdict_label_v6_val = summary_v6["verdict_label"] if summary_v6 else ""
        verdict_desc_v6_val = summary_v6["verdict_desc"] if summary_v6 else ""
        stats_v6_json = json.dumps(summary_v6["stats"]) if summary_v6 else "{}"
        results_v6_json = json.dumps(summary_v6["results"]) if summary_v6 else "[]"
        checked_at_v6_val = now if summary_v6 else 0

        if not summary_v6 and is_dual:
            prev = conn.execute(
                "SELECT target_v6, port_v6, protocol_v6, verdict_v6, verdict_label_v6, verdict_desc_v6, stats_json_v6, results_json_v6, checked_at_v6 "
                "FROM host_reachability WHERE host_id=?",
                (host_id,),
            ).fetchone()
            if prev and prev["target_v6"]:
                target_v6_val = prev["target_v6"]
                port_v6_val = prev["port_v6"]
                proto_v6_val = prev["protocol_v6"]
                verdict_v6_val = prev["verdict_v6"]
                verdict_label_v6_val = prev["verdict_label_v6"]
                verdict_desc_v6_val = prev["verdict_desc_v6"]
                stats_v6_json = prev["stats_json_v6"]
                results_v6_json = prev["results_json_v6"]
                checked_at_v6_val = prev["checked_at_v6"]

        prev_reach_row = conn.execute("SELECT verdict FROM host_reachability WHERE host_id=?", (host_id,)).fetchone()
        prev_v_val = prev_reach_row["verdict"] if prev_reach_row else None

        conn.execute("""
            INSERT INTO host_reachability(
                host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at,
                target_v6, port_v6, protocol_v6, verdict_v6, verdict_label_v6, verdict_desc_v6, stats_json_v6, results_json_v6, checked_at_v6
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                target=excluded.target, port=excluded.port, protocol=excluded.protocol,
                verdict=excluded.verdict, verdict_label=excluded.verdict_label, verdict_desc=excluded.verdict_desc,
                stats_json=excluded.stats_json, results_json=excluded.results_json, checked_at=excluded.checked_at,
                target_v6=excluded.target_v6, port_v6=excluded.port_v6, protocol_v6=excluded.protocol_v6,
                verdict_v6=excluded.verdict_v6, verdict_label_v6=excluded.verdict_label_v6, verdict_desc=excluded.verdict_desc,
                stats_json_v6=excluded.stats_json_v6, results_json=excluded.results_json_v6, checked_at_v6=excluded.checked_at_v6
        """, (
            host_id, primary_target, port, summary_v4["protocol"], summary_v4["verdict"], summary_v4["verdict_label"],
            summary_v4["verdict_desc"], json.dumps(summary_v4["stats"]), json.dumps(summary_v4["results"]), now,
            target_v6_val, port_v6_val, proto_v6_val, verdict_v6_val, verdict_label_v6_val, verdict_desc_v6_val,
            stats_v6_json, results_v6_json, checked_at_v6_val
        ))

        conn.execute("""
            INSERT INTO host_reachability_history(
                host_id, target, port, protocol, verdict, stats_json, checked_at,
                target_v6, port_v6, protocol_v6, verdict_v6, stats_json_v6, checked_at_v6
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host_id, primary_target, port, summary_v4["protocol"], summary_v4["verdict"], json.dumps(summary_v4["stats"]), now,
            target_v6_val, port_v6_val, proto_v6_val, verdict_v6_val, stats_v6_json, checked_at_v6_val
        ))
        conn.commit()
        if prev_v_val != summary_v4["verdict"]:
            notify_reachability_state_change(
                conn, host_id, summary_v4["verdict"], summary_v4["verdict_label"],
                primary_target, port, summary_v4["protocol"], prev_v_val
            )

        combined = dict(summary_v4)
        combined["is_dual_stack"] = is_dual
        combined["has_ipv6"] = bool(target_v6_val)
        combined["target_v6"] = target_v6_val
        combined["port_v6"] = port_v6_val
        combined["protocol_v6"] = proto_v6_val
        combined["verdict_v6"] = verdict_v6_val
        combined["verdict_label_v6"] = verdict_label_v6_val
        combined["verdict_desc_v6"] = verdict_desc_v6_val
        combined["stats_v6"] = json.loads(stats_v6_json) if stats_v6_json else {}
        combined["results_v6"] = json.loads(results_v6_json) if results_v6_json else []
        combined["checked_at_v6"] = checked_at_v6_val
        combined["checked_at_iso_utc8"] = format_utc8(now)
        combined["checked_at_v6_iso_utc8"] = format_utc8(checked_at_v6_val)
        return combined
    except Exception as e:
        logger.error(f"Failed automated reach check for {host_id} ({primary_target}:{port} {protocol}): {e}")
        return None


async def run_hourly_reach_cycle(
    db_factory: Callable[[], sqlite3.Connection],
    pace_seconds_override: Optional[float] = None,
) -> int:
    """Executes reachability checks across active cluster nodes in an intelligently staggered schedule."""
    conn = db_factory()
    try:
        init_db(conn)
        now = int(time.time())
        api_key = get_globalping_api_key(conn)
        sync_rate_limits(api_key)

        # Query active hosts from last 30 minutes, ordered by least-recently-checked first (LRU priority)
        query = """
            SELECT h.host_id, COALESCE(hr.checked_at, 0) as last_checked
            FROM hosts h
            LEFT JOIN host_reachability hr ON h.host_id = hr.host_id
            WHERE h.last_seen > ?
            ORDER BY last_checked ASC, h.host_id ASC
        """
        rows = conn.execute(query, (now - 1800,)).fetchall()
        hosts = [r["host_id"] for r in rows]
    finally:
        conn.close()

    if not hosts:
        logger.info("No active hosts found for automated reach check")
        return 0

    # Staggered pacing: evenly distribute hosts across 3600 seconds
    # e.g., 28 hosts -> 3600 / 28 = 128 seconds interval
    if pace_seconds_override is not None:
        pace_seconds = pace_seconds_override
    else:
        pace_seconds = max(10.0, min(180.0, 3600.0 / max(1, len(hosts))))
    _rate_limit_state["pacing_seconds"] = int(pace_seconds)

    def _worker_check(db_f: Callable[[], sqlite3.Connection], h_id: str) -> Optional[Dict[str, Any]]:
        c = db_f()
        try:
            return perform_host_reach_check(c, h_id)
        finally:
            c.close()

    checked = 0
    for host_id in hosts:
        # If rate limited, sleep until reset
        if _rate_limit_state.get("is_rate_limited") or _rate_limit_state.get("remaining", 250) < 3:
            reset_wait = max(5, min(3600, int(_rate_limit_state.get("reset_seconds", 300))))
            logger.info(f"Reachability cycle paused due to quota limit. Sleeping {reset_wait}s until reset.")
            await asyncio.sleep(reset_wait)
            # Resync limits after sleep
            sync_rate_limits(api_key, force=True)
            if _rate_limit_state.get("remaining", 0) < 3:
                logger.warning("Quota still below minimum after reset wait; skipping remaining cycle hosts.")
                break

        try:
            res = await asyncio.to_thread(_worker_check, db_factory, host_id)
            if res:
                checked += 1
        except Exception as e:
            logger.error(f"Error in reach check cycle for {host_id}: {e}")

        # Paced interval between hosts to prevent burst quota consumption
        await asyncio.sleep(pace_seconds)

    return checked


async def run_loop(db_factory: Callable[[], sqlite3.Connection]) -> None:
    """Continuous background loop for cluster reachability scheduling."""
    await asyncio.sleep(45)  # Initial grace window after server startup
    while True:
        cycle_start = time.monotonic()
        try:
            logger.info("Starting cluster automated reach check cycle (staggered pacing)...")
            checked = await run_hourly_reach_cycle(db_factory)
            logger.info(f"Finished automated reach check cycle: {checked} hosts inspected")
        except Exception as e:
            logger.error(f"Automated reach check cycle crashed: {e}")

        elapsed = time.monotonic() - cycle_start
        sleep_time = max(15.0, 3600.0 - elapsed)
        await asyncio.sleep(sleep_time)


def _get_quota_payload(conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
    api_key = get_globalping_api_key(conn)
    reset_sec = max(0, int(_rate_limit_state.get("reset_seconds", 0)))
    return {
        "remaining": int(_rate_limit_state.get("remaining", 250)),
        "limit": int(_rate_limit_state.get("limit", 250)),
        "reset_seconds": reset_sec,
        "is_rate_limited": bool(_rate_limit_state.get("is_rate_limited", False)),
        "api_key_configured": bool(api_key),
        "pacing_seconds": int(_rate_limit_state.get("pacing_seconds", 128)),
        "dual_stack_budget": "IPv4 5探针 + IPv6 3探针 = 8点/台 (28台集群稳定消耗 224点/小时)",
    }


def attach(app: FastAPI, db_factory: Callable[[], sqlite3.Connection], verify_signature: Any, signed_json_response: Any) -> None:
    """Attaches reachability endpoints to the FastAPI server."""

    @app.get("/api/v1/reachability/summary")
    def get_reachability_summary(request: Request) -> JSONResponse:
        conn = db_factory()
        try:
            init_db(conn)
            now = int(time.time())
            total_active_row = conn.execute("SELECT count(*) FROM hosts WHERE last_seen > ?", (now - 1800,)).fetchone()
            total_active = total_active_row[0] if total_active_row else 0

            # Batch extract trend points for sparklines (up to 24 per host)
            history_by_host: dict[str, list[dict[str, Any]]] = {}
            for h in conn.execute(
                "SELECT host_id, verdict, stats_json, checked_at "
                "FROM host_reachability_history ORDER BY checked_at ASC"
            ).fetchall():
                hid = h["host_id"]
                if hid not in history_by_host:
                    history_by_host[hid] = []
                try:
                    st_data = json.loads(h["stats_json"] or "{}")
                except Exception:
                    st_data = {}
                cn_ms = st_data.get("cn_avg") or st_data.get("cnAvg")
                gl_ms = st_data.get("global_avg") or st_data.get("globalAvg")
                history_by_host[hid].append({
                    "ts": int(h["checked_at"] or 0),
                    "verdict": h["verdict"],
                    "cn_ms": round(float(cn_ms), 1) if cn_ms is not None else None,
                    "global_ms": round(float(gl_ms), 1) if gl_ms is not None else None,
                })
                if len(history_by_host[hid]) > 24:
                    history_by_host[hid].pop(0)

            rows = conn.execute("SELECT * FROM host_reachability ORDER BY checked_at DESC").fetchall()
            items = []
            max_checked = 0
            ok_count = 0
            blocked_count = 0
            is_auth = bool(getattr(request.state, "dashboard_user", None))

            for r in rows:
                checked_at = int(r["checked_at"] or 0)
                if checked_at > max_checked:
                    max_checked = checked_at
                verdict = str(r["verdict"] or "")
                if verdict == "ok":
                    ok_count += 1
                elif verdict in ("gfw_blocked", "timeout", "partial"):
                    blocked_count += 1

                try:
                    stats = json.loads(r["stats_json"] or "{}")
                    results = json.loads(r["results_json"] or "[]")
                except Exception:
                    stats, results = {}, []

                target_v6_raw = str(r["target_v6"] or "") if "target_v6" in r.keys() else ""
                stats_v6_raw = str(r["stats_json_v6"] or "{}") if "stats_json_v6" in r.keys() else "{}"
                results_v6_raw = str(r["results_json_v6"] or "[]") if "results_json_v6" in r.keys() else "[]"
                try:
                    stats_v6 = json.loads(stats_v6_raw or "{}")
                    results_v6 = json.loads(results_v6_raw or "[]")
                except Exception:
                    stats_v6, results_v6 = {}, []

                # IP masking for unauthenticated public visitors
                target_val = r["target"]
                target_v6_val = target_v6_raw
                if not is_auth:
                    target_val = ""
                    target_v6_val = ""
                    for res_item in results:
                        if isinstance(res_item, dict) and "ip" in res_item:
                            res_item["ip"] = ""
                    for res_item in results_v6:
                        if isinstance(res_item, dict) and "ip" in res_item:
                            res_item["ip"] = ""

                has_v6 = bool(target_v6_raw)
                has_v4 = bool(r["target"])
                is_dual = bool(has_v4 and has_v6)

                items.append({
                    "host_id": r["host_id"],
                    "target": target_val,
                    "port": r["port"],
                    "protocol": r["protocol"],
                    "verdict": verdict,
                    "verdict_label": r["verdict_label"],
                    "verdict_desc": r["verdict_desc"],
                    "stats": stats,
                    "results": results,
                    "checked_at": checked_at,
                    "checked_at_iso_utc8": format_utc8(checked_at),
                    "is_dual_stack": is_dual,
                    "has_ipv6": has_v6,
                    "target_v6": target_v6_val,
                    "port_v6": int(r["port_v6"] or 0) if "port_v6" in r.keys() else 0,
                    "protocol_v6": str(r["protocol_v6"] or "TCP") if "protocol_v6" in r.keys() else "TCP",
                    "verdict_v6": str(r["verdict_v6"] or "") if "verdict_v6" in r.keys() else "",
                    "verdict_label_v6": str(r["verdict_label_v6"] or "") if "verdict_label_v6" in r.keys() else "",
                    "verdict_desc_v6": str(r["verdict_desc_v6"] or "") if "verdict_desc_v6" in r.keys() else "",
                    "stats_v6": stats_v6,
                    "results_v6": results_v6,
                    "checked_at_v6": int(r["checked_at_v6"] or 0) if "checked_at_v6" in r.keys() else 0,
                    "checked_at_v6_iso_utc8": format_utc8(int(r["checked_at_v6"] or 0) if "checked_at_v6" in r.keys() else 0),
                    "trend_24h": history_by_host.get(r["host_id"], []),
                })

            return JSONResponse(content={
                "items": items,
                "total_hosts": total_active or len(items),
                "checked_hosts": len(items),
                "ok_hosts": ok_count,
                "blocked_hosts": blocked_count,
                "checked_at": max_checked,
                "last_checked": max_checked,
                "quota": _get_quota_payload(conn),
            })
        finally:
            conn.close()

    @app.get("/api/v1/reachability/quota")
    def get_reachability_quota(request: Request) -> JSONResponse:
        conn = db_factory()
        try:
            init_db(conn)
            return JSONResponse(content=_get_quota_payload(conn))
        finally:
            conn.close()

    @app.post("/api/v1/reachability/settings")
    async def save_reachability_settings(request: Request) -> JSONResponse:
        if not getattr(request.state, "dashboard_user", None):
            raise HTTPException(status_code=401, detail="请登录后再修改配置")
        conn = db_factory()
        try:
            init_db(conn)
            data = {}
            try:
                data = await request.json()
            except Exception:
                pass
            api_key = str(data.get("globalping_api_key") or data.get("api_key") or "").strip()
            now = int(time.time())
            if api_key:
                conn.execute(
                    "INSERT INTO system_settings(key, value, updated_at) VALUES('globalping_api_key', ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    (api_key, now),
                )
            else:
                conn.execute("DELETE FROM system_settings WHERE key = 'globalping_api_key'")
            conn.commit()
            sync_rate_limits(api_key, force=True)
            return JSONResponse(content={
                "ok": True,
                "message": "Globalping API Key 配置已成功更新并同步配额",
                "quota": _get_quota_payload(conn),
            })
        finally:
            conn.close()

    @app.get("/api/v1/reachability/host/{host_id}")
    def get_reachability_host(host_id: str, request: Request) -> JSONResponse:
        conn = db_factory()
        try:
            init_db(conn)
            r = conn.execute("SELECT * FROM host_reachability WHERE host_id=?", (host_id,)).fetchone()
            if not r:
                raise HTTPException(status_code=404, detail="Host reachability result not found")
            try:
                stats = json.loads(r["stats_json"] or "{}")
                results = json.loads(r["results_json"] or "[]")
            except Exception:
                stats, results = {}, []

            target_v6_raw = str(r["target_v6"] or "") if "target_v6" in r.keys() else ""
            stats_v6_raw = str(r["stats_json_v6"] or "{}") if "stats_json_v6" in r.keys() else "{}"
            results_v6_raw = str(r["results_json_v6"] or "[]") if "results_json_v6" in r.keys() else "[]"
            try:
                stats_v6 = json.loads(stats_v6_raw or "{}")
                results_v6 = json.loads(results_v6_raw or "[]")
            except Exception:
                stats_v6, results_v6 = {}, []

            is_auth = bool(getattr(request.state, "dashboard_user", None))
            target_val = r["target"] if is_auth else ""
            target_v6_val = target_v6_raw if is_auth else ""
            if not is_auth:
                for res_item in results:
                    if isinstance(res_item, dict) and "ip" in res_item:
                        res_item["ip"] = ""
                for res_item in results_v6:
                    if isinstance(res_item, dict) and "ip" in res_item:
                        res_item["ip"] = ""

            has_v6 = bool(target_v6_raw)
            has_v4 = bool(r["target"])
            is_dual = bool(has_v4 and has_v6)

            item = {
                "host_id": r["host_id"],
                "target": target_val,
                "port": r["port"],
                "protocol": r["protocol"],
                "verdict": r["verdict"],
                "verdict_label": r["verdict_label"],
                "verdict_desc": r["verdict_desc"],
                "stats": stats,
                "results": results,
                "checked_at": int(r["checked_at"] or 0),
                "checked_at_iso_utc8": format_utc8(int(r["checked_at"] or 0)),
                "is_dual_stack": is_dual,
                "has_ipv6": has_v6,
                "target_v6": target_v6_val,
                "port_v6": int(r["port_v6"] or 0) if "port_v6" in r.keys() else 0,
                "protocol_v6": str(r["protocol_v6"] or "TCP") if "protocol_v6" in r.keys() else "TCP",
                "verdict_v6": str(r["verdict_v6"] or "") if "verdict_v6" in r.keys() else "",
                "verdict_label_v6": str(r["verdict_label_v6"] or "") if "verdict_label_v6" in r.keys() else "",
                "verdict_desc_v6": str(r["verdict_desc_v6"] or "") if "verdict_desc_v6" in r.keys() else "",
                "stats_v6": stats_v6,
                "results_v6": results_v6,
                "checked_at_v6": int(r["checked_at_v6"] or 0) if "checked_at_v6" in r.keys() else 0,
                "checked_at_v6_iso_utc8": format_utc8(int(r["checked_at_v6"] or 0) if "checked_at_v6" in r.keys() else 0),
            }
            hist_rows = conn.execute(
                "SELECT verdict, stats_json, checked_at "
                "FROM host_reachability_history WHERE host_id=? ORDER BY checked_at ASC LIMIT 48",
                (host_id,)
            ).fetchall()
            trend_24h = []
            for h in hist_rows:
                try:
                    st_data = json.loads(h["stats_json"] or "{}")
                except Exception:
                    st_data = {}
                cn_ms = st_data.get("cn_avg") or st_data.get("cnAvg")
                gl_ms = st_data.get("global_avg") or st_data.get("globalAvg")
                trend_24h.append({
                    "ts": int(h["checked_at"] or 0),
                    "verdict": h["verdict"],
                    "cn_ms": round(float(cn_ms), 1) if cn_ms is not None else None,
                    "global_ms": round(float(gl_ms), 1) if gl_ms is not None else None,
                })
            item["trend_24h"] = trend_24h
            return JSONResponse(content={"item": item, **item})
        finally:
            conn.close()

    @app.post("/api/v1/reachability/trigger")
    async def trigger_reachability_check(request: Request) -> JSONResponse:
        if not getattr(request.state, "dashboard_user", None):
            raise HTTPException(status_code=401, detail="请登录后再触发测试")
        conn = db_factory()
        try:
            init_db(conn)
            data = {}
            try:
                data = await request.json()
            except Exception:
                pass
            host_id = str(data.get("host_id") or "").strip()
            if host_id:
                def _worker_single():
                    c = db_factory()
                    try:
                        return perform_host_reach_check(c, host_id)
                    finally:
                        c.close()
                res = await asyncio.to_thread(_worker_single)
                return JSONResponse(content={"ok": True, "message": f"主机 {host_id} 可达性测试已完成", "item": res})
            else:
                asyncio.create_task(run_hourly_reach_cycle(db_factory))
                return JSONResponse(content={"ok": True, "message": "全集群可达性自动化巡检已在后台启动（平滑时序调度）"})
        finally:
            conn.close()
