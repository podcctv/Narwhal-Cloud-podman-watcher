import asyncio
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
        checked_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS host_reachability_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id TEXT NOT NULL,
        target TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        verdict TEXT NOT NULL,
        stats_json TEXT NOT NULL DEFAULT '{}',
        checked_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_reach_hist_host ON host_reachability_history(host_id, checked_at);
    CREATE TABLE IF NOT EXISTS host_client_ips (
        host_id TEXT PRIMARY KEY,
        client_ip TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL DEFAULT 0
    );
    """)


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


def is_public_ip(ip_str: str) -> bool:
    """SSRF & Bogon protection: ensures target is not RFC 1918, CGNAT, loopback, link-local, multicast."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean = ip_str.split("/")[0].strip()
    try:
        ip = ipaddress.ip_address(clean)
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


def discover_host_target(conn: sqlite3.Connection, host_id: str) -> str:
    """Finds a verified public IPv4 / IPv6 address or domain name for the host."""
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
                for addr in iface.get("addresses", []):
                    clean_ip = str(addr or "").split("/")[0].strip()
                    if is_public_ip(clean_ip) and "." in clean_ip:
                        return clean_ip
                for addr in iface.get("addresses", []):
                    clean_ip = str(addr or "").split("/")[0].strip()
                    if is_public_ip(clean_ip):
                        return clean_ip
        except Exception:
            pass

    # 2. From reports network_addresses
    rep = conn.execute(
        "SELECT payload_json FROM reports WHERE host_id=? ORDER BY ts DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    if rep:
        try:
            p = json.loads(rep["payload_json"])
            for addr in p.get("network_addresses", []) or []:
                clean_ip = str(addr or "").split("/")[0].strip()
                if is_public_ip(clean_ip) and "." in clean_ip:
                    return clean_ip
                if is_public_ip(clean_ip):
                    return clean_ip
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
                tip = str(t.get("ip") or "").strip()
                if is_public_ip(tip):
                    return tip
            for bek in gp.get("blocked_endpoint_keys", []) or []:
                if bek and is_public_ip(str(bek[0])):
                    return str(bek[0])
        except Exception:
            pass

    # 4. From host_client_ips
    try:
        cip = conn.execute("SELECT client_ip FROM host_client_ips WHERE host_id=?", (host_id,)).fetchone()
        if cip and cip["client_ip"] and is_public_ip(str(cip["client_ip"])):
            return str(cip["client_ip"])
    except Exception:
        pass

    # 5. From hosts client_ip if legacy column exists
    try:
        h = conn.execute("SELECT client_ip FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if h and h["client_ip"] and is_public_ip(str(h["client_ip"])):
            return str(h["client_ip"])
    except Exception:
        pass

    return ""


def discover_host_open_ports(conn: sqlite3.Connection, host_id: str) -> List[int]:
    """Finds all open listening ports for this machine from reports and host_security."""
    ports: Set[int] = set()
    # From reports
    rows = conn.execute("SELECT payload_json FROM reports WHERE host_id=?", (host_id,)).fetchall()
    for r in rows:
        try:
            p = json.loads(r["payload_json"])
            sec = p.get("security", {})
            for lp in sec.get("listening_ports", []) or []:
                try:
                    port = int(lp)
                    if 1 <= port <= 65535 and port not in {25, 53}:
                        ports.add(port)
                except (ValueError, TypeError):
                    continue
            for exp in sec.get("network_exposure", []) or []:
                if isinstance(exp, dict) and exp.get("host_port"):
                    try:
                        hp = int(exp["host_port"])
                        if 1 <= hp <= 65535 and hp not in {25, 53}:
                            ports.add(hp)
                    except (ValueError, TypeError):
                        continue
        except Exception:
            pass

    # From host_security
    sec = conn.execute(
        "SELECT payload_json FROM host_security WHERE host_id=? ORDER BY ts DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    if sec:
        try:
            p = json.loads(sec["payload_json"])
            hf = p.get("host_firewall", {})
            for lp in hf.get("listening_ports", []) or []:
                try:
                    port = int(lp)
                    if 1 <= port <= 65535 and port not in {25, 53}:
                        ports.add(port)
                except (ValueError, TypeError):
                    continue
        except Exception:
            pass

    return sorted(ports)


def choose_random_port(ports: List[int]) -> int:
    """Randomly selects an open port on the target machine, or falls back to standard ports."""
    if ports:
        return random.choice(ports)
    return random.choice([443, 80, 22])


def execute_globalping_measurement(target: str, port: int, timeout_seconds: int = 25) -> Dict[str, Any]:
    """Posts a measurement to Globalping and polls until completion."""
    protocol = "HTTPS" if port == 443 else "HTTP"
    measurement_body = {
        "type": "http",
        "target": target,
        "locations": [{"limit": 1, **r["loc"]} for r in REACH_REGIONS],
        "measurementOptions": {
            "port": port,
            "protocol": protocol,
        },
    }
    body_bytes = json.dumps(measurement_body).encode("utf-8")
    ctx = _get_ssl_context()
    req = urllib.request.Request(
        f"{GLOBALPING_API_URL}/measurements",
        data=body_bytes,
        headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Watcher"},
    )
    with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
        post_data = json.loads(resp.read().decode("utf-8"))
        measurement_id = post_data["id"]

    # Poll for completion
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        time.sleep(1.5)
        poll_req = urllib.request.Request(
            f"{GLOBALPING_API_URL}/measurements/{measurement_id}",
            headers={"User-Agent": "Narwhal-Watcher"},
        )
        with urllib.request.urlopen(poll_req, context=ctx, timeout=10) as poll_resp:
            m_data = json.loads(poll_resp.read().decode("utf-8"))
            if m_data.get("status") == "finished":
                return m_data
            if m_data.get("results") and len(m_data["results"]) >= len(REACH_REGIONS):
                return m_data

    return m_data if "m_data" in locals() else {"results": []}


def parse_measurement_results(m_data: Dict[str, Any], target: str, port: int) -> Dict[str, Any]:
    """Processes Globalping raw output into verdicts, latency stats, and 18-region breakdown."""
    raw_results = m_data.get("results", [])
    region_results = []
    matched = set()

    for item in REACH_REGIONS:
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
        timings = res_obj.get("timings") or {}
        raw_output = str(res_obj.get("rawOutput") or "")
        tcp_ms = timings.get("tcp")
        total_ms = timings.get("total") or 0

        # Status classification
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
                "dns": timings.get("dns"),
                "tls": timings.get("tls"),
                "ttfb": timings.get("firstByte"),
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

    # Verdict diagnosis
    total_count = len(region_results)
    success_count = len(ok_results)
    cn_success_count = len(cn_ok)

    if cn_success_count == 3 and success_count >= 14:
        verdict = "ok"
        verdict_label = "三网通畅·全球可达"
        verdict_desc = "中国电信、联通、移动及全球各主要区域均可顺畅建立连接。"
    elif cn_success_count == 0 and success_count >= 8:
        verdict = "gfw_blocked"
        verdict_label = "国内受阻·疑似GFW阻断"
        verdict_desc = "海外节点完全通畅，但中国大陆三大运营商探针均连接超时或握手被中断。"
    elif cn_success_count >= 1 and success_count < 6:
        verdict = "cn_only"
        verdict_label = "仅国内可达·海外受阻"
        verdict_desc = "国内部分或全部可连，但大部分海外区域无法访问，疑似配置了海外 IP 白名单或境外出口丢包。"
    elif success_count == 0:
        verdict = "timeout"
        verdict_label = "全网连接超时/端口未放行"
        verdict_desc = "所有探针均无法建立 TCP 握手，请检查防火墙或服务监听状态。"
    else:
        verdict = "partial"
        verdict_label = "部分区域受阻"
        verdict_desc = f"{success_count}/{total_count} 个区域可达，部分运营商或地区连接异常。"

    stats = {
        "total": total_count,
        "success": success_count,
        "failed": total_count - success_count,
        "cn_success": cn_success_count,
        "cn_total": cn_total,
        "cn_avg_ms": cn_avg,
        "global_avg_ms": global_avg,
        "min_ms": min_lat,
        "max_ms": max_lat,
    }

    return {
        "target": target,
        "port": port,
        "protocol": "TCP",
        "verdict": verdict,
        "verdict_label": verdict_label,
        "verdict_desc": verdict_desc,
        "stats": stats,
        "results": region_results,
        "checked_at": int(time.time()),
    }


def perform_host_reach_check(conn: sqlite3.Connection, host_id: str) -> Optional[Dict[str, Any]]:
    """Runs reachability check for a single host with a randomly selected open port."""
    target = discover_host_target(conn, host_id)
    if not target or not is_public_ip(target):
        logger.info(f"Skipping reach check for {host_id}: no public target discovered")
        return None

    open_ports = discover_host_open_ports(conn, host_id)
    port = choose_random_port(open_ports)
    logger.info(f"Running automated reach check for {host_id} -> {target}:{port} (from {len(open_ports)} open ports)")

    try:
        m_data = execute_globalping_measurement(target, port)
        summary = parse_measurement_results(m_data, target, port)

        now = int(time.time())
        conn.execute("""
            INSERT INTO host_reachability(host_id, target, port, protocol, verdict, verdict_label, verdict_desc, stats_json, results_json, checked_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                target=excluded.target, port=excluded.port, protocol=excluded.protocol,
                verdict=excluded.verdict, verdict_label=excluded.verdict_label, verdict_desc=excluded.verdict_desc,
                stats_json=excluded.stats_json, results_json=excluded.results_json, checked_at=excluded.checked_at
        """, (
            host_id, target, port, summary["protocol"], summary["verdict"], summary["verdict_label"],
            summary["verdict_desc"], json.dumps(summary["stats"]), json.dumps(summary["results"]), now
        ))
        conn.execute("""
            INSERT INTO host_reachability_history(host_id, target, port, protocol, verdict, stats_json, checked_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
        """, (host_id, target, port, summary["protocol"], summary["verdict"], json.dumps(summary["stats"]), now))
        conn.commit()
        return summary
    except Exception as e:
        logger.error(f"Failed automated reach check for {host_id} ({target}:{port}): {e}")
        return None


async def run_hourly_reach_cycle(db_factory: Callable[[], sqlite3.Connection]) -> int:
    """Executes reachability checks across all active cluster nodes with rate pacing."""
    conn = db_factory()
    try:
        init_db(conn)
        now = int(time.time())
        # Query active hosts from last 30 minutes
        hosts = [
            row["host_id"] for row in conn.execute(
                "SELECT host_id FROM hosts WHERE last_seen > ? ORDER BY host_id",
                (now - 1800,),
            ).fetchall()
        ]
    finally:
        conn.close()

    if not hosts:
        logger.info("No active hosts found for automated reach check")
        return 0

    checked = 0
    for host_id in hosts:
        conn = db_factory()
        try:
            res = await asyncio.to_thread(perform_host_reach_check, conn, host_id)
            if res:
                checked += 1
        except Exception as e:
            logger.error(f"Error in reach check cycle for {host_id}: {e}")
        finally:
            conn.close()
        # Rate-limiting pause between hosts
        await asyncio.sleep(2.5)

    return checked


async def run_loop(db_factory: Callable[[], sqlite3.Connection]) -> None:
    """Background loop executing reachability inspection every 1 hour (3600 seconds)."""
    await asyncio.sleep(45)  # Initial grace window after server startup
    while True:
        cycle_start = time.monotonic()
        try:
            logger.info("Starting cluster hourly automated reach check cycle...")
            checked = await run_hourly_reach_cycle(db_factory)
            logger.info(f"Finished automated reach check cycle: {checked} hosts inspected")
        except Exception as e:
            logger.error(f"Automated reach check cycle crashed: {e}")

        elapsed = time.monotonic() - cycle_start
        sleep_time = max(60.0, 3600.0 - elapsed)
        await asyncio.sleep(sleep_time)


def attach(app: FastAPI, db_factory: Callable[[], sqlite3.Connection], verify_signature: Any, signed_json_response: Any) -> None:
    """Attaches reachability endpoints to the FastAPI server."""

    @app.get("/api/v1/reachability/summary")
    def get_reachability_summary(request: Request) -> JSONResponse:
        conn = db_factory()
        try:
            init_db(conn)
            rows = conn.execute("SELECT * FROM host_reachability ORDER BY checked_at DESC").fetchall()
            items = []
            max_checked = 0
            for r in rows:
                checked_at = int(r["checked_at"] or 0)
                if checked_at > max_checked:
                    max_checked = checked_at
                try:
                    stats = json.loads(r["stats_json"] or "{}")
                except Exception:
                    stats = {}
                items.append({
                    "host_id": r["host_id"],
                    "target": r["target"],
                    "port": r["port"],
                    "protocol": r["protocol"],
                    "verdict": r["verdict"],
                    "verdict_label": r["verdict_label"],
                    "verdict_desc": r["verdict_desc"],
                    "stats": stats,
                    "checked_at": checked_at,
                })
            return JSONResponse(content={"items": items, "last_checked": max_checked})
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
            return JSONResponse(content={
                "host_id": r["host_id"],
                "target": r["target"],
                "port": r["port"],
                "protocol": r["protocol"],
                "verdict": r["verdict"],
                "verdict_label": r["verdict_label"],
                "verdict_desc": r["verdict_desc"],
                "stats": stats,
                "results": results,
                "checked_at": int(r["checked_at"] or 0),
            })
        finally:
            conn.close()

    @app.post("/api/v1/reachability/trigger")
    async def trigger_reachability_check(request: Request) -> JSONResponse:
        asyncio.create_task(run_hourly_reach_cycle(db_factory))
        return JSONResponse(content={"ok": True, "message": "全集群可达性自动化巡检已在后台启动"})
