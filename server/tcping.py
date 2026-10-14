"""Public VPS -> Zstatic TCP measurements, isolated from private monitoring data."""
import hashlib
import ipaddress
import json
import math
import re
import secrets
import statistics
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

DIRECTORY_URL = "https://www.zstaticcdn.com/api/v1/DescribeAllNodes"
PUBLIC = "/api/public/tcping"
CAPABILITY = "public-tcp-v1"
ACTIVE = ("queued", "running")
GROUPS = {"province", "city", "all"}
PROVINCES = set("河北 山西 辽宁 吉林 黑龙江 江苏 浙江 安徽 福建 江西 山东 河南 湖北 湖南 广东 海南 四川 贵州 云南 陕西 甘肃 青海 内蒙古 广西 西藏 宁夏 新疆 北京 天津 上海 重庆".split())
CARRIERS = {"mobile", "unicom", "telecom"}
ERRORS = {"", "timeout", "refused", "network_error", "dns_error", "blocked_dns", "deadline", "worker_error", "cancelled"}
_refresh_lock = threading.Lock()
_attempt = 0.0


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global and not ip.is_multicast
    except ValueError:
        return False


def endpoint(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9-]{1,120}-v4\.ip\.zstaticcdn\.com:(80|443)", value):
        raise ValueError("invalid Zstatic endpoint")
    host, port = value.rsplit(":", 1)
    return host, int(port)


def normalize_directory(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("ProvinceNodes"), list) or not isinstance(raw.get("CityNodes"), list):
        raise ValueError("invalid node directory")
    updated = raw.get("UpdatedAt")
    if not isinstance(updated, str) or len(updated) > 40:
        raise ValueError("invalid directory timestamp")
    datetime.fromisoformat(updated.replace("Z", "+00:00"))
    nodes, provinces, seen = [], set(), set()
    def add(kind, province, city, carrier, address):
        if province not in PROVINCES or carrier not in CARRIERS or not isinstance(city, str) or len(city) > 40:
            raise ValueError("invalid directory location")
        host, port = endpoint(address)
        item = {"kind": kind, "province": province, "city": city, "carrier": carrier, "host": host, "port": port}
        item["id"] = digest(item)[:20]
        if item["id"] in seen:
            raise ValueError("duplicate directory record")
        seen.add(item["id"])
        nodes.append(item)
    for group in raw["ProvinceNodes"]:
        if not isinstance(group, dict) or group.get("province") in provinces or not isinstance(group.get("carriers"), dict):
            raise ValueError("invalid province group")
        province = group.get("province")
        provinces.add(province)
        if set(group["carriers"]) - CARRIERS:
            raise ValueError("unknown carrier")
        for carrier, address in group["carriers"].items():
            if address:
                add("province", province, "", carrier, address)
    for item in raw["CityNodes"]:
        if not isinstance(item, dict):
            raise ValueError("invalid city record")
        add("city", item.get("province"), item.get("city"), item.get("carrier"), item.get("endpoint"))
    if not 1 <= len(provinces) <= 31 or not 1 <= len(nodes) <= 400:
        raise ValueError("directory outside limits")
    counts = {"province_groups": len(provinces), "province_nodes": sum(n["kind"] == "province" for n in nodes),
              "city_nodes": sum(n["kind"] == "city" for n in nodes), "total": len(nodes),
              "unique_endpoints": len({(n["host"], n["port"]) for n in nodes})}
    result = {"updated_at": updated, "nodes": nodes, "counts": counts}
    result["generation"] = digest(result)
    return result


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS tcp_directories(generation TEXT PRIMARY KEY,payload TEXT NOT NULL,fetched_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS tcp_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    INSERT OR IGNORE INTO tcp_settings VALUES('enabled','false');
    CREATE TABLE IF NOT EXISTS tcp_sources(id TEXT PRIMARY KEY,host_id TEXT NOT NULL,node_id TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,region TEXT NOT NULL DEFAULT '',purchase_url TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 1,sort_order INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS tcp_cooldowns(node_id TEXT PRIMARY KEY,next_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS tcp_jobs(id TEXT PRIMARY KEY,source_id TEXT NOT NULL,node_id TEXT NOT NULL,
      host_id TEXT NOT NULL,source_revision INTEGER NOT NULL,generation TEXT NOT NULL,scope TEXT NOT NULL,
      targets TEXT NOT NULL,samples INTEGER NOT NULL,status TEXT NOT NULL,lease TEXT NOT NULL,
      created_at INTEGER NOT NULL,deadline_at INTEGER NOT NULL,started_at INTEGER NOT NULL DEFAULT 0,
      finished_at INTEGER NOT NULL DEFAULT 0,message TEXT NOT NULL DEFAULT '');
    CREATE UNIQUE INDEX IF NOT EXISTS tcp_one_active_node ON tcp_jobs(node_id) WHERE status IN ('queued','running');
    CREATE INDEX IF NOT EXISTS tcp_jobs_source_time ON tcp_jobs(source_id,created_at);
    CREATE TABLE IF NOT EXISTS tcp_results(job_id TEXT NOT NULL,target_id TEXT NOT NULL,payload TEXT NOT NULL,
      PRIMARY KEY(job_id,target_id));
    CREATE TABLE IF NOT EXISTS tcp_batches(job_id TEXT NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL,
      PRIMARY KEY(job_id,sequence));
    """)


def public_route(path, method):
    if path == "/tcping" and method in {"GET", "HEAD"}:
        return True
    if path in {PUBLIC + "/directory", PUBLIC + "/sources"} and method in {"GET", "HEAD"}:
        return True
    if path == PUBLIC + "/jobs" and method == "POST":
        return True
    return method in {"GET", "HEAD"} and bool(re.fullmatch(re.escape(PUBLIC) + r"/jobs/[0-9a-f-]{36}", path))


def enabled(conn):
    row = conn.execute("SELECT value FROM tcp_settings WHERE key='enabled'").fetchone()
    return bool(row and row[0] == "true")


def refresh_directory(db):
    global _attempt
    if not _refresh_lock.acquire(False):
        return
    try:
        conn = db()
        try:
            row = conn.execute("SELECT fetched_at FROM tcp_directories ORDER BY fetched_at DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        if row and time.time() - row[0] < 21600 or time.monotonic() - _attempt < 60:
            return
        _attempt = time.monotonic()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        request = urllib.request.Request(DIRECTORY_URL, headers={"User-Agent": "Narwhal-Personal-TCP/1", "Accept": "application/json"})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as response:
            body = response.read(262145)
        if len(body) > 262144:
            raise ValueError("oversized directory")
        directory = normalize_directory(json.loads(body))
        conn = db()
        try:
            conn.execute("INSERT INTO tcp_directories VALUES(?,?,?) ON CONFLICT(generation) DO UPDATE SET fetched_at=excluded.fetched_at",
                         (directory["generation"], encoded(directory), int(time.time())))
            conn.commit()
        finally:
            conn.close()
    except (OSError, ValueError, TypeError, KeyError):
        pass  # Preserve the last independently validated directory.
    finally:
        _refresh_lock.release()


def directory(conn):
    row = conn.execute("SELECT payload,fetched_at FROM tcp_directories ORDER BY fetched_at DESC LIMIT 1").fetchone()
    if not row:
        raise HTTPException(503, "节点目录暂不可用，请稍后重试")
    return {**json.loads(row[0]), "fetched_at": row[1], "stale": time.time() - row[1] > 86400, "source": DIRECTORY_URL}


def expire(conn, now):
    conn.execute("""UPDATE tcp_jobs SET status=CASE WHEN EXISTS(SELECT 1 FROM tcp_results r WHERE r.job_id=tcp_jobs.id)
      THEN 'partial' ELSE 'expired' END,finished_at=?,message='任务超过执行期限，未完成项目未计为连接失败'
      WHERE status IN ('queued','running') AND deadline_at<=?""", (now, now))
    old = [r[0] for r in conn.execute("SELECT id FROM tcp_jobs WHERE created_at<? AND status NOT IN ('queued','running') LIMIT 100", (now-86400,))]
    for job_id in old:
        conn.execute("DELETE FROM tcp_results WHERE job_id=?", (job_id,))
        conn.execute("DELETE FROM tcp_batches WHERE job_id=?", (job_id,))
        conn.execute("DELETE FROM tcp_jobs WHERE id=?", (job_id,))
    conn.execute("DELETE FROM tcp_directories WHERE fetched_at<? AND generation NOT IN (SELECT generation FROM tcp_jobs) AND generation NOT IN (SELECT generation FROM tcp_directories ORDER BY fetched_at DESC LIMIT 3)", (now-86400,))


def host_state(conn, source, now):
    row = conn.execute("SELECT h.last_seen,h.config_json,o.payload FROM hosts h LEFT JOIN ops_hosts o ON o.node=h.node_id WHERE h.host_id=? AND h.node_id=?", (source["host_id"], source["node_id"])).fetchone()
    if not row:
        return "identity_changed"
    try:
        interval = int(json.loads(row[1] or "{}").get("report_interval", 300))
        caps = json.loads(row[2] or "{}").get("capabilities", [])
    except (ValueError, TypeError):
        interval, caps = 300, []
    if now - row[0] > max(600, min(3600, interval*2.5)):
        return "offline"
    return "ready" if CAPABILITY in caps else "needs_upgrade"


def source_item(conn, row, now, private=False):
    cooldown = conn.execute("SELECT next_at FROM tcp_cooldowns WHERE node_id=?", (row["node_id"],)).fetchone()
    latest = conn.execute("SELECT id,status,scope,finished_at FROM tcp_jobs WHERE source_id=? ORDER BY created_at DESC LIMIT 1", (row["id"],)).fetchone()
    item = {k: row[k] for k in ("id", "name", "region", "purchase_url", "sort_order")}
    item.update(status=host_state(conn, row, now), cooldown_until=cooldown[0] if cooldown else 0,
                latest_job=dict(latest) if latest else None)
    if private:
        item.update(host_id=row["host_id"], node_id=row["node_id"], enabled=bool(row["enabled"]))
    return item


def get_job(conn, job_id):
    row = conn.execute("SELECT j.* FROM tcp_jobs j JOIN tcp_sources s ON s.id=j.source_id WHERE j.id=? AND s.enabled=1", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "测试任务不存在或来源已撤回")
    results = {r[0]: json.loads(r[1]) for r in conn.execute("SELECT target_id,payload FROM tcp_results WHERE job_id=?", (job_id,))}
    fields = ("id", "source_id", "generation", "scope", "samples", "status", "created_at", "deadline_at", "started_at", "finished_at", "message")
    return {**{k: row[k] for k in fields}, "nodes": [{**n, "result": results.get(n["id"])} for n in json.loads(row["targets"])],
            "completed": len(results), "direction": "vps_to_zstatic"}


def admit(conn, source_id, scope, now):
    if scope not in GROUPS:
        raise HTTPException(400, "请选择省级、市级或全部节点")
    conn.execute("BEGIN IMMEDIATE")
    expire(conn, now)
    if not enabled(conn):
        raise HTTPException(503, "公开测试暂时关闭，可查看已有结果")
    source = conn.execute("SELECT * FROM tcp_sources WHERE id=? AND enabled=1", (source_id,)).fetchone()
    if not source or host_state(conn, source, now) != "ready":
        raise HTTPException(409, "该小鸡暂不可执行测试，请选择在线且已支持测速的来源")
    current = directory(conn)
    job = conn.execute("SELECT id FROM tcp_jobs WHERE node_id=? AND status IN ('queued','running')", (source["node_id"],)).fetchone()
    if job:
        conn.commit()
        return {"job": get_job(conn, job[0]), "reused": "running"}
    cached = conn.execute("SELECT id FROM tcp_jobs WHERE source_id=? AND source_revision=? AND generation=? AND scope=? AND status='completed' AND finished_at>? ORDER BY finished_at DESC LIMIT 1",
                          (source_id, source["revision"], current["generation"], scope, now-900)).fetchone()
    if cached:
        conn.commit()
        return {"job": get_job(conn, cached[0]), "reused": "cache"}
    cooldown = conn.execute("SELECT next_at FROM tcp_cooldowns WHERE node_id=?", (source["node_id"],)).fetchone()
    if cooldown and cooldown[0] > now:
        latest = conn.execute("SELECT id FROM tcp_jobs WHERE source_id=? ORDER BY created_at DESC LIMIT 1", (source_id,)).fetchone()
        raise HTTPException(429, {"message": "该小鸡处于冷却期，请复用最近结果", "retry_after": cooldown[0]-now, "latest_job_id": latest[0] if latest else None}, headers={"Retry-After": str(cooldown[0]-now)})
    active = conn.execute("SELECT COUNT(*) FROM tcp_jobs WHERE status IN ('queued','running')").fetchone()[0]
    recent = conn.execute("SELECT COUNT(*) FROM tcp_jobs WHERE created_at>?", (now-3600,)).fetchone()[0]
    if active >= 2 or recent >= 20:
        raise HTTPException(429, "当前测试额度已占用，请稍后重试", headers={"Retry-After": "60"})
    nodes = [n for n in current["nodes"] if scope == "all" or n["kind"] == scope]
    if not nodes:
        raise HTTPException(409, "所选目录没有测试目标")
    job_id, lease = str(uuid.uuid4()), secrets.token_urlsafe(32)
    samples = 2 if len(nodes) <= 93 else 1
    conn.execute("INSERT INTO tcp_jobs(id,source_id,node_id,host_id,source_revision,generation,scope,targets,samples,status,lease,created_at,deadline_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',?,?,?)",
                 (job_id, source_id, source["node_id"], source["host_id"], source["revision"], current["generation"], scope, encoded(nodes), samples, lease, now, now+210))
    conn.execute("INSERT INTO tcp_cooldowns VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET next_at=excluded.next_at", (source["node_id"], now+(900 if scope == "province" else 1800)))
    conn.commit()
    return {"job": get_job(conn, job_id), "reused": ""}


def lease_jobs(conn, host_id, node_id, now):
    """Called inside the existing signed poll transaction; no security action semantics."""
    expire(conn, now)
    cancelled = [r[0] for r in conn.execute("SELECT id FROM tcp_jobs WHERE host_id=? AND node_id=? AND status='cancelled' AND created_at>? LIMIT 30", (host_id, node_id, now-3600))]
    row = conn.execute("SELECT j.* FROM tcp_jobs j JOIN tcp_sources s ON s.id=j.source_id WHERE j.host_id=? AND j.node_id=? AND s.enabled=1 AND j.status IN ('queued','running') AND j.started_at=0 ORDER BY j.created_at LIMIT 1", (host_id, node_id)).fetchone() if enabled(conn) else None
    job = None
    if row:
        conn.execute("UPDATE tcp_jobs SET status='running' WHERE id=? AND status='queued'", (row["id"],))
        job = {k: row[k] for k in ("id", "node_id", "lease", "generation", "samples", "deadline_at")}
        job.update(targets=json.loads(row["targets"]), target_hash=digest(json.loads(row["targets"])), execution_seconds=180, concurrency=4)
    return {"job": job, "cancelled": cancelled}


def normalized_result(raw, sample_limit):
    if not isinstance(raw, dict) or set(raw) != {"target_id", "ip", "samples_ms", "error"}:
        raise HTTPException(400, "invalid result fields")
    values, ip, error = raw["samples_ms"], raw["ip"], raw["error"]
    if not isinstance(values, list) or len(values) > sample_limit or not isinstance(ip, str) or not isinstance(error, str) or error not in ERRORS:
        raise HTTPException(400, "invalid result samples")
    if ip and not public_ip(ip):
        raise HTTPException(400, "invalid resolved address")
    for value in values:
        if value is not None and (type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 10000):
            raise HTTPException(400, "invalid latency")
    good = [v for v in values if v is not None]
    if good and not ip or not values and error not in {"dns_error", "blocked_dns", "deadline", "worker_error", "cancelled"}:
        raise HTTPException(400, "inconsistent result")
    if len(good) != len(values) and not error:
        raise HTTPException(400, "missing failure reason")
    return {**raw, "median_ms": statistics.median(good) if good else None,
            "min_ms": min(good) if good else None, "max_ms": max(good) if good else None,
            "mean_ms": round(statistics.mean(good), 2) if good else None,
            "success": len(good), "attempts": len(values),
            "status": "ok" if good and len(good) == sample_limit else "partial" if good else error or "network_error"}


def report(conn, payload, now):
    keys = {"job_id", "node_id", "host_id", "lease", "generation", "target_hash", "sequence", "rows", "done", "outcome"}
    if not isinstance(payload, dict) or set(payload) != keys or type(payload["sequence"]) is not int or not 0 <= payload["sequence"] <= 50 or type(payload["done"]) is not bool:
        raise HTTPException(400, "invalid batch contract")
    if any(not isinstance(payload[k], str) or len(payload[k]) > 256 for k in ("job_id", "node_id", "host_id", "lease", "generation", "target_hash", "outcome")):
        raise HTTPException(400, "invalid batch identity")
    rows = payload["rows"]
    if not isinstance(rows, list) or len(rows) > 32 or payload["outcome"] not in {"", "complete", "deadline", "worker_error", "cancelled"}:
        raise HTTPException(400, "invalid batch bounds")
    if payload["done"] != bool(payload["outcome"]):
        raise HTTPException(400, "invalid completion state")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM tcp_jobs WHERE id=?", (payload["job_id"],)).fetchone()
    if not row or row["host_id"] != payload["host_id"] or row["node_id"] != payload["node_id"] or not isinstance(payload["lease"], str) or not secrets.compare_digest(row["lease"], payload["lease"]):
        raise HTTPException(403, "invalid probe lease")
    targets = json.loads(row["targets"])
    if payload["generation"] != row["generation"] or payload["target_hash"] != digest(targets):
        raise HTTPException(409, "target generation mismatch")
    try:
        batch_digest = digest(payload)
    except (ValueError, TypeError):
        raise HTTPException(400, "invalid batch values")
    previous = conn.execute("SELECT digest FROM tcp_batches WHERE job_id=? AND sequence=?", (row["id"], payload["sequence"])).fetchone()
    if previous:
        if previous[0] != batch_digest:
            raise HTTPException(409, "conflicting batch replay")
        conn.commit()
        return {"ok": True, "duplicate": True}
    source = conn.execute("SELECT enabled FROM tcp_sources WHERE id=? AND revision=?", (row["source_id"], row["source_revision"])).fetchone()
    identity = conn.execute("SELECT 1 FROM hosts WHERE host_id=? AND node_id=?", (row["host_id"], row["node_id"])).fetchone()
    if row["status"] != "running" or row["deadline_at"] <= now or not source or not source[0] or not identity or not enabled(conn):
        raise HTTPException(409, "probe no longer accepts results")
    allowed, incoming = {t["id"] for t in targets}, {}
    for item in rows:
        result = normalized_result(item, row["samples"])
        target_id = result["target_id"]
        if not isinstance(target_id, str) or target_id not in allowed or target_id in incoming:
            raise HTTPException(400, "unexpected or repeated target")
        incoming[target_id] = encoded(result)
        old = conn.execute("SELECT payload FROM tcp_results WHERE job_id=? AND target_id=?", (row["id"], target_id)).fetchone()
        if old and old[0] != incoming[target_id]:
            raise HTTPException(409, "conflicting target result")
    for target_id, value in incoming.items():
        conn.execute("INSERT OR IGNORE INTO tcp_results VALUES(?,?,?)", (row["id"], target_id, value))
    conn.execute("INSERT INTO tcp_batches VALUES(?,?,?)", (row["id"], payload["sequence"], batch_digest))
    conn.execute("UPDATE tcp_jobs SET status='running',started_at=CASE WHEN started_at=0 THEN ? ELSE started_at END WHERE id=?", (now, row["id"]))
    if payload["done"]:
        results = [json.loads(r[0]) for r in conn.execute("SELECT payload FROM tcp_results WHERE job_id=?", (row["id"],))]
        complete = len(results) == len(targets) and payload["outcome"] == "complete" and all(r["attempts"] == row["samples"] or r["error"] in {"dns_error", "blocked_dns"} for r in results)
        status = "completed" if complete else "partial" if results else "failed"
        conn.execute("UPDATE tcp_jobs SET status=?,finished_at=?,message=? WHERE id=?", (status, now, "" if complete else "部分目标未完成；已测结果保留，未测目标不计连接失败", row["id"]))
    conn.commit()
    return {"ok": True}


def purchase_url(value):
    if not isinstance(value, str) or len(value) > 1000 or any(ord(c) < 33 for c in value):
        raise HTTPException(400, "购买链接格式无效")
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.fragment or parts.port not in (None, 443):
            raise ValueError()
        if parts.hostname == "localhost" or "." not in parts.hostname:
            raise ValueError()
        try:
            ipaddress.ip_address(parts.hostname)
        except ValueError:
            pass
        else:
            if not ipaddress.ip_address(parts.hostname).is_global:
                raise ValueError()
        if any(re.search(r"token|key|password|secret|signature|credential|auth", k, re.I) for k, _ in parse_qsl(parts.query)):
            raise ValueError()
    except ValueError:
        raise HTTPException(400, "请填写不含凭据的 HTTPS 商品链接") from None
    return value


async def body_json(request, maximum=4096):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum:
            raise HTTPException(413, "请求过大")
    try:
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except ValueError:
        raise HTTPException(400, "请使用 JSON 对象") from None


def attach(app, db, static_dir, verify_signature, signed_response):
    @app.api_route("/tcping", methods=["GET", "HEAD"])
    @app.api_route("/tcping/manage", methods=["GET", "HEAD"])
    def page():
        return FileResponse(static_dir / "index.html", headers={"Cache-Control": "no-store"})

    @app.get(PUBLIC + "/directory")
    def nodes():
        refresh_directory(db)
        conn = db()
        try:
            return JSONResponse(directory(conn), headers={"Cache-Control": "public, max-age=60"})
        finally:
            conn.close()

    @app.get(PUBLIC + "/sources")
    def sources():
        conn, now = db(), int(time.time())
        try:
            return JSONResponse({"enabled": enabled(conn), "items": [source_item(conn, r, now) for r in conn.execute("SELECT * FROM tcp_sources WHERE enabled=1 ORDER BY sort_order,name LIMIT 200")]}, headers={"Cache-Control": "no-store"})
        finally:
            conn.close()

    @app.post(PUBLIC + "/jobs")
    async def start(request: Request):
        origin = request.headers.get("origin")
        scheme = "https" if request.headers.get("x-forwarded-proto") == "https" else request.url.scheme
        if origin and origin != scheme + "://" + request.headers.get("host", ""):
            raise HTTPException(403, "请求来源无效")
        payload = await body_json(request, 1024)
        if set(payload) != {"source_id", "scope"} or not all(isinstance(v, str) for v in payload.values()):
            raise HTTPException(400, "请选择公开目录中的小鸡与测试范围")
        conn = db()
        try:
            return JSONResponse(admit(conn, payload["source_id"], payload["scope"], int(time.time())), headers={"Cache-Control": "no-store"})
        finally:
            conn.close()

    @app.get(PUBLIC + "/jobs/{job_id}")
    def job(job_id: str):
        conn = db()
        try:
            expire(conn, int(time.time()))
            conn.commit()
            return JSONResponse(get_job(conn, job_id), headers={"Cache-Control": "no-store"})
        finally:
            conn.close()

    @app.post("/api/v1/tcp-probe/report")
    async def agent_report(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 65536:
                raise HTTPException(413, "probe report too large")
        ts = request.headers.get("x-timestamp", "")
        verify_signature(bytes(raw), ts, request.headers.get("x-signature", ""))
        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "invalid JSON") from None
        conn = db()
        try:
            return signed_response(report(conn, payload, int(time.time())), ts)
        finally:
            conn.close()

    def admin(request):
        if getattr(request.state, "dashboard_role", "") != "admin":
            raise HTTPException(403, "仅管理员可配置公开测速来源")

    @app.get("/api/v1/tcping/manage")
    def management(request: Request):
        admin(request)
        conn, now = db(), int(time.time())
        try:
            return {"enabled": enabled(conn), "sources": [source_item(conn, r, now, True) for r in conn.execute("SELECT * FROM tcp_sources ORDER BY sort_order,name LIMIT 200")],
                    "candidates": [dict(r) for r in conn.execute("SELECT host_id,node_id,agent_version,last_seen FROM hosts WHERE node_id<>'' ORDER BY host_id LIMIT 200")]}
        finally:
            conn.close()

    @app.post("/api/v1/tcping/settings")
    async def settings(request: Request):
        admin(request)
        p = await body_json(request)
        if set(p) != {"enabled"} or type(p["enabled"]) is not bool:
            raise HTTPException(400, "invalid setting")
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE tcp_settings SET value=? WHERE key='enabled'", ("true" if p["enabled"] else "false",))
            if not p["enabled"]:
                conn.execute("UPDATE tcp_jobs SET status='cancelled',finished_at=? WHERE status IN ('queued','running')", (int(time.time()),))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.post("/api/v1/tcping/sources")
    async def save_source(request: Request):
        admin(request)
        p = await body_json(request)
        if set(p) - {"id", "host_id", "name", "region", "purchase_url", "enabled"} or not all(isinstance(p.get(k, ""), str) for k in ("id", "host_id", "name", "region", "purchase_url")) or type(p.get("enabled")) is not bool or not 1 <= len(p.get("name", "").strip()) <= 120 or len(p.get("region", "")) > 80:
            raise HTTPException(400, "请填写有效的来源名称、主机和公开状态")
        link = purchase_url(p.get("purchase_url", ""))
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            host = conn.execute("SELECT node_id FROM hosts WHERE host_id=? AND node_id<>''", (p.get("host_id", ""),)).fetchone()
            if not host:
                raise HTTPException(409, "来源必须为具有稳定节点身份的已注册 VPS")
            old = conn.execute("SELECT * FROM tcp_sources WHERE id=?", (p.get("id", ""),)).fetchone()
            if p.get("id") and not old:
                raise HTTPException(404, "公开来源不存在")
            if old and (old["node_id"] != host[0] or old["host_id"] != p["host_id"]):
                raise HTTPException(409, "来源身份变化，请撤回旧来源并重新关联")
            if not old and conn.execute("SELECT 1 FROM tcp_sources WHERE node_id=?", (host[0],)).fetchone():
                raise HTTPException(409, "该节点已有公开来源，不能用别名绕过限制")
            source_id = old["id"] if old else str(uuid.uuid4())
            conn.execute("INSERT INTO tcp_sources(id,host_id,node_id,name,region,purchase_url,enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,region=excluded.region,purchase_url=excluded.purchase_url,enabled=excluded.enabled",
                         (source_id, p["host_id"], host[0], p["name"].strip(), p.get("region", "").strip(), link, int(p["enabled"])))
            if not p["enabled"]:
                conn.execute("UPDATE tcp_jobs SET status='cancelled',finished_at=? WHERE source_id=? AND status IN ('queued','running')", (int(time.time()), source_id))
            conn.commit()
            return {"ok": True, "id": source_id}
        finally:
            conn.close()
