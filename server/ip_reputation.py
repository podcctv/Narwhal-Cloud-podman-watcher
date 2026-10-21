"""On-demand AbuseIPDB lookups with encrypted credentials and bounded caching."""
import ipaddress
import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

API_URL = "https://api.abuseipdb.com/api/v2/check"
API_TEST_IP = "8.8.8.8"
SUCCESS_CACHE_SECONDS = 24 * 60 * 60
ERROR_CACHE_SECONDS = 60
DAILY_LOOKUP_LIMIT = 900  # Leave room below the provider's free 1,000/day allowance.


def initialize(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS ip_reputation_settings(
        id INTEGER PRIMARY KEY CHECK(id=1), encrypted_api_key TEXT NOT NULL,
        updated_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ip_reputation_cache(
        ip TEXT PRIMARY KEY, result_json TEXT NOT NULL, checked_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ip_reputation_daily_usage(
        utc_day TEXT PRIMARY KEY, requests INTEGER NOT NULL DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ip_reputation_health(
        id INTEGER PRIMARY KEY CHECK(id=1), status TEXT NOT NULL,
        checked_at INTEGER NOT NULL, provider_status INTEGER,
        retry_after_seconds INTEGER, message TEXT NOT NULL DEFAULT '')""")


def normalize_public_ip(value: object) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        raise HTTPException(status_code=400, detail="请输入有效的 IPv4 或 IPv6 地址") from None
    if not address.is_global:
        raise HTTPException(status_code=400, detail="只查询公网来源 IP；私网、保留和本机地址不会发送给第三方")
    return address.compressed


def _api_error(status: int) -> str:
    if status == 401:
        return "AbuseIPDB Key 无效或已撤销，请在系统设置中更换"
    if status == 403:
        return "AbuseIPDB 拒绝了请求；请检查 Key 权限、账号方案或 API 访问限制"
    if status == 429:
        return "AbuseIPDB 请求被限流或账号额度不足，请检查上游配额后重试"
    if status in (408, 425):
        return "AbuseIPDB 请求暂时未完成，请稍后重试"
    if status >= 500:
        return "AbuseIPDB 暂时不可用"
    return "AbuseIPDB 查询失败"


def _provider_error(ip: str, now: int, status: int | None, message: str, retry_after: object = None) -> dict:
    result = {
        "status": "error",
        "provider": "AbuseIPDB",
        "ip": ip,
        "checked_at": now,
        "message": message,
        "retryable": status is None or status in (408, 425) or status >= 500,
    }
    if status is not None:
        result["provider_status"] = status
    delay = None
    try:
        delay = int(str(retry_after).strip())
    except (TypeError, ValueError, OverflowError):
        try:
            retry_at = parsedate_to_datetime(str(retry_after).strip())
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            delay = int(retry_at.timestamp()) - now
        except (TypeError, ValueError, OverflowError):
            pass
    if delay is not None and 0 <= delay <= 86_400:
        result["retry_after_seconds"] = delay
    return result


def _classification(score: int, total_reports: int) -> str:
    if score >= 75:
        return "many_recent_reports"
    if score >= 25:
        return "reported"
    if score > 0:
        return "few_reports"
    if total_reports > 0:
        return "reports_low_confidence"
    return "no_recent_reports"


def _safe_result(ip: str, data: object, checked_at: int) -> dict:
    if not isinstance(data, dict):
        raise ValueError("provider response has no data object")
    try:
        score = max(0, min(100, int(data.get("abuseConfidenceScore") or 0)))
        reports = max(0, min(1_000_000_000, int(data.get("totalReports") or 0)))
        reporters = max(0, min(1_000_000_000, int(data.get("numDistinctUsers") or 0)))
    except (TypeError, ValueError, OverflowError):
        raise ValueError("provider response has invalid counts") from None
    return {
        "status": "checked",
        "provider": "AbuseIPDB",
        "ip": ip,
        "classification": _classification(score, reports),
        "abuse_confidence_score": score,
        "total_reports": reports,
        "distinct_reporters": reporters,
        "last_reported_at": str(data.get("lastReportedAt") or "")[:40],
        "usage_type": str(data.get("usageType") or "")[:120],
        "isp": str(data.get("isp") or "")[:160],
        "country_code": str(data.get("countryCode") or "")[:8],
        "is_whitelisted": data.get("isWhitelisted") if isinstance(data.get("isWhitelisted"), bool) else None,
        "checked_at": checked_at,
        "message": "公开信誉记录只表示社区报告情况，不能单独证明该 IP 对本容器实施了攻击或代表客户本人。",
    }


def _query_provider(api_key: str, ip: str, now: int) -> dict:
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    request = urllib.request.Request(
        f"{API_URL}?{query}",
        headers={"Key": api_key, "Accept": "application/json", "User-Agent": "Narwhal-Monitor-IP-Reputation"},
        method="GET",
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=5) as response:
            if response.status != 200:
                return _provider_error(ip, now, int(response.status), _api_error(int(response.status)))
            raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("provider response too large")
        payload = json.loads(raw.decode("utf-8"))
        return _safe_result(ip, payload.get("data") if isinstance(payload, dict) else None, now)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        exc.close()
        return _provider_error(ip, now, status, _api_error(status), retry_after)
    except (urllib.error.URLError, TimeoutError, OSError):
        return _provider_error(ip, now, None, "连接 AbuseIPDB 失败，请稍后重试")
    except (UnicodeError, ValueError, TypeError):
        return _provider_error(ip, now, None, "AbuseIPDB 返回数据无法验证")


def _read_key(conn: sqlite3.Connection, db_path, cipher_factory) -> str:
    row = conn.execute("SELECT encrypted_api_key FROM ip_reputation_settings WHERE id=1").fetchone()
    if row is None:
        return ""
    try:
        return cipher_factory(db_path()).decrypt(str(row[0]).encode("ascii")).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=503, detail="AbuseIPDB 密钥解密失败；请重新配置密钥") from None


def _cached_result(conn: sqlite3.Connection, ip: str, now: int):
    row = conn.execute(
        "SELECT result_json, expires_at FROM ip_reputation_cache WHERE ip=?", (ip,)
    ).fetchone()
    if row is None or int(row["expires_at"] or 0) <= now:
        return None
    try:
        data = json.loads(row["result_json"] or "{}")
        if not isinstance(data, dict):
            return None
        if data.get("status") == "checked":
            score = max(0, min(100, int(data.get("abuse_confidence_score") or 0)))
            reports = max(0, min(1_000_000_000, int(data.get("total_reports") or 0)))
            data["classification"] = _classification(score, reports)
        return data
    except (TypeError, ValueError, OverflowError):
        return None


def _last_provider_check(conn: sqlite3.Connection) -> dict | None:
    """Return a redacted connectivity summary for the currently saved key only."""
    row = conn.execute(
        "SELECT status,checked_at,provider_status,retry_after_seconds,message "
        "FROM ip_reputation_health WHERE id=1"
    ).fetchone()
    if row is None:
        return None
    try:
        status = str(row["status"] or "")
        checked_at = int(row["checked_at"] or 0)
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if status not in {"checked", "error"}:
        return None
    summary = {"status": status, "checked_at": checked_at}
    provider_status = row["provider_status"]
    if type(provider_status) is int and 100 <= provider_status <= 599:
        summary["provider_status"] = provider_status
    retry_after = row["retry_after_seconds"]
    if type(retry_after) is int and 0 <= retry_after <= 86_400:
        summary["retry_after_seconds"] = retry_after
    if status == "error":
        # _provider_error messages are controlled text; never expose upstream bodies.
        summary["message"] = str(row["message"] or "AbuseIPDB 查询失败")[:240]
    return summary


def check_ip(
    conn: sqlite3.Connection,
    ip: str,
    db_path,
    cipher_factory,
    now: int | None = None,
    force_refresh: bool = False,
) -> dict:
    now = int(now or time.time())
    if not force_refresh:
        cached = _cached_result(conn, ip, now)
        if cached is not None:
            cached["cached"] = True
            return cached
    api_key = _read_key(conn, db_path, cipher_factory)
    if not api_key:
        return {"status": "not_configured", "ip": ip, "message": "请先在系统设置配置 AbuseIPDB API Key"}

    utc_day = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT OR IGNORE INTO ip_reputation_daily_usage(utc_day,requests) VALUES(?,0)", (utc_day,))
    reserved = conn.execute(
        "UPDATE ip_reputation_daily_usage SET requests=requests+1 WHERE utc_day=? AND requests<?",
        (utc_day, DAILY_LOOKUP_LIMIT),
    )
    if reserved.rowcount != 1:
        conn.commit()
        return {"status": "local_limit", "ip": ip, "message": "已达到本系统每日 900 次查询保护上限；缓存命中仍可查看"}
    conn.execute("DELETE FROM ip_reputation_cache WHERE ip IN (SELECT ip FROM ip_reputation_cache WHERE expires_at<=? LIMIT 1000)", (now,))
    conn.execute("DELETE FROM ip_reputation_daily_usage WHERE utc_day<?", (utc_day,))
    # Release SQLite's write lock before making the bounded external request.
    conn.commit()

    result = _query_provider(api_key, ip, now)
    if result.get("status") == "checked":
        ttl = SUCCESS_CACHE_SECONDS
    elif result.get("retryable"):
        # Let the bounded frontend retry reach the provider instead of replaying
        # a just-cached network/5xx failure for the full negative-cache window.
        ttl = 0
    else:
        ttl = ERROR_CACHE_SECONDS
    conn.execute(
        "INSERT OR REPLACE INTO ip_reputation_cache(ip,result_json,checked_at,expires_at) VALUES(?,?,?,?)",
        (ip, json.dumps(result, ensure_ascii=False, separators=(",", ":")), now, now + ttl),
    )
    if result.get("status") in {"checked", "error"}:
        # Do not let an in-flight request with an old key overwrite the health
        # status after an administrator has rotated or removed that key.
        try:
            current_key = _read_key(conn, db_path, cipher_factory)
        except HTTPException:
            current_key = ""
        if current_key == api_key:
            conn.execute(
                "INSERT OR REPLACE INTO ip_reputation_health "
                "(id,status,checked_at,provider_status,retry_after_seconds,message) VALUES(1,?,?,?,?,?)",
                (
                    result["status"],
                    now,
                    result.get("provider_status"),
                    result.get("retry_after_seconds"),
                    str(result.get("message") or "")[:240],
                ),
            )
    conn.commit()
    result["cached"] = False
    return result


def attach(app, db, db_path, cipher_factory) -> None:
    @app.get("/api/v1/ip-reputation/settings")
    def get_settings() -> JSONResponse:
        conn = db()
        try:
            row = conn.execute("SELECT updated_at FROM ip_reputation_settings WHERE id=1").fetchone()
            updated_at = int(row[0]) if row else 0
            last_check = _last_provider_check(conn) if row is not None else None
            return JSONResponse({
                "provider": "AbuseIPDB",
                "configured": row is not None,
                "updated_at": updated_at,
                "last_check": last_check,
            })
        finally:
            conn.close()

    @app.post("/api/v1/ip-reputation/settings")
    async def save_settings(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body") from None
        if not isinstance(payload, dict) or set(payload) != {"api_key"}:
            raise HTTPException(status_code=400, detail="仅接受 api_key 字段")
        api_key = str(payload.get("api_key") or "").strip()
        if not 20 <= len(api_key) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in api_key):
            raise HTTPException(status_code=400, detail="API Key 格式无效")
        try:
            encrypted = cipher_factory(db_path()).encrypt(api_key.encode("utf-8")).decode("ascii")
        except Exception:
            raise HTTPException(status_code=503, detail="密钥加密配置不可用，未保存 API Key") from None
        conn = db()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO ip_reputation_settings(id,encrypted_api_key,updated_at) VALUES(1,?,?)",
                (encrypted, int(time.time())),
            )
            # A previous invalid key or a temporary provider outage may have been
            # cached for a short time. Do not let that stale failure survive key rotation.
            conn.execute("""DELETE FROM ip_reputation_cache
                WHERE CASE WHEN json_valid(result_json)
                    THEN json_extract(result_json, '$.status') ELSE '' END != 'checked'""")
            conn.execute("DELETE FROM ip_reputation_health")
            conn.commit()
            return JSONResponse({"ok": True, "configured": True, "message": "AbuseIPDB Key 已加密保存；不会返回或下发到节点"})
        finally:
            conn.close()

    @app.delete("/api/v1/ip-reputation/settings")
    def delete_settings() -> JSONResponse:
        conn = db()
        try:
            conn.execute("DELETE FROM ip_reputation_settings WHERE id=1")
            conn.execute("DELETE FROM ip_reputation_health")
            conn.commit()
            return JSONResponse({"ok": True, "configured": False})
        finally:
            conn.close()

    @app.post("/api/v1/ip-reputation/test")
    async def test_settings() -> JSONResponse:
        """Verify the saved credential with one explicit, fixed public-IP lookup."""
        def lookup() -> dict:
            conn = db()
            try:
                return check_ip(
                    conn, API_TEST_IP, db_path, cipher_factory, force_refresh=True
                )
            finally:
                conn.close()

        return JSONResponse(await run_in_threadpool(lookup))

    @app.post("/api/v1/ip-reputation/check")
    async def query_ip(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body") from None
        if not isinstance(payload, dict) or set(payload) != {"ip"}:
            raise HTTPException(status_code=400, detail="仅接受 ip 字段")
        ip = normalize_public_ip(payload.get("ip"))

        def lookup() -> dict:
            conn = db()
            try:
                return check_ip(conn, ip, db_path, cipher_factory)
            finally:
                conn.close()

        return JSONResponse(await run_in_threadpool(lookup))
