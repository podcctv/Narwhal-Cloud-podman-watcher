"""Security observability & dynamic policy routes (SNI whitelist, service audit, RFW & node health)."""
import json
import re
import time
from typing import Any, Callable, Dict, List

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

DEFAULT_SNI_WHITELIST: List[str] = [
    "dl-cdn.alpinelinux.org",
    "deb.debian.org",
    "crates.io",
    "pypi.org",
    "rubygems.org",
    "addons.mozilla.org",
    "formulae.brew.sh",
    "static.rust-lang.org",
    "cpan.org",
]
DEFAULT_DISALLOWED_PROTOCOLS: List[str] = ["vmess", "trojan"]
_POLICY_KEY = "dynamic_security_policy"


def _default_policy() -> Dict[str, Any]:
    return {
        "sni_enforcement": True,
        "block_cn_missing_sni": True,
        "sni_whitelist": list(DEFAULT_SNI_WHITELIST),
        "service_audit_enabled": True,
        "disallowed_protocols": list(DEFAULT_DISALLOWED_PROTOCOLS),
        "updated_at": 0,
    }


def get_dynamic_security_policy(conn: Any) -> Dict[str, Any]:
    base = _default_policy()
    try:
        row = conn.execute("SELECT value FROM system_settings WHERE key=?", (_POLICY_KEY,)).fetchone()
    except Exception:
        return base
    if not row or not row[0]:
        return base
    try:
        stored = json.loads(row[0])
    except Exception:
        return base
    if not isinstance(stored, dict):
        return base
    if isinstance(stored.get("sni_enforcement"), bool):
        base["sni_enforcement"] = stored["sni_enforcement"]
    if isinstance(stored.get("block_cn_missing_sni"), bool):
        base["block_cn_missing_sni"] = stored["block_cn_missing_sni"]
    if isinstance(stored.get("service_audit_enabled"), bool):
        base["service_audit_enabled"] = stored["service_audit_enabled"]
    if isinstance(stored.get("sni_whitelist"), list) and stored["sni_whitelist"]:
        base["sni_whitelist"] = [str(x).strip().lower() for x in stored["sni_whitelist"] if str(x).strip()]
    if isinstance(stored.get("disallowed_protocols"), list):
        base["disallowed_protocols"] = [str(x).strip().lower() for x in stored["disallowed_protocols"] if str(x).strip()]
    if isinstance(stored.get("updated_at"), int):
        base["updated_at"] = stored["updated_at"]
    return base


def save_dynamic_security_policy(conn: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid security policy payload")
    current = get_dynamic_security_policy(conn)
    if "sni_enforcement" in payload:
        current["sni_enforcement"] = bool(payload["sni_enforcement"])
    if "block_cn_missing_sni" in payload:
        current["block_cn_missing_sni"] = bool(payload["block_cn_missing_sni"])
    if "service_audit_enabled" in payload:
        current["service_audit_enabled"] = bool(payload["service_audit_enabled"])
    if "sni_whitelist" in payload:
        raw_list = payload["sni_whitelist"]
        if not isinstance(raw_list, list) or not raw_list or len(raw_list) > 256:
            raise HTTPException(status_code=400, detail="sni_whitelist must contain 1..256 domains")
        cleaned: List[str] = []
        for item in raw_list:
            d = str(item or "").strip().rstrip(".").lower()
            if not re.fullmatch(r"[a-z0-9._-]{1,253}", d):
                raise HTTPException(status_code=400, detail=f"invalid SNI domain: {d}")
            if d not in cleaned:
                cleaned.append(d)
        current["sni_whitelist"] = cleaned
    if "disallowed_protocols" in payload:
        raw_protos = payload["disallowed_protocols"]
        if not isinstance(raw_protos, list) or len(raw_protos) > 32:
            raise HTTPException(status_code=400, detail="disallowed_protocols must be a list of <= 32 items")
        cleaned_p: List[str] = []
        for item in raw_protos:
            p = str(item or "").strip().lower()
            if not re.fullmatch(r"[a-z0-9_-]{1,32}", p):
                raise HTTPException(status_code=400, detail=f"invalid protocol name: {p}")
            if p not in cleaned_p:
                cleaned_p.append(p)
        current["disallowed_protocols"] = cleaned_p
    current["updated_at"] = int(time.time())
    conn.execute(
        "INSERT INTO system_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (_POLICY_KEY, json.dumps(current, ensure_ascii=False)),
    )
    conn.commit()
    return current


def collect_sni_and_node_health(
    conn: Any,
    *,
    now: int,
    stale_seconds: int,
    app_version: str,
    limit: int = 100,
) -> Dict[str, Any]:
    limit = max(1, min(limit, 500))
    sni_rows = conn.execute(
        """
        SELECT id, host_id, runtime, project, container_name, severity, status, last_seen, details_json
        FROM security_alerts
        WHERE alert_type='sni_whitelist_violation'
        ORDER BY last_seen DESC, id DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    sni_items: List[Dict[str, Any]] = []
    disallowed_counts: Dict[str, int] = {}
    cn_missing_count = 0
    for row in sni_rows:
        try:
            details = json.loads(row["details_json"] or "{}")
        except Exception:
            details = {}
        sni = str(details.get("sni") or "").strip()
        reason = str(details.get("reason") or "").strip()
        if reason == "missing_or_invalid_sni_cn" or not sni:
            cn_missing_count += 1
        else:
            disallowed_counts[sni] = disallowed_counts.get(sni, 0) + 1
        sni_items.append(
            {
                "id": row["id"],
                "host_id": row["host_id"],
                "runtime": row["runtime"],
                "project": row["project"],
                "container_name": row["container_name"],
                "severity": row["severity"],
                "status": row["status"],
                "last_seen": row["last_seen"],
                "sni": sni,
                "dst_port": details.get("dst_port"),
                "proto": details.get("proto") or "tls",
                "reason": reason,
            }
        )
    top_disallowed = [
        {"sni": k, "count": v}
        for k, v in sorted(disallowed_counts.items(), key=lambda x: (-x[1], x[0]))[:20]
    ]

    host_rows = conn.execute(
        "SELECT host_id, agent_version, last_seen FROM hosts WHERE last_seen >= ? ORDER BY host_id",
        (now - stale_seconds,),
    ).fetchall()
    rfw_unhealthy: List[Dict[str, Any]] = []
    auto_update_issues: List[Dict[str, Any]] = []
    for h in host_rows:
        hid = h["host_id"]
        aver = str(h["agent_version"] or "")
        hs = conn.execute(
            "SELECT payload_json FROM host_security WHERE host_id=? ORDER BY id DESC LIMIT 1",
            (hid,),
        ).fetchone()
        rfw: Dict[str, Any] = {}
        if hs and hs["payload_json"]:
            try:
                sec = json.loads(hs["payload_json"])
                rfw = sec.get("rfw_service_health") or sec.get("rfw") or {}
            except Exception:
                rfw = {}
        if isinstance(rfw, dict) and rfw.get("status") in {"not_installed", "stopped", "restart_loop"}:
            rfw_unhealthy.append(
                {
                    "host_id": hid,
                    "status": rfw.get("status"),
                    "reason": rfw.get("reason") or "",
                    "remediation": "请检查并安装/启用 rfw.service，并执行 /opt/narwhal-monitor/auto-update.sh client",
                }
            )
        rep = conn.execute(
            "SELECT payload_json FROM reports WHERE host_id=? ORDER BY id DESC LIMIT 1",
            (hid,),
        ).fetchone()
        auto_upd: Dict[str, Any] = {}
        if rep and rep["payload_json"]:
            try:
                rp = json.loads(rep["payload_json"])
                auto_upd = (rp.get("operations") or {}).get("auto_update") or {}
            except Exception:
                auto_upd = {}
        has_err = bool(isinstance(auto_upd, dict) and auto_upd.get("has_error"))
        if has_err or (app_version != "dev" and aver and aver != app_version):
            auto_update_issues.append(
                {
                    "host_id": hid,
                    "agent_version": aver,
                    "expected_version": app_version,
                    "last_seen": h["last_seen"],
                    "auto_update": auto_upd,
                }
            )

    return {
        "server_version": app_version,
        "sni_violations": {
            "total": len(sni_items),
            "cn_missing_sni_count": cn_missing_count,
            "top_disallowed_snis": top_disallowed,
            "items": sni_items,
        },
        "rfw_unhealthy_hosts": rfw_unhealthy,
        "auto_update_issues": auto_update_issues,
    }


def attach(app: Any, db_fn: Callable[[], Any], stale_seconds: int, app_version_fn: Callable[[], str]) -> None:
    router = APIRouter()

    @router.get("/api/v1/security/sni-and-node-health")
    def sni_and_node_health(limit: int = 100) -> JSONResponse:
        conn = db_fn()
        try:
            payload = collect_sni_and_node_health(
                conn,
                now=int(time.time()),
                stale_seconds=stale_seconds,
                app_version=app_version_fn(),
                limit=limit,
            )
            return JSONResponse(content=payload)
        finally:
            conn.close()

    @router.get("/api/v1/security/policy")
    def get_security_policy() -> JSONResponse:
        conn = db_fn()
        try:
            return JSONResponse(content=get_dynamic_security_policy(conn))
        finally:
            conn.close()

    @router.post("/api/v1/security/policy")
    def update_security_policy(payload: Dict[str, Any]) -> JSONResponse:
        conn = db_fn()
        try:
            return JSONResponse(content={"ok": True, "policy": save_dynamic_security_policy(conn, payload)})
        finally:
            conn.close()

    app.include_router(router)
