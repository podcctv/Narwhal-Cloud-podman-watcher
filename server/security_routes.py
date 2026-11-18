"""Security observability API routes (SNI whitelist violations, RFW & auto-update health)."""
import json
import time
from typing import Any, Callable, Dict, List

from fastapi import APIRouter
from fastapi.responses import JSONResponse


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

    app.include_router(router)
