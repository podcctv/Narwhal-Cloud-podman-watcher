"""Authenticated operations API; all mutation targets are bounded and explicit."""
import asyncio
import hashlib
import json
import re
import sqlite3
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request
try:
    from . import operations as ops
    from . import fleet_updates
    from . import buyer_mapping
    from . import inbound_assessment, ip_reputation
    from . import upgrade_health
except ImportError:
    import operations as ops
    import fleet_updates
    import buyer_mapping
    import inbound_assessment, ip_reputation
    import upgrade_health


def attach(app, db, database_path, storage, cleanup, version, admin_name):
    router = APIRouter(prefix="/api/v1/ops")
    table_cache={}

    def bandwidth_auto_settings(saved, has_host_limit):
        configured = saved.get("auto_throttle") if isinstance(saved, dict) else None
        enabled = configured.get("enabled") if isinstance(configured, dict) else None
        if type(enabled) is not bool:
            enabled = bool(has_host_limit)
        enabled = bool(enabled and has_host_limit)
        return {
            "enabled": enabled,
            "threshold_percent": 80,
            "trigger_seconds": 300,
            "tier_percentages": [50, 25, 5],
            "minimum_mbps": 1,
            "recovery_percent": 50,
            "recovery_seconds": 600,
        }

    def rows(conn, query, params=()):
        return [dict(r) for r in conn.execute(query, params).fetchall()]

    def unpack(items):
        for item in items:
            if "payload" in item:
                item["data"] = ops.loads(item.pop("payload"))
        return items

    def queue(conn, host, action_type, params, user):
        row = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (host,)).fetchone()
        if not row or not row[0] or time.time()-row[1] > 900:
            raise HTTPException(409, "需要在线且支持节点身份的新版 Client")
        params["expected_node_id"] = row[0]
        now = int(time.time())
        return conn.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,'host','','__host__',?,?,'queued',?,?,?)", (host, action_type, json.dumps(params), user, now, now)).lastrowid

    def bandwidth_context(conn, host_id):
        host = conn.execute("SELECT node_id,last_seen,agent_version FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if not host:
            raise HTTPException(404, "主机不存在")
        report = conn.execute(
            "SELECT ts,payload_json FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        security = ops.loads(report["payload_json"], {}) if report else {}
        firewall = security.get("host_firewall") if isinstance(security.get("host_firewall"), dict) else {}
        inventory = firewall.get("interface_inventory") if isinstance(firewall.get("interface_inventory"), dict) else {}
        interfaces = []
        for item in inventory.get("interfaces", []) if isinstance(inventory.get("interfaces"), list) else []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name):
                continue
            interfaces.append({
                "name": name, "kind": str(item.get("kind") or "")[:40],
                "state": str(item.get("state") or "unknown")[:24],
                "is_default_route": item.get("is_default_route") is True,
                "runtimes": [runtime for runtime in item.get("runtimes", [])
                             if runtime in {"incus", "podman"}][:2]
                    if isinstance(item.get("runtimes"), list) else [],
                "network_names": [str(network)[:100] for network in item.get("network_names", [])
                                  if isinstance(network, str)][:16]
                    if isinstance(item.get("network_names"), list) else [],
            })
        latest_container_rows = conn.execute(
            """SELECT r.runtime,r.project,r.container_name,r.payload_json FROM reports r
               JOIN (SELECT runtime,project,container_name,MAX(ts) AS ts FROM reports
                     WHERE host_id=? AND ts>=? GROUP BY runtime,project,container_name) latest
                 ON latest.runtime=r.runtime AND latest.project=r.project
                AND latest.container_name=r.container_name AND latest.ts=r.ts
               WHERE r.host_id=? AND r.ts>=? ORDER BY r.container_name LIMIT 500""",
            (host_id, int(time.time()) - 900, host_id, int(time.time()) - 900),
        ).fetchall()
        containers = []
        for row in latest_container_rows:
            item = ops.loads(row["payload_json"], {})
            if row["runtime"] not in {"incus", "podman"}:
                continue
            name = str(row["container_name"] or "")
            container_id = str(item.get("id") or "")
            if not name or not container_id:
                continue
            containers.append({
                "runtime": row["runtime"], "project": str(row["project"] or ""),
                "container_name": name, "container_id": container_id,
            })
        settings_row = conn.execute("SELECT payload FROM ops_settings WHERE key=?", (f"manual_bandwidth:{host_id}",)).fetchone()
        saved = ops.loads(settings_row[0], {}) if settings_row else {}
        if not isinstance(saved, dict):
            saved = {}
        saved_limits = saved.get("limits", []) if isinstance(saved.get("limits"), list) else []
        has_host_limit = any(
            isinstance(item, dict) and item.get("scope") == "host"
            and (item.get("upload_mbps", 0) or item.get("download_mbps", 0))
            for item in saved_limits
        )
        reported = security.get("manual_bandwidth_limits") if isinstance(security.get("manual_bandwidth_limits"), dict) else {}
        return {
            "host_id": host_id, "expected_node_id": str(host["node_id"] or ""),
            "agent_version": str(host["agent_version"] or "unknown")[:80],
            "host_online": bool(host["node_id"] and int(time.time()) - int(host["last_seen"] or 0) <= 900),
            "sample_at": int(report["ts"] or 0) if report else 0,
            "interfaces": interfaces, "containers": containers,
            "policy": {"schema": 1, "revision": int(saved.get("revision") or 0),
                       "limits": saved_limits,
                       "auto_throttle": bandwidth_auto_settings(saved, has_host_limit)},
            "reported": reported,
        }

    def require_admin(request):
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(403, "只有管理员可以执行此运维操作")

    def require_operator(request):
        if getattr(request.state, "dashboard_role", "admin") not in {"admin", "operator"}:
            raise HTTPException(403, "只有管理员或运维人员可以查看此数据")

    @router.get("/session")
    def session(request: Request):
        return {"username": request.state.dashboard_user, "role": request.state.dashboard_role}

    @router.get("/overview")
    def overview():
        conn = db()
        try:
            hosts = unpack(rows(conn, "SELECT * FROM ops_hosts ORDER BY host_id LIMIT 500"))
            now = int(time.time())
            for host in hosts:
                host["stale"] = now-host["ts"] > 900
                health=host["data"].get("health",[])
                states={x.get("status") for x in health}
                host["status"] = "stale" if host["stale"] else "unavailable" if not health else "critical" if states & {"permission_denied","parse_error","failed","read_error"} else "partial" if states-{"healthy","idle"} else "healthy"
            # Hosts with older Clients are visible too, not silently healthy.
            known = {h["host_id"] for h in hosts}
            for h in rows(conn, "SELECT host_id,node_id,last_seen,agent_version FROM hosts ORDER BY host_id LIMIT 500"):
                if h["host_id"] not in known:
                    hosts.append({"node": h["node_id"] or h["host_id"], "host_id": h["host_id"], "ts": h["last_seen"], "status": "unavailable", "stale": now-h["last_seen"]>900, "data": {}})
            return {"hosts": hosts, "incidents": unpack(rows(conn, "SELECT * FROM ops_incidents ORDER BY last_seen DESC LIMIT 100")), "rechecks": rows(conn, "SELECT r.*,a.host_id,a.container_name,a.status AS execution_status,a.result_message FROM ops_rechecks r LEFT JOIN security_actions a ON a.id=r.action_id ORDER BY r.ts DESC LIMIT 100"), "actions": rows(conn, "SELECT id,host_id,container_name,action_type,status,result_message,attempts,updated_at FROM security_actions ORDER BY id DESC LIMIT 100"), "profiles": ops.PROFILES}
        finally:
            conn.close()

    @router.get("/storage")
    def storage_details():
        now=time.monotonic()
        cached=table_cache.get(database_path())
        if cached and now-cached[0]<60:
            return {**storage(),"tables":cached[1],"hour_retention_days":30,"day_retention_days":400}
        conn = db()
        try:
            # Large legacy databases must not monopolize a request with dbstat/count scans.
            deadline=time.monotonic()+3
            conn.set_progress_handler(lambda:int(time.monotonic()>deadline),2000)
            names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            try:
                sizes = dict(conn.execute("SELECT name,SUM(pgsize) FROM dbstat GROUP BY name"))
            except Exception:
                sizes = {}
            tables=[]
            for n in names:
                try:
                    count=conn.execute('SELECT COUNT(*) FROM "'+n.replace('"','""')+'"').fetchone()[0]
                except sqlite3.OperationalError:
                    count=None
                tables.append({"name":n,"bytes":sizes.get(n),"rows":count})
            table_cache.clear()
            table_cache[database_path()]=(now,tables)
            return {**storage(), "tables": tables, "hour_retention_days": 30, "day_retention_days": 400}
        finally:
            conn.close()

    @router.post("/storage/cleanup")
    async def cleanup_now():
        removed = await asyncio.to_thread(cleanup, force=True)
        return {"removed": removed, **storage()}

    @router.get("/traffic")
    def traffic(period: str = "day", days: int = 31, entity: str = ""):
        if period not in ("day", "hour"):
            raise HTTPException(400, "period must be day/hour")
        conn = db()
        try:
            items = unpack(rows(conn, "SELECT * FROM ops_meter ORDER BY host_id,name LIMIT 500"))
            now = int(time.time())
            month = int(ops.datetime.fromtimestamp(now, ops.TZ).replace(day=1,hour=0,minute=0,second=0,microsecond=0).timestamp())
            today = int((now+28800)//86400)*86400-28800
            for item in items:
                item["policy"] = ops.policy(conn, item["entity"])
                for label, cutoff in (("month", month), ("today", today)):
                    item[label] = dict(conn.execute("SELECT COALESCE(SUM(rx),0) AS rx,COALESCE(SUM(tx),0) AS tx,COALESCE(SUM(covered),0) AS covered,COALESCE(SUM(gaps),0) AS gaps,COALESCE(SUM(estimated),0) AS estimated FROM ops_rollups WHERE entity=? AND period='day' AND bucket>=?", (item["entity"], cutoff)).fetchone())
                item["data"].pop("baseline", None)
            return {"items": items, "buckets": rows(conn, "SELECT entity,bucket,rx,tx,covered,gaps,estimated,samples,cpu_sum/MAX(samples,1) AS cpu_avg,mem_sum/MAX(samples,1) AS mem_avg,peak_connections FROM ops_rollups WHERE period=? AND bucket>=? AND (?='' OR entity=?) ORDER BY bucket DESC LIMIT 2000", (period, now-max(1,min(400,days))*86400,entity,entity)), "timezone": "Asia/Shanghai"}
        finally:
            conn.close()

    @router.get("/policies")
    def policies():
        conn = db()
        try:
            return {"profiles": ops.PROFILES, "items": unpack(rows(conn, "SELECT * FROM ops_policies LIMIT 500"))}
        finally:
            conn.close()

    async def policy_input(request):
        payload = await request.json()
        entity = payload.get("entity", "")
        parts = ops.loads(entity, [])
        if not isinstance(parts,list) or len(parts)!=4 or not all(isinstance(x,str) and len(x)<=200 for x in parts):
            raise HTTPException(400, "entity 必须是精确的节点/运行时/项目/容器身份")
        entity = ops.identity(*parts)
        profile = payload.get("profile", "general")
        if profile not in ops.PROFILES:
            raise HTTPException(400, "unknown profile")
        rules = payload.get("rules", {})
        if not isinstance(rules,dict) or set(rules)-{"connections","rx_bps","http_rps","baseline_factor","monthly_quota_bytes","quota_warning","silent_until","bandwidth_mbps","bandwidth_ratio","bandwidth_duration_seconds"}:
            raise HTTPException(400, "unknown policy field")
        bounds = {"connections": (1,1000000), "rx_bps": (1,1e12), "http_rps": (1,1e6), "baseline_factor": (2,20), "monthly_quota_bytes": (0,1e18), "quota_warning": (.1,1), "silent_until": (0,time.time()+86400)}
        bounds.update(bandwidth_mbps=(0,1_000_000),bandwidth_ratio=(.5,1),bandwidth_duration_seconds=(600,86400))
        for key,value in rules.items():
            try:
                n = float(value)
            except (TypeError,ValueError):
                raise HTTPException(400, "policy values must be numeric")
            if not ops.math.isfinite(n) or not bounds[key][0]<=n<=bounds[key][1]:
                raise HTTPException(400, f"invalid {key}")
            rules[key] = n
        return entity,profile,rules

    @router.post("/policies/preview")
    async def preview(request: Request):
        entity,profile,rules = await policy_input(request)
        conn = db()
        try:
            return {"entity": entity, "before": ops.policy(conn, entity), "after": {**ops.PROFILES[profile], 'bandwidth_mbps':0, 'bandwidth_ratio':.9, 'bandwidth_duration_seconds':600, **rules}, "scope": "网络观测/基线/持续带宽提醒；实例带宽不继承主机值；不提醒流量额度，不自动停机，不解除弱认证与恶意进程处置"}
        finally:
            conn.close()

    @router.post("/policies")
    async def save_policy(request: Request):
        entity,profile,rules = await policy_input(request)
        conn = db()
        try:
            if not conn.execute("SELECT 1 FROM ops_hosts WHERE node=?", (ops.loads(entity)[0],)).fetchone():
                raise HTTPException(404, "node not found")
            conn.execute("INSERT INTO ops_policies VALUES(?,?,?,?) ON CONFLICT(entity) DO UPDATE SET profile=excluded.profile,payload=excluded.payload,updated_at=excluded.updated_at", (entity,profile,json.dumps(rules),int(time.time())))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @router.get("/incidents/{incident_id}")
    def incident(incident_id: int):
        conn = db()
        try:
            found = rows(conn, "SELECT * FROM ops_incidents WHERE id=?", (incident_id,))
            if not found:
                raise HTTPException(404, "incident not found")
            return {"incident": unpack(found)[0], "events": unpack(rows(conn, "SELECT * FROM ops_events WHERE incident_id=? ORDER BY ts,id LIMIT 500", (incident_id,)))}
        finally:
            conn.close()

    @router.post("/logs/discover")
    async def discover(request: Request):
        payload = await request.json()
        conn = db()
        try:
            action_id = queue(conn, str(payload.get("host_id", "")), "discover_access_logs", {}, request.state.dashboard_user)
            conn.commit()
            return {"action_id": action_id}
        finally:
            conn.close()

    @router.get("/services")
    def services():
        conn = db()
        try:
            return {"items": unpack(rows(conn, "SELECT * FROM ops_services LIMIT 500")), "results": unpack(rows(conn, "SELECT * FROM ops_service_results LIMIT 500"))}
        finally:
            conn.close()

    @router.get("/hosts/{host_id}/bandwidth-limits")
    def get_bandwidth_limits(host_id: str, request: Request):
        require_operator(request)
        if not host_id or len(host_id) > 200:
            raise HTTPException(400, "invalid host")
        conn = db()
        try:
            return bandwidth_context(conn, host_id)
        finally:
            conn.close()

    @router.put("/hosts/{host_id}/bandwidth-limits")
    async def put_bandwidth_limits(host_id: str, request: Request):
        require_admin(request)
        if not host_id or len(host_id) > 200:
            raise HTTPException(400, "invalid host")
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(400, "请求必须是有效 JSON") from None
        if (not isinstance(body, dict) or set(body) - {"limits", "auto_throttle"}
                or "limits" not in body or not isinstance(body["limits"], list)
                or len(body["limits"]) > 256):
            raise HTTPException(400, "limits 必须是最多 256 项的列表")
        auto_payload = body.get("auto_throttle")
        if auto_payload is not None and (
                not isinstance(auto_payload, dict) or set(auto_payload) != {"enabled"}
                or type(auto_payload.get("enabled")) is not bool):
            raise HTTPException(400, "auto_throttle 仅支持布尔 enabled 字段")
        conn = db()
        try:
            context = bandwidth_context(conn, host_id)
            if not context["host_online"] or not context["expected_node_id"]:
                raise HTTPException(409, "需要主机在线并上报节点身份")
            if int(time.time()) - int(context["sample_at"] or 0) > 900:
                raise HTTPException(409, "网卡和容器清单已过期，请等待主机重新上报")
            allowed_interfaces = {item["name"] for item in context["interfaces"] if item["state"] == "up"}
            known_containers = {
                (item["runtime"], item["project"], item["container_name"], item["container_id"])
                for item in context["containers"]
            }
            normalized = []
            identities = set()
            host_limit_count = 0
            for item in body["limits"]:
                if not isinstance(item, dict) or set(item) - {"scope", "interface", "runtime", "project", "container_name", "container_id", "upload_mbps", "download_mbps"}:
                    raise HTTPException(400, "带宽策略字段无效")
                scope = item.get("scope")
                upload = item.get("upload_mbps", 0)
                download = item.get("download_mbps", 0)
                if type(upload) is not int or type(download) is not int or not 0 <= upload <= 100000 or not 0 <= download <= 100000 or not (upload or download):
                    raise HTTPException(400, "上下行速率必须是 0–100000 之间的整数，且至少一项大于 0")
                if scope == "host":
                    interface = str(item.get("interface") or "")
                    if interface not in allowed_interfaces:
                        raise HTTPException(409, "母机网卡不在当前在线采集清单中")
                    host_limit_count += 1
                    key = ("host", interface)
                    entry = {"scope": "host", "interface": interface,
                             "upload_mbps": upload, "download_mbps": download}
                elif scope == "container":
                    runtime = str(item.get("runtime") or "")
                    project = str(item.get("project") or "")
                    name = str(item.get("container_name") or "")
                    container_id = str(item.get("container_id") or "")
                    if (runtime, project, name, container_id) not in known_containers:
                        raise HTTPException(409, "容器身份与最新采样不匹配；刷新后重新选择目标容器")
                    if len(name) > 200 or len(project) > 100 or not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,256}", container_id):
                        raise HTTPException(400, "容器身份无效")
                    key = ("container", runtime, project, name, container_id)
                    entry = {"scope": "container", "runtime": runtime, "project": project,
                             "container_name": name, "container_id": container_id,
                             "upload_mbps": upload, "download_mbps": download}
                else:
                    raise HTTPException(400, "scope 必须为 host 或 container")
                if key in identities:
                    raise HTTPException(400, "同一目标不能重复配置")
                identities.add(key)
                normalized.append(entry)
            if host_limit_count > 1:
                raise HTTPException(400, "每台母机只可选择一张网卡设置主机总限速")
            auto_enabled = (
                bool(auto_payload["enabled"]) if isinstance(auto_payload, dict)
                else bool(host_limit_count)
            )
            if auto_enabled and host_limit_count != 1:
                raise HTTPException(400, "自动阶梯限速需要先配置一张母机网卡及其上下行带宽")
            saved = context["policy"]
            policy = {
                "schema": 1, "host_id": host_id,
                "expected_node_id": context["expected_node_id"],
                "revision": int(saved.get("revision") or 0) + 1,
                "limits": normalized, "auto_throttle": {"enabled": auto_enabled},
                "updated_at": int(time.time()),
                "updated_by": request.state.dashboard_user,
            }
            conn.execute("INSERT OR REPLACE INTO ops_settings(key,payload) VALUES(?,?)",
                         (f"manual_bandwidth:{host_id}", json.dumps(policy, ensure_ascii=True)))
            conn.commit()
            return {"ok": True, "revision": policy["revision"], "limits": normalized,
                    "auto_throttle": bandwidth_auto_settings(policy, bool(host_limit_count)),
                    "apply": "主机 Agent 下一次动作轮询时应用；最多等待一个轮询周期"}
        finally:
            conn.close()

    @router.get("/service-inventory")
    def service_inventory(request: Request, host_id: str = "", runtime: str = "", limit: int = 200):
        limit = max(1, min(500, int(limit)))
        conn = db()
        try:
            filters = []
            params = []
            if host_id:
                filters.append("host_id=?")
                params.append(host_id[:200])
            if runtime in {"incus", "podman", "docker"}:
                filters.append("runtime=?")
                params.append(runtime)
            where = " WHERE " + " AND ".join(filters) if filters else ""
            current = rows(conn, "SELECT * FROM ops_service_inventory" + where + " ORDER BY observed_at DESC LIMIT ?", (*params, limit))
            can_view_owner = getattr(request.state, "dashboard_role", "admin") in {"admin", "operator"}
            buyer_owner_emails = {}
            buyer_owner_issues = {}
            if can_view_owner:
                buyer_owner_emails = {
                    (owner["host_id"], owner["runtime"], owner["project"], owner["container_name"], owner["vm_id"]): str(owner["user_email"] or "")
                    for owner in conn.execute(
                        """
                        SELECT host_id,runtime,project,container_name,vm_id,user_email
                        FROM buyer_targets WHERE source='upstream' AND enabled=1 AND scope='user'
                          AND user_email<>'' AND verified_at>=?
                        """,
                        (int(time.time()) - buyer_mapping.TTL,),
                    )
                }
                buyer_owner_issues = {
                    (issue["host_id"], issue["runtime"], issue["project"], issue["container_name"]): str(issue["reason"] or "")
                    for issue in conn.execute(
                        "SELECT host_id,runtime,project,container_name,reason FROM buyer_mapping_issues"
                    )
                }
            for item in current:
                item["listeners"] = ops.loads(item.pop("inventory_json", "[]"), [])
                item["coverage"] = item.pop("inventory_state", "unavailable")
                report = conn.execute(
                    "SELECT payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1",
                    (item["host_id"], item["runtime"], item["project"], item["container_name"]),
                ).fetchone()
                payload = ops.loads(report[0] if report else "{}")
                container_id = str(payload.get("id") or "")[:200]
                owner = conn.execute(
                    "SELECT user_email,user_note,updated_at FROM container_user_notes WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND container_id=?",
                    (item["host_id"], item["runtime"], item["project"], item["container_name"], container_id),
                ).fetchone() if container_id else None
                item["container_id"] = container_id
                manual_email = str(owner["user_email"] or "") if can_view_owner and owner else ""
                upstream_email = buyer_owner_emails.get((item["host_id"], item["runtime"], item["project"], item["container_name"], container_id), "") if can_view_owner else ""
                mapping_issue = buyer_owner_issues.get((item["host_id"], item["runtime"], item["project"], item["container_name"]), "") if can_view_owner else ""
                item["owner"] = {
                    "user_email": manual_email or upstream_email,
                    "user_email_source": "manual" if manual_email else "upstream" if upstream_email else "unmatched" if mapping_issue else "",
                    "user_email_status": mapping_issue if not (manual_email or upstream_email) else "",
                    "user_note": owner["user_note"] if can_view_owner and owner else "",
                    "updated_at": int(owner["updated_at"] or 0) if can_view_owner and owner else 0,
                }
            changes = rows(conn, "SELECT * FROM ops_service_inventory_changes" + where + " ORDER BY ts DESC,id DESC LIMIT ?", (*params, min(1000, limit * 2)))
            for item in changes:
                item["data"] = ops.loads(item.pop("payload", "{}"))
                item["owner"] = next(({
                    "user_email": current_item["owner"]["user_email"],
                    "user_email_source": current_item["owner"]["user_email_source"],
                    "user_email_status": current_item["owner"]["user_email_status"],
                    "user_note": current_item["owner"]["user_note"],
                    "updated_at": current_item["owner"]["updated_at"],
                } for current_item in current if (current_item["host_id"], current_item["runtime"], current_item["project"], current_item["container_name"]) == (item["host_id"], item["runtime"], item["project"], item["container_name"])), {"user_email": "", "user_email_source": "", "user_email_status": "", "user_note": "", "updated_at": 0})
            return {"items": current, "changes": changes, "retention_days": 90}
        finally:
            conn.close()

    @router.get("/alerts/replays")
    def alert_replays(request: Request):
        require_operator(request)
        conn = db()
        try:
            items = rows(conn, "SELECT * FROM ops_alert_replays ORDER BY created_at DESC,id DESC LIMIT 50")
            for item in items:
                item["assessment"] = ops.loads(item.pop("assessment_json", "{}"), {})
                item["feedback"] = rows(conn, "SELECT id,replay_id,source_ip,category,note,requested_by,created_at FROM ops_alert_feedback WHERE replay_id=? ORDER BY id DESC LIMIT 50", (item["id"],))
            return {"items": items, "feedback_categories": ["likely_external_scan", "legitimate_business", "false_positive", "confirmed_abuse", "insufficient_evidence"], "enforcement_effect": "none"}
        finally:
            conn.close()

    @router.post("/alerts/replay")
    async def replay_alert(request: Request):
        require_operator(request)
        try:
            payload = await request.json()
            host_id = str(payload.get("host_id") or "").strip()[:200]
            runtime = str(payload.get("runtime") or "")
            project = str(payload.get("project") or "")[:100]
            container_name = str(payload.get("container_name") or "").strip()[:200]
            minutes = int(payload.get("minutes", 60))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(400, "请提供有效的目标容器和回放时间窗") from None
        if not host_id or not container_name or runtime not in {"incus", "podman"} or not 15 <= minutes <= 60:
            raise HTTPException(400, "回放仅支持 Incus / Podman，时间窗为 15-60 分钟")
        now = int(time.time())
        conn = db()
        try:
            sampled = conn.execute(
                "SELECT id,ts,payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND ts BETWEEN ? AND ? ORDER BY ts DESC,id DESC LIMIT 60",
                (host_id, runtime, project, container_name, now-minutes*60, now),
            ).fetchall()
            if not sampled:
                raise HTTPException(409, "所选时间窗内没有采样记录；没有足够数据可回放")
            digest = hashlib.sha256()
            for row in sampled:
                digest.update(f"{row['id']}:{row['ts']}:".encode())
                digest.update(str(row["payload_json"] or "").encode())
                digest.update(b"\n")
            assessment = inbound_assessment.assess(sampled, now=now, lookback_seconds=minutes*60)
            cursor = conn.execute(
                "INSERT INTO ops_alert_replays(host_id,runtime,project,container_name,created_at,lookback_minutes,input_digest,report_count,assessment_json) VALUES(?,?,?,?,?,?,?,?,?)",
                (host_id, runtime, project, container_name, now, minutes, digest.hexdigest(), len(sampled), json.dumps(assessment, ensure_ascii=False)),
            )
            replay_id = int(cursor.lastrowid)
            conn.commit()
            return {"id": replay_id, "host_id": host_id, "runtime": runtime, "project": project,
                    "container_name": container_name, "created_at": now, "lookback_minutes": minutes,
                    "input_digest": digest.hexdigest(), "report_count": len(sampled), "assessment": assessment,
                    "feedback": [], "enforcement_effect": "none"}
        finally:
            conn.close()

    @router.post("/alerts/replays/{replay_id}/feedback")
    async def alert_replay_feedback(replay_id: int, request: Request):
        require_operator(request)
        allowed = {"likely_external_scan", "legitimate_business", "false_positive", "confirmed_abuse", "insufficient_evidence"}
        try:
            payload = await request.json()
            source_ip = str(payload.get("source_ip") or "").strip()[:64]
            category = str(payload.get("category") or "")
            note = "".join(ch for ch in str(payload.get("note") or "") if ch >= " " and ch != "\x7f")[:500]
            note = re.sub(r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", note)
        except (TypeError, AttributeError):
            raise HTTPException(400, "反馈内容格式无效") from None
        if category not in allowed:
            raise HTTPException(400, "反馈类别无效")
        conn = db()
        try:
            replay = conn.execute("SELECT assessment_json FROM ops_alert_replays WHERE id=?", (replay_id,)).fetchone()
            if not replay:
                raise HTTPException(404, "找不到这次回放记录")
            assessment = ops.loads(replay["assessment_json"], {})
            known_ips = {str(item.get("ip") or "") for item in assessment.get("assessments", []) if isinstance(item, dict)}
            if source_ip and source_ip not in known_ips:
                raise HTTPException(400, "来源 IP 不属于这次回放的采样结果")
            cursor = conn.execute(
                "INSERT INTO ops_alert_feedback(replay_id,alert_id,host_id,runtime,project,container_name,source_ip,category,note,requested_by,created_at) SELECT ?,0,host_id,runtime,project,container_name,?,?,?,?,? FROM ops_alert_replays WHERE id=?",
                (replay_id, source_ip, category, note, str(request.state.dashboard_user)[:100], int(time.time()), replay_id),
            )
            conn.commit()
            return {"id": int(cursor.lastrowid), "replay_id": replay_id, "source_ip": source_ip,
                    "category": category, "note": note, "enforcement_effect": "none"}
        finally:
            conn.close()

    @router.get("/evidence")
    def connection_evidence(host_id: str, runtime: str, container_name: str, project: str = "", minutes: int = 1440):
        if runtime not in {"incus", "podman", "docker"} or not host_id or not container_name:
            raise HTTPException(400, "需要明确指定主机、运行时与容器")
        minutes = max(15, min(1440, int(minutes)))
        now = int(time.time())
        conn = db()
        try:
            raw_rows = conn.execute(
                "SELECT ts,payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND ts>=? ORDER BY ts DESC LIMIT 300",
                (host_id[:200], runtime, project[:100], container_name[:200], now - minutes * 60),
            ).fetchall()
            assessment = inbound_assessment.assess(raw_rows, now=now, lookback_seconds=min(minutes * 60, 3600))
            by_ip = {item["ip"]: item for item in assessment.get("assessments", []) if isinstance(item, dict)}
            reputation_cache = {}
            timeline = []
            for row in reversed(raw_rows[:60]):
                payload = ops.loads(row["payload_json"])
                security = payload.get("security") if isinstance(payload.get("security"), dict) else {}
                deep_sample = payload.get("deep_sample") if isinstance(payload.get("deep_sample"), dict) else {}
                signals = security.get("inbound_source_signals") if isinstance(security.get("inbound_source_signals"), list) else []
                connection_ips = deep_sample.get("connection_ips") if isinstance(deep_sample.get("connection_ips"), list) else []
                if not connection_ips:
                    connection_ips = security.get("connection_ips") if isinstance(security.get("connection_ips"), list) else []
                inbound = deep_sample.get("inbound_ips") if isinstance(deep_sample.get("inbound_ips"), list) else []
                if not inbound:
                    inbound = security.get("inbound_ips") if isinstance(security.get("inbound_ips"), list) else []
                if not inbound:
                    inbound = [item for item in connection_ips if isinstance(item, dict) and ops.number(item.get("inbound")) > 0]
                socket_rows = deep_sample.get("communication_sockets") if isinstance(deep_sample.get("communication_sockets"), list) else []
                if not socket_rows:
                    socket_rows = security.get("communication_sockets") if isinstance(security.get("communication_sockets"), list) else []
                # Older agents did not report a summary object. Derive counts
                # from their actual captured socket rows when available; never
                # substitute zeros when both sources are absent.
                if not inbound and socket_rows:
                    grouped: dict[str, dict[str, Any]] = {}
                    for socket in socket_rows[:2000]:
                        if not isinstance(socket, dict) or socket.get("direction") != "inbound":
                            continue
                        ips = socket.get("original_remote_ips") if isinstance(socket.get("original_remote_ips"), list) else []
                        if not ips and socket.get("remote_ip"):
                            ips = [socket.get("remote_ip")]
                        for raw_ip in ips[:5]:
                            source_ip = str(raw_ip or "")[:64]
                            if not source_ip:
                                continue
                            item = grouped.setdefault(source_ip, {
                                "ip": source_ip, "inbound": 0, "outbound": 0,
                                "inbound_processes": [], "inbound_origin_confidence": "unknown",
                                "inbound_direction_evidence": [],
                            })
                            item["inbound"] = int(item["inbound"]) + 1
                            process_name = str(socket.get("process") or "")[:120]
                            try:
                                process_pid = int(socket.get("pid") or 0)
                            except (TypeError, ValueError, OverflowError):
                                process_pid = 0
                            if process_name and process_name != "unknown":
                                owner = {"process": process_name}
                                if process_pid > 0:
                                    owner["pid"] = process_pid
                                if owner not in item["inbound_processes"]:
                                    item["inbound_processes"].append(owner)
                            confidence = str(socket.get("origin_confidence") or "unknown")
                            if confidence == "confirmed" or item["inbound_origin_confidence"] == "unknown":
                                item["inbound_origin_confidence"] = confidence
                            evidence = str(socket.get("direction_evidence") or "")
                            if evidence and evidence not in item["inbound_direction_evidence"]:
                                item["inbound_direction_evidence"].append(evidence)
                    inbound = list(grouped.values())
                observed = {}
                for item in inbound[:20]:
                    if isinstance(item, dict) and item.get("ip"):
                        observed[str(item["ip"])[:64]] = item
                for item in signals[:20]:
                    if isinstance(item, dict) and item.get("ip"):
                        observed.setdefault(str(item["ip"])[:64], item)
                ips = []
                for ip, item in list(observed.items())[:20]:
                    reputation = reputation_cache.get(ip)
                    if ip not in reputation_cache:
                        cached = ip_reputation._cached_result(conn, ip, now)
                        reputation = cached if cached is not None else {"status": "not_cached", "message": "尚未查询 AbuseIPDB；不会在读取时间线时自动提交来源 IP"}
                        reputation_cache[ip] = reputation
                    ips.append({
                        "ip": ip,
                        "inbound": max(0, min(1_000_000, int(ops.number(item.get("inbound", item.get("flow_count", 0)))))),
                        "processes": item.get("inbound_processes") or item.get("processes") or [],
                        "origin_confidence": item.get("inbound_origin_confidence") or item.get("origin_confidence") or "unknown",
                        "direction_evidence": item.get("inbound_direction_evidence") or item.get("direction_evidence") or [],
                        "network_evidence": item.get("network_evidence") if isinstance(item.get("network_evidence"), dict) else item,
                        "assessment": by_ip.get(ip, {"classification": "insufficient_evidence", "identity_confirmed": False}),
                        "abuseipdb": reputation,
                    })
                attribution = deep_sample.get("connection_attribution") if isinstance(deep_sample.get("connection_attribution"), dict) else {}
                if not attribution:
                    attribution = security.get("connection_attribution") if isinstance(security.get("connection_attribution"), dict) else {}
                connection_metrics = security.get("connection_metrics") if isinstance(security.get("connection_metrics"), dict) else {}
                access = security.get("access_log") if isinstance(security.get("access_log"), dict) else {}
                connection_count = max(
                    0,
                    min(10_000_000, int(ops.number(connection_metrics.get("total", payload.get("conn_count", 0))))),
                    min(10_000_000, int(ops.number(deep_sample.get("connection_count")))) if deep_sample else 0,
                )
                raw_captured = attribution.get("captured_sockets")
                captured = None
                attributed = None
                confirmed_local = probable_local = confirmed_remote = probable_remote = unknown_direction = None
                if raw_captured is not None and (ops.number(raw_captured) > 0 or not socket_rows):
                    captured = max(0, min(5000, int(ops.number(raw_captured))))
                    attributed = max(0, min(captured, int(ops.number(attribution.get("process_attributed_sockets")))))
                    confirmed_local = max(0, min(captured, int(ops.number(attribution.get("confirmed_local_initiated")))))
                    probable_local = max(0, min(captured, int(ops.number(attribution.get("probable_local_initiated")))))
                    confirmed_remote = max(0, min(captured, int(ops.number(attribution.get("confirmed_remote_initiated")))))
                    probable_remote = max(0, min(captured, int(ops.number(attribution.get("probable_remote_initiated")))))
                    unknown_direction = max(0, min(captured, int(ops.number(attribution.get("unknown_direction")))))
                elif socket_rows:
                    captured = min(5000, len(socket_rows))
                    attributed = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and (ops.number(item.get("pid")) > 0 or item.get("process_attribution") == "attributed"))
                    confirmed_local = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and item.get("direction") == "outbound" and item.get("origin_confidence") == "confirmed")
                    probable_local = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and item.get("direction") == "outbound" and item.get("origin_confidence") == "probable")
                    confirmed_remote = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and item.get("direction") == "inbound" and item.get("origin_confidence") == "confirmed")
                    probable_remote = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and item.get("direction") == "inbound" and item.get("origin_confidence") == "probable")
                    unknown_direction = sum(1 for item in socket_rows[:5000] if isinstance(item, dict) and item.get("direction") not in ("inbound", "outbound"))
                conntrack_value = attribution.get("conntrack_available")
                if not isinstance(conntrack_value, bool):
                    conntrack_value = security.get("host_conntrack_available") if isinstance(security.get("host_conntrack_available"), bool) else None
                evidence_status = str(attribution.get("evidence_status") or "")
                if evidence_status == "unavailable":
                    captured = attributed = confirmed_local = probable_local = confirmed_remote = probable_remote = unknown_direction = None
                elif captured is None and connection_count == 0 and security.get("communication_detail_available") is True:
                    evidence_status = "no_connections"
                    captured = attributed = confirmed_local = probable_local = confirmed_remote = probable_remote = unknown_direction = 0
                elif captured is None or (captured == 0 and connection_count > 0):
                    evidence_status = "unavailable"
                    captured = attributed = confirmed_local = probable_local = confirmed_remote = probable_remote = unknown_direction = None
                elif not evidence_status:
                    evidence_status = "partial" if attribution.get("socket_snapshot_truncated") or security.get("communication_snapshot_truncated") else "available"
                if evidence_status == "no_connections" and connection_count > 0:
                    evidence_status = "unavailable"
                    captured = attributed = confirmed_local = probable_local = confirmed_remote = probable_remote = unknown_direction = None
                timeline.append({
                    "ts": int(row["ts"]),
                    "connection_count": connection_count,
                    "process_attribution": {
                        "status": evidence_status,
                        "captured": captured,
                        "attributed": attributed,
                        "confirmed_local": confirmed_local,
                        "probable_local": probable_local,
                        "confirmed_remote": confirmed_remote,
                        "probable_remote": probable_remote,
                        "unknown_direction": unknown_direction,
                        "conntrack_available": conntrack_value,
                        "conntrack_confirmed": int(ops.number(attribution.get("conntrack_confirmed_sockets"))) if captured is not None else None,
                        "source": str(attribution.get("source") or deep_sample.get("communication_source") or security.get("communication_source") or "unknown"),
                        "reason": str(attribution.get("unavailable_reason") or ("legacy_agent_missing_attribution" if evidence_status == "unavailable" else "")),
                    },
                    "access_log": {key: access.get(key) for key in ("requests", "requests_per_second", "readable_files", "parse_errors") if key in access},
                    "ips": ips,
                })
            return {
                "host_id": host_id, "runtime": runtime, "project": project, "container_name": container_name,
                "window_minutes": minutes, "sample_count": len(raw_rows), "timeline": timeline,
                "source_assessment": assessment,
                "interpretation": "TCP 建连、PID 归属或 AbuseIPDB 评分都不能单独证明用户身份或恶意意图；这里只展示对应采样证据。未查询的 IP 不会自动发送给第三方。",
            }
        finally:
            conn.close()

    @router.post("/logs/connect")
    async def connect_logs(request: Request):
        p=await request.json()
        paths=p.get("paths",[])
        host=str(p.get("host_id",""))
        if not isinstance(paths,list) or not 1<=len(paths)<=20 or any(not isinstance(x,str) or not re.fullmatch(r"/var/log/[A-Za-z0-9_./-]{1,200}",x) or ".." in x for x in paths):
            raise HTTPException(400,"日志路径仅支持 /var/log 内明确文件")
        conn=db()
        try:
            row=conn.execute("SELECT payload,ts FROM ops_hosts WHERE host_id=?",(host,)).fetchone()
            discovered={x.get("path") for x in ops.loads(row[0] if row else None).get("log_discovery",[]) if x.get("status") in {"healthy","idle"}}
            if not row or time.time()-row[1]>900 or not set(paths)<=discovered:
                raise HTTPException(409,"请先发现并验证可读取日志")
            action=queue(conn,host,"update_host_config",{"config":{"security_access_log_paths":paths}},request.state.dashboard_user)
            conn.commit()
            return {"action_id":action}
        finally:
            conn.close()

    @router.post("/services")
    async def save_service(request: Request):
        p = await request.json()
        kind = p.get("kind", "http")
        target = str(p.get("target", ""))
        u = urlsplit(target)
        if kind not in ("http","tcp") or u.scheme not in ({"http","https"} if kind=="http" else {"tcp"}) or not u.hostname or u.username or u.password or u.fragment or len(target)>500:
            raise HTTPException(400, "需要无凭据的 http(s):// 或 tcp://host:port 地址")
        try:
            port = u.port or (443 if u.scheme=="https" else 80 if kind=="http" else 0)
        except ValueError:
            port = 0
        if not 1<=port<=65535:
            raise HTTPException(400,"invalid port")
        conn = db()
        try:
            host = str(p.get("host_id", ""))
            if not conn.execute("SELECT 1 FROM hosts WHERE host_id=?", (host,)).fetchone():
                raise HTTPException(404,"host not found")
            if conn.execute("SELECT COUNT(*) FROM ops_services WHERE host_id=?", (host,)).fetchone()[0]>=20:
                raise HTTPException(409,"每节点最多 20 个服务")
            config = {"kind":kind,"target":target,"latency_warning_ms": max(100,min(30000,ops.number(p.get("latency_warning_ms",1000)))),"tls_warning_days":14}
            cur = conn.execute("INSERT INTO ops_services(host_id,name,payload) VALUES(?,?,?)", (host,str(p.get("name",u.hostname))[:100],json.dumps(config)))
            conn.commit()
            return {"id":cur.lastrowid}
        finally:
            conn.close()

    @router.delete("/services/{service_id}")
    def delete_service(service_id: int):
        conn=db()
        try:
            conn.execute("DELETE FROM ops_services WHERE id=?",(service_id,))
            conn.execute("DELETE FROM ops_service_results WHERE service_id=?",(service_id,))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.get("/upgrades")
    def upgrades():
        conn=db()
        try:
            now = int(time.time())
            nodes = rows(conn,"SELECT host_id,node_id,agent_version,last_seen FROM hosts ORDER BY host_id LIMIT 500")
            for item in nodes:
                report = conn.execute("SELECT ts,payload FROM ops_hosts WHERE host_id=? AND node=?", (item["host_id"], item["node_id"])).fetchone()
                item["last_report_at"] = int(report["ts"] or 0) if report else 0
                item["report_stale"] = not report or now - int(report["ts"] or 0) > 900
                op_data = ops.loads(report["payload"] if report else "{}")
                item["managed_upgrade"] = bool(op_data.get("managed_upgrade"))
                action = conn.execute("SELECT id,action_type,status,result_message,updated_at,attempts FROM security_actions WHERE host_id=? AND action_type IN ('managed_upgrade','managed_rollback') ORDER BY id DESC LIMIT 1", (item["host_id"],)).fetchone()
                item["latest_update"] = dict(action) if action else None
            progress = rows(conn,"SELECT n.*,u.version,u.revision,u.status AS campaign_status,u.payload AS campaign_payload FROM ops_upgrade_nodes n JOIN ops_upgrades u ON u.id=n.campaign ORDER BY n.campaign DESC LIMIT 500")
            for item in progress:
                current = conn.execute("SELECT agent_version,last_seen FROM hosts WHERE host_id=?", (item["host_id"],)).fetchone()
                item["target_version"] = str(item.get("version") or "unknown")
                item["actual_version"] = str(current["agent_version"] or "unknown") if current else "unknown"
                item["node_last_seen"] = int(current["last_seen"] or 0) if current else 0
                item["version_matches_target"] = item["actual_version"] == item["target_version"]
                action = conn.execute("SELECT action_type,status,result_message,updated_at,attempts FROM security_actions WHERE id=?", (item.get("action_id"),)).fetchone() if item.get("action_id") else None
                item["action"] = dict(action) if action else None
                metadata = ops.loads(item.pop("campaign_payload", "{}"))
                item["manual_attempts"] = int((metadata.get("attempts") or {}).get(item["host_id"], 0))
                item.pop("campaign_status", None)
            return {"automatic":fleet_updates.settings(conn),"nodes":nodes,"campaigns":unpack(rows(conn,"SELECT * FROM ops_upgrades ORDER BY id DESC LIMIT 50")),"progress":progress,"server_version":version()}
        finally:
            conn.close()

    @router.post("/upgrades/automatic")
    async def automatic_upgrades(request:Request):
        p=await request.json()
        if not isinstance(p.get('enabled'),bool):
            raise HTTPException(400,'enabled must be boolean')
        conn=db()
        try:
            cfg=fleet_updates.settings(conn)
            host=p.get('resume_host')
            if host is not None and host not in cfg['holds']:
                raise HTTPException(400,'node is not held')
            fleet_updates.save(conn,{**cfg,'enabled':p['enabled'],'holds':[h for h in cfg['holds'] if h!=host]})
            conn.commit()
            return {'ok':True}
        finally:
            conn.close()

    @router.post("/upgrades")
    async def create_upgrade(request:Request):
        require_admin(request)
        p=await request.json()
        revision=str(p.get("revision",""))
        target_version=str(p.get("version",""))
        hosts=p.get("hosts",[])
        if not re.fullmatch(r"[0-9a-f]{40}",revision) or not re.fullmatch(r"\d+\.\d+\.\d+",target_version) or not isinstance(hosts,list) or not 1<=len(hosts)<=100 or len(set(hosts))!=len(hosts):
            raise HTTPException(400,"需要固定 SHA、版本和不重复的 1-100 个节点")
        if target_version!=version():
            raise HTTPException(409,"请先将 Server 升级到目标版本")
        # Trusted fixed repository; callers cannot submit arbitrary download URLs.
        def resolve():
            req=urllib.request.Request("https://api.github.com/repos/podcctv/Narwhal-Cloud-podman-watcher/commits/main",headers={"User-Agent":"Narwhal-Operations"})
            with urllib.request.urlopen(req,timeout=10) as r:
                return json.load(r)["sha"]
        try:
            actual=await asyncio.to_thread(resolve)
        except Exception:
            raise HTTPException(503,"无法验证 fork main，未下发升级")
        if actual!=revision:
            raise HTTPException(409,"升级 SHA 必须是已发布的 fork main")
        conn=db()
        try:
            for host in hosts:
                found=conn.execute("SELECT payload FROM ops_hosts WHERE host_id=?",(host,)).fetchone()
                if not found or not ops.loads(found[0]).get("managed_upgrade"):
                    raise HTTPException(409,f"{host} 未启用管理升级（需要新版主机 Agent）")
            now=int(time.time())
            campaign=conn.execute("INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES(?,?,'canary',?,?)",(target_version,revision,now,json.dumps({"hosts":hosts,"canary":hosts[0],"attempts":{h:(1 if i==0 else 0) for i,h in enumerate(hosts)}}))).lastrowid
            for i,host in enumerate(hosts):
                old=conn.execute("SELECT agent_version FROM hosts WHERE host_id=?",(host,)).fetchone()[0]
                action=queue(conn,host,"managed_upgrade",{"revision":revision,"version":target_version,"campaign_id":campaign},request.state.dashboard_user) if i==0 else None
                conn.execute("INSERT INTO ops_upgrade_nodes VALUES(?,?,?,?,?)",(campaign,host,action,"dispatched" if i==0 else "pending",old))
            conn.commit()
            return {"id":campaign,"canary":hosts[0]}
        finally:
            conn.close()

    @router.post("/upgrades/{campaign}/promote")
    def promote(campaign:int,request:Request):
        require_admin(request)
        conn=db()
        try:
            row=conn.execute("SELECT * FROM ops_upgrades WHERE id=?",(campaign,)).fetchone()
            if not row or row["status"]!="canary" or not conn.execute("SELECT 1 FROM ops_upgrade_nodes WHERE campaign=? AND status='verified'",(campaign,)).fetchone():
                raise HTTPException(409,"灰度节点尚未验证目标版本")
            if ops.loads(row['payload']).get('automatic'):
                raise HTTPException(409,'自动发布由协调器完成健康观察和分批推广，请勿手动跳过')
            metadata = ops.loads(row["payload"])
            canary = conn.execute(
                "SELECT n.host_id,n.status,n.action_id,a.status AS action_status,a.updated_at,a.params_json "
                "FROM ops_upgrade_nodes n LEFT JOIN security_actions a ON a.id=n.action_id "
                "WHERE n.campaign=? AND n.status='verified' ORDER BY n.host_id LIMIT 1",
                (campaign,),
            ).fetchone()
            if not canary or not canary["action_id"] or canary["action_status"] != "succeeded":
                raise HTTPException(409, "灰度升级回执尚未成功确认")
            canary_params = ops.loads(canary["params_json"], {})
            healthy, failed_sources = upgrade_health.post_upgrade_observation(
                conn, canary["host_id"], canary_params.get("expected_node_id"), row["version"],
                canary["updated_at"], int(time.time()), fleet_updates.ROLLOUT_SOAK_SECONDS,
            )
            if not healthy:
                raise HTTPException(409, "灰度节点尚未通过升级后健康观察：" + "、".join(failed_sources))
            attempts = metadata.setdefault("attempts", {})
            running = conn.execute(
                "SELECT COUNT(*) FROM security_actions WHERE action_type IN ('managed_upgrade','managed_rollback') AND status IN ('queued','dispatched','running')"
            ).fetchone()[0]
            slots = max(0, min(fleet_updates.ROLLOUT_BATCH_SIZE, 3 - int(running)))
            if slots <= 0:
                raise HTTPException(409, "当前已有 3 个 Agent 升级任务运行；请稍后再推进该批次")
            wave_hosts = []
            for n in conn.execute("SELECT host_id FROM ops_upgrade_nodes WHERE campaign=? AND status='pending' ORDER BY host_id LIMIT ?",(campaign,slots)).fetchall():
                host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (n[0],)).fetchone()
                if not host or not host["node_id"] or int(time.time()) - int(host["last_seen"] or 0) > 900:
                    continue
                action=queue(conn,n[0],"managed_upgrade",{"revision":row["revision"],"version":row["version"],"campaign_id":campaign},request.state.dashboard_user)
                conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?",(action,campaign,n[0]))
                attempts[n[0]] = int(attempts.get(n[0], 0)) + 1
                wave_hosts.append(n[0])
            metadata["rollout_wave"] = 1
            metadata["rollout_wave_hosts"] = wave_hosts
            if wave_hosts:
                metadata["rollout_waiting_for_health"] = {
                    "wave": 1,
                    "hosts": wave_hosts,
                    "since": int(time.time()),
                }
            conn.execute("UPDATE ops_upgrades SET payload=? WHERE id=?", (json.dumps(metadata), campaign))
            conn.execute("UPDATE ops_upgrades SET status='rollout' WHERE id=?",(campaign,))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.post("/upgrades/{campaign}/{host_id}/retry")
    async def retry_upgrade(campaign: int, host_id: str, request: Request):
        require_admin(request)
        conn = db()
        try:
            row = conn.execute("SELECT * FROM ops_upgrades WHERE id=?", (campaign,)).fetchone()
            node = conn.execute("SELECT * FROM ops_upgrade_nodes WHERE campaign=? AND host_id=?", (campaign, host_id)).fetchone()
            if not row or not node or node["status"] != "failed" or row["status"] not in {"canary", "rollout", "paused"}:
                raise HTTPException(409, "只有灰度、分批发布或已暂停发布中的失败节点可重试")
            active = conn.execute(
                "SELECT a.host_id FROM security_actions a JOIN ops_upgrade_nodes n ON n.action_id=a.id "
                "WHERE n.campaign=? AND a.id<>COALESCE(?,0) AND a.action_type IN ('managed_upgrade','managed_rollback') "
                "AND a.status IN ('queued','dispatched','running') LIMIT 1",
                (campaign, node["action_id"]),
            ).fetchone()
            if active:
                raise HTTPException(409, f"节点 {active['host_id']} 仍在升级；等待当前任务结束后再重试")
            failed_action = conn.execute("SELECT action_type FROM security_actions WHERE id=?", (node["action_id"],)).fetchone() if node["action_id"] else None
            if failed_action and failed_action["action_type"] != "managed_upgrade":
                raise HTTPException(409, "该节点最近失败的是回滚操作；请从回滚入口重新核对后操作")
            metadata = ops.loads(row["payload"])
            attempts = metadata.setdefault("attempts", {})
            if int(attempts.get(host_id, 0)) >= 3:
                raise HTTPException(409, "该发布对节点的尝试已达 3 次上限，请先回滚或创建新版本")
            host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (host_id,)).fetchone()
            if not host or not host["node_id"] or time.time() - int(host["last_seen"] or 0) > 900:
                raise HTTPException(409, "节点离线或上报过期，未重试")
            previous_action = conn.execute("SELECT params_json FROM security_actions WHERE id=?", (node["action_id"],)).fetchone() if node["action_id"] else None
            old_node = ops.loads(previous_action["params_json"] if previous_action else "{}").get("expected_node_id")
            if old_node and old_node != host["node_id"]:
                raise HTTPException(409, "节点身份已变化，需要重新核对目标")
            def resolve():
                req=urllib.request.Request("https://api.github.com/repos/podcctv/Narwhal-Cloud-podman-watcher/git/ref/heads/main",headers={"User-Agent":"Narwhal-Operations"})
                with urllib.request.urlopen(req,timeout=10) as response:
                    return json.load(response)["object"]["sha"]
            try:
                actual = await asyncio.to_thread(resolve)
            except Exception:
                raise HTTPException(503, "无法验证当前 main；未下发重试") from None
            if actual != row["revision"]:
                raise HTTPException(409, "该提交已不是当前 main；为避免部署旧代码，未重试")
            action = queue(conn, host_id, "managed_upgrade", {"revision": row["revision"], "version": row["version"], "campaign_id": campaign}, request.state.dashboard_user)
            attempts[host_id] = int(attempts.get(host_id, 0)) + 1
            if row["status"] == "paused":
                # A manual retry is not approval to resume the rollout. Keep the
                # campaign paused until an administrator rechecks health and resumes it.
                metadata["last_retry_at"] = int(time.time())
                metadata["last_retry_host"] = host_id
            conn.execute("UPDATE ops_upgrades SET payload=? WHERE id=?", (json.dumps(metadata), campaign))
            conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?", (action, campaign, host_id))
            conn.commit()
            return {"action_id": action, "attempt": attempts[host_id]}
        finally:
            conn.close()

    @router.post("/upgrades/{campaign}/resume")
    def resume_upgrade(campaign: int, request: Request):
        require_admin(request)
        conn = db()
        try:
            row = conn.execute("SELECT * FROM ops_upgrades WHERE id=?", (campaign,)).fetchone()
            if not row or row["status"] != "paused":
                raise HTTPException(409, "该发布当前未处于暂停状态")
            active = conn.execute(
                "SELECT a.host_id FROM security_actions a JOIN ops_upgrade_nodes n ON n.action_id=a.id "
                "WHERE n.campaign=? AND a.action_type IN ('managed_upgrade','managed_rollback') "
                "AND a.status IN ('queued','dispatched','running') LIMIT 1",
                (campaign,),
            ).fetchone()
            if active:
                raise HTTPException(409, f"节点 {active['host_id']} 仍有升级任务未完成；等待其回报后再恢复发布")
            metadata = ops.loads(row["payload"])
            canary_host = str(metadata.get("canary") or "")
            canary = conn.execute("SELECT n.status,n.action_id,a.action_type,a.status AS action_status,a.params_json FROM ops_upgrade_nodes n LEFT JOIN security_actions a ON a.id=n.action_id WHERE n.campaign=? AND n.host_id=?", (campaign, canary_host)).fetchone()
            if not canary or canary["status"] != "verified":
                raise HTTPException(409, "灰度节点尚未通过新版健康检查")
            if canary["action_type"] != "managed_upgrade" or canary["action_status"] != "succeeded":
                raise HTTPException(409, "灰度升级回执尚未成功确认")
            blocked = conn.execute("SELECT host_id,status FROM ops_upgrade_nodes WHERE campaign=? AND status IN ('failed','rollback_queued') LIMIT 1", (campaign,)).fetchone()
            if blocked:
                raise HTTPException(409, f"节点 {blocked['host_id']} 状态为 {blocked['status']}；请先人工重试或回滚")
            host = conn.execute("SELECT node_id,last_seen,agent_version FROM hosts WHERE host_id=?", (canary_host,)).fetchone()
            action_params = ops.loads(canary["params_json"], {})
            if not host or host["agent_version"] != row["version"] or action_params.get("expected_node_id") != host["node_id"]:
                raise HTTPException(409, "灰度节点当前身份或 Agent 版本与本次发布不一致")
            ops_report = conn.execute("SELECT ts,payload FROM ops_hosts WHERE host_id=? AND node=?", (canary_host, host["node_id"] if host else "")).fetchone()
            latest_report = conn.execute("SELECT ts,payload_json FROM reports WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1", (canary_host,)).fetchone()
            if not host or not ops_report or not latest_report or int(ops_report["ts"] or 0) < int(time.time())-900 or int(latest_report["ts"] or 0) < int(time.time())-900:
                raise HTTPException(409, "灰度节点上报已过期，暂不能恢复发布")
            operation_data = ops.loads(ops_report["payload"], {})
            report_data = ops.loads(latest_report["payload_json"], {})
            healthy, _ = upgrade_health.check(operation_data, report_data)
            if not healthy:
                raise HTTPException(409, "最新主机审计或安全采样仍未通过；发布保持暂停")
            next_status = metadata.get("paused_from_status") if metadata.get("paused_from_status") in {"canary", "rollout"} else "canary"
            metadata["last_resume_at"] = int(time.time())
            metadata["last_resume_by"] = request.state.dashboard_user
            metadata.pop("paused_at", None)
            metadata.pop("paused_host", None)
            metadata.pop("pause_kind", None)
            metadata.pop("paused_from_status", None)
            metadata.pop("paused_reason", None)
            conn.execute("UPDATE ops_upgrades SET status=?,payload=? WHERE id=?", (next_status, json.dumps(metadata), campaign))
            conn.commit()
            return {"ok": True, "status": next_status}
        finally:
            conn.close()

    @router.post("/security/rescan")
    async def request_security_rescan(request: Request):
        require_admin(request)
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(400, "请求必须是有效 JSON") from None
        if not isinstance(payload, dict):
            raise HTTPException(400, "请求必须是 JSON 对象")
        host_id = str(payload.get("host_id") or "")[:200]
        conn = db()
        try:
            last = conn.execute("SELECT created_at FROM security_actions WHERE host_id=? AND action_type='host_security_rescan' ORDER BY id DESC LIMIT 1", (host_id,)).fetchone()
            if last and time.time() - int(last[0] or 0) < 900:
                raise HTTPException(429, "15 分钟内已经请求过复扫")
            action_id = queue(conn, host_id, "host_security_rescan", {}, request.state.dashboard_user)
            conn.commit()
            return {"action_id": action_id, "queued": True}
        finally:
            conn.close()

    @router.post("/upgrades/rollback")
    async def rollback(request:Request):
        require_admin(request)
        p=await request.json()
        conn=db()
        try:
            host=str(p.get("host_id",""))
            previous=conn.execute("SELECT n.previous_version,n.campaign,n.status,u.version,u.status AS campaign_status FROM ops_upgrade_nodes n JOIN ops_upgrades u ON u.id=n.campaign WHERE n.host_id=? AND n.action_id IS NOT NULL ORDER BY n.campaign DESC LIMIT 1",(host,)).fetchone()
            current=conn.execute("SELECT agent_version FROM hosts WHERE host_id=?",(host,)).fetchone()
            if not previous or not current:
                raise HTTPException(409,"没有该节点受管升级记录，无法确认回滚目标")
            if current[0] != previous["version"]:
                raise HTTPException(409,"节点当前版本不等于此发布目标，不能盲目回滚")
            if previous["status"] == "rollback_queued":
                raise HTTPException(409,"该节点已有回滚任务等待回报")
            action=queue(conn,host,"managed_rollback",{"version":previous["previous_version"],"campaign_id":previous["campaign"]},request.state.dashboard_user)
            metadata=ops.loads(conn.execute("SELECT payload FROM ops_upgrades WHERE id=?",(previous["campaign"],)).fetchone()[0])
            metadata.update(paused_at=int(time.time()),paused_host=host,pause_kind="manual_rollback",paused_from_status=previous["campaign_status"],paused_reason="管理员已请求回滚；自动发布保持暂停")
            conn.execute("UPDATE ops_upgrades SET status='paused',payload=? WHERE id=?",(json.dumps(metadata),previous["campaign"]))
            conn.execute("UPDATE ops_upgrade_nodes SET status='rollback_queued',action_id=? WHERE campaign=? AND host_id=?",(action,previous["campaign"],host))
            cfg=fleet_updates.settings(conn)
            fleet_updates.save(conn,{**cfg,'holds':sorted(set(cfg['holds']+[host]))})
            conn.commit()
            return {"action_id":action}
        finally:
            conn.close()

    @router.get("/backups")
    def backups(request: Request):
        require_admin(request)
        conn=db()
        try:
            row=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            folder=Path(database_path()).parent/"backups"
            drills=rows(conn,"SELECT id,backup_name,started_at,finished_at,duration_ms,status,message,bytes,sha256,details_json FROM ops_backup_drills ORDER BY started_at DESC,id DESC LIMIT 50")
            for drill in drills:
                drill["details"] = ops.loads(drill.pop("details_json", "{}"), {})
            latest={}
            for drill in drills:
                latest.setdefault(drill["backup_name"],drill)
            items=[]
            for path in sorted(folder.glob("monitor-*.db"),key=lambda item:item.stat().st_mtime,reverse=True)[:30]:
                if path.is_symlink() or not path.is_file():
                    continue
                items.append({"name":path.name,"bytes":path.stat().st_size,"ts":int(path.stat().st_mtime),"last_drill":latest.get(path.name)})
            settings=ops.loads(row[0]) if row else {"enabled":False,"interval_hours":24,"retention":7,"drill_enabled":True}
            settings.setdefault("drill_enabled", True)
            now=int(time.time())
            last_success=max((int(item.get("finished_at") or 0) for item in drills if item.get("status")=="succeeded"),default=0)
            last_attempt=drills[0] if drills else None
            if not settings.get("enabled") or not ops.restore_drill_enabled(settings):
                drill_health={"state":"disabled","last_success_at":last_success,"due_at":0,"message":"定时备份或每周恢复演练未启用。"}
            elif last_attempt and last_attempt.get("status")=="failed" and int(last_attempt.get("finished_at") or 0)>last_success:
                drill_health={"state":"failed","last_success_at":last_success,"last_attempt_at":int(last_attempt.get("finished_at") or 0),"due_at":last_success+7*86400 if last_success else 0,"message":"最近一次隔离恢复演练失败；查看演练记录与可用空间后重试。"}
            elif not last_success:
                drill_health={"state":"never_tested","last_success_at":0,"due_at":0,"message":"尚无成功的隔离恢复演练记录。"}
            else:
                due_at=last_success+7*86400
                drill_health={"state":"overdue" if now>=due_at else "healthy","last_success_at":last_success,"due_at":due_at,"message":"恢复演练已逾期，等待下一轮自动校验。" if now>=due_at else "最近备份已通过隔离恢复演练。"}
            return {"settings":settings,"items":items,"drills":drills,"drill_health":drill_health}
        finally:
            conn.close()

    @router.post("/backups/settings")
    async def backup_settings(request:Request):
        require_admin(request)
        p=await request.json()
        interval=int(ops.number(p.get("interval_hours",24)))
        retention=int(ops.number(p.get("retention",7)))
        if not 1<=interval<=168 or not 1<=retention<=30 or not isinstance(p.get("enabled"),bool):
            raise HTTPException(400,"interval 1-168 hours, retention 1-30")
        if "drill_enabled" in p and not isinstance(p["drill_enabled"],bool):
            raise HTTPException(400,"drill_enabled must be boolean")
        conn=db()
        try:
            old=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            settings={**ops.loads(old[0] if old else None),"enabled":p["enabled"],"interval_hours":interval,"retention":retention,"drill_enabled":p.get("drill_enabled",ops.loads(old[0] if old else None).get("drill_enabled",True))}
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)",(json.dumps(settings),))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.post("/backups")
    async def make_backup(request: Request):
        require_admin(request)
        conn=db()
        try:
            row=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            retention=ops.loads(row[0] if row else None).get("retention",7)
        finally:
            conn.close()
        try:
            return await asyncio.to_thread(ops.backup,database_path(),retention)
        except (ValueError,TimeoutError) as e:
            raise HTTPException(409,str(e))

    @router.post("/backups/{name}/drill")
    async def drill_backup(name: str, request: Request):
        require_admin(request)
        if not re.fullmatch(r"monitor-\d{8}-\d{6}-[0-9a-f]{6}\.db", name):
            raise HTTPException(400,"备份名称无效")
        folder=(Path(database_path()).parent/"backups").resolve()
        candidate=folder/name
        if candidate.is_symlink():
            raise HTTPException(400,"不接受符号链接备份")
        try:
            source=candidate.resolve(strict=True)
        except OSError:
            raise HTTPException(404,"备份文件不存在") from None
        if source.parent!=folder or not source.is_file():
            raise HTTPException(400,"备份路径无效")
        try:
            result=await asyncio.to_thread(ops.restore_drill,source)
        except (RuntimeError,TimeoutError,ValueError) as exc:
            raise HTTPException(409,str(exc)) from None
        conn=db()
        try:
            ops.record_backup_drill(conn,result)
            settings_row=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            settings=ops.loads(settings_row[0]) if settings_row else {"enabled":False,"interval_hours":24,"retention":7,"drill_enabled":True}
            settings["last_drill_attempt"]=result["started_at"]
            settings["last_drill"]={key:result[key] for key in ("backup_name","started_at","finished_at","duration_ms","status","message","bytes","sha256")}
            settings["last_drill_at"]=result["finished_at"]
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)",(json.dumps(settings,ensure_ascii=False),))
            conn.commit()
            return result
        finally:
            conn.close()

    @router.get("/users")
    def users():
        conn=db()
        try:
            return {"items":rows(conn,"SELECT username,role,enabled,updated_at FROM ops_users ORDER BY username"),"environment_admin":admin_name()}
        finally:
            conn.close()

    @router.post("/users")
    async def save_user(request:Request):
        p=await request.json()
        name=str(p.get("username",""))
        password=str(p.get("password",""))
        role=p.get("role","viewer")
        if not re.fullmatch(r"[a-zA-Z0-9_.@-]{1,64}",name) or name==admin_name() or role not in {"admin","operator","viewer"} or len(password)<12 or len(password)>256:
            raise HTTPException(400,"用户名不可覆盖环境管理员；密码至少12位；角色 admin/operator/viewer")
        conn=db()
        try:
            conn.execute("INSERT INTO ops_users VALUES(?,?,?,1,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,role=excluded.role,enabled=1,updated_at=excluded.updated_at",(name,ops.password_hash(password),role,int(time.time())))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.delete("/users/{username}")
    def remove_user(username:str,request:Request):
        if username==request.state.dashboard_user or username==admin_name():
            raise HTTPException(409,"不可删除当前用户或环境管理员")
        conn=db()
        try:
            conn.execute("DELETE FROM ops_users WHERE username=?",(username,))
            conn.execute("DELETE FROM commerce_accounts WHERE username=?", (username,))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.get("/audit")
    def audit(before:int=0):
        conn=db()
        try:
            return {"items":rows(conn,"SELECT * FROM ops_audit WHERE (?=0 OR id<?) ORDER BY id DESC LIMIT 100",(before,before))}
        finally:
            conn.close()

    app.include_router(router)
