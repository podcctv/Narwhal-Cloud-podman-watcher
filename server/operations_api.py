"""Authenticated operations API; all mutation targets are bounded and explicit."""
import asyncio
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
    from . import inbound_assessment, ip_reputation
except ImportError:
    import operations as ops
    import fleet_updates
    import inbound_assessment, ip_reputation


def attach(app, db, database_path, storage, cleanup, version, admin_name):
    router = APIRouter(prefix="/api/v1/ops")
    table_cache={}

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

    def require_admin(request):
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(403, "只有管理员可以执行此运维操作")

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

    @router.get("/service-inventory")
    def service_inventory(host_id: str = "", runtime: str = "", limit: int = 200):
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
            for item in current:
                item["listeners"] = ops.loads(item.pop("inventory_json", "[]"), [])
                item["coverage"] = item.pop("inventory_state", "unavailable")
            changes = rows(conn, "SELECT * FROM ops_service_inventory_changes" + where + " ORDER BY ts DESC,id DESC LIMIT ?", (*params, min(1000, limit * 2)))
            for item in changes:
                item["data"] = ops.loads(item.pop("payload", "{}"))
            return {"items": current, "changes": changes, "retention_days": 90}
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
                signals = security.get("inbound_source_signals") if isinstance(security.get("inbound_source_signals"), list) else []
                connection_ips = security.get("connection_ips") if isinstance(security.get("connection_ips"), list) else []
                inbound = security.get("inbound_ips") if isinstance(security.get("inbound_ips"), list) else []
                if not inbound:
                    inbound = [item for item in connection_ips if isinstance(item, dict) and ops.number(item.get("inbound")) > 0]
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
                        "network_evidence": item.get("network_evidence") if isinstance(item.get("network_evidence"), dict) else item,
                        "assessment": by_ip.get(ip, {"classification": "insufficient_evidence", "identity_confirmed": False}),
                        "abuseipdb": reputation,
                    })
                attribution = security.get("connection_attribution") if isinstance(security.get("connection_attribution"), dict) else {}
                connection_metrics = security.get("connection_metrics") if isinstance(security.get("connection_metrics"), dict) else {}
                access = security.get("access_log") if isinstance(security.get("access_log"), dict) else {}
                timeline.append({
                    "ts": int(row["ts"]),
                    "connection_count": max(0, min(10_000_000, int(ops.number(connection_metrics.get("total", payload.get("conn_count", 0)))))),
                    "process_attribution": {
                        "captured": int(ops.number(attribution.get("captured_sockets"))),
                        "attributed": int(ops.number(attribution.get("process_attributed_sockets"))),
                        "confirmed_local": int(ops.number(attribution.get("confirmed_local_initiated"))),
                        "confirmed_remote": int(ops.number(attribution.get("confirmed_remote_initiated"))),
                        "unknown_direction": int(ops.number(attribution.get("unknown_direction"))),
                        "conntrack_available": attribution.get("conntrack_available") is True,
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
                action = conn.execute("SELECT status,result_message,updated_at,attempts FROM security_actions WHERE id=?", (item.get("action_id"),)).fetchone() if item.get("action_id") else None
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
            campaign=conn.execute("INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES(?,?,'canary',?,?)",(target_version,revision,now,json.dumps({"hosts":hosts,"attempts":{h:(1 if i==0 else 0) for i,h in enumerate(hosts)}}))).lastrowid
            for i,host in enumerate(hosts):
                old=conn.execute("SELECT agent_version FROM hosts WHERE host_id=?",(host,)).fetchone()[0]
                action=queue(conn,host,"managed_upgrade",{"revision":revision,"version":target_version},request.state.dashboard_user) if i==0 else None
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
            attempts = metadata.setdefault("attempts", {})
            for n in conn.execute("SELECT host_id FROM ops_upgrade_nodes WHERE campaign=? AND status='pending'",(campaign,)).fetchall():
                action=queue(conn,n[0],"managed_upgrade",{"revision":row["revision"],"version":row["version"],"campaign_id":campaign},request.state.dashboard_user)
                conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?",(action,campaign,n[0]))
                attempts[n[0]] = int(attempts.get(n[0], 0)) + 1
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
            if not row or not node or node["status"] != "failed" or row["status"] not in {"canary", "rollout"}:
                raise HTTPException(409, "只有仍处于灰度/分批发布中的失败节点可重试")
            metadata = ops.loads(row["payload"])
            if metadata.get("automatic"):
                raise HTTPException(409, "自动升级由协调器重试；此处不重复下发")
            attempts = metadata.setdefault("attempts", {})
            if int(attempts.get(host_id, 0)) >= 3:
                raise HTTPException(409, "该发布对节点的手动尝试已达 3 次上限，请先回滚或创建新版本")
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
            conn.execute("UPDATE ops_upgrades SET payload=? WHERE id=?", (json.dumps(metadata), campaign))
            conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?", (action, campaign, host_id))
            conn.commit()
            return {"action_id": action, "attempt": attempts[host_id]}
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
            previous=conn.execute("SELECT previous_version FROM ops_upgrade_nodes WHERE host_id=? AND action_id IS NOT NULL ORDER BY campaign DESC LIMIT 1",(host,)).fetchone()
            if not previous:
                raise HTTPException(409,"没有该节点受管升级记录，无法确认回滚目标")
            action=queue(conn,host,"managed_rollback",{"version":previous[0]},request.state.dashboard_user)
            cfg=fleet_updates.settings(conn)
            fleet_updates.save(conn,{**cfg,'holds':sorted(set(cfg['holds']+[host]))})
            conn.commit()
            return {"action_id":action}
        finally:
            conn.close()

    @router.get("/backups")
    def backups():
        conn=db()
        try:
            row=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            folder=Path(database_path()).parent/"backups"
            return {"settings":ops.loads(row[0]) if row else {"enabled":False,"interval_hours":24,"retention":7},"items":[{"name":p.name,"bytes":p.stat().st_size,"ts":int(p.stat().st_mtime)} for p in sorted(folder.glob("monitor-*.db"),reverse=True)[:30]]}
        finally:
            conn.close()

    @router.post("/backups/settings")
    async def backup_settings(request:Request):
        p=await request.json()
        interval=int(ops.number(p.get("interval_hours",24)))
        retention=int(ops.number(p.get("retention",7)))
        if not 1<=interval<=168 or not 1<=retention<=30 or not isinstance(p.get("enabled"),bool):
            raise HTTPException(400,"interval 1-168 hours, retention 1-30")
        conn=db()
        try:
            old=conn.execute("SELECT payload FROM ops_settings WHERE key='backup'").fetchone()
            settings={**ops.loads(old[0] if old else None),"enabled":p["enabled"],"interval_hours":interval,"retention":retention}
            conn.execute("INSERT OR REPLACE INTO ops_settings VALUES('backup',?)",(json.dumps(settings),))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.post("/backups")
    async def make_backup():
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
