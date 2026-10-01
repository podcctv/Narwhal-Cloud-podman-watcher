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
except ImportError:
    import operations as ops


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
            return {"nodes":rows(conn,"SELECT host_id,node_id,agent_version,last_seen FROM hosts ORDER BY host_id LIMIT 500"),"campaigns":unpack(rows(conn,"SELECT * FROM ops_upgrades ORDER BY id DESC LIMIT 50")),"progress":rows(conn,"SELECT * FROM ops_upgrade_nodes ORDER BY campaign DESC LIMIT 500"),"server_version":version()}
        finally:
            conn.close()

    @router.post("/upgrades")
    async def create_upgrade(request:Request):
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
            campaign=conn.execute("INSERT INTO ops_upgrades(version,revision,status,created_at,payload) VALUES(?,?,'canary',?,?)",(target_version,revision,now,json.dumps({"hosts":hosts}))).lastrowid
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
        conn=db()
        try:
            row=conn.execute("SELECT * FROM ops_upgrades WHERE id=?",(campaign,)).fetchone()
            if not row or row["status"]!="canary" or not conn.execute("SELECT 1 FROM ops_upgrade_nodes WHERE campaign=? AND status='verified'",(campaign,)).fetchone():
                raise HTTPException(409,"灰度节点尚未验证目标版本")
            for n in conn.execute("SELECT host_id FROM ops_upgrade_nodes WHERE campaign=? AND status='pending'",(campaign,)).fetchall():
                action=queue(conn,n[0],"managed_upgrade",{"revision":row["revision"],"version":row["version"]},request.state.dashboard_user)
                conn.execute("UPDATE ops_upgrade_nodes SET status='dispatched',action_id=? WHERE campaign=? AND host_id=?",(action,campaign,n[0]))
            conn.execute("UPDATE ops_upgrades SET status='rollout' WHERE id=?",(campaign,))
            conn.commit()
            return {"ok":True}
        finally:
            conn.close()

    @router.post("/upgrades/rollback")
    async def rollback(request:Request):
        p=await request.json()
        conn=db()
        try:
            host=str(p.get("host_id",""))
            previous=conn.execute("SELECT previous_version FROM ops_upgrade_nodes WHERE host_id=? AND action_id IS NOT NULL ORDER BY campaign DESC LIMIT 1",(host,)).fetchone()
            if not previous:
                raise HTTPException(409,"没有该节点受管升级记录，无法确认回滚目标")
            action=queue(conn,host,"managed_rollback",{"version":previous[0]},request.state.dashboard_user)
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
