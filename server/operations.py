"""Bounded operational state, independent of FastAPI and deployment paths."""
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import statistics
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

TZ = timezone(timedelta(hours=8))
PROFILES = {
    "general": {"connections": 500, "rx_bps": 50_000_000, "http_rps": 100, "baseline_factor": 4},
    "web": {"connections": 2000, "rx_bps": 100_000_000, "http_rps": 500, "baseline_factor": 4},
    "socks": {"connections": 1000, "rx_bps": 100_000_000, "http_rps": 100, "baseline_factor": 5},
    "hy2": {"connections": 1500, "rx_bps": 150_000_000, "http_rps": 100, "baseline_factor": 6},
}
_backup_lock = threading.Lock()


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS ops_hosts(node TEXT PRIMARY KEY,host_id TEXT,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_meter(entity TEXT PRIMARY KEY,host_id TEXT,runtime TEXT,project TEXT,name TEXT,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_rollups(entity TEXT,period TEXT,bucket INTEGER,samples INTEGER DEFAULT 0,
      rx REAL DEFAULT 0,tx REAL DEFAULT 0,covered REAL DEFAULT 0,gaps INTEGER DEFAULT 0,estimated INTEGER DEFAULT 0,
      cpu_sum REAL DEFAULT 0,mem_sum REAL DEFAULT 0,peak_connections INTEGER DEFAULT 0,PRIMARY KEY(entity,period,bucket));
    CREATE INDEX IF NOT EXISTS idx_ops_rollups_period_bucket ON ops_rollups(period,bucket);
    CREATE TABLE IF NOT EXISTS ops_policies(entity TEXT PRIMARY KEY,profile TEXT,payload TEXT,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS ops_incidents(id INTEGER PRIMARY KEY,entity TEXT,kind TEXT,status TEXT,opened_at INTEGER,last_seen INTEGER,payload TEXT);
    CREATE INDEX IF NOT EXISTS idx_ops_incidents_entity ON ops_incidents(entity,last_seen);
    CREATE TABLE IF NOT EXISTS ops_events(id INTEGER PRIMARY KEY,incident_id INTEGER,ts INTEGER,kind TEXT,payload TEXT);
    CREATE INDEX IF NOT EXISTS idx_ops_events_incident ON ops_events(incident_id,ts);
    CREATE TABLE IF NOT EXISTS ops_rechecks(action_id INTEGER PRIMARY KEY,entity TEXT,alert_type TEXT,status TEXT,
      attempts INTEGER DEFAULT 0,clean_samples INTEGER DEFAULT 0,ts INTEGER,message TEXT);
    CREATE TABLE IF NOT EXISTS ops_services(id INTEGER PRIMARY KEY,host_id TEXT,name TEXT,payload TEXT,enabled INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS ops_service_results(service_id INTEGER PRIMARY KEY,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_upgrades(id INTEGER PRIMARY KEY,version TEXT,revision TEXT,status TEXT,created_at INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_upgrade_nodes(campaign INTEGER,host_id TEXT,action_id INTEGER,status TEXT,previous_version TEXT,
      PRIMARY KEY(campaign,host_id));
    CREATE TABLE IF NOT EXISTS ops_users(username TEXT PRIMARY KEY,password_hash TEXT,role TEXT,enabled INTEGER DEFAULT 1,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS ops_audit(id INTEGER PRIMARY KEY,ts INTEGER,username TEXT,method TEXT,path TEXT,status INTEGER);
    CREATE TABLE IF NOT EXISTS ops_settings(key TEXT PRIMARY KEY,payload TEXT);
    """)


def loads(value, fallback=None):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {} if fallback is None else fallback


def number(value):
    try:
        v = float(value)
        return max(0, v) if math.isfinite(v) else 0
    except (TypeError, ValueError):
        return 0


def identity(node, runtime="host", project="", name="__host__"):
    return json.dumps([node, runtime, project, name], ensure_ascii=False, separators=(",", ":"))


def policy(conn, entity):
    parts = loads(entity, [])
    host = identity(parts[0]) if parts else entity
    row = conn.execute("SELECT * FROM ops_policies WHERE entity IN (?,?) ORDER BY entity=? DESC LIMIT 1", (entity, host, entity)).fetchone()
    profile = row["profile"] if row else "general"
    saved = loads(row["payload"]) if row else {}
    return {"profile": profile, "monthly_quota_bytes":0, "quota_warning":.8, "silent_until":0, **PROFILES.get(profile, PROFILES["general"]), **saved}


def event(conn, entity, kind, ts, payload, active=True):
    row = conn.execute("SELECT id FROM ops_incidents WHERE entity=? AND kind=? AND status='open' ORDER BY id DESC LIMIT 1", (entity, kind)).fetchone()
    if not row and not active:
        return
    if row:
        incident = row[0]
        conn.execute("UPDATE ops_incidents SET last_seen=?,status=?,payload=? WHERE id=?", (ts, "open" if active else "resolved", json.dumps(payload), incident))
    else:
        incident = conn.execute("INSERT INTO ops_incidents(entity,kind,status,opened_at,last_seen,payload) VALUES(?,?,'open',?,?,?)", (entity, kind, ts, ts, json.dumps(payload))).lastrowid
    # Repeated samples update episode state, but do not flood the timeline.
    last = conn.execute("SELECT ts,kind FROM ops_events WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident,)).fetchone()
    label = kind if active else "recovered"
    if not last or last[1] != label or ts - last[0] >= 300:
        conn.execute("INSERT INTO ops_events(incident_id,ts,kind,payload) VALUES(?,?,?,?)", (incident, ts, label, json.dumps(payload)))


def ingest(conn, host_id, node_id, ts, data):
    node = node_id or host_id
    previous = conn.execute("SELECT ts FROM ops_hosts WHERE node=?", (node,)).fetchone()
    if previous and ts <= previous[0]:
        return []  # Old/replayed report must not mutate ledger/baseline/rechecks.
    operations = data.get("operations") if isinstance(data.get("operations"), dict) else {}
    conn.execute("INSERT INTO ops_hosts VALUES(?,?,?,?) ON CONFLICT(node) DO UPDATE SET host_id=excluded.host_id,ts=excluded.ts,payload=excluded.payload", (node, host_id, ts, json.dumps(operations)))
    interval = max(60, min(3600, number(data.get("client_config", {}).get("report_interval", 300))))
    alerts = data.get("security", {}).get("alerts", [])
    for c in data.get("containers", []):
        entity = identity(node, c.get("runtime", "podman"), c.get("project", ""), c.get("name", "unknown"))
        row = conn.execute("SELECT ts,payload FROM ops_meter WHERE entity=?", (entity,)).fetchone()
        old = loads(row["payload"]) if row else {}
        elapsed = ts - row["ts"] if row else 0
        gap = int(bool(row) and elapsed > interval * 2.5)
        counters = c.get("traffic_counters") or {}
        counter_valid = counters.get("available") is True
        reset = bool(counter_valid and old.get("counter_valid") and (number(counters.get("rx")) < old.get("rx", 0) or number(counters.get("tx")) < old.get("tx", 0) or counters.get("epoch") != old.get("epoch")))
        covered = elapsed if row and not gap and not reset else 0
        estimated = int(bool(covered) and not (counter_valid and old.get("counter_valid")))
        if covered:
            rx = max(0, number(counters.get("rx")) - old.get("rx", 0)) if not estimated else number(c.get("net_rx_bps")) * elapsed
            tx = max(0, number(counters.get("tx")) - old.get("tx", 0)) if not estimated else number(c.get("net_tx_bps")) * elapsed
        else:
            rx = tx = 0
        # Split bytes at local midnight/hour boundaries instead of billing all to the last sample.
        for period, size in (("hour", 3600), ("day", 86400)):
            start = ts - covered
            pieces = []
            if covered:
                cursor = start
                while cursor < ts:
                    bucket = int((cursor + 28800) // size) * size - 28800
                    end = min(ts, bucket + size)
                    pieces.append((bucket, (end - cursor) / covered, end - cursor))
                    cursor = end
            else:
                pieces = [(int((ts + 28800) // size) * size - 28800, 1, 0)]
            for bucket, fraction, duration in pieces:
                conn.execute("""INSERT INTO ops_rollups VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity,period,bucket) DO UPDATE SET
                  samples=samples+excluded.samples,rx=rx+excluded.rx,tx=tx+excluded.tx,covered=covered+excluded.covered,
                  gaps=gaps+excluded.gaps,estimated=estimated+excluded.estimated,cpu_sum=cpu_sum+excluded.cpu_sum,
                  mem_sum=mem_sum+excluded.mem_sum,peak_connections=MAX(peak_connections,excluded.peak_connections)""",
                  (entity, period, bucket, 1, rx*fraction, tx*fraction, duration, gap + int(reset), estimated,
                   number(c.get("cpu_percent")), number(c.get("mem_percent")), int(number(c.get("conn_count")))))
        rules = policy(conn, entity)
        values = [number(c.get("net_rx_bps")), number(c.get("conn_count"))]
        history = [x for x in old.get("baseline", []) if ts-x[0] < 86400][-288:]
        medians = [statistics.median(x[i+1] for x in history) if history else 0 for i in range(2)]
        enough = len(history) >= 24 and ts-history[0][0] >= 3600
        sample_valid = counter_valid or (values[0]>0 and number(c.get("security",{}).get("process_count"))>0)
        abnormal = sample_valid and enough and all(values[i] > max(medians[i]*rules["baseline_factor"], rules[k]) for i,k in enumerate(("rx_bps", "connections")))
        streak = old.get("streak", 0)+1 if abnormal else 0
        anomaly = streak >= 3 and rules.get("silent_until", 0) < ts
        if not sample_valid:
            streak=old.get("streak",0)
            anomaly=bool(old.get("anomaly"))
        if sample_valid and not abnormal:
            history.append([ts, *values])
        if sample_valid and (anomaly or old.get("anomaly")):
            event(conn, entity, "baseline_anomaly", ts, {"values": values, "baseline": medians, "streak": streak,"severity":"critical"}, anomaly)
        state = {"counter_valid": counter_valid, "rx": number(counters.get("rx")), "tx": number(counters.get("tx")), "epoch": counters.get("epoch"), "baseline": history[-288:], "streak": streak, "anomaly": anomaly, "baseline_ready": enough, "gap": gap, "reset": bool(reset), "estimated": bool(estimated), "medians": medians}
        conn.execute("INSERT INTO ops_meter VALUES(?,?,?,?,?,?,?) ON CONFLICT(entity) DO UPDATE SET host_id=excluded.host_id,ts=excluded.ts,payload=excluded.payload", (entity, host_id, c.get("runtime", "podman"), c.get("project", ""), c.get("name", "unknown"), ts, json.dumps(state)))
        for alert in alerts:
            if (alert.get("runtime"), alert.get("project", ""), alert.get("container_name")) == (c.get("runtime"), c.get("project", ""), c.get("name")):
                event(conn, entity, str(alert.get("type", "security")), ts, {"severity": alert.get("severity"), "message": str(alert.get("message", ""))[:500]})
        if data.get("security", {}).get("enabled") is True and number(c.get("security", {}).get("process_count")) > 0:
            recheck(conn, entity, c, alerts, ts)
        access = c.get("security", {}).get("access_log", {})
        signals = {"connections": values[1] >= rules["connections"], "rx_bps": values[0] >= rules["rx_bps"], "http_rps": number(access.get("requests_per_second")) >= rules["http_rps"]}
        if sample_valid:
            severe = values[1]>=rules["connections"]*2 or values[0]>=rules["rx_bps"]*2 or number(access.get("requests_per_second"))>=rules["http_rps"]*2
            event(conn, entity, "policy_signal", ts, {"signals": signals,"profile":rules["profile"],"severity":"critical" if severe else "warning"}, any(signals.values()) and rules.get("silent_until",0)<ts)
        # Close only security episodes proven absent in a complete fresh scan.
        if number(c.get("security", {}).get("process_count")) > 0 and data.get("security", {}).get("enabled") is True:
            current={str(a.get("type")) for a in alerts if (a.get("runtime"),a.get("project",""),a.get("container_name")) == (c.get("runtime"),c.get("project",""),c.get("name"))}
            for episode in conn.execute("SELECT kind FROM ops_incidents WHERE entity=? AND status='open'",(entity,)).fetchall():
                if episode[0] not in {"remediation","baseline_anomaly","traffic_quota","policy_signal"} and episode[0] not in current:
                    event(conn,entity,episode[0],ts,{"reason":"新安全样本中已消失"},False)
        quota = number(rules.get("monthly_quota_bytes"))
        if quota:
            month = int(datetime.fromtimestamp(ts, TZ).replace(day=1,hour=0,minute=0,second=0,microsecond=0).timestamp())
            usage = conn.execute("SELECT COALESCE(SUM(rx+tx),0) FROM ops_rollups WHERE entity=? AND period='day' AND bucket>=?", (entity, month)).fetchone()[0]
            event(conn, entity, "traffic_quota", ts, {"used": usage, "quota": quota, "severity": "critical" if usage >= quota else "warning"}, usage >= quota*number(rules.get("quota_warning", .8)))
    host_entity=identity(node)
    host_rules=policy(conn,host_entity)
    host_access=data.get("security",{}).get("access_log",{})
    host_http=number(host_access.get("requests_per_second"))
    if number(host_access.get("readable_files"))>0:
        event(conn,host_entity,"policy_signal",ts,{"signals":{"http_rps":host_http},"profile":host_rules["profile"],"severity":"critical" if host_http>=host_rules["http_rps"]*2 else "warning"},host_http>=host_rules["http_rps"] and host_rules.get("silent_until",0)<ts)
    for result in operations.get("services", [])[:50]:
        service = conn.execute("SELECT id FROM ops_services WHERE id=? AND host_id=? AND enabled=1", (result.get("id"), host_id)).fetchone()
        if service:
            conn.execute("INSERT INTO ops_service_results VALUES(?,?,?) ON CONFLICT(service_id) DO UPDATE SET ts=excluded.ts,payload=excluded.payload", (service[0], ts, json.dumps(result)))
            event(conn, identity(node), f"service:{service[0]}", ts, {**result,"severity":"critical" if result.get("status")=="failed" else "warning"}, result.get("status") != "healthy")
    for upgrade in conn.execute("SELECT n.*,u.version FROM ops_upgrade_nodes n JOIN ops_upgrades u ON u.id=n.campaign WHERE n.host_id=? AND n.status='dispatched'", (host_id,)).fetchall():
        core_health=[x for x in operations.get("health",[]) if x.get("source") in {"network_counters","security"}]
        healthy_scan = data.get("security",{}).get("enabled") is True and bool(core_health) and all(x.get("status") in {"healthy","idle"} for x in core_health) and all(x.get("status")=="healthy" for x in operations.get("services",[]))
        if data.get("agent_version") == upgrade["version"] and healthy_scan:
            conn.execute("UPDATE ops_upgrade_nodes SET status='verified' WHERE campaign=? AND host_id=?", (upgrade["campaign"], host_id))
            conn.execute("UPDATE security_actions SET status='succeeded',result_message='target version reported',updated_at=? WHERE id=?", (ts, upgrade["action_id"]))
    result = operations.get("upgrade_result",{})
    # The previous Client may predate operations-v1, so its signed version report
    # (not a new operations payload) must be sufficient to confirm a rollback.
    for action in conn.execute("SELECT id,params_json FROM security_actions WHERE host_id=? AND action_type='managed_rollback' AND status IN ('running','dispatched')",(host_id,)).fetchall():
        params=loads(action["params_json"])
        if params.get("expected_node_id")==node_id and params.get("version")==data.get("agent_version"):
            conn.execute("UPDATE security_actions SET status='succeeded',result_message='previous version reported after rollback',updated_at=? WHERE id=?",(ts,action["id"]))
    if isinstance(result,dict) and result.get("action_id"):
        action = conn.execute("SELECT action_type,params_json,status FROM security_actions WHERE id=? AND host_id=?", (result["action_id"],host_id)).fetchone()
        if action and action[0] in {"managed_upgrade","managed_rollback"} and action[2] in {"running","dispatched"} and loads(action[1]).get("expected_node_id")==node_id:
            if result.get("status")=="failed":
                conn.execute("UPDATE security_actions SET status='failed',result_message='managed worker failed; inspect journalctl -u narwhal-managed-*',updated_at=? WHERE id=?",(ts,result["action_id"]))
                conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE action_id=?",(result["action_id"],))
            elif action[0]=="managed_rollback" and result.get("status")=="installed" and result.get("version")==data.get("agent_version"):
                conn.execute("UPDATE security_actions SET status='succeeded',result_message='rollback version reported',updated_at=? WHERE id=?",(ts,result["action_id"]))
    for campaign in conn.execute("SELECT id FROM ops_upgrades WHERE status IN ('canary','rollout')").fetchall():
        states=[r[0] for r in conn.execute("SELECT status FROM ops_upgrade_nodes WHERE campaign=?",(campaign[0],))]
        if states and all(s=="verified" for s in states):
            conn.execute("UPDATE ops_upgrades SET status='verified' WHERE id=?",(campaign[0],))
    generated=[]
    prefix=json.dumps([node],ensure_ascii=False,separators=(",",":"))[:-1]+","
    for row in conn.execute("SELECT * FROM ops_incidents WHERE status='open' AND substr(entity,1,?)=? AND (kind IN ('baseline_anomaly','traffic_quota','policy_signal') OR kind LIKE 'service:%') ORDER BY last_seen DESC LIMIT 500",(len(prefix),prefix)).fetchall():
        parts=loads(row["entity"],[])
        if len(parts)!=4 or parts[0]!=node:
            continue
        payload=loads(row["payload"])
        payload.update(observed_at=row["last_seen"],data_stale=ts-row["last_seen"]>interval*2.5)
        generated.append({"runtime":parts[1],"project":parts[2],"container_name":parts[3],"type":"ops_"+row["kind"],"severity":payload.get("severity","warning"),"title":"运维信号："+row["kind"],"message":json.dumps(payload,ensure_ascii=False)[:1000],"value":0,"threshold":0})
    return generated


def track_recheck(conn, action_id, ts):
    row = conn.execute("SELECT a.*,s.alert_type FROM security_actions a JOIN security_alerts s ON s.id=a.alert_id WHERE a.id=?", (action_id,)).fetchone()
    if not row or row["action_type"] not in {"remediate_panel_pairing", "remediate_malicious_process", "enforce_socks_auth"}:
        return
    host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (row["host_id"],)).fetchone()
    entity = identity((host[0] if host and host[0] else row["host_id"]), row["runtime"], row["project"], row["container_name"])
    conn.execute("INSERT OR IGNORE INTO ops_rechecks(action_id,entity,alert_type,status,ts,message) VALUES(?,?,?,'awaiting_report',?,'执行完成，等待两次新报告复查')", (action_id, entity, row["alert_type"], ts))
    event(conn, entity, "remediation", ts, {"action_id": action_id, "status": "awaiting_report"})


def recheck(conn, entity, container, alerts, ts):
    for row in conn.execute("SELECT * FROM ops_rechecks WHERE entity=? AND status IN ('awaiting_report','retrying') AND ts<?", (entity, ts)).fetchall():
        socks = container.get("security",{}).get("socks_proxy",{})
        if row["alert_type"] == "socks_weak_auth" and socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}:
            # A still-present service with unknown authentication is not clean.
            conn.execute("UPDATE ops_rechecks SET clean_samples=0,message='SOCKS 仍存在，但认证采集证据不足' WHERE action_id=?",(row["action_id"],))
            continue
        failed = any((a.get("type"),a.get("runtime"),a.get("project", ""),a.get("container_name")) == (row["alert_type"],container.get("runtime"),container.get("project", ""),container.get("name")) for a in alerts)
        if row["status"] == "retrying":
            action = conn.execute("SELECT status FROM security_actions WHERE id=?", (row["action_id"],)).fetchone()
            if action and action[0] in ("queued", "dispatched", "running"):
                continue
            if action and action[0] == "failed":
                conn.execute("UPDATE ops_rechecks SET status='recurring',message='复查重试执行失败',ts=? WHERE action_id=?", (ts,row["action_id"]))
                continue
        clean = 0 if failed else row["clean_samples"] + 1
        status = "recurring" if failed and row["attempts"] >= 2 else "retrying" if failed else "verified" if clean >= 2 else "awaiting_report"
        attempts = row["attempts"] + int(status == "retrying")
        if status == "retrying":
            # Original action retains server/agent safeguards; refresh PID at dispatch.
            conn.execute("UPDATE security_actions SET status='queued',attempts=0,updated_at=? WHERE id=? AND status IN ('succeeded','failed')", (ts, row["action_id"]))
        conn.execute("UPDATE ops_rechecks SET status=?,attempts=?,clean_samples=?,ts=?,message=? WHERE action_id=?", (status, attempts, clean, ts, "风险复发，已到重试上限" if status == "recurring" else status, row["action_id"]))
        event(conn, entity, "remediation", ts, {"action_id": row["action_id"], "status": status}, status != "verified")


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return salt+":"+digest


def authenticate(conn, authorization):
    try:
        if not authorization.startswith("Basic "):
            return None
        name, password = base64.b64decode(authorization[6:], validate=True).decode().split(":", 1)
        row = conn.execute("SELECT * FROM ops_users WHERE username=? AND enabled=1", (name,)).fetchone()
        if row and hmac.compare_digest(password_hash(password, row["password_hash"].split(":")[0]), row["password_hash"]):
            return name, row["role"]
    except (ValueError, UnicodeError):
        pass
    return None


def permitted(role, method, path):
    if role == "admin":
        return True
    # These reads expose credentials/configuration even when the response is masked today.
    if any(path.startswith(p) for p in ("/api/v1/notifications", "/api/v1/settings", "/api/v1/ops/users", "/api/v1/ops/backups", "/api/v1/ops/audit")):
        return False
    if method in ("GET", "HEAD"):
        return True
    if role != "operator":
        return False
    return (path.startswith("/api/v1/containers/") or path.startswith("/api/v1/security/alerts/")) and (path.endswith("/diagnostics") or path.endswith("/disposition") or path.endswith("/actions")) or path == "/api/v1/ops/logs/discover"


def purge_host(conn,host_id):
    host=conn.execute("SELECT node_id FROM hosts WHERE host_id=?",(host_id,)).fetchone()
    node=(host[0] if host and host[0] else host_id)
    prefix=json.dumps([node],ensure_ascii=False,separators=(",",":"))[:-1]+","
    conn.execute("DELETE FROM ops_events WHERE incident_id IN (SELECT id FROM ops_incidents WHERE substr(entity,1,?)=?)",(len(prefix),prefix))
    for table in ("ops_meter","ops_rollups","ops_policies","ops_rechecks","ops_incidents"):
        conn.execute(f"DELETE FROM {table} WHERE substr(entity,1,?)=?",(len(prefix),prefix))
    conn.execute("DELETE FROM ops_hosts WHERE node=?",(node,))
    conn.execute("DELETE FROM ops_service_results WHERE service_id IN (SELECT id FROM ops_services WHERE host_id=?)",(host_id,))
    conn.execute("DELETE FROM ops_services WHERE host_id=?",(host_id,))
    conn.execute("DELETE FROM ops_upgrade_nodes WHERE host_id=?",(host_id,))


def maintain(conn, now):
    for table, column, days in (("ops_rollups", "bucket", 400), ("ops_events", "ts", 90), ("ops_incidents", "last_seen", 90), ("ops_audit", "ts", 180), ("ops_rechecks", "ts", 90)):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column}<? LIMIT 5000)", (now-days*86400,))
    conn.execute("DELETE FROM ops_rollups WHERE rowid IN (SELECT rowid FROM ops_rollups WHERE period='hour' AND bucket<? LIMIT 5000)", (now-30*86400,))
    for table, cap in (("ops_rollups", 200000), ("ops_events", 20000), ("ops_incidents", 5000), ("ops_audit", 20000)):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY rowid DESC LIMIT 5000 OFFSET ?)", (cap,))
    conn.execute("UPDATE ops_rechecks SET status='unverified',message='主机未上报，无法确认处置效果' WHERE status IN ('awaiting_report','retrying') AND ts<?", (now-3600,))
    conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE status='dispatched' AND action_id IN (SELECT id FROM security_actions WHERE status='failed' OR created_at<?)", (now-1800,))
    for table in ("ops_meter","ops_hosts"):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE ts<? LIMIT 5000)",(now-90*86400,))
    conn.execute("DELETE FROM ops_service_results WHERE service_id NOT IN (SELECT id FROM ops_services)")
    conn.commit()


def backup(database_path, retention=7):
    if not _backup_lock.acquire(False):
        raise ValueError("backup already running")
    target = None
    try:
        directory = Path(database_path).parent / "backups"
        directory.mkdir(mode=0o700, exist_ok=True)
        name = f"monitor-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(3)}.db"
        target = directory/name
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        source = sqlite3.connect(database_path, timeout=5)
        destination = sqlite3.connect(target)
        try:
            deadline = time.monotonic()+120
            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise TimeoutError("backup time budget exceeded")
            source.backup(destination, pages=256, progress=progress, sleep=.05)
            if destination.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("backup integrity check failed")
        finally:
            destination.close()
            source.close()
        digest = hashlib.sha256()
        with target.open("rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                digest.update(chunk)
        for old in sorted(directory.glob("monitor-*.db"), key=lambda x:x.stat().st_mtime, reverse=True)[max(1,min(30,retention)):]:
            old.unlink()
        return {"name": name, "bytes": target.stat().st_size, "sha256": digest.hexdigest(), "integrity": "ok"}
    except Exception:
        if target and target.exists():
            target.unlink()
        raise
    finally:
        _backup_lock.release()
