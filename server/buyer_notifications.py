"""Durable buyer delivery. No network I/O in report ingestion; no implicit broadcasts."""
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from email.utils import parsedate_to_datetime
try:
    from . import buyer_mapping, buyer_content
except ImportError:
    import buyer_mapping
    import buyer_content

STATES = {"active": "风险存在", "awaiting_report": "已执行，待复查", "verified": "复查通过",
          "resolved": "告警已关闭（未验证）", "recurring": "风险复发 / 处置失败", "unverified": "证据不足，未确认恢复"}
TERMINAL = ("succeeded", "failed", "uncertain", "cancelled", "expired")
MAX_ATTEMPTS = 5


def clean(value, limit=500):
    # Remove terminal escapes, OSC links, control/bidi characters and likely secrets.
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value or ""))
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(c for c in text if unicodedata.category(c) not in {"Cc", "Cf"} or c == "\n")
    text = re.sub(r"(?i)(password|passwd|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)
    return text[:limit]


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS buyer_targets(
      host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,machine_id TEXT,user_id TEXT,
      node_name TEXT,scope TEXT NOT NULL DEFAULT 'user',enabled INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY(host_id,runtime,project,container_name));
    CREATE TABLE IF NOT EXISTS buyer_outbox(
      id INTEGER PRIMARY KEY,event_key TEXT UNIQUE,alert_id INTEGER,host_id TEXT,runtime TEXT,
      project TEXT,container_name TEXT,state TEXT,severity TEXT,subject TEXT,message TEXT,
      machine_id TEXT DEFAULT '',user_id TEXT DEFAULT '',scope TEXT DEFAULT 'user',status TEXT,
      attempts INTEGER DEFAULT 0,due_at INTEGER,created_at INTEGER,updated_at INTEGER,
      http_status INTEGER DEFAULT 0,last_error TEXT DEFAULT '',batch_id TEXT DEFAULT '');
    CREATE INDEX IF NOT EXISTS idx_buyer_due ON buyer_outbox(status,due_at);
    CREATE TABLE IF NOT EXISTS buyer_cooldowns(machine_id TEXT PRIMARY KEY,next_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS buyer_checks(alert_id INTEGER PRIMARY KEY,episode INTEGER,clean_samples INTEGER DEFAULT 0,last_sample INTEGER,state TEXT);
    """)
    buyer_mapping.initialize(conn)


def setting(conn, key, default=""):
    row = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else os.getenv(key.upper(), default)


def config(conn):
    return {"enabled": setting(conn, "buyer_notify_enabled", os.getenv("NARWHAL_BUYER_NOTIFY_ENABLED", "true")).lower() not in {"false", "0", "off", "no"},
            "api_url": setting(conn, "narwhal_api_url", "https://api.fuckip.me/api/v1").rstrip("/"),
            "api_key": setting(conn, "narwhal_api_key"),
            "min_severity": setting(conn, "buyer_min_severity", "warning"),
            "recovery": setting(conn, "buyer_recovery_enabled", "true").lower() == "true"}


def valid_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("机器 ID 必须是有效 UUID")


def save_target(conn, data):
    fields = [str(data.get(k) or "").strip() for k in ("host_id", "runtime", "project", "container_name")]
    if not fields[0] or not fields[1] or not fields[3] or any(len(v) > 200 for v in fields):
        raise ValueError("需要精确的主机 / 运行时 / 项目 / 容器身份")
    machine = valid_uuid(data.get("machine_id"))
    scope = data.get("scope", "user")
    user = str(data.get("user_id") or "").strip()
    if scope not in {"user", "machine"} or (scope == "user" and not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", user)):
        raise ValueError("定向通知必须指定有效 user_id")
    if scope == "machine" and data.get("confirm_broadcast") is not True:
        raise ValueError("整机买家广播必须明确确认")
    if type(data.get("enabled", True)) is not bool:
        raise ValueError("enabled 必须是布尔值")
    if conn.execute("SELECT 1 FROM buyer_outbox WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND status='sending' LIMIT 1",fields).fetchone():
        raise ValueError("该容器正在投递，请等待结果后修改收件范围")
    conn.execute("INSERT INTO buyer_targets(host_id,runtime,project,container_name,machine_id,user_id,node_name,scope,enabled) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id,runtime,project,container_name) DO UPDATE SET machine_id=excluded.machine_id,user_id=excluded.user_id,node_name=excluded.node_name,scope=excluded.scope,enabled=excluded.enabled,source='manual',vm_id='',verified_at=0",
                 (*fields, machine, user if scope == "user" else "", clean(data.get("node_name"), 100), scope, int(data.get("enabled", True))))


def target(conn, row, now=None):
    now = int(time.time()) if now is None else now
    return conn.execute("SELECT * FROM buyer_targets WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND enabled=1 AND (source='manual' OR verified_at>=?)", (*tuple(row[k] for k in ("host_id", "runtime", "project", "container_name")), now-buyer_mapping.TTL)).fetchone()


def current_state(conn, alert):
    if alert["status"] in {"suppressed", "dismissed"}:
        return "suppressed"
    recheck = conn.execute("SELECT r.status FROM ops_rechecks r JOIN security_actions a ON a.id=r.action_id WHERE a.alert_id=? AND r.ts>=? ORDER BY r.ts DESC,r.action_id DESC LIMIT 1", (alert["id"],alert["first_seen"])).fetchone()
    # A fresh recurrence must not inherit a previous successful verification.
    if recheck and (alert["status"] != "active" or recheck[0] != "verified"):
        return recheck[0]
    check=conn.execute("SELECT state FROM buyer_checks WHERE alert_id=? AND episode=?",(alert["id"],alert["first_seen"])).fetchone()
    if check and alert["status"] in {"remediated","resolved"}:
        return check[0]
    return "awaiting_report" if alert["status"] == "remediated" else alert["status"]


def observe(conn, host, ts, containers, alerts):
    """Inline remediation verification needs fresh samples, not just a successful kill."""
    lookup={(c.get("runtime",""),c.get("project",""),c.get("name")):c for c in containers}
    observed={(a.get("type"),a.get("runtime",""),a.get("project",""),a.get("container_name")) for a in alerts}
    for a in conn.execute("SELECT * FROM security_alerts WHERE host_id=? AND status IN ('active','remediated','resolved') AND last_seen>=?",(host,ts-86400)).fetchall():
        c=lookup.get((a["runtime"],a["project"],a["container_name"]))
        if not c:
            continue  # Missing container is not proof of cleanup.
        old=conn.execute("SELECT * FROM buyer_checks WHERE alert_id=?",(a["id"],)).fetchone()
        if old and old["episode"]==a["first_seen"] and ts<=old["last_sample"]:
            continue
        present=(a["alert_type"],a["runtime"],a["project"],a["container_name"]) in observed
        socks=c.get("security",{}).get("socks_proxy",{})
        unknown=a["alert_type"]=="socks_weak_auth" and ("detected" not in socks or (socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}))
        if a["alert_type"] == "ops_bandwidth_saturation":
            unknown = not c.get("bandwidth_monitor", {}).get("available", False)
        # Only verify events with an existing observation/remediation history.
        clean_samples=0 if present or unknown else (old["clean_samples"] if old and old["episode"]==a["first_seen"] else 0)+1
        state="awaiting_report" if present and a["status"]=="remediated" else "active" if present else "unverified" if unknown else "verified" if clean_samples>=2 else "awaiting_report"
        conn.execute("INSERT INTO buyer_checks VALUES(?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET episode=excluded.episode,clean_samples=excluded.clean_samples,last_sample=excluded.last_sample,state=excluded.state",(a["id"],a["first_seen"],clean_samples,ts,state))


def render(alert, state, node="", conn=None):
    action = None
    if conn is not None:
        action = conn.execute("SELECT * FROM security_actions WHERE alert_id=? AND created_at>=? "
                              "AND action_type IN ('remediate_panel_pairing','remediate_malicious_process','enforce_socks_auth','apply_udp_throttle','stop_container') "
                              "ORDER BY id DESC LIMIT 1", (alert['id'], alert['first_seen'])).fetchone()
    if action:
        action = dict(action)
        receipt = conn.execute('SELECT payload FROM security_action_receipts WHERE action_id=?',(action['id'],)).fetchone()
        action['items'] = json.loads(receipt[0]) if receipt else []
    return buyer_content.render(alert, state, node, action)


def reconcile(conn, host, now):
    cfg = config(conn)
    for alert in conn.execute("SELECT * FROM security_alerts WHERE host_id=? AND last_seen>=? ORDER BY id DESC LIMIT 1000", (host, now-7*86400)).fetchall():
        if alert["alert_type"] == "ops_traffic_quota":
            conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=?,last_error='流量额度提醒已停用' WHERE alert_id=? AND status IN ('queued','retrying','blocked')", (now, alert['id']))
            continue
        state = current_state(conn, alert)
        # Reconcile pending snapshots: never send stale active warnings after recovery.
        conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=?,last_error='事件状态或等级已变化' WHERE alert_id=? AND (state<>? OR severity<>? OR event_key NOT LIKE ?) AND status IN ('queued','retrying','blocked')", (now, alert["id"], state, alert["severity"], f"{alert['id']}:{alert['first_seen']}:%"))
        if state == "suppressed" or alert["severity"] == "info" or (cfg["min_severity"] == "critical" and alert["severity"] != "critical"):
            continue
        existing = conn.execute("SELECT 1 FROM buyer_outbox WHERE alert_id=? AND created_at>=? LIMIT 1", (alert["id"], alert["first_seen"])).fetchone()
        if state in {"verified", "resolved"} and (not cfg["recovery"] or not existing):
            continue  # No historical recovery flood on migration.
        if not cfg["enabled"]:
            continue
        t = target(conn, alert)
        subject, message = render(alert, state, t["node_name"] if t else "", conn)
        event_key = f"{alert['id']}:{alert['first_seen']}:{state}:{alert['severity']}"
        # Bounded outbox protects the monitoring database from notification growth.
        count = conn.execute("SELECT COUNT(*) FROM buyer_outbox WHERE status IN ('queued','retrying','blocked','sending')").fetchone()[0]
        if count >= 10000:
            break
        conn.execute("INSERT OR IGNORE INTO buyer_outbox(event_key,alert_id,host_id,runtime,project,container_name,state,severity,subject,message,machine_id,user_id,scope,status,due_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (event_key, alert["id"], *(alert[k] for k in ("host_id","runtime","project","container_name")), state, alert["severity"], subject, message,
                      t["machine_id"] if t else "", t["user_id"] if t else "", t["scope"] if t else "user", "queued" if t else "blocked", now, now, now))


def banner_states(conn, host):
    states = []
    for a in conn.execute("SELECT * FROM security_alerts WHERE host_id=? AND last_seen>=? ORDER BY id DESC LIMIT 1000", (host, int(time.time())-86400)):
        if a['alert_type'] == 'ops_traffic_quota':
            continue
        states.append({"runtime": a["runtime"], "project": a["project"], "name": a["container_name"], "type": a["alert_type"],
                       "event_id": f"NW-{a['id']}-{a['first_seen']}", "state": current_state(conn,a), "updated_at": a["last_seen"]})
    return states


def validate_url(url, resolve=False):
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.port not in (None, 443):
        raise ValueError("API 地址必须为不带凭据 / 查询参数的 HTTPS 公网地址")
    if resolve:
        addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError("API 地址不能指向本机或私网")
    else:
        try:
            if not ipaddress.ip_address(p.hostname).is_global:
                raise ValueError("API 地址不能指向本机或私网")
        except ValueError as exc:
            if "API 地址" in str(exc):
                raise
        if p.hostname.lower() == "localhost" or p.hostname.lower().endswith((".local", ".localhost")):
            raise ValueError("API 地址不能指向本机或私网")
    return url.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward Authorization to a redirected endpoint.


def sync_mappings(db, force=False):
    conn = db()
    try:
        cfg = config(conn)
    finally:
        conn.close()
    if not force and not cfg["enabled"]:
        return {"status": "disabled", "message": "买家推送已停用"}
    return buyer_mapping.sync(db, cfg, validate_url, lambda: urllib.request.build_opener(NoRedirect), force=force)


def deliver(cfg, machine, user, scope, subject, message, batch):
    base = validate_url(cfg["api_url"], resolve=True)
    endpoint = base + f"/machines/{valid_uuid(machine)}/notify-buyers"
    body = {"subject": clean(subject,200), "message": clean(message,2000), "user_id": user if scope == "user" else ""}
    req = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer "+cfg["api_key"], "Content-Type":"application/json", "Accept":"application/json", "User-Agent":"Narwhal-Monitor/"+os.getenv("NARWHAL_VERSION","dev"), "Idempotency-Key":batch})
    # A response timeout/crash is uncertain: caller must not blindly resend.
    with urllib.request.build_opener(NoRedirect).open(req, timeout=12) as resp:
        raw = resp.read(8192)
        if not 200 <= resp.status < 300:
            raise urllib.error.HTTPError(endpoint, resp.status, "unexpected response", resp.headers, None)
        try:
            data=json.loads(raw) if raw else {}
        except ValueError:
            return "uncertain", resp.status
        if not isinstance(data, dict):
            return "uncertain", resp.status
        result = data.get("data", data)
        if data.get("ok") is False or data.get("success") is False or data.get("code",0) not in (0,200,"0","200",None) or (isinstance(result,dict) and result.get("notified") == 0):
            return "failed", resp.status
        return "succeeded", resp.status


def retry_after(headers, now):
    raw = headers.get("Retry-After", "") if headers else ""
    try:
        seconds = int(raw)
    except ValueError:
        try:
            seconds = int(parsedate_to_datetime(raw).timestamp()-now)
        except (ValueError, TypeError, OverflowError):
            seconds = 86400
    return now + max(60, min(7*86400, seconds))


def work_once(db, now=None, sender=deliver):
    now = int(time.time()) if now is None else int(now)
    conn = db()
    batch = ""
    ids = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        # Exactly-once cannot be guaranteed without upstream support. Expired leases
        conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=?,last_error='流量额度提醒已停用' WHERE status IN ('queued','retrying','blocked') AND alert_id IN (SELECT id FROM security_alerts WHERE alert_type='ops_traffic_quota')", (now,))
        # are surfaced for inspection, never automatically retransmitted.
        conn.execute("UPDATE buyer_outbox SET status='uncertain',last_error='发送进程中断，需核对上游投递结果',updated_at=? WHERE status='sending' AND updated_at<?", (now,now-120))
        conn.execute("DELETE FROM buyer_outbox WHERE id IN (SELECT id FROM buyer_outbox WHERE updated_at<? AND status IN ('succeeded','failed','uncertain','cancelled','expired') LIMIT 500)", (now-90*86400,))
        conn.execute("DELETE FROM buyer_checks WHERE alert_id NOT IN (SELECT id FROM security_alerts)")
        conn.execute("UPDATE buyer_outbox SET status='expired',updated_at=?,last_error='超过七天投递期限' WHERE created_at<? AND status IN ('queued','retrying','blocked')", (now,now-7*86400))
        cfg = config(conn)
        if not cfg["enabled"] or not cfg["api_key"]:
            conn.commit()
            return
        # Refresh the mapping at delivery time (mapping changes never leak to old recipient).
        eligible=[]
        for row in conn.execute("SELECT * FROM buyer_outbox WHERE status IN ('queued','retrying','blocked') AND due_at<=? ORDER BY id LIMIT 200",(now,)).fetchall():
            a=conn.execute("SELECT * FROM security_alerts WHERE id=?",(row["alert_id"],)).fetchone()
            if not a or current_state(conn,a)!=row["state"] or a["severity"]!=row["severity"] or a["first_seen"]!=int(row["event_key"].split(":")[1]) or a["status"] in {"suppressed","dismissed"} or (cfg["min_severity"]=="critical" and a["severity"]!="critical") or (row["state"] in {"resolved","verified"} and not cfg["recovery"]):
                conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=? WHERE id=?",(now,row["id"]))
                continue
            if buyer_content.loads(a["details_json"]).get("data_stale") and row['state'] not in {'verified','resolved'}:
                conn.execute("UPDATE buyer_outbox SET status='blocked',last_error='异常采样已过期，等待新鲜证据',due_at=?,updated_at=? WHERE id=?", (now+300,now,row['id']))
                continue
            t=target(conn,row,now)
            if not t:
                issue=conn.execute("SELECT reason FROM buyer_mapping_issues WHERE host_id=? AND runtime=? AND project=? AND container_name=?",tuple(row[k] for k in buyer_mapping.IDENTITY)).fetchone()
                reason=issue[0] if issue else '收件映射缺失、已停用或上游关联已过期'
                conn.execute("UPDATE buyer_outbox SET status='blocked',last_error=?,due_at=?,updated_at=? WHERE id=?",(reason,now+300,now,row["id"]))
                continue
            host=conn.execute("SELECT last_seen FROM hosts WHERE host_id=?",(row["host_id"],)).fetchone()
            if host and now-host[0]>900:
                conn.execute("UPDATE buyer_outbox SET status='blocked',last_error='主机离线，等待新鲜证据',due_at=?,updated_at=? WHERE id=?",(now+300,now,row["id"]))
                continue
            subject,message=render(a,row["state"],t["node_name"],conn)
            conn.execute("UPDATE buyer_outbox SET machine_id=?,user_id=?,scope=?,subject=?,message=?,status=CASE WHEN status='blocked' THEN 'queued' ELSE status END WHERE id=?",(t["machine_id"],t["user_id"],t["scope"],subject,message,row["id"]))
            eligible.append(row["id"])
        if not eligible:
            conn.commit()
            return
        slots=','.join('?' for _ in eligible)
        row=conn.execute(f"SELECT o.* FROM buyer_outbox o LEFT JOIN buyer_cooldowns c ON o.machine_id=c.machine_id WHERE o.id IN ({slots}) AND o.status IN ('queued','retrying') AND o.due_at<=? AND o.attempts<? AND COALESCE(c.next_at,0)<=? ORDER BY o.id LIMIT 1",(*eligible,now,MAX_ATTEMPTS,now)).fetchone()
        if not row:
            conn.commit()
            return
        # Acquire a persisted machine-level reservation before the network request.
        conn.execute("INSERT INTO buyer_cooldowns VALUES(?,?) ON CONFLICT(machine_id) DO UPDATE SET next_at=excluded.next_at", (row["machine_id"],now+120))
        candidates=conn.execute(f"SELECT * FROM buyer_outbox WHERE id IN ({slots}) AND status IN ('queued','retrying') AND due_at<=? AND machine_id=? AND user_id=? AND scope=? AND attempts<? ORDER BY id LIMIT 8",(*eligible,now,row["machine_id"],row["user_id"],row["scope"],MAX_ATTEMPTS)).fetchall()
        # Only acknowledge events actually included in the bounded digest.
        chunks=[]
        for item in candidates:
            part=item["message"]
            if sum(len(c) for c in chunks)+len(part)+2*len(chunks)>1900:
                break
            chunks.append(part)
            ids.append(item["id"])
        message="\n\n".join(chunks)
        subject=row["subject"] if len(ids)==1 else clean(f"服务器提醒汇总（{len(ids)} 项）",200)
        batch=hashlib.sha256((row["machine_id"]+":"+",".join(map(str,ids))).encode()).hexdigest()
        conn.executemany("UPDATE buyer_outbox SET status='sending',batch_id=?,attempts=attempts+1,updated_at=? WHERE id=?",[(batch,now,i) for i in ids])
        conn.commit()
        status,error,http,next_at="uncertain","发送结果不确定",0,now+86400
        try:
            status,http=sender(cfg,row["machine_id"],row["user_id"],row["scope"],subject,message,batch)
            error="" if status=="succeeded" else "上游响应未确认成功"
        except urllib.error.HTTPError as exc:
            http=exc.code
            error=f"上游 HTTP {http}"  # Never store bodies/credentials.
            if http==429:
                status="retrying"
                next_at=retry_after(exc.headers,now)
            elif 500<=http<600:
                status="retrying"
                next_at=now+min(3600,60*2**min(row["attempts"],5))
            else:
                status="failed"
        except ValueError:
            status,error="failed","API URL / 机器标识配置无效"
        except Exception:
            # Timeout/connection reset could occur AFTER upstream acceptance.
            status,error="uncertain","网络异常；可能已投递，请核对上游后补发"
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE buyer_cooldowns SET next_at=? WHERE machine_id=?",(next_at,row["machine_id"]))
        conn.executemany("UPDATE buyer_outbox SET status=CASE WHEN ?='retrying' AND attempts>=? THEN 'failed' ELSE ? END,http_status=?,last_error=?,due_at=?,updated_at=? WHERE id=? AND batch_id=? AND status='sending'",[(status,MAX_ATTEMPTS,status,http,error,next_at,now,i,batch) for i in ids])
        conn.commit()
    finally:
        conn.close()


def test_notification(db, payload, sender=deliver):
    if not isinstance(payload,dict):
        raise ValueError("payload 必须是对象")
    conn=db()
    try:
        cfg=config(conn)
        for field in ("api_url","api_key"):
            supplied=str(payload.get("narwhal_"+field) or "").strip()
            if supplied and "*" not in supplied:
                cfg[field]=supplied
        validate_url(cfg["api_url"])
        machine=str(payload.get("narwhal_machine_id") or setting(conn,"narwhal_machine_id")).strip()
        if machine:
            machine=valid_uuid(machine)
        user=str(payload.get("user_id") or "").strip()
        scope=payload.get("scope","user")
        subject=clean(f"[测试通知] {payload.get('narwhal_node_name') or 'Narwhal'}",200)
        message="仅测试 API 投递，不代表容器异常或自动处置成功。"
        audience=f"机器 {machine or '未指定'} / 用户 {user or '未指定'}" if scope=="user" else f"机器 {machine or '未指定'} / 全部买家"
        if payload.get("send") is not True:
            return {"ok":True,"preview":True,"message":"仅预览，未请求上游，也未验证连通性", "subject":subject,"body":message,"audience":audience,"status_code":0}
        if not machine or not cfg["api_key"]:
            raise ValueError("真实测试需要机器 UUID 和 API 密钥")
        if scope not in {"user","machine"} or (scope=="user" and not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}",user)):
            raise ValueError("真实测试必须明确收件人")
        if payload.get("confirm_audience") != audience or (scope=="machine" and payload.get("confirm_broadcast") is not True):
            raise ValueError("请确认显示的收件范围")
        now=int(time.time())
        conn.execute("BEGIN IMMEDIATE")
        cooldown=conn.execute("SELECT next_at FROM buyer_cooldowns WHERE machine_id=?",(machine,)).fetchone()
        if cooldown and cooldown[0]>now:
            conn.rollback()
            return {"ok":False,"message":"机器仍在冷却期，未发送", "status_code":429}
        batch="test-"+uuid.uuid4().hex
        conn.execute("INSERT INTO buyer_cooldowns VALUES(?,?) ON CONFLICT(machine_id) DO UPDATE SET next_at=excluded.next_at",(machine,now+86400))
        record=conn.execute("INSERT INTO buyer_outbox(event_key,alert_id,host_id,runtime,project,container_name,state,severity,subject,message,machine_id,user_id,scope,status,due_at,created_at,updated_at,attempts,batch_id) VALUES(?,0,'manual-test','','','manual-test','test','info',?,?,?,?,?,'sending',?,?,?,1,?)",(batch,subject,message,machine,user,scope,now,now,now,batch)).lastrowid
        conn.commit()
        http=0
        try:
            status,http=sender(cfg,machine,user,scope,subject,message,batch)
            error="" if status=="succeeded" else "上游未确认成功"
        except urllib.error.HTTPError as exc:
            status,http,error="failed",exc.code,f"上游 HTTP {exc.code}"
            if http==429:
                conn.execute("UPDATE buyer_cooldowns SET next_at=? WHERE machine_id=?",(retry_after(exc.headers,now),machine))
        except ValueError:
            status,error="failed","API URL / 标识配置无效"
        except Exception:
            status,error="uncertain","网络异常，结果不确定，不自动重发"
        conn.execute("UPDATE buyer_outbox SET status=?,http_status=?,last_error=?,updated_at=? WHERE id=?",(status,http,error,now,record))
        conn.commit()
        return {"ok":status=="succeeded","message":"测试投递成功" if status=="succeeded" else error,"status_code":http,"delivery_status":status,"record_id":record,"audience":audience}
    finally:
        conn.close()


def attach(app, db):
    from fastapi import HTTPException, Request

    @app.get("/api/v1/buyer/records")
    def records():
        conn=db()
        try:
            return {"items":[dict(r) for r in conn.execute("SELECT o.*,COALESCE(c.next_at,0) AS machine_next_at FROM buyer_outbox o LEFT JOIN buyer_cooldowns c ON o.machine_id=c.machine_id ORDER BY o.id DESC LIMIT 100")],
                    "counts":dict(conn.execute("SELECT status,COUNT(*) FROM buyer_outbox GROUP BY status")),
                    "targets":[dict(r) for r in conn.execute("SELECT * FROM buyer_targets LIMIT 1000")],
                    "hosts":[dict(r) for r in conn.execute("SELECT host_id,runtime,project,container_name FROM reports GROUP BY host_id,runtime,project,container_name HAVING MAX(ts)>=? LIMIT 1000",(int(time.time())-900,))],
                    "mapping_sync":buyer_mapping.status(conn),
                    "mapping_issues":[dict(r) for r in conn.execute("SELECT * FROM buyer_mapping_issues LIMIT 2000")]}
        finally:
            conn.close()

    @app.post("/api/v1/buyer/sync")
    async def sync():
        import asyncio
        return await asyncio.to_thread(sync_mappings, db, True)

    @app.post("/api/v1/buyer/targets")
    async def targets(request: Request):
        conn=db()
        try:
            save_target(conn,await request.json())
            conn.commit()
            return {"ok":True}
        except (ValueError,TypeError,AttributeError) as exc:
            raise HTTPException(400,str(exc))
        finally:
            conn.close()

    @app.post("/api/v1/buyer/records/{record_id}/retry")
    async def retry(record_id: int,request: Request):
        data=await request.json()
        conn=db()
        try:
            row=conn.execute("SELECT * FROM buyer_outbox WHERE id=?",(record_id,)).fetchone()
            if not row or row["status"] not in ("failed","uncertain","blocked"):
                raise HTTPException(409,"仅失败 / 未知 / 缺映射的记录可补发")
            if data.get("confirm_duplicate_risk") is not True:
                raise HTTPException(400,"补发可能重复通知，请明确确认")
            now=int(time.time())
            conn.execute("UPDATE buyer_outbox SET status='queued',attempts=0,due_at=?,updated_at=?,last_error='' WHERE id=?",(now,now,record_id))
            conn.commit()
            return {"ok":True,"message":"已重新排队；仍遵守机器冷却和最新事件状态"}
        finally:
            conn.close()
