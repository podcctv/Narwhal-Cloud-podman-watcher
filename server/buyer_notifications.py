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
    CREATE TABLE IF NOT EXISTS buyer_user_notices(
      id TEXT PRIMARY KEY,alert_id INTEGER,episode INTEGER,host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,
      subject TEXT,message TEXT,machine_id TEXT,user_id TEXT,requested_by TEXT,created_at INTEGER,expires_at INTEGER,container_id TEXT DEFAULT '',
      telegram_status TEXT,banner_status TEXT DEFAULT 'queued',last_error TEXT DEFAULT '',updated_at INTEGER,
      attempts INTEGER DEFAULT 0,due_at INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_user_notices_host ON buyer_user_notices(host_id,expires_at);
    """)
    if 'container_id' not in {r[1] for r in conn.execute('PRAGMA table_info(buyer_user_notices)')}:
        conn.execute("ALTER TABLE buyer_user_notices ADD COLUMN container_id TEXT DEFAULT ''")
    if 'connection_stop_json' not in {r[1] for r in conn.execute('PRAGMA table_info(buyer_user_notices)')}:
        conn.execute("ALTER TABLE buyer_user_notices ADD COLUMN connection_stop_json TEXT DEFAULT ''")
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
    for notice in conn.execute("SELECT * FROM buyer_user_notices WHERE host_id=? AND expires_at>? AND banner_status='queued'", (host, ts)).fetchall():
        c = lookup.get((notice['runtime'], notice['project'], notice['container_name']))
        if notice['container_id'] and (not c or str(c.get('id') or '') != notice['container_id']):
            continue
        delivery = c.get('security', {}).get('motd_delivery', {}) if c else {}
        if (delivery.get('status') in {'written', 'unchanged'} or delivery.get('shell_delivery') == 'installed') and 'NOTICE-'+notice['id'] in delivery.get('notice_ids', []):
            conn.execute("UPDATE buyer_user_notices SET banner_status='written',updated_at=? WHERE id=?", (ts, notice['id']))
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
        unknown=a["alert_type"] in {"socks_weak_auth", "socks_password_review"} and ("detected" not in socks or (socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}))
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
                              "AND action_type IN ('remediate_panel_pairing','remediate_malicious_process','enforce_socks_auth','stop_reviewed_socks','apply_udp_throttle','stop_container') "
                              "ORDER BY id DESC LIMIT 1", (alert['id'], alert['first_seen'])).fetchone()
    if action:
        action = dict(action)
        receipt = conn.execute('SELECT payload FROM security_action_receipts WHERE action_id=?',(action['id'],)).fetchone()
        action['items'] = json.loads(receipt[0]) if receipt else []
    return buyer_content.render(alert, state, node, action)


def reconcile(conn, host, now):
    cfg = config(conn)
    for alert in conn.execute("SELECT * FROM security_alerts WHERE host_id=? AND last_seen>=? ORDER BY id DESC LIMIT 1000", (host, now-7*86400)).fetchall():
        if alert['alert_type'] in {'socks_password_review', 'standalone_proxy_panel'}:
            # Pending administrator judgement is not a confirmed customer risk.
            # Only the explicit user-notice workflow may notify the buyer.
            conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=?,last_error='仅提醒管理员，买家通知由管理员明确触发' WHERE alert_id=? AND status IN ('queued','retrying','blocked')", (now, alert['id']))
            continue
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
        if alert['alert_type'] == 'container_connection_count' and state in ('active', 'recurring') and buyer_content.loads(alert['details_json']).get('connection_policy', {}).get('escalated'):
            event_key += ':connection-escalated'
            conn.execute("UPDATE buyer_outbox SET status='cancelled',updated_at=?,last_error='已升级为连续严重超标提醒' WHERE alert_id=? AND event_key<>? AND status IN ('queued','retrying','blocked')", (now,alert['id'],event_key))
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
    now = int(time.time())
    notices = []
    for n in conn.execute("SELECT * FROM buyer_user_notices WHERE host_id=? AND expires_at>? ORDER BY created_at DESC LIMIT 200", (host, now)):
        t = target(conn, n, now)
        if n['user_id'] and (not t or (t['machine_id'], t['user_id'], t['scope']) != (n['machine_id'], n['user_id'], 'user')):
            continue  # Do not leave the old owner's notice on a reassigned container.
        if n['container_id'] and container_id(conn,n) != n['container_id']:
            continue
        notices.append({'runtime': n['runtime'], 'project': n['project'], 'name': n['container_name'], 'expected_container_id': n['container_id'],
            'type': 'user_notice', 'event_id': 'NOTICE-'+n['id'], 'state': 'active', 'updated_at': now,
            'created_at': n['created_at'], 'expires_at': n['expires_at'], 'title': n['subject'], 'message': n['message']})
    return notices + states[:1000-len(notices)]


def container_id(conn, row):
    report = conn.execute('SELECT payload_json FROM reports WHERE host_id=? AND runtime=? AND project=? AND container_name=? ORDER BY ts DESC,id DESC LIMIT 1',
        tuple(row[k] for k in buyer_mapping.IDENTITY)).fetchone()
    return str(buyer_content.loads(report[0]).get('id') or '')[:200] if report else ''


def notice_preview(conn, alert_id):
    a = conn.execute('SELECT * FROM security_alerts WHERE id=?', (alert_id,)).fetchone()
    if not a:
        raise ValueError('告警不存在')
    now = int(time.time())
    t = target(conn, a, now)
    mapped = bool(t and t['scope'] == 'user' and t['user_id'])
    cfg = config(conn)
    subject, message = render(a, current_state(conn, a), t['node_name'] if t else '', conn)
    snapshot = [a[k] for k in ('id', 'first_seen', 'status', 'host_id', 'runtime', 'project', 'container_name')]
    instance = container_id(conn, a)
    snapshot += [t['machine_id'] if mapped else '', t['user_id'] if mapped else '', instance, subject, message]
    token = hashlib.sha256(json.dumps(snapshot, ensure_ascii=False).encode()).hexdigest()
    live = a['runtime'] in {'incus', 'podman'} and 0 <= now-a['last_seen'] <= 900
    return {'subject': subject, 'message': message, 'preview_token': token, 'can_submit': live, 'container_id': instance,
        'audience': f"用户 {t['user_id']} / {t['node_name'] or a['container_name']}" if mapped else '收件未映射（不会整机广播）',
        'telegram': 'ready' if mapped and cfg['enabled'] and cfg['api_key'] else 'blocked',
        'telegram_note': '通过买家通知 API 投递；受理不等于用户已阅读，Telegram 绑定由上游维护' if mapped else '请先补齐精确用户收件映射；SSH 提醒可以独立排队',
        'banner': 'ready' if live else 'blocked',
        'banner_note': '写入该容器的 SSH 登录后提醒；不修改 SSH 认证前横幅。离线时等待节点回连。',
        'latest': [dict(n) for n in conn.execute('SELECT id,telegram_status,banner_status,last_error,created_at,expires_at FROM buyer_user_notices WHERE alert_id=? ORDER BY created_at DESC LIMIT 5', (alert_id,))]}


def queue_user_notice(conn, alert_id, payload, requested_by):
    notice_id = str(payload.get('request_id', ''))
    if not re.fullmatch(r'[0-9a-f]{32}', notice_id) or payload.get('confirm') is not True:
        raise ValueError('需要明确确认和有效请求 ID')
    old = conn.execute('SELECT * FROM buyer_user_notices WHERE id=?', (notice_id,)).fetchone()
    if old:
        if old['alert_id'] != alert_id or old['requested_by'] != requested_by:
            raise ValueError('请求 ID 与目标不匹配')
        return {'ok': True, 'id': notice_id, 'duplicate': True, 'telegram': old['telegram_status'], 'banner': old['banner_status']}
    preview = notice_preview(conn, alert_id)
    if payload.get('preview_token') != preview['preview_token'] or not preview['can_submit']:
        raise ValueError('目标、收件人或通知内容已变化/过期，请重新预览')
    a = conn.execute('SELECT * FROM security_alerts WHERE id=?', (alert_id,)).fetchone()
    now = int(time.time())
    recent = conn.execute('SELECT 1 FROM buyer_user_notices WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND created_at>?',
                          (*tuple(a[k] for k in buyer_mapping.IDENTITY), now-120)).fetchone()
    if recent:
        raise ValueError('该容器两分钟内已请求通知，请查看投递记录，勿重复发送')
    t = target(conn, a, now)
    mapped = bool(t and t['scope'] == 'user' and t['user_id'])
    telegram_state = 'queued' if preview['telegram'] == 'ready' else preview['telegram']
    banner_state = 'queued' if preview['banner'] == 'ready' else preview['banner']
    if conn.execute('SELECT COUNT(*) FROM buyer_user_notices').fetchone()[0] >= 10000:
        raise ValueError('通知记录已达到上限，请等待保留期清理')
    conn.execute('INSERT INTO buyer_user_notices(id,alert_id,episode,host_id,runtime,project,container_name,subject,message,machine_id,user_id,requested_by,created_at,expires_at,telegram_status,banner_status,updated_at,due_at,container_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (notice_id, alert_id, a['first_seen'], *(a[k] for k in buyer_mapping.IDENTITY), preview['subject'], preview['message'],
         t['machine_id'] if mapped else '', t['user_id'] if mapped else '', requested_by, now, now+86400,
         telegram_state, banner_state, now, now, preview['container_id']))
    return {'ok': True, 'id': notice_id, 'duplicate': False, 'telegram': telegram_state, 'banner': banner_state}


def connection_stop_gate(conn, identity, params, now):
    row=dict(zip(buyer_mapping.IDENTITY, identity))
    notice_id=hashlib.sha256(json.dumps([identity,params['metric_epoch'],params['threshold'],params['required_duration_seconds'],params['stop_since']]).encode()).hexdigest()[:32]
    notice=conn.execute('SELECT * FROM buyer_user_notices WHERE id=?',(notice_id,)).fetchone()
    t=target(conn,row,now)
    mapped=bool(t and t['scope']=='user' and t['user_id'])
    if notice:
        same=mapped and (notice['machine_id'],notice['user_id'])==(t['machine_id'],t['user_id'])
        context=buyer_content.loads(notice['connection_stop_json'])
        if same and notice['telegram_status']=='succeeded' and context.get('accepted_at'):
            return {'ready':True,'params':{'notice_required':True,'notice_id':notice_id,'notification_accepted_at':context['accepted_at']}}
        if same and (notice['telegram_status'] in {'queued','retrying'} or (notice['telegram_status']=='expired' and notice['attempts']==0)):
            # Refresh proof, not the network outcome; uncertain sends are never replayed.
            conn.execute("UPDATE buyer_user_notices SET connection_stop_json=?,telegram_status=CASE WHEN telegram_status='expired' THEN 'queued' ELSE telegram_status END WHERE id=?",(json.dumps(params),notice_id))
        return {'ready':False,'notice_id':notice_id,'status':notice['telegram_status'] if same else 'blocked',
            'reason':'等待用户通知投递确认；未执行停机。收件变化或结果不确定时需管理员核查。'}
    cfg=config(conn)
    if not mapped or not cfg['enabled'] or not cfg['api_key']:
        return {'ready':False,'status':'blocked','reason':'用户收件映射或通知配置缺失；为保证先通知后停机，暂未停止容器'}
    if conn.execute('SELECT COUNT(*) FROM buyer_user_notices').fetchone()[0]>=10000:
        return {'ready':False,'status':'blocked','reason':'通知队列已满，未执行停机'}
    existing=conn.execute("SELECT id,first_seen FROM security_alerts WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND alert_type='container_connection_count' ORDER BY last_seen DESC LIMIT 1",identity).fetchone()
    title='服务器连接数过高提醒'
    message=clean(f"您的 {t['node_name'] or identity[0]} 服务器（实例 {identity[3]}）检测时连接数 {params['connection_count']}，有效采样已连续 {params['duration_seconds']//60} 分钟超过 {params['threshold']} 个。\n为保护服务，通知投递确认后系统将重新核验连接数；若仍超标，将关闭该容器，不删除数据。请检查代理账号和后台任务。如有疑问，请发工单。",1600)
    conn.execute('INSERT INTO buyer_user_notices(id,alert_id,episode,host_id,runtime,project,container_name,subject,message,machine_id,user_id,requested_by,created_at,expires_at,telegram_status,banner_status,updated_at,due_at,container_id,connection_stop_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (notice_id,existing['id'] if existing else 0,existing['first_seen'] if existing else now,*identity,title,message,
         t['machine_id'],t['user_id'],'system:connection-guard',now,now+86400,'queued','queued',now,now,container_id(conn,row),json.dumps(params)))
    return {'ready':False,'notice_id':notice_id,'status':'queued','reason':'连续超标已确认；先向用户发送停机前提醒，投递确认前不下发停止指令'}


def activate_notified_stop(conn, notice, context, now):
    """Called only after buyer API acknowledgement, never before network acceptance."""
    if os.getenv('CONNECTION_AUTO_STOP_ENABLED','true').lower() not in {'1','true','yes','on'}:
        return
    identity=tuple(notice[k] for k in buyer_mapping.IDENTITY)
    t=target(conn,notice,now)
    if not t or t['scope']!='user' or (t['machine_id'],t['user_id'])!=(notice['machine_id'],notice['user_id']):
        return
    window=conn.execute('SELECT payload FROM connection_windows WHERE host_id=? AND runtime=? AND project=? AND container_name=?',identity).fetchone()
    current=buyer_content.loads(window[0]) if window else {}
    policy=current.get('policy',{})
    if (not policy.get('valid') or current.get('stop_since')!=context.get('stop_since')
        or not str(current.get('epoch','')).startswith(str(context.get('metric_epoch'))+':')
        or now>context.get('expires_at',0) or now-current.get('last',0)>policy.get('max_gap_seconds',0)
        or policy.get('stop_threshold')!=context.get('threshold') or policy.get('required_duration_seconds')!=context.get('required_duration_seconds')
        or policy.get('stop_duration_seconds',0)<context.get('required_duration_seconds',1)
        or policy.get('status')=='disabled'):
        return
    if conn.execute("SELECT 1 FROM security_actions WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND action_type='stop_container' AND status IN ('queued','dispatched','running')",identity).fetchone():
        return
    params={**context,'notice_required':True,'notice_id':notice['id'],'notification_accepted_at':now}
    params.pop('accepted_at',None)
    action=conn.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,?,?,?,'stop_container',?,'queued','system:connection-guard',?,?)",(*identity,json.dumps(params),now,now)).lastrowid
    current['retries']=current.get('retries',0)+1
    current['policy'].update(status='queued',action_id=action,reason='用户通知已获上游确认，已下发停机保护；不删除实例')
    conn.execute('UPDATE connection_windows SET payload=? WHERE host_id=? AND runtime=? AND project=? AND container_name=?',(json.dumps(current),*identity))
    conn.execute('UPDATE connection_overloads SET stop_action_id=? WHERE host_id=? AND runtime=? AND project=? AND container_name=?',(action,*identity))


def work_user_notices(db, now, sender):
    """Independent receipts; freeze recipients and never retry uncertain delivery."""
    conn = db()
    notice = None
    try:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("DELETE FROM buyer_user_notices WHERE id IN (SELECT id FROM buyer_user_notices WHERE expires_at<? LIMIT 500)", (now-30*86400,))
        conn.execute("UPDATE buyer_user_notices SET telegram_status='uncertain',last_error='发送进程中断，需核对上游结果' WHERE telegram_status='sending' AND updated_at<?", (now-120,))
        conn.execute("UPDATE buyer_user_notices SET telegram_status='expired' WHERE expires_at<=? AND telegram_status IN ('queued','blocked','retrying')", (now,))
        conn.execute("UPDATE buyer_user_notices SET banner_status='expired' WHERE expires_at<=? AND banner_status='queued'", (now,))
        cfg = config(conn)
        if not cfg['enabled'] or not cfg['api_key']:
            conn.commit()
            return
        for n in conn.execute("SELECT * FROM buyer_user_notices WHERE telegram_status IN ('queued','blocked','retrying') AND due_at<=? AND expires_at>? ORDER BY (requested_by='system:connection-guard') DESC,created_at LIMIT 100", (now, now)).fetchall():
            guard=buyer_content.loads(n['connection_stop_json'])
            if guard and now>guard.get('expires_at',0):
                conn.execute("UPDATE buyer_user_notices SET telegram_status='expired',last_error='超标证据过期，等待新的连续采样' WHERE id=?",(n['id'],))
                continue
            if n['container_id'] and container_id(conn,n) != n['container_id']:
                conn.execute("UPDATE buyer_user_notices SET telegram_status='cancelled',banner_status=CASE WHEN banner_status='queued' THEN 'cancelled' ELSE banner_status END,last_error='容器已重建，请重新预览' WHERE id=?", (n['id'],))
                continue
            t = target(conn, n, now)
            if not n['user_id'] or not t or t['scope'] != 'user' or (t['machine_id'], t['user_id']) != (n['machine_id'], n['user_id']):
                conn.execute("UPDATE buyer_user_notices SET telegram_status='blocked',last_error='收件未映射或已变化，请重新预览并发送',due_at=? WHERE id=?", (now+300,n['id']))
                continue
            cooldown = conn.execute('SELECT next_at FROM buyer_cooldowns WHERE machine_id=?', (n['machine_id'],)).fetchone()
            if cooldown and cooldown[0] > now and not guard:
                continue
            if guard and (conn.execute("SELECT 1 FROM buyer_user_notices WHERE machine_id=? AND telegram_status='sending'",(n['machine_id'],)).fetchone()
                or conn.execute("SELECT 1 FROM buyer_outbox WHERE machine_id=? AND status='sending'",(n['machine_id'],)).fetchone()):
                continue
            notice = dict(n)
            conn.execute('INSERT INTO buyer_cooldowns VALUES(?,?) ON CONFLICT(machine_id) DO UPDATE SET next_at=excluded.next_at', (n['machine_id'], now+120))
            conn.execute("UPDATE buyer_user_notices SET telegram_status='sending',attempts=attempts+1,updated_at=? WHERE id=?", (now,n['id']))
            break
        conn.commit()
        if not notice:
            return
        status, error, due = 'uncertain', '网络结果不确定；请核对上游，系统不会自动重发', now+86400
        try:
            status, _ = sender(cfg,notice['machine_id'],notice['user_id'],'user',notice['subject'],notice['message'],'user-notice-'+notice['id'])
            error = '' if status == 'succeeded' else '上游未确认投递成功'
        except urllib.error.HTTPError as exc:
            error = f'上游 HTTP {exc.code}'
            status = 'retrying' if exc.code == 429 else 'failed'
            due = retry_after(exc.headers,now) if exc.code == 429 else due
        except ValueError:
            status,error='failed','API 配置无效'
        except Exception:
            pass
        if status == 'retrying' and notice['attempts']+1 >= MAX_ATTEMPTS:
            status = 'failed'
        conn.execute("UPDATE buyer_user_notices SET telegram_status=?,last_error=?,due_at=?,updated_at=? WHERE id=? AND telegram_status='sending'", (status,error,due,now,notice['id']))
        context=buyer_content.loads(notice.get('connection_stop_json'))
        if status=='succeeded' and context:
            context['accepted_at']=now
            conn.execute('UPDATE buyer_user_notices SET connection_stop_json=? WHERE id=?',(json.dumps(context),notice['id']))
            activate_notified_stop(conn,notice,context,now)
        conn.commit()
    finally:
        conn.close()


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
    work_user_notices(db, now, sender)
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

    @app.get('/api/v1/security/alerts/{alert_id}/notify-user')
    def preview_user_notice(alert_id: int):
        conn = db()
        try:
            return notice_preview(conn, alert_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        finally:
            conn.close()

    @app.post('/api/v1/security/alerts/{alert_id}/notify-user')
    async def send_user_notice(alert_id: int, request: Request):
        conn = db()
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                raise ValueError('请求必须是对象')
            conn.execute('BEGIN IMMEDIATE')
            result = queue_user_notice(conn, alert_id, payload, str(getattr(request.state, 'dashboard_user', 'dashboard'))[:100])
            conn.commit()
            return result
        except (ValueError, TypeError) as exc:
            conn.rollback()
            raise HTTPException(status_code=409, detail=str(exc))
        finally:
            conn.close()

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
