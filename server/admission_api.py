"""Signed, bounded node-local enforcement receipts. No firewall decisions here."""
import asyncio
import ipaddress
import json
import os
import re
import threading
import time
from fastapi import Header, HTTPException, Request

HEARTBEAT_WRITE_INTERVAL_SECONDS = max(
    0, min(120, int(os.getenv("POLL_HEARTBEAT_WRITE_INTERVAL_SECONDS", "25")))
)
_heartbeat_lock = threading.Lock()
_heartbeat_by_db: dict[tuple[str, str], tuple[int, str]] = {}


def reset_throttle() -> None:
    """Clear per-database admission heartbeat throttle cache."""
    with _heartbeat_lock:
        _heartbeat_by_db.clear()


def _db_file_key(conn) -> str:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        return str(row[2] or "") if row else ""
    except Exception:
        return ""

KINDS={'inbound_source_blocked','tcp_concurrency_limited','admission_unverified','pasarguard_node_removed'}
ADMISSION_FAILURES={
    'ambiguous_ownership':'容器地址或宿主机接口无法唯一归属；未确认保护规则已生效。',
    'unsupported_network':'该容器网络模式不在当前自动保护支持范围内。',
    'sample_timeout':'容器网络采样命令超时，无法确认当前网络状态。',
    'permission_denied':'Agent 缺少读取网络或应用防火墙规则所需的权限。',
    'dependency_unavailable':'Agent 依赖的网络工具或内核接口不可用。',
    'sample_failed':'Incus/Podman 或网络采样接口返回失败。',
    'firewall_apply_failed':'nftables/NFQUEUE 规则应用或内核读回失败，保护未能确认。',
    'sample_invalid':'网络采样数据不完整或无效，保护未能确认。',
    'stale_sample':'最近一次保护状态采样已超过 30 秒，无法确认仍有效。',
    'worker_error':'保护检查未完成，具体原因无法归类；请查看节点 Agent 日志。',
    'unknown':'该节点未上报具体失败原因，请查看节点 Agent 日志。',
}
ADMISSION_STAGES={'startup':'启动检查','sampling':'网络采样','ownership':'网络归属检查','enforcement':'防火墙应用/验证','unknown':'状态检查'}


def initialize(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS admission_states(
        host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,instance_id TEXT,
        observed_at INTEGER,payload TEXT,PRIMARY KEY(host_id,runtime,project,container_name))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_admission_states_observed_at ON admission_states(observed_at)')
    db_file = _db_file_key(conn)
    if db_file:
        with _heartbeat_lock:
            for key in [k for k in _heartbeat_by_db if k[0] == db_file]:
                _heartbeat_by_db.pop(key, None)


def normalized_alert(value):
    if not isinstance(value,dict) or value.get('type') not in KINDS:
        raise HTTPException(400,'unsupported admission event')
    runtime,project,name,identity=(str(value.get(k) or '') for k in ('runtime','project','container_name','instance_id'))
    if runtime not in {'incus','podman','runman'} or not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}',name):
        raise HTTPException(400,'supported instance required')
    if project and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',project):raise HTTPException(400,'invalid project')
    if identity and not re.fullmatch(r'[A-Za-z0-9-]{12,100}',identity):raise HTTPException(400,'invalid identity')
    if runtime=='runman':
        if (project!='default'
                or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',name)
                or (identity and not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',identity))):
            raise HTTPException(400,'Runman requires default project, canonical VM UUID and UUID v4 generation')
    if not identity and value['type']!='admission_unverified':raise HTTPException(400,'stable identity required')
    kind=value['type']
    clean={'runtime':runtime,'project':project,'container_name':name,'instance_id':identity,'type':kind,
           'severity':'warning' if kind in {'inbound_source_blocked','admission_unverified','tcp_concurrency_limited'} else 'critical',
           'value':0,'threshold':5 if kind=='inbound_source_blocked' else 500}
    if kind=='pasarguard_node_removed':
        result=value.get('automatic_remediation') or {}
        if not isinstance(result,dict) or not isinstance(result.get('items',[]),list):raise HTTPException(400,'invalid cleanup receipt')
        items=[]
        for item in result.get('items',[])[:20]:
            if isinstance(item,dict) and item.get('kind') in {'service','binary','startup'} and item.get('status') in {'ok','failed'} and re.fullmatch(r'[A-Za-z0-9_./@:+-]{1,240}',str(item.get('target') or '')):
                items.append({k:item[k] for k in ('kind','target','status')})
        success=result.get('succeeded') is True and bool(items) and all(x['status']=='ok' for x in items)
        clean.update(title='禁止运行 PasarGuard Node：'+('已禁用服务' if success else '清理未完成'),
            message='已停止并禁用确认归属的 PasarGuard Node 服务，保留客户实例及数据。' if success else '确认存在 PasarGuard Node，但服务清理未完整验证，需管理员处理。',
            automatic_remediation={'attempted':True,'succeeded':success,'items':items},value=len(items),threshold=0)
        return clean
    source=value.get('admission') or {}
    if not isinstance(source,dict) or not isinstance(source.get('sources',[]),list) or not isinstance(source.get('blocked',{}),dict):
        raise HTTPException(400,'invalid admission facts')
    data={k:v for k,v in source.items() if k in {'tcp_connections','sampled_at','observed_at','blocked_packets','tcp_denied','limited_since','review_at','extensions','recovered_at'} and type(v) is int and 0<=v<10**15}
    if kind=='admission_unverified':
        code=source.get('failure_code')
        stage=source.get('failure_stage')
        data['failure_code']=code if code in ADMISSION_FAILURES else 'unknown'
        data['failure_stage']=stage if stage in ADMISSION_STAGES else 'unknown'
        detail=str(source.get('failure_detail') or '').strip()[:200]
        if detail:
            data['failure_detail']=detail
        data['error']=f"{ADMISSION_STAGES[data['failure_stage']]}未通过：{ADMISSION_FAILURES[data['failure_code']]}"
    source_limit_enforced = source.get('source_limit_enforced') is not False
    raw_limit = source.get('source_limit')
    source_limit = int(raw_limit) if raw_limit is not None else (10 if source_limit_enforced else 5)
    default_policy = 'active_limit_enforced' if (source_limit_enforced and raw_limit is not None) else ('first_five_enforced' if source_limit_enforced else 'observe_only')
    source_policy = source.get('source_policy') or default_policy
    data.update(state=source.get('state') if source.get('state') in {'enforced','unverified','unavailable'} else 'unverified',
                limited=source.get('limited') is True,source_limit=source_limit,
                source_limit_enforced=source_limit_enforced,
                source_policy=source_policy,
                tcp_limit=500 if source.get('limited') is True else None)
    data['sources']=[];data['blocked']={}
    try:
        max_sources = max(5, source_limit) if source_limit_enforced else 5
        for item in source.get('sources',[])[:max_sources]:
            data['sources'].append({'ip':str(ipaddress.ip_address(item['ip'])),'first_seen':max(0,int(item['first_seen'])),'confirmed':bool(item.get('confirmed',True))})
        if 'confirmed_sources' in source:
            data['confirmed_sources'] = []
            for item in source.get('confirmed_sources',[])[:max_sources]:
                try:data['confirmed_sources'].append({'ip':str(ipaddress.ip_address(item['ip'])),'first_seen':max(0,int(item['first_seen']))})
                except Exception:pass
        for ip,item in list(source.get('blocked',{}).items())[:32]:
            data['blocked'][str(ipaddress.ip_address(ip))]={k:max(0,min(int(item.get(k,0)),10**15)) for k in ('first_seen','last_seen','packets')}
    except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(400,'invalid bounded source facts')
    if kind!='admission_unverified' and (data['state']!='enforced' or abs(time.time()-data.get('observed_at',0))>30):
        raise HTTPException(400,'fresh verified enforcement receipt required')
    titles={
        'inbound_source_blocked': f'单容器并发业务已达 {source_limit} IP 上限并阻断新连接',
        'tcp_concurrency_limited': 'TCP 新连接上限已设为 500',
        'admission_unverified': '容器网络保护未确认生效',
    }
    messages={
        'inbound_source_blocked': f"活跃并发业务来源已达上限 {source_limit} 个，已阻断超出上限的新来源连接；不影响已有业务连接与常规端口扫描探测。",
        'tcp_concurrency_limited': f"TCP 当前 {data.get('tcp_connections',0)} 条，新连接上限 500，已续期 {data.get('extensions',0)} 次。已有连接自然回落，通知失败不影响保护。",
    }
    message=(f"{ADMISSION_STAGES[data['failure_stage']]}未通过：{ADMISSION_FAILURES[data['failure_code']]}这表示保护状态待核实，不代表已确认攻击，也不能认定保护已生效。"
        if kind=='admission_unverified' else messages[kind])
    clean.update(title=titles[kind],message=message,admission=data,
                 threshold=source_limit if (kind=='inbound_source_blocked' and raw_limit is not None) else clean['threshold'],
                 value=data.get('tcp_connections',0) if kind=='tcp_concurrency_limited' else len(data['sources'])+len(data['blocked']))
    return clean


def _write_admission_status(db, host_id, node_id, client_ip, items, now, on_metric=None):
    conn = db()
    try:
        host = conn.execute('SELECT node_id, last_seen FROM hosts WHERE host_id=?', (host_id,)).fetchone()
        if not host or not node_id or host['node_id'] != node_id:
            raise HTTPException(403, 'wrong node identity')
        existing_rows = conn.execute(
            'SELECT runtime, project, container_name, observed_at FROM admission_states WHERE host_id=?',
            (host_id,),
        ).fetchall()
        existing_observed = {
            (row['runtime'], row['project'], row['container_name']): row['observed_at']
            for row in existing_rows
        }
        items_to_write = []
        for value in items:
            data = value['admission']
            stamp = data.get('observed_at', 0)
            if not isinstance(stamp, int) or isinstance(stamp, bool) or not now - 90 <= stamp <= now + 30:
                continue
            key = (value['runtime'], value['project'], value['container_name'])
            prev_observed = existing_observed.get(key)
            if prev_observed is None or stamp > int(prev_observed):
                items_to_write.append((value, data, stamp))
        has_active = conn.execute(
            "SELECT 1 FROM security_alerts WHERE host_id=? AND alert_type='admission_unverified' AND status='active' LIMIT 1",
            (host_id,),
        ).fetchone()
        db_file = _db_file_key(conn)
        if db_file == '' or HEARTBEAT_WRITE_INTERVAL_SECONDS == 0:
            need_heartbeat = True
        else:
            with _heartbeat_lock:
                cached = _heartbeat_by_db.get((db_file, host_id))
            if cached is None:
                need_heartbeat = True
            else:
                last_ts, last_ip = cached
                need_heartbeat = (
                    now < last_ts
                    or now - last_ts >= HEARTBEAT_WRITE_INTERVAL_SECONDS
                    or (bool(client_ip) and client_ip != last_ip)
                    or now - int(host['last_seen'] or 0) >= HEARTBEAT_WRITE_INTERVAL_SECONDS
                )
        if not need_heartbeat and not items_to_write and not has_active:
            if callable(on_metric):
                on_metric('admission_readonly_hits')
            return

        conn.execute('BEGIN IMMEDIATE')
        conn.execute('UPDATE hosts SET last_seen=? WHERE host_id=?', (now, host_id))
        if client_ip:
            try:
                conn.execute(
                    "INSERT INTO host_client_ips(host_id, client_ip, updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(host_id) DO UPDATE SET client_ip=excluded.client_ip, updated_at=excluded.updated_at",
                    (host_id, client_ip, now),
                )
            except Exception:
                pass
        for value, data, stamp in items_to_write:
            conn.execute(
                '''INSERT INTO admission_states VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(host_id,runtime,project,container_name) DO UPDATE SET
                   instance_id=excluded.instance_id,observed_at=excluded.observed_at,payload=excluded.payload
                   WHERE excluded.observed_at>admission_states.observed_at''',
                (host_id, value['runtime'], value['project'], value['container_name'], value['instance_id'], stamp, json.dumps(data)),
            )
        # Legacy Agents may have written protection-health states into the
        # security incident table. Close those rows only when an active row exists.
        if has_active:
            conn.execute(
                "UPDATE security_alerts SET status='resolved',last_seen=? "
                "WHERE host_id=? AND alert_type='admission_unverified' AND status='active'",
                (now, host_id),
            )
        conn.commit()
        if db_file:
            with _heartbeat_lock:
                _heartbeat_by_db[(db_file, host_id)] = (now, client_ip)
        if callable(on_metric):
            on_metric('admission_write_hits')
    finally:
        conn.close()


def _write_admission_event(db, host_id, node_id, alert, now, process_alerts, reconcile):
    conn = db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        host = conn.execute('SELECT node_id FROM hosts WHERE host_id=?', (host_id,)).fetchone()
        if not host or not node_id or host['node_id'] != node_id:
            raise HTTPException(403, 'wrong node identity')
        conn.execute('UPDATE hosts SET last_seen=? WHERE host_id=?', (now, host_id))
        process_alerts(conn, host_id, now, [alert], partial=True)
        reconcile(conn, host_id, now)
        conn.commit()
    finally:
        conn.close()


def attach(app,db,verify_signature,signed_response,process_alerts,sync_bots,reconcile,on_event=None,on_metric=None):
    @app.post('/api/v1/admission/status')
    async def status(request:Request,x_timestamp:str=Header(default=''),x_signature:str=Header(default='')):
        chunks=bytearray()
        async for chunk in request.stream():
            if len(chunks)+len(chunk)>1048576:raise HTTPException(413,'status too large')
            chunks.extend(chunk)
        body=bytes(chunks);verify_signature(body,x_timestamp,x_signature)
        try:
            payload=json.loads(body);host_id=str(payload.get('host_id') or '');node_id=str(payload.get('node_id') or '')
            values=payload['items']
            if not isinstance(values,list) or len(values)>1000:raise ValueError()
            items=[normalized_alert({**v,'type':'admission_unverified'}) for v in values]
        except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(400,'invalid bounded status batch')
        now=int(time.time())
        forwarded = request.headers.get('x-forwarded-for')
        client_ip = forwarded.split(',')[0].strip() if forwarded else (request.client.host if request.client else '')
        await asyncio.to_thread(_write_admission_status, db, host_id, node_id, client_ip, items, now, on_metric)
        return signed_response({'ok':True},x_timestamp)

    @app.post('/api/v1/admission/events')
    async def event(request:Request,x_timestamp:str=Header(default=''),x_signature:str=Header(default='')):
        chunks=bytearray()
        async for chunk in request.stream():
            if len(chunks)+len(chunk)>65536:raise HTTPException(413,'event too large')
            chunks.extend(chunk)
        body=bytes(chunks);verify_signature(body,x_timestamp,x_signature)
        try:
            payload=json.loads(body)
            host_id,node_id=str(payload.get('host_id') or ''),str(payload.get('node_id') or '')
            alert=normalized_alert(payload.get('alert'))
        except (ValueError,TypeError,AttributeError):raise HTTPException(400,'invalid event payload')
        now=int(time.time())
        await asyncio.to_thread(_write_admission_event, db, host_id, node_id, alert, now, process_alerts, reconcile)
        if callable(on_event):
            on_event('admission', host_id)
        # Delivery may fail without affecting the committed receipt or local rules.
        try:await asyncio.to_thread(sync_bots, host_id, now)
        except Exception:pass
        return signed_response({'ok':True},x_timestamp)
