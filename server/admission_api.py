"""Signed, bounded node-local enforcement receipts. No firewall decisions here."""
import ipaddress
import json
import re
import time
from fastapi import Header, HTTPException, Request

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


def normalized_alert(value):
    if not isinstance(value,dict) or value.get('type') not in KINDS:
        raise HTTPException(400,'unsupported admission event')
    runtime,project,name,identity=(str(value.get(k) or '') for k in ('runtime','project','container_name','instance_id'))
    if runtime not in {'incus','podman'} or not re.fullmatch(r'[A-Za-z0-9_.:@+-]{1,200}',name):
        raise HTTPException(400,'supported instance required')
    if project and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',project):raise HTTPException(400,'invalid project')
    if identity and not re.fullmatch(r'[A-Za-z0-9-]{12,100}',identity):raise HTTPException(400,'invalid identity')
    if not identity and value['type']!='admission_unverified':raise HTTPException(400,'stable identity required')
    kind=value['type']
    clean={'runtime':runtime,'project':project,'container_name':name,'instance_id':identity,'type':kind,
           'severity':'warning' if kind in {'admission_unverified','tcp_concurrency_limited'} else 'critical',
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
    data.update(state=source.get('state') if source.get('state') in {'enforced','unverified','unavailable'} else 'unverified',
                limited=source.get('limited') is True,source_limit=5,tcp_limit=500 if source.get('limited') is True else None)
    data['sources']=[];data['blocked']={}
    try:
        for item in source.get('sources',[])[:5]:
            data['sources'].append({'ip':str(ipaddress.ip_address(item['ip'])),'first_seen':max(0,int(item['first_seen']))})
        for ip,item in list(source.get('blocked',{}).items())[:32]:
            data['blocked'][str(ipaddress.ip_address(ip))]={k:max(0,min(int(item.get(k,0)),10**15)) for k in ('first_seen','last_seen','packets')}
    except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(400,'invalid bounded source facts')
    if kind!='admission_unverified' and (data['state']!='enforced' or abs(time.time()-data.get('observed_at',0))>30):
        raise HTTPException(400,'fresh verified enforcement receipt required')
    titles={'inbound_source_blocked':'入站超过 5 个来源，已拒绝新增来源','tcp_concurrency_limited':'TCP 新连接上限已设为 500','admission_unverified':'容器网络保护未确认生效'}
    messages={'inbound_source_blocked':f"保留先观测到的 {len(data['sources'])} 个来源，拒绝新增来源；不影响母鸡及其他容器。",
        'tcp_concurrency_limited':f"TCP 当前 {data.get('tcp_connections',0)} 条，新连接上限 500，已续期 {data.get('extensions',0)} 次。已有连接自然回落，通知失败不影响保护。",
        'admission_unverified':f"{ADMISSION_STAGES[data['failure_stage']]}未通过：{ADMISSION_FAILURES[data['failure_code']]}这表示保护状态待核实，不代表已确认攻击，也不能认定保护已生效。"}
    clean.update(title=titles[kind],message=messages[kind],admission=data,value=data.get('tcp_connections',0) if kind=='tcp_concurrency_limited' else len(data['sources'])+len(data['blocked']))
    return clean


def attach(app,db,verify_signature,signed_response,process_alerts,sync_bots,reconcile):
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
        now=int(time.time());conn=db()
        try:
            host=conn.execute('SELECT node_id FROM hosts WHERE host_id=?',(host_id,)).fetchone()
            if not host or not node_id or host['node_id']!=node_id:raise HTTPException(403,'wrong node identity')
            for value in items:
                data=value['admission'];stamp=data.get('observed_at',0)
                if not now-90<=stamp<=now+30:continue
                conn.execute('''INSERT INTO admission_states VALUES(?,?,?,?,?,?,?)
                    ON CONFLICT(host_id,runtime,project,container_name) DO UPDATE SET
                    instance_id=excluded.instance_id,observed_at=excluded.observed_at,payload=excluded.payload
                    WHERE excluded.observed_at>admission_states.observed_at''',
                    (host_id,value['runtime'],value['project'],value['container_name'],value['instance_id'],stamp,json.dumps(data)))
            # A current-state table, not an append-only telemetry log.
            conn.execute('DELETE FROM admission_states WHERE observed_at<?',(now-86400,))
            conn.commit()
        finally:conn.close()
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
        now=int(time.time());conn=db()
        try:
            conn.execute('BEGIN IMMEDIATE')
            host=conn.execute('SELECT node_id FROM hosts WHERE host_id=?',(host_id,)).fetchone()
            if not host or not node_id or host['node_id']!=node_id:raise HTTPException(403,'wrong node identity')
            process_alerts(conn,host_id,now,[alert],partial=True)
            reconcile(conn,host_id,now)
            conn.commit()
        finally:conn.close()
        # Delivery may fail without affecting the committed receipt or local rules.
        try:sync_bots(host_id,now)
        except Exception:pass
        return signed_response({'ok':True},x_timestamp)
