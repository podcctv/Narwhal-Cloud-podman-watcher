"""Admin-only opt-in disk maintenance and bounded, node-scoped history."""
import json
import re
import time
from fastapi import APIRouter,HTTPException,Request

DEFAULT={'enabled':False,'include_containers':True,'retention_days':14,'interval_hours':24}
TYPES={'disk_cleanup_scan','disk_cleanup_execute'}


def policy(value):
    if not isinstance(value,dict) or set(value)-set(DEFAULT):raise ValueError('unknown cleanup policy')
    p={**DEFAULT,**value}
    if any(type(p[k]) is not bool for k in ('enabled','include_containers')):raise ValueError('boolean required')
    if type(p['retention_days']) is not int or not 14<=p['retention_days']<=90:raise ValueError('日志保留应为 14-90 天')
    if type(p['interval_hours']) is not int or not 6<=p['interval_hours']<=168:raise ValueError('清理间隔应为 6-168 小时')
    return p


def node_config(conn,node):
    row=conn.execute('SELECT payload FROM ops_disk_cleanup_policies WHERE node=?',(node,)).fetchone()
    return {**(json.loads(row[0]) if row else DEFAULT),'node_id':node}


def record(conn,host,node,value):
    if not isinstance(value,dict):return
    run_id=str(value.get('run_id',''))
    if not re.fullmatch(r'(?:action-\d{1,15}|[a-f0-9]{32})',run_id) or value.get('node_id')!=node:return
    status=value.get('status');mode=value.get('mode')
    if status not in ('running','scanned','succeeded','partial','failed','interrupted') or mode not in ('scan','clean'):return
    try:
        started=int(value['started_at']);action=int(value.get('action_id',0))
        if abs(started-time.time())>30*86400:return
    except (ValueError,TypeError,KeyError):return
    if action:
        row=conn.execute('SELECT action_type,params_json FROM security_actions WHERE id=? AND host_id=?',(action,host)).fetchone()
        if not row or row[0] not in TYPES or json.loads(row[1]).get('expected_node_id')!=node or run_id!='action-'+str(action):return
        if mode!=('scan' if row[0]=='disk_cleanup_scan' else 'clean'):return
    elif value.get('automatic') is not True:return
    clean={k:value.get(k) for k in ('run_id','node_id','action_id','mode','automatic','started_at','finished_at','status','plan_id')}
    clean['items']=[]
    items=value.get('items',[])
    if not isinstance(items,list):return
    for item in items[:5]:
        if not isinstance(item,dict):continue
        safe={k:item.get(k) for k in ('runtime','name','project','instance_id','status','reason','bounded') if isinstance(item.get(k),(str,bool))}
        if any(len(str(v))>200 for v in safe.values()):continue
        for k in ('candidate_files','candidate_bytes','deleted_files','unlinked_bytes','freed_bytes','skipped','errors'):
            n=item.get(k,0);safe[k]=min(2**60,max(0,n)) if type(n) is int else 0
        for k in ('before','after'):
            x=item.get(k,{})
            if isinstance(x,dict):safe[k]={name:n for name,n in x.items() if name in ('total_bytes','available_bytes','used_percent') and type(n) in (int,float) and 0<=n<=2**60}
        clean['items'].append(safe)
    # Delayed reports must not turn a terminal result back into running.
    old=conn.execute('SELECT payload FROM ops_disk_cleanup_runs WHERE node=? AND run_id=?',(node,run_id)).fetchone()
    if old and json.loads(old[0]).get('status')!='running' and status=='running':return
    conn.execute('INSERT INTO ops_disk_cleanup_runs VALUES(?,?,?,?,?) ON CONFLICT(node,run_id) DO UPDATE SET payload=excluded.payload,ts=excluded.ts',
                 (node,run_id,host,started,json.dumps(clean,ensure_ascii=False)))


def attach(app,db):
    router=APIRouter(prefix='/api/v1/ops/disk-cleanup')
    @router.get('')
    def overview():
        c=db()
        try:
            hosts=[]
            for h in c.execute('SELECT host_id,node_id,last_seen FROM hosts ORDER BY host_id LIMIT 500'):
                row=c.execute('SELECT payload FROM ops_hosts WHERE node=?',(h['node_id'],)).fetchone()
                data=json.loads(row[0]) if row else {};s=data.get('disk_cleanup',{})
                hosts.append({**dict(h),'stale':time.time()-h['last_seen']>900,'available':s.get('available') is True,
                              'running':s.get('running') is True,'disk':s.get('disk',{}),'policy':node_config(c,h['node_id'])})
            runs=[{**json.loads(r['payload']),'host_id':r['host_id']} for r in c.execute('SELECT host_id,payload FROM ops_disk_cleanup_runs ORDER BY ts DESC LIMIT 200')]
            actions=[dict(r) for r in c.execute("SELECT id,host_id,action_type,status,result_message,updated_at FROM security_actions WHERE action_type IN ('disk_cleanup_scan','disk_cleanup_execute') ORDER BY id DESC LIMIT 50")]
            return {'hosts':hosts,'runs':runs,'actions':actions,'warning_percent':90}
        finally:c.close()

    @router.post('/{operation}')
    async def change(operation:str,request:Request):
        if getattr(request.state,'dashboard_role','')!='admin':raise HTTPException(403,'仅管理员可配置或清理磁盘')
        p=await request.json()
        if not isinstance(p,dict):raise HTTPException(400,'invalid payload')
        c=db()
        try:
            h=c.execute('SELECT host_id,node_id,last_seen FROM hosts WHERE host_id=?',(str(p.get('host_id','')),)).fetchone()
            if not h or not h['node_id'] or h['node_id']!=p.get('node_id') or time.time()-h['last_seen']>900:raise HTTPException(409,'节点过期或身份已变化，请刷新')
            row=c.execute('SELECT payload FROM ops_hosts WHERE node=?',(h['node_id'],)).fetchone()
            if not row or json.loads(row[0]).get('disk_cleanup',{}).get('available') is not True:raise HTTPException(409,'需要支持安全清理的原生宿主机 Agent')
            if operation=='policy':
                try:saved=policy(p.get('policy'))
                except ValueError as e:raise HTTPException(400,str(e)) from None
                if saved['enabled'] and p.get('confirmed') is not True:raise HTTPException(400,'启用自动删除需要确认')
                c.execute('INSERT INTO ops_disk_cleanup_policies VALUES(?,?,?) ON CONFLICT(node) DO UPDATE SET host_id=excluded.host_id,payload=excluded.payload',(h['node_id'],h['host_id'],json.dumps(saved)))
                c.commit();return {'ok':True,'policy':saved}
            if operation not in ('scan','execute'):raise HTTPException(404,'unknown operation')
            if c.execute("SELECT 1 FROM security_actions WHERE host_id=? AND action_type IN ('disk_cleanup_scan','disk_cleanup_execute') AND status IN ('queued','dispatched','running') AND created_at>?",(h['host_id'],time.time()-900)).fetchone():raise HTTPException(409,'已有清理任务在排队或执行')
            params={'expected_node_id':h['node_id']}
            if operation=='execute':
                plan=c.execute('SELECT payload FROM ops_disk_cleanup_runs WHERE node=? AND run_id=?',(h['node_id'],str(p.get('plan_id','')))).fetchone()
                data=json.loads(plan[0]) if plan else {}
                if p.get('confirmed') is not True or data.get('mode')!='scan' or data.get('status') not in ('scanned','partial') or not any(i.get('status')=='scanned' for i in data.get('items',[])) or time.time()-data.get('started_at',0)>900:raise HTTPException(409,'需要 15 分钟内安全完成的扫描及确认')
                params.update(plan_id=p['plan_id'],confirmed=True)
            now=int(time.time());action=c.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,?,'host','','__host__',?,?,'queued',?,?,?)",(h['host_id'],'disk_cleanup_'+('scan' if operation=='scan' else 'execute'),json.dumps(params),request.state.dashboard_user,now,now)).lastrowid
            c.commit();return {'ok':True,'queued':True,'action_id':action}
        finally:c.close()
    app.include_router(router)
