"""Loopback-only synthetic UI preview; never starts a cleanup worker or real node."""
import asyncio
import hashlib
import hmac
import json
import tempfile
import time
from pathlib import Path
import httpx
import uvicorn
from fastapi import Request
from server import app as server, operations as ops, disk_cleanup


def main():
    with tempfile.TemporaryDirectory(prefix='narwhal-disk-preview-') as directory:
        server.DB_PATH=str(Path(directory)/'preview.db')
        server.DASHBOARD_USERNAME='preview';server.DASHBOARD_PASSWORD='local-preview-only'
        server.APP_VERSION='1.7.23';server.init_db();now=int(time.time())
        async def populate():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url='http://test') as c:
                for i in range(3):
                    host='synthetic-host-'+str(i);node='synthetic-node-'+str(i)
                    data={'host_id':host,'node_id':node,'timestamp':now,'agent_version':'1.7.23',
                          'client_config':{'report_interval':300},'security':{'enabled':True,'alerts':[]},
                          'containers':[{'name':'owned-long-container-name-'+48*'a','id':32*'b','runtime':'podman','status':'running','cpu_percent':4,'mem_percent':20,'security':{},
                                         'disk':{'used_percent':93 if i==0 else 50,'root_used_percent':93 if i==0 else 50,'root_total_bytes':100*1024**3,'root_avail_bytes':7*1024**3}}],
                          'operations':{'health':[],'disk_cleanup':{'available':i!=2,'running':False,'policy':disk_cleanup.DEFAULT,'runs':[],
                                        'disk':{'used_percent':93 if i==0 else 50,'available_bytes':7*1024**3}}}}
                    body=json.dumps(data).encode();ts=str(now)
                    sig=hmac.new(server.SHARED_SECRET.encode(),body+ts.encode(),hashlib.sha256).hexdigest()
                    r=await c.post('/api/v1/report',content=body,headers={'X-Timestamp':ts,'X-Signature':sig,'Content-Type':'application/json'});r.raise_for_status()
        asyncio.run(populate())
        c=server.db()
        c.execute("INSERT INTO ops_users VALUES('reader',?,'viewer',1,?)",(ops.password_hash('local-preview-only'),now))
        cur=c.execute("INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) VALUES(0,'synthetic-host-0','host','','__host__','disk_cleanup_scan',?,'succeeded','preview',?,?)",(json.dumps({'expected_node_id':'synthetic-node-0'}),now,now))
        aid=cur.lastrowid
        disk_cleanup.record(c,'synthetic-host-0','synthetic-node-0',{'run_id':'action-'+str(aid),'action_id':aid,'node_id':'synthetic-node-0','mode':'scan','status':'scanned','automatic':False,'started_at':now,'finished_at':now,
            'items':[{'runtime':'host','name':'__host__','status':'scanned','candidate_files':3,'candidate_bytes':5*1024**2,'before':{'used_percent':93},'after':{'used_percent':93}},
                     {'runtime':'podman','name':'owned-long-container-name-'+48*'a','status':'scanned','candidate_files':2,'candidate_bytes':2*1024**2,'before':{'used_percent':93},'after':{'used_percent':93}}]})
        c.commit();c.close()
        @server.app.post('/api/v1/ops/cleanup-preview-expire')
        def expire(request:Request):
            assert request.client.host in ('127.0.0.1','testclient')
            c=server.db();c.execute("UPDATE hosts SET last_seen=1 WHERE host_id='synthetic-host-0'");c.commit();c.close()
            return {'ok':True}
        uvicorn.run(server.app,host='127.0.0.1',port=8788,log_level='warning')


if __name__=='__main__':main()
