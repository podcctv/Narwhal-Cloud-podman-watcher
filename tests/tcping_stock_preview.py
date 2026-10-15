"""Loopback-only product mapping fixture. No upstream network or real probes."""
import json
import tempfile
import time
import uuid
from pathlib import Path
import uvicorn
from server import app as server, tcping
from tests.test_tcping import raw_directory


def main():
    with tempfile.TemporaryDirectory(prefix='narwhal-stock-preview-') as temp:
        server.DB_PATH = str(Path(temp)/'preview.db')
        server.DASHBOARD_USERNAME = 'preview'
        server.DASHBOARD_PASSWORD = 'local-preview-only'
        server.init_db();now=int(time.time());c=server.db();products={}
        for i,(name,remaining,kind) in enumerate([
            ('自动关联新增节点',9,'auto'),('手动关联售罄节点',0,'manual'),
            ('冲突关联节点',5,'conflict'),('名称不符节点',6,'mismatch')]):
            node,mid,plan=str(uuid.uuid4()),str(uuid.uuid4()),str(uuid.uuid4())
            server._reconcile_host(c,name,node,now,'1.7.36',{})
            c.execute('INSERT INTO ops_hosts VALUES(?,?,?,?)',(node,name,now,json.dumps({'capabilities':[tcping.CAPABILITY]})))
            link=f'https://dash.fuckip.me/deploy?machine_id={mid}' if kind=='manual' else ''
            c.execute('INSERT INTO tcp_sources(id,host_id,node_id,name,purchase_url,enabled) VALUES(?,?,?,?,?,1)',(str(i),name,node,name,link))
            products[mid]={'product_id':mid,'product_name':name if kind!='mismatch' else '不相关商品','virtualization_type':'incus',
                           'sale_status':'available' if remaining else 'sold_out','remaining':remaining,
                           'purchase_url':f'https://dash.fuckip.me/deploy?machine_id={mid}&plan_id={plan}&region=HK' if remaining else ''}
            if kind!='manual':
                for mapped in [mid]+([str(uuid.uuid4())] if kind=='conflict' else []):
                    vm=str(uuid.uuid4())
                    c.execute("INSERT INTO buyer_targets(host_id,runtime,project,container_name,machine_id,user_id,enabled,source,vm_id,verified_at) VALUES(?,'incus','default',?,?,'synthetic-private-buyer',1,'upstream',?,?)",(name,vm,mapped,vm,now))
        c.execute("UPDATE tcp_settings SET value='true' WHERE key='enabled'")
        d=tcping.configured_directory(raw_directory());c.execute('INSERT INTO tcp_directories VALUES(?,?,?)',(d['generation'],tcping.encoded(d),now));c.commit();c.close()
        tcping.refresh_directory=lambda db:None
        tcping.fetch_public_product=lambda mid:products.get(mid)
        uvicorn.run(server.app,host='127.0.0.1',port=8794,log_level='warning')


if __name__=='__main__':main()
