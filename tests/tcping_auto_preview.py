"""Loopback-only synthetic TCPing management; no real Agents or probes."""
import json
import tempfile
import time
from pathlib import Path
import uvicorn
from server import app as server, tcping
from tests.test_tcping import raw_directory


def main():
    with tempfile.TemporaryDirectory(prefix='narwhal-tcp-auto-preview-') as directory:
        server.DB_PATH = str(Path(directory)/'preview.db')
        server.DASHBOARD_USERNAME = 'preview'
        server.DASHBOARD_PASSWORD = 'local-preview-only'
        server.APP_VERSION = '1.7.30'
        server.init_db()
        now = int(time.time())
        c = server.db()
        long_host = '[Hytron2.0][AdguardVPN+Hurricane Electric + 公益家宽]船新上线'
        for name,node in [(long_host,'existing-node'),('GB CN2 合成伦敦节点','new-node'),('hidden-host','hidden-node')]:
            server._reconcile_host(c,name,node,now,'1.7.29',{})
            c.execute('INSERT INTO ops_hosts VALUES(?,?,?,?)',(node,name,now,json.dumps({'capabilities':[tcping.CAPABILITY]})))
        c.execute("INSERT INTO tcp_sources(id,host_id,node_id,name,enabled) VALUES('existing',?,'existing-node',?,1)",(long_host,long_host))
        c.execute("INSERT INTO tcp_sources(id,host_id,node_id,name,enabled) VALUES('hidden','hidden-host','hidden-node','hidden-public',0)")
        c.execute("UPDATE tcp_settings SET value='true' WHERE key='enabled'")
        d = tcping.configured_directory(raw_directory())
        c.execute('INSERT INTO tcp_directories VALUES(?,?,?)',(d['generation'],tcping.encoded(d),now))
        c.commit();c.close()
        tcping.refresh_directory = lambda db: None
        uvicorn.run(server.app,host='127.0.0.1',port=8791,log_level='warning')


if __name__ == '__main__':
    main()
