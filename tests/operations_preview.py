"""Local UI fixture (loopback only). Never run this wrapper on a public server."""
import base64
import json
import tempfile
import time
from pathlib import Path
import uvicorn
from server import app as server
from server import operations as ops


def main():
    with tempfile.TemporaryDirectory(prefix="narwhal-preview-") as temp:
        server.DB_PATH=str(Path(temp)/"preview.db")
        server.DASHBOARD_USERNAME="preview"
        server.DASHBOARD_PASSWORD="local-preview-only"
        server.APP_VERSION="1.7.0"
        server.init_db()
        now=int(time.time())
        conn=server.db()
        for i,host in enumerate(("HK-Hytron 1号鸡", "HK-Hytron 2号鸡")):
            node=f"preview-{i}"
            conn.execute("INSERT INTO hosts VALUES(?,?,'1.7.0',?,'{}')",(host,now,node))
            data={"agent_version":"1.7.0","client_config":{"report_interval":300},"security":{"enabled":True,"alerts":[]},"containers":[{"name":"very-long-container-name-proxy-application","runtime":"incus","project":"default","cpu_percent":15,"mem_percent":40,"net_rx_bps":20000,"net_tx_bps":30000,"conn_count":50,"traffic_counters":{"available":True,"rx":1000,"tx":1000,"epoch":"a"},"security":{"process_count":4}}],"operations":{"architecture":"aarch64" if i else "x86_64","managed_upgrade":True,"health":[{"source":"http_logs","status":"permission_denied" if i else "idle","details":{"readable_files":0 if i else 1,"requests":0,"parse_errors":0},"guidance":"使用日志向导发现路径，确认格式和 Agent 读取权限"},{"source":"network_counters","status":"healthy","details":{"available":1,"containers":1},"guidance":"网络累计计数已采集"}],"log_discovery":[{"path":"/var/log/nginx/access.log","status":"healthy","parsed":20,"samples":20,"formats":["combined"],"methods":["GET"],"modified_at":now}]}}
            ops.ingest(conn,host,node,now-300,data)
            data["containers"][0]["traffic_counters"]["rx"]=250000
            ops.ingest(conn,host,node,now,data)
            ops.event(conn,ops.identity(node,"incus","default",data["containers"][0]["name"]),"baseline_anomaly",now,{"severity":"warning","message":"预览事件：流量与连接持续偏离"})
        conn.commit()
        conn.close()
        async def loopback_preview(scope,receive,send):
            if scope["type"]=="http":
                scope["headers"]=[(k,v) for k,v in scope["headers"] if k!=b"authorization"]+[(b"authorization",b"Basic "+base64.b64encode(b"preview:local-preview-only"))]
            await server.app(scope,receive,send)
        uvicorn.run(loopback_preview,host="127.0.0.1",port=8785,log_level="warning")


if __name__=="__main__":
    main()
