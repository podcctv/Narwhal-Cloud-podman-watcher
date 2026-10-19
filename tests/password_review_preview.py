"""Loopback-only synthetic UI, lifespan disabled: no buyers, Agents or bots contacted."""
import json
import os
import tempfile
import time
from pathlib import Path
from contextlib import closing
import uvicorn
from server import app as server, buyer_notifications as buyer
from client.socks_detector import password_profile


def main():
    with tempfile.TemporaryDirectory(prefix='narwhal-password-review-') as directory:
        server.DB_PATH = str(Path(directory)/'preview.db')
        server.DASHBOARD_USERNAME = 'preview'
        server.DASHBOARD_PASSWORD = 'local-preview-only'
        server.PUBLIC_BASE_URL = ''
        server.APP_VERSION = '1.7.44'
        server.init_db()
        now = int(time.time())
        with closing(server.db()) as conn:
            conn.execute("INSERT INTO hosts VALUES('合成香港节点',?,'1.7.39','synthetic-node','{}')",(now,))
            server._set_system_setting(conn,'narwhal_api_key','synthetic-not-for-network')
            for index, process in enumerate(('gost','danted')):
                name=f'synthetic-instance-{index+1}'
                profile=password_profile('Aa1112!!') if index == 0 else {'available':False,'reason':'Dante 使用系统/PAM 认证；不能从密码哈希还原长度或组成'}
                alert={'type':'socks_password_review','severity':'warning','title':'SOCKS 密码待人工评估',
                    'message':'已确认服务要求认证；请查看密码组成后选择放行或停止，未自动停止服务',
                    'runtime':'incus','project':'default','container_name':name,'review_token':str(index+1)*64,
                    'review_observed_at':now,'socks_auth_mode':'unknown','socks_processes':[process],
                    'service_listeners':[{'pid':27+index,'process':process,'local':'*:6987','port':6987}],
                    'password_review':[{'pid':27+index,'process':process,'port':6987,'action_safe':True,
                        'config_path':f'/etc/{process}/config.yaml','password_profiles':[profile]}]}
                server.process_security_alerts(conn,'合成香港节点',now,[alert],partial=True)
                buyer.save_target(conn,{'host_id':'合成香港节点','runtime':'incus','project':'default','container_name':name,
                    'machine_id':'00000000-0000-0000-0000-000000000001','user_id':'synthetic-user-1','node_name':'香港演示服务器'})
                container={'name':name,'runtime':'incus','project':'default','cpu_percent':1,'mem_bytes':1024,
                    'mem_percent':1,'net_rx_bps':0,'net_tx_bps':0,'conn_count':2,'security':{'socks_proxy':{'detected':True,'auth_mode':'unknown'}}}
                if index==0:
                    container['security']['admission']={'state':'enforced','instance_id':'a'*36,'observed_at':now,
                        'sources':[{'ip':ip,'first_seen':now-300} for ip in ('192.0.2.1','2001:db8::1','192.0.2.2','2001:db8::2','192.0.2.3')],
                        'blocked':{'2001:db8:ffff:ffff:ffff:ffff:ffff:ffff':{'first_seen':now,'last_seen':now,'packets':42}},
                        'limited':True,'tcp_connections':499,'review_at':now+900,'extensions':2}
                conn.execute("INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,ts,payload_json,podman_network_ok_v4,podman_network_ok_v6) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,1)",
                    ('合成香港节点',name,'incus','default',1,1024,1,0,0,2,now,json.dumps(container)))
            panel_alert={'type':'standalone_proxy_panel','severity':'warning','title':'检测到独立代理管理面板（仅提醒）',
                'message':'检测到 S-ui（PID 210，监听端口 9443）。安装本身不等于弱密码或异常行为；仅提醒，不自动停止业务。',
                'runtime':'incus','project':'default','container_name':'synthetic-panel-instance',
                'standalone_panels':[{'panel':'S-ui','process':'sui','pid':210}],'panel_auth_status':'not_assessed','auto_stop_eligible':False}
            server.process_security_alerts(conn,'合成香港节点',now,[panel_alert],partial=True)
            conn.execute("INSERT INTO reports(host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,net_rx_bps,net_tx_bps,conn_count,ts,payload_json,podman_network_ok_v4,podman_network_ok_v6) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,1)",
                ('合成香港节点','synthetic-panel-instance','incus','default',0,0,0,0,0,0,now,json.dumps({'name':'synthetic-panel-instance','runtime':'incus','project':'default'})))
            recovered = {'type':'container_connection_count','severity':'critical','title':'历史连接数告警',
                'message':'合成历史恢复记录','runtime':'incus','project':'default','container_name':'synthetic-recovered',
                'value':3251,'threshold':1000}
            first = now-6*3600-34*60
            server.process_security_alerts(conn,'合成香港节点',first,[recovered],partial=True)
            row = conn.execute("SELECT id FROM security_alerts WHERE container_name='synthetic-recovered'").fetchone()
            conn.execute("UPDATE security_alerts SET status='resolved',last_seen=? WHERE id=?", (now-60,row['id']))
            conn.execute('INSERT INTO buyer_checks(alert_id,episode,clean_samples,last_sample,state,verified_at) VALUES(?,?,2,?,?,?)', (row['id'],first,now,'verified',now))
            conn.commit()
        uvicorn.run(server.app,host='127.0.0.1',port=int(os.getenv('NARWHAL_PREVIEW_PORT','8793')),log_level='warning',lifespan='off')


if __name__ == '__main__': main()
