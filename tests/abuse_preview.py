"""Loopback-only UI fixture. Synthetic events; never connects to a real node/bot."""
import tempfile
import time
from pathlib import Path
import uvicorn
from server import app as server, abuse_api


def main():
    with tempfile.TemporaryDirectory(prefix='narwhal-abuse-ui-') as temp:
        server.DB_PATH = str(Path(temp)/'preview.db')
        server.DASHBOARD_USERNAME = 'preview'
        server.DASHBOARD_PASSWORD = 'local-preview-only'
        server.PUBLIC_BASE_URL = ''
        server.init_db()
        now = int(time.time())
        conn = server.db()
        conn.execute("INSERT INTO hosts VALUES('synthetic-lab-host',?,'test','synthetic-node','{}')", (now,))
        alert = abuse_api.normalized_alert({
            'type': 'prohibited_activity', 'runtime': 'incus', 'project': 'default',
            'container_name': 'synthetic-long-container-name-1234567890', 'instance_id': 'a'*36,
            'abuse_evidence': [{'kind': 'identity_enumeration', 'confidence': 'high',
                'pid': 1234, 'start_ticks': '4567', 'source_sha256': 'b'*64,
                'pending_attempts':48,'vertical_ports':48,'pending_ratio':1,
                'features': {'corroborating_samples': 2, 'concurrency': 100}}],
            'network_quarantine': {'status': 'isolated', 'ingress_blocked': True, 'egress_blocked': True}})
        server.process_security_alerts(conn, 'synthetic-lab-host', now, [alert], partial=True)
        alert_id = conn.execute('SELECT id FROM security_alerts').fetchone()[0]
        conn.execute('INSERT INTO network_quarantines VALUES(?,?,?,?,?,?,?,?,?)',
            ('synthetic-lab-host','incus','default',alert['container_name'],alert['instance_id'],alert_id,'isolated',now,now))
        conn.commit()
        conn.close()
        uvicorn.run(server.app, host='127.0.0.1', port=8787, log_level='warning')


if __name__ == '__main__':
    main()
