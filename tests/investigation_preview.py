"""Synthetic loopback-only UI fixture. Never use on a public/production server."""
import base64
import tempfile
import time
from pathlib import Path

import uvicorn
from server import app as server
from server import buyer_notifications as buyer, investigation


def main():
    with tempfile.TemporaryDirectory(prefix="narwhal-investigation-preview-") as temp:
        server.DB_PATH = str(Path(temp) / "preview.db")
        server.DASHBOARD_USERNAME = "preview"
        server.DASHBOARD_PASSWORD = "local-preview-only"
        server.APP_VERSION = "1.7.5-preview"
        server.init_db()
        now = int(time.time())
        conn = server.db()
        host = "HK-Hytron 1号鸡"
        node = "preview-node-1"
        conn.execute("INSERT INTO hosts VALUES(?,?,'preview',?,'{}')", (host, now, node))
        owners = ['U-1042'] * 8 + ['U-2038'] * 10 + ['U-3011'] * 7 + ['U-4040'] * 16 + ['']
        names = ['A1B2', 'C3D4', 'E5F6', 'G7H8', 'J9K0', 'L1M2'] + [f'instance-{i:02d}' for i in range(6, 42)]
        containers = [{"runtime": "incus", "project": "default", "name": name, "id": "demo-" + name,
                       "security": {"socks_proxy": {"detected": False}}} for name in names]
        for c, owner in zip(containers, owners):
            if owner:
                buyer.save_target(conn, {"host_id": host, "runtime": "incus", "project": "default", "container_name": c['name'],
                                        "machine_id": "00000000-0000-0000-0000-000000000001", "user_id": owner})
        counts = {0: 3, 1: 2, 2: 1, 3: 1, 4: 1, 5: 1, 8: 2, 9: 1, 18: 1, 41: 1}
        events = {}
        for index, count in counts.items():
            for episode in range(count):
                ts = now - (10 - episode * 3) * 86400 + index * 30
                kind = "ops_bandwidth_saturation" if index == 2 else "http_signal" if index == 3 else "socks_weak_auth"
                title = "带宽持续占满" if index == 2 else "外部攻击信号" if index == 3 else "弱密码代理" if index == 1 else "无密码 SOCKS代理"
                alert = {"type": kind, "runtime": "incus", "project": "default", "container_name": names[index],
                         "title": title, "severity": "warning" if index in {2, 3} else "critical", "value": 96 if index == 2 else 0, "threshold": 90 if index == 2 else 0,
                         "auth_mode": "no_auth", "service_listeners": [{"process": "danted", "local": "0.0.0.0:1080", "pid": 1234}]}
                events.setdefault(ts, []).append(alert)
        investigation.observe(conn, host, node, now - 31 * 86400, containers, set())
        for ts, alerts in sorted(events.items()):
            for sample, current in ((ts, alerts), (ts + 10, []), (ts + 20, [])):
                server.process_security_alerts(conn, host, sample, current)
                buyer.observe(conn, host, sample, containers, current)
                fingerprints = {r[0] for r in conn.execute("SELECT fingerprint FROM security_alerts WHERE host_id=? AND last_seen=? AND status<>'resolved'", (host, sample))}
                investigation.observe(conn, host, node, sample, containers, fingerprints)
        investigation.observe(conn, host, node, now, containers, set())
        other = "HK-Hytron 2号鸡"
        conn.execute("INSERT INTO hosts VALUES(?,?,'preview',?,'{}')", (other, now, 'preview-node-2'))
        investigation.observe(conn, other, 'preview-node-2', now, [], set())
        conn.commit()
        conn.close()

        async def loopback_preview(scope, receive, send):
            if scope['type'] == 'http':
                scope['headers'] = [(k, v) for k, v in scope['headers'] if k != b'authorization'] + [
                    (b'authorization', b'Basic ' + base64.b64encode(b'preview:local-preview-only'))]
            await server.app(scope, receive, send)
        uvicorn.run(loopback_preview, host="127.0.0.1", port=8786, log_level="warning")


if __name__ == '__main__': main()
