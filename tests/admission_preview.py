"""Loopback-only admission UI fixture with synthetic container evidence."""
import json
import tempfile
import time
from pathlib import Path

import uvicorn
from server import app as server


def main():
    with tempfile.TemporaryDirectory(prefix="narwhal-admission-preview-") as directory:
        server.DB_PATH = str(Path(directory) / "preview.db")
        server.DASHBOARD_USERNAME = "preview"
        server.DASHBOARD_PASSWORD = "local-preview-only"
        server.APP_VERSION = "ui-preview"
        server.init_db()
        now = int(time.time())
        host_id = "synthetic-admission-host"
        container_name = "synthetic-instance-1"
        payload = {
            "id": container_name,
            "name": container_name,
            "runtime": "incus",
            "project": "default",
            "status": "running",
            "cpu_percent": 1.0,
            "mem_percent": 12.0,
            "net_rx_bps": 0,
            "net_tx_bps": 0,
            "conn_count": 499,
            "security": {
                "admission": {
                    "state": "enforced",
                    "observed_at": now,
                    "source_limit": 5,
                    "source_limit_enforced": False,
                    "sources": [
                        {"ip": f"192.0.2.{index}", "first_seen": now - index * 10}
                        for index in range(1, 6)
                    ],
                    "blocked": {
                        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff": {
                            "first_seen": now - 20,
                            "last_seen": now,
                            "packets": 5,
                        }
                    },
                    "limited": True,
                    "tcp_connections": 499,
                    "extensions": 2,
                }
            },
        }
        conn = server.db()
        conn.execute(
            "INSERT INTO hosts(host_id,last_seen,agent_version,node_id,config_json) VALUES(?,?,?,?,?)",
            (host_id, now, "ui-preview", "synthetic-admission-node", "{}"),
        )
        conn.execute(
            """INSERT INTO reports(
                host_id,container_name,runtime,project,cpu_percent,mem_bytes,mem_percent,
                net_rx_bps,net_tx_bps,conn_count,disk_file,disk_size_bytes,disk_used_percent,
                podman_network_ok_v4,podman_network_ok_v6,ts,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (host_id, container_name, "incus", "default", 1.0, 0, 12.0, 0, 0, 499,
             "", 0, 0, 1, 1, now, json.dumps(payload)),
        )
        conn.commit()
        conn.close()
        uvicorn.run(server.app, host="127.0.0.1", port=8795, log_level="warning", lifespan="off")


if __name__ == "__main__":
    main()
