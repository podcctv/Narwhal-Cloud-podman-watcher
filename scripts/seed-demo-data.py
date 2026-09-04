import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))
import app as server

conn = server.db()
now = int(time.time())

# Insert hosts
conn.execute("REPLACE INTO hosts (host_id, last_seen, agent_version) VALUES (?, ?, ?)", ("node-us-east-1", now, "dev"))
conn.execute("REPLACE INTO hosts (host_id, last_seen, agent_version) VALUES (?, ?, ?)", ("node-eu-central-1", now, "dev"))
conn.execute("REPLACE INTO hosts (host_id, last_seen, agent_version) VALUES (?, ?, ?)", ("node-ap-east-1", now, "1.2.0"))

# Containers to seed
containers = [
    {
        "host_id": "node-us-east-1",
        "container_name": "api-gateway",
        "runtime": "podman",
        "project": "core",
        "cpu_percent": 18.5,
        "mem_percent": 42.1,
        "mem_bytes": 1024 * 1024 * 850,
        "net_rx_bps": 12500000,
        "net_tx_bps": 18400000,
        "conn_count": 482,
        "sec": {
            "process_count": 24,
            "top_cpu_process_command": "envoy -c /etc/envoy/envoy.yaml",
            "top_cpu_process_cpu_percent": 14.2,
            "top_cpu_process_pid": 1102,
            "inbound_unique_ips": 6,
            "inbound_unique_ip_threshold": 10,
            "listening_ports": ["80/tcp", "443/tcp"],
            "socks_proxy": {"detected": False},
            "panel_pairing": {"detected": False},
        }
    },
    {
        "host_id": "node-us-east-1",
        "container_name": "payment-worker",
        "runtime": "podman",
        "project": "billing",
        "cpu_percent": 5.2,
        "mem_percent": 28.4,
        "mem_bytes": 1024 * 1024 * 512,
        "net_rx_bps": 2400000,
        "net_tx_bps": 3100000,
        "conn_count": 45,
        "sec": {
            "process_count": 12,
            "top_cpu_process_command": "python worker.py",
            "top_cpu_process_cpu_percent": 4.1,
            "top_cpu_process_pid": 2045,
            "inbound_unique_ips": 2,
            "inbound_unique_ip_threshold": 10,
            "listening_ports": [],
            "socks_proxy": {"detected": False},
            "panel_pairing": {"detected": False},
        }
    },
    {
        "host_id": "node-eu-central-1",
        "container_name": "redis-cache-cluster",
        "runtime": "incus",
        "project": "infra",
        "cpu_percent": 24.8,
        "mem_percent": 71.3,
        "mem_bytes": 1024 * 1024 * 2800,
        "net_rx_bps": 45000000,
        "net_tx_bps": 42000000,
        "conn_count": 1250,
        "sec": {
            "process_count": 6,
            "top_cpu_process_command": "redis-server *:6379",
            "top_cpu_process_cpu_percent": 22.0,
            "top_cpu_process_pid": 401,
            "inbound_unique_ips": 18,
            "inbound_unique_ip_threshold": 10,
            "listening_ports": ["6379/tcp"],
            "socks_proxy": {"detected": False},
            "panel_pairing": {"detected": False},
        }
    },
    {
        "host_id": "node-ap-east-1",
        "container_name": "suspicious-proxy-node",
        "runtime": "incus",
        "project": "edge",
        "cpu_percent": 88.5,
        "mem_percent": 64.2,
        "mem_bytes": 1024 * 1024 * 1200,
        "net_rx_bps": 85000000,
        "net_tx_bps": 92000000,
        "conn_count": 3400,
        "sec": {
            "process_count": 35,
            "top_cpu_process_command": "xmrig --donate-level 1 -o pool.minexmr.com:4444",
            "top_cpu_process_cpu_percent": 82.5,
            "top_cpu_process_pid": 8821,
            "inbound_unique_ips": 45,
            "inbound_unique_ip_threshold": 10,
            "listening_ports": ["1080/tcp"],
            "socks_proxy": {"detected": True, "auth_mode": "no_auth", "public_exposure": True},
            "panel_pairing": {"detected": True, "approved": False},
            "suspicious_processes": [{"pid": 8821, "command": "xmrig", "pattern": "xmrig"}]
        }
    }
]

# Insert reports across last 2 hours for history curves
for minute_offset in range(30, -1, -2):
    t = now - (minute_offset * 60)
    for c in containers:
        payload = {
            "_agent_version": "dev" if c["host_id"] != "node-ap-east-1" else "1.2.0",
            "timestamp_iso_utc8": server.format_utc8(t),
            "mem_limit_bytes": 1024 * 1024 * 4096,
            "security": c["sec"]
        }
        conn.execute(
            """
            INSERT INTO reports (
                host_id, container_name, runtime, project,
                cpu_percent, mem_bytes, mem_percent,
                net_rx_bps, net_tx_bps, conn_count,
                disk_file, disk_size_bytes, disk_used_percent,
                podman_network_ok_v4, podman_network_ok_v6,
                ts, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                c["host_id"], c["container_name"], c["runtime"], c["project"],
                c["cpu_percent"] + (minute_offset % 5 - 2) * 1.5,
                c["mem_bytes"], c["mem_percent"],
                c["net_rx_bps"] * (1 + (minute_offset % 4 - 2) * 0.1),
                c["net_tx_bps"] * (1 + (minute_offset % 3 - 1) * 0.1),
                c["conn_count"],
                "/dev/sda1", 1024 * 1024 * 1024 * 50, 45.2,
                1, 1, t, json.dumps(payload)
            )
        )

# Insert sample security alert
conn.execute(
    """
    REPLACE INTO security_alerts (
        id, fingerprint, host_id, runtime, project, container_name,
        alert_type, severity, title, message, value, threshold,
        details_json, occurrence_count, first_seen, last_seen, status
    ) VALUES (
        1, 'fp-xmrig-1', 'node-ap-east-1', 'incus', 'edge', 'suspicious-proxy-node',
        'malicious_process', 'critical', '检测到挖矿程序 (XMRig)',
        '容器内检测到高负载未知进程 xmrig，CPU 占用率持续超过 80%，存在资源滥用与未授权挖矿风险。',
        88.5, 80.0,
        '{"process_patterns":["xmrig"],"malicious_processes":[{"process":"xmrig","pid":8821}]}',
        12, ?, ?, 'active'
    )
    """,
    (now - 3600, now)
)

conn.execute(
    """
    REPLACE INTO security_alerts (
        id, fingerprint, host_id, runtime, project, container_name,
        alert_type, severity, title, message, value, threshold,
        details_json, occurrence_count, first_seen, last_seen, status
    ) VALUES (
        2, 'fp-socks-1', 'node-ap-east-1', 'incus', 'edge', 'suspicious-proxy-node',
        'socks_weak_auth', 'warning', 'SOCKS 代理无认证且暴露公网',
        '容器监听 1080 端口且处于 no_auth 无认证状态，已被外网并发访问。',
        45, 10,
        '{"socks_auth_mode":"no_auth","socks_processes":["socks5-server"]}',
        5, ?, ?, 'active'
    )
    """,
    (now - 1800, now)
)

# Insert host security telemetry
conn.execute(
    """
    INSERT INTO host_security (host_id, ts, payload_json) VALUES (?, ?, ?)
    """,
    ('node-us-east-1', now, json.dumps({"rx_mbps": 45.2, "rx_pps": 3210.0, "syn_recv": 4, "http_rps": 182.5, "top_ip_rps": 18.0, "access_log": "正常"}))
)
conn.execute(
    """
    INSERT INTO host_security (host_id, ts, payload_json) VALUES (?, ?, ?)
    """,
    ('node-eu-central-1', now, json.dumps({"rx_mbps": 88.6, "rx_pps": 6840.0, "syn_recv": 8, "http_rps": 345.0, "top_ip_rps": 42.0, "access_log": "正常"}))
)
conn.execute(
    """
    INSERT INTO host_security (host_id, ts, payload_json) VALUES (?, ?, ?)
    """,
    ('node-ap-east-1', now, json.dumps({"rx_mbps": 195.4, "rx_pps": 15420.0, "syn_recv": 92, "http_rps": 780.0, "top_ip_rps": 152.0, "access_log": "异常泛洪"}))
)

conn.commit()
print("Successfully seeded demo data!")
