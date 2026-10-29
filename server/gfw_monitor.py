"""Correlate domestic and overseas TCP probes for conservative GFW reachability history."""
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request

MAX_TARGETS = 8
DAILY_CONTAINER_SAMPLE_LIMIT = 2
MIN_MAINLAND = 2
MIN_OVERSEAS = 1
CYCLE_SECONDS = 300
STALE_SECONDS = 900
JOB_SECONDS = 600
MAX_ACTIVE_CYCLES = 30
SUCCESSFUL_PROBE_ERRORS = {"", "timeout", "refused", "network_error"}
PROBE_FAILURE_CODES = {
    "probe_source_identity_mismatch", "invalid_probe_identity", "invalid_probe_lease",
    "invalid_probe_deadline", "invalid_target_count", "invalid_target_fields",
    "invalid_target_endpoint", "invalid_target_identity", "invalid_targets_hash",
    "incomplete_probe_results", "probe_runtime_unavailable", "probe_worker_busy", "probe_worker_error",
}
PROBE_FAILURE_LABELS = {
    "probe_source_identity_mismatch": "探针身份不匹配",
    "invalid_probe_identity": "探针任务身份校验失败",
    "invalid_probe_lease": "探针任务授权校验失败",
    "invalid_probe_deadline": "探针任务已过期",
    "invalid_target_count": "目标端口数量不符合限制",
    "invalid_target_fields": "目标字段校验失败",
    "invalid_target_endpoint": "目标地址校验失败",
    "invalid_target_identity": "目标身份校验失败",
    "invalid_targets_hash": "目标清单校验失败",
    "incomplete_probe_results": "探测结果不完整",
    "probe_runtime_unavailable": "探针未运行在宿主机网络环境",
    "probe_worker_busy": "探针已有任务执行中",
    "probe_worker_error": "探针执行异常",
    "probe deadline elapsed": "任务超时",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _utc_sample_date(now):
    return datetime.fromtimestamp(int(now), timezone.utc).date()


def _same_day_sample(conn, host_id, now):
    day_start = int(datetime.fromtimestamp(int(now), timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    rows = conn.execute(
        "SELECT result_json FROM gfw_cycles WHERE host_id=? AND created_at>=? ORDER BY created_at,id LIMIT 400",
        (host_id, day_start),
    ).fetchall()
    for row in rows:
        try:
            result = json.loads(row["result_json"] or "{}")
            sample = result.get("sample", {}) if isinstance(result, dict) else {}
            if isinstance(sample, dict) and sample.get("policy") == "daily_container_rotation":
                return sample
        except (TypeError, ValueError):
            continue
    return {}


def _blocked_endpoint_keys(evidence_json):
    try:
        evidence = json.loads(evidence_json or "{}")
        return {
            (str(item[0]), int(item[1])) for item in evidence.get("blocked_endpoint_keys", [])
            if isinstance(item, (list, tuple)) and len(item) == 2 and 1 <= int(item[1]) <= 65535
        }
    except (TypeError, ValueError, AttributeError):
        return set()


def _public_v4(value):
    try:
        addr = ipaddress.ip_address(str(value).split("/", 1)[0])
        return str(addr) if addr.version == 4 and addr.is_global and not addr.is_multicast else ""
    except ValueError:
        return ""


def _listen_endpoint(item):
    """Return (bind address, TCP port) only for an explicit TCP mapping."""
    if not isinstance(item, dict):
        return "", 0
    source = str(item.get("source") or "")
    listen = str(item.get("listen") or "").strip()
    if source == "podman-publish":
        target = str(item.get("target") or "").lower()
        if not target.endswith("/tcp"):
            return "", 0
    elif source in {"incus-proxy", "incus-forward", "host-dnat"}:
        target = str(item.get("target") or "").lower()
        if listen.lower().startswith("udp:") or target.startswith("udp:"):
            return "", 0
        # Incus network-forward records carry the protocol on both endpoints.
        # Do not silently accept an untyped or non-TCP forward as a TCP probe.
        if source in {"incus-forward", "host-dnat"} and (not listen.lower().startswith("tcp:") or not target.startswith("tcp:")):
            return "", 0
        if listen.lower().startswith("tcp:"):
            listen = listen[4:]
    else:
        return "", 0
    match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})", listen)
    if not match:
        return "", 0
    address = (match.group(1) or match.group(2) or "").strip()
    try:
        port = int(match.group(3))
    except ValueError:
        return "", 0
    if not 1 <= port <= 65535:
        return "", 0
    return address, port


def _targets_for_host(conn, host_id, node_id, now, pinned_endpoint_keys=None, daily_selection=None):
    pinned_endpoint_keys = set(pinned_endpoint_keys or ())
    daily_selection = daily_selection if isinstance(daily_selection, dict) else {}
    host_sample = conn.execute(
        "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1", (host_id,)
    ).fetchone()
    inventory_reason = ""
    if not host_sample or now - int(host_sample["ts"] or 0) > STALE_SECONDS:
        inventory_reason = "宿主机网卡采样已过期"
    try:
        payload = json.loads(host_sample["payload_json"] or "{}") if host_sample else {}
        inventory = payload.get("host_firewall", {}).get("interface_inventory", {})
    except (TypeError, ValueError, AttributeError):
        inventory = {}
    if not isinstance(inventory, dict) or inventory.get("status") != "ready":
        inventory_reason = inventory_reason or "尚未收到可用的网卡地址清单"
        inventory = {}
    addresses, interface_by_ip = [], {}
    for interface in inventory.get("interfaces", [])[:64] if isinstance(inventory.get("interfaces"), list) else []:
        if not isinstance(interface, dict):
            continue
        name = str(interface.get("name") or "")[:32]
        for raw in interface.get("addresses", [])[:16] if isinstance(interface.get("addresses"), list) else []:
            address = _public_v4(raw)
            if address:
                interface_by_ip[address] = name
                if address not in addresses:
                    addresses.append(address)
    latest = conn.execute(
        "SELECT runtime,project,container_name,payload_json,ts FROM reports WHERE host_id=? AND runtime IN ('incus','podman') AND ts>=? ORDER BY ts DESC,id DESC LIMIT 1200",
        (host_id, now - STALE_SECONDS),
    ).fetchall()
    newest, discovered = set(), {}
    socket_owners = {}
    has_public_container_ip = False

    def add_endpoint(address, port, interface, container):
        target = {"ip": address, "port": port, "interface": interface}
        target_id = _digest({"host_id": host_id, **target})[:24]
        endpoint = discovered.setdefault(target_id, {"id": target_id, **target, "owners": {}})
        endpoint["owners"][container["key"]] = container
        socket_owners.setdefault((address, port), set()).add(container["key"])

    for row in latest:
        key = (row["runtime"], row["project"], row["container_name"])
        if key in newest:
            continue
        newest.add(key)
        try:
            report = json.loads(row["payload_json"] or "{}")
            security = report.get("security", {})
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(report, dict):
            continue
        container_id = str(report.get("id") or report.get("container_id") or "")[:255]
        container = {
            "key": f"{row['runtime']}|{row['project']}|{container_id or row['container_name']}",
            "runtime": str(row["runtime"] or "")[:32],
            "project": str(row["project"] or "")[:255],
            "name": str(row["container_name"] or "")[:255],
            "container_id": container_id,
        }
        # A container with a directly assigned public address and a live TCP
        # listener is independently probeable, including routed/macvlan setups
        # that do not use a host-side proxy or published port.
        container_addresses = report.get("network_addresses", [])
        listening_ports = security.get("listening_ports", []) if isinstance(security, dict) else []
        public_container_ips = set()
        for value in container_addresses[:32] if isinstance(container_addresses, list) else []:
            ip = _public_v4(value) if isinstance(value, str) else ""
            if ip:
                public_container_ips.add(ip)
        public_container_ips = sorted(public_container_ips)
        has_public_container_ip = has_public_container_ip or bool(public_container_ips)
        valid_ports = set()
        for value in listening_ports[:128] if isinstance(listening_ports, list) else []:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                valid_ports.add(port)
        for ip in public_container_ips:
            for port in valid_ports:
                add_endpoint(ip, port, "container", container)
        exposures = security.get("network_exposure", []) if isinstance(security, dict) else []
        for exposure in exposures[:128] if isinstance(exposures, list) else []:
            bind, port = _listen_endpoint(exposure)
            if not port:
                continue
            explicit = _public_v4(bind)
            target_ips = [explicit] if explicit and explicit in addresses else addresses if bind in ("", "*", "0.0.0.0", "::") else []
            for ip in target_ips:
                add_endpoint(ip, port, interface_by_ip.get(ip, ""), container)

    # Public endpoints must map to one unambiguous Incus/Podman container before
    # they can participate in a per-container sample.
    containers = {}
    eligible_endpoint_count = 0
    seen_sockets = set()
    for endpoint in discovered.values():
        socket = (endpoint["ip"], endpoint["port"])
        if socket in seen_sockets or len(socket_owners.get(socket, set())) != 1:
            continue
        owners = endpoint.pop("owners", {})
        if len(owners) != 1:
            continue
        seen_sockets.add(socket)
        container = next(iter(owners.values()))
        container_key = container["key"]
        containers.setdefault(container_key, {"container": container, "targets": []})["targets"].append(endpoint)
        eligible_endpoint_count += 1

    sample_date = _utc_sample_date(now).isoformat()
    sample = {
        "policy": "daily_container_rotation",
        "date_utc": sample_date,
        "eligible_containers": len(containers),
        "sampled_containers": 0,
        "eligible_endpoints": eligible_endpoint_count,
        "sampled_endpoints": 0,
        "containers": [],
    }
    targets = []
    endpoint_containers = {}
    if containers:
        day_index = _utc_sample_date(now).toordinal()
        ordered_keys = sorted(
            containers,
            key=lambda key: (hashlib.sha256(f"{host_id}\0{key}".encode("utf-8")).hexdigest(), key),
        )
        offset = day_index % len(ordered_keys)
        rotated_keys = ordered_keys[offset:] + ordered_keys[:offset]
        pinned_by_container = {}
        for container_key, group in containers.items():
            matches = [target for target in group["targets"] if (target["ip"], target["port"]) in pinned_endpoint_keys]
            if matches:
                pinned_by_container[container_key] = sorted(matches, key=lambda target: target["id"])
        previous_endpoints = {}
        previous_keys = []
        for item in daily_selection.get("containers", []) if isinstance(daily_selection.get("containers"), list) else []:
            if not isinstance(item, dict):
                continue
            container_key = str(item.get("key") or "")
            if not container_key or container_key not in containers:
                continue
            previous_keys.append(container_key)
            points = set()
            for endpoint in item.get("endpoints", []) if isinstance(item.get("endpoints"), list) else []:
                if not isinstance(endpoint, dict):
                    continue
                try:
                    port = int(endpoint.get("port") or 0)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and isinstance(endpoint.get("ip"), str):
                    points.add((endpoint["ip"], port))
            previous_endpoints[container_key] = points
        selected_limit = min(DAILY_CONTAINER_SAMPLE_LIMIT, len(rotated_keys), MAX_TARGETS)
        priority_keys = ([key for key in rotated_keys if key in pinned_by_container]
                         + [key for key in previous_keys if key not in pinned_by_container]
                         + rotated_keys)
        selected_keys = []
        for key in priority_keys:
            if key not in selected_keys:
                selected_keys.append(key)
            if len(selected_keys) >= selected_limit:
                break
        sample["sampled_containers"] = len(selected_keys)
        for container_key in selected_keys:
            group = containers[container_key]
            ordered_endpoints = sorted(
                group["targets"],
                key=lambda target: (
                    hashlib.sha256(f"{container_key}\0{target['id']}".encode("utf-8")).hexdigest(),
                    target["id"],
                ),
            )
            selected_endpoints = pinned_by_container.get(container_key)
            if not selected_endpoints:
                preferred = previous_endpoints.get(container_key, set())
                selected_endpoints = [target for target in ordered_endpoints if (target["ip"], target["port"]) in preferred][:1]
            if not selected_endpoints:
                selected_endpoints = [ordered_endpoints[day_index % len(ordered_endpoints)]]
            # A container with many previously blocked listeners must not make
            # one daily sample exceed the existing per-cycle probe target cap.
            remaining_target_slots = MAX_TARGETS - len(targets)
            if remaining_target_slots <= 0:
                break
            selected_endpoints = selected_endpoints[:remaining_target_slots]
            container = group["container"]
            sample_container = {"key": container_key, "runtime": container["runtime"], "project": container["project"], "name": container["name"], "endpoints": []}
            for target in selected_endpoints:
                # Probe payloads intentionally remain limited to id/ip/port/interface;
                # the separately stored metadata is for admin evidence and display.
                targets.append({key: target[key] for key in ("id", "ip", "port", "interface")})
                endpoint_containers[target["id"]] = {
                    "runtime": container["runtime"], "project": container["project"],
                    "name": container["name"],
                }
                sample_container["endpoints"].append({"ip": target["ip"], "port": target["port"]})
            sample["containers"].append({
                **sample_container,
            })
        sample["sampled_containers"] = len(sample["containers"])
        sample["sampled_endpoints"] = len(targets)
        sample["follow_up_blocked_endpoint"] = any(key in pinned_by_container for key in selected_keys)
    sample_metadata = {"sample": sample, "endpoint_containers": endpoint_containers}
    if targets:
        return targets, "", sample_metadata
    if not addresses and not has_public_container_ip:
        return [], inventory_reason or "未发现公网 IPv4 地址；NAT 公网地址无法安全推断", sample_metadata
    return [], "未发现可确认的公网容器 TCP 端口：检查 Incus 代理/网络转发、Podman 端口发布或容器公网地址与监听端口", sample_metadata


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS gfw_probe_roles(
      node_id TEXT PRIMARY KEY,host_id TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('mainland','overseas')),
      updated_at INTEGER NOT NULL,region TEXT NOT NULL DEFAULT '',carrier TEXT NOT NULL DEFAULT '');
    CREATE TABLE IF NOT EXISTS gfw_cycles(
      id TEXT PRIMARY KEY,host_id TEXT NOT NULL,node_id TEXT NOT NULL,targets_json TEXT NOT NULL,status TEXT NOT NULL,
      created_at INTEGER NOT NULL,deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,result_json TEXT NOT NULL DEFAULT '{}');
    CREATE UNIQUE INDEX IF NOT EXISTS gfw_one_active_cycle ON gfw_cycles(host_id) WHERE status IN ('queued','running');
    CREATE INDEX IF NOT EXISTS gfw_cycles_host_time ON gfw_cycles(host_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS gfw_probe_jobs(
      id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,source_host_id TEXT NOT NULL,source_node_id TEXT NOT NULL,role TEXT NOT NULL,
      targets_json TEXT NOT NULL,targets_hash TEXT NOT NULL,lease TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,
      deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',
      source_region TEXT NOT NULL DEFAULT '',source_carrier TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS gfw_jobs_source_queue ON gfw_probe_jobs(source_node_id,status,created_at);
    CREATE TABLE IF NOT EXISTS gfw_probe_results(
      job_id TEXT NOT NULL,target_id TEXT NOT NULL,success INTEGER NOT NULL,latency_ms REAL,error TEXT NOT NULL,attempts INTEGER NOT NULL,
      PRIMARY KEY(job_id,target_id));
    CREATE TABLE IF NOT EXISTS gfw_states(
      host_id TEXT PRIMARY KEY,node_id TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'unassessed',blocked_since INTEGER NOT NULL DEFAULT 0,
      recovered_at INTEGER NOT NULL DEFAULT 0,normal_since INTEGER NOT NULL DEFAULT 0,last_cycle_at INTEGER NOT NULL DEFAULT 0,
      last_sample_at INTEGER NOT NULL DEFAULT 0,last_classification TEXT NOT NULL DEFAULT 'unknown',pending_block_count INTEGER NOT NULL DEFAULT 0,
      pending_block_since INTEGER NOT NULL DEFAULT 0,pending_recovery_count INTEGER NOT NULL DEFAULT 0,last_normal_duration INTEGER NOT NULL DEFAULT 0,
      blocked_count INTEGER NOT NULL DEFAULT 0,evidence_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS gfw_events(
      id INTEGER PRIMARY KEY AUTOINCREMENT,host_id TEXT NOT NULL,node_id TEXT NOT NULL,event_type TEXT NOT NULL,at INTEGER NOT NULL,
      duration_seconds INTEGER NOT NULL DEFAULT 0,normal_duration_seconds INTEGER NOT NULL DEFAULT 0,evidence_json TEXT NOT NULL DEFAULT '{}');
    CREATE INDEX IF NOT EXISTS gfw_events_host_time ON gfw_events(host_id,at DESC);
    """)
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(gfw_probe_roles)")}
    if "region" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN region TEXT NOT NULL DEFAULT ''")
    if "carrier" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN carrier TEXT NOT NULL DEFAULT ''")
    job_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(gfw_probe_jobs)")}
    if "source_region" not in job_columns:
        conn.execute("ALTER TABLE gfw_probe_jobs ADD COLUMN source_region TEXT NOT NULL DEFAULT ''")
    if "source_carrier" not in job_columns:
        conn.execute("ALTER TABLE gfw_probe_jobs ADD COLUMN source_carrier TEXT NOT NULL DEFAULT ''")


def _role_counts(conn, now):
    result = {"mainland": 0, "overseas": 0}
    for row in conn.execute("SELECT r.role,h.last_seen,o.payload FROM gfw_probe_roles r JOIN hosts h ON h.node_id=r.node_id LEFT JOIN ops_hosts o ON o.node=h.node_id"):
        try:
            interval = int(json.loads(row["payload"] or "{}").get("report_interval", 300))
        except (ValueError, TypeError):
            interval = 300
        if now - int(row["last_seen"] or 0) <= max(600, min(1800, interval * 3)):
            result[row["role"]] += 1
    return result


def _active_roles(conn, now):
    rows = conn.execute("SELECT r.host_id,r.node_id,r.role,r.region,r.carrier,h.last_seen,o.payload FROM gfw_probe_roles r JOIN hosts h ON h.node_id=r.node_id LEFT JOIN ops_hosts o ON o.node=h.node_id ORDER BY r.role,r.host_id").fetchall()
    result = {"mainland": [], "overseas": []}
    for row in rows:
        try:
            interval = int(json.loads(row["payload"] or "{}").get("report_interval", 300))
        except (ValueError, TypeError):
            interval = 300
        if now - int(row["last_seen"] or 0) <= max(600, min(1800, interval * 3)):
            result[row["role"]].append({"host_id": row["host_id"], "node_id": row["node_id"],
                                         "region": str(row["region"] or "")[:80],
                                         "carrier": str(row["carrier"] or "")[:100]})
    result["mainland"] = result["mainland"][:5]
    result["overseas"] = result["overseas"][:3]
    return result


def _source_coverage_for_host(roles, node_id):
    """Return probe sources available to test a host, excluding the host itself."""
    available = {
        role: [source for source in roles.get(role, []) if source["node_id"] != node_id]
        for role in ("mainland", "overseas")
    }
    required = {"mainland": MIN_MAINLAND, "overseas": MIN_OVERSEAS}
    missing = [role for role in required if len(available[role]) < required[role]]
    if not missing:
        return available, ""
    own_roles = [role for role in required if any(source["node_id"] == node_id for source in roles.get(role, []))]
    counts = f"国内 {len(available['mainland'])}/{MIN_MAINLAND}、海外 {len(available['overseas'])}/{MIN_OVERSEAS}"
    if own_roles:
        own_label = "国内" if own_roles[0] == "mainland" else "海外"
        reason = f"该主机本身是{own_label}探针，探针不会自测；排除本机后仅有 {counts} 个可用探测点"
    else:
        reason = f"独立探针覆盖不足：当前 {counts} 个可用探测点"
    return available, reason


def _schedule(conn, now):
    roles = _active_roles(conn, now)
    if len(roles["mainland"]) < MIN_MAINLAND or len(roles["overseas"]) < MIN_OVERSEAS:
        return
    hosts = conn.execute("SELECT host_id,node_id,last_seen FROM hosts WHERE node_id<>'' AND last_seen>=? ORDER BY COALESCE((SELECT last_cycle_at FROM gfw_states s WHERE s.host_id=hosts.host_id),0),host_id LIMIT 300", (now - STALE_SECONDS,)).fetchall()
    for host in hosts:
        active_cycles = int(conn.execute("SELECT COUNT(*) FROM gfw_cycles WHERE status IN ('queued','running')").fetchone()[0])
        if active_cycles >= MAX_ACTIVE_CYCLES:
            break
        state = conn.execute("SELECT last_cycle_at,state,evidence_json FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        last_cycle = int(state["last_cycle_at"] or 0) if state else 0
        if now - last_cycle < CYCLE_SECONDS:
            continue
        if conn.execute("SELECT 1 FROM gfw_cycles WHERE host_id=? AND status IN ('queued','running') LIMIT 1", (host["host_id"],)).fetchone():
            continue
        host_roles, coverage_reason = _source_coverage_for_host(roles, host["node_id"])
        host_roles = {role: sources[:need] for role, sources, need in (
            ("mainland", host_roles["mainland"], MIN_MAINLAND),
            ("overseas", host_roles["overseas"], MIN_OVERSEAS),
        )}
        if coverage_reason:
            reason = coverage_reason + "；需增加不同主机上的在线探针"
            conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,last_classification,evidence_json) VALUES(?,?,?,'unknown',?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,last_classification='unknown',evidence_json=excluded.evidence_json",
                         (host["host_id"], host["node_id"], now, _json({"reason": reason, "targets": []})))
            continue  # Never use a node to probe its own public endpoint.
        pinned_endpoint_keys = set()
        if state and state["state"] == "blocked":
            pinned_endpoint_keys = _blocked_endpoint_keys(state["evidence_json"])
        daily_selection = _same_day_sample(conn, host["host_id"], now)
        targets, _reason, sample_metadata = _targets_for_host(
            conn, host["host_id"], host["node_id"], now,
            pinned_endpoint_keys=pinned_endpoint_keys, daily_selection=daily_selection,
        )
        if not targets:
            preserved_blocked_endpoints = sorted([list(key) for key in pinned_endpoint_keys])
            conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,last_classification,evidence_json) VALUES(?,?,?,'unknown',?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,last_classification='unknown',evidence_json=excluded.evidence_json",
                         (host["host_id"], host["node_id"], now, _json({"reason": _reason, "targets": [], "sample": sample_metadata["sample"], "blocked_endpoint_keys": preserved_blocked_endpoints})))
            continue
        cycle_id = str(uuid.uuid4())
        targets_json = _json(targets)
        conn.execute("INSERT INTO gfw_cycles(id,host_id,node_id,targets_json,status,created_at,deadline_at,result_json) VALUES(?,?,?,?,'queued',?,?,?)",
                     (cycle_id, host["host_id"], host["node_id"], targets_json, now, now + JOB_SECONDS, _json(sample_metadata)))
        conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at) VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at",
                     (host["host_id"], host["node_id"], now))
        for role in ("mainland", "overseas"):
            for source in host_roles[role]:
                job_id = str(uuid.uuid4())
                conn.execute("INSERT INTO gfw_probe_jobs(id,cycle_id,source_host_id,source_node_id,role,targets_json,targets_hash,lease,status,created_at,deadline_at,source_region,source_carrier) VALUES(?,?,?,?,?,?,?,?, 'queued',?,?,?,?)",
                             (job_id, cycle_id, source["host_id"], source["node_id"], role, targets_json, _digest(targets), secrets.token_urlsafe(32), now, now + JOB_SECONDS, source.get("region", ""), source.get("carrier", "")))


def _apply_cycle(conn, cycle, now):
    jobs = conn.execute("SELECT * FROM gfw_probe_jobs WHERE cycle_id=?", (cycle["id"],)).fetchall()
    if not jobs or any(job["status"] not in ("complete", "expired", "failed", "cancelled") for job in jobs):
        return False
    targets = json.loads(cycle["targets_json"])
    try:
        cycle_metadata = json.loads(cycle["result_json"] or "{}")
    except (TypeError, ValueError):
        cycle_metadata = {}
    sample_metadata = cycle_metadata.get("sample", {}) if isinstance(cycle_metadata, dict) else {}
    endpoint_containers = cycle_metadata.get("endpoint_containers", {}) if isinstance(cycle_metadata, dict) else {}
    if not isinstance(sample_metadata, dict):
        sample_metadata = {}
    if not isinstance(endpoint_containers, dict):
        endpoint_containers = {}
    evidence = []
    successful_cycle = False
    blocked_cycle = False
    for target in targets:
        by_role = {"mainland": {"success": 0, "failed": 0, "total": 0}, "overseas": {"success": 0, "failed": 0, "total": 0}}
        probe_sources = []
        for job in jobs:
            result = conn.execute("SELECT success,error,latency_ms FROM gfw_probe_results WHERE job_id=? AND target_id=?", (job["id"], target["id"])).fetchone()
            probe_sources.append({
                "source_host_id": str(job["source_host_id"] or "")[:200],
                "role": job["role"],
                "source_region": str(job["source_region"] or "")[:80],
                "source_carrier": str(job["source_carrier"] or "")[:100],
                "job_status": job["status"],
                "success": bool(result["success"]) if result else None,
                "latency_ms": result["latency_ms"] if result else None,
                "error": str((result["error"] if result else job["error"]) or "")[:160],
            })
            if not result:
                continue
            stats = by_role[job["role"]]
            stats["total"] += 1
            stats["success" if result["success"] else "failed"] += 1
        main, over = by_role["mainland"], by_role["overseas"]
        is_blocked = main["total"] >= MIN_MAINLAND and main["failed"] >= MIN_MAINLAND and over["success"] >= MIN_OVERSEAS
        is_normal = main["success"] >= MIN_MAINLAND and over["success"] >= MIN_OVERSEAS
        blocked_cycle = blocked_cycle or is_blocked
        successful_cycle = successful_cycle or is_normal
        if is_blocked:
            status = "blocked"
        elif is_normal:
            status = "normal"
        else:
            status = "unknown"
        endpoint = {"ip": target["ip"], "port": target["port"], "interface": target.get("interface", ""),
                    "status": status, "mainland": main, "overseas": over, "probes": probe_sources}
        owner = endpoint_containers.get(target["id"])
        if isinstance(owner, dict):
            endpoint.update({"runtime": str(owner.get("runtime") or ""),
                             "project": str(owner.get("project") or ""),
                             "container_name": str(owner.get("name") or "")})
        evidence.append(endpoint)
    classification = "blocked" if blocked_cycle else "normal" if successful_cycle else "unknown"
    prior = conn.execute("SELECT * FROM gfw_states WHERE host_id=?", (cycle["host_id"],)).fetchone()
    state = dict(prior) if prior else {"host_id": cycle["host_id"], "node_id": cycle["node_id"], "state": "unassessed",
        "blocked_since": 0, "recovered_at": 0, "normal_since": 0, "pending_block_count": 0, "last_classification": "unknown",
        "pending_block_since": 0, "pending_recovery_count": 0, "last_normal_duration": 0, "blocked_count": 0, "last_sample_at": 0}
    try:
        prior_evidence = json.loads(prior["evidence_json"] or "{}") if prior else {}
    except (TypeError, ValueError):
        prior_evidence = {}
    previous_targets = prior_evidence.get("targets", []) if isinstance(prior_evidence, dict) else []
    previous_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in previous_targets if isinstance(item, dict)}
    previous_blocked_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in previous_targets if isinstance(item, dict) and item.get("status") == "blocked"}
    try:
        anchored_blocked_keys = {(str(item[0]), int(item[1])) for item in prior_evidence.get("blocked_endpoint_keys", []) if isinstance(item, (list, tuple)) and len(item) == 2}
    except (TypeError, ValueError):
        anchored_blocked_keys = set()
    if state["state"] == "blocked" and not anchored_blocked_keys:
        anchored_blocked_keys = previous_blocked_keys
    current_blocked_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in evidence if item.get("status") == "blocked"}
    current_normal_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in evidence if item.get("status") == "normal"}
    reason = ""
    if state["last_sample_at"] and classification == "blocked" and not (previous_keys & current_blocked_keys):
        classification = "unknown"  # A changed public endpoint is not a consecutive blocked observation.
        reason = "公网 IP 或端口发生变化；新端点需重新连续确认，当前不计为阻断"
    if state["state"] == "blocked" and classification == "normal" and not (anchored_blocked_keys & current_normal_keys):
        classification = "unknown"  # Recovery must succeed on the endpoint that was blocked.
        reason = "原阻断 IP/端口已变化；新端点可达不能证明原端点已恢复"
    if state["state"] == "blocked" and classification == "blocked" and not (anchored_blocked_keys & current_blocked_keys):
        classification = "unknown"
        reason = "当前异常发生在不同 IP/端口；不能与原阻断端点合并计时"
    elif classification == "unknown" and not reason:
        failures = {}
        for job in jobs:
            if job["status"] not in ("failed", "expired"):
                continue
            code = str(job["error"] or ("probe deadline elapsed" if job["status"] == "expired" else "probe_worker_error"))
            label = PROBE_FAILURE_LABELS.get(code, "任务未完成")
            role = "国内" if job["role"] == "mainland" else "海外"
            key = (role, label)
            failures[key] = failures.get(key, 0) + 1
        if failures:
            reason = "探测任务未完成：" + "；".join(
                f"{role}探针{label} {count} 个"
                for (role, label), count in sorted(failures.items())
            ) + "；本轮不用于确认阻断或恢复"
        else:
            reason = "国内或海外探测样本不足/结果不一致；本轮不用于确认阻断或恢复"
    event = None
    if classification == "blocked":
        if state["state"] != "blocked":
            if state["last_classification"] == "blocked":
                state["pending_block_count"] += 1
            else:
                state["pending_block_count"] = 1
                state["pending_block_since"] = cycle["created_at"]
            state["pending_recovery_count"] = 0
            if state["pending_block_count"] >= 3:
                normal_start = state["recovered_at"] or state["normal_since"]
                first_block_signal = state["pending_block_since"] or cycle["created_at"]
                normal_duration = max(0, first_block_signal - normal_start) if normal_start else 0
                state.update(state="blocked", blocked_since=state["pending_block_since"], recovered_at=0,
                             pending_block_count=0, pending_block_since=0, pending_recovery_count=0,
                             last_normal_duration=normal_duration, blocked_count=state["blocked_count"] + 1)
                event = ("blocked", state["blocked_since"], 0, normal_duration)
        else:
            state["pending_recovery_count"] = 0
        state["last_classification"] = "blocked"
    elif classification == "normal":
        state["pending_block_count"] = 0
        state["pending_block_since"] = 0
        if state["state"] == "blocked":
            if state["last_classification"] == "normal":
                state["pending_recovery_count"] += 1
            else:
                state["pending_recovery_count"] = 1
            if state["pending_recovery_count"] >= 2:
                duration = max(0, cycle["created_at"] - state["blocked_since"])
                state.update(state="recovered", recovered_at=cycle["created_at"], normal_since=cycle["created_at"],
                             blocked_since=0, pending_recovery_count=0)
                event = ("recovered", cycle["created_at"], duration, 0)
        elif state["state"] == "unassessed":
            state.update(state="normal", normal_since=cycle["created_at"], pending_recovery_count=0)
        state["last_classification"] = "normal"
    else:
        state["pending_block_count"] = 0
        state["pending_block_since"] = 0
        state["pending_recovery_count"] = 0
        state["last_classification"] = "unknown"
    if state["state"] == "blocked":
        if classification == "blocked" and not anchored_blocked_keys:
            anchored_blocked_keys = current_blocked_keys
    else:
        anchored_blocked_keys = set()
    evidence_payload = {"targets": evidence, "classification": classification,
                        "blocked_endpoint_keys": sorted([list(key) for key in anchored_blocked_keys]),
                        "sample": sample_metadata}
    if reason:
        evidence_payload["reason"] = reason
    evidence_payload["probe_failures"] = [
        {"role": job["role"], "status": job["status"],
         "code": str(job["error"] or ("probe deadline elapsed" if job["status"] == "expired" else "probe_worker_error"))}
        for job in jobs if job["status"] in ("failed", "expired")
    ][:5]
    state.update(node_id=cycle["node_id"], last_sample_at=cycle["created_at"], evidence_json=_json(evidence_payload))
    conn.execute("""INSERT INTO gfw_states(host_id,node_id,state,blocked_since,recovered_at,normal_since,last_cycle_at,last_sample_at,
      last_classification,pending_block_count,pending_block_since,pending_recovery_count,last_normal_duration,blocked_count,evidence_json)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,state=excluded.state,
      blocked_since=excluded.blocked_since,recovered_at=excluded.recovered_at,normal_since=excluded.normal_since,last_cycle_at=excluded.last_cycle_at,
      last_sample_at=excluded.last_sample_at,last_classification=excluded.last_classification,pending_block_count=excluded.pending_block_count,
      pending_block_since=excluded.pending_block_since,pending_recovery_count=excluded.pending_recovery_count,last_normal_duration=excluded.last_normal_duration,
      blocked_count=excluded.blocked_count,evidence_json=excluded.evidence_json""",
      (cycle["host_id"], state["node_id"], state["state"], state["blocked_since"], state["recovered_at"], state["normal_since"],
       cycle["created_at"], state["last_sample_at"], state["last_classification"], state["pending_block_count"], state["pending_block_since"],
       state["pending_recovery_count"], state["last_normal_duration"], state["blocked_count"], state["evidence_json"]))
    if event:
        conn.execute("INSERT INTO gfw_events(host_id,node_id,event_type,at,duration_seconds,normal_duration_seconds,evidence_json) VALUES(?,?,?,?,?,?,?)",
                     (cycle["host_id"], cycle["node_id"], event[0], event[1], event[2], event[3], _json({"targets": evidence})))
    conn.execute("UPDATE gfw_cycles SET status=?,finished_at=?,result_json=? WHERE id=?",
                 ("complete" if classification != "unknown" else "partial", now,
                  _json({"classification": classification, "targets": evidence, "sample": sample_metadata}), cycle["id"]))
    # Longitudinal history is compact: keep the most recent 100 transitions per host.
    conn.execute("DELETE FROM gfw_events WHERE host_id=? AND id NOT IN (SELECT id FROM gfw_events WHERE host_id=? ORDER BY at DESC,id DESC LIMIT 100)",
                 (cycle["host_id"], cycle["host_id"]))
    return True


def lease_job(conn, host_id, node_id, now):
    conn.execute("DELETE FROM gfw_probe_results WHERE job_id IN (SELECT id FROM gfw_probe_jobs WHERE created_at<? AND status<>'running')", (now - 90 * 86400,))
    conn.execute("DELETE FROM gfw_probe_jobs WHERE created_at<? AND status<>'running'", (now - 90 * 86400,))
    conn.execute("DELETE FROM gfw_cycles WHERE created_at<? AND status NOT IN ('queued','running')", (now - 90 * 86400,))
    _schedule(conn, now)
    conn.execute("UPDATE gfw_probe_jobs SET status='expired',finished_at=?,error='probe deadline elapsed' WHERE status IN ('queued','running') AND deadline_at<=?", (now, now))
    cycles = conn.execute("SELECT * FROM gfw_cycles WHERE status IN ('queued','running') AND deadline_at<=? LIMIT 100", (now,)).fetchall()
    for cycle in cycles:
        _apply_cycle(conn, cycle, now)
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE source_host_id=? AND source_node_id=? AND status='queued' AND deadline_at>? ORDER BY created_at LIMIT 1", (host_id, node_id, now)).fetchone()
    if not row:
        return {"job": None}
    conn.execute("UPDATE gfw_probe_jobs SET status='running' WHERE id=? AND status='queued'", (row["id"],))
    cycle = conn.execute("SELECT host_id,node_id FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    conn.execute("UPDATE gfw_cycles SET status='running' WHERE id=? AND status='queued'", (row["cycle_id"],))
    targets = json.loads(row["targets_json"])
    return {"job": {"id": row["id"], "cycle_id": row["cycle_id"], "source_host_id": host_id, "source_node_id": node_id,
                     "target_host_id": cycle["host_id"], "target_node_id": cycle["node_id"], "role": row["role"],
                     "lease": row["lease"], "targets": targets, "targets_hash": row["targets_hash"], "deadline_at": row["deadline_at"]}}


def report(conn, payload, now):
    keys = {"job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash", "results"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise HTTPException(400, "invalid GFW probe report")
    if any(not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 256 for key in ("job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash")):
        raise HTTPException(400, "invalid GFW probe identity")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE id=?", (payload["job_id"],)).fetchone()
    if not row or row["cycle_id"] != payload["cycle_id"] or row["source_host_id"] != payload["source_host_id"] or row["source_node_id"] != payload["source_node_id"] or not secrets.compare_digest(row["lease"], str(payload["lease"])):
        raise HTTPException(403, "invalid GFW probe lease")
    targets = json.loads(row["targets_json"])
    if payload["targets_hash"] != row["targets_hash"] or row["status"] != "running" or row["deadline_at"] <= now:
        raise HTTPException(409, "GFW probe job is no longer active")
    role = conn.execute("SELECT role FROM gfw_probe_roles WHERE host_id=? AND node_id=?", (row["source_host_id"], row["source_node_id"])).fetchone()
    if not role or role["role"] != row["role"]:
        raise HTTPException(409, "probe node role changed")
    results = payload["results"]
    if not isinstance(results, list) or len(results) != len(targets):
        raise HTTPException(400, "incomplete GFW probe results")
    allowed = {target["id"] for target in targets}
    seen = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {"target_id", "success", "latency_ms", "error", "attempts"}:
            raise HTTPException(400, "invalid GFW result fields")
        target_id = result["target_id"]
        if target_id not in allowed or target_id in seen or type(result["success"]) is not bool or type(result["attempts"]) is not int or not 1 <= result["attempts"] <= 2:
            raise HTTPException(400, "invalid GFW result")
        if result["error"] not in SUCCESSFUL_PROBE_ERRORS:
            raise HTTPException(400, "invalid GFW result error")
        latency = result["latency_ms"]
        if latency is not None and (type(latency) not in (int, float) or not 0 <= latency <= 10000):
            raise HTTPException(400, "invalid GFW latency")
        if result["success"] and latency is None:
            raise HTTPException(400, "successful probe requires latency")
        seen.add(target_id)
    for result in results:
        conn.execute("INSERT INTO gfw_probe_results(job_id,target_id,success,latency_ms,error,attempts) VALUES(?,?,?,?,?,?)",
                     (row["id"], result["target_id"], int(result["success"]), result["latency_ms"], result["error"], result["attempts"]))
    conn.execute("UPDATE gfw_probe_jobs SET status='complete',finished_at=? WHERE id=?", (now, row["id"]))
    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    _apply_cycle(conn, cycle, now)
    conn.commit()
    return {"ok": True}


def report_failure(conn, payload, now):
    keys = {"job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash", "failure_code"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise HTTPException(400, "invalid GFW probe failure report")
    if any(not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 256 for key in keys):
        raise HTTPException(400, "invalid GFW probe failure identity")
    if payload["failure_code"] not in PROBE_FAILURE_CODES:
        raise HTTPException(400, "invalid GFW probe failure code")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE id=?", (payload["job_id"],)).fetchone()
    if (not row or row["cycle_id"] != payload["cycle_id"]
            or row["source_host_id"] != payload["source_host_id"]
            or row["source_node_id"] != payload["source_node_id"]
            or not secrets.compare_digest(row["lease"], payload["lease"])):
        raise HTTPException(403, "invalid GFW probe lease")
    if (payload["targets_hash"] != row["targets_hash"] or row["status"] != "running"
            or row["deadline_at"] <= now):
        raise HTTPException(409, "GFW probe job is no longer active")
    role = conn.execute("SELECT role FROM gfw_probe_roles WHERE host_id=? AND node_id=?",
                        (row["source_host_id"], row["source_node_id"])).fetchone()
    if not role or role["role"] != row["role"]:
        raise HTTPException(409, "probe node role changed")
    conn.execute("UPDATE gfw_probe_jobs SET status='failed',finished_at=?,error=? WHERE id=?",
                 (now, payload["failure_code"], row["id"]))
    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    _apply_cycle(conn, cycle, now)
    conn.commit()
    return {"ok": True}


def status_map(conn, now):
    counts = _role_counts(conn, now)
    active_roles = _active_roles(conn, now)
    result = {}
    rows = conn.execute("SELECT * FROM hosts ORDER BY host_id LIMIT 500").fetchall()
    for host in rows:
        state_row = conn.execute("SELECT * FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        history = [dict(event) for event in conn.execute("SELECT event_type,at,duration_seconds,normal_duration_seconds FROM gfw_events WHERE host_id=? ORDER BY at DESC,id DESC LIMIT 6", (host["host_id"],))]
        host_sources, source_reason = _source_coverage_for_host(active_roles, host["node_id"])
        source_counts = {role: len(sources) for role, sources in host_sources.items()}
        if state_row:
            state = state_row["state"]
            last_sample_at = int(state_row["last_sample_at"] or 0)
            stale = last_sample_at > 0 and now - last_sample_at > STALE_SECONDS
            coverage_insufficient = bool(source_reason)
            try:
                evidence = json.loads(state_row["evidence_json"] or "{}")
            except ValueError:
                evidence = {}
            reason = str(evidence.get("reason") or "") if isinstance(evidence, dict) else ""
            sample = evidence.get("sample", {}) if isinstance(evidence, dict) else {}
            if not isinstance(sample, dict):
                sample = {}
            if stale:
                status = "stale"
            elif coverage_insufficient or not last_sample_at:
                status = "unassessed"
            elif state_row["pending_block_count"] or (last_sample_at and state_row["last_classification"] == "unknown"):
                status = "investigating"
            else:
                status = state
            if state == "blocked":
                since = int(state_row["blocked_since"] or 0)
            elif state == "recovered":
                since = int(state_row["recovered_at"] or 0)
            else:
                since = int(state_row["normal_since"] or 0)
            duration = max(0, now - since) if since else 0
            if coverage_insufficient:
                reason = source_reason + "；本机不会作为自己的探测来源"
                if stale:
                    reason = "探测数据已过期；" + reason
            elif status == "investigating" and not reason:
                reason = "本轮证据不足或端点变化；当前不确认恢复，也不把未知样本计入持续时长"
            result[host["host_id"]] = {"status": status, "last_known_state": state, "stale": stale,
                "since": since, "duration_seconds": duration, "last_normal_duration_seconds": int(state_row["last_normal_duration"] or 0),
                "blocked_count": int(state_row["blocked_count"] or 0), "last_sample_at": int(state_row["last_sample_at"] or 0),
                "last_classification": state_row["last_classification"], "pending_block_rounds": int(state_row["pending_block_count"] or 0),
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"],
                "available_mainland_sources": source_counts["mainland"], "available_overseas_sources": source_counts["overseas"],
                "evidence": evidence.get("targets", []) if isinstance(evidence, dict) else [], "sample": sample,
                "reason": reason or ("探测数据已过期" if stale else ""), "history": history}
        else:
            result[host["host_id"]] = {"status": "unassessed", "last_known_state": "unassessed", "stale": False,
                "since": 0, "duration_seconds": 0, "last_normal_duration_seconds": 0, "blocked_count": 0,
                "last_sample_at": 0, "last_classification": "unknown", "pending_block_rounds": 0,
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"], "evidence": [], "sample": {},
                "available_mainland_sources": source_counts["mainland"], "available_overseas_sources": source_counts["overseas"],
                "reason": source_reason + "；本机不会作为自己的探测来源" if source_reason else "探针覆盖已就绪，等待首轮自动发现端点并完成 TCP 抽测", "history": history}
    return result


def attach(app, db, verify_signature, signed_response):
    def admin(request):
        if getattr(request.state, "dashboard_role", "") != "admin":
            raise HTTPException(403, "仅管理员可配置 GFW 探测节点")

    @app.get("/api/v1/gfw-probes/manage")
    def manage(request: Request):
        admin(request)
        conn, now = db(), int(time.time())
        try:
            candidates = [dict(row) for row in conn.execute("SELECT host_id,node_id,agent_version,last_seen FROM hosts WHERE node_id<>'' ORDER BY host_id LIMIT 300")]
            role_rows = {row["node_id"]: dict(row) for row in conn.execute("SELECT node_id,role,region,carrier FROM gfw_probe_roles")}
            active_roles = _active_roles(conn, now)
            online_hosts = [item for item in candidates if now - int(item.get("last_seen") or 0) <= STALE_SECONDS]
            target_hosts = 0
            ready_hosts = 0
            independent_probe_hosts = 0
            target_endpoints = 0
            eligible_endpoints = 0
            eligible_containers = 0
            sampled_containers = 0
            missing_reasons = {}
            probe_missing_reasons = {}
            probe_job_counts = {"complete": 0, "failed": 0, "expired": 0, "queued": 0, "running": 0, "cancelled": 0}
            probe_jobs_since = now - 86400
            for job in conn.execute("SELECT status,COUNT(*) AS count FROM gfw_probe_jobs WHERE created_at>=? GROUP BY status", (probe_jobs_since,)):
                if job["status"] in probe_job_counts:
                    probe_job_counts[job["status"]] = int(job["count"] or 0)
            last_probe_job = conn.execute("SELECT MAX(finished_at) FROM gfw_probe_jobs WHERE created_at>=? AND status IN ('complete','failed','expired')", (probe_jobs_since,)).fetchone()
            for item in online_hosts:
                _source_candidates, source_reason = _source_coverage_for_host(active_roles, item["node_id"])
                if not source_reason:
                    independent_probe_hosts += 1
                else:
                    probe_missing_reasons[source_reason] = probe_missing_reasons.get(source_reason, 0) + 1
                state = conn.execute("SELECT state,evidence_json FROM gfw_states WHERE host_id=? AND node_id=?",
                                     (item["host_id"], item["node_id"])).fetchone()
                pinned_endpoint_keys = _blocked_endpoint_keys(state["evidence_json"]) if state and state["state"] == "blocked" else set()
                daily_selection = _same_day_sample(conn, item["host_id"], now)
                targets, reason, sample_metadata = _targets_for_host(
                    conn, item["host_id"], item["node_id"], now,
                    pinned_endpoint_keys=pinned_endpoint_keys, daily_selection=daily_selection,
                )
                sample = sample_metadata.get("sample", {})
                if isinstance(sample, dict):
                    eligible_endpoints += int(sample.get("eligible_endpoints") or 0)
                    eligible_containers += int(sample.get("eligible_containers") or 0)
                    sampled_containers += int(sample.get("sampled_containers") or 0)
                if targets:
                    target_hosts += 1
                    target_endpoints += len(targets)
                    if not source_reason:
                        ready_hosts += 1
                else:
                    label = reason or "未发现可验证的公网 TCP 端点"
                    missing_reasons[label] = missing_reasons.get(label, 0) + 1
            return {"minimum_mainland": MIN_MAINLAND, "minimum_overseas": MIN_OVERSEAS,
                    "coverage": _role_counts(conn, now),
                    "target_coverage": {
                        "online_hosts": len(online_hosts),
                        "hosts_with_targets": target_hosts,
                        "hosts_with_independent_probes": independent_probe_hosts,
                        "hosts_ready_for_probe": ready_hosts,
                        "target_endpoints": target_endpoints,
                        "eligible_endpoints": eligible_endpoints,
                        "eligible_containers": eligible_containers,
                        "sampled_containers": sampled_containers,
                        "sample_limit_per_host": DAILY_CONTAINER_SAMPLE_LIMIT,
                        "sample_date_utc": _utc_sample_date(now).isoformat(),
                        "missing_reasons": [{"reason": reason, "hosts": count} for reason, count in sorted(missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[:5]],
                        "probe_missing_reasons": [{"reason": reason, "hosts": count} for reason, count in sorted(probe_missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[:5]],
                    },
                    "probe_health": {"window_seconds": 86400, "jobs": probe_job_counts,
                                     "last_finished_at": int(last_probe_job[0] or 0) if last_probe_job else 0},
                    "candidates": [{**item,
                                    "role": role_rows.get(item["node_id"], {}).get("role", "disabled"),
                                    "region": role_rows.get(item["node_id"], {}).get("region", ""),
                                    "carrier": role_rows.get(item["node_id"], {}).get("carrier", "")}
                                   for item in candidates]}
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probes/role")
    async def save_role(request: Request):
        admin(request)
        raw = await request.body()
        if len(raw) > 4096:
            raise HTTPException(413, "probe role request too large")
        try:
            payload = json.loads(raw)
        except Exception:
            raise HTTPException(400, "invalid JSON") from None
        if not isinstance(payload, dict) or not {"host_id", "node_id", "role"}.issubset(payload) or set(payload) - {"host_id", "node_id", "role", "region", "carrier"} or not all(isinstance(payload.get(k, ""), str) for k in payload):
            raise HTTPException(400, "invalid probe role")
        payload["region"] = str(payload.get("region") or "").strip()
        payload["carrier"] = str(payload.get("carrier") or "").strip()
        if (payload["role"] not in {"disabled", "mainland", "overseas"}
                or not 1 <= len(payload["host_id"]) <= 200 or not 1 <= len(payload["node_id"]) <= 128
                or len(payload["region"]) > 80 or len(payload["carrier"]) > 100
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in payload["region"] + payload["carrier"])):
            raise HTTPException(400, "invalid probe role")
        conn, now = db(), int(time.time())
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not conn.execute("SELECT 1 FROM hosts WHERE host_id=? AND node_id=?", (payload["host_id"], payload["node_id"])).fetchone():
                raise HTTPException(409, "主机身份已变化，请刷新节点列表")
            previous = conn.execute("SELECT role FROM gfw_probe_roles WHERE node_id=?", (payload["node_id"],)).fetchone()
            if previous and previous["role"] != payload["role"]:
                affected = conn.execute("SELECT DISTINCT cycle_id FROM gfw_probe_jobs WHERE source_node_id=? AND status='queued'", (payload["node_id"],)).fetchall()
                conn.execute("UPDATE gfw_probe_jobs SET status='cancelled',finished_at=?,error='probe role changed' WHERE source_node_id=? AND status='queued'", (now, payload["node_id"]))
                for cycle_row in affected:
                    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (cycle_row["cycle_id"],)).fetchone()
                    if cycle:
                        _apply_cycle(conn, cycle, now)
            if payload["role"] == "disabled":
                conn.execute("DELETE FROM gfw_probe_roles WHERE node_id=?", (payload["node_id"],))
            else:
                conn.execute("INSERT INTO gfw_probe_roles(node_id,host_id,role,updated_at,region,carrier) VALUES(?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET host_id=excluded.host_id,role=excluded.role,updated_at=excluded.updated_at,region=excluded.region,carrier=excluded.carrier",
                             (payload["node_id"], payload["host_id"], payload["role"], now, payload["region"], payload["carrier"]))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probe/report")
    async def agent_report(request: Request):
        raw = await request.body()
        if len(raw) > 32768:
            raise HTTPException(413, "GFW probe report too large")
        ts = request.headers.get("x-timestamp", "")
        verify_signature(raw, ts, request.headers.get("x-signature", ""))
        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "invalid JSON") from None
        conn = db()
        try:
            return signed_response(report(conn, payload, int(time.time())), ts)
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probe/failure")
    async def agent_failure(request: Request):
        raw = await request.body()
        if len(raw) > 8192:
            raise HTTPException(413, "GFW probe failure report too large")
        ts = request.headers.get("x-timestamp", "")
        verify_signature(raw, ts, request.headers.get("x-signature", ""))
        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "invalid JSON") from None
        conn = db()
        try:
            return signed_response(report_failure(conn, payload, int(time.time())), ts)
        finally:
            conn.close()
