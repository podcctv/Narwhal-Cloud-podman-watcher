"""Correlate domestic and overseas TCP probes for conservative GFW reachability history."""
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid

from fastapi import HTTPException, Request

MAX_TARGETS = 8
MIN_MAINLAND = 2
MIN_OVERSEAS = 1
CYCLE_SECONDS = 300
STALE_SECONDS = 900
JOB_SECONDS = 600
MAX_ACTIVE_CYCLES = 30
SUCCESSFUL_PROBE_ERRORS = {"", "timeout", "refused", "network_error"}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


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
    elif source == "incus-proxy":
        if listen.lower().startswith("udp:"):
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


def _targets_for_host(conn, host_id, node_id, now):
    host_sample = conn.execute(
        "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1", (host_id,)
    ).fetchone()
    if not host_sample or now - int(host_sample["ts"] or 0) > STALE_SECONDS:
        return [], "宿主机网卡采样已过期"
    try:
        payload = json.loads(host_sample["payload_json"] or "{}")
        inventory = payload.get("host_firewall", {}).get("interface_inventory", {})
    except (TypeError, ValueError, AttributeError):
        inventory = {}
    if not isinstance(inventory, dict) or inventory.get("status") != "ready":
        return [], "尚未收到可用的网卡地址清单"
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
    if not addresses:
        return [], "未发现直接配置在网卡上的公网 IPv4；NAT 公网地址无法安全推断"

    latest = conn.execute(
        "SELECT runtime,project,container_name,payload_json,ts FROM reports WHERE host_id=? AND runtime IN ('incus','podman') AND ts>=? ORDER BY ts DESC,id DESC LIMIT 1200",
        (host_id, now - STALE_SECONDS),
    ).fetchall()
    newest, discovered = set(), {}
    for row in latest:
        key = (row["runtime"], row["project"], row["container_name"])
        if key in newest:
            continue
        newest.add(key)
        try:
            security = json.loads(row["payload_json"] or "{}").get("security", {})
        except (TypeError, ValueError, AttributeError):
            continue
        exposures = security.get("network_exposure", []) if isinstance(security, dict) else []
        for exposure in exposures[:128] if isinstance(exposures, list) else []:
            bind, port = _listen_endpoint(exposure)
            if not port:
                continue
            explicit = _public_v4(bind)
            target_ips = [explicit] if explicit and explicit in addresses else addresses if bind in ("", "*", "0.0.0.0", "::") else []
            for ip in target_ips:
                target = {"ip": ip, "port": port, "interface": interface_by_ip.get(ip, "")}
                target["id"] = _digest({"host_id": host_id, **target})[:24]
                discovered[target["id"]] = target
    targets = sorted(discovered.values(), key=lambda item: (item["ip"], item["port"]))[:MAX_TARGETS]
    return targets, "" if targets else "没有发现已确认的公网 Incus / Podman TCP 端口映射"


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS gfw_probe_roles(
      node_id TEXT PRIMARY KEY,host_id TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('mainland','overseas')),updated_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS gfw_cycles(
      id TEXT PRIMARY KEY,host_id TEXT NOT NULL,node_id TEXT NOT NULL,targets_json TEXT NOT NULL,status TEXT NOT NULL,
      created_at INTEGER NOT NULL,deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,result_json TEXT NOT NULL DEFAULT '{}');
    CREATE UNIQUE INDEX IF NOT EXISTS gfw_one_active_cycle ON gfw_cycles(host_id) WHERE status IN ('queued','running');
    CREATE INDEX IF NOT EXISTS gfw_cycles_host_time ON gfw_cycles(host_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS gfw_probe_jobs(
      id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,source_host_id TEXT NOT NULL,source_node_id TEXT NOT NULL,role TEXT NOT NULL,
      targets_json TEXT NOT NULL,targets_hash TEXT NOT NULL,lease TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,
      deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '');
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
    rows = conn.execute("SELECT r.host_id,r.node_id,r.role,h.last_seen,o.payload FROM gfw_probe_roles r JOIN hosts h ON h.node_id=r.node_id LEFT JOIN ops_hosts o ON o.node=h.node_id ORDER BY r.role,r.host_id").fetchall()
    result = {"mainland": [], "overseas": []}
    for row in rows:
        try:
            interval = int(json.loads(row["payload"] or "{}").get("report_interval", 300))
        except (ValueError, TypeError):
            interval = 300
        if now - int(row["last_seen"] or 0) <= max(600, min(1800, interval * 3)):
            result[row["role"]].append({"host_id": row["host_id"], "node_id": row["node_id"]})
    result["mainland"] = result["mainland"][:5]
    result["overseas"] = result["overseas"][:3]
    return result


def _schedule(conn, now):
    roles = _active_roles(conn, now)
    if len(roles["mainland"]) < MIN_MAINLAND or len(roles["overseas"]) < MIN_OVERSEAS:
        return
    hosts = conn.execute("SELECT host_id,node_id,last_seen FROM hosts WHERE node_id<>'' AND last_seen>=? ORDER BY COALESCE((SELECT last_cycle_at FROM gfw_states s WHERE s.host_id=hosts.host_id),0),host_id LIMIT 300", (now - STALE_SECONDS,)).fetchall()
    for host in hosts:
        active_cycles = int(conn.execute("SELECT COUNT(*) FROM gfw_cycles WHERE status IN ('queued','running')").fetchone()[0])
        if active_cycles >= MAX_ACTIVE_CYCLES:
            break
        state = conn.execute("SELECT last_cycle_at FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        last_cycle = int(state[0] or 0) if state else 0
        if now - last_cycle < CYCLE_SECONDS:
            continue
        if conn.execute("SELECT 1 FROM gfw_cycles WHERE host_id=? AND status IN ('queued','running') LIMIT 1", (host["host_id"],)).fetchone():
            continue
        host_roles = {role: [source for source in roles[role] if source["node_id"] != host["node_id"]][:need]
                      for role, need in (("mainland", MIN_MAINLAND), ("overseas", MIN_OVERSEAS))}
        if len(host_roles["mainland"]) < MIN_MAINLAND or len(host_roles["overseas"]) < MIN_OVERSEAS:
            own_role = next((role for role in ("mainland", "overseas") if any(item["node_id"] == host["node_id"] for item in roles[role])), "")
            missing = []
            if len(host_roles["mainland"]) < MIN_MAINLAND:
                missing.append(f"{MIN_MAINLAND} 个非本机国内探测点")
            if len(host_roles["overseas"]) < MIN_OVERSEAS:
                missing.append(f"{MIN_OVERSEAS} 个非本机海外探测点")
            reason = "作为探测节点不能自测；请补充" + "和".join(missing) if own_role else "可用探测点不足；请配置至少 2 个国内和 1 个海外探测节点"
            conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,last_classification,evidence_json) VALUES(?,?,?,'unknown',?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,last_classification='unknown',evidence_json=excluded.evidence_json",
                         (host["host_id"], host["node_id"], now, _json({"reason": reason, "targets": []})))
            continue  # Never use a node to probe its own public endpoint.
        targets, _reason = _targets_for_host(conn, host["host_id"], host["node_id"], now)
        if not targets:
            conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,last_classification,evidence_json) VALUES(?,?,?,'unknown',?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,last_classification='unknown',evidence_json=excluded.evidence_json",
                         (host["host_id"], host["node_id"], now, _json({"reason": _reason, "targets": []})))
            continue
        cycle_id = str(uuid.uuid4())
        targets_json = _json(targets)
        conn.execute("INSERT INTO gfw_cycles(id,host_id,node_id,targets_json,status,created_at,deadline_at) VALUES(?,?,?,?,'queued',?,?)",
                     (cycle_id, host["host_id"], host["node_id"], targets_json, now, now + JOB_SECONDS))
        conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at) VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at",
                     (host["host_id"], host["node_id"], now))
        for role in ("mainland", "overseas"):
            for source in host_roles[role]:
                job_id = str(uuid.uuid4())
                conn.execute("INSERT INTO gfw_probe_jobs(id,cycle_id,source_host_id,source_node_id,role,targets_json,targets_hash,lease,status,created_at,deadline_at) VALUES(?,?,?,?,?,?,?,?, 'queued',?,?)",
                             (job_id, cycle_id, source["host_id"], source["node_id"], role, targets_json, _digest(targets), secrets.token_urlsafe(32), now, now + JOB_SECONDS))


def _apply_cycle(conn, cycle, now):
    jobs = conn.execute("SELECT * FROM gfw_probe_jobs WHERE cycle_id=?", (cycle["id"],)).fetchall()
    if not jobs or any(job["status"] not in ("complete", "expired", "failed", "cancelled") for job in jobs):
        return False
    targets = json.loads(cycle["targets_json"])
    evidence = []
    successful_cycle = False
    blocked_cycle = False
    for target in targets:
        by_role = {"mainland": {"success": 0, "failed": 0, "total": 0}, "overseas": {"success": 0, "failed": 0, "total": 0}}
        for job in jobs:
            result = conn.execute("SELECT success,error,latency_ms FROM gfw_probe_results WHERE job_id=? AND target_id=?", (job["id"], target["id"])).fetchone()
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
        evidence.append({"ip": target["ip"], "port": target["port"], "interface": target.get("interface", ""),
                         "status": status, "mainland": main, "overseas": over})
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
                        "blocked_endpoint_keys": sorted([list(key) for key in anchored_blocked_keys])}
    if reason:
        evidence_payload["reason"] = reason
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
                 ("complete" if classification != "unknown" else "partial", now, _json({"classification": classification, "targets": evidence}), cycle["id"]))
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


def status_map(conn, now):
    counts = _role_counts(conn, now)
    result = {}
    rows = conn.execute("SELECT * FROM hosts ORDER BY host_id LIMIT 500").fetchall()
    for host in rows:
        state_row = conn.execute("SELECT * FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        history = [dict(event) for event in conn.execute("SELECT event_type,at,duration_seconds,normal_duration_seconds FROM gfw_events WHERE host_id=? ORDER BY at DESC,id DESC LIMIT 6", (host["host_id"],))]
        if state_row:
            state = state_row["state"]
            last_sample_at = int(state_row["last_sample_at"] or 0)
            stale = last_sample_at > 0 and now - last_sample_at > STALE_SECONDS
            coverage_insufficient = counts["mainland"] < MIN_MAINLAND or counts["overseas"] < MIN_OVERSEAS
            try:
                evidence = json.loads(state_row["evidence_json"] or "{}")
            except ValueError:
                evidence = {}
            reason = str(evidence.get("reason") or "") if isinstance(evidence, dict) else ""
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
                reason = "探测节点不足：需至少 2 个在线国内点和 1 个在线海外点"
            elif status == "investigating" and not reason:
                reason = "本轮证据不足或端点变化；当前不确认恢复，也不把未知样本计入持续时长"
            result[host["host_id"]] = {"status": status, "last_known_state": state, "stale": stale,
                "since": since, "duration_seconds": duration, "last_normal_duration_seconds": int(state_row["last_normal_duration"] or 0),
                "blocked_count": int(state_row["blocked_count"] or 0), "last_sample_at": int(state_row["last_sample_at"] or 0),
                "last_classification": state_row["last_classification"], "pending_block_rounds": int(state_row["pending_block_count"] or 0),
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"],
                "evidence": evidence.get("targets", []) if isinstance(evidence, dict) else [], "reason": "探测数据已过期" if stale else reason, "history": history}
        else:
            result[host["host_id"]] = {"status": "unassessed", "last_known_state": "unassessed", "stale": False,
                "since": 0, "duration_seconds": 0, "last_normal_duration_seconds": 0, "blocked_count": 0,
                "last_sample_at": 0, "last_classification": "unknown", "pending_block_rounds": 0,
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"], "evidence": [],
                "reason": "需配置至少 2 个国内和 1 个海外探测节点" if counts["mainland"] < MIN_MAINLAND or counts["overseas"] < MIN_OVERSEAS else "等待有效的公网 TCP 映射采样", "history": history}
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
            roles = {row["node_id"]: row["role"] for row in conn.execute("SELECT node_id,role FROM gfw_probe_roles")}
            return {"minimum_mainland": MIN_MAINLAND, "minimum_overseas": MIN_OVERSEAS,
                    "coverage": _role_counts(conn, now), "candidates": [{**item, "role": roles.get(item["node_id"], "disabled")} for item in candidates]}
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
        if not isinstance(payload, dict) or set(payload) != {"host_id", "node_id", "role"} or not all(isinstance(payload.get(k), str) for k in payload):
            raise HTTPException(400, "invalid probe role")
        if payload["role"] not in {"disabled", "mainland", "overseas"} or not 1 <= len(payload["host_id"]) <= 200 or not 1 <= len(payload["node_id"]) <= 128:
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
                conn.execute("INSERT INTO gfw_probe_roles(node_id,host_id,role,updated_at) VALUES(?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET host_id=excluded.host_id,role=excluded.role,updated_at=excluded.updated_at",
                             (payload["node_id"], payload["host_id"], payload["role"], now))
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
