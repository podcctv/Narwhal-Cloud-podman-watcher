"""Bounded operational state, independent of FastAPI and deployment paths."""
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import statistics
import shutil
import threading
import tempfile
import time
try:
    from server import disk_cleanup, upgrade_health
except ImportError:
    import disk_cleanup
    import upgrade_health
from datetime import datetime, timezone, timedelta
from pathlib import Path

TZ = timezone(timedelta(hours=8))
PROFILES = {
    "general": {"connections": 500, "rx_bps": 50_000_000, "http_rps": 100, "baseline_factor": 4},
    "web": {"connections": 2000, "rx_bps": 100_000_000, "http_rps": 500, "baseline_factor": 4},
    "socks": {"connections": 1000, "rx_bps": 100_000_000, "http_rps": 100, "baseline_factor": 5},
    "hy2": {"connections": 1500, "rx_bps": 150_000_000, "http_rps": 100, "baseline_factor": 6},
}
_backup_lock = threading.Lock()
_restore_drill_lock = threading.Lock()


def restore_drill_enabled(settings):
    """Treat legacy settings without an explicit opt-out as enabled."""
    if not isinstance(settings, dict):
        return True
    return settings.get("drill_enabled", True) is not False


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS ops_hosts(node TEXT PRIMARY KEY,host_id TEXT,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_meter(entity TEXT PRIMARY KEY,host_id TEXT,runtime TEXT,project TEXT,name TEXT,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_rollups(entity TEXT,period TEXT,bucket INTEGER,samples INTEGER DEFAULT 0,
      rx REAL DEFAULT 0,tx REAL DEFAULT 0,covered REAL DEFAULT 0,gaps INTEGER DEFAULT 0,estimated INTEGER DEFAULT 0,
      cpu_sum REAL DEFAULT 0,mem_sum REAL DEFAULT 0,peak_connections INTEGER DEFAULT 0,PRIMARY KEY(entity,period,bucket));
    CREATE INDEX IF NOT EXISTS idx_ops_rollups_period_bucket ON ops_rollups(period,bucket);
    CREATE TABLE IF NOT EXISTS ops_policies(entity TEXT PRIMARY KEY,profile TEXT,payload TEXT,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS ops_incidents(id INTEGER PRIMARY KEY,entity TEXT,kind TEXT,status TEXT,opened_at INTEGER,last_seen INTEGER,payload TEXT);
    CREATE INDEX IF NOT EXISTS idx_ops_incidents_entity ON ops_incidents(entity,last_seen);
    CREATE TABLE IF NOT EXISTS ops_events(id INTEGER PRIMARY KEY,incident_id INTEGER,ts INTEGER,kind TEXT,payload TEXT);
    CREATE INDEX IF NOT EXISTS idx_ops_events_incident ON ops_events(incident_id,ts);
    CREATE TABLE IF NOT EXISTS ops_rechecks(action_id INTEGER PRIMARY KEY,entity TEXT,alert_type TEXT,status TEXT,
      attempts INTEGER DEFAULT 0,clean_samples INTEGER DEFAULT 0,ts INTEGER,message TEXT);
    CREATE TABLE IF NOT EXISTS ops_services(id INTEGER PRIMARY KEY,host_id TEXT,name TEXT,payload TEXT,enabled INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS ops_service_results(service_id INTEGER PRIMARY KEY,ts INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_service_inventory(
      entity TEXT PRIMARY KEY,host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,
      observed_at INTEGER NOT NULL DEFAULT 0,inventory_state TEXT NOT NULL DEFAULT 'unavailable',
      complete_at INTEGER NOT NULL DEFAULT 0,inventory_json TEXT NOT NULL DEFAULT '[]');
    CREATE INDEX IF NOT EXISTS idx_ops_service_inventory_host ON ops_service_inventory(host_id,runtime,container_name);
    CREATE TABLE IF NOT EXISTS ops_service_inventory_changes(
      id INTEGER PRIMARY KEY,entity TEXT NOT NULL,host_id TEXT NOT NULL,runtime TEXT NOT NULL,
      project TEXT NOT NULL DEFAULT '',container_name TEXT NOT NULL,ts INTEGER NOT NULL,
      change_type TEXT NOT NULL,confidence TEXT NOT NULL,listener_key TEXT NOT NULL,payload TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_ops_service_inventory_changes_host_ts
      ON ops_service_inventory_changes(host_id,ts DESC);
    CREATE INDEX IF NOT EXISTS idx_ops_service_inventory_changes_entity_ts
      ON ops_service_inventory_changes(entity,ts DESC);
    CREATE TABLE IF NOT EXISTS ops_upgrades(id INTEGER PRIMARY KEY,version TEXT,revision TEXT,status TEXT,created_at INTEGER,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_upgrade_nodes(campaign INTEGER,host_id TEXT,action_id INTEGER,status TEXT,previous_version TEXT,
      PRIMARY KEY(campaign,host_id));
    CREATE TABLE IF NOT EXISTS ops_users(username TEXT PRIMARY KEY,password_hash TEXT,role TEXT,enabled INTEGER DEFAULT 1,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS ops_audit(id INTEGER PRIMARY KEY,ts INTEGER,username TEXT,method TEXT,path TEXT,status INTEGER);
    CREATE TABLE IF NOT EXISTS security_action_receipts(action_id INTEGER PRIMARY KEY,payload TEXT,updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS ops_settings(key TEXT PRIMARY KEY,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_disk_cleanup_policies(node TEXT PRIMARY KEY,host_id TEXT,payload TEXT);
    CREATE TABLE IF NOT EXISTS ops_disk_cleanup_runs(node TEXT,run_id TEXT,host_id TEXT,ts INTEGER,payload TEXT,PRIMARY KEY(node,run_id));
    CREATE TABLE IF NOT EXISTS ops_backup_drills(
      id INTEGER PRIMARY KEY,backup_name TEXT NOT NULL,started_at INTEGER NOT NULL,finished_at INTEGER NOT NULL,
      duration_ms INTEGER NOT NULL,status TEXT NOT NULL,message TEXT NOT NULL DEFAULT '',bytes INTEGER NOT NULL DEFAULT 0,
      sha256 TEXT NOT NULL DEFAULT '',details_json TEXT NOT NULL DEFAULT '{}');
    CREATE INDEX IF NOT EXISTS idx_ops_backup_drills_started ON ops_backup_drills(started_at DESC);
    CREATE TABLE IF NOT EXISTS ops_alert_replays(
      id INTEGER PRIMARY KEY,host_id TEXT NOT NULL,runtime TEXT NOT NULL,project TEXT NOT NULL DEFAULT '',
      container_name TEXT NOT NULL,created_at INTEGER NOT NULL,lookback_minutes INTEGER NOT NULL,
      input_digest TEXT NOT NULL,report_count INTEGER NOT NULL,assessment_json TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_ops_alert_replays_target ON ops_alert_replays(host_id,runtime,project,container_name,created_at DESC);
    CREATE TABLE IF NOT EXISTS ops_alert_feedback(
      id INTEGER PRIMARY KEY,replay_id INTEGER,alert_id INTEGER,host_id TEXT NOT NULL,runtime TEXT NOT NULL,
      project TEXT NOT NULL DEFAULT '',container_name TEXT NOT NULL,source_ip TEXT NOT NULL DEFAULT '',
      category TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',requested_by TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_ops_alert_feedback_target ON ops_alert_feedback(host_id,runtime,project,container_name,created_at DESC);
    """)


def pause_upgrade_campaign_for_failure(conn, action_id, host_id, ts, reason, kind="install_failure"):
    """Pause the owning rollout immediately and cancel work not yet dispatched."""
    action = conn.execute(
        "SELECT params_json FROM security_actions WHERE id=? AND host_id=?",
        (action_id, host_id),
    ).fetchone()
    params = loads(action["params_json"] if action else "{}", {})
    campaign_id = params.get("campaign_id")
    if not campaign_id:
        owner = conn.execute(
            "SELECT campaign FROM ops_upgrade_nodes WHERE action_id=? AND host_id=?",
            (action_id, host_id),
        ).fetchone()
        campaign_id = owner["campaign"] if owner else None
    if not campaign_id:
        return False
    campaign = conn.execute(
        "SELECT status,payload FROM ops_upgrades WHERE id=?", (campaign_id,)
    ).fetchone()
    if not campaign or campaign["status"] not in {"canary", "rollout", "paused"}:
        return False

    clean_reason = "".join(ch for ch in str(reason or "升级未通过健康门禁") if ch >= " " or ch == "\t")[:400]
    metadata = loads(campaign["payload"], {})
    if campaign["status"] != "paused":
        metadata["paused_from_status"] = campaign["status"]
    metadata.update(
        paused_at=int(ts),
        paused_host=host_id,
        pause_kind=kind,
        paused_reason=clean_reason,
    )
    conn.execute(
        "UPDATE ops_upgrades SET status='paused',payload=? WHERE id=?",
        (json.dumps(metadata, ensure_ascii=False), campaign_id),
    )

    # Unpolled actions cannot be executing yet. Cancel them and return their
    # rollout nodes to pending so an administrator can safely resume later.
    queued = conn.execute(
        "SELECT a.id,a.host_id FROM security_actions a "
        "JOIN ops_upgrade_nodes n ON n.action_id=a.id "
        "WHERE n.campaign=? AND a.action_type='managed_upgrade' AND a.status='queued' AND a.id<>?",
        (campaign_id, action_id),
    ).fetchall()
    for pending in queued:
        conn.execute(
            "UPDATE security_actions SET status='cancelled',result_message=?,updated_at=? WHERE id=? AND status='queued'",
            (f"发布因节点 {host_id} 未通过门禁而暂停；该升级尚未派发", int(ts), pending["id"]),
        )
        conn.execute(
            "UPDATE ops_upgrade_nodes SET status='pending',action_id=NULL WHERE campaign=? AND host_id=? AND action_id=?",
            (campaign_id, pending["host_id"], pending["id"]),
        )
        attempts = metadata.setdefault("attempts", {})
        host_attempts = int(attempts.get(pending["host_id"], 0) or 0)
        if host_attempts > 0:
            attempts[pending["host_id"]] = host_attempts - 1
    if queued:
        conn.execute(
            "UPDATE ops_upgrades SET payload=? WHERE id=?",
            (json.dumps(metadata, ensure_ascii=False), campaign_id),
        )
    return True


def loads(value, fallback=None):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {} if fallback is None else fallback


def number(value):
    try:
        v = float(value)
        return max(0, v) if math.isfinite(v) else 0
    except (TypeError, ValueError):
        return 0


def identity(node, runtime="host", project="", name="__host__"):
    return json.dumps([node, runtime, project, name], ensure_ascii=False, separators=(",", ":"))


def policy(conn, entity):
    parts = loads(entity, [])
    host = identity(parts[0]) if parts else entity
    row = conn.execute("SELECT * FROM ops_policies WHERE entity IN (?,?) ORDER BY entity=? DESC LIMIT 1", (entity, host, entity)).fetchone()
    profile = row["profile"] if row else "general"
    saved = loads(row["payload"]) if row else {}
    return {"profile": profile, "monthly_quota_bytes":0, "quota_warning":.8, "silent_until":0,
            "bandwidth_mbps":0, "bandwidth_ratio":.9, "bandwidth_duration_seconds":600,
            **PROFILES.get(profile, PROFILES["general"]), **saved}


def bandwidth_capacity(conn, host, c, entity, ts):
    # Capacity is per instance. Never inherit the entire host NIC capacity.
    row = conn.execute("SELECT payload FROM ops_policies WHERE entity=?", (entity,)).fetchone()
    explicit = number(loads(row[0] if row else None).get('bandwidth_mbps'))
    if explicit:
        return explicit, 'instance_policy'
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE name='buyer_targets'").fetchone():
        return 0, ''
    mapped = conn.execute("SELECT bandwidth_mbps FROM buyer_targets WHERE host_id=? AND runtime=? AND project=? AND container_name=? "
                          "AND source='upstream' AND enabled=1 AND verified_at>=?", (host,c.get('runtime','podman'),c.get('project',''),c.get('name',''),ts-900)).fetchone()
    return (number(mapped[0]), 'upstream_instance') if mapped else (0, '')


def bandwidth_sample(conn, entity, ts, c, old, covered, rx, tx, valid, capacity, source, rules):
    c['bandwidth_monitor'] = {'available': bool(valid and covered and capacity), 'capacity_mbps': capacity}
    prior = old.get('bandwidth', {})
    current = {'capacity_mbps':capacity, 'source':source, 'covered_seconds':0, 'samples':0, 'direction':''}
    if not c['bandwidth_monitor']['available']:
        row = conn.execute("SELECT payload FROM ops_incidents WHERE entity=? AND kind='bandwidth_saturation' AND status='open'", (entity,)).fetchone()
        if row:
            event(conn,entity,'bandwidth_saturation',ts,{**loads(row[0]), 'data_stale':True})
        return current
    rx_mbps, tx_mbps = rx * 8 / covered / 1e6, tx * 8 / covered / 1e6
    direction = 'rx' if rx_mbps >= tx_mbps else 'tx'
    rate = max(rx_mbps, tx_mbps)  # Full-duplex directions must not be added.
    ratio = number(rules.get('bandwidth_ratio', .9))
    duration = number(rules.get('bandwidth_duration_seconds', 600))
    high = rate >= capacity * ratio
    same = (prior.get('direction') == direction and prior.get('capacity_mbps') == capacity
            and prior.get('source') == source and prior.get('ratio') == ratio and prior.get('duration') == duration)
    current.update(direction=direction if high else '', ratio=ratio, duration=duration)
    if high:
        current['covered_seconds'] = min(7*86400, (number(prior.get('covered_seconds')) if same else 0) + covered)
        current['samples'] = min(100000, (int(number(prior.get('samples'))) if same else 0) + 1)
    ready = high and current['covered_seconds'] >= duration and current['samples'] >= 2
    payload = {**current, 'rate_mbps':rate, 'rx_mbps':rx_mbps,'tx_mbps':tx_mbps,
               'direction_label':'下载' if direction=='rx' else '上传', 'utilization':rate/capacity,
               'observed_at':ts, 'data_stale':not ready or rules.get('silent_until',0) >= ts,
               'severity':'critical' if current['covered_seconds'] >= max(1800,duration*3) else 'warning'}
    if ready and rules.get('silent_until',0) < ts:
        event(conn,entity,'bandwidth_saturation',ts,payload)
    elif not high:
        event(conn,entity,'bandwidth_saturation',ts,{**payload,'data_stale':False},False)
    elif conn.execute("SELECT id FROM ops_incidents WHERE entity=? AND kind='bandwidth_saturation' AND status='open'", (entity,)).fetchone():
        event(conn,entity,'bandwidth_saturation',ts,payload)
    return current


def event(conn, entity, kind, ts, payload, active=True):
    row = conn.execute("SELECT id FROM ops_incidents WHERE entity=? AND kind=? AND status='open' ORDER BY id DESC LIMIT 1", (entity, kind)).fetchone()
    if not row and not active:
        return
    if row:
        incident = row[0]
        conn.execute("UPDATE ops_incidents SET last_seen=?,status=?,payload=? WHERE id=?", (ts, "open" if active else "resolved", json.dumps(payload), incident))
    else:
        incident = conn.execute("INSERT INTO ops_incidents(entity,kind,status,opened_at,last_seen,payload) VALUES(?,?,'open',?,?,?)", (entity, kind, ts, ts, json.dumps(payload))).lastrowid
    # Repeated samples update episode state, but do not flood the timeline.
    last = conn.execute("SELECT ts,kind FROM ops_events WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident,)).fetchone()
    label = kind if active else "recovered"
    if not last or last[1] != label or ts - last[0] >= 300:
        conn.execute("INSERT INTO ops_events(incident_id,ts,kind,payload) VALUES(?,?,?,?)", (incident, ts, label, json.dumps(payload)))


def _service_inventory_rows(value):
    """Normalize bounded listener data while keeping PID as evidence, not identity."""
    if not isinstance(value, list):
        return []
    normalized = {}
    for raw in value[:100]:
        if not isinstance(raw, dict):
            continue
        proto = str(raw.get('proto') or '').lower()
        process = str(raw.get('process') or '').strip()[:120]
        local = str(raw.get('local') or '').strip()[:160]
        try:
            port = int(raw.get('port') or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if proto not in {'tcp', 'udp'} or not 1 <= port <= 65535:
            continue
        app_protocols = sorted({str(x).lower()[:32] for x in raw.get('application_protocols', [])[:16]
                                if isinstance(x, str) and x.strip()}) if isinstance(raw.get('application_protocols'), list) else []
        try:
            pid = max(0, min(4_194_304, int(raw.get('pid') or 0)))
        except (TypeError, ValueError, OverflowError):
            pid = 0
        row = {
            'process': process, 'pid': pid, 'proto': proto, 'local': local, 'port': port,
            'source': str(raw.get('source') or '')[:40],
            'process_attribution': str(raw.get('process_attribution') or 'unavailable')[:24],
            'application_protocols': app_protocols,
            'application_protocol_evidence': str(raw.get('application_protocol_evidence') or '')[:64],
        }
        # A process restart must not create a fake service addition/removal.
        binding = json.dumps([proto, port, local], ensure_ascii=False, separators=(',', ':'))
        normalized.setdefault(binding, []).append(row)
    return [row for key in sorted(normalized) for row in sorted(normalized[key], key=lambda x: (x['process'].lower(), x['application_protocols']))]


def _service_listener_confidence(listener):
    if listener.get('process_attribution') == 'attributed' and int(listener.get('pid') or 0) > 1:
        if listener.get('application_protocol_evidence') == 'config_matches_live_pid_and_port':
            return 'high'
        return 'medium'
    return 'low'


def _ingest_service_inventory(conn, entity, host_id, runtime, project, name, ts, security):
    state = str(security.get('service_inventory_state') or 'unavailable')[:24]
    if state not in {'complete', 'partial', 'unavailable'}:
        state = 'unavailable'
    current = conn.execute('SELECT * FROM ops_service_inventory WHERE entity=?', (entity,)).fetchone()
    previous_rows = loads(current['inventory_json'], []) if current else []
    if not isinstance(previous_rows, list):
        previous_rows = []
    if state == 'complete':
        observed_rows = _service_inventory_rows(security.get('service_listeners'))
        old_by_binding = {}
        new_by_binding = {}
        for item in previous_rows:
            if isinstance(item, dict):
                key = json.dumps([item.get('proto'), item.get('port'), item.get('local')], ensure_ascii=False, separators=(',', ':'))
                old_by_binding.setdefault(key, []).append(item)
        for item in observed_rows:
            key = json.dumps([item.get('proto'), item.get('port'), item.get('local')], ensure_ascii=False, separators=(',', ':'))
            new_by_binding.setdefault(key, []).append(item)
        # First complete sample is a baseline, never an alert.
        if current is not None and int(current['complete_at'] or 0) > 0:
            for key in sorted(set(old_by_binding) | set(new_by_binding)):
                old_items = old_by_binding.get(key, [])
                new_items = new_by_binding.get(key, [])
                old_owner = {(str(x.get('process') or '').lower(), tuple(x.get('application_protocols') or ())): x for x in old_items}
                new_owner = {(str(x.get('process') or '').lower(), tuple(x.get('application_protocols') or ())): x for x in new_items}
                changes = []
                if not old_items:
                    changes.extend(('listener_added', item, None) for item in new_items)
                elif not new_items:
                    changes.extend(('listener_removed', None, item) for item in old_items)
                elif set(old_owner) != set(new_owner):
                    if len(old_owner) == len(new_owner) == 1:
                        changes.append(('listener_owner_changed', next(iter(new_owner.values()), None), next(iter(old_owner.values()), None)))
                    else:
                        changes.extend(('listener_added', item, None) for ident, item in new_owner.items() if ident not in old_owner)
                        changes.extend(('listener_removed', None, item) for ident, item in old_owner.items() if ident not in new_owner)
                for change_type, item, old_item in changes[:200]:
                    listener = item or old_item or {}
                    confidence = _service_listener_confidence(listener)
                    detail = {
                        'change_type': change_type, 'confidence': confidence,
                        'proto': listener.get('proto'), 'port': listener.get('port'),
                        'local': listener.get('local'), 'process': listener.get('process') or '',
                        'pid': listener.get('pid') or 0, 'source': listener.get('source') or '',
                        'application_protocols': listener.get('application_protocols') or [],
                        'application_protocol_evidence': listener.get('application_protocol_evidence') or '',
                        'previous_process': (old_item or {}).get('process') or '',
                        'previous_pid': (old_item or {}).get('pid') or 0,
                        'evidence': '完整服务清单采样差异；PID 仅作取证线索，变更判断基于监听地址/协议/端口/进程/配置标签。',
                    }
                    conn.execute(
                        'INSERT INTO ops_service_inventory_changes(entity,host_id,runtime,project,container_name,ts,change_type,confidence,listener_key,payload) VALUES(?,?,?,?,?,?,?,?,?,?)',
                        (entity, host_id, runtime, project, name, ts, change_type, confidence, key, json.dumps(detail, ensure_ascii=False)),
                    )
        conn.execute(
            'INSERT INTO ops_service_inventory(entity,host_id,runtime,project,container_name,observed_at,inventory_state,complete_at,inventory_json) VALUES(?,?,?,?,?,?,?,?,?) '
            'ON CONFLICT(entity) DO UPDATE SET host_id=excluded.host_id,runtime=excluded.runtime,project=excluded.project,container_name=excluded.container_name,observed_at=excluded.observed_at,inventory_state=excluded.inventory_state,complete_at=excluded.complete_at,inventory_json=excluded.inventory_json',
            (entity, host_id, runtime, project, name, ts, state, ts, json.dumps(observed_rows, ensure_ascii=False)),
        )
    else:
        # Keep the last complete inventory, but explicitly surface the latest coverage state.
        conn.execute(
            'INSERT INTO ops_service_inventory(entity,host_id,runtime,project,container_name,observed_at,inventory_state,complete_at,inventory_json) VALUES(?,?,?,?,?,?,?,0,?) '
            'ON CONFLICT(entity) DO UPDATE SET host_id=excluded.host_id,runtime=excluded.runtime,project=excluded.project,container_name=excluded.container_name,observed_at=excluded.observed_at,inventory_state=excluded.inventory_state',
            (entity, host_id, runtime, project, name, ts, state, '[]'),
        )


def ingest(conn, host_id, node_id, ts, data):
    node = node_id or host_id
    previous = conn.execute("SELECT ts FROM ops_hosts WHERE node=?", (node,)).fetchone()
    if previous and ts <= previous[0]:
        return []  # Old/replayed report must not mutate ledger/baseline/rechecks.
    operations = data.get("operations") if isinstance(data.get("operations"), dict) else {}
    maintenance=operations.get('disk_cleanup',{})
    if isinstance(maintenance,dict):
        for run in maintenance.get('runs',[])[:20]:disk_cleanup.record(conn,host_id,node_id,run)
    conn.execute("INSERT INTO ops_hosts VALUES(?,?,?,?) ON CONFLICT(node) DO UPDATE SET host_id=excluded.host_id,ts=excluded.ts,payload=excluded.payload", (node, host_id, ts, json.dumps(operations)))
    interval = max(60, min(3600, number(data.get("client_config", {}).get("report_interval", 300))))
    alerts = data.get("security", {}).get("alerts", [])
    for c in data.get("containers", []):
        entity = identity(node, c.get("runtime", "podman"), c.get("project", ""), c.get("name", "unknown"))
        security = c.get('security') if isinstance(c.get('security'), dict) else {}
        _ingest_service_inventory(conn, entity, host_id, c.get('runtime', 'podman'), c.get('project', ''), c.get('name', 'unknown'), ts, security)
        row = conn.execute("SELECT ts,payload FROM ops_meter WHERE entity=?", (entity,)).fetchone()
        old = loads(row["payload"]) if row else {}
        elapsed = ts - row["ts"] if row else 0
        gap = int(bool(row) and elapsed > interval * 2.5)
        counters = c.get("traffic_counters") or {}
        counter_valid = counters.get("available") is True
        reset = bool(counter_valid and old.get("counter_valid") and (number(counters.get("rx")) < old.get("rx", 0) or number(counters.get("tx")) < old.get("tx", 0) or counters.get("epoch") != old.get("epoch")))
        covered = elapsed if row and not gap and not reset else 0
        estimated = int(bool(covered) and not (counter_valid and old.get("counter_valid")))
        if covered:
            rx = max(0, number(counters.get("rx")) - old.get("rx", 0)) if not estimated else number(c.get("net_rx_bps")) * elapsed
            tx = max(0, number(counters.get("tx")) - old.get("tx", 0)) if not estimated else number(c.get("net_tx_bps")) * elapsed
        else:
            rx = tx = 0
        # Split bytes at local midnight/hour boundaries instead of billing all to the last sample.
        for period, size in (("hour", 3600), ("day", 86400)):
            start = ts - covered
            pieces = []
            if covered:
                cursor = start
                while cursor < ts:
                    bucket = int((cursor + 28800) // size) * size - 28800
                    end = min(ts, bucket + size)
                    pieces.append((bucket, (end - cursor) / covered, end - cursor))
                    cursor = end
            else:
                pieces = [(int((ts + 28800) // size) * size - 28800, 1, 0)]
            for bucket, fraction, duration in pieces:
                conn.execute("""INSERT INTO ops_rollups VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(entity,period,bucket) DO UPDATE SET
                  samples=samples+excluded.samples,rx=rx+excluded.rx,tx=tx+excluded.tx,covered=covered+excluded.covered,
                  gaps=gaps+excluded.gaps,estimated=estimated+excluded.estimated,cpu_sum=cpu_sum+excluded.cpu_sum,
                  mem_sum=mem_sum+excluded.mem_sum,peak_connections=MAX(peak_connections,excluded.peak_connections)""",
                  (entity, period, bucket, 1, rx*fraction, tx*fraction, duration, gap + int(reset), estimated,
                   number(c.get("cpu_percent")), number(c.get("mem_percent")), int(number(c.get("conn_count")))))
        rules = policy(conn, entity)
        capacity, capacity_source = bandwidth_capacity(conn, host_id, c, entity, ts)
        bandwidth = bandwidth_sample(conn,entity,ts,c,old,covered,rx,tx,
                                     counter_valid and old.get('counter_valid') and not reset and not gap,
                                     capacity,capacity_source,rules)
        values = [number(c.get("net_rx_bps")), number(c.get("conn_count"))]
        history = [x for x in old.get("baseline", []) if ts-x[0] < 86400][-288:]
        medians = [statistics.median(x[i+1] for x in history) if history else 0 for i in range(2)]
        enough = len(history) >= 24 and ts-history[0][0] >= 3600
        sample_valid = counter_valid or (values[0]>0 and number(c.get("security",{}).get("process_count"))>0)
        abnormal = sample_valid and enough and all(values[i] > max(medians[i]*rules["baseline_factor"], rules[k]) for i,k in enumerate(("rx_bps", "connections")))
        streak = old.get("streak", 0)+1 if abnormal else 0
        anomaly = streak >= 3 and rules.get("silent_until", 0) < ts
        if not sample_valid:
            streak=old.get("streak",0)
            anomaly=bool(old.get("anomaly"))
        if sample_valid and not abnormal:
            history.append([ts, *values])
        if sample_valid and (anomaly or old.get("anomaly")):
            event(conn, entity, "baseline_anomaly", ts, {"values": values, "baseline": medians, "streak": streak,"severity":"critical"}, anomaly)
        state = {"counter_valid": counter_valid, "rx": number(counters.get("rx")), "tx": number(counters.get("tx")), "epoch": counters.get("epoch"), "baseline": history[-288:], "streak": streak, "anomaly": anomaly, "baseline_ready": enough, "gap": gap, "reset": bool(reset), "estimated": bool(estimated), "medians": medians}
        state['bandwidth'] = bandwidth
        conn.execute("INSERT INTO ops_meter VALUES(?,?,?,?,?,?,?) ON CONFLICT(entity) DO UPDATE SET host_id=excluded.host_id,ts=excluded.ts,payload=excluded.payload", (entity, host_id, c.get("runtime", "podman"), c.get("project", ""), c.get("name", "unknown"), ts, json.dumps(state)))
        for alert in alerts:
            if (alert.get("runtime"), alert.get("project", ""), alert.get("container_name")) == (c.get("runtime"), c.get("project", ""), c.get("name")):
                event(conn, entity, str(alert.get("type", "security")), ts, {"severity": alert.get("severity"), "message": str(alert.get("message", ""))[:500]})
        if data.get("security", {}).get("enabled") is True and number(c.get("security", {}).get("process_count")) > 0:
            recheck(conn, entity, c, alerts, ts)
        access = c.get("security", {}).get("access_log", {})
        signals = {"connections": values[1] >= rules["connections"], "rx_bps": values[0] >= rules["rx_bps"], "http_rps": number(access.get("requests_per_second")) >= rules["http_rps"]}
        if sample_valid:
            severe = values[1]>=rules["connections"]*2 or values[0]>=rules["rx_bps"]*2 or number(access.get("requests_per_second"))>=rules["http_rps"]*2
            event(conn, entity, "policy_signal", ts, {"signals": signals,"profile":rules["profile"],
                  "values":{"connections":values[1],"rx_bps":values[0],"http_rps":number(access.get('requests_per_second'))},
                  "thresholds":{k:rules[k] for k in ('connections','rx_bps','http_rps')},
                  "severity":"critical" if severe else "warning"}, any(signals.values()) and rules.get("silent_until",0)<ts)
        # Close only security episodes proven absent in a complete fresh scan.
        if number(c.get("security", {}).get("process_count")) > 0 and data.get("security", {}).get("enabled") is True:
            current={str(a.get("type")) for a in alerts if (a.get("runtime"),a.get("project",""),a.get("container_name")) == (c.get("runtime"),c.get("project",""),c.get("name"))}
            for episode in conn.execute("SELECT kind FROM ops_incidents WHERE entity=? AND status='open'",(entity,)).fetchall():
                if episode[0] not in {"remediation","baseline_anomaly","bandwidth_saturation","traffic_quota","policy_signal"} and episode[0] not in current:
                    event(conn,entity,episode[0],ts,{"reason":"新安全样本中已消失"},False)
        # Keep accounting/policy compatibility, but never emit quota notifications.
        event(conn, entity, 'traffic_quota', ts, {'reason':'流量额度提醒已停用'}, False)
    host_entity=identity(node)
    host_rules=policy(conn,host_entity)
    host_access=data.get("security",{}).get("access_log",{})
    host_http=number(host_access.get("requests_per_second"))
    if number(host_access.get("readable_files"))>0:
        event(conn,host_entity,"policy_signal",ts,{"signals":{"http_rps":host_http},"values":{"http_rps":host_http},"thresholds":{"http_rps":host_rules['http_rps']},"profile":host_rules["profile"],"severity":"critical" if host_http>=host_rules["http_rps"]*2 else "warning"},host_http>=host_rules["http_rps"] and host_rules.get("silent_until",0)<ts)
    for result in operations.get("services", [])[:50]:
        service = conn.execute("SELECT id FROM ops_services WHERE id=? AND host_id=? AND enabled=1", (result.get("id"), host_id)).fetchone()
        if service:
            conn.execute("INSERT INTO ops_service_results VALUES(?,?,?) ON CONFLICT(service_id) DO UPDATE SET ts=excluded.ts,payload=excluded.payload", (service[0], ts, json.dumps(result)))
            event(conn, identity(node), f"service:{service[0]}", ts, {**result,"severity":"critical" if result.get("status")=="failed" else "warning"}, result.get("status") != "healthy")
    for upgrade in conn.execute("SELECT n.*,u.version FROM ops_upgrade_nodes n JOIN ops_upgrades u ON u.id=n.campaign WHERE n.host_id=? AND n.status IN ('dispatched','failed')", (host_id,)).fetchall():
        healthy_scan, failed_sources = upgrade_health.check(operations, data)
        action=conn.execute('SELECT params_json,created_at FROM security_actions WHERE id=?',(upgrade['action_id'],)).fetchone()
        bound=action and loads(action['params_json']).get('expected_node_id')==node_id and ts>=action['created_at']
        if bound and data.get("agent_version") == upgrade["version"]:
            if healthy_scan:
                conn.execute("UPDATE ops_upgrade_nodes SET status='verified' WHERE campaign=? AND host_id=?", (upgrade["campaign"], host_id))
                conn.execute("UPDATE security_actions SET status='succeeded',result_message='target version reported with healthy checks',updated_at=? WHERE id=?", (ts, upgrade["action_id"]))
            else:
                reason = "升级后健康检查未通过：" + "、".join(dict.fromkeys(failed_sources))
                conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE campaign=? AND host_id=?", (upgrade["campaign"], host_id))
                conn.execute("UPDATE security_actions SET status='failed',result_message=?,updated_at=? WHERE id=?", (reason[:400], ts, upgrade["action_id"]))
                pause_upgrade_campaign_for_failure(
                    conn, upgrade["action_id"], host_id, ts, reason, "health_check"
                )
    result = operations.get("upgrade_result",{})
    # The previous Client may predate operations-v1, so its signed version report
    # (not a new operations payload) must be sufficient to confirm a rollback.
    for action in conn.execute("SELECT id,params_json FROM security_actions WHERE host_id=? AND action_type='managed_rollback' AND status IN ('running','dispatched')",(host_id,)).fetchall():
        params=loads(action["params_json"])
        if params.get("expected_node_id")==node_id and params.get("version")==data.get("agent_version"):
            conn.execute("UPDATE security_actions SET status='succeeded',result_message='previous version reported after rollback',updated_at=? WHERE id=?",(ts,action["id"]))
            if params.get("campaign_id"):
                conn.execute("UPDATE ops_upgrade_nodes SET status='rolled_back' WHERE campaign=? AND host_id=? AND status='rollback_queued'", (params["campaign_id"], host_id))
    if isinstance(result,dict) and result.get("action_id"):
        action = conn.execute("SELECT action_type,params_json,status FROM security_actions WHERE id=? AND host_id=?", (result["action_id"],host_id)).fetchone()
        if action and action[0] in {"managed_upgrade","managed_rollback"} and action[2] in {"running","dispatched"} and loads(action[1]).get("expected_node_id")==node_id:
            if result.get("status")=="failed":
                failure = str(result.get("message") or result.get("error") or "托管升级任务失败；请检查节点升级日志")
                failure = ''.join(ch for ch in failure if ch >= ' ' or ch == '\t')[:400]
                conn.execute("UPDATE security_actions SET status='failed',result_message=?,updated_at=? WHERE id=?",(failure,ts,result["action_id"]))
                if action[0] == "managed_upgrade":
                    conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE action_id=?",(result["action_id"],))
                    pause_upgrade_campaign_for_failure(
                        conn, result["action_id"], host_id, ts, failure, "install_failure"
                    )
                else:
                    params = loads(action[1])
                    if params.get("campaign_id"):
                        conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE campaign=? AND host_id=? AND status='rollback_queued'", (params["campaign_id"], host_id))
            elif action[0]=="managed_rollback" and result.get("status")=="installed" and result.get("version")==data.get("agent_version"):
                conn.execute("UPDATE security_actions SET status='succeeded',result_message='rollback version reported',updated_at=? WHERE id=?",(ts,result["action_id"]))
                params = loads(action[1])
                if params.get("campaign_id"):
                    conn.execute("UPDATE ops_upgrade_nodes SET status='rolled_back' WHERE campaign=? AND host_id=? AND status IN ('failed','verified','rollback_queued')", (params["campaign_id"], host_id))
    for campaign in conn.execute("SELECT id FROM ops_upgrades WHERE status IN ('canary','rollout')").fetchall():
        states=[r[0] for r in conn.execute("SELECT status FROM ops_upgrade_nodes WHERE campaign=?",(campaign[0],))]
        if states and all(s=="verified" for s in states):
            conn.execute("UPDATE ops_upgrades SET status='verified' WHERE id=?",(campaign[0],))
    generated=[]
    prefix=json.dumps([node],ensure_ascii=False,separators=(",",":"))[:-1]+","
    for row in conn.execute("SELECT * FROM ops_incidents WHERE status='open' AND substr(entity,1,?)=? AND (kind IN ('baseline_anomaly','bandwidth_saturation','policy_signal') OR kind LIKE 'service:%') ORDER BY last_seen DESC LIMIT 500",(len(prefix),prefix)).fetchall():
        parts=loads(row["entity"],[])
        if len(parts)!=4 or parts[0]!=node:
            continue
        payload=loads(row["payload"])
        payload.update(observed_at=row["last_seen"],data_stale=payload.get('data_stale',False) or ts-row["last_seen"]>interval*2.5)
        message = json.dumps(payload, ensure_ascii=False)[:1000]
        title = '运维信号：' + row['kind']
        if row['kind'] == 'policy_signal':
            labels = {'connections': 'socket 总数', 'rx_bps': '接收速率（B/s）', 'http_rps': 'HTTP 请求（次/秒）'}
            facts = [f"{labels[k]} {payload.get('values', {}).get(k, 0):g}，提醒门槛 {payload.get('thresholds', {}).get(k, 0):g}" for k in labels if payload.get('signals', {}).get(k)]
            title = '实例使用情况超出提醒范围'
            message = '；'.join(facts) + '。此策略用于提醒，自动停机由独立的连续超标保护规则决定。'
        generated.append({"runtime":parts[1],"project":parts[2],"container_name":parts[3],"type":"ops_"+row["kind"],"severity":payload.get("severity","warning"),"title":title,"message":message,"observation":payload,"data_stale":payload['data_stale'],"value":payload.get('rate_mbps',0),"threshold":payload.get('capacity_mbps',0)*payload.get('ratio',0)})
    return generated


def record_connection_guard(conn, action_id, ts):
    """Record the actual stop receipt, not a speculative queued stop."""
    row = conn.execute('SELECT * FROM security_actions WHERE id=?',(action_id,)).fetchone()
    if not row or row['action_type'] != 'stop_container' or row['status'] not in {'succeeded','failed'}:
        return
    params = loads(row['params_json'])
    if params.get('reason') != 'sustained_connection_overload':
        return
    fingerprint = 'connection-guard-action-' + str(action_id)
    details = {'observation':params, 'automatic_remediation': {'attempted':True,
        'succeeded':row['status']=='succeeded','action_type':'stop_container','message':row['result_message']}}
    conn.execute("INSERT OR IGNORE INTO security_alerts(fingerprint,host_id,runtime,project,container_name,alert_type,severity,title,message,value,threshold,first_seen,last_seen,status,details_json) VALUES(?,?,?,?,?,'ops_connection_guard','critical','连接保护处理回执',?,?,?,?,?,?,?)",
        (fingerprint,row['host_id'],row['runtime'],row['project'],row['container_name'],
         row['result_message'],number(params.get('connection_count')),number(params.get('threshold')),
         row['created_at'],ts,'remediated' if row['status']=='succeeded' else 'active',json.dumps(details)))
    alert = conn.execute('SELECT id FROM security_alerts WHERE fingerprint=?',(fingerprint,)).fetchone()
    conn.execute('UPDATE security_actions SET alert_id=? WHERE id=?',(alert[0],action_id))


def track_recheck(conn, action_id, ts):
    row = conn.execute("SELECT a.*,s.alert_type FROM security_actions a JOIN security_alerts s ON s.id=a.alert_id WHERE a.id=?", (action_id,)).fetchone()
    if not row or row["action_type"] not in {"remediate_panel_pairing", "remediate_malicious_process", "enforce_socks_auth", "stop_reviewed_socks"}:
        return
    host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (row["host_id"],)).fetchone()
    entity = identity((host[0] if host and host[0] else row["host_id"]), row["runtime"], row["project"], row["container_name"])
    conn.execute("INSERT OR IGNORE INTO ops_rechecks(action_id,entity,alert_type,status,ts,message) VALUES(?,?,?,'awaiting_report',?,'执行完成，等待两次新报告复查')", (action_id, entity, row["alert_type"], ts))
    event(conn, entity, "remediation", ts, {"action_id": action_id, "status": "awaiting_report"})


def recheck(conn, entity, container, alerts, ts):
    for row in conn.execute("SELECT * FROM ops_rechecks WHERE entity=? AND status IN ('awaiting_report','retrying') AND ts<?", (entity, ts)).fetchall():
        socks = container.get("security",{}).get("socks_proxy",{})
        if row["alert_type"] in {"socks_weak_auth", "socks_password_review"} and socks.get("detected") and socks.get("auth_mode") not in {"configured","no_auth","weak_password"}:
            # A still-present service with unknown authentication is not clean.
            conn.execute("UPDATE ops_rechecks SET clean_samples=0,message='SOCKS 仍存在，但认证采集证据不足' WHERE action_id=?",(row["action_id"],))
            continue
        failed = any((a.get("type"),a.get("runtime"),a.get("project", ""),a.get("container_name")) == (row["alert_type"],container.get("runtime"),container.get("project", ""),container.get("name")) for a in alerts)
        if row["status"] == "retrying":
            action = conn.execute("SELECT status FROM security_actions WHERE id=?", (row["action_id"],)).fetchone()
            if action and action[0] in ("queued", "dispatched", "running"):
                continue
            if action and action[0] == "failed":
                conn.execute("UPDATE ops_rechecks SET status='recurring',message='复查重试执行失败',ts=? WHERE action_id=?", (ts,row["action_id"]))
                continue
        clean = 0 if failed else row["clean_samples"] + 1
        status = "recurring" if failed and row["attempts"] >= 2 else "retrying" if failed else "verified" if clean >= 2 else "awaiting_report"
        attempts = row["attempts"] + int(status == "retrying")
        action = conn.execute('SELECT action_type FROM security_actions WHERE id=?', (row['action_id'],)).fetchone()
        if status == 'retrying' and action and action[0] == 'stop_reviewed_socks':
            status = 'recurring'  # One human approval is not permission for a later generation.
        if status == "retrying":
            # Original action retains server/agent safeguards; refresh PID at dispatch.
            conn.execute("UPDATE security_actions SET status='queued',attempts=0,updated_at=? WHERE id=? AND status IN ('succeeded','failed')", (ts, row["action_id"]))
        conn.execute("UPDATE ops_rechecks SET status=?,attempts=?,clean_samples=?,ts=?,message=? WHERE action_id=?", (status, attempts, clean, ts, "风险复发，已到重试上限" if status == "recurring" else status, row["action_id"]))
        event(conn, entity, "remediation", ts, {"action_id": row["action_id"], "status": status}, status != "verified")


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1).hex()
    return salt+":"+digest


def authenticate(conn, authorization):
    try:
        if not authorization.startswith("Basic "):
            return None
        name, password = base64.b64decode(authorization[6:], validate=True).decode().split(":", 1)
        row = conn.execute("SELECT * FROM ops_users WHERE username=? AND enabled=1", (name,)).fetchone()
        if row and hmac.compare_digest(password_hash(password, row["password_hash"].split(":")[0]), row["password_hash"]):
            return name, row["role"]
    except (ValueError, UnicodeError):
        pass
    return None


def permitted(role, method, path):
    if role == "admin":
        return True
    if path == "/api/v1/containers/user-note":
        return role == "operator" and method in {"GET", "HEAD", "POST"}
    # Personal settings are scoped to the authenticated identity inside commerce.
    if path in {"/api/v1/commerce/settings", "/api/v1/commerce/sync"}:
        return method in {"GET", "HEAD", "POST", "DELETE"}
    # These reads expose credentials/configuration even when the response is masked today.
    if any(path.startswith(p) for p in ("/api/v1/notifications", "/api/v1/settings", "/api/v1/buyer", "/api/v1/ops/users", "/api/v1/ops/backups", "/api/v1/ops/audit")):
        return False
    if method in ("GET", "HEAD"):
        return True
    if role != "operator":
        return False
    return ((path.startswith("/api/v1/containers/") or path.startswith("/api/v1/security/alerts/"))
            and (path.endswith("/diagnostics") or path.endswith("/disposition")
                 or path.endswith("/actions") or path.endswith('/notify-user'))
            or path == "/api/v1/ops/logs/discover")


def purge_host(conn,host_id):
    host=conn.execute("SELECT node_id FROM hosts WHERE host_id=?",(host_id,)).fetchone()
    node=(host[0] if host and host[0] else host_id)
    prefix=json.dumps([node],ensure_ascii=False,separators=(",",":"))[:-1]+","
    conn.execute("DELETE FROM ops_events WHERE incident_id IN (SELECT id FROM ops_incidents WHERE substr(entity,1,?)=?)",(len(prefix),prefix))
    for table in ("ops_meter","ops_rollups","ops_policies","ops_rechecks","ops_incidents"):
        conn.execute(f"DELETE FROM {table} WHERE substr(entity,1,?)=?",(len(prefix),prefix))
    conn.execute("DELETE FROM ops_hosts WHERE node=?",(node,))
    conn.execute('DELETE FROM ops_disk_cleanup_policies WHERE node=?',(node,))
    conn.execute('DELETE FROM ops_disk_cleanup_runs WHERE node=?',(node,))
    conn.execute("DELETE FROM ops_service_results WHERE service_id IN (SELECT id FROM ops_services WHERE host_id=?)",(host_id,))
    conn.execute("DELETE FROM ops_services WHERE host_id=?",(host_id,))
    conn.execute("DELETE FROM ops_service_inventory WHERE host_id=?",(host_id,))
    conn.execute("DELETE FROM ops_service_inventory_changes WHERE host_id=?",(host_id,))
    conn.execute("DELETE FROM ops_upgrade_nodes WHERE host_id=?",(host_id,))


def maintain(conn, now):
    for table, column, days in (("ops_rollups", "bucket", 400), ("ops_events", "ts", 90), ("ops_incidents", "last_seen", 90), ("ops_audit", "ts", 180), ("ops_rechecks", "ts", 90),('ops_disk_cleanup_runs','ts',30),('ops_service_inventory_changes','ts',90),('ops_backup_drills','started_at',180),('ops_alert_replays','created_at',90),('ops_alert_feedback','created_at',180)):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {column}<? LIMIT 5000)", (now-days*86400,))
    conn.execute("DELETE FROM ops_rollups WHERE rowid IN (SELECT rowid FROM ops_rollups WHERE period='hour' AND bucket<? LIMIT 5000)", (now-30*86400,))
    for table, cap in (("ops_rollups", 200000), ("ops_events", 20000), ("ops_incidents", 5000), ("ops_audit", 20000),('ops_disk_cleanup_runs',20000),('ops_service_inventory_changes',20000),('ops_service_inventory',100000),('ops_backup_drills',2000),('ops_alert_replays',5000),('ops_alert_feedback',20000)):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY rowid DESC LIMIT 5000 OFFSET ?)", (cap,))
    conn.execute("UPDATE ops_rechecks SET status='unverified',message='主机未上报，无法确认处置效果' WHERE status IN ('awaiting_report','retrying') AND ts<?", (now-3600,))
    conn.execute("UPDATE ops_upgrade_nodes SET status='failed' WHERE status='dispatched' AND action_id IN (SELECT id FROM security_actions WHERE status='failed' OR created_at<?)", (now-1800,))
    for table in ("ops_meter","ops_hosts"):
        conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE ts<? LIMIT 5000)",(now-90*86400,))
    conn.execute("DELETE FROM ops_service_results WHERE service_id NOT IN (SELECT id FROM ops_services)")
    conn.execute("DELETE FROM security_action_receipts WHERE action_id NOT IN (SELECT id FROM security_actions)")
    conn.commit()


def backup(database_path, retention=7):
    if not _backup_lock.acquire(False):
        raise ValueError("backup already running")
    target = None
    try:
        directory = Path(database_path).parent / "backups"
        directory.mkdir(mode=0o700, exist_ok=True)
        name = f"monitor-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(3)}.db"
        target = directory/name
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        source = sqlite3.connect(database_path, timeout=5)
        destination = sqlite3.connect(target)
        try:
            deadline = time.monotonic()+120
            def progress(status, remaining, total):
                if time.monotonic() > deadline:
                    raise TimeoutError("backup time budget exceeded")
            source.backup(destination, pages=256, progress=progress, sleep=.05)
            if destination.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("backup integrity check failed")
        finally:
            destination.close()
            source.close()
        digest = hashlib.sha256()
        with target.open("rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                digest.update(chunk)
        for old in sorted(directory.glob("monitor-*.db"), key=lambda x:x.stat().st_mtime, reverse=True)[max(1,min(30,retention)):]:
            old.unlink()
        return {"name": name, "bytes": target.stat().st_size, "sha256": digest.hexdigest(), "integrity": "ok"}
    except Exception:
        if target and target.exists():
            target.unlink()
        raise
    finally:
        _backup_lock.release()


def _restore_drill(backup_path, *, timeout_seconds=1800):
    """Copy one backup into an isolated directory and verify it can be reopened."""
    source_path = Path(backup_path).resolve(strict=True)
    started_at = int(time.time())
    started = time.monotonic()
    size = source_path.stat().st_size
    if not source_path.is_file() or size <= 0:
        return {"backup_name": source_path.name, "started_at": started_at, "finished_at": int(time.time()),
                "duration_ms": int((time.monotonic()-started)*1000), "status": "failed",
                "message": "backup file is empty or unavailable", "bytes": max(0, size), "sha256": "", "details": {}}
    scratch_root = Path(tempfile.gettempdir())
    reserve = max(64 * 1024 * 1024, size // 20)
    if shutil.disk_usage(scratch_root).free < size + reserve:
        return {"backup_name": source_path.name, "started_at": started_at, "finished_at": int(time.time()),
                "duration_ms": int((time.monotonic()-started)*1000), "status": "failed",
                "message": "临时目录剩余空间不足，未复制备份", "bytes": size, "sha256": "", "details": {}}
    digest = hashlib.sha256()
    try:
        with tempfile.TemporaryDirectory(prefix="narwhal-restore-drill-") as directory:
            restored = Path(directory) / "monitor.db"
            deadline = started + max(30, min(int(timeout_seconds), 1800))
            with source_path.open("rb") as source, restored.open("xb") as destination:
                os.chmod(restored, 0o600)
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("isolated restore copy exceeded the time budget")
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    destination.write(chunk)
                    digest.update(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            # Reopen the isolated copy read/write, as a restored server database
            # would be opened, while leaving the source backup untouched.
            conn = sqlite3.connect(restored, timeout=5)
            try:
                conn.execute("PRAGMA query_only=ON")
                conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
                result = conn.execute("PRAGMA integrity_check").fetchall()
                if len(result) != 1 or result[0][0] != "ok":
                    raise ValueError("isolated database integrity_check failed")
                tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                required = {"reports", "hosts", "security_alerts", "ops_settings"}
                missing = sorted(required - tables)
                if missing:
                    raise ValueError("backup is missing required tables: " + ", ".join(missing))
                foreign_key_errors = conn.execute("PRAGMA foreign_key_check").fetchmany(10)
                if foreign_key_errors:
                    raise ValueError("isolated database foreign_key_check found inconsistencies")
                row_counts = {table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                              for table in ("reports", "hosts", "security_alerts")}
            finally:
                conn.close()
            return {
                "backup_name": source_path.name, "started_at": started_at,
                "finished_at": int(time.time()), "duration_ms": int((time.monotonic() - started) * 1000),
                "status": "succeeded", "message": "备份已复制到隔离目录并重新打开；SQLite 完整性与核心表检查通过。",
                "bytes": size, "sha256": digest.hexdigest(), "details": {"row_counts": row_counts},
            }
    except Exception as exc:
        return {
            "backup_name": source_path.name, "started_at": started_at,
            "finished_at": int(time.time()), "duration_ms": int((time.monotonic() - started) * 1000),
            "status": "failed", "message": str(exc)[:400] or type(exc).__name__,
            "bytes": size, "sha256": digest.hexdigest(), "details": {},
        }


def restore_drill(backup_path, *, timeout_seconds=1800):
    if not _restore_drill_lock.acquire(False):
        raise RuntimeError("a backup restore drill is already running")
    try:
        return _restore_drill(backup_path, timeout_seconds=timeout_seconds)
    finally:
        _restore_drill_lock.release()


def record_backup_drill(conn, result):
    conn.execute(
        "INSERT INTO ops_backup_drills(backup_name,started_at,finished_at,duration_ms,status,message,bytes,sha256,details_json) VALUES(?,?,?,?,?,?,?,?,?)",
        (result["backup_name"], result["started_at"], result["finished_at"], result["duration_ms"],
         result["status"], result["message"], result["bytes"], result["sha256"],
         json.dumps(result.get("details") or {}, ensure_ascii=False)),
    )
    result["id"] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    return result
