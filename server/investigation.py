"""Bounded incident history and event-time tenant attribution for investigations.

Never backfill ownership from today's buyer cache or count polling hits as incidents.
Only allowlisted evidence is retained; raw configs/credentials are not copied.
"""
import hashlib
import json
import math
import re
from datetime import datetime, timedelta, timezone

try:
    from . import buyer_content, buyer_notifications
except ImportError:
    import buyer_content
    import buyer_notifications

RETENTION_DAYS = 90
INCIDENT_CAP = 20000
OBSERVATION_CAP = 100000
TRANSITION_CAP = 60000
IDENTITY = ("runtime", "project", "container_name")
UTC8 = timezone(timedelta(hours=8))


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS investigation_hosts(
      host_key TEXT PRIMARY KEY,host_id TEXT NOT NULL,first_sample INTEGER,last_sample INTEGER);
    CREATE TABLE IF NOT EXISTS investigation_observations(
      identity_key TEXT,user_id TEXT,day TEXT,host_key TEXT,host_id TEXT,runtime TEXT,
      project TEXT,container_name TEXT,first_sample INTEGER,last_sample INTEGER,
      assessed INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(identity_key,user_id,day));
    CREATE INDEX IF NOT EXISTS idx_investigation_observed ON investigation_observations(host_id,last_sample);
    CREATE TABLE IF NOT EXISTS investigation_incidents(
      id INTEGER PRIMARY KEY,alert_id INTEGER,episode INTEGER,identity_key TEXT,host_key TEXT,
      host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,user_id TEXT,machine_id TEXT,
      alert_type TEXT,severity TEXT,title TEXT,category TEXT,status TEXT,state TEXT,
      first_seen INTEGER,last_anomaly INTEGER,recorded_from INTEGER,updated_at INTEGER,
      legacy INTEGER,value REAL,threshold REAL,initial_value REAL,initial_threshold REAL,
      evidence_json TEXT,action_json TEXT,
      UNIQUE(alert_id,episode,identity_key));
    CREATE INDEX IF NOT EXISTS idx_investigation_incidents_scope ON investigation_incidents(host_id,last_anomaly);
    CREATE TABLE IF NOT EXISTS investigation_transitions(
      id INTEGER PRIMARY KEY,incident_id INTEGER,ts INTEGER,status TEXT,state TEXT,severity TEXT,
      value REAL,threshold REAL,evidence_json TEXT,action_json TEXT);
    CREATE INDEX IF NOT EXISTS idx_investigation_transitions ON investigation_transitions(incident_id,id);
    CREATE TABLE IF NOT EXISTS investigation_storage(id INTEGER PRIMARY KEY CHECK(id=1),trimmed_through INTEGER DEFAULT 0);
    INSERT OR IGNORE INTO investigation_storage(id) VALUES(1);
    """)


def _owner(conn, host, identity, ts):
    row = buyer_notifications.target(conn, {"host_id": host, **identity}, ts)
    if row and row["scope"] == "user" and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row["user_id"] or ""):
        # Future-dated mappings do not establish ownership at an earlier report.
        if row["source"] == "manual" or row["verified_at"] <= ts + 60:
            return row["user_id"], row["machine_id"]
    return "", ""


def _key(host_key, identity, container=None):
    container = container or {}
    material = [host_key, *(identity[k] for k in IDENTITY),
                str(container.get("id") or identity["container_name"]),
                str(container.get("created_at") or "")]
    return hashlib.sha256(json.dumps(material, ensure_ascii=False).encode()).hexdigest()


def category(kind):
    if kind in {"socks_weak_auth", "unauthorized_panel_pairing", "malicious_process", "container_security_risk"}:
        return "security"
    if kind == 'socks_auth_unknown':
        return 'security_attention'
    if kind.startswith('outbound_') or kind in {'udp_outbound_flood', 'process_fanout_abuse'}:
        return 'network_signal'
    if kind in {'web_scan', 'port_scan'} or any(word in kind.lower() for word in ("ddos", "http", "syn", "cc_")):
        return "external_signal"
    return "operational"


def _evidence(alert):
    raw = buyer_content.loads(alert["details_json"])
    # Keep useful scalar facts and exact process/listener association, never raw configuration.
    result = {}
    observation = raw.get('observation') if isinstance(raw.get('observation'), dict) else {}
    for k in ("auth_mode", "duration_seconds", "duration_verified", "sample_count", "max_gap_seconds"):
        v = raw.get(k, observation.get(k))
        if isinstance(v, (str, bool, int, float)):
            if isinstance(v, float) and not math.isfinite(v):
                continue
            result[k] = buyer_content.clean(v, 120) if isinstance(v, str) else v
    result["service_listeners"] = [
        {k: buyer_content.clean(item.get(k), 100) for k in ("process", "local", "pid")}
        for item in raw.get("service_listeners", [])[:8] if isinstance(item, dict)
    ] if isinstance(raw.get("service_listeners"), list) else []
    for k in ("process_names", "process_patterns", "unapproved_domains"):
        if isinstance(raw.get(k), list):
            result[k] = [buyer_content.clean(v, 100) for v in raw[k][:8] if isinstance(v, str)]
    auto = raw.get("automatic_remediation")
    if isinstance(auto, dict):
        result["automatic_remediation"] = {"attempted": auto.get("attempted") is True,
                                           "succeeded": auto.get("succeeded") is True,
                                           "items": buyer_content.receipt_items(auto.get("items"))}
    return json.dumps(result, ensure_ascii=False, allow_nan=False)


def _action(conn, alert):
    row = conn.execute("SELECT id,action_type,status,updated_at FROM security_actions WHERE alert_id=? "
                       "AND created_at>=? AND action_type IN ('enforce_socks_auth','remediate_panel_pairing',"
                       "'remediate_malicious_process','stop_container','apply_udp_throttle','release_udp_throttle',"
                       "'release_socks_auth','allow_panel_domains','disallow_panel_domains') ORDER BY id DESC LIMIT 1",
                       (alert["id"], alert["first_seen"])).fetchone()
    if not row:
        return "{}"
    result = dict(row)
    receipt = conn.execute("SELECT payload FROM security_action_receipts WHERE action_id=?", (row["id"],)).fetchone()
    try:
        result["items"] = buyer_content.receipt_items(json.loads(receipt[0])) if receipt else []
    except (TypeError, ValueError):
        result["items"] = []
    return json.dumps(result, ensure_ascii=False)


def sync_states(conn, host, ts, containers=None, present=None, host_key=None, alert_id=None):
    """Record incident boundaries and status transitions; keep original owner immutable."""
    containers = containers or []
    lookup = {(c.get("runtime", "podman"), c.get("project", ""), c.get("name")): c for c in containers}
    host_row = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host,)).fetchone()
    host_key = host_key or (host_row[0] if host_row and host_row[0] else "host:" + host)
    incident_count = conn.execute("SELECT COUNT(*) FROM investigation_incidents").fetchone()[0]
    transition_count = conn.execute("SELECT COUNT(*) FROM investigation_transitions").fetchone()[0]
    # Explicit action callbacks may arrive after a node has been offline for days.
    # Scope those to the exact alert instead of applying the live-sampling cutoff.
    predicate, params = ("id=?", (host, alert_id)) if alert_id is not None else ("last_seen>=?", (host, ts - 86400))
    for alert in conn.execute(f"SELECT * FROM security_alerts WHERE host_id=? AND {predicate}", params).fetchall():
        if alert["alert_type"] == "ops_traffic_quota":
            continue
        identity = {k: alert[k] for k in IDENTITY}
        c = lookup.get(tuple(identity[k] for k in IDENTITY))
        # Use the persisted generation for action callbacks without a container sample.
        old = conn.execute("SELECT * FROM investigation_incidents WHERE alert_id=? AND episode=? "
                           "AND host_key=? ORDER BY id DESC LIMIT 1", (alert["id"], alert["first_seen"], host_key)).fetchone()
        key = _key(host_key, identity, c) if c is not None or not old else old["identity_key"]
        if old and old["identity_key"] != key:
            old = None  # A recreated container must not inherit the old generation's history.
        if old and ts < old["updated_at"]:
            continue
        state = buyer_notifications.current_state(conn, alert)
        evidence, action = _evidence(alert), _action(conn, alert)
        if state == 'awaiting_report' and alert['status'] != 'remediated' and json.loads(action).get('status') != 'succeeded':
            state = 'awaiting_verification'  # A clean sample alone does not mean a stop was executed.
        hit = present is not None and alert["fingerprint"] in present
        if not old:
            if incident_count >= INCIDENT_CAP:
                conn.execute("UPDATE investigation_storage SET trimmed_through=MAX(trimmed_through,?) WHERE id=1", (ts,))
                continue  # Never allow ingestion to outgrow a slower cleanup worker.
            # Legacy first_seen is not evidence that today's owner owned the instance then.
            legacy = int(alert["first_seen"] < ts)
            owner, machine = _owner(conn, host, identity, ts) if not legacy and c is not None else ("", "")
            cur = conn.execute("INSERT OR IGNORE INTO investigation_incidents "
                "(alert_id,episode,identity_key,host_key,host_id,runtime,project,container_name,user_id,machine_id,"
                "alert_type,severity,title,category,status,state,first_seen,last_anomaly,recorded_from,updated_at,"
                "legacy,value,threshold,initial_value,initial_threshold,evidence_json,action_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert["id"], alert["first_seen"], key, host_key, host, *(identity[k] for k in IDENTITY),
                 owner, machine, alert["alert_type"], alert["severity"], buyer_content.clean(alert["title"], 200),
                 category(alert["alert_type"]), alert["status"], state, alert["first_seen"],
                 ts if hit else alert["first_seen"], ts, ts, legacy, alert["value"], alert["threshold"],
                 alert["value"], alert["threshold"], evidence, action))
            if not cur.rowcount:
                continue
            incident_id = cur.lastrowid
            incident_count += 1
            changed = True
        else:
            incident_id = old["id"]
            changed = (old["status"], old["state"], old["severity"], old["action_json"], old['threshold']) != (alert["status"], state, alert["severity"], action, alert['threshold'])
            conn.execute("UPDATE investigation_incidents SET status=?,state=?,severity=?,value=?,threshold=?,"
                         "evidence_json=?,action_json=?,updated_at=?,last_anomaly=CASE WHEN ? THEN ? ELSE last_anomaly END WHERE id=?",
                         (alert["status"], state, alert["severity"], alert["value"], alert["threshold"], evidence,
                          action, ts, hit, ts, incident_id))
        if changed and transition_count >= TRANSITION_CAP:
            conn.execute("UPDATE investigation_storage SET trimmed_through=MAX(trimmed_through,?) WHERE id=1", (ts,))
        elif changed:
            conn.execute("INSERT INTO investigation_transitions(incident_id,ts,status,state,severity,value,threshold,evidence_json,action_json) VALUES(?,?,?,?,?,?,?,?,?)",
                         (incident_id, ts, alert["status"], state, alert["severity"], alert["value"], alert["threshold"], evidence, action))
            transition_count += 1
            # Retain first transition and the last nineteen, not unlimited flapping.
            conn.execute("DELETE FROM investigation_transitions WHERE incident_id=? AND id NOT IN "
                         "(SELECT id FROM investigation_transitions WHERE incident_id=? ORDER BY id DESC LIMIT 19) "
                         "AND id<>(SELECT MIN(id) FROM investigation_transitions WHERE incident_id=?)",
                         (incident_id, incident_id, incident_id))


def observe(conn, host, node, ts, containers, fingerprints):
    host_key = node or "host:" + host
    old = conn.execute("SELECT last_sample FROM investigation_hosts WHERE host_key=?", (host_key,)).fetchone()
    if old and ts <= old[0]:
        return
    day = datetime.fromtimestamp(ts, UTC8).date().isoformat()
    conn.execute("INSERT INTO investigation_hosts VALUES(?,?,?,?) ON CONFLICT(host_key) DO UPDATE SET "
                 "host_id=excluded.host_id,last_sample=excluded.last_sample", (host_key, host, ts, ts))
    observation_count = conn.execute("SELECT COUNT(*) FROM investigation_observations").fetchone()[0]
    for c in containers:
        identity = {"runtime": str(c.get("runtime") or "podman"), "project": str(c.get("project") or ""),
                    "container_name": str(c.get("name") or "")}
        if not identity["container_name"]:
            continue
        owner, _ = _owner(conn, host, identity, ts)
        key = _key(host_key, identity, c)
        exists = conn.execute("SELECT 1 FROM investigation_observations WHERE identity_key=? AND user_id=? AND day=?", (key, owner, day)).fetchone()
        if not exists and observation_count >= OBSERVATION_CAP:
            conn.execute("UPDATE investigation_storage SET trimmed_through=MAX(trimmed_through,?) WHERE id=1", (ts,))
            continue
        conn.execute("INSERT INTO investigation_observations VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(identity_key,user_id,day) "
                     "DO UPDATE SET last_sample=MAX(last_sample,excluded.last_sample),assessed=MAX(assessed,excluded.assessed)",
                     (key, owner, day, host_key, host, *(identity[k] for k in IDENTITY), ts, ts, fingerprints is not None))
        observation_count += not bool(exists)
    if fingerprints is not None:
        sync_states(conn, host, ts, containers, fingerprints, host_key)


def maintain(conn, now):
    """Age and hard row caps, bounded batches; independent of raw-report retention."""
    cutoff = now - RETENTION_DAYS * 86400
    def prune(table, column, predicate, params):
        rows = conn.execute(f"SELECT rowid,{column} FROM {table} WHERE {predicate} ORDER BY {column},rowid LIMIT 2000", params).fetchall()
        if rows:
            conn.execute(f"DELETE FROM {table} WHERE rowid IN ({','.join('?' for _ in rows)})", [r[0] for r in rows])
            conn.execute("UPDATE investigation_storage SET trimmed_through=MAX(trimmed_through,?) WHERE id=1", (max(r[1] for r in rows),))
    for table, cap, column in (("investigation_incidents", INCIDENT_CAP, "last_anomaly"),
                               ("investigation_observations", OBSERVATION_CAP, "last_sample")):
        prune(table, column, f"{column}<?", (cutoff,))
        excess = max(0, conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] - cap)
        if excess:
            # Avoid deleting more than the current excess, in bounded batches.
            prune(table, column, f"rowid IN (SELECT rowid FROM {table} ORDER BY {column},rowid LIMIT ?)", (min(excess, 2000),))
    conn.execute("DELETE FROM investigation_transitions WHERE id IN (SELECT t.id FROM investigation_transitions t "
                 "WHERE NOT EXISTS(SELECT 1 FROM investigation_incidents i WHERE i.id=t.incident_id) LIMIT 40000)")
    excess = max(0, conn.execute("SELECT COUNT(*) FROM investigation_transitions").fetchone()[0] - TRANSITION_CAP)
    if excess:
        prune("investigation_transitions", "ts", "id IN (SELECT id FROM investigation_transitions ORDER BY id LIMIT ?)", (min(excess, 2000),))
    conn.execute("DELETE FROM investigation_hosts WHERE last_sample<?", (cutoff,))


def rename_host(conn, old, new):
    for table in ("investigation_hosts", "investigation_observations", "investigation_incidents"):
        conn.execute(f"UPDATE {table} SET host_id=? WHERE host_id=?", (new, old))


def purge_host(conn, host):
    conn.execute("DELETE FROM investigation_transitions WHERE incident_id IN (SELECT id FROM investigation_incidents WHERE host_id=?)", (host,))
    for table in ('investigation_incidents', 'investigation_observations', 'investigation_hosts'):
        conn.execute(f"DELETE FROM {table} WHERE host_id=?", (host,))


def _items(rows):
    items = []
    for row in rows:
        item = dict(row)
        for key in ('value', 'threshold', 'initial_value', 'initial_threshold'):
            if isinstance(item.get(key), float) and not math.isfinite(item[key]):
                item[key] = None
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["action"] = json.loads(item.pop("action_json"))
        items.append(item)
    return items


def overview(conn, host, start, end, query="", user=None, identity_key="", offset=0, limit=30):
    """All totals use the same host/window; unknown owners stay a separate bucket."""
    scope, params = "last_sample>=? AND first_sample<=?", [start, end]
    incident_scope, incident_params = "last_anomaly>=? AND recorded_from<=?", [start, end]
    if host:
        scope += " AND host_id=?"
        incident_scope += " AND host_id=?"
        params.append(host)
        incident_params.append(host)
    observations = [dict(r) for r in conn.execute(f"SELECT * FROM investigation_observations WHERE {scope}", params)]
    columns = "id,identity_key,user_id,container_name,title,status,state,category,legacy"
    incidents = [dict(r) for r in conn.execute(f"SELECT {columns} FROM investigation_incidents WHERE {incident_scope} ORDER BY last_anomaly DESC,id DESC", incident_params)]
    groups = {}
    def group(owner):
        return groups.setdefault(owner, {"user_id": owner, "observed": set(), "assessed": set(), "affected": set(), "episodes": 0,
                                         "pending": 0, "security": 0, "signals": 0, "legacy": 0})
    for row in observations:
        group(row["user_id"])["observed"].add(row["identity_key"])
        if row['assessed']:
            group(row["user_id"])["assessed"].add(row["identity_key"])
    container_incidents = [i for i in incidents if i["container_name"]]
    public = [i for i in incidents if not i["container_name"]]
    for item in container_incidents:
        g = group(item["user_id"])
        # Allowed/ignored and external victim signals remain visible, not violations.
        if item["status"] not in {"suppressed", "dismissed"}:
            g["affected"].add(item["identity_key"])
            g["episodes"] += not item["legacy"]
            g["legacy"] += item["legacy"]
            g["pending"] += item["state"] not in {"verified", "resolved", "suppressed"}
            g["security"] += item["category"] == "security"
            g["signals"] += item["category"] == "external_signal"
    affected = set().union(*(g["affected"] for g in groups.values())) if groups else set()
    known = set().union(*(g["affected"] for k, g in groups.items() if k)) if any(groups) else set()
    unknown = groups.get("", {}).get("affected", set())
    users = []
    for owner, g in groups.items():
        denominator = len(g["observed"] | g["affected"])
        unassessed = len(g["observed"] - g["assessed"] - g["affected"])
        users.append({**{k: v for k, v in g.items() if k not in {"observed", "affected", "assessed"}},
                      "observed": denominator, "affected": len(g["affected"]),
                      "unassessed": unassessed,
                      "rate": round(100 * len(g["affected"]) / denominator, 1) if owner and denominator and not unassessed else None,
                      "share": round(100 * len(g["affected"]) / len(known), 1) if owner and known else None})
    users.sort(key=lambda g: (not bool(g["user_id"]), -g["affected"], -g["pending"], g["user_id"]))
    concentration = next((g for g in users if g['user_id'] and g['affected']), None)
    q = query.strip().casefold()
    if q:
        matched = {i["user_id"] for i in container_incidents if q in i["container_name"].casefold() or q in i["title"].casefold()}
        matched.update(o["user_id"] for o in observations if q in o["container_name"].casefold())
        users = [g for g in users if q in g["user_id"].casefold() or g["user_id"] in matched or (not g["user_id"] and q in "未知归属")]
    visible = [i for i in container_incidents if user is None or i["user_id"] == user]
    if identity_key:
        visible = [i for i in visible if i["identity_key"] == identity_key]
    if q:
        visible = [i for i in visible if q in (i["user_id"] + " " + i["container_name"] + " " + i["title"]).casefold()]
    def hydrate(items):
        return [_items(conn.execute("SELECT * FROM investigation_incidents WHERE id=?", (i["id"],)))[0] for i in items]
    details = hydrate(visible[offset:offset + limit])
    for item in details:
        item["transitions"] = _items(conn.execute("SELECT ts,status,state,severity,value,threshold,evidence_json,action_json FROM investigation_transitions WHERE incident_id=? ORDER BY id", (item["id"],)))
    hosts = [dict(r) for r in conn.execute("SELECT host_id,MIN(first_sample) AS first_sample,MAX(last_sample) AS last_sample FROM investigation_hosts GROUP BY host_id ORDER BY host_id")]
    earliest = min((o["first_sample"] for o in observations), default=None)
    trimmed = conn.execute("SELECT trimmed_through FROM investigation_storage WHERE id=1").fetchone()[0]
    return {"hosts": hosts, "users": users, "concentration": concentration, "items": details, "total": len(visible), "offset": offset,
            "public_items": hydrate(public[:10]), "public_total": len(public),
            "summary": {"observed": len({o["identity_key"] for o in observations} | affected), "affected": len(affected),
                        "users": sum(bool(k) and bool(g["affected"]) for k, g in groups.items()),
                        "unknown": len(unknown), "attributed": len(known), "legacy": sum(i["legacy"] for i in incidents)},
            "coverage": {"from": earliest, "retention_days": RETENTION_DAYS,
                         "complete_window": earliest is not None and earliest <= start and trimmed < start,
                         "note": "历史保留90天，并受事件/观测/状态记录上限约束。仅统计已观测记录；归属转移可能使同一容器出现在多个用户下。旧告警不补猜历史用户；外部攻击信号不是用户违规。"}}
