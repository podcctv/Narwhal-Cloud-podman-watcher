"""Associate only complete upstream VM identities; never guess names or broadcast."""
import concurrent.futures
import json
import math
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid

TTL = 900
INTERVAL = 300
IDENTITY = ("host_id", "runtime", "project", "container_name")
_lock = threading.Lock()


def initialize(conn):
    columns = {r[1] for r in conn.execute("PRAGMA table_info(buyer_targets)")}
    for name, definition in (("source", "TEXT NOT NULL DEFAULT 'manual'"),
                             ("vm_id", "TEXT DEFAULT ''"), ("verified_at", "INTEGER DEFAULT 0"),
                             ("bandwidth_mbps", "REAL NOT NULL DEFAULT 0")):
        if name not in columns:
            conn.execute(f"ALTER TABLE buyer_targets ADD COLUMN {name} {definition}")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS buyer_mapping_status(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT);
    CREATE TABLE IF NOT EXISTS buyer_mapping_issues(
      host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,reason TEXT,updated_at INTEGER,
      PRIMARY KEY(host_id,runtime,project,container_name));
    """)


def status(conn):
    row = conn.execute("SELECT payload FROM buyer_mapping_status WHERE id=1").fetchone()
    return json.loads(row[0]) if row else {"status": "not_synced", "message": "尚未同步上游实例与买家"}


def identifier(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return ""


def fetch_catalog(cfg, validate_url, opener_factory):
    """Bounded complete pagination; retain no VM credentials, email or agent token."""
    base = validate_url(cfg["api_url"], resolve=True)
    deadline = time.monotonic() + 60
    budget = [0]
    budget_lock = threading.Lock()

    def get(path):
        with budget_lock:
            budget[0] += 1
            if budget[0] > 200 or time.monotonic() >= deadline:
                raise ValueError("上游列表超出同步预算，未应用任何关联")
        request = urllib.request.Request(base + path, headers={
            "Authorization": "Bearer " + cfg["api_key"], "Accept": "application/json",
            "User-Agent": "Narwhal-Monitor/" + os.getenv("NARWHAL_VERSION", "dev")})
        with opener_factory().open(request, timeout=10) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("上游响应过大，未应用任何关联")
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("success") is False or data.get("ok") is False or data.get("code", 0) not in (0, 200, "0", "200"):
            raise ValueError("上游响应未确认成功")
        return data.get("data", data)

    data = get("/machines")
    machines = data.get("machines") if isinstance(data, dict) else None
    if not isinstance(machines, list) or len(machines) > 100 or int(data.get("total", len(machines))) != len(machines):
        raise ValueError("机器列表不完整或超过一百台，未应用任何关联")
    machine_ids = [identifier(m.get("id")) for m in machines]
    if not all(machine_ids) or len(set(machine_ids)) != len(machine_ids):
        raise ValueError("机器身份无效或重复，未应用任何关联")

    def instances(machine):
        machine_id = identifier(machine.get("id"))
        result, total = [], None
        for page in range(1, 21):
            data = get(f"/machines/{machine_id}/vms?page={page}&page_size=100")
            if not isinstance(data, dict) or not isinstance(data.get("vms"), list):
                raise ValueError("实例分页格式无效")
            count = int(data.get("total", -1))
            if count < 0 or count > 2000 or (total is not None and total != count):
                raise ValueError("实例列表变化或不完整，稍后重试")
            total = count
            items = data["vms"]
            for item in items:
                if not isinstance(item, dict) or identifier(item.get("machine_id")) != machine_id:
                    raise ValueError("实例与来源机器不一致，未应用任何关联")
                result.append({"id": identifier(item.get("id")), "machine_id": machine_id,
                               "user_id": str(item.get("user_id") or ""),
                               "runtime": item.get("type"), "status": item.get("status"),
                               "node_name": str(machine.get("name") or "")[:100],
                               "bandwidth_mbps": capacity(item.get("bandwidth_mbps"))})
            if len(result) == total:
                return result
            if len(result) > total or not items:
                raise ValueError("实例分页不完整，未应用任何关联")
        raise ValueError("实例分页超过二十页，未应用任何关联")

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        groups = list(pool.map(instances, machines))
    catalog = [item for group in groups for item in group]
    if len(catalog) > 10000:
        raise ValueError("实例数量超出同步上限")
    return catalog, len(machines)


def capacity(value):
    try:
        n = float(value)
        return n if math.isfinite(n) and 0 < n <= 1_000_000 else 0
    except (TypeError, ValueError):
        return 0


def apply(conn, catalog, now):
    index = {}
    for vm in catalog:
        key = identifier(vm.get("id"))
        if key:
            index.setdefault(key, []).append(vm)
    identities = [dict(r) for r in conn.execute(
        "SELECT host_id,runtime,project,container_name,MAX(ts) AS last_seen FROM reports "
        "GROUP BY host_id,runtime,project,container_name HAVING MAX(ts)>=? AND MAX(ts)<=? LIMIT 2001", (now - TTL, now+60))]
    if len(identities) > 2000:
        raise ValueError("当前容器超过两千个，未应用任何关联")
    local = {}
    for row in identities:
        key = identifier(row["container_name"])
        if key:
            local.setdefault(key, []).append(row)
    conn.execute("DELETE FROM buyer_mapping_issues")
    counts = {"matched": 0, "unmatched": 0, "manual": 0, "deferred": 0}
    for row in identities:
        fields = tuple(row[k] for k in IDENTITY)
        old = conn.execute("SELECT * FROM buyer_targets WHERE host_id=? AND runtime=? AND project=? AND container_name=?", fields).fetchone()
        if old and old["source"] == "manual":
            counts["manual"] += 1
            continue  # Includes explicit manual disable / broadcast choices.
        key = identifier(row["container_name"])
        candidates = index.get(key, [])
        vm = candidates[0] if len(candidates) == 1 else None
        reason = ""
        if not key or row["runtime"] not in {"incus", "podman"}:
            reason = "非托管实例 UUID；请手工登记收件人"
        elif len(local.get(key, [])) != 1:
            reason = "同一实例 UUID 对应多个本地身份，拒绝自动关联"
        elif not candidates:
            reason = "上游找不到此实例（已删除或非托管）"
        elif len(candidates) != 1:
            reason = "上游实例 UUID 重复，拒绝自动关联"
        elif not identifier(vm.get("machine_id")) or vm.get("runtime") != row["runtime"]:
            reason = "上游机器或运行时身份不一致"
        elif not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", str(vm.get("user_id") or "")):
            reason = "上游实例没有有效买家 user_id"
        elif vm.get("status") not in {"running", "stopped", "error", "creating", "pending"}:
            reason = "上游实例已终止或状态无法确认"
        if conn.execute("SELECT 1 FROM buyer_outbox WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND status='sending' LIMIT 1", fields).fetchone():
            counts["deferred"] += 1
            continue  # Never change an in-flight recipient snapshot.
        if reason:
            conn.execute("INSERT INTO buyer_mapping_issues VALUES(?,?,?,?,?,?)", (*fields, reason, now))
            if old:
                conn.execute("UPDATE buyer_targets SET enabled=0 WHERE host_id=? AND runtime=? AND project=? AND container_name=?", fields)
            counts["unmatched"] += 1
            continue
        conn.execute("INSERT INTO buyer_targets(host_id,runtime,project,container_name,machine_id,user_id,node_name,scope,enabled,source,vm_id,verified_at) "
                     "VALUES(?,?,?,?,?,?,?,'user',1,'upstream',?,?) ON CONFLICT(host_id,runtime,project,container_name) DO UPDATE SET "
                     "machine_id=excluded.machine_id,user_id=excluded.user_id,node_name=excluded.node_name,scope='user',enabled=1,source='upstream',vm_id=excluded.vm_id,verified_at=excluded.verified_at",
                     (*fields, identifier(vm["machine_id"]), vm["user_id"], vm.get("node_name", ""), key, now))
        conn.execute("UPDATE buyer_targets SET bandwidth_mbps=? WHERE host_id=? AND runtime=? AND project=? AND container_name=?", (capacity(vm.get('bandwidth_mbps')), *fields))
        conn.execute("UPDATE buyer_outbox SET machine_id=?,user_id=?,scope='user',due_at=?,last_error='' WHERE host_id=? AND runtime=? AND project=? AND container_name=? AND status IN ('queued','retrying','blocked')",
                     (identifier(vm["machine_id"]), vm["user_id"], now, *fields))
        counts["matched"] += 1
    # Automatic associations are a bounded cache, not permanent tenant history.
    excess = max(0, conn.execute("SELECT COUNT(*) FROM buyer_targets WHERE source='upstream'").fetchone()[0]-10000)
    conn.execute("DELETE FROM buyer_targets WHERE rowid IN (SELECT t.rowid FROM buyer_targets t WHERE source='upstream' AND verified_at<? "
                 "AND NOT EXISTS(SELECT 1 FROM buyer_outbox o WHERE o.host_id=t.host_id AND o.runtime=t.runtime AND o.project=t.project AND o.container_name=t.container_name AND o.status='sending') "
                 "ORDER BY verified_at LIMIT ?)", (now-TTL, excess))
    conn.execute("DELETE FROM buyer_targets WHERE rowid IN (SELECT rowid FROM buyer_targets WHERE source='upstream' AND verified_at<? LIMIT 500)", (now-7*86400,))
    return counts


def sync(db, cfg, validate_url, opener_factory, force=False, fetcher=None, now=None):
    now = int(time.time()) if now is None else now
    if not _lock.acquire(blocking=False):
        return {"status": "busy", "message": "已有映射同步正在执行"}
    conn = db()
    try:
        previous = status(conn)
        if not force and now - int(previous.get("attempted_at", 0)) < INTERVAL:
            return previous
        if not cfg.get("api_key"):
            result = {"status": "error", "message": "API 密钥未配置", "attempted_at": now}
        else:
            try:
                catalog, machines = (fetcher or fetch_catalog)(cfg, validate_url, opener_factory)
                conn.execute("BEGIN IMMEDIATE")
                # The API configuration may have changed during the bounded fetch.
                settings = dict(conn.execute("SELECT key,value FROM system_settings WHERE key IN ('narwhal_api_url','narwhal_api_key')"))
                for key in ("api_url", "api_key"):
                    actual = settings.get("narwhal_" + key, cfg[key])
                    if (actual.rstrip("/") if key=="api_url" else actual) != cfg[key]:
                        raise ValueError("API 配置已变化，未应用本次关联")
                result = {"status": "ok", "message": "已按唯一实例 UUID 关联指定买家，无整机广播",
                          "attempted_at": now, "verified_at": now, "machines": machines, "instances": len(catalog), **apply(conn, catalog, now)}
            except Exception as exc:
                conn.rollback()
                message = "上游列表校验失败，未应用任何关联" if isinstance(exc, ValueError) else f"上游 HTTP {exc.code}" if hasattr(exc, "code") else "上游同步失败；原关联未续期，不猜测收件人"
                result = {"status": "error", "message": message[:200], "attempted_at": now,
                          "verified_at": previous.get("verified_at", 0)}
        conn.execute("INSERT INTO buyer_mapping_status VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (json.dumps(result, ensure_ascii=False),))
        conn.commit()
        return result
    finally:
        conn.close()
        _lock.release()
