"""Associate only complete upstream VM identities; never guess names or broadcast."""
from contextlib import closing
import concurrent.futures
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import uuid

TTL = 900
INTERVAL = 180
IDENTITY = ("host_id", "runtime", "project", "container_name")
_lock = threading.Lock()


def initialize(conn):
    columns = {r[1] for r in conn.execute("PRAGMA table_info(buyer_targets)")}
    for name, definition in (("source", "TEXT NOT NULL DEFAULT 'manual'"),
                             ("vm_id", "TEXT DEFAULT ''"), ("verified_at", "INTEGER DEFAULT 0"),
                             ("bandwidth_mbps", "REAL NOT NULL DEFAULT 0"),
                             ("user_email", "TEXT NOT NULL DEFAULT ''"),
                             ("user_name", "TEXT NOT NULL DEFAULT ''")):
        if name not in columns:
            conn.execute(f"ALTER TABLE buyer_targets ADD COLUMN {name} {definition}")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS buyer_mapping_status(id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT);
    CREATE TABLE IF NOT EXISTS buyer_mapping_issues(
      host_id TEXT,runtime TEXT,project TEXT,container_name TEXT,reason TEXT,updated_at INTEGER,
      PRIMARY KEY(host_id,runtime,project,container_name));
    CREATE TABLE IF NOT EXISTS buyer_user_directory(
      user_id TEXT PRIMARY KEY,
      user_email TEXT NOT NULL DEFAULT '',
      user_name TEXT NOT NULL DEFAULT '',
      updated_at INTEGER NOT NULL DEFAULT 0);
    """)
    conn.execute("""
    INSERT INTO buyer_user_directory(user_id,user_email,user_name,updated_at)
    SELECT user_id,MAX(user_email),MAX(user_name),MAX(verified_at)
    FROM buyer_targets WHERE user_id<>'' AND (user_email<>'' OR user_name<>'')
    GROUP BY user_id
    ON CONFLICT(user_id) DO UPDATE SET
      user_email=CASE WHEN excluded.user_email<>'' THEN excluded.user_email ELSE buyer_user_directory.user_email END,
      user_name=CASE WHEN excluded.user_name<>'' THEN excluded.user_name ELSE buyer_user_directory.user_name END,
      updated_at=MAX(buyer_user_directory.updated_at,excluded.updated_at)
    """)
    try:
        db_list = conn.execute("PRAGMA database_list").fetchall()
        main_db = next((str(r[2] or "") for r in db_list if str(r[1] or "") == "main"), "")
        if main_db and main_db not in {":memory:", ""}:
            backup_dir = Path(main_db).resolve().parent / "backups"
            if backup_dir.is_dir():
                for bpath in sorted(backup_dir.glob("monitor*.db"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]:
                    try:
                        with closing(sqlite3.connect(str(bpath))) as bconn:
                            bcols = {r[1] for r in bconn.execute("PRAGMA table_info(buyer_targets)")}
                            if "user_email" not in bcols:
                                continue
                            uname_expr = "user_name" if "user_name" in bcols else "''"
                            brows = bconn.execute(
                                f"SELECT user_id,MAX(user_email),MAX({uname_expr}),MAX(verified_at) "
                                "FROM buyer_targets WHERE user_id<>'' AND user_email<>'' GROUP BY user_id"
                            ).fetchall()
                            for uid, uemail, uname, uts in brows:
                                record_user_email(conn, uid, uemail, uname, int(uts or 0))
                    except Exception:
                        continue
    except Exception:
        pass
    conn.execute("""
    UPDATE buyer_targets
    SET user_email=COALESCE(
      (SELECT d.user_email FROM buyer_user_directory d WHERE d.user_id=buyer_targets.user_id AND d.user_email<>''),
      buyer_targets.user_email
    )
    WHERE (user_email='' OR user_email IS NULL) AND user_id<>''
    """)


def record_user_email(conn, user_id, user_email="", user_name="", now=None):
    uid = str(user_id or "").strip()
    if not uid or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", uid):
        return
    email = normalize_email(user_email)
    uname = str(user_name or "").strip()[:128]
    if not email and not uname:
        return
    ts = int(time.time()) if now is None else int(now)
    conn.execute(
        "INSERT INTO buyer_user_directory(user_id,user_email,user_name,updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET "
        "user_email=CASE WHEN excluded.user_email<>'' THEN excluded.user_email ELSE buyer_user_directory.user_email END,"
        "user_name=CASE WHEN excluded.user_name<>'' THEN excluded.user_name ELSE buyer_user_directory.user_name END,"
        "updated_at=MAX(buyer_user_directory.updated_at,excluded.updated_at)",
        (uid, email, uname, ts),
    )
    if email:
        conn.execute(
            "UPDATE buyer_targets SET user_email=? WHERE user_id=? AND (user_email='' OR user_email IS NULL)",
            (email, uid),
        )


def needs_urgent_sync(conn, now=None):
    now = int(time.time()) if now is None else int(now)
    prev = status(conn)
    last_attempted = int(prev.get("attempted_at", 0) or 0)
    if now - last_attempted < 30:
        return False
    rows = conn.execute(
        "SELECT host_id,runtime,project,container_name FROM reports "
        "WHERE runtime IN ('incus','podman','runman') "
        "GROUP BY host_id,runtime,project,container_name HAVING MAX(ts)>=? LIMIT 500",
        (now - TTL,),
    ).fetchall()
    for r in rows:
        if not identifier(r[3]):
            continue
        mapped = conn.execute(
            "SELECT verified_at,enabled FROM buyer_targets WHERE host_id=? AND runtime=? AND project=? AND container_name=?",
            (r[0], r[1], r[2], r[3]),
        ).fetchone()
        if mapped and int(mapped[1] or 0) and int(mapped[0] or 0) >= now - TTL:
            continue
        issue = conn.execute(
            "SELECT updated_at FROM buyer_mapping_issues WHERE host_id=? AND runtime=? AND project=? AND container_name=?",
            (r[0], r[1], r[2], r[3]),
        ).fetchone()
        if issue and int(issue[0] or 0) >= last_attempted:
            continue
        return True
    return False


def status(conn):
    row = conn.execute("SELECT payload FROM buyer_mapping_status WHERE id=1").fetchone()
    return json.loads(row[0]) if row else {"status": "not_synced", "message": "尚未同步上游实例与买家"}


def identifier(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return ""


def _runtime_compatible(upstream_rt, local_rt):
    if not upstream_rt or upstream_rt == local_rt:
        return True
    u = str(upstream_rt).strip().lower()
    l = str(local_rt).strip().lower()
    if u == l:
        return True
    # runman manages both incus and podman containers locally
    if "runman" in (u, l) and (u in ("incus", "podman", "container", "runman") and l in ("incus", "podman", "container", "runman")):
        return True
    # generic container from upstream matches any container runtime
    if "container" in (u, l) and (u in ("incus", "podman", "runman", "container") and l in ("incus", "podman", "runman", "container")):
        return True
    return False


def normalize_email(value):
    email = str(value or "").strip()
    if len(email) > 254 or not re.fullmatch(r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+", email):
        return ""
    return email


def fetch_catalog(cfg, validate_url, opener_factory):
    """Fetch complete, bounded VM mappings; retain no VM credentials or agent token."""
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
                raw_email = normalize_email(item.get("user_email"))
                if not raw_email and "@" in str(item.get("user_name") or ""):
                    raw_email = normalize_email(item.get("user_name"))
                result.append({"id": identifier(item.get("id")), "machine_id": machine_id,
                               "user_id": str(item.get("user_id") or ""),
                               "user_email": raw_email,
                               "user_name": str(item.get("user_name") or ""),
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
        if vm.get("user_id") and (vm.get("user_email") or vm.get("user_name")):
            record_user_email(conn, vm.get("user_id"), vm.get("user_email"), vm.get("user_name"), now)
    directory = {
        str(r[0] or ""): (str(r[1] or ""), str(r[2] or ""))
        for r in conn.execute("SELECT user_id,user_email,user_name FROM buyer_user_directory")
    }
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
        old = conn.execute("SELECT * FROM buyer_targets WHERE host_id=? AND container_name=? AND (runtime=? OR runtime IN ('incus','podman','runman','container')) ORDER BY (runtime=?) DESC, verified_at DESC LIMIT 1", (row["host_id"], row["container_name"], row["runtime"], row["runtime"])).fetchone()
        if old and old["source"] == "manual":
            counts["manual"] += 1
            continue  # Includes explicit manual disable / broadcast choices.
        key = identifier(row["container_name"])
        candidates = index.get(key, [])
        vm = candidates[0] if len(candidates) == 1 else None
        reason = ""
        if not key or row["runtime"] not in {"incus", "podman", "runman"}:
            reason = "非托管实例 UUID；请手工登记收件人"
        elif len({r["host_id"] for r in local.get(key, [])}) != 1:
            reason = "同一实例 UUID 对应多个本地身份，拒绝自动关联"
        elif not candidates:
            reason = "上游找不到此实例（已删除或非托管）"
        elif len(candidates) != 1:
            reason = "上游实例 UUID 重复，拒绝自动关联"
        elif not identifier(vm.get("machine_id")) or not _runtime_compatible(vm.get("runtime"), row["runtime"]):
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
        dir_email, dir_name = directory.get(str(vm["user_id"]), ("", ""))
        email_to_save = (
            normalize_email(vm.get("user_email"))
            or normalize_email(dir_email)
            or (normalize_email(old["user_email"]) if old and old["user_email"] else "")
        )
        old_name = str(old["user_name"] or "") if old and "user_name" in old.keys() else ""
        name_to_save = str(vm.get("user_name") or dir_name or old_name).strip()[:128]
        if email_to_save or name_to_save:
            record_user_email(conn, vm["user_id"], email_to_save, name_to_save, now)
            directory[str(vm["user_id"])] = (email_to_save or dir_email, name_to_save or dir_name)
        conn.execute("INSERT INTO buyer_targets(host_id,runtime,project,container_name,machine_id,user_id,node_name,user_email,user_name,scope,enabled,source,vm_id,verified_at) "
                     "VALUES(?,?,?,?,?,?,?,?,?,'user',1,'upstream',?,?) ON CONFLICT(host_id,runtime,project,container_name) DO UPDATE SET "
                     "machine_id=excluded.machine_id,user_id=excluded.user_id,node_name=excluded.node_name,"
                     "user_email=CASE WHEN excluded.user_email<>'' THEN excluded.user_email ELSE buyer_targets.user_email END,"
                     "user_name=CASE WHEN excluded.user_name<>'' THEN excluded.user_name ELSE buyer_targets.user_name END,"
                     "scope='user',enabled=1,source='upstream',vm_id=excluded.vm_id,verified_at=excluded.verified_at",
                     (*fields, identifier(vm["machine_id"]), vm["user_id"], vm.get("node_name", ""), email_to_save, name_to_save, key, now))
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
