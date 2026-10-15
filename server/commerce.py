"""Private, read-only Narwhal business snapshots. Never share global buyer keys.

Contract: https://api.fuckip.me/openapi.yaml (user-facing v2 API).
Only allowlisted fields leave this module; upstream VM credentials are discarded.
"""
import asyncio
import hashlib
import http.client
import json
import os
import re
import stat
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request

BASE = "https://api.fuckip.me/api/v1"
DOC = "https://api.fuckip.me/openapi.yaml"
LIMIT = 10000
_slots = threading.BoundedSemaphore(2)
_tasks = set()


class CommerceError(ValueError):
    pass


class CommerceConnectionError(CommerceError):
    """Safe public message; never retain an upstream URL, body or credentials."""
    def __init__(self, message, delay=None):
        super().__init__(message)
        self.delay = delay


def retry_after(value):
    try:
        delay = float(value) if str(value).isdigit() else parsedate_to_datetime(value).timestamp() - time.time()
        return max(0, delay)
    except (ValueError, TypeError, OverflowError):
        return None


def initialize(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS commerce_accounts(
        username TEXT PRIMARY KEY, encrypted_key TEXT NOT NULL, revision TEXT NOT NULL,
        upstream_user TEXT NOT NULL, updated_at INTEGER NOT NULL,
        synced_at INTEGER NOT NULL DEFAULT 0, snapshot TEXT, last_error TEXT NOT NULL DEFAULT '',
        binding TEXT NOT NULL DEFAULT '', sync_token TEXT NOT NULL DEFAULT '', sync_started INTEGER NOT NULL DEFAULT 0)""")


def cipher(database_path):
    """Master key must survive container replacement, separately from SQLite backups."""
    configured = os.getenv("COMMERCE_ENCRYPTION_KEY")
    try:
        if configured:
            return Fernet(configured.encode("ascii"))
        path = Path(database_path).resolve().parent / ".commerce-secret.key"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(Fernet.generate_key())
                stream.flush()
                os.fsync(stream.fileno())
        if path.is_symlink() or (os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise ValueError()
        return Fernet(path.read_bytes())
    except (OSError, ValueError, UnicodeError):
        raise CommerceError("个人密钥加密配置不可用，请检查持久化主密钥及权限") from None


def text(value, limit=200):
    return str(value or "")[:limit]


def identity(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise CommerceError("上游返回无效记录 ID，同步未覆盖旧数据") from None


def money(value):
    if value is None:
        return None
    try:
        result = Decimal(str(value))
        if not result.is_finite() or abs(result) > Decimal("1e15"):
            raise ValueError()
        return format(result, "f")
    except (InvalidOperation, ValueError, TypeError):
        raise CommerceError("上游金额无效，同步未覆盖旧数据") from None


def timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)) or value != int(value) or not 0 <= value <= 253402300799:
        raise CommerceError("上游时间无效，同步未覆盖旧数据")
    return int(value)


class Client:
    def __init__(self, key):
        self.key = key
        self.deadline = time.monotonic() + 180
        self.cutoff = int(time.time())
        self.requests = 0
        self.bytes = 0
        self.lock = threading.Lock()
        self.transport_slots = threading.BoundedSemaphore(4)
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener_factory = lambda: urllib.request.build_opener(NoRedirect)

    def get(self, path):
        for attempt in range(3):
            try:
                return self._get(path)
            except CommerceConnectionError as exc:
                delay = exc.delay if exc.delay is not None else (2 ** attempt)
                # Do not retry before the upstream's Retry-After, or extend the
                # existing total budget. Never retry auth/schema/data failures.
                if attempt == 2 or delay > 30 or delay >= self.deadline - time.monotonic():
                    raise
                time.sleep(delay)

    def _get(self, path):
        remaining = self.deadline - time.monotonic()
        with self.lock:
            if remaining <= 0 or self.requests >= 250:
                raise CommerceError("同步超过安全预算，旧数据已保留；请稍后重试")
            self.requests += 1
        req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + self.key,
            "Accept": "application/json", "User-Agent": "Narwhal-Monitor-Commerce/1"})
        try:
            with self.transport_slots:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise CommerceError("同步超过安全预算，旧数据已保留；请稍后重试")
                with self.opener_factory().open(req, timeout=min(25, remaining)) as response:
                    raw = response.read(2_000_001)
            with self.lock:
                self.bytes += len(raw)
                oversized = self.bytes > 20_000_000
            if len(raw) > 2_000_000 or oversized:
                raise CommerceError("上游响应超出安全上限，旧数据已保留")
            payload = json.loads(raw, parse_float=Decimal)
            if not isinstance(payload, dict) or payload.get("code", 0) not in (0, 200) or payload.get("success") is False:
                raise CommerceError("上游拒绝请求，请检查个人 API Key 权限")
            data = payload.get("data")
            if not isinstance(data, dict):
                raise CommerceError("上游响应结构不符，旧数据已保留")
            return data
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504):
                reason = "上游请求过于频繁（HTTP 429），请稍后重试" if exc.code == 429 else f"上游服务暂时不可用（HTTP {exc.code}），请稍后重试"
                raise CommerceConnectionError(reason + "；旧数据已保留", retry_after((exc.headers or {}).get('Retry-After'))) from None
            raise CommerceError("上游认证失败，请更换 API Key" if exc.code in (401, 403) else
                                f"上游请求失败（HTTP {exc.code}），旧数据已保留") from None
        except (OSError, http.client.IncompleteRead) as exc:
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise CommerceError("上游 TLS 证书验证失败，请联系管理员；旧数据已保留") from None
            message = "上游域名解析失败" if isinstance(reason, socket.gaierror) else "上游连接或读取超时" if isinstance(reason, TimeoutError) else "上游网络连接中断或不可达"
            raise CommerceConnectionError(message + "，请稍后重试；旧数据已保留") from None
        except ValueError as exc:
            if isinstance(exc, CommerceError):
                raise
            raise CommerceError("上游连接或响应异常，旧数据已保留") from None

    def pages(self, path, field, paged=True):
        rows, seen, expected = [], set(), None
        def fetch(page):
            return self.get(path + (("&" if "?" in path else "?") + f"page={page}&page_size=100" if paged else ""))
        def consume(data):
            nonlocal expected
            batch, total = data.get(field), data.get("total")
            if not isinstance(batch, list) or type(total) is not int or not 0 <= total <= LIMIT:
                raise CommerceError("上游分页不完整或超出 10000 条上限，旧数据已保留")
            if expected is not None and total != expected:
                raise CommerceError("同步期间上游记录总数变化，请重试；旧数据已保留")
            expected = total
            for row in batch:
                if not isinstance(row, dict):
                    raise CommerceError("上游记录结构不符")
                rid = identity(row.get("id"))
                if rid in seen:
                    raise CommerceError("上游分页出现重复记录，请重试；旧数据已保留")
                seen.add(rid)
                rows.append(row)
            if len(rows) > total:
                raise CommerceError("上游分页未完成，旧数据已保留")
            return len(batch)
        size = consume(fetch(1))
        if len(rows) == expected:
            return rows
        if not paged or not size or (expected + size - 1)//size > 101:
            raise CommerceError("上游分页未完成，旧数据已保留")
        # Fixed transaction cutoff + bounded concurrency; every page must reconcile.
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(fetch, page) for page in range(2, (expected + size - 1)//size + 1)]
            try:
                for future in futures:
                    if not consume(future.result()):
                        raise CommerceError("上游分页未完成，旧数据已保留")
            except Exception:
                for future in futures:
                    future.cancel()
                raise
        if len(rows) != expected:
            raise CommerceError("上游分页未完成，旧数据已保留")
        return rows

    def transaction_history(self):
        """Walk disjoint second-resolution windows, not unstable OFFSET boundaries.

        Rows tied at the oldest timestamp are deferred in full to the next window.
        A dense single-second bucket is reconciled by ID and exact total, never by
        silently dropping duplicates from an incomplete financial history.
        """
        def fetch(start, end, page=1):
            data = self.get('/billing/transactions?' + urlencode({
                'start_time': start, 'end_time': end, 'page': page, 'page_size': 100}))
            batch, total = data.get('transactions'), data.get('total')
            if not isinstance(batch, list) or type(total) is not int or not 0 <= total <= LIMIT or len(batch) > 100:
                raise CommerceError('上游账单时间分段结构不符，旧数据已保留')
            stamps = []
            ids = set()
            for row in batch:
                if not isinstance(row, dict):
                    raise CommerceError('上游账单记录结构不符')
                rid = identity(row.get('id'))
                stamp = timestamp(row.get('created_at'))
                if not start <= stamp <= end or rid in ids:
                    raise CommerceError('上游账单时间筛选或单页记录异常，旧数据已保留')
                ids.add(rid)
                stamps.append(stamp)
            if stamps != sorted(stamps, reverse=True) or len(batch) > total:
                raise CommerceError('上游账单排序或总数异常，旧数据已保留')
            return batch, total

        rows, seen, end, remaining, expected = [], set(), self.cutoff, None, None
        def append(batch):
            for row in batch:
                rid = identity(row['id'])
                if rid in seen:
                    raise CommerceError('上游账单分段重复，旧数据已保留')
                seen.add(rid)
                rows.append(row)

        while end >= 0:
            batch, total = fetch(0, end)
            if expected is None:
                expected = remaining = total
            if total != remaining:
                raise CommerceError('上游账单历史在同步期间发生变化，旧数据已保留，请重试')
            if total == len(batch):
                append(batch)
                remaining = 0
                break
            if not batch:
                raise CommerceError('上游账单时间分段不完整，旧数据已保留')
            boundary = timestamp(batch[-1]['created_at'])
            head = [row for row in batch if row['created_at'] > boundary]
            if head:
                append(head)
                remaining -= len(head)
                end = boundary
                continue
            # More than one page at exactly the same second: retry only this
            # bounded bucket. Completion requires every distinct ID in total.
            first, bucket_total = fetch(boundary, boundary)
            if not len(batch) <= bucket_total <= remaining or bucket_total == 0:
                raise CommerceError('上游账单同秒分组总数异常，旧数据已保留')
            unique = {}
            page_count = (bucket_total + 99)//100
            for attempt in range(3):
                with ThreadPoolExecutor(max_workers=4) as pool:
                    futures = [pool.submit(fetch, boundary, boundary, page)
                               for page in range(1 if attempt else 2, page_count+1)]
                    results = ([] if attempt else [(first, bucket_total)]) + [f.result() for f in futures]
                for page_rows, page_total in results:
                    if page_total != bucket_total or not page_rows:
                        raise CommerceError('上游账单同秒分页发生变化，旧数据已保留')
                    for row in page_rows:
                        rid = identity(row['id'])
                        if rid in unique and unique[rid] != row:
                            raise CommerceError('上游同一账单记录发生变化，旧数据已保留')
                        unique[rid] = row
                if len(unique) == bucket_total:
                    break
                if len(unique) > bucket_total:
                    raise CommerceError('上游账单分组超过声明总数，旧数据已保留')
            if len(unique) != bucket_total:
                raise CommerceError('上游同秒账单分页无法完整核对，旧数据已保留，请稍后重试')
            append(unique.values())
            remaining -= bucket_total
            end = boundary-1
            if remaining == 0:
                break
        if remaining != 0 or len(rows) != expected:
            raise CommerceError('上游账单时间分段未完整核对，旧数据已保留')
        return rows


def profile(client):
    data = client.get("/user/me")
    return {"id": identity(data.get("id")), **{k: money(data.get(k)) for k in
        ("available_balance", "escrow_balance", "escrow_locked_value", "commission_rate")}}


def snapshot(client, account):
    machines = []
    vms = []
    # Even a privileged upstream key must not expose other sellers' machines.
    owned = [m for m in client.pages("/machines", "machines", paged=False)
             if identity(m.get("owner_id")) == account["id"]]
    with ThreadPoolExecutor(max_workers=4) as pool:
        inventories = list(pool.map(lambda m: client.pages(f"/machines/{identity(m['id'])}/vms", "vms"), owned))
    for raw, batch in zip(owned, inventories):
        mid = identity(raw["id"])
        machine = {"id": mid, "name": text(raw.get("name")), "region": text(raw.get("region"), 20),
                   "status": text(raw.get("status"), 30), "vm_count": raw.get("vm_count"),
                   **{k: money(raw.get(k)) for k in ("est_revenue", "earned_revenue", "locked_value")}}
        if machine["vm_count"] is not None and (type(machine["vm_count"]) is not int or machine["vm_count"] < 0):
            raise CommerceError("上游小鸡数量无效")
        for vm in batch:
            if identity(vm.get("machine_id")) != mid:
                raise CommerceError("上游小鸡归属不一致")
            vms.append({"id": identity(vm["id"]), "machine_id": mid, "user_id": identity(vm.get("user_id")),
                "status": text(vm.get("status"), 30), "type": text(vm.get("type"), 30),
                "price_monthly": money(vm.get("price_monthly")), "expires_at": timestamp(vm.get("expires_at", 0))})
        if len(vms) > LIMIT:
            raise CommerceError("上游小鸡超过同步上限")
        machine["observed_vms"] = len(batch)
        machine["buyer_count"] = len({v["user_id"] for v in vms if v["machine_id"] == mid and v["user_id"] != account["id"]})
        machine["sold_current"] = sum(v["user_id"] != account["id"] for v in vms if v["machine_id"] == mid)
        machine["self_current"] = len(batch) - machine["sold_current"]
        machines.append(machine)
    # Own purchases may be on another seller's machine. This endpoint is documented.
    own = client.pages("/vms", "vms")
    vm_map = {v["id"]: v["machine_id"] for v in vms}
    for vm in own:
        if identity(vm.get("user_id")) == account["id"]:
            vm_map[identity(vm["id"])] = identity(vm.get("machine_id"))
    orders = []
    for raw in client.pages("/billing/orders", "orders"):
        if identity(raw.get("user_id")) != account["id"]:
            continue
        vid = identity(raw["vm_id"]) if raw.get("vm_id") else ""
        details = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        mid = identity(details["machine_id"]) if details.get("machine_id") else vm_map.get(vid, "")
        orders.append({"id": identity(raw["id"]), "vm_id": vid, "machine_id": mid,
            "machine_name": text(details.get("machine_name")), "status": text(raw.get("status"), 30) or "unknown",
            "type": text(raw.get("type"), 40), "amount": money(raw.get("amount")),
            "discount_amount": money(raw.get("discount_amount")), "created_at": timestamp(raw.get("created_at"))})
    transactions = []
    for raw in client.transaction_history():
        if identity(raw.get("user_id")) != account["id"]:
            continue
        details = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        transactions.append({"id": identity(raw["id"]), "type": text(raw.get("type"), 40),
            "machine_id": identity(details["machine_id"]) if details.get("machine_id") else "",
            "machine_name": text(details.get("machine_name")),
            "amount": money(raw.get("amount")), "balance_type": text(raw.get("balance_type"), 30),
            "balance_after": money(raw.get("balance_after")), "created_at": timestamp(raw.get("created_at"))})
    return {"profile": account, "machines": machines, "orders": orders, "transactions": transactions,
            "source": BASE, "documentation": DOC, "currency": "USD"}


def analyse(data, start=0, end=253402300799, machine="", kind="", offset=0, limit=50, ledger=False):
    # Balance/profile and current machine inventory deliberately stay outside history filters.
    rows = data["transactions" if ledger else "orders"]
    selected = [r for r in rows if start <= r["created_at"] <= end
                and (not kind or r["type"] == kind)
                and (not machine or (r.get("machine_id", "") == machine if machine != "unknown" else not r.get("machine_id")))]
    selected.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
    totals, days = {}, {}
    for row in selected:
        typ = row["type"]
        balance = row.get("balance_type", "")
        entry = totals.setdefault((typ, balance), {"type": typ, "balance_type": balance, "count": 0, "amount": Decimal(0), "missing_amounts": 0, "uncompleted": 0})
        entry["count"] += 1
        if not ledger and row.get("status") != "completed":
            entry["uncompleted"] += 1
        elif row["amount"] is None:
            entry["missing_amounts"] += 1
        else:
            entry["amount"] += Decimal(row["amount"])
        day = datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%Y-%m-%d")
        group = days.setdefault((day, typ), {"day": day, "type": typ, "count": 0})
        group["count"] += 1
    for entry in totals.values():
        entry["amount"] = None if entry["missing_amounts"] else format(entry["amount"], "f")
    return {"items": selected[offset:offset+limit], "total": len(selected), "totals": list(totals.values()),
            "trend": sorted(days.values(), key=lambda r: (r["day"], r["type"])),
            "unmapped": sum(not r.get("machine_id") for r in selected),
            "offset": offset, "limit": limit, "timezone": "UTC"}


def attach(app, db, database_path, credentials):
    router = APIRouter(prefix="/api/v1/commerce")

    def binding(conn, username):
        user = conn.execute("SELECT password_hash,enabled FROM ops_users WHERE username=?", (username,)).fetchone()
        env_name, env_password = credentials()
        source = ("env:" + env_password) if username == env_name and env_password else ("db:" + user["password_hash"]) if user and user["enabled"] else ""
        return hashlib.sha256(source.encode()).hexdigest() if source else ""

    def read(username):
        conn = db()
        try:
            row = conn.execute("SELECT * FROM commerce_accounts WHERE username=? AND binding=?", (username, binding(conn, username))).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @router.get("/settings")
    def settings(request: Request):
        row = read(request.state.dashboard_user)
        error = row["last_error"] if row else ""
        if row and row["sync_token"] and time.time()-row["sync_started"] >= 240:
            error = "上次同步未完成，请重试；旧数据已保留"
        return {"configured": bool(row), "updated_at": row["updated_at"] if row else 0,
                "synced_at": row["synced_at"] if row else 0, "last_error": error,
                "api_url": BASE, "syncing": bool(row and row["sync_token"] and time.time()-row["sync_started"] < 240)}

    @router.post("/settings")
    async def save(request: Request):
        conn = db()
        try:
            captured_binding = binding(conn, request.state.dashboard_user)
        finally:
            conn.close()
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 4096:
                raise HTTPException(413, "密钥请求过大")
        try:
            payload = json.loads(body)
            key = payload["api_key"]
            if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{8,512}", key) or set(payload) != {"api_key"}:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "请输入有效 API Key") from None
        try:
            account = await asyncio.to_thread(profile, Client(key))
            encrypted = cipher(database_path()).encrypt(key.encode()).decode()
        except CommerceError as exc:
            raise HTTPException(400, str(exc)) from None
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not captured_binding or binding(conn, request.state.dashboard_user) != captured_binding:
                raise HTTPException(409, "登录账号已变化，请重新登录")
            # A new key never inherits another upstream account's data or errors.
            conn.execute("INSERT INTO commerce_accounts(username,encrypted_key,revision,upstream_user,updated_at,binding) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET encrypted_key=excluded.encrypted_key,revision=excluded.revision,upstream_user=excluded.upstream_user,updated_at=excluded.updated_at,binding=excluded.binding,synced_at=0,snapshot=NULL,last_error='',sync_token='',sync_started=0",
                (request.state.dashboard_user, encrypted, str(uuid.uuid4()), account["id"], int(time.time()), captured_binding))
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    @router.delete("/settings")
    def remove(request: Request):
        conn = db()
        try:
            conn.execute("DELETE FROM commerce_accounts WHERE username=?", (request.state.dashboard_user,))
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    def synchronize(username, row, token):
        try:
            try:
                key = cipher(database_path()).decrypt(row["encrypted_key"].encode()).decode()
                client = Client(key)
                account = profile(client)
                if account["id"] != row["upstream_user"]:
                    raise CommerceError("API Key 对应账号发生变化，请重新配置")
                data = snapshot(client, account)
                encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            except (InvalidToken, UnicodeError):
                raise CommerceError("无法解密个人密钥，请恢复主密钥或重新配置 API Key") from None
            conn = db()
            try:
                conn.execute("UPDATE commerce_accounts SET snapshot=?,synced_at=?,last_error='',sync_token='' WHERE username=? AND revision=? AND sync_token=? AND binding=?",
                    (encoded, int(time.time()), username, row["revision"], token, binding(conn, username)))
                conn.commit()
            finally:
                conn.close()
            return {"ok": True}
        except Exception as exc:
            message = str(exc) if isinstance(exc, CommerceError) else "同步异常，旧数据已保留；请重试或联系管理员"
            conn = db()
            try:
                conn.execute("UPDATE commerce_accounts SET last_error=?,sync_token='' WHERE username=? AND revision=? AND sync_token=?", (message, username, row["revision"], token))
                conn.commit()
            finally:
                conn.close()
        finally:
            _slots.release()

    @router.post("/sync")
    async def sync(request: Request):
        username = request.state.dashboard_user
        row = read(username)
        if not row:
            raise HTTPException(409, "请先配置个人 API Key")
        if not _slots.acquire(False):
            raise HTTPException(429, "已有同步任务运行，请稍后重试")
        token = str(uuid.uuid4())
        conn = db()
        try:
            changed = conn.execute("UPDATE commerce_accounts SET sync_token=?,sync_started=?,last_error='' WHERE username=? AND revision=? AND (sync_token='' OR sync_started<?)",
                (token, int(time.time()), username, row["revision"], int(time.time())-240)).rowcount
            conn.commit()
            if changed != 1:
                raise HTTPException(409, "当前账号已在同步，或密钥已更换")
        except Exception:
            _slots.release()
            raise
        finally:
            conn.close()
        task = asyncio.create_task(asyncio.to_thread(synchronize, username, row, token))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return {"ok": True, "syncing": True}

    @router.get("/overview")
    def overview(request: Request):
        row = read(request.state.dashboard_user)
        data = json.loads(row["snapshot"]) if row and row["snapshot"] else None
        error = row["last_error"] if row else ""
        if row and row["sync_token"] and time.time()-row["sync_started"] >= 240:
            error = "上次同步未完成，请重试；旧数据已保留"
        return {"synced_at": row["synced_at"] if row else 0, "stale": bool(row and (error or time.time()-row["synced_at"] > 900)),
                "last_error": error, "profile": data["profile"] if data else None,
                "machines": data["machines"] if data else [], "available": data is not None,
                "source": BASE, "documentation": DOC, "currency": "USD"}

    @router.get("/history")
    def history(request: Request, start: int = 0, end: int = 253402300799,
                machine: str = "", kind: str = "", offset: int = 0, limit: int = 50, ledger: bool = False):
        if not 0 <= start <= end <= 253402300799 or not 0 <= offset <= LIMIT or not 1 <= limit <= 100 or len(machine) > 64 or len(kind) > 40:
            raise HTTPException(400, "筛选参数无效")
        row = read(request.state.dashboard_user)
        if not row or not row["snapshot"]:
            raise HTTPException(409, "请先同步个人经营数据")
        return analyse(json.loads(row["snapshot"]), start, end, machine, kind, offset, limit, ledger)

    app.include_router(router)
