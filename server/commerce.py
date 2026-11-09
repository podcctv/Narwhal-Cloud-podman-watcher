"""Private, read-only Narwhal business snapshots. Never share global buyer keys.

Contract: https://api.fuckip.me/openapi.yaml (user-facing v2 API).
Only allowlisted fields leave this module; upstream VM credentials are discarded.
"""
import asyncio
import hashlib
import http.client
import json
import logging
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
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlencode

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger("narwhal.commerce")

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
    conn.execute("""CREATE TABLE IF NOT EXISTS commerce_notification_settings(
        username TEXT PRIMARY KEY,
        auto_sync INTEGER NOT NULL DEFAULT 1,
        interval_seconds INTEGER NOT NULL DEFAULT 300,
        tg_notify_orders INTEGER NOT NULL DEFAULT 1,
        tg_notify_refunds INTEGER NOT NULL DEFAULT 1,
        tg_daily_digest INTEGER NOT NULL DEFAULT 1,
        tg_monthly_digest INTEGER NOT NULL DEFAULT 1,
        digest_hour INTEGER NOT NULL DEFAULT 8,
        last_sync_at INTEGER NOT NULL DEFAULT 0,
        last_daily_digest_date TEXT NOT NULL DEFAULT '',
        last_monthly_digest_date TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL DEFAULT 0)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS commerce_notified_events(
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        notified_at INTEGER NOT NULL)""")


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

    def post(self, path, payload):
        remaining = self.deadline - time.monotonic()
        with self.lock:
            if remaining <= 0 or self.requests >= 250:
                raise CommerceError("请求超过安全预算，请稍后重试")
            self.requests += 1
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            BASE + path,
            data=data,
            headers={
                "Authorization": "Bearer " + self.key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Narwhal-Monitor-Commerce/1",
            },
            method="POST",
        )
        try:
            with self.transport_slots:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise CommerceError("请求超过安全预算，请稍后重试")
                with self.opener_factory().open(req, timeout=min(25, remaining)) as response:
                    raw = response.read(2_000_001)
            with self.lock:
                self.bytes += len(raw)
            payload_data = json.loads(raw, parse_float=Decimal)
            if not isinstance(payload_data, dict) or payload_data.get("code", 0) not in (0, 200) or payload_data.get("success") is False:
                msg = payload_data.get("msg") or "上游拒绝请求"
                raise CommerceError(f"上游操作失败：{msg}")
            return payload_data.get("data")
        except urllib.error.HTTPError as exc:
            try:
                err_raw = exc.read(4096)
                err_data = json.loads(err_raw)
                err_msg = err_data.get("msg") or f"HTTP {exc.code}"
            except Exception:
                err_msg = f"HTTP {exc.code}"
            raise CommerceError(f"上游请求失败：{err_msg}") from None
        except Exception as exc:
            if isinstance(exc, CommerceError):
                raise
            raise CommerceError("上游连接异常，请稍后重试") from None

    def delete(self, path):
        remaining = self.deadline - time.monotonic()
        with self.lock:
            if remaining <= 0 or self.requests >= 250:
                raise CommerceError("请求超过安全预算，请稍后重试")
            self.requests += 1
        req = urllib.request.Request(
            BASE + path,
            headers={
                "Authorization": "Bearer " + self.key,
                "Accept": "application/json",
                "User-Agent": "Narwhal-Monitor-Commerce/1",
            },
            method="DELETE",
        )
        try:
            with self.transport_slots:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise CommerceError("请求超时，请稍后重试")
                with self.opener_factory().open(req, timeout=min(25, remaining)) as response:
                    raw = response.read(2_000_001)
            with self.lock:
                self.bytes += len(raw)
            payload_data = json.loads(raw, parse_float=Decimal) if raw else {"code": 0}
            if not isinstance(payload_data, dict) or payload_data.get("code", 0) not in (0, 200) or payload_data.get("success") is False:
                msg = payload_data.get("msg") or "上游拒绝请求"
                raise CommerceError(f"上游操作失败：{msg}")
            return payload_data.get("data")
        except urllib.error.HTTPError as exc:
            try:
                err_raw = exc.read(4096)
                err_data = json.loads(err_raw)
                err_msg = err_data.get("msg") or f"HTTP {exc.code}"
            except Exception:
                err_msg = f"HTTP {exc.code}"
            raise CommerceError(f"上游请求失败：{err_msg}") from None
        except Exception as exc:
            if isinstance(exc, CommerceError):
                raise
            raise CommerceError("上游连接异常，请稍后重试") from None

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


def account_balances(data):
    values = {k: money(data.get(k)) for k in
              ("available_balance", "escrow_balance", "escrow_locked_value", "commission_rate")}
    total, locked = values['escrow_balance'], values['escrow_locked_value']
    # Ordinary available_balance is spending credit, not withdrawable escrow.
    # Missing/inconsistent inputs must not become zero or a fabricated balance.
    available = None
    if total is not None and locked is not None and Decimal(0) <= Decimal(locked) <= Decimal(total):
        available = format(Decimal(total) - Decimal(locked), 'f')
    return {**values, 'escrow_available_balance': available}


def profile(client):
    data = client.get("/user/me")
    return {"id": identity(data.get("id")), **account_balances(data)}


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
        vid = ""
        if details.get("vm_id"):
            try:
                vid = identity(details["vm_id"])
            except CommerceError:
                vid = ""
        tx_item = {"id": identity(raw["id"]), "type": text(raw.get("type"), 40),
            "machine_id": identity(details["machine_id"]) if details.get("machine_id") else "",
            "machine_name": text(details.get("machine_name")),
            "amount": money(raw.get("amount")), "balance_type": text(raw.get("balance_type"), 30),
            "balance_after": money(raw.get("balance_after")), "created_at": timestamp(raw.get("created_at"))}
        if vid:
            tx_item["vm_id"] = vid
        transactions.append(tx_item)
    return {"profile": account, "machines": machines, "vms": vms, "orders": orders, "transactions": transactions,
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


def _has_seller_escrow(transactions):
    return any(
        str(t.get("type") or "").lower() in ("escrow_in", "escrow_renew", "escrow_deduct")
        for t in transactions
    )


def _classify_seller_escrow(transactions, start_ts=0):
    """Classify seller escrow ledger into retained purchases, renewals, mid-term refunds, and 24h quick-trial washes.

    When a buyer purchases a VM (`escrow_in`) and refunds it within 24 hours on the same machine
    for >=80% of the purchase amount (`escrow_deduct`), the pair is a quick-trial / IP-swap wash.
    Cancelling matched washes from both effective GMV and effective refund expenditure prevents
    repeated trial re-creations from inflating monthly refund figures by 3x-5x while keeping
    exact net revenue intact.
    """
    txs = sorted(
        [t for t in transactions if int(t.get("created_at") or 0) >= start_ts],
        key=lambda x: (int(x.get("created_at") or 0), str(x.get("id") or ""))
    )
    recent_ins = {}
    records = []
    for t in txs:
        typ = str(t.get("type") or "").lower()
        if typ not in ("escrow_in", "escrow_renew", "escrow_deduct", "compensation"):
            continue
        amt = Decimal(str(t.get("amount") or "0"))
        ts = int(t.get("created_at") or 0)
        mid = str(t.get("machine_id") or "unknown")
        vid = str(t.get("vm_id") or "")
        day = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
        month = day[:7]
        rec = {
            "id": str(t.get("id") or ""),
            "type": typ,
            "amt": amt,
            "abs_amt": abs(amt),
            "ts": ts,
            "day": day,
            "month": month,
            "mid": mid,
            "vid": vid,
            "quick_wash": False,
            "wash_partner": None,
        }
        records.append(rec)
        if typ == "escrow_in" and amt > 0:
            recent_ins.setdefault(mid, []).append(rec)
        elif typ == "escrow_deduct":
            d_amt = abs(amt)
            candidates = recent_ins.get(mid, [])
            matched = None
            for c in reversed(candidates):
                if c["quick_wash"]:
                    continue
                if vid and c["vid"] and vid != c["vid"]:
                    continue
                if 0 <= ts - c["ts"] <= 86400 and Decimal("0.80") * c["amt"] <= d_amt <= c["amt"]:
                    matched = c
                    break
            if matched is not None:
                matched["quick_wash"] = True
                matched["wash_partner"] = rec
                rec["quick_wash"] = True
                rec["wash_partner"] = matched
    return records


def compute_daily_analytics(snapshot, days_limit=30):
    orders = snapshot.get("orders", [])
    transactions = snapshot.get("transactions", [])

    daily = {}

    def ensure_day(day):
        return daily.setdefault(day, {
            "date": day, "orders_count": 0, "orders_amount": Decimal(0),
            "refunds_count": 0, "refunds_amount": Decimal(0), "net_revenue": Decimal(0),
            "renewals_count": 0, "purchases_count": 0,
            "quick_trials_count": 0, "quick_trials_amount": Decimal(0),
        })

    if _has_seller_escrow(transactions):
        for rec in _classify_seller_escrow(transactions):
            item = ensure_day(rec["day"])
            typ = rec["type"]
            if typ == "escrow_in":
                item["net_revenue"] += rec["amt"]
                if not rec["quick_wash"]:
                    item["orders_count"] += 1
                    item["purchases_count"] += 1
                    item["orders_amount"] += rec["amt"]
            elif typ == "escrow_renew":
                item["orders_count"] += 1
                item["renewals_count"] += 1
                item["orders_amount"] += rec["amt"]
                item["net_revenue"] += rec["amt"]
            elif typ == "escrow_deduct":
                item["net_revenue"] -= rec["abs_amt"]
                if rec["quick_wash"]:
                    item["quick_trials_count"] += 1
                    item["quick_trials_amount"] += rec["abs_amt"]
                else:
                    item["refunds_count"] += 1
                    item["refunds_amount"] += rec["abs_amt"]
            elif typ == "compensation":
                item["net_revenue"] -= rec["abs_amt"]
    else:
        for o in orders:
            status = str(o.get("status") or "").lower()
            typ = str(o.get("type") or "").lower()
            amt = Decimal(str(o.get("amount") or "0"))
            day = datetime.fromtimestamp(o["created_at"], timezone.utc).strftime("%Y-%m-%d")
            item = ensure_day(day)
            if status == "completed":
                if typ in ("purchase", "buy"):
                    item["orders_count"] += 1
                    item["purchases_count"] += 1
                    item["orders_amount"] += amt
                    item["net_revenue"] += amt
                elif typ in ("renew", "renewal"):
                    item["orders_count"] += 1
                    item["renewals_count"] += 1
                    item["orders_amount"] += amt
                    item["net_revenue"] += amt
                elif typ == "refund":
                    item["refunds_count"] += 1
                    item["refunds_amount"] += abs(amt)
                    item["net_revenue"] -= abs(amt)

    result = []
    for day in sorted(daily.keys(), reverse=True)[:days_limit]:
        row = daily[day]
        total_ops = row["orders_count"] + row["refunds_count"]
        rate = round(float(row["refunds_count"] / total_ops * 100), 2) if total_ops > 0 else 0.0
        result.append({
            "date": row["date"],
            "orders_count": row["orders_count"],
            "purchases_count": row["purchases_count"],
            "renewals_count": row["renewals_count"],
            "orders_amount": format(row["orders_amount"], "f"),
            "refunds_count": row["refunds_count"],
            "refunds_amount": format(row["refunds_amount"], "f"),
            "net_revenue": format(row["net_revenue"], "f"),
            "refund_rate": rate,
            "quick_trials_count": row["quick_trials_count"],
            "quick_trials_amount": format(row["quick_trials_amount"], "f"),
        })

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    empty_day = {
        "orders_count": 0, "orders_amount": Decimal(0),
        "refunds_count": 0, "refunds_amount": Decimal(0),
        "net_revenue": Decimal(0), "quick_trials_count": 0, "quick_trials_amount": Decimal(0),
    }
    today_data = daily.get(today_str, empty_day)
    yesterday_data = daily.get(yesterday_str, empty_day)

    today_summary = {
        "today_date": today_str,
        "gmv": format(today_data["orders_amount"], "f"),
        "orders_count": today_data["orders_count"],
        "refunds_count": today_data["refunds_count"],
        "refunds_amount": format(today_data["refunds_amount"], "f"),
        "net_revenue": format(today_data["net_revenue"], "f"),
        "yesterday_gmv": format(yesterday_data["orders_amount"], "f"),
        "yesterday_net": format(yesterday_data["net_revenue"], "f"),
        "quick_trials_count": today_data["quick_trials_count"],
        "quick_trials_amount": format(today_data["quick_trials_amount"], "f"),
    }
    return {"daily": result, "today_summary": today_summary}


def compute_monthly_analytics(snapshot, months_limit=12):
    orders = snapshot.get("orders", [])
    transactions = snapshot.get("transactions", [])
    machines_map = {m["id"]: m.get("name") or m["id"] for m in snapshot.get("machines", [])}

    monthly = {}
    machine_sales = {}

    def ensure_month(month):
        return monthly.setdefault(month, {
            "month": month, "orders_count": 0, "orders_amount": Decimal(0),
            "refunds_count": 0, "refunds_amount": Decimal(0), "net_revenue": Decimal(0),
            "renewals_count": 0, "purchases_count": 0,
            "quick_trials_count": 0, "quick_trials_amount": Decimal(0),
        })

    if _has_seller_escrow(transactions):
        for rec in _classify_seller_escrow(transactions):
            month = rec["month"]
            mid = rec["mid"]
            item = ensure_month(month)
            typ = rec["type"]
            if typ == "escrow_in":
                item["net_revenue"] += rec["amt"]
                if not rec["quick_wash"]:
                    item["orders_count"] += 1
                    item["purchases_count"] += 1
                    item["orders_amount"] += rec["amt"]
                    machine_sales[month, mid] = machine_sales.get((month, mid), Decimal(0)) + rec["amt"]
            elif typ == "escrow_renew":
                item["orders_count"] += 1
                item["renewals_count"] += 1
                item["orders_amount"] += rec["amt"]
                item["net_revenue"] += rec["amt"]
                machine_sales[month, mid] = machine_sales.get((month, mid), Decimal(0)) + rec["amt"]
            elif typ == "escrow_deduct":
                item["net_revenue"] -= rec["abs_amt"]
                if rec["quick_wash"]:
                    item["quick_trials_count"] += 1
                    item["quick_trials_amount"] += rec["abs_amt"]
                else:
                    item["refunds_count"] += 1
                    item["refunds_amount"] += rec["abs_amt"]
            elif typ == "compensation":
                item["net_revenue"] -= rec["abs_amt"]
    else:
        for o in orders:
            status = str(o.get("status") or "").lower()
            typ = str(o.get("type") or "").lower()
            amt = Decimal(str(o.get("amount") or "0"))
            month = datetime.fromtimestamp(o["created_at"], timezone.utc).strftime("%Y-%m")
            mid = o.get("machine_id") or "unknown"
            item = ensure_month(month)
            if status == "completed":
                if typ in ("purchase", "buy", "renew", "renewal"):
                    item["orders_count"] += 1
                    if typ in ("purchase", "buy"):
                        item["purchases_count"] += 1
                    else:
                        item["renewals_count"] += 1
                    item["orders_amount"] += amt
                    item["net_revenue"] += amt
                    machine_sales[month, mid] = machine_sales.get((month, mid), Decimal(0)) + amt
                elif typ == "refund":
                    item["refunds_count"] += 1
                    item["refunds_amount"] += abs(amt)
                    item["net_revenue"] -= abs(amt)

    result = []
    for month in sorted(monthly.keys(), reverse=True)[:months_limit]:
        row = monthly[month]
        total_ops = row["orders_count"] + row["refunds_count"]
        rate = round(float(row["refunds_count"] / total_ops * 100), 2) if total_ops > 0 else 0.0
        m_list = []
        for (mth, mid), samt in machine_sales.items():
            if mth == month and samt > 0:
                m_list.append({"machine_id": mid, "machine_name": machines_map.get(mid, mid), "amount": format(samt, "f")})
        m_list.sort(key=lambda x: Decimal(x["amount"]), reverse=True)
        result.append({
            "month": row["month"],
            "orders_count": row["orders_count"],
            "purchases_count": row["purchases_count"],
            "renewals_count": row["renewals_count"],
            "orders_amount": format(row["orders_amount"], "f"),
            "refunds_count": row["refunds_count"],
            "refunds_amount": format(row["refunds_amount"], "f"),
            "net_revenue": format(row["net_revenue"], "f"),
            "refund_rate": rate,
            "quick_trials_count": row["quick_trials_count"],
            "quick_trials_amount": format(row["quick_trials_amount"], "f"),
            "top_machines": m_list[:5]
        })
    return result


def compute_risk_analysis(snapshot, conn=None):
    machines = snapshot.get("machines", [])
    orders = snapshot.get("orders", [])
    transactions = snapshot.get("transactions", [])
    vms = snapshot.get("vms", [])

    user_dir = {}
    vm_target_map = {}
    if conn:
        try:
            ud_rows = conn.execute("SELECT user_id, user_email, user_name FROM buyer_user_directory WHERE user_id<>''").fetchall()
            user_dir = {str(r[0]): {"user_email": str(r[1] or ""), "user_name": str(r[2] or "")} for r in ud_rows}
        except Exception:
            pass
        try:
            bt_rows = conn.execute("SELECT vm_id, user_id, user_email, user_name FROM buyer_targets WHERE vm_id<>'' AND user_id<>''").fetchall()
            for r in bt_rows:
                vid, uid, uemail, uname = str(r[0]), str(r[1]), str(r[2] or ""), str(r[3] or "")
                vm_target_map[vid] = uid
                if uid not in user_dir or (not user_dir[uid].get("user_email") and uemail):
                    user_dir[uid] = {
                        "user_email": uemail or user_dir.get(uid, {}).get("user_email", ""),
                        "user_name": uname or user_dir.get(uid, {}).get("user_name", ""),
                    }
        except Exception:
            pass

    # 1. Abnormal machines (focused on recent 30-day window & excluding 24h trial washes)
    machine_stats = {}
    for m in machines:
        machine_stats[m["id"]] = {
            "machine_id": m["id"],
            "machine_name": m.get("name") or m["id"],
            "region": m.get("region") or "",
            "orders_count": 0,
            "refunds_count": 0,
            "refund_amount": Decimal(0),
            "orders_amount": Decimal(0),
            "quick_trial_count": 0,
            "quick_trial_amount": Decimal(0),
        }

    seller_mode = _has_seller_escrow(transactions)
    if seller_mode:
        max_ts = max((int(t.get("created_at") or 0) for t in transactions), default=int(time.time()))
        cutoff_30d = max(0, max_ts - 30 * 86400)
        for rec in _classify_seller_escrow(transactions, start_ts=cutoff_30d):
            mid = rec["mid"]
            if mid not in machine_stats:
                continue
            typ = rec["type"]
            if typ == "escrow_in":
                if not rec["quick_wash"]:
                    machine_stats[mid]["orders_count"] += 1
                    machine_stats[mid]["orders_amount"] += rec["amt"]
            elif typ == "escrow_renew":
                machine_stats[mid]["orders_count"] += 1
                machine_stats[mid]["orders_amount"] += rec["amt"]
            elif typ == "escrow_deduct":
                if rec["quick_wash"]:
                    machine_stats[mid]["quick_trial_count"] += 1
                    machine_stats[mid]["quick_trial_amount"] += rec["abs_amt"]
                else:
                    machine_stats[mid]["refunds_count"] += 1
                    machine_stats[mid]["refund_amount"] += rec["abs_amt"]
    else:
        for o in orders:
            mid = o.get("machine_id")
            if mid and mid in machine_stats:
                typ = str(o.get("type") or "").lower()
                amt = Decimal(str(o.get("amount") or "0"))
                if typ in ("purchase", "buy", "renew", "renewal") and o.get("status") == "completed":
                    machine_stats[mid]["orders_count"] += 1
                    machine_stats[mid]["orders_amount"] += amt
                elif typ == "refund":
                    machine_stats[mid]["refunds_count"] += 1
                    machine_stats[mid]["refund_amount"] += abs(amt)

    abnormal_machines = []
    for mid, stat in machine_stats.items():
        total_ops = stat["orders_count"] + stat["refunds_count"]
        rate = round(float(stat["refunds_count"] / total_ops * 100), 2) if total_ops > 0 else 0.0
        if seller_mode:
            is_abnormal = (rate >= 30.0 and stat["refunds_count"] >= 5) or (rate >= 25.0 and stat["refund_amount"] >= Decimal("8"))
        else:
            is_abnormal = (rate >= 15.0 and stat["refunds_count"] >= 2) or stat["refunds_count"] >= 3
        stat["refund_rate"] = rate
        stat["is_abnormal"] = is_abnormal
        stat["refund_amount"] = format(stat["refund_amount"], "f")
        stat["orders_amount"] = format(stat["orders_amount"], "f")
        stat["quick_trial_amount"] = format(stat["quick_trial_amount"], "f")
        if is_abnormal:
            trial_note = f"（已剔除 {stat['quick_trial_count']} 次 24h 秒退试用）" if stat["quick_trial_count"] else ""
            stat["suggestion"] = f"近30天中途退订率偏高{trial_note}，建议核查机房线路稳定性、IP墙况或宿主负载"
        else:
            trial_note = f"（另有 {stat['quick_trial_count']} 次 24h 内秒退换IP已冲销）" if stat["quick_trial_count"] else ""
            stat["suggestion"] = f"近30天中途退订处于合理范围{trial_note}"
        abnormal_machines.append(stat)
    abnormal_machines.sort(key=lambda x: (x["is_abnormal"], float(x["refund_amount"]), float(x["refund_rate"])), reverse=True)

    # 2. Abnormal users & Watchlist
    vm_user_map = {v["id"]: v["user_id"] for v in vms if v.get("id") and v.get("user_id")}
    for vid, uid in vm_target_map.items():
        vm_user_map.setdefault(vid, uid)
    user_records = {}

    vm_purchase_time = {}
    for o in sorted(orders, key=lambda x: x["created_at"]):
        vid = o.get("vm_id")
        uid = vm_user_map.get(vid, "")
        if not uid and not vid:
            continue
        effective_uid = uid or f"vm-user:{vid}"
        rec = user_records.setdefault(effective_uid, {
            "user_id": effective_uid,
            "user_name": user_dir.get(effective_uid, {}).get("user_name", ""),
            "user_email": user_dir.get(effective_uid, {}).get("user_email", ""),
            "total_purchases": 0,
            "total_refunds": 0,
            "quick_refunds": 0,
            "total_spent": Decimal(0),
            "total_refunded": Decimal(0),
            "sample_vm_id": vid or ""
        })
        if vid and not rec["sample_vm_id"]:
            rec["sample_vm_id"] = vid

        typ = str(o.get("type") or "").lower()
        amt = Decimal(str(o.get("amount") or "0"))
        if typ in ("purchase", "buy") and o.get("status") == "completed":
            rec["total_purchases"] += 1
            rec["total_spent"] += amt
            if vid:
                vm_purchase_time[vid] = o["created_at"]
        elif typ == "refund":
            rec["total_refunds"] += 1
            rec["total_refunded"] += abs(amt)
            if vid and vid in vm_purchase_time:
                if o["created_at"] - vm_purchase_time[vid] <= 86400:
                    rec["quick_refunds"] += 1

    if seller_mode:
        for rec_tx in _classify_seller_escrow(transactions):
            vid = rec_tx["vid"]
            if not vid:
                continue
            uid = vm_user_map.get(vid, "")
            if not uid:
                continue
            rec = user_records.setdefault(uid, {
                "user_id": uid,
                "user_name": user_dir.get(uid, {}).get("user_name", ""),
                "user_email": user_dir.get(uid, {}).get("user_email", ""),
                "total_purchases": 0,
                "total_refunds": 0,
                "quick_refunds": 0,
                "total_spent": Decimal(0),
                "total_refunded": Decimal(0),
                "sample_vm_id": vid,
            })
            if rec_tx["type"] == "escrow_in":
                rec["total_purchases"] += 1
                rec["total_spent"] += rec_tx["amt"]
            elif rec_tx["type"] == "escrow_deduct":
                rec["total_refunds"] += 1
                rec["total_refunded"] += rec_tx["abs_amt"]
                if rec_tx["quick_wash"]:
                    rec["quick_refunds"] += 1

    abnormal_users = []
    for uid, r in user_records.items():
        if r["total_purchases"] == 0 and r["total_refunds"] == 0:
            continue
        base_ops = max(r["total_purchases"], r["total_refunds"], 1)
        rate = min(100.0, round(float(r["total_refunds"] / base_ops * 100), 2))
        risk_tags = []
        if r["quick_refunds"] >= 1:
            risk_tags.append(f"极速买退 ({r['quick_refunds']}次<24h)")
        if rate >= 50.0 and r["total_refunds"] >= 2:
            risk_tags.append(f"高退款率 ({rate}%)")
        if r["total_refunds"] >= 3:
            risk_tags.append(f"频繁退款 ({r['total_refunds']}次)")

        is_abnormal = bool(risk_tags)
        item = {
            "user_id": uid,
            "user_name": r["user_name"] or (uid[:8] + "..." if len(uid) > 12 else uid),
            "user_email": r["user_email"] or "未登记邮箱",
            "total_purchases": r["total_purchases"],
            "total_refunds": r["total_refunds"],
            "refund_rate": rate,
            "quick_refunds": r["quick_refunds"],
            "total_spent": format(r["total_spent"], "f"),
            "total_refunded": format(r["total_refunded"], "f"),
            "risk_tags": risk_tags,
            "is_abnormal": is_abnormal,
            "sample_vm_id": r["sample_vm_id"]
        }
        abnormal_users.append(item)

    abnormal_users.sort(key=lambda x: (x["is_abnormal"], len(x["risk_tags"]), float(x["refund_rate"])), reverse=True)
    watchlist = [u for u in abnormal_users if u["is_abnormal"]]

    return {
        "abnormal_machines": abnormal_machines,
        "abnormal_users": abnormal_users,
        "watchlist": watchlist
    }


def compute_loyalty_users(snapshot, conn=None):
    profile_data = snapshot.get("profile", {})
    owner_id = profile_data.get("id", "")
    vms = snapshot.get("vms", [])
    orders = snapshot.get("orders", [])
    transactions = snapshot.get("transactions", [])
    machines_map = {m["id"]: m.get("name") or m["id"] for m in snapshot.get("machines", [])}

    user_dir = {}
    if conn:
        try:
            ud_rows = conn.execute("SELECT user_id, user_email, user_name FROM buyer_user_directory WHERE user_id<>''").fetchall()
            user_dir = {str(r[0]): {"user_email": str(r[1] or ""), "user_name": str(r[2] or "")} for r in ud_rows}
        except Exception:
            pass
        try:
            bt_rows = conn.execute("SELECT user_id, user_email, user_name FROM buyer_targets WHERE user_id<>''").fetchall()
            for r in bt_rows:
                uid, uemail, uname = str(r[0]), str(r[1] or ""), str(r[2] or "")
                if uid not in user_dir or (not user_dir[uid].get("user_email") and uemail):
                    user_dir[uid] = {
                        "user_email": uemail or user_dir.get(uid, {}).get("user_email", ""),
                        "user_name": uname or user_dir.get(uid, {}).get("user_name", ""),
                    }
        except Exception:
            pass

    now_ts = int(time.time())
    users_vms = {}
    for v in vms:
        uid = v.get("user_id")
        if not uid or uid == owner_id:
            continue
        v_copy = {
            "id": v["id"],
            "machine_id": v.get("machine_id", ""),
            "machine_name": machines_map.get(v.get("machine_id", ""), "未知母鸡"),
            "price_monthly": v.get("price_monthly"),
            "expires_at": v.get("expires_at", 0),
            "days_remaining": max(0, (v.get("expires_at", 0) - now_ts) // 86400)
        }
        users_vms.setdefault(uid, []).append(v_copy)

    user_renewals = {}
    user_spent = {}
    user_earliest_order = {}
    vm_user_map = {v["id"]: v["user_id"] for v in vms if v.get("id") and v.get("user_id")}

    for o in orders:
        vid = o.get("vm_id")
        uid = vm_user_map.get(vid)
        if not uid or uid == owner_id:
            continue
        typ = str(o.get("type") or "").lower()
        amt = Decimal(str(o.get("amount") or "0"))
        if o.get("status") == "completed":
            user_spent[uid] = user_spent.get(uid, Decimal(0)) + amt
            created = o.get("created_at", now_ts)
            if uid not in user_earliest_order or created < user_earliest_order[uid]:
                user_earliest_order[uid] = created
            if typ in ("renew", "renewal"):
                user_renewals[uid] = user_renewals.get(uid, 0) + 1

    for t in transactions:
        vid = t.get("vm_id")
        uid = vm_user_map.get(vid) if vid else None
        if not uid or uid == owner_id:
            continue
        typ = str(t.get("type") or "").lower()
        amt = Decimal(str(t.get("amount") or "0"))
        if typ in ("escrow_in", "escrow_renew") and amt > 0:
            user_spent[uid] = user_spent.get(uid, Decimal(0)) + amt
            created = t.get("created_at", now_ts)
            if uid not in user_earliest_order or created < user_earliest_order[uid]:
                user_earliest_order[uid] = created
            if typ == "escrow_renew":
                user_renewals[uid] = user_renewals.get(uid, 0) + 1

    loyalty_list = []
    for uid, vm_list in users_vms.items():
        renew_cnt = user_renewals.get(uid, 0)
        spent = user_spent.get(uid, Decimal(0))
        if spent == Decimal(0):
            spent = sum(Decimal(str(v.get("price_monthly") or "0")) for v in vm_list)
        earliest = user_earliest_order.get(uid, now_ts - 86400 * 30)
        tenure_days = max(1, (now_ts - earliest) // 86400)

        if tenure_days >= 180 or renew_cnt >= 6:
            tier = "diamond"
        elif tenure_days >= 60 or renew_cnt >= 2:
            tier = "gold"
        else:
            tier = "silver"

        loyalty_list.append({
            "user_id": uid,
            "user_name": user_dir.get(uid, {}).get("user_name") or (uid[:8] + "..."),
            "user_email": user_dir.get(uid, {}).get("user_email") or "未登记邮箱",
            "loyalty_tier": tier,
            "active_vms_count": len(vm_list),
            "vms": vm_list,
            "estimated_tenure_days": tenure_days,
            "renewal_count": renew_cnt,
            "total_spent": format(spent, "f"),
            "sample_vm_id": vm_list[0]["id"] if vm_list else ""
        })

    tier_order = {"diamond": 0, "gold": 1, "silver": 2, "watchlist": 3}
    loyalty_list.sort(key=lambda x: (tier_order.get(x["loyalty_tier"], 9), -x["estimated_tenure_days"]))
    return loyalty_list


def process_commerce_events(username, data, db, send_telegram):
    if not send_telegram:
        return
    conn = db()
    try:
        settings_row = conn.execute("SELECT * FROM commerce_notification_settings WHERE username=?", (username,)).fetchone()
        settings = dict(settings_row) if settings_row else {
            "tg_notify_orders": 1, "tg_notify_refunds": 1, "auto_sync": 1
        }
        known_rows = conn.execute("SELECT event_id FROM commerce_notified_events").fetchall()
        known_ids = {r[0] for r in known_rows}

        orders = data.get("orders", [])
        transactions = data.get("transactions", [])

        if not known_ids:
            initial = [(o["id"], "order", int(time.time())) for o in orders if o.get("id")]
            initial += [(t["id"], "transaction", int(time.time())) for t in transactions if t.get("id")]
            if initial:
                conn.executemany("INSERT OR IGNORE INTO commerce_notified_events(event_id, event_type, notified_at) VALUES(?,?,?)", initial)
                conn.commit()
            return

        machines = {m["id"]: m.get("name") or m["id"] for m in data.get("machines", [])}
        new_events = []

        for o in orders:
            oid = o.get("id")
            if not oid or oid in known_ids:
                continue
            otype = str(o.get("type") or "").lower()
            ostatus = str(o.get("status") or "").lower()
            mname = o.get("machine_name") or machines.get(o.get("machine_id", ""), "未知母鸡")
            vmid = o.get("vm_id") or ""
            amount = o.get("amount") or "0"
            created_at = o.get("created_at") or int(time.time())
            time_str = datetime.fromtimestamp(created_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if ostatus == "completed" and otype in ("purchase", "buy", "renew", "renewal"):
                if settings.get("tg_notify_orders", 1):
                    type_label = "新买入" if otype in ("purchase", "buy") else "续费"
                    vm_short = f"<code>{vmid[:8]}...</code>" if vmid else "无"
                    msg = (
                        f"🛒 <b>【Narwhal 经营动态 · {type_label}订单】</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"🖥️ <b>母鸡</b>：<code>{mname}</code>\n"
                        f"📦 <b>小鸡</b>：{vm_short}\n"
                        f"💵 <b>金额</b>：<code>${amount} USD</code> (状态: {ostatus})\n"
                        f"🔖 <b>订单号</b>：<code>#{oid[:8]}</code>\n"
                        f"⏰ <b>时间</b>：{time_str}"
                    )
                    try:
                        send_telegram(msg, parse_mode="HTML")
                    except Exception:
                        pass
                new_events.append((oid, "order", int(time.time())))
            elif otype == "refund":
                if settings.get("tg_notify_refunds", 1):
                    msg = (
                        f"⚠️ <b>【Narwhal 经营动态 · 订单退款提醒】</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"🖥️ <b>母鸡</b>：<code>{mname}</code>\n"
                        f"💸 <b>退款金额</b>：<code>-${abs(float(amount)):.2f} USD</code>\n"
                        f"🔖 <b>退款单号</b>：<code>#{oid[:8]}</code>\n"
                        f"⏰ <b>时间</b>：{time_str}"
                    )
                    try:
                        send_telegram(msg, parse_mode="HTML")
                    except Exception:
                        pass
                new_events.append((oid, "order", int(time.time())))
            else:
                new_events.append((oid, "order", int(time.time())))

        for t in transactions:
            tid = t.get("id")
            if not tid or tid in known_ids:
                continue
            ttype = str(t.get("type") or "").lower()
            if ttype in ("refund", "escrow_deduct"):
                if settings.get("tg_notify_refunds", 1):
                    mname = t.get("machine_name") or machines.get(t.get("machine_id", ""), "未知母鸡")
                    amount = t.get("amount") or "0"
                    created_at = t.get("created_at") or int(time.time())
                    time_str = datetime.fromtimestamp(created_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    balance_after = t.get("balance_after") or "0"
                    msg = (
                        f"⚠️ <b>【Narwhal 经营动态 · 托管资金退款/扣减】</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"🖥️ <b>涉及母鸡</b>：<code>{mname}</code>\n"
                        f"💸 <b>扣减金额</b>：<code>{amount} USD</code>\n"
                        f"🏦 <b>变动后余额</b>：<code>${balance_after} USD</code>\n"
                        f"🔖 <b>流水号</b>：<code>#{tid[:8]}</code>\n"
                        f"⏰ <b>时间</b>：{time_str}"
                    )
                    try:
                        send_telegram(msg, parse_mode="HTML")
                    except Exception:
                        pass
                new_events.append((tid, "transaction", int(time.time())))
            else:
                new_events.append((tid, "transaction", int(time.time())))

        if new_events:
            conn.executemany("INSERT OR IGNORE INTO commerce_notified_events(event_id, event_type, notified_at) VALUES(?,?,?)", new_events)
            conn.commit()
    finally:
        conn.close()


def attach(app, db, database_path, credentials, send_telegram=None):
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

    def client_for_user(username):
        row = read(username)
        if not row:
            raise HTTPException(409, "请先配置个人 API Key")
        try:
            key = cipher(database_path()).decrypt(row["encrypted_key"].encode()).decode()
            return Client(key), row
        except (InvalidToken, UnicodeError):
            raise HTTPException(409, "无法解密个人 API Key，请重新配置")

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
            conn.execute("INSERT INTO commerce_accounts(username,encrypted_key,revision,upstream_user,updated_at,binding) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET encrypted_key=excluded.encrypted_key,revision=excluded.revision,upstream_user=excluded.upstream_user,updated_at=excluded.updated_at,binding=excluded.binding,synced_at=0,snapshot=NULL,last_error='',sync_token='',sync_started=0",
                (request.state.dashboard_user, encrypted, str(uuid.uuid4()), account["id"], int(time.time()), captured_binding))
            conn.execute(
                "INSERT INTO commerce_notification_settings(username, auto_sync, interval_seconds, tg_notify_orders, tg_notify_refunds, tg_daily_digest, tg_monthly_digest, digest_hour, updated_at) "
                "VALUES(?,1,300,1,1,1,1,8,?) ON CONFLICT(username) DO NOTHING",
                (request.state.dashboard_user, int(time.time()))
            )
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    @router.delete("/settings")
    def remove(request: Request):
        conn = db()
        try:
            conn.execute("DELETE FROM commerce_accounts WHERE username=?", (request.state.dashboard_user,))
            conn.execute("DELETE FROM commerce_notification_settings WHERE username=?", (request.state.dashboard_user,))
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    def synchronize(username, row, token):
        start_t = time.monotonic()
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
                effective_binding = str(row.get("binding") or binding(conn, username) or "")
                conn.execute("UPDATE commerce_accounts SET snapshot=?,synced_at=?,last_error='',sync_token='' WHERE username=? AND revision=? AND sync_token=? AND binding=?",
                    (encoded, int(time.time()), username, row["revision"], token, effective_binding))
                conn.commit()
            finally:
                conn.close()
            try:
                process_commerce_events(username, data, db, send_telegram)
            except Exception as ev_err:
                logger.warning("Failed processing commerce events for %s: %s", username, ev_err)
            elapsed = time.monotonic() - start_t
            logger.info("Commerce sync succeeded for %s (upstream user=%s, elapsed=%.2fs)", username, row.get("upstream_user"), elapsed)
            return {"ok": True}
        except Exception as exc:
            message = str(exc) if isinstance(exc, CommerceError) else "同步异常，旧数据已保留；请重试或联系管理员"
            logger.warning("Commerce sync failed for %s: %s", username, exc)
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
                "last_error": error, "profile": {"id": data["profile"]["id"], **account_balances(data["profile"])} if data else None,
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

    @router.get("/notification-settings")
    def get_notification_settings(request: Request):
        username = request.state.dashboard_user
        conn = db()
        try:
            r = conn.execute("SELECT * FROM commerce_notification_settings WHERE username=?", (username,)).fetchone()
            if not r:
                return {
                    "auto_sync": True,
                    "interval_seconds": 300,
                    "tg_notify_orders": True,
                    "tg_notify_refunds": True,
                    "tg_daily_digest": True,
                    "tg_monthly_digest": True,
                    "digest_hour": 8,
                    "last_sync_at": 0,
                    "last_daily_digest_date": "",
                    "last_monthly_digest_date": ""
                }
            return {
                "auto_sync": bool(r["auto_sync"]),
                "interval_seconds": int(r["interval_seconds"]),
                "tg_notify_orders": bool(r["tg_notify_orders"]),
                "tg_notify_refunds": bool(r["tg_notify_refunds"]),
                "tg_daily_digest": bool(r["tg_daily_digest"]),
                "tg_monthly_digest": bool(r["tg_monthly_digest"]),
                "digest_hour": int(r["digest_hour"]),
                "last_sync_at": int(r["last_sync_at"]),
                "last_daily_digest_date": str(r["last_daily_digest_date"] or ""),
                "last_monthly_digest_date": str(r["last_monthly_digest_date"] or "")
            }
        finally:
            conn.close()

    @router.post("/notification-settings")
    async def save_notification_settings(request: Request):
        username = request.state.dashboard_user
        payload = await request.json()
        auto_sync = 1 if payload.get("auto_sync", True) else 0
        interval = max(60, min(86400, int(payload.get("interval_seconds", 300))))
        tg_orders = 1 if payload.get("tg_notify_orders", True) else 0
        tg_refunds = 1 if payload.get("tg_notify_refunds", True) else 0
        tg_daily = 1 if payload.get("tg_daily_digest", True) else 0
        tg_monthly = 1 if payload.get("tg_monthly_digest", True) else 0
        digest_hour = max(0, min(23, int(payload.get("digest_hour", 8))))

        conn = db()
        try:
            conn.execute(
                "INSERT INTO commerce_notification_settings(username, auto_sync, interval_seconds, tg_notify_orders, tg_notify_refunds, tg_daily_digest, tg_monthly_digest, digest_hour, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(username) DO UPDATE SET "
                "auto_sync=excluded.auto_sync, interval_seconds=excluded.interval_seconds, "
                "tg_notify_orders=excluded.tg_notify_orders, tg_notify_refunds=excluded.tg_notify_refunds, "
                "tg_daily_digest=excluded.tg_daily_digest, tg_monthly_digest=excluded.tg_monthly_digest, "
                "digest_hour=excluded.digest_hour, updated_at=excluded.updated_at",
                (username, auto_sync, interval, tg_orders, tg_refunds, tg_daily, tg_monthly, digest_hour, int(time.time()))
            )
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    @router.post("/test-telegram")
    def test_telegram_notification(request: Request):
        if not send_telegram:
            raise HTTPException(400, "尚未配置可用的 Telegram Bot，请先在通知设置中添加 Telegram 机器人")
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            "🔔 <b>【Narwhal 经营分析 · Telegram 播报通道测试】</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "✅ 您的经营变动推送与每日/每月简报机器人已就绪！\n"
            f"👤 <b>操作者</b>：<code>{request.state.dashboard_user}</code>\n"
            f"⏰ <b>测试时间</b>：{now_str}\n"
            "💡 当平台产生新的买入订单或退款流水时，将通过此频道实时向您推送。"
        )
        count = send_telegram(msg, parse_mode="HTML")
        if count == 0:
            raise HTTPException(400, "没有已启用的有效 Telegram Bot，请检查机器人的 Token 和 Target 配置")
        return {"ok": True, "sent_count": count}

    @router.get("/daily-analytics")
    def daily_analytics(request: Request, days: int = 30):
        row = read(request.state.dashboard_user)
        if not row or not row["snapshot"]:
            raise HTTPException(409, "请先同步个人经营数据")
        return compute_daily_analytics(json.loads(row["snapshot"]), days_limit=max(1, min(days, 90)))

    @router.get("/monthly-analytics")
    def monthly_analytics(request: Request, months: int = 12):
        row = read(request.state.dashboard_user)
        if not row or not row["snapshot"]:
            raise HTTPException(409, "请先同步个人经营数据")
        return compute_monthly_analytics(json.loads(row["snapshot"]), months_limit=max(1, min(months, 24)))

    @router.get("/risk-analysis")
    def risk_analysis(request: Request):
        row = read(request.state.dashboard_user)
        if not row or not row["snapshot"]:
            raise HTTPException(409, "请先同步个人经营数据")
        conn = db()
        try:
            return compute_risk_analysis(json.loads(row["snapshot"]), conn=conn)
        finally:
            conn.close()

    @router.get("/loyalty-users")
    def loyalty_users(request: Request):
        row = read(request.state.dashboard_user)
        if not row or not row["snapshot"]:
            raise HTTPException(409, "请先同步个人经营数据")
        conn = db()
        try:
            return compute_loyalty_users(json.loads(row["snapshot"]), conn=conn)
        finally:
            conn.close()

    @router.post("/compensate")
    async def compensate_vm(request: Request):
        body = await request.json()
        vid = identity(body.get("vm_id"))
        days = int(body.get("days", 0))
        if days < 1 or days > 365:
            raise HTTPException(400, "赠送时长天数必须在 1 到 365 天之间")
        client, row = client_for_user(request.state.dashboard_user)
        try:
            result = client.post(f"/vms/{vid}/compensate", {"days": days})
            return {"ok": True, "result": result}
        except CommerceError as exc:
            raise HTTPException(400, str(exc)) from None

    @router.get("/blocked-users")
    def get_blocked_users(request: Request, page: int = 1, page_size: int = 100):
        client, row = client_for_user(request.state.dashboard_user)
        try:
            data = client.get(f"/machines/blocked-users?page={page}&page_size={page_size}")
            return {"ok": True, **data}
        except CommerceError as exc:
            raise HTTPException(400, str(exc)) from None

    @router.post("/block-user")
    async def block_user(request: Request):
        body = await request.json()
        vid = identity(body.get("vm_id"))
        reason = text(body.get("reason", "频繁买退/恶意滥用"), 500)
        client, row = client_for_user(request.state.dashboard_user)
        try:
            result = client.post(f"/vms/{vid}/block-user", {"reason": reason})
            return {"ok": True, "result": result}
        except CommerceError as exc:
            raise HTTPException(400, str(exc)) from None

    @router.delete("/blocked-users/{user_id}")
    def unblock_user(user_id: str, request: Request):
        uid = identity(user_id)
        client, row = client_for_user(request.state.dashboard_user)
        try:
            client.delete(f"/machines/blocked-users/{uid}")
            return {"ok": True}
        except CommerceError as exc:
            raise HTTPException(400, str(exc)) from None

    async def _auto_sync_loop():
        while True:
            try:
                await asyncio.sleep(30)
                conn = db()
                try:
                    rows = conn.execute(
                        "SELECT a.username, COALESCE(s.auto_sync, 1) as auto_sync, "
                        "COALESCE(s.interval_seconds, 300) as interval_seconds, "
                        "COALESCE(s.tg_notify_orders, 1) as tg_notify_orders, "
                        "COALESCE(s.tg_notify_refunds, 1) as tg_notify_refunds, "
                        "COALESCE(s.tg_daily_digest, 1) as tg_daily_digest, "
                        "COALESCE(s.tg_monthly_digest, 1) as tg_monthly_digest, "
                        "COALESCE(s.digest_hour, 8) as digest_hour, "
                        "COALESCE(s.last_sync_at, 0) as last_sync_at, "
                        "COALESCE(s.last_daily_digest_date, '') as last_daily_digest_date, "
                        "COALESCE(s.last_monthly_digest_date, '') as last_monthly_digest_date, "
                        "a.encrypted_key, a.revision, a.upstream_user, a.snapshot, a.sync_token, a.sync_started, a.binding "
                        "FROM commerce_accounts a "
                        "LEFT JOIN commerce_notification_settings s ON a.username = s.username "
                        "WHERE a.encrypted_key IS NOT NULL AND a.encrypted_key != '' AND COALESCE(s.auto_sync, 1) = 1"
                    ).fetchall()
                finally:
                    conn.close()

                now_ts = int(time.time())
                now_utc = datetime.now(timezone.utc)
                now_bj = now_utc + timedelta(hours=8)
                today_bj_str = now_bj.strftime("%Y-%m-%d")
                this_month_bj_str = now_bj.strftime("%Y-%m")

                for r in rows:
                    username = r["username"]
                    interval = max(60, int(r["interval_seconds"] or 300))
                    last_sync = int(r["last_sync_at"] or 0)
                    sync_token = str(r["sync_token"] or "")
                    sync_started = int(r["sync_started"] or 0)

                    if (now_ts - last_sync >= interval) and (not sync_token or (now_ts - sync_started >= 240)):
                        if _slots.acquire(False):
                            try:
                                new_token = str(uuid.uuid4())
                                logger.info("Auto-sync scheduled for %s (interval=%ds, last_sync=%ds ago)", username, interval, now_ts - last_sync)
                                conn = db()
                                try:
                                    conn.execute(
                                        "UPDATE commerce_accounts SET sync_token=?, sync_started=?, last_error='' WHERE username=? AND revision=?",
                                        (new_token, now_ts, username, r["revision"])
                                    )
                                    conn.execute(
                                        "INSERT INTO commerce_notification_settings(username, last_sync_at, updated_at) "
                                        "VALUES(?,?,?) ON CONFLICT(username) DO UPDATE SET last_sync_at=excluded.last_sync_at",
                                        (username, now_ts, now_ts)
                                    )
                                    conn.commit()
                                finally:
                                    conn.close()
                                await asyncio.to_thread(synchronize, username, dict(r), new_token)
                            except Exception as sync_exc:
                                logger.warning("Auto-sync trigger error for %s: %s", username, sync_exc)
                                _slots.release()

                    if r["tg_daily_digest"] and send_telegram and r["snapshot"]:
                        target_hour = int(r["digest_hour"] if r["digest_hour"] is not None else 8)
                        if now_bj.hour == target_hour and r["last_daily_digest_date"] != today_bj_str:
                            try:
                                snap = json.loads(r["snapshot"])
                                daily_info = compute_daily_analytics(snap, days_limit=7)
                                today_sum = daily_info["today_summary"]
                                risk_info = compute_risk_analysis(snap)
                                ab_machines_cnt = sum(1 for m in risk_info.get("abnormal_machines", []) if m.get("is_abnormal"))
                                ab_users_cnt = len(risk_info.get("watchlist", []))

                                ab_notice = "🟢 各母鸡与买家退款指标平稳"
                                if ab_machines_cnt > 0 or ab_users_cnt > 0:
                                    ab_notice = f"⚠️ 发现 {ab_machines_cnt} 台退款偏高母鸡，{ab_users_cnt} 位重点关注买家"

                                sold_total = sum(m.get("sold_current", 0) for m in snap.get("machines", []))
                                machines_total = len(snap.get("machines", []))

                                msg = (
                                    f"📊 <b>【Narwhal 每日经营简报】（{today_bj_str}）</b>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"💰 <b>今日总收入 (GMV)</b>：<code>${today_sum['gmv']} USD</code> ({today_sum['orders_count']} 笔订单)\n"
                                    f"💸 <b>今日退款支出</b>：<code>${today_sum['refunds_amount']} USD</code> ({today_sum['refunds_count']} 笔退款)\n"
                                    f"📈 <b>今日净收益</b>：<code>${today_sum['net_revenue']} USD</code>\n"
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"🖥️ <b>在售母鸡概况</b>：{machines_total} 台母鸡在售 · 当前售出 {sold_total} 台小鸡\n"
                                    f"🚨 <b>经营风控</b>：{ab_notice}\n"
                                    f"⏰ <b>播报时间</b>：{now_bj.strftime('%H:%M:%S')} (UTC+8)"
                                )
                                send_telegram(msg, parse_mode="HTML")
                                conn = db()
                                try:
                                    conn.execute(
                                        "UPDATE commerce_notification_settings SET last_daily_digest_date=? WHERE username=?",
                                        (today_bj_str, username)
                                    )
                                    conn.commit()
                                finally:
                                    conn.close()
                            except Exception:
                                pass

                    if r["tg_monthly_digest"] and send_telegram and r["snapshot"]:
                        if now_bj.day == 1 and now_bj.hour == 9 and r["last_monthly_digest_date"] != this_month_bj_str:
                            try:
                                snap = json.loads(r["snapshot"])
                                monthly_info = compute_monthly_analytics(snap, months_limit=2)
                                if monthly_info:
                                    last_m = monthly_info[0]
                                    top_m_text = "\n".join([f"  • {m['machine_name']}：${m['amount']} USD" for m in last_m.get("top_machines", [])[:3]]) or "  • 暂无明细"
                                    msg = (
                                        f"🗓️ <b>【Narwhal 每月经营报表】（{last_m['month']}）</b>\n"
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"💰 <b>全月销售额 (GMV)</b>：<code>${last_m['orders_amount']} USD</code> ({last_m['orders_count']} 笔订单)\n"
                                        f"💸 <b>全月总退款</b>：<code>${last_m['refunds_amount']} USD</code> ({last_m['refunds_count']} 笔退款)\n"
                                        f"💵 <b>全月净收入</b>：<code>${last_m['net_revenue']} USD</code>\n"
                                        f"📉 <b>全月退款率</b>：<code>{last_m['refund_rate']}%</code>\n"
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"🏆 <b>热销母鸡排行</b>：\n{top_m_text}\n"
                                        f"⏰ <b>发布时间</b>：{now_bj.strftime('%Y-%m-%d %H:%M:%S')} (UTC+8)"
                                    )
                                    send_telegram(msg, parse_mode="HTML")
                                conn = db()
                                try:
                                    conn.execute(
                                        "UPDATE commerce_notification_settings SET last_monthly_digest_date=? WHERE username=?",
                                        (this_month_bj_str, username)
                                    )
                                    conn.commit()
                                finally:
                                    conn.close()
                            except Exception:
                                pass
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(5)

    @app.on_event('startup')
    async def _start_commerce_background_tasks():
        _bg_task = asyncio.create_task(_auto_sync_loop())
        _tasks.add(_bg_task)
        _bg_task.add_done_callback(_tasks.discard)

    app.include_router(router)
