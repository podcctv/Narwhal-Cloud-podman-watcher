"""Synthetic fixtures only. No upstream credential or production data in tests."""
import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from decimal import Decimal
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit, parse_qs

from fastapi.testclient import TestClient
from server import app as server, commerce, operations


def uid(n):
    return str(uuid.UUID(int=n))


def fixture():
    return {"profile": {"id": uid(1), "available_balance": "1.23", "escrow_balance": "4.56", "escrow_locked_value": "0.12", "commission_rate": "0.1"},
        "machines": [{"id": uid(2), "name": "合成测试母鸡", "region": "JP", "status": "online", "sold_current": 3, "self_current": 1,
            "observed_vms": 4, "vm_count": 4, "buyer_count": 2, "est_revenue": "12.5", "earned_revenue": "8.25", "locked_value": "1.5"}],
        "orders": [
            {"id": uid(10), "vm_id": uid(20), "machine_id": uid(2), "machine_name": "合成测试母鸡", "type": "purchase", "amount": "0.1", "status": "completed", "created_at": 1704067200},
            {"id": uid(11), "vm_id": uid(20), "machine_id": uid(2), "machine_name": "合成测试母鸡", "type": "purchase", "amount": "0.2", "status": "completed", "created_at": 1704153600},
            {"id": uid(12), "vm_id": "", "machine_id": "", "type": "refund", "amount": "-0.1", "status": "completed", "created_at": 1704240000},
            {"id": uid(13), "vm_id": "", "machine_id": "", "type": "purchase", "amount": "1000", "status": "pending", "created_at": 1704326400}],
        "transactions": [
            {"id": uid(30), "type": "refund", "amount": "1.1", "balance_type": "available", "balance_after": "2.2", "machine_id": uid(2), "created_at": 1704067200},
            {"id": uid(31), "type": "refund", "amount": "-0.2", "balance_type": "escrow", "balance_after": "0.2", "machine_id": uid(2), "created_at": 1704067200}],
        "currency": "USD", "source": commerce.BASE, "documentation": commerce.DOC}


class CommerceMathTests(unittest.TestCase):
    def window_client(self, rows):
        client = commerce.Client('synthetic-key-only')
        client.cutoff = 1000
        urls = []
        def fetch(path):
            urls.append(path)
            q = parse_qs(urlsplit(path).query)
            start, end, page = (int(q.get(k, [default])[0]) for k, default in [('start_time', 0), ('end_time', 1000), ('page', 1)])
            selected = sorted([r for r in rows if start <= r['created_at'] <= end], key=lambda r: r['created_at'], reverse=True)
            return {'transactions': selected[(page-1)*100:page*100], 'total': len(selected)}
        client.get = mock.Mock(side_effect=fetch)
        return client, urls, fetch

    def test_time_windows_avoid_offset_ties_and_reconcile_total(self):
        rows = [{'id': uid(1000+i), 'created_at': 300 if i < 80 else 200 if i < 160 else 100} for i in range(200)]
        client, urls, _ = self.window_client(rows)
        result = client.transaction_history()
        self.assertEqual(len(result), 200)
        self.assertEqual(len({r['id'] for r in result}), 200)
        self.assertEqual(len(urls), 3)
        self.assertTrue(all('page=1' in url for url in urls))

    def test_dense_same_second_retries_only_bucket_until_complete(self):
        rows = [{'id': uid(1000+i), 'created_at': 200} for i in range(105)]
        client, urls, fetch = self.window_client(rows)
        overlaps = 0
        def unstable(path):
            nonlocal overlaps
            q = parse_qs(urlsplit(path).query)
            if q.get('start_time') == ['200'] and q.get('page') == ['2']:
                overlaps += 1
                if overlaps == 1:
                    return {'transactions': rows[95:100], 'total': 105}
            return fetch(path)
        client.get = mock.Mock(side_effect=unstable)
        self.assertEqual(len(client.transaction_history()), 105)
        self.assertEqual(overlaps, 2)

    def test_dense_missing_records_never_silently_deduplicate(self):
        rows = [{'id': uid(1000+i), 'created_at': 200} for i in range(105)]
        client, urls, fetch = self.window_client(rows)
        def unstable(path):
            if parse_qs(urlsplit(path).query).get('page') == ['2']:
                return {'transactions': rows[95:100], 'total': 105}
            return fetch(path)
        client.get = mock.Mock(side_effect=unstable)
        with self.assertRaisesRegex(commerce.CommerceError, '无法完整核对'):
            client.transaction_history()

    def test_window_filter_drift_sort_and_duplicate_rows_rejected(self):
        rows = [{'id': uid(1000+i), 'created_at': 300 if i < 80 else 200} for i in range(150)]
        client, _, fetch = self.window_client(rows)
        def ignored(path):
            data = fetch(path)
            if 'end_time=200' in path:
                data['transactions'][0]['created_at'] = 300
            return data
        client.get = mock.Mock(side_effect=ignored)
        with self.assertRaises(commerce.CommerceError):
            client.transaction_history()
        for data in (
            {'transactions': [{'id':uid(1),'created_at':1},{'id':uid(2),'created_at':2}], 'total':2},
            {'transactions': [{'id':uid(1),'created_at':2},{'id':uid(1),'created_at':2}], 'total':2},
            {'transactions': [], 'total':10001},
        ):
            client.get = mock.Mock(return_value=data)
            with self.assertRaises(commerce.CommerceError):
                client.transaction_history()

    def test_empty_window_returns_empty_history(self):
        client, _, _ = self.window_client([])
        self.assertEqual(client.transaction_history(), [])

    def test_decimal_completed_and_signed_refunds_not_combined(self):
        result = commerce.analyse(fixture())
        totals = {t["type"]: t for t in result["totals"]}
        self.assertEqual(totals["purchase"]["amount"], "0.3")
        self.assertEqual(totals["purchase"]["count"], 3)
        self.assertEqual(totals["purchase"]["uncompleted"], 1)
        self.assertEqual(totals["refund"]["amount"], "-0.1")
        self.assertEqual(result["total"], 4)
        self.assertEqual(sum(r["count"] for r in result["trend"]), 4)

    def test_balances_are_separate(self):
        result = commerce.analyse(fixture(), ledger=True)
        self.assertEqual({t["balance_type"]: t["amount"] for t in result["totals"]}, {"available": "1.1", "escrow": "-0.2"})

    def test_date_host_type_pagination_and_unknown(self):
        result = commerce.analyse(fixture(), start=1704153600, end=1704240000, machine=uid(2), kind="purchase", limit=1)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["id"], uid(11))
        self.assertEqual(commerce.analyse(fixture(), machine="unknown")["total"], 2)
        self.assertEqual(commerce.analyse(fixture(), machine=uid(999))["total"], 0)
        self.assertEqual(commerce.analyse(fixture(), offset=1, limit=1)["items"][0]["id"], uid(12))
        self.assertEqual(commerce.analyse(fixture(), ledger=True, machine=uid(2))["total"], 2)

    def test_missing_money_is_not_zero(self):
        data = fixture()
        data["orders"][0]["amount"] = None
        self.assertIsNone(next(t for t in commerce.analyse(data)["totals"] if t["type"] == "purchase")["amount"])
        for value in ("NaN", "Infinity", "not-money", "1e100"):
            with self.assertRaises(commerce.CommerceError):
                commerce.money(value)
        self.assertEqual(commerce.money(Decimal("0.30000000")), "0.30000000")

    def test_invalid_identity_and_timestamp(self):
        for bad in (None, "../../etc/passwd", "not-a-uuid"):
            with self.assertRaises(commerce.CommerceError):
                commerce.identity(bad)
        for bad in (None, -1, True, "123", Decimal("1.5")):
            with self.assertRaises(commerce.CommerceError):
                commerce.timestamp(bad)

    def test_only_transient_get_errors_are_retried_once(self):
        client = commerce.Client("synthetic-key-only")
        transient = commerce.CommerceError("上游连接暂时异常，旧数据已保留")
        with mock.patch.object(client, "_get", side_effect=[transient, {"ok": True}]) as get, mock.patch.object(commerce.time, "sleep"):
            self.assertEqual(client.get("/user/me"), {"ok": True})
            self.assertEqual(get.call_count, 2)
        with mock.patch.object(client, "_get", side_effect=commerce.CommerceError("上游认证失败")) as get:
            with self.assertRaises(commerce.CommerceError):
                client.get("/user/me")
            self.assertEqual(get.call_count, 1)

    def test_pagination_complete_and_duplicate_incomplete_drift(self):
        client = commerce.Client("synthetic-key-only")
        with mock.patch.object(client, "get", side_effect=[{"orders": [{"id": uid(10)}], "total": 2}, {"orders": [{"id": uid(11)}], "total": 2}]):
            self.assertEqual(len(client.pages("/billing/orders", "orders")), 2)
        for batches in (
            [{"orders": [{"id": uid(10)}], "total": 2}, {"orders": [{"id": uid(10)}], "total": 2}],
            [{"orders": [], "total": 2}],
            [{"orders": [{"id": uid(10)}], "total": 2}, {"orders": [{"id": uid(11)}], "total": 3}],
            [{"orders": [], "total": 10001}],
        ):
            with mock.patch.object(client, "get", side_effect=batches), self.assertRaises(commerce.CommerceError):
                client.pages("/billing/orders", "orders")

    def test_adapter_discards_secrets_and_keeps_historical_machine(self):
        client = mock.Mock(cutoff=1705000000)
        machine = {"id": uid(2), "owner_id": uid(1), "name": "fixture", "agent_token": "SHOULD-NOT-LEAVE", "vm_count": 1}
        vm = {"id": uid(20), "machine_id": uid(2), "user_id": uid(3), "credentials": {"password": "SHOULD-NOT-LEAVE"}}
        order = {"id": uid(10), "user_id": uid(1), "vm_id": uid(999), "type": "refund", "status": "completed", "amount": -1,
            "created_at": 1704067200, "data": {"machine_id": uid(2), "machine_name": "historical", "secret": "SHOULD-NOT-LEAVE"}}
        client.pages.side_effect = [[machine, {"id": uid(4), "owner_id": uid(5)}], [vm], [], [order]]
        client.transaction_history.return_value = []
        data = commerce.snapshot(client, {"id": uid(1)})
        self.assertNotIn("SHOULD-NOT-LEAVE", json.dumps(data))
        self.assertEqual(len(data["machines"]), 1)
        self.assertEqual(data["machines"][0]["sold_current"], 1)
        self.assertEqual(data["orders"][0]["machine_id"], uid(2))


class CommerceHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "monitor.db")
        self.patch = mock.patch.multiple(server, DB_PATH=self.database, DASHBOARD_USERNAME="admin", DASHBOARD_PASSWORD="synthetic-admin-password")
        self.patch.start()
        self.env = mock.patch.dict(os.environ, {"COMMERCE_ENCRYPTION_KEY": ""})
        self.env.start()
        server.init_db()
        conn = server.db()
        conn.execute("INSERT INTO ops_users VALUES(?,?,?,1,0)", ("viewer", operations.password_hash("synthetic-viewer-password"), "viewer"))
        conn.commit()
        conn.close()
        server.app.state.dashboard_sessions.records.clear()
        server.app.state.dashboard_login_limiter.records.clear()
        self.client = TestClient(server.app, base_url="https://testserver")
        self.client.__enter__()
        self.headers = {"Origin": "https://testserver"}

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.patch.stop()
        self.env.stop()
        self.temp.cleanup()

    def login(self, viewer=False):
        self.assertEqual(self.client.post("/api/v1/auth/login", json={"username": "viewer" if viewer else "admin", "password": "synthetic-viewer-password" if viewer else "synthetic-admin-password"}, headers=self.headers).status_code, 200)

    def save(self):
        with mock.patch.object(commerce, "profile", return_value=fixture()["profile"]):
            result = self.client.post("/api/v1/commerce/settings", json={"api_key": "synthetic-personal-key-only"}, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)

    def seed(self, user="viewer"):
        conn = server.db()
        conn.execute("UPDATE commerce_accounts SET snapshot=?,synced_at=? WHERE username=?", (json.dumps(fixture()), int(time.time()), user))
        conn.commit()
        conn.close()

    def wait_sync(self):
        for _ in range(200):
            state = self.client.get("/api/v1/commerce/settings").json()
            if not state["syncing"]:
                return state
            time.sleep(0.01)
        self.fail("test worker did not finish")

    def test_auth_csrf_and_viewer_private_mutations(self):
        self.assertEqual(self.client.get("/api/v1/commerce/settings").status_code, 401)
        self.login(viewer=True)
        self.assertEqual(self.client.post("/api/v1/commerce/settings", json={}, headers={"Origin": "https://evil.test"}).status_code, 403)
        self.save()
        self.assertEqual(self.client.get("/api/v1/settings/push").status_code, 403)
        self.assertEqual(self.client.delete("/api/v1/commerce/settings", headers=self.headers).status_code, 200)

    def test_key_encrypted_no_echo_audit_or_other_users_data(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        self.assertTrue(self.client.get("/api/v1/commerce/overview").json()["available"])
        conn = server.db()
        row = conn.execute("SELECT * FROM commerce_accounts").fetchone()
        self.assertNotIn("synthetic-personal-key-only", str(dict(row)))
        self.assertEqual(commerce.cipher(self.database).decrypt(row["encrypted_key"].encode()).decode(), "synthetic-personal-key-only")
        self.assertNotIn("synthetic-personal-key-only", str([dict(r) for r in conn.execute("SELECT * FROM ops_audit")]))
        conn.close()
        settings = self.client.get("/api/v1/commerce/settings")
        self.assertNotIn("encrypted", settings.text)
        self.assertNotIn("synthetic-personal", settings.text)
        self.assertEqual(settings.headers["cache-control"], "no-store")
        self.login()
        self.assertFalse(self.client.get("/api/v1/commerce/settings").json()["configured"])
        self.assertFalse(self.client.get("/api/v1/commerce/overview").json()["available"])
        self.assertEqual(self.client.get("/api/v1/commerce/history?username=viewer").status_code, 409)

    def test_failed_validation_does_not_replace_key(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        with mock.patch.object(commerce, "profile", side_effect=commerce.CommerceError("上游认证失败")):
            self.assertEqual(self.client.post("/api/v1/commerce/settings", json={"api_key": "other-synthetic-key"}, headers=self.headers).status_code, 400)
        self.assertTrue(self.client.get("/api/v1/commerce/overview").json()["available"])
        for payload in ({"api_key": "short"}, [], {"api_key": "valid-looking-key", "username": "admin"}):
            self.assertEqual(self.client.post("/api/v1/commerce/settings", json=payload, headers=self.headers).status_code, 400)
        self.assertEqual(self.client.post("/api/v1/commerce/settings", content="x" * 4097, headers=self.headers).status_code, 413)

    def test_async_success_and_failed_sync_retains_snapshot(self):
        self.login(viewer=True)
        self.save()
        with mock.patch.object(commerce, "profile", return_value=fixture()["profile"]), mock.patch.object(commerce, "snapshot", return_value=fixture()):
            self.assertTrue(self.client.post("/api/v1/commerce/sync", headers=self.headers).json()["syncing"])
            self.assertFalse(self.wait_sync()["last_error"])
        with mock.patch.object(commerce, "profile", return_value=fixture()["profile"]), mock.patch.object(commerce, "snapshot", side_effect=commerce.CommerceError("分页不完整")):
            self.client.post("/api/v1/commerce/sync", headers=self.headers)
            self.assertEqual(self.wait_sync()["last_error"], "分页不完整")
        overview = self.client.get("/api/v1/commerce/overview").json()
        self.assertTrue(overview["available"])
        self.assertTrue(overview["stale"])
        self.assertEqual(overview["machines"][0]["sold_current"], 3)

    def test_new_key_and_delete_clear_cached_history(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        self.save()
        self.assertFalse(self.client.get("/api/v1/commerce/overview").json()["available"])
        self.seed()
        self.client.delete("/api/v1/commerce/settings", headers=self.headers)
        self.assertEqual(self.client.get("/api/v1/commerce/history").status_code, 409)

    def test_old_worker_cannot_overwrite_replaced_key(self):
        self.login(viewer=True)
        self.save()
        entered, finish = threading.Event(), threading.Event()
        def held(*args):
            entered.set()
            finish.wait(3)
            return fixture()
        with mock.patch.object(commerce, "profile", return_value=fixture()["profile"]), mock.patch.object(commerce, "snapshot", side_effect=held):
            self.client.post("/api/v1/commerce/sync", headers=self.headers)
            self.assertTrue(entered.wait(1))
            self.assertEqual(self.client.post("/api/v1/commerce/sync", headers=self.headers).status_code, 409)
            self.save()
            finish.set()
            deadline = time.monotonic() + 2
            while commerce._tasks and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertFalse(self.client.get("/api/v1/commerce/overview").json()["available"])

    def test_invalid_master_key_does_not_leak_or_overwrite(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        with mock.patch.dict(os.environ, {"COMMERCE_ENCRYPTION_KEY": "invalid-master-key"}):
            with self.assertRaises(commerce.CommerceError):
                commerce.cipher(self.database)
            self.client.post("/api/v1/commerce/sync", headers=self.headers)
            state = self.wait_sync()
            self.assertIn("加密配置不可用", state["last_error"])
            self.assertNotIn("invalid-master-key", state["last_error"])
        self.assertTrue(self.client.get("/api/v1/commerce/overview").json()["available"])

    def test_delete_and_recreate_user_does_not_inherit_key(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        self.login()
        self.assertEqual(self.client.delete("/api/v1/ops/users/viewer", headers=self.headers).status_code, 200)
        conn = server.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM commerce_accounts").fetchone()[0], 0)
        conn.close()

    def test_password_change_binds_personal_data_to_account_generation(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        conn = server.db()
        conn.execute("UPDATE ops_users SET password_hash=? WHERE username='viewer'", (operations.password_hash("synthetic-viewer-password"),))
        conn.commit()
        conn.close()
        self.login(viewer=True)
        self.assertFalse(self.client.get("/api/v1/commerce/settings").json()["configured"])

    def test_filters_and_invalid_bounds(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        response = self.client.get("/api/v1/commerce/history?kind=refund&machine=unknown").json()
        self.assertEqual(response["total"], 1)
        for query in ("start=2&end=1", "limit=101", "offset=-1"):
            self.assertEqual(self.client.get("/api/v1/commerce/history?" + query).status_code, 400)

    def test_expired_worker_is_not_reported_as_success(self):
        self.login(viewer=True)
        self.save()
        self.seed()
        conn = server.db()
        conn.execute("UPDATE commerce_accounts SET sync_token='expired-fixture',sync_started=? WHERE username='viewer'", (int(time.time())-241,))
        conn.commit()
        conn.close()
        state = self.client.get("/api/v1/commerce/settings").json()
        self.assertFalse(state["syncing"])
        self.assertIn("未完成", state["last_error"])
        self.assertTrue(self.client.get("/api/v1/commerce/overview").json()["stale"])


if __name__ == "__main__":
    unittest.main()
