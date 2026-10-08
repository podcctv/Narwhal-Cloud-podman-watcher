"""HTTP auth boundaries: no Basic challenge, cookies, roles and agent isolation."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from server import app as server, dashboard_auth as auth, operations


class DashboardAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.multiple(server, DB_PATH=str(Path(self.temp.name) / "monitor.db"),
                                         DASHBOARD_USERNAME="test-admin", DASHBOARD_PASSWORD="test-password-only")
        self.patch.start()
        server.init_db()
        self.store = server.app.state.dashboard_sessions
        self.store.records.clear()
        server.app.state.dashboard_login_limiter.records.clear()
        self.client = TestClient(server.app, base_url="https://testserver", follow_redirects=False)

    def tearDown(self):
        self.client.close()
        self.patch.stop()
        self.temp.cleanup()

    def login(self, user="test-admin", password="test-password-only", **extra):
        return self.client.post("/api/v1/auth/login", json={"username": user, "password": password, **extra},
                                headers={"Origin": "https://testserver"})

    def add_user(self, role="viewer"):
        conn = server.db()
        try:
            conn.execute("INSERT INTO ops_users VALUES(?,?,?,1,0)", ("viewer", operations.password_hash("viewer-test-only"), role))
            conn.commit()
        finally:
            conn.close()

    def edit_user(self, field, value):
        conn = server.db()
        try:
            self.assertIn(field, {"password_hash", "enabled", "role"})
            conn.execute(f"UPDATE ops_users SET {field}=? WHERE username='viewer'", (value,))
            conn.commit()
        finally:
            conn.close()

    def test_unauthenticated_page_and_api_never_challenge(self):
        page = self.client.get("/alerts/history?days=2")
        self.assertEqual(page.status_code, 303)
        self.assertEqual(page.headers["location"], "/login?next=%2Falerts%2Fhistory%3Fdays%3D2")
        self.assertNotIn("www-authenticate", page.headers)
        api = self.client.get("/api/v1/latest")
        self.assertEqual(api.status_code, 401)
        self.assertNotIn("www-authenticate", api.headers)
        self.assertEqual(api.headers["cache-control"], "no-store")
        login = self.client.get("/login")
        self.assertEqual(login.status_code, 200)
        self.assertIn("text/html", login.headers["content-type"])
        asset = next(server.ASSETS_DIR.glob("*.css"))
        self.assertEqual(self.client.get("/assets/" + asset.name).status_code, 200)
        self.assertNotEqual(self.client.get("/assets/../../app.py").status_code, 200)

    def test_login_cookie_and_session(self):
        response = self.login(next="/alerts/history?days=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["next"], "/alerts/history?days=2")
        for flag in ("HttpOnly", "Secure", "SameSite=strict", "Max-Age=43200", "Path=/"):
            self.assertIn(flag, response.headers["set-cookie"])
        session = self.client.get("/api/v1/ops/session")
        self.assertEqual(session.json(), {"username": "test-admin", "role": "admin"})
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/login?next=//evil.test").headers["location"], "/")
        self.assertNotIn(self.client.cookies.get(auth.COOKIE), str(self.store.records))

    def test_wrong_password_and_malformed_requests(self):
        response = self.login(password="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("www-authenticate", response.headers)
        for payload in ({}, [], None, {"username": "x", "password": ""}, {"username": "\ud800", "password": "x"}):
            response = self.client.post("/api/v1/auth/login", content=json.dumps(payload),
                                        headers={"Origin": "https://testserver", "Content-Type": "application/json"})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.post("/api/v1/auth/login", content="x" * 8193,
                                         headers={"Origin": "https://testserver", "Content-Type": "application/json"}).status_code, 413)

    def test_cross_site_login_logout_and_mutations_rejected(self):
        for origin in (None, "https://evil.test", "null", "https://testserver.evil.test"):
            headers = {"Origin": origin} if origin else {}
            self.assertEqual(self.client.post("/api/v1/auth/login", json={}, headers=headers).status_code, 403)
        self.login()
        self.assertEqual(self.client.post("/api/v1/auth/logout", headers={"Origin": "https://evil.test"}).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/ops/logs/discover", json={}).status_code, 403)
        self.assertEqual(self.client.get("/api/v1/ops/session").status_code, 200)

    def test_logout_revokes_copied_token(self):
        self.login()
        token = self.client.cookies.get(auth.COOKIE)
        self.assertEqual(self.client.post("/api/v1/auth/logout", headers={"Origin": "https://testserver"}).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/ops/session", headers={"Cookie": f"{auth.COOKIE}={token}"}).status_code, 401)

    def test_legacy_cli_basic_but_not_browser_cached_basic(self):
        header = {"Authorization": "Basic " + base64.b64encode(b"test-admin:test-password-only").decode()}
        self.assertEqual(self.client.get("/api/v1/ops/session", headers=header).status_code, 200)
        header["Sec-Fetch-Mode"] = "navigate"
        self.assertEqual(self.client.get("/", headers=header).status_code, 303)

    def test_database_account_role_changes_and_audit(self):
        self.add_user()
        self.assertEqual(self.login("viewer", "viewer-test-only").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/ops/session").json()["role"], "viewer")
        self.assertEqual(self.client.get("/api/v1/ops/users").status_code, 403)
        self.assertEqual(self.client.post("/api/v1/ops/logs/discover", json={}, headers={"Origin": "https://testserver"}).status_code, 403)
        self.edit_user("role", "admin")
        self.assertEqual(self.client.get("/api/v1/ops/users").status_code, 200)
        conn = server.db()
        try:
            audit = conn.execute("SELECT username,path,status FROM ops_audit").fetchall()
            self.assertEqual(tuple(audit[0]), ("viewer", "/api/v1/ops/logs/discover", 403))
        finally:
            conn.close()

    def test_password_disable_and_env_changes_invalidate_sessions(self):
        self.add_user()
        self.login("viewer", "viewer-test-only")
        self.edit_user("password_hash", operations.password_hash("changed-test-only"))
        self.assertEqual(self.client.get("/api/v1/ops/session").status_code, 401)
        self.login("viewer", "changed-test-only")
        self.edit_user("enabled", 0)
        self.assertEqual(self.client.get("/api/v1/ops/session").status_code, 401)
        self.login()
        with mock.patch.object(server, "DASHBOARD_PASSWORD", "new-test-only"):
            self.assertEqual(self.client.get("/api/v1/ops/session").status_code, 401)

    def test_session_expiration_and_fresh_store(self):
        self.login()
        with mock.patch.object(auth.time, "monotonic", return_value=auth.time.monotonic() + auth.SESSION_SECONDS + 1):
            self.assertEqual(self.client.get("/api/v1/ops/session").status_code, 401)
        self.login()
        self.assertIsNone(auth.SessionStore().get(self.client.cookies.get(auth.COOKIE)))

    def test_agent_paths_keep_their_own_authentication(self):
        for path in server._AGENT_ONLY_PATHS:
            response = self.client.get(path)
            self.assertNotIn(response.status_code, (302, 303, 307))
            self.assertNotIn("www-authenticate", response.headers)
        response = self.client.post("/api/v1/report", json={})
        self.assertEqual(response.status_code, 401)
        self.assertNotEqual(response.json().get("detail"), "登录已过期，请重新登录")

    def test_rate_limit_and_bounded_sessions(self):
        for _ in range(30):
            self.assertEqual(self.login(password="wrong").status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        store = auth.SessionStore()
        first = store.issue(("u", "db", "hash"))
        for _ in range(9):
            store.issue(("u", "db", "hash"))
        self.assertEqual(len(store.records), 8)
        self.assertIsNone(store.get(first))

    def test_forwarded_https_sets_secure_cookie(self):
        client = TestClient(server.app, base_url="http://testserver", follow_redirects=False)
        try:
            response = client.post("/api/v1/auth/login", json={"username": "test-admin", "password": "test-password-only"},
                                   headers={"Origin": "https://testserver", "X-Forwarded-Proto": "https"})
            self.assertEqual(response.status_code, 200)
            self.assertIn("Secure", response.headers["set-cookie"])
        finally:
            client.close()

    def test_safe_next_rejects_external_and_encoded_targets(self):
        for value in ("https://evil.test", "//evil.test", "/%2fevil.test", "/\\evil.test", "/%5cevil.test", "/%0d%0aevil", "/login", None):
            self.assertEqual(auth.safe_next(value), "/")
        self.assertEqual(auth.safe_next("/alerts/history?days=3"), "/alerts/history?days=3")


if __name__ == "__main__":
    unittest.main()
