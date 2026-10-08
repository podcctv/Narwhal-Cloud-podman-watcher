"""Dashboard cookie sessions; agent signatures and bot callbacks stay independent."""
import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from urllib.parse import quote, unquote, urlsplit

from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

try:
    from server import operations
except ImportError:
    import operations

COOKIE = "narwhal_session"
SESSION_SECONDS = 12 * 3600
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def safe_next(value):
    if not isinstance(value, str) or len(value) > 2000:
        return "/"
    decoded = unquote(value)
    if (not value.startswith("/") or decoded.startswith("//")
            or any(ord(c) < 32 or c == "\\" for c in decoded)):
        return "/"
    parts = urlsplit(value)
    if parts.netloc or parts.scheme or parts.path in {"/login", "/api/v1/auth/logout"}:
        return "/"
    return value


class SessionStore:
    def __init__(self):
        self.records = OrderedDict()
        self.lock = threading.Lock()
        self.pepper = secrets.token_bytes(32)

    def stamp(self, value):
        return hmac.new(self.pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def prune(self):
        now = time.monotonic()
        for key, (_, expires) in list(self.records.items()):
            if expires <= now:
                self.records.pop(key, None)

    def issue(self, account):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.prune()
            matching = [key for key, (saved, _) in self.records.items() if saved[:2] == account[:2]]
            for key in matching[:-7]:
                self.records.pop(key, None)
            while len(self.records) >= 4096:
                self.records.popitem(last=False)
            self.records[self.key(token)] = (account, time.monotonic() + SESSION_SECONDS)
        return token

    @staticmethod
    def key(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def get(self, token):
        if not token or len(token) > 128:
            return None
        with self.lock:
            self.prune()
            record = self.records.get(self.key(token))
            return record[0] if record else None

    def revoke(self, token):
        if token and len(token) <= 128:
            with self.lock:
                self.records.pop(self.key(token), None)


class LoginLimiter:
    """Bounded per-connection-peer budget, without trusting spoofable forwarding headers."""
    def __init__(self):
        self.records = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, peer):
        key = hashlib.sha256(peer.encode()).digest()
        now = time.monotonic()
        with self.lock:
            for old, (start, _) in list(self.records.items()):
                if now - start >= 60:
                    self.records.pop(old, None)
            start, count = self.records.get(key, (now, 0))
            if count >= 30:
                return False
            if key not in self.records and len(self.records) >= 4096:
                self.records.popitem(last=False)
            self.records[key] = (start, count + 1)
        return True


def attach(app, db, credentials, agent_paths, callback_prefix, static_dir):
    sessions, limiter = SessionStore(), LoginLimiter()
    app.state.dashboard_sessions = sessions
    app.state.dashboard_login_limiter = limiter

    def error(status, detail):
        # Deliberately no WWW-Authenticate: browser-native login dialogs are retired.
        return JSONResponse({"detail": detail}, status_code=status, headers={"Cache-Control": "no-store"})

    def scheme(request):
        # Caddy terminates TLS and overwrites X-Forwarded-Proto. Keep the backend
        # loopback-only, as configured by the installer, instead of exposing it.
        return "https" if request.headers.get("x-forwarded-proto") == "https" else request.url.scheme

    def same_origin(request):
        return request.headers.get("origin", "") == f"{scheme(request)}://{request.headers.get('host', '')}"

    def env_match(username, password):
        name, secret = credentials()
        return (bool(name and secret)
                and hmac.compare_digest(username.encode(), name.encode())
                and hmac.compare_digest(password.encode(), secret.encode()))

    def resolve(username, password):
        name, secret = credentials()
        if env_match(username, password):
            return (username, "env", sessions.stamp(name + "\0" + secret)), "admin"
        conn = db()
        try:
            auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
            account = operations.authenticate(conn, auth)
            if account:
                row = conn.execute("SELECT password_hash FROM ops_users WHERE username=?", (username,)).fetchone()
                return (username, "db", sessions.stamp(row[0])), account[1]
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
        return None

    def validate(token):
        account = sessions.get(token)
        if not account:
            return None
        username, source, stamp = account
        if source == "env":
            name, secret = credentials()
            if name and secret and username == name and hmac.compare_digest(stamp, sessions.stamp(name + "\0" + secret)):
                return username, "admin"
        else:
            conn = db()
            try:
                row = conn.execute("SELECT password_hash,role,enabled FROM ops_users WHERE username=?", (username,)).fetchone()
                if row and row[2] and hmac.compare_digest(stamp, sessions.stamp(row[0])):
                    return username, row[1]
            finally:
                conn.close()
        sessions.revoke(token)
        return None

    @app.middleware("http")
    async def dashboard_session_auth(request, call_next):
        path = request.url.path
        if path in agent_paths or path.startswith(callback_prefix):
            return await call_next(request)
        if (path in {"/login", "/api/v1/auth/login", "/api/v1/auth/logout"}
                or (path.startswith("/assets/") and request.method in {"GET", "HEAD"})):
            return await call_next(request)
        token = request.cookies.get(COOKIE, "")
        account = validate(token)
        cookie_auth = bool(account)
        # Preemptive Basic remains available for CLI integrations, not browser caches.
        if not account and "sec-fetch-mode" not in request.headers:
            auth = request.headers.get("authorization", "")
            if auth.startswith("Basic "):
                try:
                    user, password = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)
                    found = await asyncio.to_thread(resolve, user, password)
                    if found:
                        account = found[0][0], found[1]
                except (ValueError, UnicodeError):
                    pass
        if not account:
            if request.method in {"GET", "HEAD"} and not path.startswith("/api/"):
                target = safe_next(path + ("?" + request.url.query if request.url.query else ""))
                return RedirectResponse("/login?next=" + quote(target, safe=""), status_code=303,
                                        headers={"Cache-Control": "no-store"})
            return error(401, "登录已过期，请重新登录")
        if cookie_auth and request.method not in SAFE_METHODS and not same_origin(request):
            return error(403, "请求来源无效，请刷新页面后重试")
        username, role = account
        request.state.dashboard_user, request.state.dashboard_role = username, role
        allowed = operations.permitted(role, request.method, path)
        response = await call_next(request) if allowed else error(403, "当前角色无此操作权限")
        response.headers["Cache-Control"] = "no-store"
        if request.method not in SAFE_METHODS:
            conn = db()
            try:
                # Never record bodies, queries, auth headers, tokens or passwords.
                conn.execute("INSERT INTO ops_audit(ts,username,method,path,status) VALUES(?,?,?,?,?)",
                             (int(time.time()), username, request.method, path[:500], response.status_code))
                conn.commit()
            finally:
                conn.close()
        return response

    @app.api_route("/login", methods=["GET", "HEAD"])
    async def login_page(request: Request):
        if validate(request.cookies.get(COOKIE, "")):
            return RedirectResponse(safe_next(request.query_params.get("next", "/")), status_code=303,
                                    headers={"Cache-Control": "no-store"})
        return FileResponse(static_dir / "index.html", headers={"Cache-Control": "no-store"})

    @app.post("/api/v1/auth/login")
    async def login(request: Request):
        if not same_origin(request):
            return error(403, "请求来源无效，请刷新页面后重试")
        if not limiter.allow(request.client.host if request.client else "unknown"):
            response = error(429, "登录尝试过于频繁，请一分钟后重试")
            response.headers["Retry-After"] = "60"
            return response
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return error(400, "请使用 JSON 登录请求")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 8192:
                return error(413, "登录请求过大")
        try:
            payload = json.loads(body)
            username, password = payload["username"], payload["password"]
            if (not isinstance(username, str) or not 1 <= len(username) <= 128 or ":" in username
                    or not isinstance(password, str) or not 1 <= len(password) <= 4096):
                raise ValueError()
            username.encode("utf-8")
            password.encode("utf-8")
        except (ValueError, TypeError, KeyError):
            return error(400, "请输入有效的用户名和密码")
        found = await asyncio.to_thread(resolve, username, password)
        if not found:
            return error(401, "用户名或密码不正确")
        account, role = found
        sessions.revoke(request.cookies.get(COOKIE, ""))
        response = JSONResponse({"username": username, "role": role, "next": safe_next(payload.get("next", "/"))},
                                headers={"Cache-Control": "no-store"})
        response.set_cookie(COOKIE, sessions.issue(account), max_age=SESSION_SECONDS, path="/",
                            secure=scheme(request) == "https", httponly=True, samesite="strict")
        return response

    @app.post("/api/v1/auth/logout")
    async def logout(request: Request):
        if not same_origin(request):
            return error(403, "请求来源无效，请刷新页面后重试")
        sessions.revoke(request.cookies.get(COOKIE, ""))
        response = JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})
        response.delete_cookie(COOKIE, path="/", secure=scheme(request) == "https", httponly=True, samesite="strict")
        return response
