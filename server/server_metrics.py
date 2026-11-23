"""In-memory server self-observability metrics and pure ASGI middlewares."""
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import os
import re
import threading
import time
from typing import Any

from starlette.middleware.gzip import GZipMiddleware

SLOW_REQUEST_MS = max(10.0, float(os.getenv("SERVER_SLOW_REQUEST_MS", "250")))

_UUID_RE = re.compile(
    r"(?<=/)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$)"
)
_NUMERIC_ID_RE = re.compile(r"(?<=/)\d+(?=/|$)")

_DEFAULT_COUNTERS = (
    "idle_poll_readonly_hits",
    "idle_poll_write_hits",
    "admission_readonly_hits",
    "admission_write_hits",
    "etag_304_hits",
    "sse_events_published",
)
_DEFAULT_GAUGES = ("sse_active_connections",)


def normalize_route_path(path: str) -> str:
    """Normalize HTTP request path to bound metric cardinality and redact secrets."""
    raw = str(path or "/").split("?", 1)[0].strip() or "/"
    if not raw.startswith("/"):
        raw = "/" + raw

    if raw.startswith("/api/v1/notifications/telegram/"):
        return "/api/v1/notifications/telegram/{bot_id}/{secret}"
    if raw.startswith("/assets/"):
        return "/assets/{file}"
    if raw.startswith("/api/v1/reachability/host/"):
        return "/api/v1/reachability/host/{host_id}"

    if raw.startswith("/api/v1/hosts/"):
        if re.fullmatch(r"/api/v1/hosts/.+/firewall-policy", raw):
            raw = "/api/v1/hosts/{host_id}/firewall-policy"
        elif re.fullmatch(r"/api/v1/hosts/.+/firewall-rules/[^/]+", raw):
            raw = "/api/v1/hosts/{host_id}/firewall-rules/{id}"
        else:
            raw = re.sub(r"^/api/v1/hosts/[^/]+(/.*)?$", r"/api/v1/hosts/{host_id}\1", raw)
    elif raw.startswith("/api/v1/ops/hosts/"):
        raw = re.sub(r"^/api/v1/ops/hosts/[^/]+(/.*)?$", r"/api/v1/ops/hosts/{host_id}\1", raw)
    elif raw.startswith("/api/v1/ops/backups/"):
        raw = re.sub(r"^/api/v1/ops/backups/[^/]+/drill$", "/api/v1/ops/backups/{name}/drill", raw)
    elif raw.startswith("/api/v1/ops/upgrades/"):
        raw = re.sub(
            r"^/api/v1/ops/upgrades/[^/]+/([^/]+)/retry$",
            "/api/v1/ops/upgrades/{id}/{host_id}/retry",
            raw,
        )
    elif raw.startswith("/api/v1/ops/users/"):
        raw = re.sub(r"^/api/v1/ops/users/[^/]+$", "/api/v1/ops/users/{username}", raw)
    elif raw.startswith("/api/v1/security/user-notices/"):
        raw = re.sub(
            r"^/api/v1/security/user-notices/[^/]+/retry$",
            "/api/v1/security/user-notices/{id}/retry",
            raw,
        )

    raw = _UUID_RE.sub("{id}", raw)
    raw = _NUMERIC_ID_RE.sub("{id}", raw)
    return raw[:200]


def _percentile(sorted_samples: list[float], q: float) -> float:
    n = len(sorted_samples)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_samples[0]
    pos = (n - 1) * q
    lo = int(pos)
    hi = min(n - 1, lo + 1)
    frac = pos - lo
    return sorted_samples[lo] + (sorted_samples[hi] - sorted_samples[lo]) * frac


@dataclass
class _RouteStats:
    samples: deque[float] = field(default_factory=lambda: deque(maxlen=256))
    count: int = 0
    error_count: int = 0
    status_304_count: int = 0
    slow_count: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0


class ServerMetrics:
    """Thread-safe bounded in-memory request latency, counter, and gauge store."""

    def __init__(self, slow_threshold_ms: float | None = None, max_routes: int = 128) -> None:
        self._lock = threading.Lock()
        self._explicit_threshold = float(slow_threshold_ms) if slow_threshold_ms is not None else None
        self._max_routes = max(1, int(max_routes))
        self._started_at = int(time.time())
        self._started_monotonic = time.monotonic()
        self._total_requests = 0
        self._slow_request_count = 0
        self._routes: OrderedDict[tuple[str, str], _RouteStats] = OrderedDict()
        self._recent_slow_requests: deque[dict[str, Any]] = deque(maxlen=50)
        self._counters: dict[str, int] = {name: 0 for name in _DEFAULT_COUNTERS}
        self._gauges: dict[str, int | float] = {name: 0 for name in _DEFAULT_GAUGES}

    def _threshold_ms(self) -> float:
        return self._explicit_threshold if self._explicit_threshold is not None else SLOW_REQUEST_MS

    def record_request(self, method: str, path: str, status_code: int, duration_ms: float) -> None:
        method_norm = str(method or "GET").upper()[:16]
        path_norm = normalize_route_path(path)
        status = int(status_code)
        ms = max(0.0, float(duration_ms))
        threshold = self._threshold_ms()
        key = (method_norm, path_norm)
        now_ts = int(time.time())

        with self._lock:
            self._total_requests += 1
            entry = self._routes.get(key)
            if entry is None:
                if len(self._routes) >= self._max_routes:
                    self._routes.popitem(last=False)
                entry = _RouteStats()
                self._routes[key] = entry
            else:
                self._routes.move_to_end(key)

            entry.samples.append(ms)
            entry.count += 1
            if status >= 500:
                entry.error_count += 1
            if status == 304:
                entry.status_304_count += 1
            entry.total_ms += ms
            if ms > entry.max_ms:
                entry.max_ms = ms

            if ms >= threshold:
                entry.slow_count += 1
                self._slow_request_count += 1
                self._recent_slow_requests.append(
                    {
                        "ts": now_ts,
                        "method": method_norm,
                        "path": path_norm,
                        "status_code": status,
                        "duration_ms": round(ms, 2),
                    }
                )

    def inc(self, name: str, delta: int = 1) -> int:
        key = str(name or "")[:64]
        if not key:
            return 0
        with self._lock:
            if key not in self._counters and len(self._counters) >= 64:
                return 0
            val = self._counters.get(key, 0) + int(delta)
            self._counters[key] = val
            return val

    def set_gauge(self, name: str, value: int | float) -> None:
        key = str(name or "")[:64]
        if not key:
            return
        with self._lock:
            if key not in self._gauges and len(self._gauges) >= 64:
                return
            self._gauges[key] = value

    def reset(self) -> None:
        with self._lock:
            self._started_at = int(time.time())
            self._started_monotonic = time.monotonic()
            self._total_requests = 0
            self._slow_request_count = 0
            self._routes.clear()
            self._recent_slow_requests.clear()
            self._counters = {name: 0 for name in _DEFAULT_COUNTERS}
            self._gauges = {name: 0 for name in _DEFAULT_GAUGES}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = round(max(0.0, time.monotonic() - self._started_monotonic), 2)
            started_at = self._started_at
            threshold = round(self._threshold_ms(), 2)
            total_requests = self._total_requests
            slow_request_count = self._slow_request_count
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            route_items = []
            for (method, path), entry in self._routes.items():
                ordered = sorted(entry.samples)
                p50 = _percentile(ordered, 0.50)
                p95 = _percentile(ordered, 0.95)
                avg = entry.total_ms / entry.count if entry.count else 0.0
                route_items.append(
                    {
                        "method": method,
                        "path": path,
                        "count": entry.count,
                        "error_count": entry.error_count,
                        "status_304_count": entry.status_304_count,
                        "slow_count": entry.slow_count,
                        "p50_ms": round(p50, 2),
                        "p95_ms": round(p95, 2),
                        "avg_ms": round(avg, 2),
                        "max_ms": round(entry.max_ms, 2),
                    }
                )
            route_items.sort(key=lambda item: (item["p95_ms"], item["count"], item["max_ms"]), reverse=True)
            recent_slow = list(reversed(self._recent_slow_requests))[:25]

        return {
            "uptime_seconds": uptime,
            "started_at": started_at,
            "slow_threshold_ms": threshold,
            "total_requests": total_requests,
            "slow_request_count": slow_request_count,
            "counters": counters,
            "gauges": gauges,
            "routes": route_items[:40],
            "recent_slow_requests": recent_slow,
        }


metrics = ServerMetrics()


class MetricsMiddleware:
    """Pure ASGI middleware recording HTTP route timings while skipping SSE streams."""

    def __init__(self, app: Any, metrics_collector: ServerMetrics | None = None) -> None:
        self.app = app
        self._metrics = metrics_collector if metrics_collector is not None else metrics

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or "/"
        if path == "/api/v1/events/stream":
            await self.app(scope, receive, send)
            return

        method = scope.get("method") or "GET"
        status_code = 500
        start = time.perf_counter()

        async def send_wrapper(message: Any) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._metrics.record_request(method, path, status_code, elapsed_ms)


class SelectiveGZipMiddleware:
    """Pure ASGI GZip wrapper that passes SSE streams and excluded paths through uncompressed."""

    def __init__(
        self,
        app: Any,
        excluded_paths: tuple[str, ...] | list[str] | set[str] = (),
        minimum_size: int = 1024,
        compresslevel: int = 5,
    ) -> None:
        self.app = app
        self.excluded_paths = set(excluded_paths or ())
        self.excluded_paths.add("/api/v1/events/stream")
        self._gzip = GZipMiddleware(
            app,
            minimum_size=minimum_size,
            compresslevel=compresslevel,
        )

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        if path in self.excluded_paths:
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers") or ():
            key = name.decode("latin-1").lower() if isinstance(name, (bytes, bytearray)) else str(name).lower()
            if key == "accept":
                val = value.decode("latin-1").lower() if isinstance(value, (bytes, bytearray)) else str(value).lower()
                if "text/event-stream" in val:
                    await self.app(scope, receive, send)
                    return
        await self._gzip(scope, receive, send)
