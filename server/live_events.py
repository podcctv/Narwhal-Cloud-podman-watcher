"""Lightweight authenticated SSE event bus using asyncio and zero external dependencies."""
import asyncio
import json
import threading
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

KEEPALIVE_SECONDS = 25.0


class _EventStreamingResponse(StreamingResponse):
    """StreamingResponse that guarantees generator close and subscriber cleanup."""

    def __init__(self, *args: Any, on_close: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._on_close = on_close

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            aclose = getattr(self.body_iterator, "aclose", None)
            if callable(aclose):
                try:
                    await aclose()
                except Exception:
                    pass
            if callable(self._on_close):
                self._on_close()


class LiveEventBus:
    """Thread-safe in-memory pub/sub bus delivering bounded events to SSE subscribers."""

    def __init__(self, max_subscribers: int = 64) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._subscribers: set[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = set()
        self._max_subscribers = max(1, int(max_subscribers))

    @staticmethod
    def _enqueue_drop_oldest(queue: asyncio.Queue[dict[str, Any]], event: dict[str, Any]) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    def current_seq(self) -> int:
        with self._lock:
            return self._seq

    def publish(self, topic: str, host_id: str = "", detail: dict | None = None) -> int:
        with self._lock:
            self._seq += 1
            seq = self._seq
            subscribers = list(self._subscribers)

        event: dict[str, Any] = {
            "seq": seq,
            "topic": str(topic or "")[:32],
            "host_id": str(host_id or "")[:200],
            "ts": int(time.time()),
        }
        if isinstance(detail, dict):
            event["detail"] = dict(detail)

        dead: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = []
        for sub in subscribers:
            loop, queue = sub
            try:
                if loop.is_closed():
                    dead.append(sub)
                    continue
                loop.call_soon_threadsafe(self._enqueue_drop_oldest, queue, event)
            except RuntimeError:
                dead.append(sub)

        if dead:
            with self._lock:
                self._subscribers.difference_update(dead)

        return seq

    def subscribe(self) -> tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]:
        loop = asyncio.get_running_loop()
        with self._lock:
            closed = [
                sub
                for sub in self._subscribers
                if getattr(sub[0], "is_closed", lambda: False)()
            ]
            for sub in closed:
                self._subscribers.discard(sub)
            if len(self._subscribers) >= self._max_subscribers:
                raise HTTPException(status_code=503, detail="SSE 订阅连接已达上限")
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
            sub = (loop, queue)
            self._subscribers.add(sub)
            return sub

    def unsubscribe(self, sub: tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]] | None) -> None:
        if sub is None:
            return
        with self._lock:
            self._subscribers.discard(sub)

    def active_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def reset(self) -> None:
        with self._lock:
            self._seq = 0
            self._subscribers.clear()


_enqueue_drop_oldest = LiveEventBus._enqueue_drop_oldest
bus = LiveEventBus()


def _update_sse_gauge(metrics_collector: Any) -> None:
    if metrics_collector is not None:
        metrics_collector.set_gauge("sse_active_connections", bus.active_count())


def attach(app: FastAPI, metrics_collector: Any = None) -> None:
    """Register the authenticated SSE live-events stream endpoint."""

    @app.get("/api/v1/events/stream")
    async def events_stream(request: Request, once: bool = False):
        sub = bus.subscribe()
        _update_sse_gauge(metrics_collector)

        def cleanup() -> None:
            bus.unsubscribe(sub)
            _update_sse_gauge(metrics_collector)

        async def event_stream():
            try:
                seq = bus.current_seq()
                ready_json = json.dumps(
                    {"seq": seq, "ts": int(time.time())},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                yield f"event: ready\nid: {seq}\ndata: {ready_json}\n\n"
                if once:
                    return
                queue = sub[1]
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_SECONDS)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            break
                        yield ": keepalive\n\n"
                        continue
                    event_seq = event.get("seq", "")
                    event_json = json.dumps(
                        event,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        default=str,
                    )
                    yield f"event: update\nid: {event_seq}\ndata: {event_json}\n\n"
            finally:
                cleanup()

        return _EventStreamingResponse(
            event_stream(),
            on_close=cleanup,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
