"""Telegram bot alerting, webhook delivery, interactive callback, and broadcast service."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import http.client
import json
import logging
import re
import secrets
import socket
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

try:
    from server import connection_policy
except ImportError:
    import connection_policy  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

_app: Any = None
_service: "TelegramService | None" = None


class TelegramService:
    """Telegram notification and interactive console logic bound to an app module."""

    def __init__(self, app_mod: Any) -> None:
        self._app = app_mod

    def send_alert_webhook(self, alert: Dict[str, Any]) -> None:
        webhook_url = self._app.ALERT_WEBHOOK_URL
        if not webhook_url:
            return
        severity = str(alert.get("severity") or "warning")
        severity_rank = self._app._SEVERITY_RANK
        if severity_rank.get(severity, 0) < severity_rank.get(self._app.ALERT_WEBHOOK_MIN_SEVERITY, 1):
            return
        payload = json.dumps({"event": "narwhal.security_alert", "alert": alert}, ensure_ascii=False).encode()
        request = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read(1)
        except Exception as exc:
            print(f"alert webhook failed: {exc}")

    def _notification_bot_item(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Return a dashboard-safe notification profile; bot tokens never leave the server."""
        return {
            "id": int(row["id"]),
            "name": str(row["name"]),
            "kind": str(row["kind"]),
            "target": str(row["target"]),
            "min_severity": str(row["min_severity"]),
            "enabled": bool(row["enabled"]),
            "token_configured": bool(row["token"]),
            "created_at_utc8": self._app.format_utc8(int(row["created_at"])),
            "updated_at_utc8": self._app.format_utc8(int(row["updated_at"])),
            "last_delivery_status": str(row["last_delivery_status"]),
            "last_delivery_error": str(row["last_delivery_error"]),
            "last_sent_at_utc8": self._app.format_utc8(int(row["last_sent_at"])) if int(row["last_sent_at"]) else "",
        }

    def _telegram_api_call(self, token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload, ensure_ascii=False).encode()
        proxy_url = self._app.get_telegram_proxy_url()
        proxy_scheme = urllib.parse.urlsplit(proxy_url).scheme.lower() if proxy_url else ""
        if proxy_scheme in ("socks5", "socks5h"):
            try:
                result = self._app._telegram_api_socks5(token, method, data, proxy_url)
            except Exception as exc:
                raise RuntimeError(f"Telegram SOCKS5 代理连接失败：{exc}") from exc
            if not result.get("ok"):
                raise RuntimeError(str(result.get("description") or "Telegram rejected the request"))
            return result
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
            method="POST",
        )
        try:
            if proxy_url:
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
                )
                response_context = opener.open(request, timeout=10)
            else:
                response_context = urllib.request.urlopen(request, timeout=10)
            with response_context as response:
                result = json.loads(response.read(1024 * 1024).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(1024 * 1024).decode("utf-8")).get("description")
            except Exception:
                detail = ""
            raise RuntimeError(str(detail or f"Telegram HTTP {exc.code}")) from exc
        except urllib.error.URLError as exc:
            if proxy_url:
                raise RuntimeError(f"Telegram 代理连接失败：{exc.reason}") from exc
            try:
                result = self._app._telegram_api_ipv4(token, method, data)
            except Exception as ipv4_exc:
                raise RuntimeError(
                    f"Telegram 网络不可达（常规连接：{exc.reason}；IPv4 回退：{ipv4_exc}）。"
                    "请检查 Server 容器出站网络，或配置 TELEGRAM_PROXY_URL。"
                ) from ipv4_exc
        if not result.get("ok"):
            raise RuntimeError(str(result.get("description") or "Telegram rejected the request"))
        return result

    def _telegram_api(self, token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self._app._telegram_api_call(token, method, payload)
        except RuntimeError as exc:
            err_msg = str(exc).lower()
            if ("can't parse entities" in err_msg or "entity" in err_msg) and payload.get("parse_mode"):
                fallback_payload = dict(payload)
                fallback_payload.pop("parse_mode", None)
                raw_text = str(fallback_payload.get("text") or "")
                fallback_payload["text"] = re.sub(r"<[^>]+>", "", raw_text)
                try:
                    return self._app._telegram_api_call(token, method, fallback_payload)
                except Exception:
                    pass
            raise

    def _telegram_api_socks5(self, token: str, method: str, data: bytes, proxy_url: str) -> Dict[str, Any]:
        socks_mod = self._app.socks
        if socks_mod is None:
            raise RuntimeError(
                "PySocks 未安装，无法使用 SOCKS5 代理。请运行 pip install PySocks 或配置 HTTP/HTTPS 代理。"
            )
        parsed = urllib.parse.urlsplit(proxy_url)
        if not parsed.hostname:
            raise ValueError("代理地址缺少主机名")
        proxy_rdns = True
        proxy_sock = socks_mod.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            proxy_sock.set_proxy(
                socks_mod.SOCKS5,
                parsed.hostname,
                parsed.port or 1080,
                rdns=proxy_rdns,
                username=urllib.parse.unquote(parsed.username) if parsed.username else None,
                password=urllib.parse.unquote(parsed.password) if parsed.password else None,
            )
            proxy_sock.settimeout(10)
            proxy_sock.connect(("api.telegram.org", 443))
            tls_sock = ssl.create_default_context().wrap_socket(proxy_sock, server_hostname="api.telegram.org")
            conn = http.client.HTTPSConnection("api.telegram.org", 443, timeout=10)
            conn.sock = tls_sock
            conn.request(
                "POST",
                f"/bot{token}/{method}",
                body=data,
                headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
            )
            response = conn.getresponse()
            body = response.read(1024 * 1024)
            conn.close()
            result = json.loads(body.decode("utf-8"))
            if response.status >= 400:
                raise RuntimeError(str(result.get("description") or f"Telegram HTTP {response.status}"))
            return result
        except Exception:
            try:
                proxy_sock.close()
            except Exception:
                pass
            raise

    def _telegram_api_ipv4(self, token: str, method: str, data: bytes) -> Dict[str, Any]:
        host = "api.telegram.org"
        last_error: Exception | None = None
        for family, socktype, proto, _, sockaddr in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
            raw_sock = socket.socket(family, socktype, proto)
            try:
                raw_sock.settimeout(8)
                raw_sock.connect(sockaddr)
                tls_sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
                conn = http.client.HTTPSConnection(host, 443, timeout=8)
                conn.sock = tls_sock
                conn.request(
                    "POST",
                    f"/bot{token}/{method}",
                    body=data,
                    headers={"Content-Type": "application/json", "User-Agent": "Narwhal-Container-Monitor/1.0"},
                )
                response = conn.getresponse()
                body = response.read(1024 * 1024)
                conn.close()
                result = json.loads(body.decode("utf-8"))
                if response.status >= 400:
                    raise RuntimeError(str(result.get("description") or f"Telegram HTTP {response.status}"))
                return result
            except Exception as exc:
                last_error = exc
                try:
                    raw_sock.close()
                except Exception:
                    pass
        raise RuntimeError(str(last_error or "没有可用的 Telegram IPv4 地址"))

    def _record_bot_delivery(self, bot_id: int, succeeded: bool, error: str = "") -> None:
        conn = self._app.db()
        try:
            conn.execute(
                "UPDATE notification_bots SET last_delivery_status=?, last_delivery_error=?, last_sent_at=? WHERE id=?",
                (
                    "succeeded" if succeeded else "failed",
                    "" if succeeded else str(error)[:1000],
                    int(time.time()) if succeeded else 0,
                    bot_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _telegram_chat_allowed(self, bot: sqlite3.Row, chat: Dict[str, Any]) -> bool:
        target, _ = self._app._parse_telegram_target(str(bot["target"] or "").strip())
        chat_id = str(chat.get("id") or "")
        username = str(chat.get("username") or "").strip().lower()
        if target.startswith("@"):
            return bool(username) and username == target[1:].lower()
        return bool(chat_id) and hmac.compare_digest(chat_id, target)

    def _telegram_active_alerts(
        self, severity: str = "all", offset: int = 0, limit: int = 5
    ) -> tuple[List[sqlite3.Row], int]:
        conn = self._app.db()
        try:
            where = "status='active'"
            params: List[Any] = []
            if severity in ("critical", "warning", "info"):
                where += " AND severity=?"
                params.append(severity)
            total = int(conn.execute(f"SELECT COUNT(*) FROM security_alerts WHERE {where}", params).fetchone()[0])
            rows = conn.execute(
                f"SELECT * FROM security_alerts WHERE {where} ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END DESC, last_seen DESC LIMIT ? OFFSET ?",
                (*params, limit, max(0, offset)),
            ).fetchall()
            return rows, total
        finally:
            conn.close()

    def _telegram_actionable(self, alert: sqlite3.Row) -> bool:
        if alert["runtime"] not in ("podman", "incus", "runman"):
            return False
        if alert["alert_type"] not in ("unauthorized_panel_pairing", "socks_weak_auth", "malicious_process"):
            return False
        details = self._app._alert_action_evidence(alert)
        if alert["runtime"] == "runman":
            if (
                alert["alert_type"] not in ("unauthorized_panel_pairing", "malicious_process")
                or not re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    details.get("instance_id", ""),
                )
                or not (details.get("process_targets") or details.get("file_targets"))
            ):
                return False
        if alert["alert_type"] == "unauthorized_panel_pairing":
            return bool(details.get("process_patterns") or details.get("config_files"))
        if alert["alert_type"] == "socks_weak_auth":
            return details.get("socks_auth_mode") in ("no_auth", "weak_password") and bool(
                details.get("socks_processes")
            )
        has_xmrig = any(
            isinstance(item, dict) and item.get("process") == "xmrig"
            for item in details.get("malicious_processes", [])
        )
        if alert["runtime"] == "runman":
            has_xmrig = has_xmrig and any(
                item.get("process") == "xmrig"
                and item.get("pattern") == "xmrig"
                and re.fullmatch(r"[0-9]{1,24}", item.get("start_ticks", ""))
                for item in details.get("process_targets", [])
            )
        return has_xmrig

    def _telegram_menu(self) -> tuple[str, Dict[str, Any]]:
        conn = self._app.db()
        try:
            counts = {
                row["severity"]: int(row["count"])
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS count FROM security_alerts WHERE status='active' GROUP BY severity"
                ).fetchall()
            }
        finally:
            conn.close()
        total = sum(counts.values())
        text = (
            "<b>Narwhal 告警控制台</b>\n"
            f"活动告警：<b>{total}</b>\n"
            f"严重：<b>{counts.get('critical', 0)}</b>　警告：<b>{counts.get('warning', 0)}</b>　信息：<b>{counts.get('info', 0)}</b>\n\n"
            "请选择要查看的范围。"
        )
        keyboard = {
            "inline_keyboard": [
                [{"text": f"全部活动告警 ({total})", "callback_data": "n:l:all:0"}],
                [
                    {"text": f"严重 ({counts.get('critical', 0)})", "callback_data": "n:l:critical:0"},
                    {"text": f"警告 ({counts.get('warning', 0)})", "callback_data": "n:l:warning:0"},
                ],
                [{"text": "刷新", "callback_data": "n:m"}],
            ]
        }
        return text, keyboard

    def _telegram_alert_list(self, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
        severity = severity if severity in ("all", "critical", "warning", "info") else "all"
        offset = max(0, offset)
        rows, total = self._app._telegram_active_alerts(severity, offset)
        label = {"all": "全部", "critical": "严重", "warning": "警告", "info": "信息"}[severity]
        text = f"<b>{label}活动告警</b>\n共 {total} 条，第 {offset + 1 if total else 0}-{min(offset + len(rows), total)} 条。"
        buttons: List[List[Dict[str, str]]] = []
        severity_label = {"critical": "严重", "warning": "警告", "info": "信息"}
        for row in rows:
            title = str(row["title"] or row["alert_type"] or "告警")
            buttons.append(
                [
                    {
                        "text": f"{severity_label.get(row['severity'], '告警')} #{row['id']} {title[:26]}",
                        "callback_data": f"n:d:{row['id']}:{severity}:{offset}",
                    }
                ]
            )
        nav: List[Dict[str, str]] = []
        if offset > 0:
            nav.append({"text": "上一页", "callback_data": f"n:l:{severity}:{max(0, offset - 5)}"})
        if offset + len(rows) < total:
            nav.append({"text": "下一页", "callback_data": f"n:l:{severity}:{offset + 5}"})
        if nav:
            buttons.append(nav)
        buttons.append(
            [
                {"text": "刷新", "callback_data": f"n:l:{severity}:{offset}"},
                {"text": "返回主菜单", "callback_data": "n:m"},
            ]
        )
        return text, {"inline_keyboard": buttons}

    def _telegram_alert_detail(self, alert_id: int, severity: str, offset: int) -> tuple[str, Dict[str, Any]]:
        conn = self._app.db()
        try:
            alert = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchone()
        finally:
            conn.close()
        if alert is None:
            return "该告警不存在或已被清理。", {
                "inline_keyboard": [[{"text": "返回列表", "callback_data": f"n:l:{severity}:{offset}"}]]
            }
        scope = "/".join(x for x in (str(alert["runtime"] or ""), str(alert["project"] or "")) if x) or "-"
        raw_message = str(alert["message"] or "")[:1000]
        text = (
            f"<b>{html.escape(str(alert['title'] or alert['alert_type']))}</b>\n"
            f"事件：<code>NW-{alert['id']}-{alert['first_seen']}</code>\n"
            f"状态：<b>{html.escape(str(alert['status']))}</b>　级别：<b>{html.escape(str(alert['severity']))}</b>\n"
            f"主机：<code>{html.escape(str(alert['host_id']))}</code>\n"
            f"容器：<code>{html.escape(scope)} {html.escape(str(alert['container_name'] or '-'))}</code>\n"
            f"出现次数：{int(alert['occurrence_count'])}\n"
            f"最近出现：{self._app.format_utc8(int(alert['last_seen']))}\n\n"
            f"{html.escape(raw_message)}"
        )
        buttons: List[List[Dict[str, str]]] = []
        public_base_url = self._app.PUBLIC_BASE_URL
        if alert["alert_type"] == "prohibited_activity":
            text += "\n\n请先通过宿主机控制台排查，再由网页管理员复核解除隔离。解除不等于风险已恢复。"
            if public_base_url:
                buttons.append([{"text": "打开管理员隔离面板", "url": public_base_url.rstrip("/") + "/"}])
        elif alert["status"] == "active":
            buttons.append(
                [
                    {"text": "本次忽略", "callback_data": f"n:c:{alert_id}:dismiss_once:{severity}:{offset}"},
                    {"text": "标记已处理", "callback_data": f"n:c:{alert_id}:resolve:{severity}:{offset}"},
                ]
            )
            buttons.append([{"text": "永久不再提醒", "callback_data": f"n:c:{alert_id}:allow_silent:{severity}:{offset}"}])
            if self._app._telegram_actionable(alert):
                buttons.append([{"text": "定向处置", "callback_data": f"n:c:{alert_id}:deny:{severity}:{offset}"}])
        buttons.append(
            [
                {"text": "返回列表", "callback_data": f"n:l:{severity}:{offset}"},
                {"text": "主菜单", "callback_data": "n:m"},
            ]
        )
        return text, {"inline_keyboard": buttons}

    async def _telegram_apply_decision(self, alert_id: int, decision: str, bot_id: int) -> str:
        class TelegramRequest:
            def __init__(self) -> None:
                self.state = type("State", (), {"dashboard_user": f"telegram:{bot_id}"})()

            async def json(self) -> Dict[str, str]:
                return {"decision": decision}

        response = await self._app.set_security_alert_disposition(alert_id, TelegramRequest())
        body = json.loads(response.body)
        if decision == "deny":
            return "定向处置已排队，等待节点执行。" if body.get("queued") else "已有相同处置正在执行。"
        return {
            "dismiss_once": "已忽略本次告警。",
            "resolve": "已标记为已处理。",
            "allow_silent": "已设置为永久不再提醒。",
        }.get(decision, "处理完成。")

    def _telegram_confirm(
        self, alert_id: int, decision: str, severity: str, offset: int
    ) -> tuple[str, Dict[str, Any]]:
        descriptions = {
            "dismiss_once": "只隐藏本次连续事件；以后再次发生仍会提醒。",
            "resolve": "将当前记录标记为已处理；若风险仍存在，下次上报会重新出现。",
            "allow_silent": "永久抑制此告警指纹，并可能同步放行节点策略。",
            "deny": "向节点下发定向处置动作，仅处理告警明确识别的目标。",
        }
        text = f"<b>确认操作</b>\n告警 #{alert_id}\n\n{descriptions.get(decision, '确认执行此操作？')}"
        keyboard = {
            "inline_keyboard": [
                [{"text": "确认执行", "callback_data": f"n:x:{alert_id}:{decision}:{severity}:{offset}"}],
                [{"text": "取消并返回", "callback_data": f"n:d:{alert_id}:{severity}:{offset}"}],
            ]
        }
        return text, keyboard

    def _telegram_send_view(
        self, bot: sqlite3.Row, update: Dict[str, Any], text: str, keyboard: Dict[str, Any]
    ) -> None:
        callback = update.get("callback_query") if isinstance(update.get("callback_query"), dict) else None
        message = callback.get("message") if callback and isinstance(callback.get("message"), dict) else None
        if message:
            try:
                self._app._telegram_api(
                    str(bot["token"]),
                    "editMessageText",
                    {
                        "chat_id": str(message.get("chat", {}).get("id")),
                        "message_id": int(message.get("message_id") or 0),
                        "text": text,
                        "parse_mode": "HTML",
                        "reply_markup": keyboard,
                        "disable_web_page_preview": True,
                    },
                )
            except RuntimeError as exc:
                # Refreshing an unchanged view is successful from the user's point of view.
                if "message is not modified" not in str(exc).lower():
                    raise
        else:
            incoming = update.get("message") if isinstance(update.get("message"), dict) else {}
            self._app._telegram_api(
                str(bot["token"]),
                "sendMessage",
                {
                    "chat_id": str(incoming.get("chat", {}).get("id")),
                    "text": text,
                    "parse_mode": "HTML",
                    "reply_markup": keyboard,
                    "disable_web_page_preview": True,
                },
            )

    async def _handle_telegram_update(self, bot: sqlite3.Row, update: Dict[str, Any]) -> None:
        callback = update.get("callback_query") if isinstance(update.get("callback_query"), dict) else None
        message = (
            callback.get("message")
            if callback and isinstance(callback.get("message"), dict)
            else update.get("message")
        )
        if not isinstance(message, dict) or not self._app._telegram_chat_allowed(bot, message.get("chat") or {}):
            if callback:
                self._app._telegram_api(
                    str(bot["token"]),
                    "answerCallbackQuery",
                    {"callback_query_id": str(callback.get("id") or ""), "text": "此聊天未获授权"},
                )
            return
        if callback:
            data = str(callback.get("data") or "")
            legacy = re.fullmatch(r"narwhal:(\d+):(dismiss|resolve)", data)
            if legacy:
                decision = "dismiss_once" if legacy.group(2) == "dismiss" else "resolve"
                try:
                    message_text = await self._app._telegram_apply_decision(
                        int(legacy.group(1)), decision, int(bot["id"])
                    )
                except HTTPException as exc:
                    message_text = str(exc.detail)
                self._app._telegram_api(
                    str(bot["token"]),
                    "answerCallbackQuery",
                    {"callback_query_id": str(callback.get("id") or ""), "text": message_text[:180]},
                )
                return
            parts = data.split(":")
            try:
                if data == "n:m":
                    text, keyboard = self._app._telegram_menu()
                elif len(parts) == 4 and parts[:2] == ["n", "l"]:
                    text, keyboard = self._app._telegram_alert_list(parts[2], int(parts[3]))
                elif len(parts) == 5 and parts[:2] == ["n", "d"]:
                    text, keyboard = self._app._telegram_alert_detail(int(parts[2]), parts[3], int(parts[4]))
                elif len(parts) == 6 and parts[:2] == ["n", "c"]:
                    text, keyboard = self._app._telegram_confirm(
                        int(parts[2]), parts[3], parts[4], int(parts[5])
                    )
                elif len(parts) == 6 and parts[:2] == ["n", "x"]:
                    result = await self._app._telegram_apply_decision(int(parts[2]), parts[3], int(bot["id"]))
                    detail, keyboard = self._app._telegram_alert_detail(int(parts[2]), parts[4], int(parts[5]))
                    text = f"<b>{html.escape(result)}</b>\n\n{detail}"
                else:
                    text, keyboard = self._app._telegram_menu()
                self._app._telegram_send_view(bot, update, text, keyboard)
                self._app._telegram_api(
                    str(bot["token"]),
                    "answerCallbackQuery",
                    {"callback_query_id": str(callback.get("id") or "")},
                )
            except (ValueError, HTTPException, RuntimeError) as exc:
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                self._app._telegram_api(
                    str(bot["token"]),
                    "answerCallbackQuery",
                    {"callback_query_id": str(callback.get("id") or ""), "text": str(detail)[:180], "show_alert": True},
                )
            return
        command = str(message.get("text") or "").split()[0].split("@", 1)[0].lower()
        if command in ("/start", "/menu", "/alerts"):
            text, keyboard = (
                self._app._telegram_menu() if command != "/alerts" else self._app._telegram_alert_list("all", 0)
            )
            self._app._telegram_send_view(bot, update, text, keyboard)

    async def _telegram_polling_loop(self) -> None:
        await asyncio.sleep(5)
        while True:
            if self._app.PUBLIC_BASE_URL:
                await asyncio.sleep(30)
                continue
            conn = self._app.db()
            try:
                bots = conn.execute(
                    "SELECT * FROM notification_bots WHERE enabled=1 AND kind='telegram'"
                ).fetchall()
            finally:
                conn.close()
            poll_offsets = self._app._telegram_poll_offsets
            for bot in bots:
                bot_id = int(bot["id"])
                try:
                    if bot_id not in poll_offsets:
                        await asyncio.to_thread(
                            self._app._telegram_api,
                            str(bot["token"]),
                            "deleteWebhook",
                            {"drop_pending_updates": True},
                        )
                        await asyncio.to_thread(
                            self._app._telegram_api,
                            str(bot["token"]),
                            "setMyCommands",
                            {
                                "commands": [
                                    {"command": "menu", "description": "打开交互式告警控制台"},
                                    {"command": "alerts", "description": "查看活动告警"},
                                ]
                            },
                        )
                        poll_offsets[bot_id] = 0
                    result = await asyncio.to_thread(
                        self._app._telegram_api,
                        str(bot["token"]),
                        "getUpdates",
                        {
                            "offset": poll_offsets[bot_id],
                            "timeout": 0,
                            "allowed_updates": ["message", "callback_query"],
                            "limit": 20,
                        },
                    )
                    for update in result.get("result") or []:
                        poll_offsets[bot_id] = max(
                            poll_offsets[bot_id], int(update.get("update_id") or 0) + 1
                        )
                        await self._app._handle_telegram_update(bot, update)
                except Exception as exc:
                    print(f"Telegram polling warning (bot {bot_id}): {exc}")
            await asyncio.sleep(3)

    def _telegram_duration_text(self, seconds: int) -> str:
        seconds = max(0, seconds)
        if seconds < 60:
            return "不足 1 分钟"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes} 分钟"
        hours, remaining = divmod(minutes, 60)
        return f"{hours} 小时 {remaining} 分钟" if remaining else f"{hours} 小时"

    def _telegram_alert_status_card(
        self, alert: sqlite3.Row, now: int, deep_evidence: Dict[str, Any] | None = None
    ) -> tuple[str, Dict[str, Any]]:
        status = str(alert["status"])
        active = status == "active"
        duration_end = now if active else int(alert["last_seen"])
        duration = self._app._telegram_duration_text(duration_end - int(alert["first_seen"]))
        scope = "/".join(x for x in (str(alert["runtime"] or ""), str(alert["project"] or "")) if x)
        container_label = f"{scope or '-'} {alert['container_name'] or '-'}"
        if active:
            heading = f"Narwhal {str(alert['severity']).upper()} 告警"
            state_line = f"状态：<b>持续中</b>　持续：<b>{duration}</b>"
        else:
            state_labels = {
                "resolved": "已恢复",
                "dismissed": "已忽略",
                "suppressed": "已永久静默",
                "remediated": "已自动处置",
            }
            heading = f"Narwhal 告警{state_labels.get(status, '已结束')}"
            state_line = f"状态：<b>{state_labels.get(status, '已结束')}</b>　持续：<b>{duration}</b>"
        details = self._app._alert_details(alert["details_json"])
        if alert["alert_type"] == "container_connection_count":
            state_line = state_line.replace("持续：", "事件跨度：")
        automatic_remediation = details.get("automatic_remediation") if isinstance(details, dict) else None
        remediation_text = ""
        if alert["alert_type"] == "prohibited_activity":
            network_state = str((details.get("network_quarantine") or {}).get("status") or "unknown")
            heading = "Narwhal 严重安全告警 · 违规活动"
            states = {
                "isolated": "已双向隔离，等待管理员复核",
                "failed": "隔离未能完整验证，需立即人工处理",
                "release_failed": "解除隔离未验证成功，需人工检查",
                "released": "管理员已解除隔离，正在重新监测（非恢复证明）",
            }
            state_line = "状态：<b>" + states.get(network_state, "当前隔离状态待确认") + "</b>"
            proofs = []
            for item in (details.get("abuse_evidence") or [])[:5]:
                if not isinstance(item, dict):
                    continue
                features = item.get("features") or {}
                proofs.append(
                    "PID "
                    + str(item.get("pid") or "-")
                    + " · 连续佐证 "
                    + str(features.get("corroborating_samples") or "-")
                    + " 次"
                    + (" · 工具 " + str(item["tool"]) if item.get("tool") else "")
                    + (" · 并发配置 " + str(features["concurrency"]) if features.get("concurrency") else "")
                    + (" · SYN 待连接 " + str(item["pending_attempts"]) if item.get("pending_attempts") else "")
                    + (" · 纵向端口 " + str(item["vertical_ports"]) if item.get("vertical_ports") else "")
                    + (" · 横向目标 " + str(item["horizontal_targets"]) if item.get("horizontal_targets") else "")
                    + (
                        " · 待连接占比 " + str(round(float(item.get("pending_ratio", item.get("failed_ratio", 0))) * 100)) + "%"
                        if item.get("pending_ratio") is not None or item.get("failed_ratio") is not None
                        else ""
                    )
                    + (" · 文件 SHA256 " + str(item["source_sha256"])[:12] if item.get("source_sha256") else "")
                )
            remediation_text = (
                "\n<b>特征证据</b>\n"
                + html.escape("\n".join(proofs))
                + "\n<b>容器与磁盘保留；隔离会阻断 SSH，请通过宿主机控制台排查。</b>\n"
            )
        if isinstance(automatic_remediation, dict) and automatic_remediation.get("attempted") is True:
            remediation_result = str(
                automatic_remediation.get("message")
                or automatic_remediation.get("result_message")
                or "节点已执行定向处置"
            )[:300]
            remediation_text = (
                "\n<b>自动处置</b>："
                f"<b>{'已完成' if automatic_remediation.get('succeeded') is True else '未完成'}</b>\n"
                f"{html.escape(remediation_result)}\n"
            )
        evidence_text = ""
        if isinstance(deep_evidence, dict):
            inbound_ips = int(deep_evidence.get("inbound_unique_ips") or 0)
            outbound_ips = int(deep_evidence.get("outbound_unique_ips") or 0)
            inbound_processes = int(deep_evidence.get("inbound_process_count") or 0)
            outbound_processes = int(deep_evidence.get("outbound_process_count") or 0)
            all_ips = (
                deep_evidence.get("connection_ips")
                if isinstance(deep_evidence.get("connection_ips"), list)
                else []
            )
            inbound_items = (
                deep_evidence.get("inbound_ips")
                if isinstance(deep_evidence.get("inbound_ips"), list)
                else [item for item in all_ips if isinstance(item, dict) and int(item.get("inbound") or 0) > 0]
            )
            outbound_items = (
                deep_evidence.get("outbound_ips")
                if isinstance(deep_evidence.get("outbound_ips"), list)
                else [item for item in all_ips if isinstance(item, dict) and int(item.get("outbound") or 0) > 0]
            )
            # Legacy counts may include private/proxy peers absent from public lists.
            inbound_ips = len(inbound_items)
            outbound_ips = len(outbound_items)
            captured = int(deep_evidence.get("sampled_at") or 0)
            age = max(0, now - captured) if captured else None
            evidence_time = (
                datetime.fromtimestamp(captured, timezone(timedelta(hours=8))).strftime("%m-%d %H:%M:%S")
                if 0 < captured < 253402271999
                else "时间未知"
            )
            evidence_note = f"采集时间：{evidence_time}（UTC+8）；"
            evidence_note += (
                "历史快照，已过期，不能代表当前状态。"
                if age is None or age > 900
                else "近期快照，不代表完整流量。"
            )
            if deep_evidence.get("socket_snapshot_truncated"):
                evidence_note += " 明细已截断，仅展示部分连接和进程。"
            if not inbound_items and int(
                deep_evidence.get("observed_inbound_unique_ips", deep_evidence.get("inbound_unique_ips", 0)) or 0
            ):
                evidence_note += " 检测到入站来源，但公网源 IP 尚未映射。"

            def ip_lines(items: List[Dict[str, Any]], direction: str) -> str:
                """Telegram-friendly, one public endpoint per line, safely HTML escaped."""
                label = "入站连接" if direction == "inbound" else "出站连接"
                lines: List[str] = []
                for item in items[:10]:
                    if not isinstance(item, dict) or not item.get("ip"):
                        continue
                    location_parts = [
                        str(item.get(key) or "").strip()
                        for key in ("country", "region", "city")
                        if str(item.get(key) or "").strip()
                    ]
                    location = " ".join(location_parts) or "未知归属地"
                    carrier = str(item.get("isp") or item.get("org") or item.get("asn") or "未知运营商")
                    count = int(item.get(direction) or item.get("connections") or 0)
                    lines.append(
                        f"<code>{html.escape(str(item['ip'])[:45])}</code> ｜归属地：{html.escape(location[:50])} ｜运营商：{html.escape(carrier[:50])} ｜{label}：{count}"
                    )
                return "\n".join(lines) or "-"

            attribution = deep_evidence.get("connection_attribution")
            attribution_text = ""
            attribution_unavailable = not isinstance(attribution, dict)
            if isinstance(attribution, dict):
                captured_sockets = attribution.get("captured_sockets")
                try:
                    expected_connections = max(
                        int(deep_evidence.get("connection_count") or 0),
                        int(attribution.get("expected_connection_count") or 0),
                    )
                    captured_count = int(captured_sockets or 0)
                except (TypeError, ValueError, OverflowError):
                    expected_connections, captured_count = 0, 0
                attribution_unavailable = (
                    attribution.get("evidence_status") == "unavailable"
                    or captured_sockets is None
                    or (expected_connections > 0 and captured_count == 0)
                )
                if attribution_unavailable:
                    attribution_text = (
                        "\n<b>连接发起方核验（单次快照）</b>\n"
                        "未采集到逐连接来源/PID 数据，发起方向未知；不能把缺失数据当作 0 条。"
                    )
                else:
                    attribution_text = (
                        "\n<b>连接发起方核验（单次快照）</b>\n"
                        f"本机进程发起：已确认 {int(attribution.get('confirmed_local_initiated') or 0)} / 推定 {int(attribution.get('probable_local_initiated') or 0)}；"
                        f"外部远端发起：已确认 {int(attribution.get('confirmed_remote_initiated') or 0)} / 推定 {int(attribution.get('probable_remote_initiated') or 0)}；"
                        f"方向未知 {int(attribution.get('unknown_direction') or 0)}。"
                        f"PID 归属 {int(attribution.get('process_attributed_sockets') or 0)}/{captured_count} 条，"
                        f"conntrack 五元组匹配 {int(attribution.get('conntrack_confirmed_sockets') or 0)} 条。"
                    )
                if not attribution.get("conntrack_available"):
                    attribution_text += "\nconntrack 不可用；推定方向不能视为已确认。"
            signal_counts = {
                "possible_multiport_probe": 0,
                "bidirectional_tcp_observed": 0,
                "mixed_connection_evidence": 0,
                "unreplied_tcp_observed": 0,
            }
            probe_ips: List[str] = []
            for item in inbound_items:
                if not isinstance(item, dict):
                    continue
                signal = item.get("network_evidence")
                if not isinstance(signal, dict):
                    continue
                classification = str(signal.get("classification") or "")
                if classification in signal_counts:
                    signal_counts[classification] += 1
                    if classification == "possible_multiport_probe" and item.get("ip"):
                        probe_ips.append(str(item["ip"])[:45])
            signal_text = ""
            if any(signal_counts.values()):
                signal_text = (
                    "\n<b>入站行为线索（非恶意定论）</b>："
                    f"多端口探测迹象 {signal_counts['possible_multiport_probe']} IP"
                    + (f"（{html.escape('、'.join(probe_ips[:3]))}）" if probe_ips else "")
                    + f"；双向 TCP {signal_counts['bidirectional_tcp_observed']} IP；"
                    + f"混合/未应答 {signal_counts['mixed_connection_evidence'] + signal_counts['unreplied_tcp_observed']} IP。"
                    "这些只是单次 conntrack 传输线索，需结合应用访问日志判断是否为正常用户请求。"
                )
            inbound_ip_summary = "未采集" if attribution_unavailable and not inbound_items else str(inbound_ips)
            outbound_ip_summary = "未采集" if attribution_unavailable and not outbound_items else str(outbound_ips)
            inbound_process_summary = (
                "未采集" if attribution_unavailable and not inbound_items else str(inbound_processes)
            )
            outbound_process_summary = (
                "未采集" if attribution_unavailable and not outbound_items else str(outbound_processes)
            )
            evidence_text = (
                f"\n<b>自动深度取证</b>\n"
                f"{html.escape(evidence_note)}\n"
                f"入站：{inbound_ip_summary} IP / {inbound_process_summary} 进程\n"
                f"出站：{outbound_ip_summary} IP / {outbound_process_summary} 进程\n"
                f"{attribution_text}{signal_text}\n"
                f"<b>入站 IP（每行一个）</b>\n{ip_lines(inbound_items, 'inbound')}\n"
                f"<b>出站 IP（每行一个）</b>\n{ip_lines(outbound_items, 'outbound')}\n"
            )
        raw_msg = str(alert["message"] or "")[:400]
        msg_escaped = html.escape(raw_msg)
        if alert["alert_type"] == "container_connection_count":
            conn_policy = getattr(self._app, "connection_policy", connection_policy)
            msg_escaped += "\n" + html.escape(conn_policy.text(details.get("connection_policy")))
            metric = details.get("connection_metrics") or {}
            if metric.get("valid") is True:
                msg_escaped += html.escape(
                    f"\nTCP已建立 {metric.get('tcp_established', 0)} · 待连接 {metric.get('tcp_pending', 0)} · TIME_WAIT {metric.get('tcp_time_wait', 0)} · UDP socket {metric.get('udp_sockets', 0)}"
                )
        text = (
            f"<b>{heading}</b>\n"
            f"<b>{html.escape(str(alert['title'] or alert['alert_type'] or '-'))}</b>\n"
            f"{state_line}\n"
            f"主机：<code>{html.escape(str(alert['host_id'] or '-'))}</code>\n"
            f"容器：<code>{html.escape(container_label)}</code>\n"
            f"出现次数：{int(alert['occurrence_count'])}\n"
            f"{remediation_text}"
            f"{evidence_text}"
            f"{msg_escaped}"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "查看并处理" if active else "查看历史", "callback_data": f"n:d:{alert['id']}:all:0"},
                    {"text": "活动告警", "callback_data": "n:l:all:0"},
                ]
            ]
        }
        return text, keyboard

    def sync_configured_bot_alert_messages(
        self,
        host_id: str | None = None,
        observed_at: int | None = None,
        alert_id: int | None = None,
    ) -> None:
        """Create or refresh one Telegram status card per alert, retaining recovery history."""
        now = int(time.time())
        conn = self._app.db()
        try:
            bots = conn.execute("SELECT * FROM notification_bots WHERE enabled=1 AND kind='telegram'").fetchall()
            if not bots:
                return
            if alert_id is not None:
                alerts = conn.execute("SELECT * FROM security_alerts WHERE id=?", (alert_id,)).fetchall()
            elif host_id is not None and observed_at is not None:
                alerts = conn.execute(
                    "SELECT * FROM security_alerts WHERE host_id=? AND last_seen=? AND status IN ('active','resolved','dismissed','suppressed','remediated')",
                    (host_id, observed_at),
                ).fetchall()
            elif host_id is not None:
                alerts = conn.execute(
                    "SELECT * FROM security_alerts WHERE host_id=? AND status IN ('active','resolved','dismissed','suppressed','remediated') ORDER BY id DESC LIMIT 50",
                    (host_id,),
                ).fetchall()
            else:
                alerts = []
            severity_rank = self._app._SEVERITY_RANK
            for bot in bots:
                bot_id = int(bot["id"])
                chat_target, thread_id = self._app._parse_telegram_target(str(bot["target"] or ""))
                for alert in alerts:
                    severity = str(alert["severity"])
                    mapping = conn.execute(
                        "SELECT * FROM telegram_alert_messages WHERE bot_id=? AND alert_id=?",
                        (bot_id, int(alert["id"])),
                    ).fetchone()
                    pending_quarantine = (
                        alert["alert_type"] == "prohibited_activity"
                        and (self._app._alert_details(alert["details_json"]).get("network_quarantine") or {}).get(
                            "status"
                        )
                        in {"isolated", "failed", "release_failed"}
                    )
                    if (
                        mapping is None
                        and str(alert["status"]) in ("suppressed", "dismissed", "resolved")
                        and not pending_quarantine
                    ):
                        continue
                    if mapping is None and severity_rank.get(severity, 1) < severity_rank.get(
                        str(bot["min_severity"]), 2
                    ):
                        continue
                    evidence_row = conn.execute(
                        "SELECT action_id,evidence_json FROM security_alert_evidence WHERE alert_id=? ORDER BY captured_at DESC,id DESC LIMIT 1",
                        (int(alert["id"]),),
                    ).fetchone()
                    deep_evidence = (
                        self._app._alert_details(evidence_row["evidence_json"])
                        if evidence_row is not None
                        else None
                    )
                    evidence_action_id = int(evidence_row["action_id"]) if evidence_row is not None else 0
                    text, keyboard = self._app._telegram_alert_status_card(alert, now, deep_evidence)
                    content_hash = hashlib.sha256(
                        (text + json.dumps(keyboard, sort_keys=True, ensure_ascii=False)).encode()
                    ).hexdigest()
                    if mapping is not None:
                        status_changed = str(mapping["last_status"]) != str(alert["status"])
                        severity_changed = str(mapping["last_severity"]) != severity
                        evidence_changed = int(mapping["last_evidence_action_id"]) != evidence_action_id
                        if (
                            not status_changed
                            and not severity_changed
                            and not evidence_changed
                            and now - int(mapping["updated_at"]) < 60
                        ):
                            continue
                        if str(mapping["content_hash"]) == content_hash:
                            continue
                    try:
                        if mapping is None:
                            send_payload: Dict[str, Any] = {
                                "chat_id": chat_target,
                                "text": text,
                                "parse_mode": "HTML",
                                "reply_markup": keyboard,
                                "disable_web_page_preview": True,
                            }
                            if thread_id is not None:
                                send_payload["message_thread_id"] = thread_id
                            result = self._app._telegram_api(str(bot["token"]), "sendMessage", send_payload)
                            message_id = int((result.get("result") or {}).get("message_id") or 0)
                            if message_id <= 0:
                                raise RuntimeError("Telegram did not return a message id")
                            conn.execute(
                                "INSERT INTO telegram_alert_messages(bot_id,alert_id,chat_id,message_id,last_status,last_severity,last_evidence_action_id,content_hash,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                                (
                                    bot_id,
                                    int(alert["id"]),
                                    chat_target,
                                    message_id,
                                    str(alert["status"]),
                                    severity,
                                    evidence_action_id,
                                    content_hash,
                                    now,
                                ),
                            )
                        else:
                            edit_chat_id, _ = self._app._parse_telegram_target(str(mapping["chat_id"]))
                            try:
                                self._app._telegram_api(
                                    str(bot["token"]),
                                    "editMessageText",
                                    {
                                        "chat_id": edit_chat_id,
                                        "message_id": int(mapping["message_id"]),
                                        "text": text,
                                        "parse_mode": "HTML",
                                        "reply_markup": keyboard,
                                        "disable_web_page_preview": True,
                                    },
                                )
                            except RuntimeError as edit_exc:
                                err_str = str(edit_exc).lower()
                                if "message is not modified" in err_str:
                                    pass
                                elif "message to edit not found" in err_str or "message can't be edited" in err_str:
                                    send_payload = {
                                        "chat_id": chat_target,
                                        "text": text,
                                        "parse_mode": "HTML",
                                        "reply_markup": keyboard,
                                        "disable_web_page_preview": True,
                                    }
                                    if thread_id is not None:
                                        send_payload["message_thread_id"] = thread_id
                                    resend_res = self._app._telegram_api(
                                        str(bot["token"]), "sendMessage", send_payload
                                    )
                                    new_msg_id = int((resend_res.get("result") or {}).get("message_id") or 0)
                                    if new_msg_id > 0:
                                        conn.execute(
                                            "UPDATE telegram_alert_messages SET message_id=?,chat_id=?,last_status=?,last_severity=?,last_evidence_action_id=?,content_hash=?,updated_at=? WHERE bot_id=? AND alert_id=?",
                                            (
                                                new_msg_id,
                                                chat_target,
                                                str(alert["status"]),
                                                severity,
                                                evidence_action_id,
                                                content_hash,
                                                now,
                                                bot_id,
                                                int(alert["id"]),
                                            ),
                                        )
                                        conn.commit()
                                        self._app._record_bot_delivery(bot_id, True)
                                        continue
                                else:
                                    raise
                            conn.execute(
                                "UPDATE telegram_alert_messages SET last_status=?,last_severity=?,last_evidence_action_id=?,content_hash=?,updated_at=? WHERE bot_id=? AND alert_id=?",
                                (
                                    str(alert["status"]),
                                    severity,
                                    evidence_action_id,
                                    content_hash,
                                    now,
                                    bot_id,
                                    int(alert["id"]),
                                ),
                            )
                        conn.commit()
                        self._app._record_bot_delivery(bot_id, True)
                    except Exception as exc:
                        self._app._record_bot_delivery(bot_id, False, str(exc))
                        print(f"telegram dynamic alert {bot_id}/{alert['id']} failed: {exc}")
        finally:
            conn.close()

    def notification_bots(self) -> JSONResponse:
        conn = self._app.db()
        try:
            rows = conn.execute("SELECT * FROM notification_bots ORDER BY id DESC").fetchall()
            proxy_url = self._app.get_telegram_proxy_url()
            return JSONResponse(
                content={
                    "items": [self._app._notification_bot_item(row) for row in rows],
                    "callback_ready": bool(self._app.PUBLIC_BASE_URL),
                    "proxy_configured": bool(proxy_url),
                    "proxy_scheme": urllib.parse.urlsplit(proxy_url).scheme.lower() if proxy_url else "",
                }
            )
        finally:
            conn.close()

    async def save_notification_bot(self, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        name = str(payload.get("name") or "Telegram 通知").strip()[:80]
        token = self._app._normalize_telegram_token(payload.get("token"))
        raw_target = str(payload.get("target") or "").strip()[:200]
        chat_target, target_thread_id = self._app._parse_telegram_target(raw_target)
        severity = str(payload.get("min_severity") or "critical").lower()
        if not token or len(token) > 256 or not re.fullmatch(r"\d{5,}:[A-Za-z0-9_-]{20,}", token):
            raise HTTPException(
                status_code=400,
                detail="请输入有效的 Telegram Bot Token（格式如 123456789:ABCdef...）",
            )
        if not raw_target or not chat_target or severity not in self._app._SEVERITY_RANK:
            raise HTTPException(status_code=400, detail="目标（Chat ID 或 @频道）和最低告警级别是必填项")
        now = int(time.time())
        conn = self._app.db()
        try:
            cur = conn.execute(
                "INSERT INTO notification_bots(name,kind,token,target,min_severity,enabled,callback_secret,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?,?)",
                (name, "telegram", token, raw_target, severity, secrets.token_urlsafe(32), now, now),
            )
            bot_id = int(cur.lastrowid)
            row = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
            conn.commit()
        finally:
            conn.close()
        try:
            send_payload: Dict[str, Any] = {
                "chat_id": chat_target,
                "text": "Narwhal 通知机器人已配置成功。后续将按设定的严重级别推送新告警。",
            }
            if target_thread_id is not None:
                send_payload["message_thread_id"] = target_thread_id
            self._app._telegram_api(token, "sendMessage", send_payload)
            self._app._record_bot_delivery(bot_id, True)
        except Exception as exc:
            conn = self._app.db()
            try:
                conn.execute("DELETE FROM notification_bots WHERE id=?", (bot_id,))
                conn.commit()
            finally:
                conn.close()
            raise HTTPException(status_code=502, detail=f"Telegram 配置验证失败：{exc}")
        callback_error = ""
        public_base_url = self._app.PUBLIC_BASE_URL
        if public_base_url:
            try:
                self._app._telegram_api(
                    token,
                    "setWebhook",
                    {
                        "url": f"{public_base_url}{self._app._BOT_CALLBACK_PREFIX}{bot_id}/{row['callback_secret']}",
                        "allowed_updates": ["message", "callback_query"],
                    },
                )
                self._app._telegram_api(
                    token,
                    "setMyCommands",
                    {
                        "commands": [
                            {"command": "menu", "description": "打开交互式告警控制台"},
                            {"command": "alerts", "description": "查看活动告警"},
                        ]
                    },
                )
            except Exception as exc:
                callback_error = str(exc)[:500]
        conn = self._app.db()
        try:
            row = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
            return JSONResponse(
                status_code=201,
                content={
                    "item": self._app._notification_bot_item(row),
                    "callback_ready": bool(public_base_url) and not callback_error,
                    "callback_error": callback_error,
                },
            )
        finally:
            conn.close()

    def delete_notification_bot(self, bot_id: int) -> JSONResponse:
        conn = self._app.db()
        try:
            cur = conn.execute("DELETE FROM notification_bots WHERE id=?", (bot_id,))
            conn.commit()
            if not cur.rowcount:
                raise HTTPException(status_code=404, detail="notification bot not found")
            return JSONResponse(content={"ok": True})
        finally:
            conn.close()

    def test_notification_bot(self, bot_id: int) -> JSONResponse:
        conn = self._app.db()
        try:
            bot = conn.execute("SELECT * FROM notification_bots WHERE id=?", (bot_id,)).fetchone()
        finally:
            conn.close()
        if bot is None:
            raise HTTPException(status_code=404, detail="notification bot not found")
        chat_target, target_thread_id = self._app._parse_telegram_target(str(bot["target"] or ""))
        public_base_url = self._app.PUBLIC_BASE_URL
        try:
            send_payload: Dict[str, Any] = {"chat_id": chat_target, "text": "Narwhal 通知机器人连接测试成功。"}
            if target_thread_id is not None:
                send_payload["message_thread_id"] = target_thread_id
            self._app._telegram_api(str(bot["token"]), "sendMessage", send_payload)
            if public_base_url:
                self._app._telegram_api(
                    str(bot["token"]),
                    "setWebhook",
                    {
                        "url": f"{public_base_url}{self._app._BOT_CALLBACK_PREFIX}{bot_id}/{bot['callback_secret']}",
                        "allowed_updates": ["message", "callback_query"],
                    },
                )
            self._app._telegram_api(
                str(bot["token"]),
                "setMyCommands",
                {
                    "commands": [
                        {"command": "menu", "description": "打开交互式告警控制台"},
                        {"command": "alerts", "description": "查看活动告警"},
                    ]
                },
            )
            self._app._record_bot_delivery(bot_id, True)
        except Exception as exc:
            self._app._record_bot_delivery(bot_id, False, str(exc))
            raise HTTPException(status_code=502, detail=f"Telegram 测试失败：{exc}")
        return JSONResponse(content={"ok": True, "callback_ready": bool(public_base_url)})

    async def telegram_callback(self, bot_id: int, callback_secret: str, request: Request) -> JSONResponse:
        conn = self._app.db()
        try:
            bot = conn.execute(
                "SELECT * FROM notification_bots WHERE id=? AND callback_secret=? AND enabled=1",
                (bot_id, callback_secret),
            ).fetchone()
            if bot is None:
                raise HTTPException(status_code=404, detail="unknown notification bot")
            payload = await request.json()
        finally:
            conn.close()
        if isinstance(payload, dict):
            await self._app._handle_telegram_update(bot, payload)
        return JSONResponse(content={"ok": True})

    def broadcast_commerce_telegram(self, text: str, parse_mode: str = "HTML") -> int:
        conn = self._app.db()
        try:
            bots = conn.execute(
                "SELECT id, token, target FROM notification_bots WHERE enabled=1 AND kind='telegram'"
            ).fetchall()
        finally:
            conn.close()
        sent_count = 0
        for bot in bots:
            try:
                target_chat_id, thread_id = self._app._parse_telegram_target(bot["target"])
                payload: Dict[str, Any] = {"chat_id": target_chat_id, "text": text, "parse_mode": parse_mode}
                if thread_id is not None:
                    payload["message_thread_id"] = thread_id
                self._app._telegram_api(bot["token"], "sendMessage", payload)
                sent_count += 1
            except Exception as exc:
                logger.warning("Failed to send commerce notification via bot %s: %s", bot["id"], exc)
        return sent_count


def bind(app_mod: Any) -> TelegramService:
    global _app, _service
    _app = app_mod
    _service = TelegramService(app_mod)
    return _service


def attach(app: FastAPI, app_mod: Any) -> TelegramService:
    svc = bind(app_mod)
    router = APIRouter()
    router.add_api_route("/api/v1/notifications/bots", svc.notification_bots, methods=["GET"])
    router.add_api_route("/api/v1/notifications/bots", svc.save_notification_bot, methods=["POST"])
    router.add_api_route("/api/v1/notifications/bots/{bot_id}", svc.delete_notification_bot, methods=["DELETE"])
    router.add_api_route("/api/v1/notifications/bots/{bot_id}/test", svc.test_notification_bot, methods=["POST"])
    router.add_api_route(
        "/api/v1/notifications/telegram/{bot_id}/{callback_secret}",
        svc.telegram_callback,
        methods=["POST"],
    )
    app.include_router(router)
    return svc


def __getattr__(name: str) -> Any:
    if _service is not None and hasattr(_service, name):
        return getattr(_service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
