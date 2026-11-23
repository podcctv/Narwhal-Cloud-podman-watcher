"""Host & fleet RFW firewall policy, readback validation, event ingestion, and reconciliation service."""
from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY = "speedtest-auto-default"
SPEEDTEST_POLICY_MIN_AGENT_VERSION = (1, 7, 136)
SPEEDTEST_AUTO_RETRY_INTERVAL = 15 * 60
SPEEDTEST_AUTO_RETRY_WINDOW = 24 * 60 * 60
SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW = 3

HOST_FIREWALL_READBACK_REASONS = {
    "platform_unsupported",
    "unknown",
    "response_too_large",
    "readback_endpoint_missing",
    "readback_http_error",
    "invalid_json",
    "invalid_payload",
    "socket_missing",
    "socket_permission_denied",
    "socket_refused",
    "socket_timeout",
    "socket_error",
}

_app: Any = None
_service: "FirewallService | None" = None


class FirewallService:
    """Host and fleet firewall policy management bound to an app module."""

    def __init__(self, app_mod: Any) -> None:
        self._app = app_mod

    def _validate_host_firewall_policy(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) - {"rules", "abuse"}:
            raise HTTPException(status_code=400, detail="防火墙配置只允许 rules 和 abuse 字段")
        raw_rules = payload.get("rules", [])
        if not isinstance(raw_rules, list) or len(raw_rules) > 64:
            raise HTTPException(status_code=400, detail="RFW 规则最多支持 64 条（受 eBPF 规则表容量限制）")
        protocols = {
            "all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto",
        }
        rules = []
        seen_keys = set()
        for index, raw in enumerate(raw_rules):
            allowed = {
                "key", "priority", "direction", "protocol", "action", "enabled",
                "port_start", "port_end", "ip_type", "ip", "countries",
            }
            if not isinstance(raw, dict) or set(raw) - allowed:
                raise HTTPException(status_code=400, detail=f"第 {index + 1} 条 RFW 规则字段无效")
            key = str(raw.get("key") or "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", key) or key in seen_keys:
                raise HTTPException(status_code=400, detail=f"第 {index + 1} 条 RFW 规则标识无效或重复")
            seen_keys.add(key)
            direction = str(raw.get("direction") or "").lower()
            protocol = str(raw.get("protocol") or "").lower()
            action = str(raw.get("action") or "").lower()
            ip_type = str(raw.get("ip_type") or "").lower()
            if direction not in {"in", "out"} or protocol not in protocols or action not in {"block", "pass"}:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的方向、协议或动作不支持")
            if direction == "out" and protocol not in {"all", "tcp", "udp", "socks", "fet", "wireguard", "mtproto"}:
                raise HTTPException(status_code=400, detail=f"RFW 协议 {protocol} 暂不支持出站匹配")
            priority = raw.get("priority")
            port_start = raw.get("port_start")
            port_end = raw.get("port_end")
            if type(priority) is not int or not 0 <= priority <= 100000:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的优先级无效")
            if type(port_start) is not int or not 0 <= port_start <= 65535:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的起始端口无效")
            if port_end is not None and (type(port_end) is not int or not port_start <= port_end <= 65535):
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的结束端口无效")
            if type(raw.get("enabled")) is not bool:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的 enabled 必须是布尔值")
            if ip_type not in {"any", "cidr", "geoip"}:
                raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 的 IP 匹配类型无效")
            rule: Dict[str, Any] = {
                "key": key,
                "priority": priority,
                "direction": direction,
                "protocol": protocol,
                "action": action,
                "enabled": raw["enabled"],
                "port_start": port_start,
                "ip_type": ip_type,
            }
            if port_end is not None:
                rule["port_end"] = port_end
            if ip_type == "cidr":
                try:
                    rule["ip"] = str(ipaddress.ip_network(str(raw.get("ip") or "").strip(), strict=False))
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 需要有效的 IPv4/IPv6 CIDR") from None
            elif ip_type == "geoip":
                countries = raw.get("countries")
                if not isinstance(countries, list) or not 1 <= len(countries) <= 30:
                    raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 需要 1 到 30 个国家代码")
                normalized = []
                for country in countries:
                    code = str(country).strip().upper()
                    if not re.fullmatch(r"[A-Z]{2}", code):
                        raise HTTPException(status_code=400, detail=f"RFW 规则 {key} 包含无效国家代码")
                    if code not in normalized:
                        normalized.append(code)
                rule["countries"] = sorted(normalized)
            rules.append(rule)

        raw_abuse = payload.get("abuse", {})
        categories = {"speedtest", "mining", "bt"}
        allowed_services = {
            "ookla", "cloudflare", "fast", "tcpquality",
            "iperf3_server", "librespeed", "openspeedtest", "ookla_server",
        }
        if not isinstance(raw_abuse, dict) or set(raw_abuse) - (
            categories | {"services", "service_runtimes", "interfaces", "runtimes"}
        ):
            raise HTTPException(status_code=400, detail="防火墙策略包含不支持的字段")
        abuse: Dict[str, Any] = {}
        for category in sorted(categories):
            value = raw_abuse.get(category, False)
            if type(value) is not bool:
                raise HTTPException(status_code=400, detail=f"防滥用策略 {category} 必须是布尔值")
            abuse[category] = False if category == "speedtest" else value
        raw_services = raw_abuse.get("services", [])
        if not isinstance(raw_services, list) or len(raw_services) > len(allowed_services):
            raise HTTPException(status_code=400, detail="测速服务列表无效")
        services = []
        for service in raw_services:
            name = str(service).strip().lower()
            if name not in allowed_services:
                raise HTTPException(status_code=400, detail="测速服务选择包含不支持的类型")
            if name not in services:
                services.append(name)
        raw_interfaces = raw_abuse.get("interfaces", [])
        if not isinstance(raw_interfaces, list) or len(raw_interfaces) > 16:
            raise HTTPException(status_code=400, detail="容器桥接网卡必须是最多 16 项的列表")
        interfaces = []
        for interface in raw_interfaces:
            name = str(interface).strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
                raise HTTPException(status_code=400, detail="容器桥接网卡名称无效")
            if name not in interfaces:
                interfaces.append(name)
        raw_runtimes = raw_abuse.get("runtimes", [])
        if not isinstance(raw_runtimes, list) or len(raw_runtimes) > 3:
            raise HTTPException(status_code=400, detail="容器网桥运行时必须从 Incus / Podman / Runman 中选择，最多三项")
        runtimes = []
        for runtime in raw_runtimes:
            name = str(runtime).strip().lower()
            if name not in {"incus", "podman", "runman"}:
                raise HTTPException(status_code=400, detail="容器网桥运行时只支持 Incus、Podman 或 Runman")
            if name not in runtimes:
                runtimes.append(name)
        raw_service_runtimes = raw_abuse.get("service_runtimes", [])
        if not isinstance(raw_service_runtimes, list) or len(raw_service_runtimes) > 3:
            raise HTTPException(status_code=400, detail="测速服务运行时必须从 Incus / Podman / Runman 中选择，最多三项")
        service_runtimes = []
        for runtime in raw_service_runtimes:
            name = str(runtime).strip().lower()
            if name not in {"incus", "podman", "runman"}:
                raise HTTPException(status_code=400, detail="测速服务范围只支持 Incus、Podman 或 Runman")
            if name not in service_runtimes:
                service_runtimes.append(name)
        if interfaces and runtimes:
            if not services or not any(abuse.get(key) for key in ("mining", "bt")):
                raise HTTPException(status_code=400, detail="测速服务范围和固定端口规则的目标不能混用")
        fixed_rules = any(abuse.get(key) is True for key in ("mining", "bt"))
        if fixed_rules and not interfaces and not runtimes:
            raise HTTPException(status_code=400, detail="启用固定端口规则前必须选择已采集的容器网卡或运行时")
        if services and not service_runtimes:
            raise HTTPException(status_code=400, detail="启用测速服务识别前必须选择 Incus、Podman 或 Runman")
        abuse["interfaces"] = interfaces
        abuse["runtimes"] = runtimes
        abuse["services"] = sorted(services)
        abuse["service_runtimes"] = service_runtimes
        return {"rules": rules, "abuse": abuse}

    def _empty_host_firewall_policy(self) -> Dict[str, Any]:
        return {
            "rules": [],
            "abuse": {
                "speedtest": False,
                "mining": False,
                "bt": False,
                "services": [
                    "cloudflare", "fast", "iperf3_server", "librespeed",
                    "ookla", "ookla_server", "openspeedtest", "tcpquality",
                ],
                "service_runtimes": ["incus", "podman", "runman"],
                "interfaces": [],
                "runtimes": [],
            },
        }

    def _agent_version_tuple(self, value: Any) -> Tuple[int, int, int] | None:
        match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:$|[-+])", str(value or "").strip())
        if not match:
            return None
        try:
            parts = tuple(int(part) for part in match.groups())
            return (parts[0], parts[1], parts[2])
        except (TypeError, ValueError, OverflowError):
            return None

    def _agent_supports_speedtest_policy(self, agent_version: Any) -> bool:
        version = self._app._agent_version_tuple(agent_version)
        return version is not None and version >= SPEEDTEST_POLICY_MIN_AGENT_VERSION

    def _maybe_queue_default_speedtest_policy(
        self,
        conn: sqlite3.Connection,
        host_id: str,
        node_id: str,
        agent_version: str,
        ts: int,
    ) -> bool:
        """Automatically apply the container-only service guard without replacing saved policy."""
        if not node_id or not self._app._agent_supports_speedtest_policy(agent_version):
            return False
        fleet = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
        if fleet is not None and int(fleet["revision"] or 0) > 0:
            return False

        existing = conn.execute(
            "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision "
            "FROM host_firewall_policies WHERE host_id=?",
            (host_id,),
        ).fetchone()
        if existing is not None and str(existing["updated_by"] or "") != SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY:
            return False

        desired = self._app._validate_host_firewall_policy(self._app._empty_host_firewall_policy())
        materialized, _target_status = self._app._materialize_host_firewall_policy(conn, host_id, desired, ts)
        if materialized is None:
            return False

        if existing is not None:
            try:
                saved = self._app._validate_host_firewall_policy(json.loads(existing["policy_json"] or "{}"))
            except (HTTPException, TypeError, ValueError):
                return False
            if (
                saved.get("abuse", {}).get("services") != desired.get("abuse", {}).get("services")
                or saved.get("abuse", {}).get("service_runtimes") != desired.get("abuse", {}).get("service_runtimes")
                or saved.get("rules")
            ):
                return False
            latest = self._app._latest_host_firewall_action(conn, host_id)
            if latest is not None:
                if (
                    str(latest["action_type"] or "") != "apply_host_firewall_policy"
                    or str(latest["requested_by"] or "") != SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY
                ):
                    return False
                if latest["status"] in {"queued", "dispatched", "running", "succeeded", "cancelled"}:
                    return False
                if latest["status"] == "failed":
                    if ts - int(latest["updated_at"] or 0) < SPEEDTEST_AUTO_RETRY_INTERVAL:
                        return False
                    failures = int(
                        conn.execute(
                            "SELECT COUNT(*) FROM security_actions WHERE host_id=? "
                            "AND action_type='apply_host_firewall_policy' AND requested_by=? "
                            "AND status='failed' AND created_at>=?",
                            (host_id, SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY, ts - SPEEDTEST_AUTO_RETRY_WINDOW),
                        ).fetchone()[0]
                        or 0
                    )
                    if failures >= SPEEDTEST_AUTO_MAX_FAILURES_PER_WINDOW:
                        return False

        self._app._enqueue_host_firewall_policy(
            conn, host_id, node_id, materialized, SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY, ts, 0
        )
        return True

    def _policy_has_rfw_effect(self, policy: Dict[str, Any] | None) -> bool:
        if not isinstance(policy, dict):
            return False
        rules = policy.get("rules")
        abuse = policy.get("abuse") if isinstance(policy.get("abuse"), dict) else {}
        return bool(
            isinstance(rules, list) and rules
            or any(abuse.get(key) is True for key in ("speedtest", "mining", "bt"))
        )

    def _stored_policy_has_rfw_effect(self, raw: str) -> bool:
        try:
            policy = json.loads(raw or "{}")
        except (TypeError, ValueError):
            return False
        return self._app._policy_has_rfw_effect(policy)

    def _validate_host_firewall_readback(self, payload: Any, report_ts: int) -> Dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        status = str(payload.get("status") or "")
        if status not in {"ready", "unavailable", "unsupported"}:
            return None
        raw_reason = payload.get("reason")
        reason = raw_reason if isinstance(raw_reason, str) and raw_reason in HOST_FIREWALL_READBACK_REASONS else ""
        clean: Dict[str, Any] = {
            "status": status,
            "observed_at": report_ts,
            "snapshot": None,
            "reason": "" if status == "ready" else reason or "unknown",
        }
        if status != "ready":
            return clean
        snapshot = payload.get("snapshot")
        if not isinstance(snapshot, dict):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        sync_status = snapshot.get("status")
        policy_revision = snapshot.get("policy_revision")
        rule_count = snapshot.get("rule_count")
        managed_count = snapshot.get("managed_rule_count")
        drift_count = snapshot.get("drift_count")
        missing_count = snapshot.get("missing_count")
        raw_rules = snapshot.get("rules")
        raw_expected = snapshot.get("expected_rules")
        rfw_api_version = snapshot.get("rfw_api_version", "")
        capabilities_known = snapshot.get("capabilities_known", False)
        raw_supported_protocols = snapshot.get("supported_protocols", [])
        if (
            sync_status not in {"in_sync", "drifted"}
            or type(policy_revision) is not int or not 0 <= policy_revision <= 2**63 - 1
            or type(rule_count) is not int or not 0 <= rule_count <= 256
            or type(managed_count) is not int or not 0 <= managed_count <= rule_count
            or type(drift_count) is not int or not 0 <= drift_count <= 320
            or type(missing_count) is not int or not 0 <= missing_count <= 64
            or not isinstance(raw_rules, list) or len(raw_rules) != rule_count
            or not isinstance(raw_expected, list) or len(raw_expected) > 64
            or not isinstance(rfw_api_version, str) or len(rfw_api_version) > 64
            or type(capabilities_known) is not bool
            or not isinstance(raw_supported_protocols, list) or len(raw_supported_protocols) > 32
        ):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        protocols = {
            "all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto",
        }
        supported_protocols = [str(protocol).strip().lower() for protocol in raw_supported_protocols]
        if (
            len(set(supported_protocols)) != len(supported_protocols)
            or any(protocol not in protocols for protocol in supported_protocols)
            or (capabilities_known and not supported_protocols)
        ):
            return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
        rules: List[Dict[str, Any]] = []
        seen_ids = set()
        for raw in raw_rules:
            if not isinstance(raw, dict):
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            rule_id = raw.get("id")
            priority = raw.get("priority")
            port_start = raw.get("port_start")
            port_end = raw.get("port_end")
            if (
                type(rule_id) is not int or not 1 <= rule_id <= 2**63 - 1 or rule_id in seen_ids
                or type(priority) is not int or not 0 <= priority <= 100000
                or raw.get("direction") not in {"in", "out"}
                or raw.get("protocol") not in protocols or raw.get("action") not in {"block", "pass"}
                or type(raw.get("enabled")) is not bool
                or type(port_start) is not int or not 0 <= port_start <= 65535
                or type(port_end) is not int or not port_start <= port_end <= 65535
                or raw.get("ip_type") not in {"any", "cidr", "geoip"}
                or raw.get("origin") not in {"platform", "manual"}
                or raw.get("sync_state") not in {"manual", "in_sync", "drifted", "orphaned"}
            ):
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            seen_ids.add(rule_id)
            item: Dict[str, Any] = {
                "id": rule_id,
                "priority": priority,
                "direction": raw["direction"],
                "protocol": raw["protocol"],
                "action": raw["action"],
                "enabled": raw["enabled"],
                "port_start": port_start,
                "port_end": port_end,
                "ip_type": raw["ip_type"],
                "origin": raw["origin"],
                "sync_state": raw["sync_state"],
            }
            managed_key = raw.get("managed_key")
            if raw["origin"] == "platform":
                if not isinstance(managed_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", managed_key):
                    return {
                        "status": "unavailable",
                        "observed_at": report_ts,
                        "snapshot": None,
                        "reason": "invalid_payload",
                    }
                item["managed_key"] = managed_key
            if raw["ip_type"] == "cidr":
                try:
                    item["ip"] = str(ipaddress.ip_network(str(raw.get("ip") or "").strip(), strict=False))
                except ValueError:
                    return {
                        "status": "unavailable",
                        "observed_at": report_ts,
                        "snapshot": None,
                        "reason": "invalid_payload",
                    }
            elif raw["ip_type"] == "geoip":
                countries = raw.get("countries")
                if not isinstance(countries, list) or not 1 <= len(countries) <= 30:
                    return {
                        "status": "unavailable",
                        "observed_at": report_ts,
                        "snapshot": None,
                        "reason": "invalid_payload",
                    }
                codes = sorted({str(code).strip().upper() for code in countries})
                if any(not re.fullmatch(r"[A-Z]{2}", code) for code in codes):
                    return {
                        "status": "unavailable",
                        "observed_at": report_ts,
                        "snapshot": None,
                        "reason": "invalid_payload",
                    }
                item["countries"] = codes
            rules.append(item)
        expected_rules: List[Dict[str, Any]] = []
        expected_keys = set()
        for raw in raw_expected:
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("key"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", raw["key"])
                or raw["key"] in expected_keys
                or raw.get("sync_state") not in {"in_sync", "drifted", "missing"}
            ):
                return {"status": "unavailable", "observed_at": report_ts, "snapshot": None, "reason": "invalid_payload"}
            expected_keys.add(raw["key"])
            item = {"key": raw["key"], "sync_state": raw["sync_state"]}
            if "id" in raw:
                if type(raw["id"]) is not int or not 1 <= raw["id"] <= 2**63 - 1:
                    return {
                        "status": "unavailable",
                        "observed_at": report_ts,
                        "snapshot": None,
                        "reason": "invalid_payload",
                    }
                item["id"] = raw["id"]
            expected_rules.append(item)
        clean["snapshot"] = {
            "status": sync_status,
            "observed_at": report_ts,
            "policy_revision": policy_revision,
            "rule_count": rule_count,
            "managed_rule_count": managed_count,
            "drift_count": drift_count,
            "missing_count": missing_count,
            "rfw_api_version": rfw_api_version,
            "capabilities_known": capabilities_known,
            "supported_protocols": sorted(supported_protocols),
            "rules": rules,
            "expected_rules": expected_rules,
        }
        return clean

    def _store_host_firewall_readback(
        self, conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], report_ts: int
    ) -> None:
        host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
        if not isinstance(host_firewall, dict) or not isinstance(host_firewall.get("readback"), dict):
            return
        readback = self._app._validate_host_firewall_readback(host_firewall["readback"], report_ts)
        if readback is None:
            return
        if readback["status"] == "ready":
            snapshot_json = json.dumps(readback["snapshot"], ensure_ascii=False, separators=(",", ":"))
            conn.execute(
                "INSERT INTO host_firewall_readbacks(host_id,status,observed_at,last_success_at,snapshot_json,readback_reason) VALUES(?,?,?,?,?,'') "
                "ON CONFLICT(host_id) DO UPDATE SET status=excluded.status,observed_at=excluded.observed_at,"
                "last_success_at=excluded.last_success_at,snapshot_json=excluded.snapshot_json,readback_reason=''",
                (host_id, "ready", report_ts, report_ts, snapshot_json),
            )
        else:
            conn.execute(
                "INSERT INTO host_firewall_readbacks(host_id,status,observed_at,last_success_at,snapshot_json,readback_reason) VALUES(?,?,?,0,'{}',?) "
                "ON CONFLICT(host_id) DO UPDATE SET status=excluded.status,observed_at=excluded.observed_at,readback_reason=excluded.readback_reason",
                (host_id, readback["status"], report_ts, readback["reason"]),
            )

    def _host_firewall_live_readback(
        self, conn: sqlite3.Connection, host_id: str, now: int | None = None
    ) -> Dict[str, Any]:
        stale_seconds = self._app.STALE_SECONDS
        rfw_protocols = self._app.RFW_APPLICATION_PROTOCOLS
        row = conn.execute(
            "SELECT status,observed_at,last_success_at,snapshot_json,readback_reason FROM host_firewall_readbacks WHERE host_id=?",
            (host_id,),
        ).fetchone()
        if row is None:
            return {
                "status": "unknown",
                "observed_at": 0,
                "last_success_at": 0,
                "stale": True,
                "reason": "unknown",
                "sync_status": "unknown",
                "rule_count": 0,
                "managed_rule_count": 0,
                "drift_count": 0,
                "missing_count": 0,
                "policy_revision": None,
                "rfw_api_version": "",
                "capabilities_known": False,
                "supported_protocols": [],
                "supported_protocol_count": 0,
                "active_blocked_protocols": [],
                "active_blocked_protocol_count": 0,
                "protocol_capabilities": {protocol: "unknown" for protocol in rfw_protocols},
                "mtproto_support": "unknown",
                "snapshot": None,
            }
        try:
            snapshot = json.loads(row["snapshot_json"] or "{}")
        except (TypeError, ValueError):
            snapshot = None
        if not isinstance(snapshot, dict) or not snapshot:
            snapshot = None
        observed_at = int(row["observed_at"] or 0)
        last_success_at = int(row["last_success_at"] or 0)
        now = int(time.time()) if now is None else int(now)
        status = str(row["status"] or "unknown")
        if status not in {"ready", "unavailable", "unsupported"}:
            status = "unknown"
        fresh = status == "ready" and observed_at > 0 and 0 <= now - observed_at <= stale_seconds
        capabilities_known = bool(snapshot and snapshot.get("capabilities_known")) and fresh
        supported_protocols = list(snapshot.get("supported_protocols") or []) if capabilities_known else []
        raw_rules = snapshot.get("rules") if isinstance(snapshot, dict) and isinstance(snapshot.get("rules"), list) else []
        active_blocked_protocols = (
            sorted(
                {
                    str(rule.get("protocol"))
                    for rule in raw_rules
                    if isinstance(rule, dict)
                    and rule.get("enabled", True) is True
                    and str(rule.get("action") or "block") == "block"
                    and str(rule.get("protocol") or "").strip()
                }
            )
            if fresh
            else []
        )
        protocol_capabilities = {
            protocol: self._app._protocol_capability_state(
                {
                    "status": status,
                    "stale": not fresh,
                    "capabilities_known": capabilities_known,
                    "supported_protocols": supported_protocols,
                },
                protocol,
            )
            for protocol in rfw_protocols
        }
        mtproto_support = "unknown"
        if capabilities_known:
            mtproto_support = "supported" if "mtproto" in supported_protocols else "unsupported"
        return {
            "status": status,
            "reason": str(row["readback_reason"] or "unknown") if status != "ready" else "",
            "observed_at": observed_at,
            "last_success_at": last_success_at,
            "age_seconds": max(0, now - observed_at) if observed_at else None,
            "stale": not fresh,
            "sync_status": str(snapshot.get("status") or "unknown") if snapshot else "unknown",
            "rule_count": int(snapshot.get("rule_count") or 0) if snapshot else 0,
            "managed_rule_count": int(snapshot.get("managed_rule_count") or 0) if snapshot else 0,
            "drift_count": int(snapshot.get("drift_count") or 0) if snapshot else 0,
            "missing_count": int(snapshot.get("missing_count") or 0) if snapshot else 0,
            "policy_revision": int(snapshot.get("policy_revision") or 0) if snapshot else None,
            "rfw_api_version": str(snapshot.get("rfw_api_version") or "") if capabilities_known else "",
            "capabilities_known": capabilities_known,
            "supported_protocols": supported_protocols,
            "supported_protocol_count": len(supported_protocols),
            "active_blocked_protocols": active_blocked_protocols,
            "active_blocked_protocol_count": len(active_blocked_protocols),
            "protocol_capabilities": protocol_capabilities,
            "mtproto_support": mtproto_support,
            "snapshot": snapshot,
        }

    def _policy_required_protocols(self, policy: Dict[str, Any]) -> List[str]:
        rules = policy.get("rules") if isinstance(policy, dict) else None
        rfw_protocols = self._app.RFW_APPLICATION_PROTOCOLS
        return sorted(
            {
                str(rule.get("protocol"))
                for rule in (rules if isinstance(rules, list) else [])
                if isinstance(rule, dict) and rule.get("protocol") in rfw_protocols
            }
        )

    def _policy_protocol_compatibility(
        self, policy: Dict[str, Any], live_readback: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        required = self._app._policy_required_protocols(policy)
        states = {protocol: self._app._protocol_capability_state(live_readback, protocol) for protocol in required}
        return {
            "required_protocols": required,
            "unsupported_protocols": sorted(protocol for protocol, state in states.items() if state == "unsupported"),
            "unknown_protocols": sorted(protocol for protocol, state in states.items() if state == "unknown"),
        }

    def _protocol_capability_state(self, live_readback: Dict[str, Any], protocol: str) -> str:
        """Return support only from a fresh, explicit RFW capability report."""
        if (
            not isinstance(live_readback, dict)
            or live_readback.get("status") != "ready"
            or live_readback.get("stale") is not False
            or live_readback.get("capabilities_known") is not True
        ):
            return "unknown"
        supported = live_readback.get("supported_protocols")
        if not isinstance(supported, list):
            return "unknown"
        return "supported" if protocol in supported else "unsupported"

    def _host_firewall_runtime_status(
        self, conn: sqlite3.Connection, host_id: str, now: int | None = None
    ) -> Dict[str, Any]:
        stale_seconds = self._app.STALE_SECONDS
        now = int(time.time()) if now is None else int(now)
        row = conn.execute(
            "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        if row is None:
            return {
                "control_api": "unknown",
                "control_api_reason": "no_report",
                "control_api_http_status": None,
                "observed_at": 0,
                "stale": True,
            }
        try:
            security = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            security = {}
        runtime = security.get("host_firewall") if isinstance(security, dict) else None
        if not isinstance(runtime, dict):
            observed_at = int(row["ts"] or 0)
            return {
                "control_api": "unknown",
                "control_api_reason": "no_capability_report",
                "control_api_http_status": None,
                "observed_at": observed_at,
                "stale": observed_at <= 0 or now - observed_at > stale_seconds or observed_at > now + 30,
            }
        control_api = str(runtime.get("control_api") or "unknown")
        if control_api not in {"ready", "unsupported", "unavailable", "unknown"}:
            control_api = "unknown"
        observed_at = int(runtime.get("observed_at") or row["ts"] or 0)
        allowed_reasons = {
            "ok", "platform_unsupported", "api_endpoint_missing", "unexpected_http", "http_error",
            "socket_missing", "socket_permission_denied", "socket_refused", "socket_timeout", "socket_error",
            "no_report", "no_capability_report", "legacy_report",
        }
        reason = str(runtime.get("control_api_reason") or "")
        if reason not in allowed_reasons:
            if control_api == "ready":
                reason = "ok"
            elif control_api in {"unavailable", "unsupported"}:
                reason = "legacy_report"
            else:
                reason = "no_capability_report"
        raw_http_status = runtime.get("control_api_http_status")
        http_status = raw_http_status if type(raw_http_status) is int and 100 <= raw_http_status <= 599 else None
        return {
            "control_api": control_api,
            "control_api_reason": reason,
            "control_api_http_status": http_status,
            "observed_at": observed_at,
            "stale": observed_at <= 0 or now - observed_at > stale_seconds or observed_at > now + 30,
        }

    def _host_firewall_interface_inventory(
        self, conn: sqlite3.Connection, host_id: str, now: int | None = None
    ) -> Dict[str, Any]:
        stale_seconds = self._app.STALE_SECONDS
        now = int(time.time()) if now is None else int(now)
        row = conn.execute(
            "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1",
            (host_id,),
        ).fetchone()
        empty = {"status": "unknown", "observed_at": 0, "stale": True, "interfaces": []}
        if row is None:
            return empty
        try:
            security = json.loads(row["payload_json"] or "{}")
        except (TypeError, ValueError):
            return {**empty, "status": "unavailable", "observed_at": int(row["ts"] or 0)}
        host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
        source = host_firewall.get("interface_inventory") if isinstance(host_firewall, dict) else None
        if not isinstance(source, dict):
            return {**empty, "observed_at": int(row["ts"] or 0)}
        observed_at = int(row["ts"] or 0)
        stale = observed_at <= 0 or now - observed_at > stale_seconds
        if source.get("status") != "ready" or not isinstance(source.get("interfaces"), list):
            return {
                "status": "unavailable" if source.get("status") == "unavailable" else "unknown",
                "observed_at": observed_at,
                "stale": stale,
                "interfaces": [],
            }

        interfaces = []
        seen = set()
        for raw in source["interfaces"][:64]:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,15}", name) or name in seen:
                continue
            seen.add(name)
            raw_addresses = raw.get("addresses") if isinstance(raw.get("addresses"), list) else []
            addresses = []
            for value in raw_addresses[:16]:
                try:
                    address = str(ipaddress.ip_interface(str(value).strip()))
                except ValueError:
                    continue
                if address not in addresses:
                    addresses.append(address)
            raw_runtimes = raw.get("runtimes") if isinstance(raw.get("runtimes"), list) else []
            runtimes = sorted(
                {str(value).lower() for value in raw_runtimes if str(value).lower() in {"incus", "podman", "runman"}}
            )
            raw_kind = str(raw.get("kind") or "unknown")[:32]
            kernel_kind = str(raw.get("kernel_kind") or raw_kind)[:32]
            raw_networks = raw.get("network_names") if isinstance(raw.get("network_names"), list) else []
            networks = list(
                dict.fromkeys(str(value)[:100] for value in raw_networks[:16] if isinstance(value, str) and value.strip())
            )
            mtu = raw.get("mtu")
            interfaces.append(
                {
                    "name": name,
                    "kind": "bridge" if runtimes else raw_kind,
                    "kernel_kind": kernel_kind,
                    "state": str(raw.get("state") or "unknown")[:16].lower(),
                    "mtu": mtu if type(mtu) is int and 0 < mtu <= 65535 else None,
                    "addresses": addresses,
                    "is_default_route": raw.get("is_default_route") is True,
                    "runtimes": runtimes,
                    "network_names": networks,
                    "firewall_eligible": bool(runtimes),
                }
            )
        return {
            "status": "ready",
            "observed_at": observed_at,
            "stale": stale,
            "interfaces": interfaces,
        }

    def _host_firewall_policy_targets(
        self, conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
    ) -> Tuple[List[str] | None, str]:
        """Resolve a logical runtime selection to fresh, agent-discovered bridge names."""
        abuse = policy.get("abuse") if isinstance(policy, dict) else None
        if not isinstance(abuse, dict) or not any(abuse.get(key) is True for key in ("mining", "bt")):
            return [], "not_required"

        inventory = self._app._host_firewall_interface_inventory(conn, host_id, now)
        if inventory["status"] != "ready" or inventory["stale"]:
            return None, "inventory_unavailable"

        eligible = [item for item in inventory["interfaces"] if item["firewall_eligible"]]
        runtimes = abuse.get("runtimes") if isinstance(abuse.get("runtimes"), list) else []
        requested_interfaces = abuse.get("interfaces") if isinstance(abuse.get("interfaces"), list) else []
        if runtimes:
            selected = [item["name"] for item in eligible if set(item["runtimes"]).intersection(runtimes)]
            if not selected:
                return None, "runtime_not_found"
            return list(dict.fromkeys(selected)), "ready"

        eligible_names = {item["name"] for item in eligible}
        if not requested_interfaces or any(name not in eligible_names for name in requested_interfaces):
            return None, "interface_not_found"
        return list(dict.fromkeys(requested_interfaces)), "ready"

    def _materialize_host_firewall_policy(
        self, conn: sqlite3.Connection, host_id: str, policy: Dict[str, Any], now: int | None = None
    ) -> Tuple[Dict[str, Any] | None, str]:
        """Build the host-local policy sent to Runman; never send logical runtime selectors."""
        targets, status = self._app._host_firewall_policy_targets(conn, host_id, policy, now)
        if targets is None:
            return None, status
        materialized = dict(policy)
        abuse = dict(policy.get("abuse") or {})
        if any(abuse.get(key) is True for key in ("mining", "bt")):
            abuse["interfaces"] = targets
        abuse.pop("runtimes", None)
        materialized["abuse"] = abuse
        validated = self._app._validate_host_firewall_policy(materialized)
        validated["abuse"].pop("runtimes", None)
        return validated, status

    def _latest_host_firewall_action(self, conn: sqlite3.Connection, host_id: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT id,status,result_message,created_at,updated_at,attempts,params_json,action_type,requested_by FROM security_actions "
            "WHERE host_id=? AND action_type IN ('apply_host_firewall_policy','delete_host_firewall_rule') ORDER BY id DESC LIMIT 1",
            (host_id,),
        ).fetchone()

    def _host_firewall_action_summary(self, conn: sqlite3.Connection, host_id: str) -> Dict[str, Any]:
        row = self._app._latest_host_firewall_action(conn, host_id)
        if row is None:
            return {}
        try:
            params = json.loads(row["params_json"] or "{}")
        except (TypeError, ValueError):
            params = {}
        params = params if isinstance(params, dict) else {}
        rollback = params.get("rollback") if isinstance(params.get("rollback"), dict) else {}
        action_policy = params.get("policy") if isinstance(params.get("policy"), dict) else {}
        policy_revision = action_policy.get("revision")
        rollback_revision = rollback.get("target_revision") if rollback.get("requested") is True else None
        return {
            "id": int(row["id"]),
            "status": str(row["status"] or "unknown"),
            "action_type": str(row["action_type"] or ""),
            "attempts": int(row["attempts"] or 0),
            "created_at": int(row["created_at"] or 0),
            "updated_at": int(row["updated_at"] or 0),
            "result_message": str(row["result_message"] or "")[:240],
            "policy_revision": policy_revision if type(policy_revision) is int and policy_revision >= 0 else None,
            "rollback": {
                "requested": rollback.get("requested") is True,
                "target_revision": rollback_revision if type(rollback_revision) is int and rollback_revision >= 0 else None,
            },
        }

    def _enqueue_host_firewall_policy(
        self,
        conn: sqlite3.Connection,
        host_id: str,
        node_id: str,
        policy: Dict[str, Any],
        requested_by: str,
        now: int,
        fleet_revision: int,
        rollback_target_revision: int | None = None,
    ) -> int:
        existing = conn.execute(
            "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policies WHERE host_id=?",
            (host_id,),
        ).fetchone()
        revision = (int(existing["revision"]) if existing else 0) + 1
        policy_with_revision = {"revision": revision, **policy}
        policy_json = json.dumps(policy, ensure_ascii=False, separators=(",", ":"))
        requires_rfw = self._app._policy_has_rfw_effect(policy)
        if existing and self._app._stored_policy_has_rfw_effect(str(existing["policy_json"] or "{}")):
            requires_rfw = True
        if existing and str(existing["policy_json"] or "") != policy_json:
            conn.execute(
                "INSERT INTO host_firewall_policy_history(host_id,revision,policy_json,updated_by,updated_at,source_fleet_revision) VALUES(?,?,?,?,?,?)",
                (
                    host_id,
                    int(existing["revision"]),
                    str(existing["policy_json"] or "{}"),
                    str(existing["updated_by"] or ""),
                    int(existing["updated_at"] or 0),
                    int(existing["source_fleet_revision"] or 0),
                ),
            )
            conn.execute(
                "DELETE FROM host_firewall_policy_history WHERE host_id=? AND id NOT IN (SELECT id FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 20)",
                (host_id, host_id),
            )
        conn.execute(
            "INSERT INTO host_firewall_policies(host_id,revision,policy_json,updated_by,updated_at,source_fleet_revision) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET revision=excluded.revision,"
            "policy_json=excluded.policy_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at,"
            "source_fleet_revision=excluded.source_fleet_revision",
            (host_id, revision, policy_json, requested_by, now, fleet_revision),
        )
        conn.execute(
            "UPDATE security_actions SET status='cancelled',result_message='已被更新的母机防火墙策略取代',updated_at=? "
            "WHERE host_id=? AND action_type='apply_host_firewall_policy' AND status IN ('queued','dispatched')",
            (now, host_id),
        )
        action_params: Dict[str, Any] = {
            "expected_node_id": node_id,
            "policy": policy_with_revision,
            "requires_rfw": requires_rfw,
        }
        if fleet_revision > 0:
            action_params["fleet_revision"] = int(fleet_revision)
        if rollback_target_revision is not None:
            action_params["rollback"] = {"requested": True, "target_revision": int(rollback_target_revision)}
        cur = conn.execute(
            "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
            "VALUES(0,?,'host','','__host__','apply_host_firewall_policy',?,'queued',?,?,?)",
            (host_id, json.dumps(action_params, ensure_ascii=False), requested_by, now, now),
        )
        return int(cur.lastrowid)

    def _maybe_queue_fleet_firewall_policy(
        self,
        conn: sqlite3.Connection,
        host_id: str,
        node_id: str,
        ts: int,
        security: Dict[str, Any],
    ) -> bool:
        runtime = security.get("host_firewall") if isinstance(security, dict) else None
        if not node_id:
            return False
        fleet = conn.execute("SELECT revision,policy_json FROM fleet_firewall_policy WHERE id=1").fetchone()
        if fleet is None or int(fleet["revision"] or 0) < 1:
            return False
        try:
            policy = self._app._validate_host_firewall_policy(json.loads(fleet["policy_json"] or "{}"))
        except (HTTPException, TypeError, ValueError):
            return False
        local_policy = conn.execute(
            "SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)
        ).fetchone()
        requires_rfw = self._app._policy_has_rfw_effect(policy) or (
            local_policy is not None and self._app._stored_policy_has_rfw_effect(str(local_policy["policy_json"] or "{}"))
        )
        if requires_rfw and (not isinstance(runtime, dict) or runtime.get("control_api") != "ready"):
            return False
        fleet_revision = int(fleet["revision"])
        state = conn.execute(
            "SELECT revision,source_fleet_revision FROM host_firewall_policies WHERE host_id=?", (host_id,)
        ).fetchone()
        already_on_fleet_revision = (
            state is not None and int(state["source_fleet_revision"] or 0) >= fleet_revision
        )
        live_readback = (
            self._app._host_firewall_live_readback(conn, host_id, ts)
            if requires_rfw
            else {"status": "unavailable", "stale": True}
        )
        drift_repair_needed = (
            already_on_fleet_revision
            and live_readback.get("status") == "ready"
            and live_readback.get("stale") is False
            and live_readback.get("sync_status") == "drifted"
        )
        latest = self._app._latest_host_firewall_action(conn, host_id)
        same_fleet_revision = False
        retry_failed_unverified = False
        if latest is not None:
            try:
                latest_params = json.loads(latest["params_json"] or "{}")
            except (TypeError, ValueError):
                latest_params = {}
            same_fleet_revision = int(latest_params.get("fleet_revision") or 0) == fleet_revision
            if same_fleet_revision and latest["status"] in {"queued", "dispatched", "running"}:
                return False
            if same_fleet_revision and latest["status"] == "failed":
                if ts - int(latest["updated_at"] or 0) < 900:
                    return False
                failed_for_revision = int(
                    conn.execute(
                        """SELECT COUNT(*) FROM security_actions
                           WHERE host_id=? AND action_type='apply_host_firewall_policy' AND status='failed'
                             AND json_valid(params_json)
                             AND CAST(json_extract(params_json,'$.fleet_revision') AS INTEGER)=?""",
                        (host_id, fleet_revision),
                    ).fetchone()[0]
                    or 0
                )
                snapshot = live_readback.get("snapshot") if isinstance(live_readback.get("snapshot"), dict) else {}
                readback_matches_policy = (
                    live_readback.get("status") == "ready"
                    and live_readback.get("stale") is False
                    and live_readback.get("sync_status") == "in_sync"
                    and live_readback.get("drift_count") == 0
                    and live_readback.get("missing_count") == 0
                    and state is not None
                    and snapshot.get("policy_revision") == int(state["revision"] or 0)
                )
                retry_failed_unverified = failed_for_revision < 3 and not readback_matches_policy
        if already_on_fleet_revision and not drift_repair_needed and not retry_failed_unverified:
            return False
        if (
            latest is not None
            and same_fleet_revision
            and latest["status"] == "succeeded"
            and drift_repair_needed
            and int(live_readback.get("observed_at") or 0) <= int(latest["updated_at"] or 0)
        ):
            return False
        if self._app._policy_required_protocols(policy):
            compatibility = self._app._policy_protocol_compatibility(policy, live_readback)
            if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
                return False
        host_policy, _target_status = self._app._materialize_host_firewall_policy(conn, host_id, policy, ts)
        if host_policy is None:
            return False
        self._app._enqueue_host_firewall_policy(
            conn, host_id, node_id, host_policy, "fleet-policy-reconcile", ts, fleet_revision
        )
        return True

    def _ingest_host_firewall_events(
        self, conn: sqlite3.Connection, host_id: str, security: Dict[str, Any], ts: int
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Validate, deduplicate, and turn bounded RFW event pages into grouped alerts."""
        host_firewall = security.get("host_firewall") if isinstance(security, dict) else None
        if not isinstance(host_firewall, dict) or host_firewall.get("events_api") != "ready":
            return [], ""
        instance_id = str(host_firewall.get("instance_id") or "")
        next_cursor = str(host_firewall.get("next_cursor") or "")
        events = host_firewall.get("events")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", instance_id):
            return [], ""
        cursor_match = re.fullmatch(r"([A-Za-z0-9_-]{1,80}):(\d{1,20})", next_cursor)
        if not cursor_match or cursor_match.group(1) != instance_id or not isinstance(events, list) or len(events) > 100:
            return [], ""
        try:
            page_sequence = int(cursor_match.group(2))
        except ValueError:
            return [], ""

        normalized_events: List[Dict[str, Any]] = []
        last_page_sequence = 0
        for event in events:
            if not isinstance(event, dict):
                return [], ""
            sequence = event.get("sequence")
            observed_at = event.get("observed_at")
            if type(sequence) is not int or sequence < 1 or type(observed_at) is not int or observed_at <= 0:
                return [], ""
            if event.get("cursor") != f"{instance_id}:{sequence}" or sequence <= last_page_sequence:
                return [], ""
            last_page_sequence = sequence
            try:
                source_ip = str(ipaddress.ip_address(str(event.get("source_ip") or "")))
                destination_ip = str(ipaddress.ip_address(str(event.get("destination_ip") or "")))
            except ValueError:
                return [], ""
            source_port = event.get("source_port")
            destination_port = event.get("destination_port")
            if (
                type(source_port) is not int
                or not 0 <= source_port <= 65535
                or type(destination_port) is not int
                or not 0 <= destination_port <= 65535
            ):
                return [], ""
            transport = str(event.get("transport") or "")
            app_protocol = str(event.get("app_protocol") or "")
            direction = str(event.get("direction") or "")
            action = str(event.get("action") or "")
            if (
                transport not in {"tcp", "udp", "unknown"}
                or app_protocol not in {"http", "tls", "socks", "fet", "wireguard", "ssh", "openvpn", "quic", "mtproto", "unknown"}
                or direction not in {"in", "out"}
                or action not in {"pass", "block"}
            ):
                return [], ""
            countries = event.get("rule_countries")
            if not isinstance(countries, list) or len(countries) > 30:
                return [], ""
            normalized_countries = sorted({str(code).strip().upper() for code in countries})
            if any(not re.fullmatch(r"[A-Z]{2}", code) for code in normalized_countries):
                return [], ""
            normalized_events.append(
                {
                    "sequence": sequence,
                    "observed_at": observed_at,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "transport": transport,
                    "app_protocol": app_protocol,
                    "direction": direction,
                    "action": action,
                    "rule_id": event.get("rule_id") if type(event.get("rule_id")) is int else None,
                    "rule_countries": normalized_countries,
                }
            )
        if page_sequence < last_page_sequence:
            return [], ""

        previous = conn.execute(
            "SELECT instance_id,sequence FROM host_firewall_event_state WHERE host_id=?", (host_id,)
        ).fetchone()
        previous_instance = str(previous["instance_id"]) if previous is not None else ""
        previous_sequence = int(previous["sequence"]) if previous is not None else 0
        same_instance = previous_instance == instance_id
        last_sequence = previous_sequence if same_instance else 0
        gap_reasons: List[str] = []
        dropped = max(0, min(int(host_firewall.get("dropped") or 0), 1_000_000))
        if previous_instance and not same_instance:
            gap_reasons.append("RFW 实例已重启或替换")
        if host_firewall.get("cursor_reset") is True:
            gap_reasons.append("事件游标被重置")
        if dropped > 0:
            gap_reasons.append(f"RFW 环形缓冲区丢弃 {dropped} 条")

        fresh_events = []
        for event in normalized_events:
            sequence = int(event["sequence"])
            if same_instance and sequence <= previous_sequence:
                continue
            if same_instance and last_sequence > 0 and sequence > last_sequence + 1:
                gap_reasons.append(f"事件序号从 {last_sequence} 跳至 {sequence}")
            fresh_events.append(event)
            last_sequence = max(last_sequence, sequence)

        rfw_cn_protocols = self._app.RFW_CN_ALERT_PROTOCOLS
        grouped: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = {}
        for event in fresh_events:
            if event["app_protocol"] not in rfw_cn_protocols or "CN" not in event["rule_countries"]:
                continue
            country_confidence = "exact_cn_rule" if event["rule_countries"] == ["CN"] else "rule_scope_includes_cn"
            key = (event["app_protocol"], event["direction"], event["action"], country_confidence)
            grouped.setdefault(key, []).append(event)

        alerts: List[Dict[str, Any]] = []
        for (app_protocol, direction, action, country_confidence), group in grouped.items():
            is_pass = action == "pass"
            protocol_label = {
                "wireguard": "WireGuard",
                "socks": "SOCKS",
                "fet": "FET（高熵加密特征，可能含 SS 类）",
                "mtproto": "MTProto（混淆传输特征）",
                "openvpn": "OpenVPN",
            }.get(app_protocol, app_protocol)
            if country_confidence == "exact_cn_rule":
                direction_label = "出站到 CN" if direction == "out" else "来自 CN 的入站"
            else:
                direction_label = (
                    "出站命中包含 CN 的 GeoIP 范围（实际国家未知）"
                    if direction == "out"
                    else "入站命中包含 CN 的 GeoIP 范围（实际国家未知）"
                )
            action_label = "被放行" if is_pass else "已阻断"
            scope_note = (
                "规则仅包含 CN，国家范围精确。"
                if country_confidence == "exact_cn_rule"
                else "规则国家范围包含 CN，但 RFW 事件未携带实际命中国家，需人工复核。"
            )
            protocol_note = {
                "fet": "FET 依首包高熵特征识别，不能确证 Shadowsocks；其他非 TLS 加密流量也可能命中，存在误报。",
                "mtproto": "MTProto 仅依据已知混淆初始化标记识别，覆盖不完整，不代表确认了完整会话。",
                "wireguard": "WireGuard 识别主要基于可见的初始握手；协议命中不代表恶意或未授权。",
                "socks": "SOCKS 协议命中不代表服务未授权或存在滥用。",
                "openvpn": "OpenVPN 是常见 VPN 协议；协议命中不代表服务未授权或存在滥用。",
            }.get(app_protocol, "")
            samples = [
                f"{event['source_ip']}:{event['source_port']} → {event['destination_ip']}:{event['destination_port']}"
                for event in group[:10]
            ]
            rule_ids = sorted({int(event["rule_id"]) for event in group if event.get("rule_id") is not None})
            alert_type = f"rfw_cn_{app_protocol}_{direction}_{action}"
            title = f"RFW {protocol_label} 连接{action_label}"
            message = (
                f"RFW 检测到 {direction_label} 的 {protocol_label} 流量，共 {len(group)} 条事件，已{action_label}。"
                f"样例：{'；'.join(samples) if samples else '无端点样例'}。{scope_note}{protocol_note}"
            )
            alerts.append(
                {
                    "type": alert_type,
                    "severity": "critical" if is_pass else "warning",
                    "runtime": "host",
                    "project": "",
                    "container_name": "__host__",
                    "title": title,
                    "message": message[:2000],
                    "value": float(len(group)),
                    "threshold": 1.0,
                    "instance_id": instance_id,
                    "rfw_evidence": {
                        "event_count": len(group),
                        "app_protocol": app_protocol,
                        "direction": direction,
                        "packet_action": action,
                        "country_confidence": country_confidence,
                        "rule_ids": rule_ids[:20],
                        "samples": samples,
                        "first_observed_at": min(int(event["observed_at"]) for event in group),
                        "last_observed_at": max(int(event["observed_at"]) for event in group),
                    },
                }
            )

        if gap_reasons:
            alerts.append(
                {
                    "type": "rfw_event_gap",
                    "severity": "warning",
                    "runtime": "host",
                    "project": "",
                    "container_name": "__host__",
                    "title": "RFW 连接事件存在采集缺口",
                    "message": "；".join(sorted(set(gap_reasons))) + "。事件统计可能不完整，不能据此推断未发生连接。",
                    "value": float(dropped),
                    "threshold": 0.0,
                    "instance_id": instance_id,
                    "rfw_evidence": {"dropped": dropped, "cursor_reset": host_firewall.get("cursor_reset") is True},
                }
            )

        last_sequence = max(last_sequence, page_sequence)
        conn.execute(
            "INSERT INTO host_firewall_event_state(host_id,instance_id,sequence,cursor,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(host_id) DO UPDATE SET instance_id=excluded.instance_id,sequence=excluded.sequence,cursor=excluded.cursor,updated_at=excluded.updated_at",
            (host_id, instance_id, last_sequence, next_cursor, ts),
        )
        return alerts, next_cursor

    def _fleet_firewall_node_state(
        self,
        conn: sqlite3.Connection,
        host: sqlite3.Row,
        fleet_revision: int,
        now: int,
        required_protocols: List[str] | None = None,
        required_policy: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        stale_seconds = self._app.STALE_SECONDS
        host_id = str(host["host_id"])
        node_id = str(host["node_id"] or "")
        last_seen = int(host["last_seen"] or 0)
        online = bool(node_id) and now - last_seen <= stale_seconds
        runtime = self._app._host_firewall_runtime_status(conn, host_id, now)
        live_readback = self._app._host_firewall_live_readback(conn, host_id, now)
        interface_inventory = self._app._host_firewall_interface_inventory(conn, host_id, now)
        container_interfaces = {
            runtime_name: [
                item["name"]
                for item in interface_inventory["interfaces"]
                if item["firewall_eligible"] and runtime_name in item["runtimes"]
            ]
            for runtime_name in ("incus", "podman", "runman")
        }
        policy_row = conn.execute(
            "SELECT revision,source_fleet_revision,policy_json,updated_by FROM host_firewall_policies WHERE host_id=?",
            (host_id,),
        ).fetchone()
        local_revision = int(policy_row["revision"] or 0) if policy_row is not None else 0
        applied_fleet_revision = int(policy_row["source_fleet_revision"] or 0) if policy_row is not None else 0
        stored_policy_raw = str(policy_row["policy_json"] or "{}") if policy_row is not None else "{}"
        try:
            local_policy = (
                self._app._validate_host_firewall_policy(json.loads(stored_policy_raw))
                if policy_row is not None
                else self._app._empty_host_firewall_policy()
            )
        except (HTTPException, TypeError, ValueError):
            local_policy = self._app._empty_host_firewall_policy()
        effective_policy = (
            required_policy if fleet_revision > 0 and isinstance(required_policy, dict) else local_policy
        )
        _targets, target_status = self._app._host_firewall_policy_targets(conn, host_id, effective_policy, now)
        protocol_status = self._app._policy_protocol_compatibility(effective_policy, live_readback)
        policy_abuse = effective_policy.get("abuse") if isinstance(effective_policy.get("abuse"), dict) else {}
        container_policy_enabled = any(policy_abuse.get(key) is True for key in ("mining", "bt"))
        rfw_required = self._app._policy_has_rfw_effect(effective_policy) or (
            policy_row is not None and self._app._stored_policy_has_rfw_effect(stored_policy_raw)
        )
        action = self._app._latest_host_firewall_action(conn, host_id)
        try:
            action_params = json.loads(action["params_json"] or "{}") if action is not None else {}
        except (TypeError, ValueError):
            action_params = {}
        action_params = action_params if isinstance(action_params, dict) else {}
        action_policy = action_params.get("policy") if isinstance(action_params.get("policy"), dict) else {}
        action_requires_rfw = (
            (
                action_params.get("requires_rfw") is True
                or str(action["action_type"] or "") == "delete_host_firewall_rule"
                or (
                    str(action["action_type"] or "") == "apply_host_firewall_policy"
                    and self._app._policy_has_rfw_effect(action_policy)
                )
            )
            if action is not None
            else False
        )
        rfw_action = action if action_requires_rfw else None
        auto_speedtest_default = bool(
            policy_row is not None and str(policy_row["updated_by"] or "") == SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY
        )
        rfw_status = self._app._host_firewall_component_status(
            registered=bool(node_id),
            online=online,
            configured=rfw_required,
            runtime=runtime,
            live_readback=live_readback,
            protocol_status=protocol_status,
            target_status=target_status,
            container_policy_enabled=container_policy_enabled,
            action=rfw_action,
            local_revision=local_revision,
            expected_fleet_revision=fleet_revision,
            applied_fleet_revision=applied_fleet_revision,
        )
        container_protection_status = self._app._host_container_protection_status(
            conn,
            host_id=host_id,
            now=now,
            online=online,
            agent_version=str(host["agent_version"] or "unknown"),
            policy=effective_policy,
            policy_row_exists=policy_row is not None,
            policy_revision=local_revision,
            auto_default=(fleet_revision == 0 and policy_row is None) or auto_speedtest_default,
            latest_action=action,
            fleet_revision=fleet_revision,
            applied_fleet_revision=applied_fleet_revision,
        )
        status = "unregistered"
        if node_id:
            status = "offline" if not online else "awaiting_capability"
            if online and not rfw_required:
                if action is not None and action["status"] in {"queued", "dispatched", "running"}:
                    status = "queued"
                elif action is not None and action["status"] == "failed":
                    status = "apply_failed"
                elif auto_speedtest_default and action is not None and action["status"] == "succeeded":
                    status = "last_apply_succeeded"
                elif (
                    fleet_revision > 0
                    and applied_fleet_revision == fleet_revision
                    and action is not None
                    and action["status"] == "succeeded"
                ):
                    status = "last_apply_succeeded"
                elif fleet_revision > 0:
                    status = "not_synced"
                elif policy_row is None and not self._app._agent_supports_speedtest_policy(host["agent_version"]):
                    status = "speedtest_agent_update_required"
                elif policy_row is None:
                    status = "speedtest_auto_pending"
                else:
                    status = "ready"
            elif online and not runtime["stale"] and runtime["control_api"] == "unsupported":
                status = "runman_update_required"
            elif online and not runtime["stale"] and runtime["control_api"] == "unavailable":
                status = "runman_unavailable"
            elif online and not live_readback["stale"] and protocol_status["unsupported_protocols"]:
                status = "rfw_protocol_update_required"
            elif online and runtime["stale"]:
                status = (
                    "awaiting_interfaces"
                    if container_policy_enabled and target_status == "inventory_unavailable"
                    else "firewall_status_stale"
                )
            elif online and runtime["control_api"] == "ready" and protocol_status["unknown_protocols"]:
                status = "awaiting_rfw_capability"
            elif runtime["control_api"] == "ready":
                if container_policy_enabled and target_status == "inventory_unavailable":
                    status = "awaiting_interfaces"
                elif container_policy_enabled and target_status in {"runtime_not_found", "interface_not_found"}:
                    status = "interfaces_not_found"
                elif action is not None and action["status"] in {"queued", "dispatched", "running"}:
                    status = "queued"
                elif action is not None and action["status"] == "failed":
                    status = "apply_failed"
                elif (
                    live_readback["status"] == "ready"
                    and not live_readback["stale"]
                    and live_readback["sync_status"] == "drifted"
                ):
                    status = "drifted"
                elif (
                    fleet_revision > 0
                    and applied_fleet_revision == fleet_revision
                    and action is not None
                    and action["status"] == "succeeded"
                ):
                    status = "last_apply_succeeded"
                elif fleet_revision > 0:
                    status = "not_synced"
                else:
                    status = "ready"
        return {
            "host_id": host_id,
            "registered": bool(node_id),
            "online": online,
            "agent_version": str(host["agent_version"] or "unknown"),
            "control_api": runtime["control_api"],
            "control_api_reason": runtime["control_api_reason"],
            "control_api_http_status": runtime["control_api_http_status"],
            "control_api_stale": runtime["stale"],
            "observed_at": runtime["observed_at"],
            "live_readback": {key: value for key, value in live_readback.items() if key != "snapshot"},
            "local_revision": local_revision,
            "fleet_revision": applied_fleet_revision,
            "speedtest_auto_default": auto_speedtest_default,
            "speedtest_policy_supported": self._app._agent_supports_speedtest_policy(host["agent_version"]),
            "state": status,
            "rfw_status": rfw_status,
            "rfw_configured": rfw_required,
            "container_protection_status": container_protection_status,
            "required_protocols": protocol_status["required_protocols"],
            "unsupported_protocols": protocol_status["unsupported_protocols"],
            "unknown_protocols": protocol_status["unknown_protocols"],
            "container_interfaces": {
                "status": interface_inventory["status"],
                "observed_at": interface_inventory["observed_at"],
                "stale": interface_inventory["stale"],
                "by_runtime": container_interfaces,
            },
            "last_action": None
            if action is None
            else {
                "id": int(action["id"]),
                "status": str(action["status"]),
                "message": str(action["result_message"] or ""),
                "updated_at_utc8": self._app.format_utc8(int(action["updated_at"] or 0)),
            },
        }

    def _host_firewall_component_status(
        self,
        *,
        registered: bool,
        online: bool,
        configured: bool,
        runtime: Dict[str, Any],
        live_readback: Dict[str, Any],
        protocol_status: Dict[str, List[str]],
        target_status: str,
        container_policy_enabled: bool,
        action: sqlite3.Row | None,
        local_revision: int,
        expected_fleet_revision: int,
        applied_fleet_revision: int,
    ) -> str:
        """Classify RFW from current RFW evidence only, never from Agent file persistence."""
        if not registered:
            return "unregistered"
        if not online:
            return "offline"
        if not configured:
            return "not_configured"
        if runtime.get("stale"):
            return "status_stale"
        if runtime.get("control_api") == "unsupported":
            return "runman_update_required"
        if runtime.get("control_api") == "unavailable":
            return "runman_unavailable"
        if runtime.get("control_api") != "ready":
            return "awaiting_capability"
        if live_readback.get("status") == "ready" and not live_readback.get("stale"):
            if protocol_status.get("unsupported_protocols"):
                return "rfw_protocol_update_required"
            if protocol_status.get("unknown_protocols"):
                return "awaiting_rfw_capability"
        if live_readback.get("status") != "ready" or live_readback.get("stale"):
            return "readback_unavailable"
        if live_readback.get("sync_status") == "drifted":
            return "drifted"
        observed_revision = live_readback.get("policy_revision")
        if (
            live_readback.get("sync_status") == "in_sync"
            and int(live_readback.get("drift_count") or 0) == 0
            and int(live_readback.get("missing_count") or 0) == 0
            and type(observed_revision) is int
            and observed_revision == local_revision
            and (expected_fleet_revision == 0 or applied_fleet_revision == expected_fleet_revision)
        ):
            return "verified"
        if container_policy_enabled and target_status == "inventory_unavailable":
            return "awaiting_interfaces"
        if container_policy_enabled and target_status in {"runtime_not_found", "interface_not_found"}:
            return "interfaces_not_found"
        if action is not None and action["status"] in {"queued", "dispatched", "running"}:
            return "queued"
        if action is not None and action["status"] == "failed":
            return "apply_failed"
        return "not_synced"

    def _host_container_protection_status(
        self,
        conn: sqlite3.Connection,
        *,
        host_id: str,
        now: int,
        online: bool,
        agent_version: str,
        policy: Dict[str, Any],
        policy_row_exists: bool,
        policy_revision: int,
        auto_default: bool,
        latest_action: sqlite3.Row | None,
        fleet_revision: int,
        applied_fleet_revision: int,
    ) -> Dict[str, Any]:
        """Aggregate per-container Agent readbacks for Incus/Podman protection."""
        stale_seconds = self._app.STALE_SECONDS
        abuse = policy.get("abuse") if isinstance(policy, dict) and isinstance(policy.get("abuse"), dict) else {}
        services = sorted(
            {str(item).strip().lower() for item in abuse.get("services", []) if isinstance(item, str) and item.strip()}
        )
        runtimes = sorted(
            {str(item).strip().lower() for item in abuse.get("service_runtimes", []) if item in {"incus", "podman", "runman"}}
        )
        configured = bool(services and runtimes)
        result: Dict[str, Any] = {
            "configured": configured,
            "state": "not_configured",
            "services": services,
            "runtimes": runtimes,
            "policy_revision": policy_revision,
            "observed_at": 0,
            "age_seconds": None,
            "containers_seen": 0,
            "containers_fresh": 0,
            "containers_verified": 0,
            "containers_waiting_revision": 0,
            "containers_unverified": 0,
            "containers_stale": 0,
            "reason": "",
        }
        if not configured:
            return result
        if not online:
            result.update(state="node_offline", reason="node_offline")
            return result
        if not self._app._agent_supports_speedtest_policy(agent_version):
            result.update(state="agent_update_required", reason="agent_update_required")
            return result
        if not policy_row_exists or policy_revision < 1:
            state = "waiting_policy" if auto_default or fleet_revision > 0 else "policy_not_applied"
            result.update(state=state, reason="policy_not_applied")
            return result

        action = latest_action
        if action is not None:
            try:
                params = json.loads(action["params_json"] or "{}")
            except (TypeError, ValueError):
                params = {}
            action_policy = params.get("policy") if isinstance(params, dict) and isinstance(params.get("policy"), dict) else {}
            action_revision = action_policy.get("revision")
            action_is_current = type(action_revision) is int and action_revision == policy_revision
            if action_is_current and action["status"] in {"queued", "dispatched", "running"}:
                result.update(state="applying", reason="policy_action_pending")
                return result
            if action_is_current and action["status"] == "failed":
                result.update(state="apply_failed", reason="policy_action_failed")
                return result
        if fleet_revision > 0 and applied_fleet_revision != fleet_revision:
            result.update(state="waiting_policy", reason="fleet_policy_not_applied")
            return result

        placeholders = ",".join("?" for _ in runtimes)
        rows = conn.execute(
            "SELECT runtime,project,container_name,ts,payload_json FROM ("
            "SELECT runtime,project,container_name,ts,payload_json,"
            "ROW_NUMBER() OVER (PARTITION BY runtime,project,container_name ORDER BY ts DESC,id DESC) AS row_number "
            f"FROM reports WHERE host_id=? AND runtime IN ({placeholders}) AND ts>=?"
            ") WHERE row_number=1 ORDER BY runtime,project,container_name",
            (host_id, *runtimes, now - 24 * 60 * 60),
        ).fetchall()
        result["containers_seen"] = len(rows)
        if not rows:
            result.update(state="waiting_samples", reason="no_container_reports")
            return result

        latest_at = max(int(row["ts"] or 0) for row in rows)
        result["observed_at"] = latest_at
        result["age_seconds"] = max(0, now - latest_at) if latest_at else None
        verified = waiting_revision = unverified = stale = fresh = 0
        for row in rows:
            sampled_at = int(row["ts"] or 0)
            if sampled_at <= 0 or sampled_at > now + 30 or now - sampled_at > stale_seconds:
                stale += 1
                continue
            fresh += 1
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, ValueError):
                payload = {}
            security = payload.get("security") if isinstance(payload, dict) and isinstance(payload.get("security"), dict) else {}
            guard = security.get("speedtest_guard") if isinstance(security.get("speedtest_guard"), dict) else None
            if guard is None:
                unverified += 1
                continue
            reported_revision = guard.get("policy_revision")
            if type(reported_revision) is not int or reported_revision != policy_revision:
                waiting_revision += 1
                continue
            reported_services = sorted(
                {str(item).strip().lower() for item in guard.get("services", []) if isinstance(item, str) and item.strip()}
            )
            expected_services = services if row["runtime"] in runtimes else []
            guard_state = str(guard.get("state") or "")
            if reported_services == expected_services and guard_state in {"blocked", "not_detected"}:
                verified += 1
            else:
                unverified += 1

        result.update(
            {
                "containers_fresh": fresh,
                "containers_verified": verified,
                "containers_waiting_revision": waiting_revision,
                "containers_unverified": unverified,
                "containers_stale": stale,
            }
        )
        if fresh == 0:
            result.update(state="samples_stale", reason="container_samples_stale")
        elif verified == fresh and waiting_revision == 0 and unverified == 0 and stale == 0:
            result.update(state="active", reason="all_fresh_samples_verified")
        elif verified:
            result.update(state="partial", reason="some_container_samples_unverified")
        elif waiting_revision:
            result.update(state="waiting_revision", reason="agent_has_not_reported_desired_revision")
        else:
            result.update(state="unverified", reason="guard_readback_missing_or_failed")
        return result

    def get_host_firewall_policy(self, host_id: str) -> JSONResponse:
        if not host_id or len(host_id) > 200:
            raise HTTPException(status_code=400, detail="主机标识无效")
        conn = self._app.db()
        try:
            now = int(time.time())
            host = conn.execute("SELECT node_id,agent_version FROM hosts WHERE host_id=?", (host_id,)).fetchone()
            if host is None:
                raise HTTPException(status_code=404, detail="主机不存在")
            row = conn.execute(
                "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policies WHERE host_id=?",
                (host_id,),
            ).fetchone()
            if row is None:
                revision, policy, updated_by, updated_at, source_fleet_revision = (
                    0,
                    self._app._empty_host_firewall_policy(),
                    "",
                    0,
                    0,
                )
            else:
                try:
                    policy = json.loads(row["policy_json"] or "{}")
                except (TypeError, ValueError):
                    policy = self._app._empty_host_firewall_policy()
                try:
                    policy = self._app._validate_host_firewall_policy(policy)
                except HTTPException:
                    policy = self._app._empty_host_firewall_policy()
                revision, updated_by, updated_at, source_fleet_revision = (
                    int(row["revision"]),
                    str(row["updated_by"] or ""),
                    int(row["updated_at"] or 0),
                    int(row["source_fleet_revision"] or 0),
                )
            action = self._app._latest_host_firewall_action(conn, host_id)
            latest = (
                None
                if action is None
                else {
                    "id": int(action["id"]),
                    "status": str(action["status"]),
                    "message": str(action["result_message"] or ""),
                    "updated_at_utc8": self._app.format_utc8(int(action["updated_at"] or 0)),
                }
            )
            return JSONResponse(
                {
                    "host_id": host_id,
                    "agent_ready": bool(str(host["node_id"] or "")),
                    "revision": revision,
                    "source_fleet_revision": source_fleet_revision,
                    "policy": policy,
                    "runtime_status": self._app._host_firewall_runtime_status(conn, host_id, now),
                    "interface_inventory": self._app._host_firewall_interface_inventory(conn, host_id, now),
                    "live_readback": self._app._host_firewall_live_readback(conn, host_id, now),
                    "updated_by": updated_by,
                    "speedtest_auto_default": updated_by == SPEEDTEST_AUTO_DEFAULT_REQUESTED_BY,
                    "speedtest_policy_supported": self._app._agent_supports_speedtest_policy(host["agent_version"]),
                    "updated_at_utc8": self._app.format_utc8(updated_at) if updated_at else "",
                    "latest_action": latest,
                    "policy_history": [
                        {
                            "revision": int(item["revision"]),
                            "policy": json.loads(item["policy_json"] or "{}"),
                            "updated_by": str(item["updated_by"] or ""),
                            "updated_at_utc8": self._app.format_utc8(int(item["updated_at"] or 0)),
                            "source_fleet_revision": int(item["source_fleet_revision"] or 0),
                        }
                        for item in conn.execute(
                            "SELECT revision,policy_json,updated_by,updated_at,source_fleet_revision FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 20",
                            (host_id,),
                        ).fetchall()
                    ],
                }
            )
        finally:
            conn.close()

    def _prepare_host_firewall_recovery(self, conn: sqlite3.Connection, host_id: str, now: int):
        """Fail closed unless a single online host has fresh, compatible RFW readback."""
        stale_seconds = self._app.STALE_SECONDS
        host = conn.execute("SELECT node_id,last_seen FROM hosts WHERE host_id=?", (host_id,)).fetchone()
        if host is None:
            raise HTTPException(status_code=404, detail="主机不存在")
        node_id = str(host["node_id"] or "")
        if not node_id or now - int(host["last_seen"] or 0) > stale_seconds:
            raise HTTPException(status_code=409, detail="母机离线或上报过期，未下发防火墙操作")
        fleet = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
        if fleet is not None and int(fleet["revision"] or 0) > 0:
            raise HTTPException(status_code=409, detail="全局策略模板已启用；请从全局策略入口处理，避免单机状态分叉")
        runtime = self._app._host_firewall_runtime_status(conn, host_id, now)
        if runtime.get("stale"):
            raise HTTPException(status_code=409, detail="Runman 防火墙能力状态已过期；等待 Agent 重新上报后再操作")
        if runtime.get("control_api") != "ready":
            raise HTTPException(status_code=409, detail="Runman 防火墙控制接口尚未确认可用")
        readback = self._app._host_firewall_live_readback(conn, host_id, now)
        if readback.get("status") != "ready" or readback.get("stale") or not isinstance(readback.get("snapshot"), dict):
            raise HTTPException(status_code=409, detail="RFW 实时读回缺失或已过期，未下发操作")
        if conn.execute(
            "SELECT 1 FROM security_actions WHERE host_id=? AND action_type IN ('apply_host_firewall_policy','delete_host_firewall_rule') AND status IN ('queued','dispatched','running') LIMIT 1",
            (host_id,),
        ).fetchone():
            raise HTTPException(status_code=409, detail="该主机已有防火墙操作正在执行")
        return node_id, readback

    async def retry_host_firewall_policy(self, request: Request) -> JSONResponse:
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以重试母机防火墙策略")
        try:
            payload = json.loads(await request.body())
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="请求必须是有效 JSON") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="请求必须是 JSON 对象")
        host_id = str(payload.get("host_id") or "")[:200]
        if not host_id:
            raise HTTPException(status_code=400, detail="需要指定主机")
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            action = self._app._latest_host_firewall_action(conn, host_id)
            readback = self._app._host_firewall_live_readback(conn, host_id, int(time.time()))
            if not action or (
                action["status"] != "failed" and not (readback.get("sync_status") == "drifted" and not readback.get("stale"))
            ):
                raise HTTPException(status_code=409, detail="仅当最近应用失败或新鲜读回显示策略偏差时可重试")
            now = int(time.time())
            node_id, readback = self._prepare_host_firewall_recovery(conn, host_id, now)
            current = conn.execute("SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()
            policy = (
                self._app._validate_host_firewall_policy(json.loads(current["policy_json"] or "{}"))
                if current
                else self._app._empty_host_firewall_policy()
            )
            materialized, target_state = self._app._materialize_host_firewall_policy(conn, host_id, policy, now)
            if materialized is None:
                raise HTTPException(status_code=409, detail=f"目标网卡/运行时已不可验证（{target_state}），未下发重试")
            compatibility = self._app._policy_protocol_compatibility(materialized, readback)
            if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
                raise HTTPException(status_code=409, detail="RFW 实时协议能力不满足当前策略，未下发重试")
            requested_by = str(getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard"))[:100]
            action_id = self._app._enqueue_host_firewall_policy(conn, host_id, node_id, materialized, requested_by, now, 0)
            revision = int(conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()[0])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._app.invalidate_security_status_cache()
        self._app.publish_live_event("firewall", host_id)
        return JSONResponse(status_code=202, content={"ok": True, "revision": revision, "action_id": action_id, "queued": True})

    async def rollback_host_firewall_policy(self, request: Request) -> JSONResponse:
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以回滚母机防火墙策略")
        try:
            payload = json.loads(await request.body())
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="请求必须是有效 JSON") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="请求必须是 JSON 对象")
        host_id = str(payload.get("host_id") or "")[:200]
        if not host_id:
            raise HTTPException(status_code=400, detail="需要指定主机")
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            history = conn.execute(
                "SELECT revision,policy_json FROM host_firewall_policy_history WHERE host_id=? ORDER BY revision DESC,id DESC LIMIT 1",
                (host_id,),
            ).fetchone()
            if not history:
                raise HTTPException(status_code=409, detail="没有可回滚的历史策略")
            now = int(time.time())
            node_id, readback = self._prepare_host_firewall_recovery(conn, host_id, now)
            try:
                previous = self._app._validate_host_firewall_policy(json.loads(history["policy_json"] or "{}"))
            except (TypeError, ValueError):
                raise HTTPException(status_code=409, detail="历史策略记录无效，未下发回滚") from None
            materialized, target_state = self._app._materialize_host_firewall_policy(conn, host_id, previous, now)
            if materialized is None:
                raise HTTPException(status_code=409, detail=f"历史策略引用的网卡已无法验证（{target_state}），未下发回滚")
            compatibility = self._app._policy_protocol_compatibility(materialized, readback)
            if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
                raise HTTPException(status_code=409, detail="RFW 实时协议能力不满足历史策略，未下发回滚")
            requested_by = str(getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard"))[:100]
            action_id = self._app._enqueue_host_firewall_policy(
                conn,
                host_id,
                node_id,
                materialized,
                requested_by,
                now,
                0,
                rollback_target_revision=int(history["revision"]),
            )
            revision = int(conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()[0])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._app.invalidate_security_status_cache()
        self._app.publish_live_event("firewall", host_id)
        return JSONResponse(
            status_code=202,
            content={
                "ok": True,
                "revision": revision,
                "restored_revision": int(history["revision"]),
                "action_id": action_id,
                "queued": True,
            },
        )

    async def update_host_firewall_policy(self, host_id: str, request: Request) -> JSONResponse:
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以修改母机防火墙策略")
        if not host_id or len(host_id) > 200:
            raise HTTPException(status_code=400, detail="主机标识无效")
        raw_body = await request.body()
        if len(raw_body) > 128 * 1024:
            raise HTTPException(status_code=413, detail="防火墙配置超过 128 KiB")
        try:
            payload = json.loads(raw_body)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="防火墙配置必须是有效 JSON") from None
        policy = self._app._validate_host_firewall_policy(payload)
        now = int(time.time())
        requested_by = str(getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard"))[:100]
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            fleet_template = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
            if fleet_template is not None and int(fleet_template["revision"] or 0) > 0:
                raise HTTPException(
                    status_code=409,
                    detail="全局防火墙模板已启用；请编辑全局模板，避免单机配置与统一期望策略冲突",
                )
            host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
            if host is None:
                raise HTTPException(status_code=404, detail="主机不存在")
            node_id = str(host["node_id"] or "")
            if not node_id:
                raise HTTPException(status_code=409, detail="该主机尚未注册可校验身份的 Watcher Agent")
            host_policy, target_status = self._app._materialize_host_firewall_policy(conn, host_id, policy, now)
            if host_policy is None:
                message = (
                    "网卡清单尚未就绪或已过期，请刷新并等待母机重新上报后再应用。"
                    if target_status == "inventory_unavailable"
                    else "所选运行时/网卡未出现在母机最新采集到的 Incus / Podman bridge 中，请重新选择。"
                )
                raise HTTPException(status_code=409, detail=message)
            policy = host_policy
            if self._app._policy_required_protocols(policy):
                live_readback = self._app._host_firewall_live_readback(conn, host_id, now)
                compatibility = self._app._policy_protocol_compatibility(policy, live_readback)
                if compatibility["unsupported_protocols"]:
                    names = ", ".join(compatibility["unsupported_protocols"])
                    raise HTTPException(
                        status_code=409,
                        detail=f"该节点当前 RFW 不支持所选应用协议（运行中能力清单未包含）：{names}；请部署包含对应协议检测能力的 RFW 版本并更新节点，等待新鲜能力读回后再应用。仅更新 Watcher Agent 不会增加 RFW 协议支持",
                    )
                if compatibility["unknown_protocols"]:
                    names = ", ".join(compatibility["unknown_protocols"])
                    raise HTTPException(
                        status_code=409,
                        detail=f"该节点尚无所选应用协议的新鲜 RFW 能力读回：{names}；请先刷新并等待节点上报。若读回仍显示不支持，需部署包含对应协议检测能力的 RFW 版本",
                    )
            action_id = self._app._enqueue_host_firewall_policy(conn, host_id, node_id, policy, requested_by, now, 0)
            revision_row = conn.execute("SELECT revision FROM host_firewall_policies WHERE host_id=?", (host_id,)).fetchone()
            revision = int(revision_row["revision"])
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._app.invalidate_security_status_cache()
        self._app.publish_live_event("firewall", host_id)
        return JSONResponse(status_code=202, content={"ok": True, "revision": revision, "action_id": action_id, "queued": True})

    async def delete_host_firewall_rule(self, host_id: str, rule_id: int, request: Request) -> JSONResponse:
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以删除母机 RFW 规则")
        if not host_id or len(host_id) > 200 or not 1 <= rule_id <= 2**63 - 1:
            raise HTTPException(status_code=400, detail="主机或 RFW 规则标识无效")

        now = int(time.time())
        requested_by = str(getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard"))[:100]
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            host = conn.execute("SELECT node_id FROM hosts WHERE host_id=?", (host_id,)).fetchone()
            if host is None:
                raise HTTPException(status_code=404, detail="主机不存在")
            node_id = str(host["node_id"] or "")
            if not node_id:
                raise HTTPException(status_code=409, detail="该主机尚未注册可校验身份的 Watcher Agent")

            readback = self._app._host_firewall_live_readback(conn, host_id, now)
            if readback.get("status") != "ready" or readback.get("stale") is not False:
                raise HTTPException(status_code=409, detail="RFW 规则读回已过期或不可用；刷新并等待母机重新上报后再删除")
            snapshot = readback.get("snapshot")
            if not isinstance(snapshot, dict):
                raise HTTPException(status_code=409, detail="没有可验证的当前 RFW 规则快照")
            rules = snapshot.get("rules") if isinstance(snapshot.get("rules"), list) else []
            target = next(
                (rule for rule in rules if isinstance(rule, dict) and type(rule.get("id")) is int and rule["id"] == rule_id),
                None,
            )
            if target is None:
                raise HTTPException(status_code=404, detail="该规则已不在最近一次 RFW 读回中，请刷新列表")
            if target.get("origin") != "manual" or target.get("sync_state") != "manual":
                raise HTTPException(status_code=409, detail="平台管理规则请先在期望规则列表中移除，再保存并应用")

            expected_rule = {
                key: target[key]
                for key in (
                    "id", "priority", "direction", "protocol", "action", "enabled",
                    "port_start", "port_end", "ip_type", "origin", "sync_state",
                )
                if key in target
            }
            if "ip" in target:
                expected_rule["ip"] = target["ip"]
            if "countries" in target:
                expected_rule["countries"] = target["countries"]

            pending_rows = conn.execute(
                "SELECT id,params_json FROM security_actions WHERE host_id=? AND action_type='delete_host_firewall_rule' "
                "AND status IN ('queued','dispatched','running')",
                (host_id,),
            ).fetchall()
            for pending_row in pending_rows:
                try:
                    pending_params = json.loads(pending_row["params_json"] or "{}")
                except (TypeError, ValueError):
                    pending_params = {}
                pending_rule = pending_params.get("rule") if isinstance(pending_params, dict) else None
                if isinstance(pending_rule, dict) and pending_rule.get("id") == rule_id:
                    conn.commit()
                    return JSONResponse(
                        status_code=202,
                        content={"ok": True, "rule_id": rule_id, "action_id": int(pending_row["id"]), "queued": True},
                    )

            params = {"expected_node_id": node_id, "rule": expected_rule}
            cur = conn.execute(
                "INSERT INTO security_actions(alert_id,host_id,runtime,project,container_name,action_type,params_json,status,requested_by,created_at,updated_at) "
                "VALUES(0,?,'host','','__host__','delete_host_firewall_rule',?,'queued',?,?,?)",
                (host_id, json.dumps(params, ensure_ascii=False), requested_by, now, now),
            )
            action_id = int(cur.lastrowid)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._app.invalidate_security_status_cache()
        self._app.publish_live_event("firewall", host_id)
        return JSONResponse(status_code=202, content={"ok": True, "rule_id": rule_id, "action_id": action_id, "queued": True})

    def get_fleet_firewall_policy(self) -> JSONResponse:
        now = int(time.time())
        conn = self._app.db()
        try:
            template = conn.execute(
                "SELECT revision,policy_json,updated_by,updated_at FROM fleet_firewall_policy WHERE id=1"
            ).fetchone()
            if template is None:
                revision, policy, updated_by, updated_at = 0, self._app._empty_host_firewall_policy(), "", 0
            else:
                try:
                    policy = self._app._validate_host_firewall_policy(json.loads(template["policy_json"] or "{}"))
                except (HTTPException, TypeError, ValueError):
                    policy = self._app._empty_host_firewall_policy()
                revision = int(template["revision"] or 0)
                updated_by = str(template["updated_by"] or "")
                updated_at = int(template["updated_at"] or 0)
            hosts = conn.execute(
                "SELECT host_id,node_id,last_seen,agent_version FROM hosts ORDER BY host_id"
            ).fetchall()
            required_protocols = self._app._policy_required_protocols(policy)
            nodes = [
                self._app._fleet_firewall_node_state(conn, host, revision, now, required_protocols, policy)
                for host in hosts
            ]
            readback_current = sum(
                1 for item in nodes if item["live_readback"]["status"] == "ready" and not item["live_readback"]["stale"]
            )
            readback_drifted = sum(
                1
                for item in nodes
                if item["live_readback"]["status"] == "ready"
                and not item["live_readback"]["stale"]
                and item["live_readback"]["sync_status"] == "drifted"
            )
            readback_unavailable = sum(
                1
                for item in nodes
                if item["live_readback"]["status"] in {"unavailable", "unsupported", "unknown"}
                or item["live_readback"]["stale"]
            )
            return JSONResponse(
                {
                    "revision": revision,
                    "automatic_speedtest_default": revision == 0,
                    "policy": policy,
                    "updated_by": updated_by,
                    "updated_at_utc8": self._app.format_utc8(updated_at) if updated_at else "",
                    "hosts": nodes,
                    "counts": {
                        "total": len(nodes),
                        "registered": sum(1 for item in nodes if item["registered"]),
                        "online": sum(1 for item in nodes if item["online"]),
                        "control_ready": sum(
                            1
                            for item in nodes
                            if item["control_api"] == "ready" and item["online"] and not item["control_api_stale"]
                        ),
                        "last_apply_succeeded": sum(1 for item in nodes if item["state"] == "last_apply_succeeded"),
                        "deferred": sum(1 for item in nodes if item["state"] not in {"last_apply_succeeded", "ready"}),
                        "network_deferred": sum(
                            1 for item in nodes if item["state"] in {"awaiting_interfaces", "interfaces_not_found"}
                        ),
                        "live_readback_current": readback_current,
                        "drifted_hosts": readback_drifted,
                        "readback_unavailable": readback_unavailable,
                        "mtproto_supported_hosts": sum(
                            1 for item in nodes if item["live_readback"]["mtproto_support"] == "supported"
                        ),
                        "mtproto_unsupported_hosts": sum(
                            1 for item in nodes if item["live_readback"]["mtproto_support"] == "unsupported"
                        ),
                        "mtproto_capability_unknown_hosts": sum(
                            1 for item in nodes if item["live_readback"]["mtproto_support"] == "unknown"
                        ),
                        "required_protocols_supported_hosts": sum(
                            1
                            for item in nodes
                            if item["required_protocols"]
                            and not item["unsupported_protocols"]
                            and not item["unknown_protocols"]
                        ),
                        "required_protocols_unsupported_hosts": sum(
                            1 for item in nodes if item["unsupported_protocols"]
                        ),
                        "required_protocols_unknown_hosts": sum(1 for item in nodes if item["unknown_protocols"]),
                        "rfw_configured_hosts": sum(1 for item in nodes if item["rfw_configured"]),
                        "rfw_verified_hosts": sum(1 for item in nodes if item["rfw_status"] == "verified"),
                        "rfw_attention_hosts": sum(
                            1 for item in nodes if item["rfw_configured"] and item["rfw_status"] != "verified"
                        ),
                        "container_protection_configured_hosts": sum(
                            1 for item in nodes if item["container_protection_status"]["configured"]
                        ),
                        "container_protection_active_hosts": sum(
                            1
                            for item in nodes
                            if item["container_protection_status"]["configured"]
                            and item["container_protection_status"]["state"] == "active"
                        ),
                        "container_protection_attention_hosts": sum(
                            1
                            for item in nodes
                            if item["container_protection_status"]["configured"]
                            and item["container_protection_status"]["state"] != "active"
                        ),
                        "container_protection_containers_seen": sum(
                            int(item["container_protection_status"]["containers_seen"] or 0) for item in nodes
                        ),
                        "container_protection_containers_verified": sum(
                            int(item["container_protection_status"]["containers_verified"] or 0) for item in nodes
                        ),
                    },
                    "live_rule_readback_supported": True,
                }
            )
        finally:
            conn.close()

    async def update_fleet_firewall_policy(self, request: Request) -> JSONResponse:
        if getattr(request.state, "dashboard_role", "admin") != "admin":
            raise HTTPException(status_code=403, detail="只有管理员可以修改全局母机防火墙策略")
        raw_body = await request.body()
        if len(raw_body) > 128 * 1024:
            raise HTTPException(status_code=413, detail="防火墙配置超过 128 KiB")
        try:
            payload = json.loads(raw_body)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="防火墙配置必须是有效 JSON") from None
        policy = self._app._validate_host_firewall_policy(payload)
        now = int(time.time())
        stale_seconds = self._app.STALE_SECONDS
        requested_by = str(getattr(request.state, "dashboard_user", self._app.DASHBOARD_USERNAME or "dashboard"))[:100]
        conn = self._app.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT revision FROM fleet_firewall_policy WHERE id=1").fetchone()
            revision = (int(existing["revision"]) if existing else 0) + 1
            conn.execute(
                "INSERT INTO fleet_firewall_policy(id,revision,policy_json,updated_by,updated_at) VALUES(1,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,policy_json=excluded.policy_json,"
                "updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                (revision, json.dumps(policy, ensure_ascii=False, separators=(",", ":")), requested_by, now),
            )
            hosts = conn.execute("SELECT host_id,node_id,last_seen FROM hosts ORDER BY host_id").fetchall()
            queued = 0
            deferred = 0
            network_deferred = 0
            policy_abuse = policy.get("abuse") if isinstance(policy, dict) else None
            container_policy_enabled = isinstance(policy_abuse, dict) and any(
                policy_abuse.get(key) is True for key in ("mining", "bt")
            )
            for host in hosts:
                host_id = str(host["host_id"])
                node_id = str(host["node_id"] or "")
                host_online = bool(node_id) and now - int(host["last_seen"] or 0) <= stale_seconds
                existing_policy_row = conn.execute(
                    "SELECT policy_json FROM host_firewall_policies WHERE host_id=?", (host_id,)
                ).fetchone()
                requires_rfw = self._app._policy_has_rfw_effect(policy) or (
                    existing_policy_row is not None
                    and self._app._stored_policy_has_rfw_effect(str(existing_policy_row["policy_json"] or "{}"))
                )
                runtime = self._app._host_firewall_runtime_status(conn, host_id, now)
                if host_online and (
                    not requires_rfw or (runtime["control_api"] == "ready" and not runtime["stale"])
                ):
                    if self._app._policy_required_protocols(policy):
                        live_readback = self._app._host_firewall_live_readback(conn, host_id, now)
                        compatibility = self._app._policy_protocol_compatibility(policy, live_readback)
                        if compatibility["unsupported_protocols"] or compatibility["unknown_protocols"]:
                            deferred += 1
                            continue
                    host_policy, target_status = self._app._materialize_host_firewall_policy(conn, host_id, policy, now)
                    if host_policy is None:
                        deferred += 1
                        network_deferred += 1
                        continue
                    self._app._enqueue_host_firewall_policy(conn, host_id, node_id, host_policy, requested_by, now, revision)
                    queued += 1
                else:
                    deferred += 1
                    if container_policy_enabled or requires_rfw:
                        _targets, target_status = self._app._host_firewall_policy_targets(conn, host_id, policy, now)
                        if target_status in {"inventory_unavailable", "runtime_not_found", "interface_not_found"}:
                            network_deferred += 1
            conn.commit()
            total_hosts = len(hosts)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        self._app.invalidate_security_status_cache()
        self._app.publish_live_event("firewall", "")
        return JSONResponse(
            status_code=202,
            content={
                "ok": True,
                "revision": revision,
                "queued_hosts": queued,
                "deferred_hosts": deferred,
                "network_deferred_hosts": network_deferred,
                "total_hosts": total_hosts,
            },
        )


def bind(app_mod: Any) -> FirewallService:
    global _app, _service
    _app = app_mod
    _service = FirewallService(app_mod)
    return _service


def attach(app: FastAPI, app_mod: Any) -> FirewallService:
    svc = bind(app_mod)
    router = APIRouter()
    router.add_api_route("/api/v1/hosts/{host_id:path}/firewall-policy", svc.get_host_firewall_policy, methods=["GET"])
    router.add_api_route("/api/v1/firewall/host-policy/retry", svc.retry_host_firewall_policy, methods=["POST"])
    router.add_api_route("/api/v1/firewall/host-policy/rollback", svc.rollback_host_firewall_policy, methods=["POST"])
    router.add_api_route("/api/v1/hosts/{host_id:path}/firewall-policy", svc.update_host_firewall_policy, methods=["POST"])
    router.add_api_route("/api/v1/hosts/{host_id:path}/firewall-rules/{rule_id}", svc.delete_host_firewall_rule, methods=["DELETE"])
    router.add_api_route("/api/v1/firewall/fleet-policy", svc.get_fleet_firewall_policy, methods=["GET"])
    router.add_api_route("/api/v1/firewall/fleet-policy", svc.update_fleet_firewall_policy, methods=["POST"])
    app.include_router(router)
    return svc


def __getattr__(name: str) -> Any:
    if _service is not None and hasattr(_service, name):
        return getattr(_service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
