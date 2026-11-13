"""Socket security collection, conntrack merge, process attribution, and 4D abuse evaluation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import time
from typing import Any, Dict, List, Tuple

_AGENT_NAMESPACES: List[Dict[str, Any]] = []


def register_agent_module(ns_or_mod: Any) -> None:
    """Register an agent facade module or namespace dict so patched attributes are honored."""
    ns = ns_or_mod if isinstance(ns_or_mod, dict) else getattr(ns_or_mod, "__dict__", None)
    if ns is not None and ns not in _AGENT_NAMESPACES:
        _AGENT_NAMESPACES.append(ns)


def _agent_attr(name: str, fallback: Any = None) -> Any:
    baseline = fallback
    for ns in _AGENT_NAMESPACES:
        if name not in ns:
            continue
        val = ns[name]
        if fallback is not None:
            if val is not fallback:
                return val
        else:
            if baseline is None:
                baseline = val
            elif val is not baseline and getattr(val, "__code__", None) is not getattr(baseline, "__code__", None):
                return val
            if hasattr(val, "assert_called"):
                return val
    return baseline


def _call_agent(name: str, fallback: Any, *args: Any, **kwargs: Any) -> Any:
    fn = _agent_attr(name, fallback)
    if fn is None:
        raise RuntimeError(f"Missing helper {name!r} in socket_collector")
    return fn(*args, **kwargs)


def _count_proc_net_lines(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return 0
    if len(lines) <= 1:
        return 0
    return len(lines) - 1


def _count_connections_from_pid(pid: int) -> int:
    if pid <= 0:
        return 0
    base = f"/proc/{pid}/net"
    files = ("tcp", "tcp6", "udp", "udp6")
    total = 0
    for name in files:
        total += _count_proc_net_lines(f"{base}/{name}")
    return total


def _connection_metric_epoch(pid: int) -> str:
    """Bind observations to a boot, network namespace and PID start time."""
    try:
        namespace = os.readlink(f'/proc/{pid}/ns/net')
        if namespace == os.readlink('/proc/1/ns/net'):
            return ''  # Host-network totals are not owned by this container.
        with open('/proc/sys/kernel/random/boot_id', encoding='utf-8') as handle:
            boot = handle.read().strip()
        with open(f'/proc/{pid}/stat', encoding='utf-8') as handle:
            start = handle.read().rsplit(')', 1)[1].split()[19]
        return f'{boot}:{namespace}:{pid}:{start}'
    except (OSError, ValueError, IndexError):
        return ''


def _decode_proc_addr(hex_ip: str, is_v6: bool = False) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if is_v6:
            # /proc/net/tcp6 and udp6 store four little-endian 32-bit words.
            normalized = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
            address = ipaddress.IPv6Address(normalized)
            if address.ipv4_mapped:
                return str(address.ipv4_mapped)
            return str(address)
        return str(ipaddress.IPv4Address(raw[::-1]))
    except Exception:
        return ""


def _collect_tcp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "tcp")


def _collect_udp_remote_ips(pid: int) -> Dict[str, int]:
    return _collect_remote_ips_by_proto(pid, "udp")


def _parse_remote_endpoint_ip(endpoint: str) -> str:
    text = (endpoint or "").strip()
    if not text or text in ("*", "*:*"):
        return ""
    if text.startswith("[") and "]" in text:
        return text[1:text.find("]")]
    if text.count(":") >= 2:
        # IPv6 endpoint，可能是 "2001:db8::1:443" 或 "::ffff:1.2.3.4:443"
        host, _, _ = text.rpartition(":")
        return host.strip("[]")
    if ":" in text:
        return text.split(":", 1)[0]
    return text


def _is_trackable_ip(ip: str) -> bool:
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # 私网地址也保留，GeoIP 失败时统一归为 UN，避免前端“国家 Top3”整列为空。
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    return True


def _is_public_source_ip(ip: str) -> bool:
    if not _is_trackable_ip(ip):
        return False
    try:
        return bool(ipaddress.ip_address(ip).is_global)
    except ValueError:
        return False


def _collect_remote_ips_from_exec(runtime: str, name: str, proto: str, project: str = "") -> Dict[str, int]:
    if not runtime or not name:
        return {}
    if proto == "udp":
        cmd = "ss -Huan 2>/dev/null | awk '{print $5}' || (netstat -nu 2>/dev/null | awk 'NR>2{print $5}')"
    else:
        cmd = "ss -Htan state established 2>/dev/null | awk '{print $5}' || (netstat -nt 2>/dev/null | awk 'NR>2{print $5}')"
    out = _call_agent("run", None, _call_agent("_runtime_exec_cmd", None, runtime, name, cmd, project))
    ip_counter: Dict[str, int] = {}
    for line in out.splitlines():
        ip = _parse_remote_endpoint_ip(line)
        if not _is_trackable_ip(ip):
            continue
        ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _collect_remote_ips_by_proto(pid: int, proto: str) -> Dict[str, int]:
    if pid <= 0:
        return {}
    ip_counter: Dict[str, int] = {}
    if proto == "udp":
        files = (("udp", False), ("udp6", True))
    else:
        files = (("tcp", False), ("tcp6", True))
    for name, is_v6 in files:
        path = f"/proc/{pid}/net/{name}"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            rem = parts[2]
            state = parts[3].upper()
            # TCP 仅统计 ESTABLISHED；UDP 无连接状态语义，统计所有有效远端。
            if proto == "tcp" and state != "01":
                continue
            if ":" not in rem:
                continue
            rem_ip_hex = rem.split(":", 1)[0]
            ip = _decode_proc_addr(rem_ip_hex, is_v6=is_v6)
            if not ip:
                continue
            if ip in ("0.0.0.0", "::"):
                continue
            if not _is_trackable_ip(ip):
                continue
            ip_counter[ip] = ip_counter.get(ip, 0) + 1
    return ip_counter


def _parse_socket_endpoint(endpoint: str) -> Tuple[str, int]:
    text = (endpoint or "").strip()
    if not text or text in ("*", "*:*", "0.0.0.0:*", "[::]:*"):
        return "", 0
    host, separator, port_text = text.rpartition(":")
    if not separator:
        return text.strip("[]"), 0
    host = host.strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    try:
        parsed_host = ipaddress.ip_address(host)
        if isinstance(parsed_host, ipaddress.IPv6Address) and parsed_host.ipv4_mapped:
            host = str(parsed_host.ipv4_mapped)
        else:
            host = str(parsed_host)
    except ValueError:
        pass
    return host, port


def _classify_socket_origin(
    proto: str, state: str, local_port: int, listening_ports: set[int]
) -> Tuple[str, str, str]:
    """Classify connection direction from socket state and listener evidence.

    SYN-SENT/SYN-RECV expose the handshake direction directly. An established
    socket on a TCP listener is an accepted inbound connection. An established
    TCP socket on a non-listening local port is only a probable locally-created
    connection because a point-in-time snapshot does not retain the initial SYN.
    UDP has no handshake, so both directions remain probable unless conntrack
    provides the original tuple.
    """
    protocol = str(proto or "").lower()
    socket_state = str(state or "").upper().replace("_", "-")
    if socket_state == "SYN-RECV":
        return "inbound", "remote_peer", "confirmed_syn_recv"
    if protocol.startswith("tcp") and socket_state == "SYN-SENT":
        return "outbound", "local_process", "confirmed_syn_sent"
    if protocol.startswith("tcp") and local_port in listening_ports:
        return "inbound", "remote_peer", "probable_local_listener_match"
    if protocol.startswith("tcp") and socket_state in ("ESTAB", "ESTABLISHED"):
        return "outbound", "local_process", "probable_established_non_listener"
    if protocol.startswith("udp"):
        if local_port in listening_ports:
            return "inbound", "remote_peer", "probable_connected_udp_listener_match"
        return "outbound", "local_process", "probable_connected_udp_non_listener"
    return "unknown", "unknown", "direction_not_determined"


def _communication_socket_owner_count(communication: Dict[str, object]) -> int:
    sockets = communication.get("communication_sockets")
    if not isinstance(sockets, list):
        return 0
    return sum(1 for item in sockets if isinstance(item, dict) and int(item.get("pid") or 0) > 0)


def _connection_attribution_summary(
    communication: Dict[str, object],
    conntrack: Dict[str, object],
    expected_connections: int,
) -> Dict[str, object]:
    """Summarize only captured socket evidence; never turn a missing snapshot into zero activity."""
    sockets = communication.get("communication_sockets")
    sockets = sockets if isinstance(sockets, list) else []
    conntrack_entries = conntrack.get("entries") if isinstance(conntrack.get("entries"), list) else []
    conntrack_matches = _call_agent("_enrich_communication_with_conntrack_origins", _enrich_communication_with_conntrack_origins, communication, conntrack_entries)
    captured = len(sockets)
    expected = max(0, int(expected_connections or 0))
    socket_collection_available = communication.get("communication_detail_available") is True
    if captured:
        evidence_status = "partial" if communication.get("communication_snapshot_truncated") is True or (expected > captured) else "available"
    elif expected > 0 or not socket_collection_available:
        evidence_status = "unavailable"
    else:
        evidence_status = "no_connections"

    def count(direction: str, confidence: str) -> int:
        return sum(
            1 for item in sockets
            if isinstance(item, dict)
            and item.get("direction") == direction
            and item.get("origin_confidence") == confidence
        )

    return {
        "evidence_status": evidence_status,
        "unavailable_reason": (
            "high_connection_count_socket_snapshot_empty"
            if evidence_status == "unavailable" and expected > 0 and socket_collection_available
            else "socket_collection_unavailable"
            if evidence_status == "unavailable"
            else ""
        ),
        "captured_sockets": captured if captured or evidence_status == "no_connections" else None,
        "expected_connection_count": expected,
        "confirmed_local_initiated": count("outbound", "confirmed"),
        "probable_local_initiated": count("outbound", "probable"),
        "confirmed_remote_initiated": count("inbound", "confirmed"),
        "probable_remote_initiated": count("inbound", "probable"),
        "unknown_direction": sum(1 for item in sockets if isinstance(item, dict) and item.get("direction") not in ("inbound", "outbound")),
        "process_attributed_sockets": _communication_socket_owner_count(communication),
        "conntrack_confirmed_sockets": int(conntrack_matches.get("matched_outbound") or 0) + int(conntrack_matches.get("matched_inbound") or 0),
        "conntrack_available": bool(conntrack.get("available")),
        "conntrack_entries_examined": len(conntrack_entries),
        "conntrack_snapshot_truncated": bool(conntrack.get("snapshot_truncated")),
        "socket_snapshot_truncated": bool(communication.get("communication_snapshot_truncated")),
        "process_attribution_available": _communication_socket_owner_count(communication) > 0,
        "source": str(communication.get("communication_source") or "unknown"),
    }


def _communication_process_totals(sockets: List[Dict[str, object]]) -> List[Dict[str, object]]:
    totals: Dict[Tuple[int, str], Dict[str, object]] = {}
    for item in sockets:
        pid = int(item.get("pid") or 0)
        process = str(item.get("process") or "unknown")[:120]
        key = (pid, process)
        aggregate = totals.setdefault(key, {
            "pid": pid, "process": process, "inbound_connections": 0,
            "outbound_connections": 0, "unknown_connections": 0, "remote_ips": set(),
        })
        direction = item.get("direction") if item.get("direction") in ("inbound", "outbound") else "unknown"
        aggregate[f"{direction}_connections"] = int(aggregate[f"{direction}_connections"]) + 1
        remote_ips = aggregate.get("remote_ips")
        if isinstance(remote_ips, set) and item.get("remote_ip"):
            remote_ips.add(str(item["remote_ip"]))
    result = []
    for aggregate in totals.values():
        remote_ips = aggregate.pop("remote_ips", set())
        aggregate["unique_remote_ips"] = len(remote_ips) if isinstance(remote_ips, set) else 0
        result.append(aggregate)
    return sorted(
        result,
        key=lambda item: int(item.get("inbound_connections") or 0) + int(item.get("outbound_connections") or 0),
        reverse=True,
    )[:50]


def _merge_socket_process_attribution(
    communication: Dict[str, object], fallback: Dict[str, object]
) -> None:
    """Fill missing socket owners from host /proc without replacing richer ss rows."""
    primary_sockets = communication.get("communication_sockets")
    fallback_sockets = fallback.get("communication_sockets")
    if not isinstance(primary_sockets, list) or not isinstance(fallback_sockets, list):
        return

    def socket_key(item: Dict[str, object]) -> Tuple[str, str, int, str, int, str]:
        local_ip, local_port = _parse_socket_endpoint(str(item.get("local") or ""))
        remote_ip, remote_port = _parse_socket_endpoint(str(item.get("remote") or ""))
        proto = str(item.get("proto") or "").lower()
        proto = "tcp" if proto.startswith("tcp") else "udp" if proto.startswith("udp") else proto
        state = str(item.get("state") or "").lower().replace("_", "-")
        state = {"estab": "established", "syn-sent": "syn-sent", "syn-recv": "syn-recv"}.get(state, state)
        return (
            proto, local_ip, local_port, remote_ip, remote_port, state,
        )

    fallback_by_key = {
        socket_key(item): item for item in fallback_sockets
        if isinstance(item, dict) and int(item.get("pid") or 0) > 0
    }
    merged = False
    for item in primary_sockets:
        if not isinstance(item, dict) or int(item.get("pid") or 0) > 0:
            continue
        owner = fallback_by_key.get(socket_key(item))
        if owner is None:
            continue
        item["pid"] = int(owner.get("pid") or 0)
        item["process"] = str(owner.get("process") or "unknown")[:120]
        item["process_attribution"] = "attributed"
        item["process_attribution_source"] = "host_proc_fd_inode"
        merged = True
    if merged:
        communication["communication_processes"] = _communication_process_totals(
            [item for item in primary_sockets if isinstance(item, dict)]
        )
    communication["process_attribution_available"] = _communication_socket_owner_count(communication) > 0
    communication["communication_owner_attributed_count"] = _communication_socket_owner_count(communication)


def _enrich_communication_with_conntrack_origins(
    communication: Dict[str, object], entries: List[Dict[str, object]]
) -> Dict[str, int]:
    """Confirm local-vs-remote initiation by matching socket tuples to conntrack."""
    sockets = communication.get("communication_sockets")
    if not isinstance(sockets, list):
        return {"matched_outbound": 0, "matched_inbound": 0, "ambiguous": 0}

    def normalized_ip(value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
            return str(parsed.ipv4_mapped) if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped else str(parsed)
        except ValueError:
            return value.strip().lower()

    tuple_matches: Dict[Tuple[str, str, int, str, int], set[str]] = {}
    inbound_sources: Dict[Tuple[str, str, int, str, int], set[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Only kernel conntrack's original/reply tuples confirm an individual
        # socket. Host proxy sockets are useful for port-level NAT attribution,
        # but they are a separate connection leg and must not masquerade as an
        # exact match for a socket inside the container.
        if entry.get("evidence_source") not in (None, "host_conntrack"):
            continue
        entry_proto = str(entry.get("proto") or "").lower()
        original_src = normalized_ip(str(entry.get("original_src") or ""))
        original_dst = normalized_ip(str(entry.get("original_dst") or ""))
        reply_src = normalized_ip(str(entry.get("reply_src") or ""))
        reply_dst = normalized_ip(str(entry.get("reply_dst") or ""))
        original_key = (
            entry_proto, original_src, int(entry.get("original_sport") or 0),
            original_dst, int(entry.get("original_dport") or 0),
        )
        reply_key = (
            entry_proto, reply_src, int(entry.get("reply_sport") or 0),
            reply_dst, int(entry.get("reply_dport") or 0),
        )
        tuple_matches.setdefault(original_key, set()).add("outbound")
        tuple_matches.setdefault(reply_key, set()).add("inbound")
        inbound_sources.setdefault(reply_key, set()).add(str(entry.get("original_src") or ""))
    counts = {"matched_outbound": 0, "matched_inbound": 0, "ambiguous": 0}
    for item in sockets:
        if not isinstance(item, dict):
            continue
        local_ip, local_port = _parse_socket_endpoint(str(item.get("local") or ""))
        remote_ip, remote_port = _parse_socket_endpoint(str(item.get("remote") or ""))
        proto = str(item.get("proto") or "").lower()
        if not local_ip or not remote_ip or local_port <= 0 or remote_port <= 0:
            continue
        local_key = (normalized_ip(local_ip), local_port)
        remote_key = (normalized_ip(remote_ip), remote_port)
        tuple_key = (proto, local_key[0], local_key[1], remote_key[0], remote_key[1])
        matches = tuple_matches.get(tuple_key, set())
        if len(matches) > 1:
            item["direction"] = "unknown"
            item["origin"] = "unknown"
            item["origin_confidence"] = "mixed"
            item["direction_evidence"] = "ambiguous_conntrack_tuple_match"
            item["process_role"] = "unknown"
            counts["ambiguous"] += 1
            continue
        if not matches:
            continue
        direction = next(iter(matches))
        item["direction"] = direction
        item["origin"] = "local_process" if direction == "outbound" else "remote_peer"
        item["origin_confidence"] = "confirmed"
        item["direction_evidence"] = "confirmed_conntrack_original_initiator" if direction == "outbound" else "confirmed_conntrack_reply_acceptor"
        item["process_role"] = "initiator" if direction == "outbound" else "acceptor"
        item["conntrack_match"] = "original_tuple" if direction == "outbound" else "reply_tuple"
        item["process_attribution_source"] = item.get("process_attribution_source") or "socket_owner"
        if direction == "inbound":
            inbound_original_sources = inbound_sources.get(tuple_key, set())
            public_sources = sorted({ip for ip in inbound_original_sources if _is_public_source_ip(ip)})
            if public_sources:
                item["original_remote_ips"] = public_sources[:5]
        counts[f"matched_{direction}"] += 1
    communication["communication_processes"] = _communication_process_totals(
        [item for item in sockets if isinstance(item, dict)]
    )
    communication["conntrack_match_counts"] = counts
    return counts


def _collect_socket_process_details(
    runtime: str,
    name: str,
    project: str,
    listening_ports: List[int],
    snapshot_limit_override: int = 0,
    detail_limit_override: int = 0,
) -> Dict[str, object]:
    """Collect one bounded socket snapshot and reuse it for process attribution."""
    snapshot_limit = (
        max(50, min(2000, int(snapshot_limit_override)))
        if snapshot_limit_override
        else max(50, min(2000, int(_call_agent("_env_float", None, "SECURITY_SOCKET_SNAPSHOT_MAX", 500))))
    )
    detail_limit = (
        max(10, min(500, int(detail_limit_override)))
        if detail_limit_override
        else max(10, min(500, int(_call_agent("_env_float", None, "SECURITY_COMMUNICATION_DETAIL_MAX", 100))))
    )
    command = (
        "if command -v ss >/dev/null 2>&1; then "
        "echo @@SS_AVAILABLE@@; "
        f"ss -H -t -u -n -a -p 2>/dev/null | head -n {snapshot_limit}; "
        "fi"
    )
    output = _call_agent("run", None, _call_agent("_runtime_exec_cmd", None, runtime, name, command, project))
    available = "@@SS_AVAILABLE@@" in output
    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.strip() != "@@SS_AVAILABLE@@"
    ]
    tcp_listening = {int(port) for port in listening_ports if int(port) > 0}
    udp_listening: set[int] = set()
    # Use the current socket namespace's listener table too. The caller's
    # security snapshot can be stale or omit a listener discovered by ss.
    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        _, observed_port = _parse_socket_endpoint(parts[4])
        proto = parts[0].lower()
        if observed_port > 0 and proto.startswith("tcp") and parts[1].upper() == "LISTEN":
            tcp_listening.add(observed_port)
        elif observed_port > 0 and proto.startswith("udp") and _parse_socket_endpoint(parts[5])[1] == 0:
            udp_listening.add(observed_port)
    sockets: List[Dict[str, object]] = []
    process_totals: Dict[Tuple[int, str], Dict[str, object]] = {}
    service_listeners: List[Dict[str, object]] = []

    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue
        state = parts[1].upper()
        local_endpoint = parts[4]
        remote_endpoint = parts[5]
        process_text = parts[6] if len(parts) > 6 else ""
        remote_ip, remote_port = _parse_socket_endpoint(remote_endpoint)
        _, local_port = _parse_socket_endpoint(local_endpoint)
        if (state == 'LISTEN' or (proto.startswith('udp') and remote_port == 0)) and 0 < local_port <= 65535:
            listener_owners = re.findall(r'\("([^"\\]{1,120})",pid=(\d+)', process_text)
            if not listener_owners and len(service_listeners) < 100:
                service_listeners.append({'process':'unknown', 'pid':0,
                                          'proto':'tcp' if proto.startswith('tcp') else 'udp',
                                          'local':local_endpoint, 'port':local_port, 'source':'ss_process_owner_missing'})
            for process_name, process_pid in listener_owners:
                if len(service_listeners) < 100:
                    service_listeners.append({'process':process_name.lower(), 'pid':int(process_pid),
                                              'proto':'tcp' if proto.startswith('tcp') else 'udp',
                                              'local':local_endpoint, 'port':local_port, 'source':'ss_process_owner'})
        if not _is_trackable_ip(remote_ip):
            continue
        if proto.startswith("tcp") and state not in ("ESTAB", "ESTABLISHED", "SYN-SENT", "SYN-RECV"):
            continue
        if proto.startswith("udp") and remote_port <= 0:
            continue
        direction, origin, direction_evidence = _classify_socket_origin(
            proto, state, local_port, tcp_listening if proto.startswith("tcp") else udp_listening
        )
        owners = re.findall(r'\("([^"\\]{1,120})",pid=(\d+)', process_text)
        process_name = owners[0][0] if owners else "unknown"
        process_pid = int(owners[0][1]) if owners else 0
        item = {
            "proto": "tcp" if proto.startswith("tcp") else "udp",
            "state": state.lower(),
            "direction": direction,
            "local": local_endpoint,
            "remote": remote_endpoint,
            "remote_ip": remote_ip,
            "process": process_name,
            "pid": process_pid,
            "origin": origin,
            "origin_confidence": "confirmed" if direction_evidence.startswith("confirmed_") else "probable" if direction != "unknown" else "unknown",
            "direction_evidence": direction_evidence,
            "process_role": "acceptor" if direction == "inbound" else "initiator" if direction == "outbound" else "unknown",
            "process_attribution": "attributed" if process_pid > 0 else "unavailable",
        }
        if len(sockets) < detail_limit:
            sockets.append(item)
        key = (process_pid, process_name)
        aggregate = process_totals.setdefault(
            key,
            {
                "pid": process_pid,
                "process": process_name,
                "inbound_connections": 0,
                "outbound_connections": 0,
                "unknown_connections": 0,
                "remote_ips": set(),
            },
        )
        aggregate[f"{direction}_connections"] = int(aggregate[f"{direction}_connections"]) + 1
        remote_ips = aggregate["remote_ips"]
        if isinstance(remote_ips, set):
            remote_ips.add(remote_ip)

    processes = []
    for aggregate in process_totals.values():
        remote_ips = aggregate.pop("remote_ips", set())
        aggregate["unique_remote_ips"] = len(remote_ips) if isinstance(remote_ips, set) else 0
        processes.append(aggregate)
    processes.sort(
        key=lambda item: int(item["inbound_connections"]) + int(item["outbound_connections"]),
        reverse=True,
    )
    return {
        "communication_detail_available": available,
        "communication_snapshot_count": len(lines),
        "communication_snapshot_truncated": len(lines) >= snapshot_limit,
        "communication_processes": processes[:50],
        "communication_sockets": sockets,
        "communication_owner_attributed_count": _communication_socket_owner_count({"communication_sockets": sockets}),
        "process_attribution_available": _communication_socket_owner_count({"communication_sockets": sockets}) > 0,
        "communication_source": "container_ss",
        "service_listeners": service_listeners,
        "service_listener_inventory_complete": bool(
            available and len(lines) < snapshot_limit and len(service_listeners) < 100
        ),
    }



def _parse_port(hex_port: str) -> int:
    try:
        return int(hex_port, 16)
    except (TypeError, ValueError):
        return 0


def _collect_socket_security(pid: int) -> Dict[str, object]:
    result: Dict[str, object] = {
        'connection_metrics': {'schema': 1, 'valid': False},
        "tcp_states": {},
        "syn_recv_count": 0,
        "syn_sent_count": 0,
        "incoming_established": 0,
        "inbound_unique_ips": 0,
        "inbound_established_unique_ips": 0,
        "inbound_syn_recv_unique_ips": 0,
        "inbound_top_ips": [],
        "inbound_unique_ip_threshold": int(_call_agent("_env_float", None, "ALERT_INBOUND_UNIQUE_IPS", 10)),
        "inbound_ip_observation": "container_socket",
        "inbound_public_flows": [],
        "container_ips": [],
        "outbound_established": 0,
        "outbound_unique_ips": 0,
        "outbound_unique_ports": 0,
        "outbound_syn_sent_unique_ips": 0,
        "outbound_top_ips": [],
        "outbound_top_ports": [],
        "sensitive_outbound_ports": [],
        "suspicious_outbound_connections": 0,
        "scan_unique_ports_max": 0,
        "scan_source_ip": "",
        "listening_ports": [],
        "listening_endpoints": [],
        "udp_listening_ports": [],
    }
    if pid <= 0:
        return result

    entries: List[Dict[str, object]] = []
    metric_epoch = _call_agent("_connection_metric_epoch", _connection_metric_epoch, pid)
    read_files = 0
    malformed = False
    for filename, is_v6 in (("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)):
        try:
            with open(f"/proc/{pid}/net/{filename}", "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()[1:]
                read_files += 1
        except Exception:
            continue
        proto = "udp" if filename.startswith("udp") else "tcp"
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1] or ":" not in parts[2]:
                malformed = True
                continue
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            remote_ip_hex, remote_port_hex = parts[2].rsplit(":", 1)
            entries.append(
                {
                    "proto": proto,
                    "state": parts[3].upper(),
                    "local_ip": _decode_proc_addr(local_ip_hex, is_v6=is_v6),
                    "local_port": _parse_port(local_port_hex),
                    "remote_port": _parse_port(remote_port_hex),
                    "remote_ip": _decode_proc_addr(remote_ip_hex, is_v6=is_v6),
                }
            )

    tcp_entries = [x for x in entries if x['proto'] == 'tcp']
    result['connection_metrics'] = {
        'schema': 1, 'source': 'container_proc_net', 'sampled_at': int(time.time()),
        'epoch': metric_epoch,
        'valid': bool(metric_epoch) and read_files == 4 and not malformed and metric_epoch == _call_agent("_connection_metric_epoch", _connection_metric_epoch, pid),
        'total': len(entries), 'tcp_total': len(tcp_entries),
        'tcp_established': sum(x['state'] == '01' for x in tcp_entries),
        'tcp_pending': sum(x['state'] in ('02', '03') for x in tcp_entries),
        'tcp_time_wait': sum(x['state'] == '06' for x in tcp_entries),
        'udp_sockets': len(entries) - len(tcp_entries),
    }
    listening_ports = {
        int(x["local_port"])
        for x in entries
        if x["proto"] == "tcp" and x["state"] == "0A" and int(x["local_port"]) > 0
    }
    udp_listening_ports = {
        int(x["local_port"])
        for x in entries
        if x["proto"] == "udp" and int(x["local_port"]) > 0 and int(x.get("remote_port") or 0) == 0
    }
    listening_endpoints = sorted(
        {
            f"[{entry['local_ip']}]:{int(entry['local_port'])}"
            if ":" in str(entry["local_ip"])
            else f"{entry['local_ip']}:{int(entry['local_port'])}"
            for entry in entries
            if entry["proto"] == "tcp" and entry["state"] == "0A" and int(entry["local_port"]) > 0
        }
    )
    container_ips = {
        str(entry["local_ip"])
        for entry in entries
        if _is_trackable_ip(str(entry.get("local_ip") or ""))
    }
    state_names = {
        "01": "established",
        "02": "syn_sent",
        "03": "syn_recv",
        "04": "fin_wait1",
        "05": "fin_wait2",
        "06": "time_wait",
        "07": "close",
        "08": "close_wait",
        "09": "last_ack",
        "0A": "listen",
        "0B": "closing",
    }
    tcp_states: Dict[str, int] = {}
    outbound_ips = set()
    outbound_ports = set()
    outbound_syn_sent_ips = set()
    outbound_ip_stats: Dict[str, Dict[str, Any]] = {}
    outbound_port_stats: Dict[int, Dict[str, Any]] = {}
    sensitive_port_labels = {
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP-Sub",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        6667: "IRC",
    }
    inbound_source_ports: Dict[str, set] = {}
    inbound_ip_connections: Dict[str, int] = {}
    inbound_ip_established: Dict[str, int] = {}
    inbound_ip_syn_recv: Dict[str, int] = {}
    inbound_established_ips = set()
    inbound_syn_recv_ips = set()
    suspicious_ports = {
        int(x.strip())
        for x in os.getenv("SECURITY_SUSPICIOUS_OUTBOUND_PORTS", "25,465,587,23,445,6667").split(",")
        if x.strip().isdigit()
    }
    suspicious_connections = 0
    incoming_established = 0
    outbound_established = 0
    syn_recv = 0

    for entry in entries:
        proto = str(entry["proto"])
        state = str(entry["state"])
        local_port = int(entry["local_port"])
        local_ip = str(entry["local_ip"])
        remote_port = int(entry["remote_port"])
        remote_ip = str(entry["remote_ip"])
        if proto == "tcp":
            state_name = state_names.get(state, state.lower())
            tcp_states[state_name] = tcp_states.get(state_name, 0) + 1
            if state == "03":
                syn_recv += 1
            if state not in ("01", "02", "03"):
                continue
        elif remote_port <= 0:
            continue

        incoming = local_port in listening_ports or state == "03"
        if incoming:
            if state == "01":
                incoming_established += 1
            if _is_trackable_ip(remote_ip) and remote_ip != local_ip:
                inbound_source_ports.setdefault(remote_ip, set()).add(local_port)
                inbound_ip_connections[remote_ip] = inbound_ip_connections.get(remote_ip, 0) + 1
                if proto == "tcp" and state == "01":
                    inbound_established_ips.add(remote_ip)
                    inbound_ip_established[remote_ip] = inbound_ip_established.get(remote_ip, 0) + 1
                elif proto == "tcp" and state == "03":
                    inbound_syn_recv_ips.add(remote_ip)
                    inbound_ip_syn_recv[remote_ip] = inbound_ip_syn_recv.get(remote_ip, 0) + 1
            continue
        if not _is_trackable_ip(remote_ip):
            continue
        outbound_ips.add(remote_ip)
        ostat = outbound_ip_stats.setdefault(
            remote_ip,
            {"connections": 0, "established_connections": 0, "syn_sent_connections": 0, "ports": set()},
        )
        ostat["connections"] += 1
        if remote_port > 0:
            ostat["ports"].add(remote_port)
        if state == "01" or proto == "udp":
            ostat["established_connections"] += 1
        elif proto == "tcp" and state == "02":
            ostat["syn_sent_connections"] += 1
        if proto == "tcp" and state == "02":
            outbound_syn_sent_ips.add(remote_ip)
        if remote_port > 0:
            outbound_ports.add(remote_port)
            pstat = outbound_port_stats.setdefault(
                remote_port,
                {"connections": 0, "established": 0, "syn_sent": 0, "ips": set()},
            )
            pstat["connections"] += 1
            pstat["ips"].add(remote_ip)
            if state == "01" or proto == "udp":
                pstat["established"] += 1
            elif proto == "tcp" and state == "02":
                pstat["syn_sent"] += 1
        if state == "01" or proto == "udp":
            outbound_established += 1
            if remote_port in suspicious_ports:
                suspicious_connections += 1

    scan_source_ip = ""
    scan_unique_ports_max = 0
    for source_ip, ports in inbound_source_ports.items():
        if len(ports) > scan_unique_ports_max:
            scan_unique_ports_max = len(ports)
            scan_source_ip = source_ip

    outbound_top_ips = [
        {
            "ip": ip,
            "connections": int(info["connections"]),
            "established_connections": int(info["established_connections"]),
            "syn_sent_connections": int(info["syn_sent_connections"]),
            "ports": sorted(info["ports"])[:6],
        }
        for ip, info in sorted(
            outbound_ip_stats.items(),
            key=lambda item: (int(item[1]["connections"]), int(item[1]["established_connections"])),
            reverse=True,
        )[:20]
    ]
    outbound_top_ports = [
        {
            "port": port,
            "service": sensitive_port_labels.get(port, ""),
            "connections": int(info["connections"]),
            "established": int(info["established"]),
            "syn_sent": int(info["syn_sent"]),
            "unique_ips": len(info["ips"]),
        }
        for port, info in sorted(
            outbound_port_stats.items(),
            key=lambda item: (int(item[1]["connections"]), len(item[1]["ips"])),
            reverse=True,
        )[:10]
    ]
    sensitive_outbound_ports = [
        {
            "port": port,
            "service": sensitive_port_labels[port],
            "connections": int(info["connections"]),
            "established": int(info["established"]),
            "syn_sent": int(info["syn_sent"]),
            "unique_ips": len(info["ips"]),
        }
        for port, info in sorted(
            outbound_port_stats.items(),
            key=lambda item: (int(item[1]["connections"]), len(item[1]["ips"])),
            reverse=True,
        )
        if port in sensitive_port_labels
    ]

    result.update(
        {
            "tcp_states": tcp_states,
            "syn_recv_count": syn_recv,
            "syn_sent_count": int(tcp_states.get("syn_sent", 0)),
            "incoming_established": incoming_established,
            "inbound_unique_ips": len(inbound_source_ports),
            "inbound_established_unique_ips": len(inbound_established_ips),
            "inbound_syn_recv_unique_ips": len(inbound_syn_recv_ips),
            "inbound_top_ips": [
                {
                    "ip": ip,
                    "connections": count,
                    "established_connections": inbound_ip_established.get(ip, 0),
                    "syn_recv_connections": inbound_ip_syn_recv.get(ip, 0),
                    "local_ports": sorted(int(p) for p in inbound_source_ports.get(ip, set()) if int(p) > 0)[:6],
                }
                for ip, count in sorted(
                    inbound_ip_connections.items(), key=lambda item: item[1], reverse=True
                )[:20]
            ],
            "inbound_unique_ip_threshold": int(_call_agent("_env_float", None, "ALERT_INBOUND_UNIQUE_IPS", 10)),
            "container_ips": sorted(container_ips),
            "outbound_established": outbound_established,
            "outbound_unique_ips": len(outbound_ips),
            "outbound_unique_ports": len(outbound_ports),
            "outbound_syn_sent_unique_ips": len(outbound_syn_sent_ips),
            "outbound_top_ips": outbound_top_ips,
            "outbound_top_ports": outbound_top_ports,
            "sensitive_outbound_ports": sensitive_outbound_ports,
            "suspicious_outbound_connections": suspicious_connections,
            "scan_unique_ports_max": scan_unique_ports_max,
            "scan_source_ip": scan_source_ip,
            "listening_ports": sorted(listening_ports),
            "listening_endpoints": listening_endpoints,
            "udp_listening_ports": sorted(udp_listening_ports),
        }
    )
    return result


def _build_service_inventory(
    socket_security: Dict[str, object],
    communication: Dict[str, object],
    configured_protocols: List[Dict[str, object]] | None = None,
    process_scan_states: List[Dict[str, object]] | None = None,
    authoritative_listener_ports: set[int] | None = None,
) -> Tuple[List[Dict[str, object]], str]:
    """Combine kernel listener evidence with process owners and safe config labels."""
    configured_protocols = configured_protocols if isinstance(configured_protocols, list) else []
    process_scan_states = process_scan_states if isinstance(process_scan_states, list) else []
    authoritative_listener_ports = authoritative_listener_ports if isinstance(authoritative_listener_ports, set) else set()
    owned = communication.get("service_listeners")
    owned = owned if isinstance(owned, list) else []
    inventory: List[Dict[str, object]] = []
    inventory_truncated = len(owned) >= 100
    covered: set[Tuple[str, int]] = set()

    def valid_port(value: object) -> int:
        if isinstance(value, bool):
            return 0
        try:
            port = int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return port if 0 < port < 65536 else 0

    def valid_pid(value: object) -> int:
        if isinstance(value, bool):
            return 0
        try:
            pid = int(value)
        except (TypeError, ValueError, OverflowError):
            return 0
        return pid if 1 < pid <= 4194304 else 0

    complete_protocol_processes = {
        (valid_pid(item.get("pid")), str(item.get("process") or "").lower())
        for item in process_scan_states
        if isinstance(item, dict) and str(item.get("state") or "").lower() == "complete"
        and str(item.get("start_ticks") or "").isdigit()
        and valid_pid(item.get("pid")) > 0 and str(item.get("process") or "").strip()
    }

    transports_by_owner_port: Dict[Tuple[int, str, int], set[str]] = {}
    for item in owned[:100]:
        if not isinstance(item, dict):
            continue
        try:
            owner_pid = int(item.get("pid") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        owner_process = str(item.get("process") or "").lower()
        owner_port = valid_port(item.get("port"))
        owner_proto = str(item.get("proto") or "").lower()
        if owner_pid > 1 and owner_process and owner_port and owner_proto in {"tcp", "udp"}:
            transports_by_owner_port.setdefault((owner_pid, owner_process, owner_port), set()).add(owner_proto)

    for raw in owned[:100]:
        if not isinstance(raw, dict):
            continue
        proto = str(raw.get("proto") or "").lower()
        port = valid_port(raw.get("port"))
        if proto not in {"tcp", "udp"} or not port:
            continue
        try:
            pid = int(raw.get("pid") or 0)
        except (TypeError, ValueError, OverflowError):
            pid = 0
        if pid < 0:
            pid = 0
        process = str(raw.get("process") or "")[:120]
        row: Dict[str, object] = {
            "process": process,
            "pid": pid,
            "proto": proto,
            "local": str(raw.get("local") or "")[:160],
            "port": port,
            "source": str(raw.get("source") or "ss_process_owner")[:40],
            "process_attribution": "attributed" if pid > 1 and process else "unavailable",
        }
        matches = set()
        port_config_scan: Dict[str, bool] = {}
        for item in configured_protocols:
            if not isinstance(item, dict):
                continue
            try:
                configured_pid = int(item.get("pid") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            protocol_name = str(item.get("protocol") or "").lower()
            configured_transports = item.get("transports")
            if "transports" in item:
                if not isinstance(configured_transports, list) or proto not in configured_transports:
                    continue
            elif len(transports_by_owner_port.get((pid, process.lower(), port), {proto})) > 1:
                # With TCP and UDP on the same process/port, an implicit
                # transport in config is not enough to identify this listener.
                continue
            configured_listen = str(item.get("listen") or "*").lower()
            observed_address, _ = _parse_socket_endpoint(str(raw.get("local") or ""))
            if configured_listen not in {"*", "0.0.0.0", "::", "::0"} and configured_listen != str(observed_address or "").lower():
                continue
            if (
                configured_pid == pid
                and valid_port(item.get("port")) == port
                and str(item.get("process") or "").lower() == process.lower()
                and re.fullmatch(r"[a-z0-9_-]{1,32}", protocol_name)
            ):
                matches.add(protocol_name)
                port_config_scan[protocol_name] = (
                    port_config_scan.get(protocol_name, True)
                    and item.get("port_config_complete") is True
                )
        if matches:
            row["application_protocols"] = sorted(matches)
            row["application_protocol_evidence"] = "config_matches_live_pid_and_port"
            if (pid, process.lower()) in complete_protocol_processes:
                row["protocol_process_scan_complete"] = True
            if matches == {"vmess"} and (pid, process.lower()) in complete_protocol_processes:
                row["vmess_process_scan_complete"] = True
            complete_port_protocols = sorted(
                protocol for protocol, complete in port_config_scan.items() if complete
            )
            if complete_port_protocols:
                row["protocol_port_config_complete_protocols"] = complete_port_protocols
        inventory.append(row)
        covered.add((proto, port))

    tcp_ports = {valid_port(port) for port in socket_security.get("listening_ports", []) if valid_port(port)}
    udp_ports = {valid_port(port) for port in socket_security.get("udp_listening_ports", []) if valid_port(port)}
    tcp_addresses: Dict[int, set[str]] = {}
    raw_endpoints = socket_security.get("listening_endpoints")
    if isinstance(raw_endpoints, list):
        for endpoint in raw_endpoints:
            address, port = _parse_socket_endpoint(str(endpoint))
            if port in tcp_ports:
                tcp_addresses.setdefault(port, set()).add(address or "*")
    for proto, ports in (("tcp", tcp_ports), ("udp", udp_ports)):
        for port in sorted(ports):
            if (proto, port) in covered:
                continue
            if port in authoritative_listener_ports:
                # A complete targeted /proc listener scan supersedes the
                # earlier aggregate kernel snapshot for this candidate port.
                continue
            addresses = sorted(tcp_addresses.get(port, set())) if proto == "tcp" else []
            if not addresses:
                addresses = ["?"]
            for address in addresses:
                local = f"[{address}]:{port}" if ":" in address and address != "?" else f"{address}:{port}"
                inventory.append({
                    "process": "",
                    "pid": 0,
                    "proto": proto,
                    "local": local,
                    "port": port,
                    "source": "container_proc_net",
                    "process_attribution": "unavailable",
                })
    inventory.sort(key=lambda item: (int(item.get("port") or 0), str(item.get("proto") or ""), str(item.get("process") or "")))
    inventory_truncated = inventory_truncated or len(inventory) > 100
    inventory = inventory[:100]
    metrics = socket_security.get("connection_metrics")
    metrics_valid = isinstance(metrics, dict) and metrics.get("valid") is True
    detail_available = communication.get("communication_detail_available") is True
    truncated = communication.get("communication_snapshot_truncated") is True or inventory_truncated
    if metrics_valid and not truncated and (detail_available or not inventory):
        state = "complete"
    elif metrics_valid or detail_available or inventory:
        state = "partial"
    else:
        state = "unavailable"
    return inventory, state


def _parse_conntrack_line(line: str) -> Dict[str, object] | None:
    """Parse the original and reply tuples from one conntrack record."""
    proto = next((token.lower() for token in line.split()[:8] if token.lower() in ("tcp", "udp")), "")
    src_values = re.findall(r"\bsrc=([^\s]+)", line)
    dst_values = re.findall(r"\bdst=([^\s]+)", line)
    sport_values = re.findall(r"\bsport=(\d+)", line)
    dport_values = re.findall(r"\bdport=(\d+)", line)
    if not proto or len(src_values) < 2 or len(dst_values) < 2:
        return None
    if not _is_trackable_ip(src_values[0]):
        return None
    try:
        original_sport = int(sport_values[0]) if sport_values else 0
        original_dport = int(dport_values[0]) if dport_values else 0
        reply_sport = int(sport_values[1]) if len(sport_values) > 1 else 0
        reply_dport = int(dport_values[1]) if len(dport_values) > 1 else 0
    except ValueError:
        return None
    tcp_state_match = re.search(r"\btcp\s+\d+\s+\d+\s+([A-Z_]+)\b", line, re.IGNORECASE)
    packet_values = []
    for value in re.findall(r"\bpackets=(\d+)", line)[:2]:
        try:
            packet_values.append(int(value))
        except ValueError:
            packet_values.append(0)
    return {
        "proto": proto,
        "evidence_source": "host_conntrack",
        "tcp_state": tcp_state_match.group(1).upper() if tcp_state_match else "",
        "unreplied": "[UNREPLIED]" in line,
        "original_packets": packet_values[0] if packet_values else 0,
        "reply_packets": packet_values[1] if len(packet_values) > 1 else 0,
        "original_src": src_values[0],
        "original_dst": dst_values[0],
        "original_sport": original_sport,
        "original_dport": original_dport,
        "reply_src": src_values[1],
        "reply_dst": dst_values[1],
        "reply_sport": reply_sport,
        "reply_dport": reply_dport,
    }


def _collect_host_conntrack_snapshot() -> Dict[str, object]:
    """Read one bounded host conntrack snapshot for NAT-aware source attribution."""
    limit = max(100, min(50000, int(_call_agent("_env_float", None, "SECURITY_CONNTRACK_SNAPSHOT_MAX", 5000))))
    lines: List[str] = []
    available = False
    for path in ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                available = True
                for index, line in enumerate(handle):
                    if index >= limit:
                        break
                    if line.strip():
                        lines.append(line.strip())
            break
        except (FileNotFoundError, PermissionError, OSError):
            continue
    if not available:
        output = _call_agent("run", None, 
            [
                "sh",
                "-lc",
                "if command -v conntrack >/dev/null 2>&1; then "
                f"conntrack -L -o extended 2>/dev/null | sed -n '1,{limit}p'; fi",
            ]
        )
        if output.strip():
            available = True
            lines = [line.strip() for line in output.splitlines()[:limit] if line.strip()]
    host_addresses = set()
    address_output = _call_agent("run", None, ["ip", "-j", "address", "show"])
    if address_output.strip():
        try:
            address_payload = json.loads(address_output)
        except (TypeError, ValueError):
            address_payload = []
        for interface in address_payload if isinstance(address_payload, list) else []:
            if not isinstance(interface, dict):
                continue
            address_info = interface.get("addr_info") if isinstance(interface.get("addr_info"), list) else []
            for address in address_info:
                if not isinstance(address, dict):
                    continue
                value = str(address.get("local") or "")
                if _is_trackable_ip(value):
                    host_addresses.add(value)
    nat_mappings: List[Dict[str, object]] = []
    # Collect all firewall backends in one bounded shell call. This avoids
    # spawning three processes per security sample and keeps old single-call
    # collectors compatible while still reading iptables, ip6tables and nft.
    nft_output = _call_agent("run", None, 
        [
            "sh",
            "-lc",
            "for command in iptables-save ip6tables-save; do "
            "if command -v \"$command\" >/dev/null 2>&1; then "
            "if [ \"$command\" = iptables-save ]; then source=iptables-dnat; "
            "else source=ip6tables-dnat; fi; "
            "printf '__NARWHAL_NAT_SOURCE__ %s\\n' \"$source\"; "
            "\"$command\" -t nat 2>/dev/null || true; fi; done; "
            "if command -v nft >/dev/null 2>&1; then "
            "printf '__NARWHAL_NAT_SOURCE__ nft-dnat\\n'; "
            "nft list ruleset 2>/dev/null | grep -E '(^|[[:space:]])dnat[[:space:]]+to[[:space:]]' | sed -n '1,2000p'; fi",
        ]
    )
    mapping_source = "iptables-dnat"
    existing_nat_keys = {
        (str(item.get("proto") or ""), str(item.get("host") or ""), int(item.get("public_port") or 0),
         str(item.get("target_host") or ""), int(item.get("container_port") or 0))
        for item in nat_mappings
    }
    for line in nft_output.splitlines():
        if line.startswith("__NARWHAL_NAT_SOURCE__ "):
            mapping_source = line.partition(" ")[2].strip() or "iptables-dnat"
            continue
        if mapping_source in {"iptables-dnat", "ip6tables-dnat"}:
            proto_match = re.search(r"(?:^|\s)-p\s+(tcp|udp)\b", line, re.IGNORECASE)
            port_match = re.search(r"(?:^|\s)--dport\s+(\d+)\b", line)
            target_match = re.search(r"(?:^|\s)--to-destination\s+([^\s]+)", line)
            if not port_match or not target_match:
                continue
            target_host, target_port = _parse_socket_endpoint(target_match.group(1))
            destination_match = re.search(r"(?:^|\s)-d\s+([^\s/]+)(?:/\d+)?", line)
            candidate = {
                "proto": proto_match.group(1).lower() if proto_match else "",
                "host": destination_match.group(1) if destination_match else "",
                "public_port": int(port_match.group(1)),
                "target_host": target_host,
                "container_port": target_port,
                "source": mapping_source,
            }
            key = (candidate["proto"], candidate["host"], candidate["public_port"], candidate["target_host"], candidate["container_port"])
            if key not in existing_nat_keys:
                nat_mappings.append(candidate)
                existing_nat_keys.add(key)
            continue
        # Hosts may run both compatibility NAT rules and native nftables rules.
        # Read both inventories instead of treating any iptables output
        # (including unrelated or UDP-only entries) as proof of no TCP DNAT.
        mapping_match = re.search(
            r"\b(tcp|udp)\s+dport\s+(\d+).*?\bdnat\s+to\s+([^\s]+)",
            line,
            re.IGNORECASE,
        )
        if not mapping_match:
            continue
        target_host, target_port = _parse_socket_endpoint(mapping_match.group(3))
        destination_match = re.search(r"\b(?:ip|ip6)\s+daddr\s+([^\s]+)", line)
        candidate = {
            "proto": mapping_match.group(1).lower(),
            "host": destination_match.group(1) if destination_match else "",
            "public_port": int(mapping_match.group(2)),
            "target_host": target_host,
            "container_port": target_port,
            "source": mapping_source,
        }
        key = (candidate["proto"], candidate["host"], candidate["public_port"], candidate["target_host"], candidate["container_port"])
        if key not in existing_nat_keys:
            nat_mappings.append(candidate)
            existing_nat_keys.add(key)
    entries = []
    for line in lines:
        parsed = _parse_conntrack_line(line)
        if parsed:
            entries.append(parsed)
    return {
        "available": available,
        "snapshot_count": len(lines),
        "snapshot_truncated": len(lines) >= limit,
        "host_addresses": sorted(host_addresses),
        "nat_mappings": nat_mappings[:2000],
        "entries": entries,
    }


def _augment_conntrack_with_host_proxy_sockets(
    conntrack: Dict[str, object], containers: List[Dict[str, object]]
) -> None:
    """Safely correlate two-leg user-space proxy sockets when one PID has one target."""
    address_owners: Dict[str, str] = {}
    for container in containers:
        if not isinstance(container, dict) or container.get("runtime") == "docker":
            continue
        for address in container.get("network_addresses") or []:
            value = str(address)
            if _is_trackable_ip(value):
                address_owners[value] = str(container.get("name") or "")
    if not address_owners:
        return
    limit = max(100, min(20000, int(_call_agent("_env_float", None, "SECURITY_HOST_PROXY_SOCKET_MAX", 5000))))
    output = _call_agent("run", None, 
        [
            "sh",
            "-lc",
            "if command -v ss >/dev/null 2>&1; then "
            f"ss -H -t -u -n -a -p 2>/dev/null | sed -n '1,{limit}p'; fi",
        ]
    )
    lines = [line.strip() for line in output.splitlines()[:limit] if line.strip()]
    listeners: Dict[Tuple[int, str], set] = {}
    established: List[Dict[str, object]] = []
    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        state = parts[1].upper()
        local_ip, local_port = _parse_socket_endpoint(parts[4])
        remote_ip, remote_port = _parse_socket_endpoint(parts[5])
        process_text = parts[6] if len(parts) > 6 else ""
        owners = re.findall(r'\("([^"\\]{1,120})",pid=(\d+)', process_text)
        if not owners:
            continue
        owner = (int(owners[0][1]), owners[0][0])
        if state == "LISTEN" and local_port > 0:
            listeners.setdefault(owner, set()).add((proto, local_ip, local_port))
        elif state in ("ESTAB", "ESTABLISHED") and local_port > 0 and remote_port > 0:
            established.append(
                {
                    "owner": owner,
                    "proto": "tcp" if proto.startswith("tcp") else proto,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                }
            )
    targets: Dict[Tuple[int, str], set] = {}
    external_sources: Dict[Tuple[int, str], List[Dict[str, object]]] = {}
    for socket_item in established:
        owner = socket_item["owner"]
        remote_ip = str(socket_item["remote_ip"])
        remote_port = int(socket_item["remote_port"])
        if remote_ip in address_owners:
            targets.setdefault(owner, set()).add((remote_ip, remote_port))
            continue
        if not _is_public_source_ip(remote_ip):
            continue
        local_port = int(socket_item["local_port"])
        listening = listeners.get(owner, set())
        if not any(int(item[2]) == local_port for item in listening):
            continue
        external_sources.setdefault(owner, []).append(socket_item)
    entries = conntrack.get("entries") if isinstance(conntrack.get("entries"), list) else []
    nat_mappings = conntrack.get("nat_mappings") if isinstance(conntrack.get("nat_mappings"), list) else []
    matched_connections = 0
    for owner, sources in external_sources.items():
        owner_targets = targets.get(owner, set())
        if len(owner_targets) != 1:
            continue
        target_ip, target_port = next(iter(owner_targets))
        for source in sources:
            local_ip = str(source["local_ip"])
            local_port = int(source["local_port"])
            proto = str(source["proto"])
            remote_ip = str(source["remote_ip"])
            remote_port = int(source["remote_port"])
            entries.append(
                {
                    "proto": proto,
                    "evidence_source": "host_proxy_socket",
                    "tcp_state": "ESTABLISHED" if proto == "tcp" else "",
                    "unreplied": False,
                    "original_packets": 1,
                    "reply_packets": 1,
                    "original_src": remote_ip,
                    "original_dst": local_ip,
                    "original_sport": remote_port,
                    "original_dport": local_port,
                    "reply_src": local_ip,
                    "reply_dst": remote_ip,
                    "reply_sport": local_port,
                    "reply_dport": remote_port,
                    "proxy_process": owner[1],
                    "proxy_pid": owner[0],
                }
            )
            nat_mappings.append(
                {
                    "proto": proto,
                    "host": local_ip,
                    "public_port": local_port,
                    "target_host": target_ip,
                    "container_port": target_port,
                    "source": "host-proxy-socket",
                }
            )
            matched_connections += 1
    conntrack["entries"] = entries
    conntrack["nat_mappings"] = nat_mappings
    conntrack["host_proxy_socket_available"] = bool(lines)
    conntrack["host_proxy_socket_snapshot_count"] = len(lines)
    conntrack["host_proxy_socket_snapshot_truncated"] = len(lines) >= limit
    conntrack["host_proxy_matched_connections"] = matched_connections


def _parse_exposure_endpoint(value: str) -> Tuple[str, str, int]:
    text = (value or "").strip()
    proto = ""
    if text.lower().startswith(("tcp:", "udp:")):
        proto, text = text.split(":", 1)
        proto = proto.lower()
    elif "/" in text and text.rsplit("/", 1)[1].lower() in ("tcp", "udp"):
        text, proto = text.rsplit("/", 1)
        proto = proto.lower()
    host, port = _parse_socket_endpoint(text)
    if port <= 0 and text.isdigit():
        port = int(text)
        host = ""
    return proto, host, port


def _apply_host_conntrack_security(
    security: Dict[str, object],
    conntrack: Dict[str, object],
    container_addresses: List[str],
    network_exposure: List[Dict[str, str]],
) -> None:
    """Replace proxy-collapsed source counts with original host conntrack tuples."""
    entries = conntrack.get("entries") if isinstance(conntrack.get("entries"), list) else []
    host_addresses = {
        str(address)
        for address in (conntrack.get("host_addresses") or [])
        if _is_trackable_ip(str(address))
    }
    addresses = {
        str(address)
        for address in list(container_addresses) + list(security.get("container_ips") or [])
        if _is_trackable_ip(str(address))
    }
    mappings = []
    for exposure in network_exposure:
        if not isinstance(exposure, dict):
            continue
        listen_proto, listen_host, listen_port = _parse_exposure_endpoint(str(exposure.get("listen") or ""))
        target_proto, target_host, target_port = _parse_exposure_endpoint(str(exposure.get("target") or ""))
        if target_host and _is_trackable_ip(target_host):
            addresses.add(target_host)
        if listen_port > 0 or (str(exposure.get("source") or "") == "incus-forward" and listen_host):
            mappings.append(
                {
                    "proto": listen_proto or target_proto,
                    "host": listen_host,
                    "public_port": listen_port,
                    "container_port": target_port,
                }
            )
    host_nat_mappings = conntrack.get("nat_mappings") if isinstance(conntrack.get("nat_mappings"), list) else []
    for mapping in host_nat_mappings:
        if not isinstance(mapping, dict):
            continue
        target_host = str(mapping.get("target_host") or "")
        if target_host not in addresses:
            continue
        mappings.append(
            {
                "proto": str(mapping.get("proto") or ""),
                "host": str(mapping.get("host") or ""),
                "public_port": int(mapping.get("public_port") or 0),
                "container_port": int(mapping.get("container_port") or 0),
            }
        )

    source_connections: Dict[str, int] = {}
    flow_connections: Dict[Tuple[str, str, int, int], int] = {}
    source_signals: Dict[str, Dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        source_ip = str(entry.get("original_src") or "")
        proto = str(entry.get("proto") or "")
        original_dst = str(entry.get("original_dst") or "")
        original_dport = int(entry.get("original_dport") or 0)
        reply_src = str(entry.get("reply_src") or "")
        reply_sport = int(entry.get("reply_sport") or 0)
        matched = reply_src in addresses
        container_port = reply_sport if matched else 0
        if not matched:
            for mapping in mappings:
                mapping_proto = str(mapping.get("proto") or "")
                mapping_host = str(mapping.get("host") or "")
                if mapping_proto and mapping_proto != proto:
                    continue
                mapping_public_port = int(mapping.get("public_port") or 0)
                if mapping_public_port > 0 and mapping_public_port != original_dport:
                    continue
                if mapping_host and mapping_host not in ("0.0.0.0", "::", "*") and mapping_host != original_dst:
                    continue
                if mapping_host in ("", "0.0.0.0", "::", "*") and host_addresses and original_dst not in host_addresses:
                    continue
                matched = True
                container_port = int(mapping.get("container_port") or 0) or original_dport
                break
        if not matched or not _is_public_source_ip(source_ip) or source_ip in addresses:
            continue
        source_connections[source_ip] = source_connections.get(source_ip, 0) + 1
        flow_key = (source_ip, proto, original_dport, container_port)
        flow_connections[flow_key] = flow_connections.get(flow_key, 0) + 1
        signal = source_signals.setdefault(source_ip, {
            "flow_count": 0,
            "tcp_established_flows": 0,
            "tcp_unreplied_flows": 0,
            "tcp_handshake_pending_flows": 0,
            "source_packets": 0,
            "reply_packets": 0,
            "public_ports": set(),
            "container_ports": set(),
            "protocols": set(),
            "evidence_sources": set(),
        })
        signal["flow_count"] = int(signal["flow_count"]) + 1
        signal["source_packets"] = int(signal["source_packets"]) + int(entry.get("original_packets") or 0)
        signal["reply_packets"] = int(signal["reply_packets"]) + int(entry.get("reply_packets") or 0)
        if original_dport > 0:
            signal["public_ports"].add(original_dport)
        if container_port > 0:
            signal["container_ports"].add(container_port)
        if proto:
            signal["protocols"].add(proto)
        evidence_sources = signal.get("evidence_sources")
        if isinstance(evidence_sources, set):
            evidence_sources.add(str(entry.get("evidence_source") or "host_conntrack"))
        tcp_state = str(entry.get("tcp_state") or "").upper()
        reply_packets = int(entry.get("reply_packets") or 0)
        if proto == "tcp" and tcp_state == "ESTABLISHED" and not bool(entry.get("unreplied")):
            signal["tcp_established_flows"] = int(signal["tcp_established_flows"]) + 1
        elif proto == "tcp" and tcp_state == "SYN_RECV":
            signal["tcp_handshake_pending_flows"] = int(signal["tcp_handshake_pending_flows"]) + 1
        elif proto == "tcp" and (bool(entry.get("unreplied")) or (reply_packets == 0 and tcp_state != "ESTABLISHED")):
            signal["tcp_unreplied_flows"] = int(signal["tcp_unreplied_flows"]) + 1

    security["host_conntrack_available"] = bool(conntrack.get("available"))
    security["host_conntrack_snapshot_count"] = int(conntrack.get("snapshot_count") or 0)
    security["host_conntrack_snapshot_truncated"] = bool(conntrack.get("snapshot_truncated"))
    security["host_proxy_socket_available"] = bool(conntrack.get("host_proxy_socket_available"))
    security["host_proxy_socket_snapshot_count"] = int(conntrack.get("host_proxy_socket_snapshot_count") or 0)
    security["host_proxy_matched_connections"] = int(conntrack.get("host_proxy_matched_connections") or 0)
    security["container_ips"] = sorted(addresses)
    if not source_connections:
        return
    security["inbound_ip_observation"] = "host_conntrack"
    security["inbound_unique_ips"] = len(source_connections)
    conntrack_established_ips = sum(
        1 for sig in source_signals.values() if int(sig.get("tcp_established_flows") or 0) > 0
    )
    conntrack_syn_recv_ips = sum(
        1
        for sig in source_signals.values()
        if int(sig.get("tcp_established_flows") or 0) == 0
        and (
            int(sig.get("tcp_handshake_pending_flows") or 0) > 0
            or int(sig.get("tcp_unreplied_flows") or 0) > 0
        )
    )
    if conntrack_established_ips > int(security.get("inbound_established_unique_ips") or 0):
        security["inbound_established_unique_ips"] = conntrack_established_ips
    if conntrack_syn_recv_ips > int(security.get("inbound_syn_recv_unique_ips") or 0):
        security["inbound_syn_recv_unique_ips"] = conntrack_syn_recv_ips
    security["inbound_top_ips"] = [
        {
            "ip": ip,
            "connections": count,
            "established_connections": int((source_signals.get(ip) or {}).get("tcp_established_flows") or 0),
            "syn_recv_connections": (
                int((source_signals.get(ip) or {}).get("tcp_handshake_pending_flows") or 0)
                + int((source_signals.get(ip) or {}).get("tcp_unreplied_flows") or 0)
            ),
        }
        for ip, count in sorted(source_connections.items(), key=lambda item: item[1], reverse=True)[:20]
    ]
    normalized_signals = []
    for ip, signal in source_signals.items():
        public_ports = sorted(signal["public_ports"])
        container_ports = sorted(signal["container_ports"])
        established = int(signal["tcp_established_flows"])
        unreplied = int(signal["tcp_unreplied_flows"])
        pending = int(signal["tcp_handshake_pending_flows"])
        incomplete = unreplied + pending
        if len(public_ports) >= 3 and incomplete >= 3 and incomplete >= max(1, established * 2):
            classification = "possible_multiport_probe"
        elif established and unreplied:
            classification = "mixed_connection_evidence"
        elif established:
            classification = "bidirectional_tcp_observed"
        elif unreplied:
            classification = "unreplied_tcp_observed"
        else:
            classification = "insufficient_transport_evidence"
        normalized_signals.append({
            "ip": ip,
            "flow_count": int(signal["flow_count"]),
            "tcp_established_flows": established,
            "tcp_unreplied_flows": unreplied,
            "tcp_handshake_pending_flows": pending,
            "source_packets": int(signal["source_packets"]),
            "reply_packets": int(signal["reply_packets"]),
            "public_ports": public_ports[:32],
            "container_ports": container_ports[:32],
            "protocols": sorted(signal["protocols"]),
            "evidence_sources": sorted(signal["evidence_sources"]),
            "classification": classification,
            "scope": "single_conntrack_snapshot"
            if signal["evidence_sources"] == {"host_conntrack"}
            else "single_host_network_snapshot",
        })
    security["inbound_source_signals"] = sorted(
        normalized_signals,
        key=lambda item: (item["classification"] == "possible_multiport_probe", item["flow_count"]),
        reverse=True,
    )[:20]
    security["inbound_public_flows"] = [
        {
            "remote_ip": key[0],
            "proto": key[1],
            "public_port": key[2],
            "container_port": key[3],
            "connections": count,
        }
        for key, count in sorted(flow_connections.items(), key=lambda item: item[1], reverse=True)[:100]
    ]


def _enrich_communication_with_original_sources(
    communication: Dict[str, object], public_flows: List[Dict[str, object]]
) -> None:
    """Keep NAT-derived sources at port scope unless an exact socket tuple matched.

    Host conntrack can restore the public client IP hidden by a container proxy,
    but grouping those flows by container port cannot prove which individual
    accepted socket or PID handled each source. Do not copy aggregate IPs onto
    every socket on that port or label the correlation as confirmed.
    """
    flows_by_port: Dict[int, List[Dict[str, object]]] = {}
    for flow in public_flows:
        if not isinstance(flow, dict):
            continue
        port = int(flow.get("container_port") or 0)
        if port > 0:
            flows_by_port.setdefault(port, []).append(flow)
    listener_owners: Dict[int, set[Tuple[int, str]]] = {}
    listeners = communication.get("service_listeners")
    for listener in listeners if isinstance(listeners, list) else []:
        if not isinstance(listener, dict):
            continue
        try:
            port = int(listener.get("port") or 0)
            pid = int(listener.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if port > 0 and pid > 0:
            listener_owners.setdefault(port, set()).add(
                (pid, str(listener.get("process") or "unknown")[:120])
            )

    port_evidence = []
    for port, matched_flows in sorted(flows_by_port.items()):
        source_ips = sorted({
            str(flow.get("remote_ip") or "")
            for flow in matched_flows
            if flow.get("remote_ip") and _is_public_source_ip(str(flow.get("remote_ip")))
        })
        if not source_ips:
            continue
        connections = 0
        for flow in matched_flows:
            try:
                connections += max(0, int(flow.get("connections") or 0))
            except (TypeError, ValueError):
                continue
        port_evidence.append({
            "container_port": port,
            "source_ips": source_ips[:20],
            "source_ip_count": len(source_ips),
            "connections": connections,
            "process_listeners": [
                {"pid": pid, "process": process}
                for pid, process in sorted(listener_owners.get(port, set()))[:20]
            ],
            "correlation_scope": "container_port_aggregate",
            "confidence": "port_correlated",
            "exact_socket_match": False,
        })
    communication["inbound_port_evidence"] = port_evidence[:50]



def _fmt_rate_bps(bps: float) -> str:
    val = max(0.0, float(bps or 0.0))
    if val >= 1024 * 1024:
        return f"{val / (1024 * 1024):.2f} MB/s"
    if val >= 1024:
        return f"{val / 1024:.1f} KB/s"
    return f"{val:.0f} B/s"


_PROXY_LISTEN_FLAGS = {"-L", "--listen", "-l", "--local", "-listen"}
_PROXY_FORWARD_FLAGS = {"-F", "--forward", "-forward", "--upstream", "--proxy"}


def _socks_process_commands(process_output: str, pids: set) -> List[Dict[str, object]]:
    """Return redacted launch arguments, listener specs, and upstream chains for proxy PIDs."""
    wanted = {int(p) for p in (pids or set()) if int(p or 0) > 1}
    if not wanted or not isinstance(process_output, str):
        return []
    rows: List[Dict[str, object]] = []
    seen: set = set()
    for line in process_output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        if pid not in wanted or pid in seen:
            continue
        seen.add(pid)
        # `ps -eo pid=,stat=,comm=,args=` puts stat second; the fallback omits it.
        if len(parts) == 4 and re.fullmatch(r"[A-Za-z<+lNsI]{1,6}", parts[1] or ""):
            process, args = parts[2], parts[3]
        else:
            process, args = parts[1], " ".join(parts[2:])
        command = _call_agent("_redact_process_command", None, args)
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        listeners: List[str] = []
        forwards: List[str] = []
        for index, token in enumerate(tokens):
            flag, _, inline = token.partition("=")
            value = inline if inline else (tokens[index + 1] if index + 1 < len(tokens) else "")
            if flag in _PROXY_LISTEN_FLAGS and value:
                listeners.append(value[:160])
            elif flag in _PROXY_FORWARD_FLAGS and value:
                forwards.append(value[:160])
        rows.append({
            "pid": pid,
            "process": str(process)[:60],
            "command": command[:400],
            "listeners": listeners[:6],
            "forwards": forwards[:6],
        })
        if len(rows) >= 4:
            break
    return rows


_RELAY_NETWORKS_V4 = (("104.28.0.0/16", "Cloudflare WARP 中继出口"),)
_RELAY_NETWORKS_V6 = (("2a09:bac0::/29", "Cloudflare WARP 中继出口"),)
_DATACENTER_KEYWORDS = (
    "amazon", "aws", "google", "microsoft", "azure", "oracle", "digitalocean", "ovh", "hetzner",
    "linode", "akamai", "vultr", "choopa", "alibaba", "aliyun", "tencent", "m247", "leaseweb",
    "contabo", "datacamp", "cdn77", "fastly", "hostinger", "colocrossing", "psychz", "cogent",
)
_OUTBOUND_PORT_LABELS = {
    443: "HTTPS", 80: "HTTP", 53: "DNS", 853: "DoT", 8443: "HTTPS-Alt", 8080: "HTTP-Alt",
    5228: "Google FCM/Play", 5222: "XMPP/推送", 5223: "Apple APNs", 3478: "STUN/WebRTC",
    22: "SSH", 25: "SMTP", 465: "SMTPS", 587: "SMTP-Sub", 993: "IMAPS", 995: "POP3S",
    1935: "RTMP", 6881: "BitTorrent", 51413: "BitTorrent", 123: "NTP",
}


def _classify_source_network(ip: str, isp: str = "", asn: str = "") -> Tuple[str, str]:
    """Classify an inbound source network without treating relays as independent users."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return "unknown", ""
    for cidr, label in (_RELAY_NETWORKS_V6 if addr.version == 6 else _RELAY_NETWORKS_V4):
        if addr in ipaddress.ip_network(cidr):
            return "relay", label
    asn_upper = str(asn or "").upper()
    isp_lower = str(isp or "").lower()
    if asn_upper == "AS36183":
        return "relay", "iCloud Private Relay 中继"
    if "cloudflare" in isp_lower or asn_upper in {"AS13335", "AS209242"}:
        return "relay", "Cloudflare 网络"
    if any(keyword in isp_lower for keyword in _DATACENTER_KEYWORDS):
        return "datacenter", "数据中心 / IDC"
    if isp_lower:
        return "access", "接入网 (家宽 / 移动)"
    return "unknown", ""


def _source_network_key(ip: str, kind: str, label: str, asn: str, isp: str) -> str:
    if kind == "relay":
        return f"relay:{label}"
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
        prefix = ipaddress.ip_network(f"{addr}/{48 if addr.version == 6 else 24}", strict=False)
    except ValueError:
        prefix = None
    return f"{asn or isp or 'unknown'}:{prefix}"


def _build_socket_investigation(
    security: Dict[str, object],
    inbound_top_ips: List[Dict[str, object]],
    outbound_top_ips: List[Dict[str, object]],
    outbound_top_ports: List[Dict[str, object]],
    incoming_established: int,
    outbound_established: int,
    inbound_established_ips: int,
    outbound_unique_ips: int,
    socks_detected: bool,
    socks_auth_mode: str,
    rx_bps: float,
    tx_bps: float,
) -> Dict[str, object]:
    """Structured, observation-only context that helps an operator judge proxy usage."""
    groups: Dict[str, Dict[str, object]] = {}
    relay_ips = 0
    classified = 0
    for item in inbound_top_ips[:20]:
        if not isinstance(item, dict) or not item.get("ip"):
            continue
        ip_str = str(item.get("ip"))
        if not _is_public_source_ip(ip_str):
            continue
        isp = str(item.get("isp") or "")
        asn = str(item.get("asn") or "")
        kind, label = _classify_source_network(ip_str, isp, asn)
        item["network_kind"] = kind
        item["network_label"] = label
        classified += 1
        if kind == "relay":
            relay_ips += 1
        key = _source_network_key(ip_str, kind, label, asn, isp)
        group = groups.setdefault(key, {
            "label": label or isp or asn or "未知网络",
            "kind": kind,
            "asn": asn,
            "isp": isp,
            "ips": 0,
            "established_connections": 0,
            "sample_ips": [],
        })
        group["ips"] = int(group["ips"]) + 1
        group["established_connections"] = int(group["established_connections"]) + int(item.get("established_connections") or 0)
        if len(group["sample_ips"]) < 3:
            group["sample_ips"].append(ip_str)
    source_networks = sorted(groups.values(), key=lambda g: (int(g["ips"]), int(g["established_connections"])), reverse=True)[:8]
    estimated_low = max(1, len(groups)) if classified else 0
    estimated_high = max(estimated_low, inbound_established_ips)
    relay_share = round(relay_ips / classified, 3) if classified else 0.0

    total_port_conns = sum(int(p.get("connections") or 0) for p in outbound_top_ports if isinstance(p, dict))
    port_mix = []
    for p in outbound_top_ports[:6]:
        if not isinstance(p, dict):
            continue
        port = int(p.get("port") or 0)
        conns = int(p.get("connections") or 0)
        port_mix.append({
            "port": port,
            "label": _OUTBOUND_PORT_LABELS.get(port, str(p.get("service") or "")),
            "connections": conns,
            "unique_ips": int(p.get("unique_ips") or 0),
            "share": round(conns / total_port_conns, 3) if total_port_conns else 0.0,
        })
    web_conns = sum(int(p["connections"]) for p in port_mix if p["port"] in (80, 443, 8080, 8443))
    web_share = round(web_conns / total_port_conns, 3) if total_port_conns else 0.0

    org_map: Dict[str, Dict[str, object]] = {}
    for item in outbound_top_ips[:20]:
        if not isinstance(item, dict):
            continue
        org = str(item.get("isp") or "").strip() or "未解析归属"
        entry = org_map.setdefault(org[:48], {"org": org[:48], "asn": str(item.get("asn") or ""), "ips": 0, "connections": 0})
        entry["ips"] = int(entry["ips"]) + 1
        entry["connections"] = int(entry["connections"]) + int(item.get("connections") or 0)
    outbound_orgs = sorted(org_map.values(), key=lambda e: (int(e["connections"]), int(e["ips"])), reverse=True)[:6]

    pair_max = max(incoming_established, outbound_established, 1)
    symmetry = round(min(incoming_established, outbound_established) / pair_max, 3) if incoming_established and outbound_established else 0.0
    proxy_like = bool(socks_detected or (incoming_established >= 10 and outbound_established >= 10 and symmetry >= 0.6))
    direction_ratio = round(tx_bps / rx_bps, 2) if rx_bps > 0 else 0.0

    socks_proxy = security.get("socks_proxy") if isinstance(security.get("socks_proxy"), dict) else {}
    proxy_processes = [
        p for p in (socks_proxy.get("process_commands") if isinstance(socks_proxy.get("process_commands"), list) else [])
        if isinstance(p, dict)
    ][:4]
    has_forward_chain = any(p.get("forwards") for p in proxy_processes)
    relay_labels = sorted({str(g["label"]) for g in groups.values() if g["kind"] == "relay"})

    def level(score: int) -> str:
        return "high" if score >= 2 else "medium" if score == 1 else "low"

    scenarios = []
    personal_score = (2 if relay_share >= 0.6 and estimated_low <= 2 else 1 if relay_share >= 0.3 or estimated_low <= 2 else 0) if proxy_like else 0
    scenarios.append({
        "key": "personal_relay_proxy",
        "label": "个人自用代理（含 WARP/中继二级代理）",
        "likelihood": level(personal_score),
        "basis": (
            f"{relay_ips}/{classified} 个来源 IP 属中继网络，估算独立来源网络 {estimated_low} 个"
            + ("，出站以 HTTPS 为主" if web_share >= 0.6 else "")
        ),
    })
    share_score = 2 if estimated_low >= 6 else 1 if estimated_low >= 3 or (inbound_established_ips >= 6 and relay_share < 0.6) else 0
    scenarios.append({
        "key": "multi_device_sharing",
        "label": "多设备共用 / 小规模共享",
        "likelihood": level(share_score),
        "basis": f"已建连来源 {inbound_established_ips} 个 IP、{estimated_low} 个独立网络，入站活跃 {incoming_established} 条",
    })
    commercial_score = 2 if estimated_low >= 8 and (incoming_established >= 150 or tx_bps >= 5 * 1024 * 1024) else 1 if estimated_low >= 5 and incoming_established >= 60 else 0
    scenarios.append({
        "key": "commercial_proxy_exit",
        "label": "商业共享 / 机场出口",
        "likelihood": level(commercial_score),
        "basis": f"独立来源网络 {estimated_low} 个，出站 {_fmt_rate_bps(tx_bps)}，入站活跃 {incoming_established} 条",
    })
    automation_score = 1 if outbound_unique_ips >= 80 and estimated_low <= 2 else 0
    scenarios.append({
        "key": "automation_relay",
        "label": "自动化程序 / 爬虫中转",
        "likelihood": level(automation_score),
        "basis": f"出站目标 {outbound_unique_ips} 个 IP，Web 端口占比 {web_share * 100:.0f}%，来源网络 {estimated_low} 个",
    })

    notes: List[str] = []
    if relay_ips:
        notes.append(
            f"{relay_ips} 个来源 IP 属 {'、'.join(relay_labels) or '中继'}；同一用户经中继重连或多出口会表现为多个 IP，不能按独立用户计数。"
        )
    if proxy_like and symmetry:
        notes.append(
            f"入站 {incoming_established} / 出站 {outbound_established} 条活跃连接，对称度 {symmetry * 100:.0f}%，符合 TCP 代理一进一出转发特征。"
        )
    if rx_bps > 0 and tx_bps > 0:
        if 0.67 <= direction_ratio <= 1.5:
            notes.append(f"出站 {_fmt_rate_bps(tx_bps)} 与入站 {_fmt_rate_bps(rx_bps)} 基本持平，连接数比带宽消耗更突出。")
        else:
            notes.append(f"出站 {_fmt_rate_bps(tx_bps)} / 入站 {_fmt_rate_bps(rx_bps)}（约 {direction_ratio:.1f} 倍）。")
    if port_mix:
        top = port_mix[0]
        notes.append(f"出站以 {top['port']}{('/' + top['label']) if top['label'] else ''} 为主（占 {top['share'] * 100:.0f}%），共 {outbound_unique_ips} 个目标 IP。")
    if any(p["port"] == 5228 for p in port_mix):
        notes.append("5228 为 Google FCM 推送常用端口，只能说明有持续联网应用，不足以证明运行模拟器。")
    if socks_detected and socks_auth_mode in ("unknown", ""):
        notes.append("SOCKS5 认证模式 unknown 表示未能读取配置，不等于无密码开放代理。")
    if has_forward_chain:
        notes.append("代理进程带有上游转发 (-F) 参数，可能为多级代理 / 中转链路。")
    notes.append("以上为连接特征推测，未通过应用日志还原，不作为认定用户身份或处罚的依据。")

    return {
        "schema": 1,
        "source_networks": source_networks,
        "estimated_independent_sources": {"low": estimated_low, "high": estimated_high},
        "relay_ips": relay_ips,
        "relay_share": relay_share,
        "classified_ips": classified,
        "outbound_port_mix": port_mix,
        "outbound_web_share": web_share,
        "outbound_orgs": outbound_orgs,
        "proxy_symmetry": symmetry,
        "proxy_like": proxy_like,
        "direction_ratio": direction_ratio,
        "proxy_processes": proxy_processes,
        "has_forward_chain": has_forward_chain,
        "scenarios": scenarios,
        "notes": notes[:8],
    }


def _evaluate_socket_abuse(
    container: Dict[str, object],
    security: Dict[str, object],
    rx_bps: float = 0.0,
    tx_bps: float = 0.0,
    rx_pps: float = 0.0,
    tx_pps: float = 0.0,
) -> Dict[str, object]:
    """Evaluate 4-dimension socket & SOCKS/proxy abuse evidence (observation-only)."""
    _call_agent("_enrich_socket_ips_geoip", None, security, allow_network=False)
    cm = security.get("connection_metrics") if isinstance(security.get("connection_metrics"), dict) else {}
    tcp_states = security.get("tcp_states") if isinstance(security.get("tcp_states"), dict) else {}
    raw_conn_count = int(container.get("conn_count") or 0)
    cm_total = int(cm.get("total") or 0)

    incoming_established = int(security.get("incoming_established") or 0)
    outbound_established = int(security.get("outbound_established") or 0)

    raw_tcp_est = int(
        cm["tcp_established"]
        if "tcp_established" in cm
        else tcp_states.get("established") or 0
    )
    tcp_established = max(
        raw_tcp_est,
        int(tcp_states.get("established") or 0),
        incoming_established + outbound_established,
    )
    raw_tcp_tw = int(
        cm["tcp_time_wait"]
        if "tcp_time_wait" in cm
        else tcp_states.get("time_wait") or 0
    )
    tcp_time_wait = max(raw_tcp_tw, int(tcp_states.get("time_wait") or 0))
    tcp_syn_sent = int(security.get("syn_sent_count") or tcp_states.get("syn_sent") or 0)
    tcp_syn_recv = int(security.get("syn_recv_count") or tcp_states.get("syn_recv") or 0)
    tcp_close_wait = int(tcp_states.get("close_wait") or 0)
    tcp_fin_wait = int(tcp_states.get("fin_wait1") or 0) + int(tcp_states.get("fin_wait2") or 0)
    udp_sockets = int(cm.get("udp_sockets") or 0)
    total_sockets = max(
        raw_conn_count,
        cm_total,
        tcp_established + tcp_time_wait + tcp_syn_sent + tcp_syn_recv + tcp_close_wait + tcp_fin_wait + udp_sockets,
    )

    inbound_unique_ips = int(security.get("inbound_unique_ips") or 0)
    inbound_established_ips = int(security.get("inbound_established_unique_ips") or 0)
    inbound_syn_recv_ips = int(security.get("inbound_syn_recv_unique_ips") or 0)
    inbound_top_ips = (
        security.get("inbound_top_ips")
        if isinstance(security.get("inbound_top_ips"), list)
        else []
    )

    outbound_unique_ips = int(security.get("outbound_unique_ips") or 0)
    outbound_unique_ports = int(security.get("outbound_unique_ports") or 0)
    outbound_syn_sent_ips = int(security.get("outbound_syn_sent_unique_ips") or 0)
    suspicious_outbound = int(security.get("suspicious_outbound_connections") or 0)
    outbound_top_ips = (
        security.get("outbound_top_ips")
        if isinstance(security.get("outbound_top_ips"), list)
        else []
    )
    sensitive_outbound_ports = (
        security.get("sensitive_outbound_ports")
        if isinstance(security.get("sensitive_outbound_ports"), list)
        else []
    )
    outbound_top_ports = (
        security.get("outbound_top_ports")
        if isinstance(security.get("outbound_top_ports"), list)
        else []
    )

    socks_proxy = security.get("socks_proxy") if isinstance(security.get("socks_proxy"), dict) else {}
    socks_detected = bool(socks_proxy.get("detected"))
    socks_auth_mode = str(socks_proxy.get("auth_mode") or "none")
    hy2_info = security.get("hy2_protocol") if isinstance(security.get("hy2_protocol"), dict) else {}
    hy2_detected = bool(hy2_info.get("detected"))

    comm_procs = (
        security.get("communication_processes")
        if isinstance(security.get("communication_processes"), list)
        else []
    )
    top_procs = [
        {
            "process": str(item.get("process") or "unknown")[:60],
            "pid": int(item.get("pid") or 0),
            "inbound_connections": int(item.get("inbound_connections") or 0),
            "outbound_connections": int(item.get("outbound_connections") or 0),
        }
        for item in comm_procs[:5]
        if isinstance(item, dict) and item.get("process")
    ]
    listening_ports = [
        int(p)
        for p in (security.get("listening_ports") if isinstance(security.get("listening_ports"), list) else [])
        if isinstance(p, (int, str)) and str(p).isdigit()
    ][:12]

    has_socket_evidence = bool(
        cm.get("valid") is True
        or tcp_states
        or cm_total > 0
        or inbound_established_ips > 0
        or sensitive_outbound_ports
        or socks_detected
    )

    denom = max(total_sockets, tcp_established + tcp_time_wait + tcp_syn_sent + tcp_syn_recv + udp_sockets, 1)
    time_wait_ratio = round(tcp_time_wait / denom, 3)
    established_ratio = round(tcp_established / denom, 3)
    avg_tx_pkt = round(tx_bps / tx_pps, 1) if tx_pps > 0 else 0.0

    # Evaluate 4 concrete abuse categories when socket evidence is present
    categories: List[Dict[str, object]] = []
    high_risk_ports_hit = []
    for item in sensitive_outbound_ports:
        if not isinstance(item, dict):
            continue
        p = int(item.get("port") or 0)
        svc = str(item.get("service") or p)
        conns = int(item.get("connections") or 0)
        u_ips = int(item.get("unique_ips") or 0)
        s_sent = int(item.get("syn_sent") or 0)
        if p in {23, 25, 445, 465, 587, 1433, 3389, 6379, 6667} and (conns >= 3 or u_ips >= 3):
            high_risk_ports_hit.append(f"{p}/{svc}({conns}条,{u_ips}IP)")
        elif p in {22, 3306, 5432} and (u_ips >= 5 or s_sent >= 5):
            high_risk_ports_hit.append(f"{p}/{svc}({conns}条,{u_ips}IP,SYN_SENT {s_sent})")

    if has_socket_evidence:
        # Category 1: Outbound port scan / brute-force
        if (
            (tcp_syn_sent >= 20 and (outbound_syn_sent_ips >= 8 or outbound_unique_ips >= 15))
            or high_risk_ports_hit
            or (suspicious_outbound >= 5 and (bool(tcp_states) or cm.get("valid") is True or bool(sensitive_outbound_ports)))
        ):
            reasons = []
            if tcp_syn_sent >= 20:
                reasons.append(f"主动出站握手未完成 SYN_SENT 达 {tcp_syn_sent} 个（涉及 {max(outbound_syn_sent_ips, outbound_unique_ips)} 个目标 IP）")
            if high_risk_ports_hit:
                reasons.append(f"命中高危敏感出站端口：{', '.join(high_risk_ports_hit[:4])}")
            elif suspicious_outbound >= 5:
                reasons.append(f"敏感端口出站连接数达 {suspicious_outbound} 条")
            categories.append({
                "code": "outbound_scan_bruteforce",
                "title": "对外端口扫描 / 敏感端口爆破",
                "severity": "critical",
                "value": max(tcp_syn_sent, suspicious_outbound, len(high_risk_ports_hit)),
                "threshold": 20 if tcp_syn_sent >= 20 else 5,
                "reason": "；".join(reasons),
            })

        # Category 2: Shared proxy / SOCKS multi-IP abuse
        if (
            (socks_detected and (inbound_established_ips >= 6 or (socks_auth_mode in ("no_auth", "weak_password") and incoming_established >= 10)))
            or (inbound_established_ips >= 10 and (incoming_established >= 50 or outbound_established >= 50 or outbound_unique_ips >= 35))
        ):
            reasons = []
            if socks_detected:
                reasons.append(f"已识别 SOCKS5 代理服务（认证模式：{socks_auth_mode}）")
            reasons.append(
                f"入站真实已建立 TCP 连接 (ESTABLISHED) 的公网来源达 {inbound_established_ips} 个 IP"
                f"（入站活跃连接 {incoming_established} 条，出站活跃 {outbound_established} 条 / 目标 {outbound_unique_ips} IP）"
            )
            categories.append({
                "code": "shared_proxy_socks_abuse",
                "title": "多人共享 SOCKS / 代理节点滥用",
                "severity": "critical" if (inbound_established_ips >= 15 or socks_auth_mode in ("no_auth", "weak_password")) else "warning",
                "value": max(inbound_established_ips, incoming_established),
                "threshold": 6 if socks_detected else 10,
                "reason": "；".join(reasons),
            })

        # Category 3: High outbound fanout / P2P / crawler abuse
        # Require multi-port fanout (>=30 ports), high UDP sockets (>=80), or extreme IP count (>=300)
        # so normal web/CDN browsing across 2 ports (80/443) does not trigger false positives.
        if outbound_unique_ips >= 120 and (udp_sockets >= 80 or outbound_unique_ports >= 30 or outbound_unique_ips >= 300):
            categories.append({
                "code": "p2p_or_outbound_fanout_abuse",
                "title": "高散度出站连接 / 疑似 P2P 扩散",
                "severity": "warning",
                "value": outbound_unique_ips,
                "threshold": 120,
                "reason": (
                    f"同时向 {outbound_unique_ips} 个外部 IP（跨 {outbound_unique_ports} 个端口）建立连接，"
                    f"出站活跃 {outbound_established} 条，UDP Socket {udp_sockets} 个"
                ),
            })

        # Category 4: High socket count + high small-packet flood
        if total_sockets >= 400 and tx_pps >= 1500 and 0 < avg_tx_pkt <= 160:
            categories.append({
                "code": "high_socket_packet_flood",
                "title": "高连接伴随高频小包泛洪",
                "severity": "critical",
                "value": int(round(tx_pps)),
                "threshold": 1500,
                "reason": (
                    f"Socket 总数 {total_sockets} 的同时，出站包速率达 {tx_pps:.0f} pps 且均包长仅 {avg_tx_pkt:.0f} B"
                ),
            })

    investigation = _build_socket_investigation(
        security, inbound_top_ips, outbound_top_ips, outbound_top_ports,
        incoming_established, outbound_established, inbound_established_ips,
        outbound_unique_ips, socks_detected, socks_auth_mode, rx_bps, tx_bps,
    )
    relay_low = int((investigation.get("estimated_independent_sources") or {}).get("low") or 0)
    for category in categories:
        if category.get("code") != "shared_proxy_socks_abuse":
            continue
        if int(investigation.get("relay_ips") or 0) > 0:
            category["reason"] = (
                str(category.get("reason") or "")
                + f"；其中 {investigation.get('relay_ips')} 个来源 IP 属中继网络，估算独立来源网络约 {relay_low} 个"
            )
        if relay_low <= 2 and socks_auth_mode not in ("no_auth", "weak_password"):
            category["severity"] = "warning"

    suspected = len(categories) > 0

    # Build the 4 structured dimensions
    if tcp_syn_sent >= 20:
        dim1_risk = "high"
        dim1_summary = (
            f"主动向外握手未完成 (SYN_SENT) 达 {tcp_syn_sent} 个（覆盖 {max(outbound_syn_sent_ips, outbound_unique_ips)} 个目标 IP），"
            f"存在明显对外扫描或爆破特征"
        )
    elif total_sockets >= 300 and time_wait_ratio >= 0.50:
        dim1_risk = "low"
        dim1_summary = (
            f"TIME_WAIT 短连接回收堆积占比达 {time_wait_ratio * 100:.0f}% ({tcp_time_wait}/{total_sockets})，"
            f"真实并发活跃 ESTABLISHED 仅 {tcp_established} 个（代理转发后等待内核 60s 回收属常见现象）"
        )
    elif tcp_syn_recv >= 30 and tcp_syn_recv > tcp_established:
        dim1_risk = "low"
        dim1_summary = (
            f"入站半连接 SYN_RECV 达 {tcp_syn_recv} 个（来源 {inbound_syn_recv_ips} IP），"
            f"主要为外部互联网被动扫描探测，非容器主动滥用"
        )
    elif tcp_established >= 400:
        dim1_risk = "medium"
        dim1_summary = (
            f"真实并发活跃连接 ESTABLISHED 达 {tcp_established} 个（入站 {incoming_established} / 出站 {outbound_established}），"
            f"TIME_WAIT {tcp_time_wait} 个，UDP {udp_sockets} 个"
        )
    else:
        dim1_risk = "low"
        dim1_summary = (
            f"总计 {total_sockets} (ESTABLISHED {tcp_established} [{established_ratio * 100:.0f}%] · "
            f"TIME_WAIT {tcp_time_wait} [{time_wait_ratio * 100:.0f}%] · SYN_SENT {tcp_syn_sent} · "
            f"SYN_RECV {tcp_syn_recv} · UDP {udp_sockets})"
        )

    top_ip_items = []
    top_inbound_ip_details = []
    for item in inbound_top_ips[:8]:
        if isinstance(item, dict) and item.get("ip"):
            ip_str = str(item.get("ip"))
            est_c = int(item.get("established_connections") or 0)
            tot_c = int(item.get("connections") or 0)
            geo_label = str(item.get("geo_label") or "").strip()
            geo_part = f" [{geo_label}]" if geo_label else ""
            top_ip_items.append(f"{ip_str}{geo_part}(已建连{est_c}/总{tot_c})")
            top_inbound_ip_details.append({
                "ip": ip_str,
                "connections": tot_c,
                "established_connections": est_c,
                "syn_recv_connections": int(item.get("syn_recv_connections") or 0),
                "local_ports": [int(p) for p in (item.get("local_ports") or []) if str(p).isdigit()][:4],
                "network_kind": str(item.get("network_kind") or ""),
                "network_label": str(item.get("network_label") or ""),
                "country": str(item.get("country") or "UN"),
                "country_name": str(item.get("country_name") or ""),
                "region": str(item.get("region") or ""),
                "city": str(item.get("city") or ""),
                "isp": str(item.get("isp") or ""),
                "asn": str(item.get("asn") or ""),
                "geo_label": geo_label,
            })

    top_outbound_ip_items = []
    top_outbound_ip_details = []
    for item in outbound_top_ips[:8]:
        if isinstance(item, dict) and item.get("ip"):
            ip_str = str(item.get("ip"))
            est_c = int(item.get("established_connections") or 0)
            tot_c = int(item.get("connections") or 0)
            ports_list = [int(p) for p in (item.get("ports") or []) if str(p).isdigit()][:4]
            geo_label = str(item.get("geo_label") or "").strip()
            geo_part = f" [{geo_label}]" if geo_label else ""
            port_part = f"·端口{'/'.join(str(p) for p in ports_list)}" if ports_list else ""
            top_outbound_ip_items.append(f"{ip_str}{geo_part}(活跃{est_c}/总{tot_c}{port_part})")
            top_outbound_ip_details.append({
                "ip": ip_str,
                "connections": tot_c,
                "established_connections": est_c,
                "syn_sent_connections": int(item.get("syn_sent_connections") or 0),
                "ports": ports_list,
                "country": str(item.get("country") or "UN"),
                "country_name": str(item.get("country_name") or ""),
                "region": str(item.get("region") or ""),
                "city": str(item.get("city") or ""),
                "isp": str(item.get("isp") or ""),
                "asn": str(item.get("asn") or ""),
                "geo_label": geo_label,
            })

    if socks_detected and (inbound_established_ips >= 6 or socks_auth_mode in ("no_auth", "weak_password")):
        dim2_risk = "high"
        dim2_summary = (
            f"已识别 SOCKS5 服务（认证：{socks_auth_mode}），且有 {inbound_established_ips} 个公网 IP 保持真实已建立连接"
            f"（入站活跃 {incoming_established} 条），高度疑似多人共享或公共代理滥用"
        )
    elif inbound_established_ips >= 10:
        dim2_risk = "high" if (incoming_established >= 50 or outbound_established >= 50) else "medium"
        dim2_summary = (
            f"真实已建立 TCP 连接的公网来源达 {inbound_established_ips} 个 IP（已过滤 {inbound_syn_recv_ips} 个仅 SYN 探测 IP），"
            f"入站活跃连接 {incoming_established} 条，超出单容器 10 IP 正常并发基线"
        )
    elif inbound_established_ips <= 5 and total_sockets >= 400:
        dim2_risk = "low"
        dim2_summary = (
            f"虽然总 Socket 达 {total_sockets}，但真实已建连入站来源仅 {inbound_established_ips} 个公网 IP"
            f"（入站活跃 {incoming_established} 条），属少数客户端高频并发复用（如单人代理加载网页/分片流媒体），非多人共享机场"
        )
    else:
        dim2_risk = "low"
        dim2_summary = (
            f"真实已建连入站来源 {inbound_established_ips} 个公网 IP（入站活跃 {incoming_established} 条，"
            f"未完成握手探测 {inbound_syn_recv_ips} 个 IP），处于正常范围"
        )

    proc_labels = [
        f"{p['process']}(PID {p['pid']}, 入{p['inbound_connections']}/出{p['outbound_connections']})"
        for p in top_procs[:3]
    ]
    top_port_labels = [
        f"{p['port']}{'/' + p['service'] if p.get('service') else ''}({p['connections']}条/{p['unique_ips']}IP)"
        for p in outbound_top_ports[:5]
        if isinstance(p, dict)
    ]

    if high_risk_ports_hit or (suspicious_outbound >= 5 and has_socket_evidence):
        dim3_risk = "high"
        dim3_summary = (
            f"检测到异常高危敏感端口出站：{', '.join(high_risk_ports_hit[:4]) or f'{suspicious_outbound} 条连接'}；"
            f"出站活跃 {outbound_established} 条 / 目标 {outbound_unique_ips} IP"
            + (f"；主通信进程 {', '.join(proc_labels)}" if proc_labels else "")
        )
    elif outbound_unique_ips >= 120:
        dim3_risk = "high" if (udp_sockets >= 100 or outbound_unique_ports >= 60) else "medium"
        dim3_summary = (
            f"同时连接 {outbound_unique_ips} 个外部目标 IP（跨 {outbound_unique_ports} 个端口），"
            f"出站活跃 {outbound_established} 条，散度较高"
            + (f"；主通信进程 {', '.join(proc_labels)}" if proc_labels else "")
        )
    else:
        dim3_risk = "low"
        dim3_summary = (
            f"出站活跃 {outbound_established} 条 · 外部目标 {outbound_unique_ips} IP / {outbound_unique_ports} 端口 · "
            f"敏感端口连接 {suspicious_outbound} 条"
            + (f" · 常连端口 {', '.join(top_port_labels[:3])}" if top_port_labels else "")
            + (f" · 主进程 {', '.join(proc_labels[:2])}" if proc_labels else "")
        )

    if tx_pps >= 1500 and 0 < avg_tx_pkt <= 160:
        dim4_risk = "high"
        dim4_summary = (
            f"出站包速率达 {tx_pps:.0f} pps 且平均包长仅 {avg_tx_pkt:.0f} B（出站 {_fmt_rate_bps(tx_bps)}），"
            f"呈现典型高频小包探测/泛洪特征"
        )
    elif tx_pps >= 800 and avg_tx_pkt >= 500:
        dim4_risk = "low"
        dim4_summary = (
            f"出站 {_fmt_rate_bps(tx_bps)} ({tx_pps:.0f} pps · 均包长 {avg_tx_pkt:.0f} B) · "
            f"入站 {_fmt_rate_bps(rx_bps)} ({rx_pps:.0f} pps)，属正常大包吞吐传输"
        )
    else:
        dim4_risk = "low"
        dim4_summary = (
            f"出站 {_fmt_rate_bps(tx_bps)} ({tx_pps:.0f} pps"
            + (f" · 均包长 {avg_tx_pkt:.0f} B" if avg_tx_pkt > 0 else "")
            + f") · 入站 {_fmt_rate_bps(rx_bps)} ({rx_pps:.0f} pps)，未见高频小包泛洪"
        )

    dimensions = [
        {
            "key": "state_breakdown",
            "title": "1. 连接状态拆解 (TCP States & UDP)",
            "risk": dim1_risk,
            "summary": dim1_summary,
            "metrics": {
                "total": total_sockets,
                "tcp_established": tcp_established,
                "tcp_time_wait": tcp_time_wait,
                "tcp_syn_sent": tcp_syn_sent,
                "tcp_syn_recv": tcp_syn_recv,
                "tcp_close_wait": tcp_close_wait,
                "tcp_fin_wait": tcp_fin_wait,
                "udp_sockets": udp_sockets,
                "time_wait_ratio": time_wait_ratio,
                "established_ratio": established_ratio,
            },
        },
        {
            "key": "inbound_fanout",
            "title": "2. 入站并发业务源 (排除未建连扫描)",
            "risk": dim2_risk,
            "summary": dim2_summary,
            "metrics": {
                "inbound_established_unique_ips": inbound_established_ips,
                "inbound_syn_recv_unique_ips": inbound_syn_recv_ips,
                "inbound_unique_ips": inbound_unique_ips,
                "incoming_established": incoming_established,
                "socks_detected": socks_detected,
                "socks_auth_mode": socks_auth_mode,
                "hy2_detected": hy2_detected,
                "top_ips": top_ip_items,
                "top_ip_details": top_inbound_ip_details,
                "listening_ports": listening_ports,
            },
        },
        {
            "key": "outbound_profile",
            "title": "3. 出站目标与进程画像 (端口/散度/归属)",
            "risk": dim3_risk,
            "summary": dim3_summary,
            "metrics": {
                "outbound_established": outbound_established,
                "outbound_unique_ips": outbound_unique_ips,
                "outbound_unique_ports": outbound_unique_ports,
                "outbound_syn_sent_unique_ips": outbound_syn_sent_ips,
                "suspicious_outbound_connections": suspicious_outbound,
                "sensitive_ports": sensitive_outbound_ports[:8],
                "top_ports": outbound_top_ports[:6],
                "top_processes": top_procs,
                "top_outbound_ips": top_outbound_ip_items,
                "top_ip_details": top_outbound_ip_details,
            },
        },
        {
            "key": "traffic_profile",
            "title": "4. 包速率与带宽特征 (PPS & 均包长)",
            "risk": dim4_risk,
            "summary": dim4_summary,
            "metrics": {
                "rx_bps": round(rx_bps, 1),
                "tx_bps": round(tx_bps, 1),
                "rx_pps": round(rx_pps, 1),
                "tx_pps": round(tx_pps, 1),
                "avg_tx_packet_size": avg_tx_pkt,
            },
        },
    ]

    if suspected:
        verdict = "suspected_abuse"
        cat_titles = [str(c["title"]) for c in categories]
        severity = "critical" if any(c.get("severity") == "critical" for c in categories) else "warning"
        verdict_label = f"疑似滥用 · 待人工复核 ({' / '.join(cat_titles)})"
        conclusion = (
            f"综合四维判断：命中【{'、'.join(cat_titles)}】特征；"
            + "；".join(str(c["reason"]) for c in categories)
            + "。（当前为人工核验观察模式，未执行自动停机或自动封禁）"
        )
        primary_value = int(max((int(c.get("value") or 0) for c in categories), default=total_sockets))
        primary_threshold = int(categories[0].get("threshold") or 1)
    elif total_sockets >= 400:
        verdict = "benign_high_sockets"
        severity = "info"
        verdict_label = "倾向非滥用 · 正常业务/连接回收堆积"
        reasons_benign = []
        if time_wait_ratio >= 0.50:
            reasons_benign.append(f"TIME_WAIT 短连接回收占比达 {time_wait_ratio * 100:.0f}% ({tcp_time_wait}/{total_sockets})，真实活跃 ESTABLISHED 仅 {tcp_established} 个")
        if inbound_established_ips <= 5:
            reasons_benign.append(f"入站真实已建连来源仅 {inbound_established_ips} 个公网 IP（属单用户/少数客户端高频并发复用，非多人共享）")
        if tcp_syn_sent < 20 and suspicious_outbound < 5 and not high_risk_ports_hit:
            reasons_benign.append(f"无对外端口扫描 (SYN_SENT {tcp_syn_sent}) 与高危端口爆破 (敏感连接 {suspicious_outbound})")
        conclusion = (
            "综合四维判断：倾向非滥用（"
            + ("；".join(reasons_benign) if reasons_benign else f"ESTABLISHED {tcp_established} / TIME_WAIT {tcp_time_wait} / 入站已建连 {inbound_established_ips} IP")
            + "）。单凭 Socket 总数高不判定为违规。"
        )
        primary_value = total_sockets
        primary_threshold = 500
    else:
        verdict = "normal"
        severity = "info"
        verdict_label = "正常连接分布"
        conclusion = (
            f"综合四维判断：未发现 Socket 或代理连接滥用特征"
            f"（总计 {total_sockets}，ESTABLISHED {tcp_established}，入站已建连 {inbound_established_ips} IP）。"
        )
        primary_value = total_sockets
        primary_threshold = 500

    judgment_basis = [
        f"【结论】{verdict_label} —— {conclusion}",
        f"【维度① 状态拆解】总计 {total_sockets}｜ESTABLISHED {tcp_established} ({established_ratio * 100:.0f}%) · TIME_WAIT {tcp_time_wait} ({time_wait_ratio * 100:.0f}%) · SYN_SENT {tcp_syn_sent} · SYN_RECV {tcp_syn_recv} · CLOSE_WAIT {tcp_close_wait} · UDP {udp_sockets}",
        f"【维度② 入站并发源】真实已建连 {inbound_established_ips} 个公网 IP（入站活跃 {incoming_established} 条，未完成握手 SYN_RECV {inbound_syn_recv_ips} IP）"
        + (f"｜SOCKS5 已识别 (认证: {socks_auth_mode})" if socks_detected else "")
        + (f"｜Top 来源: {', '.join(top_ip_items[:4])}" if top_ip_items else ""),
        f"【维度③ 出站与进程】出站活跃 {outbound_established} 条 · 外部目标 {outbound_unique_ips} IP / {outbound_unique_ports} 端口 · 敏感端口连接 {suspicious_outbound} 条"
        + (f" ({', '.join(high_risk_ports_hit[:3])})" if high_risk_ports_hit else "")
        + (f"｜常连端口: {', '.join(top_port_labels[:4])}" if top_port_labels else "")
        + (f"｜Top 出站目标: {', '.join(top_outbound_ip_items[:3])}" if top_outbound_ip_items else "")
        + (f"｜主进程: {', '.join(proc_labels[:2])}" if proc_labels else ""),
        f"【维度④ 包速率与带宽】出站 {_fmt_rate_bps(tx_bps)} ({tx_pps:.0f} pps"
        + (f" · 均包长 {avg_tx_pkt:.0f} B" if avg_tx_pkt > 0 else "")
        + f") · 入站 {_fmt_rate_bps(rx_bps)} ({rx_pps:.0f} pps)",
    ]

    compact_basis_text = (
        f"【四维判断依据】结论：{verdict_label}｜"
        f"①状态拆解：总计 {total_sockets} (ESTABLISHED {tcp_established} [{established_ratio * 100:.0f}%] · "
        f"TIME_WAIT {tcp_time_wait} [{time_wait_ratio * 100:.0f}%] · SYN_SENT {tcp_syn_sent} · "
        f"SYN_RECV {tcp_syn_recv} · UDP {udp_sockets})｜"
        f"②入站并发源：真实已建连 {inbound_established_ips} 个公网 IP (入站活跃 {incoming_established} 条"
        + (f"，SOCKS5[{socks_auth_mode}]" if socks_detected else "")
        + f")｜③出站与进程：出站活跃 {outbound_established} 条 / 目标 {outbound_unique_ips} IP / 敏感端口 {suspicious_outbound} 条"
        + (f" [{', '.join(high_risk_ports_hit[:2])}]" if high_risk_ports_hit else "")
        + (f" (主进程 {top_procs[0]['process']})" if top_procs else "")
        + f"｜④包速率：出栈 {tx_pps:.0f} pps"
        + (f" (均包长 {avg_tx_pkt:.0f} B)" if avg_tx_pkt > 0 else "")
        + f" / 入栈 {rx_pps:.0f} pps。"
    )

    existing_eval = security.get("socket_abuse") if isinstance(security.get("socket_abuse"), dict) else {}
    evaluated_at = int(existing_eval.get("evaluated_at") or cm.get("observed_at") or 0)
    if evaluated_at <= 0:
        try:
            evaluated_at = int(time.time())
        except StopIteration:
            evaluated_at = 0
    return {
        "schema": 1,
        "evaluated_at": evaluated_at,
        "valid_evidence": has_socket_evidence,
        "suspected": suspected,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "severity": severity,
        "conclusion": conclusion,
        "primary_value": primary_value,
        "primary_threshold": primary_threshold,
        "categories": categories,
        "dimensions": dimensions,
        "investigation": investigation,
        "judgment_basis": judgment_basis,
        "compact_basis_text": compact_basis_text,
    }


