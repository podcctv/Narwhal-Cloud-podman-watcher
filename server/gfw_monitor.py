"""Correlate domestic and overseas TCP probes for conservative GFW reachability history."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request

MAX_TARGETS = 8
DAILY_CONTAINER_SAMPLE_LIMIT = 2
MIN_MAINLAND = 2
MIN_OVERSEAS = 1
CYCLE_SECONDS = 300
STALE_SECONDS = 900
SOURCE_NETWORK_STALE_SECONDS = 7 * 86400
JOB_SECONDS = 600
MAX_ACTIVE_CYCLES = 30
PROBE_RESULT_ERROR_CODES = {"", "timeout", "refused", "network_error", "family_unsupported", "no_route", "host_unreachable", "local_policy_block"}
PROBE_CAPABILITY_STALE_SECONDS = 900
PROBE_FAILURE_CODES = {
    "probe_source_identity_mismatch", "invalid_probe_identity", "invalid_probe_lease",
    "invalid_probe_deadline", "invalid_target_count", "invalid_target_fields",
    "invalid_target_endpoint", "invalid_target_identity", "invalid_targets_hash",
    "incomplete_probe_results", "probe_runtime_unavailable", "probe_worker_busy", "probe_worker_error",
}
PROBE_FAILURE_LABELS = {
    "probe_source_identity_mismatch": "探针身份不匹配",
    "invalid_probe_identity": "探针任务身份校验失败",
    "invalid_probe_lease": "探针任务授权校验失败",
    "invalid_probe_deadline": "探针任务已过期",
    "invalid_target_count": "目标端口数量不符合限制",
    "invalid_target_fields": "目标字段校验失败",
    "invalid_target_endpoint": "目标地址校验失败",
    "invalid_target_identity": "目标身份校验失败",
    "invalid_targets_hash": "目标清单校验失败",
    "incomplete_probe_results": "探测结果不完整",
    "probe_runtime_unavailable": "探针未运行在宿主机网络环境",
    "probe_worker_busy": "探针已有任务执行中",
    "probe_worker_error": "探针执行异常",
    "probe deadline elapsed": "任务超时",
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _utc_sample_date(now):
    return datetime.fromtimestamp(int(now), timezone.utc).date()


def _same_day_sample(conn, host_id, now):
    day_start = int(datetime.fromtimestamp(int(now), timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    rows = conn.execute(
        "SELECT result_json FROM gfw_cycles WHERE host_id=? AND created_at>=? ORDER BY created_at,id LIMIT 400",
        (host_id, day_start),
    ).fetchall()
    for row in rows:
        try:
            result = json.loads(row["result_json"] or "{}")
            sample = result.get("sample", {}) if isinstance(result, dict) else {}
            if isinstance(sample, dict) and sample.get("policy") == "daily_container_rotation":
                return sample
        except (TypeError, ValueError):
            continue
    return {}


def _blocked_endpoint_keys(evidence_json):
    try:
        evidence = json.loads(evidence_json or "{}")
        return {
            (str(item[0]), int(item[1])) for item in evidence.get("blocked_endpoint_keys", [])
            if isinstance(item, (list, tuple)) and len(item) == 2 and 1 <= int(item[1]) <= 65535
        }
    except (TypeError, ValueError, AttributeError):
        return set()


def _public_address(value):
    try:
        addr = ipaddress.ip_address(str(value).split("/", 1)[0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return str(addr) if addr.is_global and not addr.is_multicast else ""
    except (TypeError, ValueError):
        return ""


def _public_network_id(value):
    """Group a verified probe source by its routed public network prefix."""
    try:
        address = ipaddress.ip_address(str(value).strip())
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global or address.is_multicast:
            return ""
        prefix = 24 if address.version == 4 else 48
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except (TypeError, ValueError):
        return ""


def _trusted_proxy_peer(request):
    """Require both the installer-generated proxy token and its exact bridge peer."""
    headers = getattr(request, "headers", {})
    expected_token = str(os.environ.get("NARWHAL_PROXY_TRUST_TOKEN") or "")
    supplied_token = str(headers.get("x-narwhal-proxy-token") or "")
    if not expected_token or not supplied_token or not secrets.compare_digest(expected_token, supplied_token):
        return False

    client = getattr(request, "client", None)
    peer = str(getattr(client, "host", "") or "").strip()
    try:
        peer_address = ipaddress.ip_address(peer)
        if isinstance(peer_address, ipaddress.IPv6Address) and peer_address.ipv4_mapped:
            peer_address = peer_address.ipv4_mapped
    except ValueError:
        return False

    configured = str(os.environ.get("NARWHAL_TRUSTED_PROXY_CIDRS") or "")
    for value in re.split(r"[,;\s]+", configured):
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if peer_address.version == network.version and peer_address in network:
            return True
    return False


def _ip_is_in_networks(value, configured):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
    except ValueError:
        return False
    for item in re.split(r"[,;\s]+", str(configured or "")):
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _request_source_network(request):
    """Use a direct public peer or an authenticated Caddy peer verified by Cloudflare ranges."""
    client = getattr(request, "client", None)
    peer = str(getattr(client, "host", "") or "").strip()
    direct_network = _public_network_id(peer)
    if direct_network:
        return direct_network

    # Caddy overwrites its internal peer/token headers. They are accepted only
    # when the request came from a configured Podman gateway. A CF-Connecting-IP
    # value is trusted only when Caddy's actual peer is in the official CF ranges.
    if not _trusted_proxy_peer(request):
        return ""
    headers = getattr(request, "headers", {})
    proxy_peer = str(headers.get("x-narwhal-proxy-peer") or "").strip()
    cf_client_ip = str(headers.get("cf-connecting-ip") or "").strip()
    cloudflare_ranges = os.environ.get("NARWHAL_CLOUDFLARE_CIDRS", "")
    if _ip_is_in_networks(proxy_peer, cloudflare_ranges):
        return _public_network_id(cf_client_ip)
    # If CF ranges could not be verified, do not count a forwarded CF header or
    # the apparent edge address as a probe network. Keep the sample unknown.
    if cf_client_ip and not cloudflare_ranges.strip():
        return ""
    return _public_network_id(proxy_peer)


def _probe_online(last_seen, payload, now):
    try:
        interval = int(json.loads(payload or "{}").get("report_interval", 300))
    except (ValueError, TypeError, AttributeError):
        interval = 300
    return now - int(last_seen or 0) <= max(600, min(1800, interval * 3))


def _fresh_source_network(row, now):
    updated_at = int(row["source_network_updated_at"] or 0)
    network_id = str(row["source_network_id"] or "").strip()
    if not network_id or not 0 < updated_at <= now or now - updated_at > SOURCE_NETWORK_STALE_SECONDS:
        return "", 0
    return network_id[:64], updated_at


def _fresh_route_capability(row, column, now):
    updated_at = int(row["route_capabilities_updated_at"] or 0)
    if not 0 < updated_at <= now or now - updated_at > PROBE_CAPABILITY_STALE_SECONDS:
        return None
    value = row[column]
    return bool(value) if value in (0, 1) else None


def _probe_health_snapshot(conn, now):
    rows = conn.execute(
        "SELECT r.host_id,r.node_id,r.role,r.region,r.carrier,r.source_network_id,r.source_network_updated_at,"
        "r.ipv4_default_route,r.ipv6_default_route,r.route_capabilities_updated_at,h.last_seen,o.payload "
        "FROM gfw_probe_roles r LEFT JOIN hosts h ON h.node_id=r.node_id "
        "LEFT JOIN ops_hosts o ON o.node=h.node_id ORDER BY r.role,r.host_id"
    ).fetchall()
    sources = []
    counts = {
        role: {"configured": 0, "online": 0, "offline": 0, "missing_region": 0,
               "missing_carrier": 0, "online_missing_region": 0, "online_missing_carrier": 0,
               "distinct_regions": 0, "distinct_carriers": 0, "distinct_networks": 0,
               "online_missing_network_identity": 0}
        for role in ("mainland", "overseas")
    }
    for row in rows:
        role = str(row["role"] or "")
        if role not in counts:
            continue
        last_seen = int(row["last_seen"] or 0)
        online = _probe_online(last_seen, row["payload"], now)
        region = str(row["region"] or "").strip()
        carrier = str(row["carrier"] or "").strip()
        network_id, network_updated_at = _fresh_source_network(row, now)
        ipv4_route = _fresh_route_capability(row, "ipv4_default_route", now)
        ipv6_route = _fresh_route_capability(row, "ipv6_default_route", now)
        stats = counts[role]
        stats["configured"] += 1
        stats["online" if online else "offline"] += 1
        if not region:
            stats["missing_region"] += 1
            if online:
                stats["online_missing_region"] += 1
        if role == "mainland" and not carrier:
            stats["missing_carrier"] += 1
            if online:
                stats["online_missing_carrier"] += 1
        if online and not network_id:
            stats["online_missing_network_identity"] += 1
        for family, route in (("ipv4", ipv4_route), ("ipv6", ipv6_route)):
            supported_key = f"online_{family}_default_route"
            unknown_key = f"online_{family}_route_unknown"
            missing_key = f"online_{family}_no_default_route"
            stats.setdefault(supported_key, 0)
            stats.setdefault(unknown_key, 0)
            stats.setdefault(missing_key, 0)
            if online and route is True:
                stats[supported_key] += 1
            elif online and route is None:
                stats[unknown_key] += 1
            elif online:
                stats[missing_key] += 1
        sources.append({
            "host_id": str(row["host_id"] or ""), "node_id": str(row["node_id"] or ""),
            "role": role, "region": region, "carrier": carrier,
            "network_id": network_id,
            "network_identity_updated_at": network_updated_at if network_id else 0,
            "ipv4_default_route": ipv4_route,
            "ipv6_default_route": ipv6_route,
            "route_capabilities_updated_at": int(row["route_capabilities_updated_at"] or 0),
            "last_seen": last_seen,
            "last_seen_age_seconds": max(0, now - last_seen) if last_seen else None,
            "online": online,
        })
    for role in counts:
        role_sources = [item for item in sources if item["role"] == role and item["online"]]
        counts[role]["distinct_regions"] = len({item["region"].casefold() for item in role_sources if item["region"]})
        counts[role]["distinct_carriers"] = len({item["carrier"].casefold() for item in role_sources if item["carrier"]})
        counts[role]["distinct_networks"] = len({item["network_id"] for item in role_sources if item["network_id"]})
    return {"roles": counts, "sources": sources}


def _latest_role_result(conn, role):
    """Return the latest completed per-endpoint probe result for an admin view."""
    row = conn.execute(
        """SELECT j.id,j.status,j.created_at,j.finished_at,j.error,j.source_host_id,
                  j.source_region,j.source_carrier,j.source_network_id,c.host_id AS target_host_id,
                  c.node_id AS target_node_id,j.targets_json
           FROM gfw_probe_jobs j JOIN gfw_cycles c ON c.id=j.cycle_id
           WHERE j.role=? AND j.status IN ('complete','failed','expired')
           ORDER BY COALESCE(NULLIF(j.finished_at,0),j.created_at) DESC,j.id DESC LIMIT 1""",
        (role,),
    ).fetchone()
    if row is None:
        return None
    try:
        targets = json.loads(row["targets_json"] or "[]")
    except (TypeError, ValueError):
        targets = []
    results = {
        str(result["target_id"]): dict(result)
        for result in conn.execute(
            "SELECT target_id,success,latency_ms,error,attempts FROM gfw_probe_results WHERE job_id=?",
            (row["id"],),
        ).fetchall()
    }
    endpoints = []
    for target in targets[:MAX_TARGETS] if isinstance(targets, list) else []:
        if not isinstance(target, dict):
            continue
        try:
            port = int(target.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        result = results.get(str(target.get("id") or ""))
        endpoints.append({
            "ip": str(target.get("ip") or "")[:64],
            "port": port,
            "success": bool(result["success"]) if result else None,
            "latency_ms": result.get("latency_ms") if result else None,
            "error": str((result.get("error") if result else row["error"]) or "")[:160],
            "attempts": int(result.get("attempts") or 0) if result else 0,
        })
    return {
        "status": str(row["status"] or "unknown"),
        "created_at": int(row["created_at"] or 0),
        "finished_at": int(row["finished_at"] or 0),
        "source_host_id": str(row["source_host_id"] or "")[:200],
        "source_region": str(row["source_region"] or "")[:80],
        "source_carrier": str(row["source_carrier"] or "")[:100],
        "source_network_id": str(row["source_network_id"] or "")[:64],
        "target_host_id": str(row["target_host_id"] or "")[:200],
        "target_node_id": str(row["target_node_id"] or "")[:128],
        "error": str(row["error"] or "")[:240],
        "endpoints": endpoints,
    }


def _listen_endpoint(item):
    """Return (bind address, TCP port) only for an explicit TCP mapping."""
    if not isinstance(item, dict):
        return "", 0
    source = str(item.get("source") or "")
    if source == "incus-proxy" and str(item.get("protocol") or "tcp").lower() != "tcp":
        return "", 0
    listen = str(item.get("listen") or "").strip()
    if source == "podman-publish":
        target = str(item.get("target") or "").lower()
        if not target.endswith("/tcp"):
            return "", 0
    elif source in {"incus-proxy", "incus-forward", "host-dnat"}:
        target = str(item.get("target") or "").lower()
        if listen.lower().startswith("udp:") or target.startswith("udp:"):
            return "", 0
        # Incus network-forward records carry the protocol on both endpoints.
        # Do not silently accept an untyped or non-TCP forward as a TCP probe.
        if source in {"incus-forward", "host-dnat"} and (not listen.lower().startswith("tcp:") or not target.startswith("tcp:")):
            return "", 0
        if listen.lower().startswith("tcp:"):
            listen = listen[4:]
    else:
        return "", 0
    host, separator, port_text = listen.rpartition(":")
    if not separator or not host or not re.fullmatch(r"\d{1,5}", port_text):
        return "", 0
    address = host.strip()
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    if ":" in address:
        try:
            if ipaddress.ip_address(address).version != 6:
                return "", 0
        except ValueError:
            return "", 0
    try:
        port = int(port_text)
    except ValueError:
        return "", 0
    if not 1 <= port <= 65535:
        return "", 0
    return address, port


def _target_listener_port(item):
    """Return the container-side TCP port for a confirmed mapping source."""
    if not isinstance(item, dict):
        return 0
    source = str(item.get("source") or "")
    target = str(item.get("target") or "").strip()
    if source == "incus-proxy" and str(item.get("protocol") or "tcp").lower() != "tcp":
        return 0
    if source == "podman-publish":
        match = re.fullmatch(r"(\d{1,5})/tcp", target.lower())
        value = match.group(1) if match else ""
    elif source in {"incus-proxy", "incus-forward", "host-dnat"}:
        if target.lower().startswith("tcp:"):
            target = target[4:]
        elif target.lower().startswith("udp:"):
            return 0
        target_host, separator, value = target.rpartition(":")
        if not separator or not target_host:
            value = ""
    else:
        return 0
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65535 else 0


def _tcp_listener_bindings(security):
    bindings = {}
    endpoints = security.get("listening_endpoints", []) if isinstance(security, dict) else []
    for value in endpoints[:128] if isinstance(endpoints, list) else []:
        host, separator, port_text = str(value or "").rpartition(":")
        if not separator or not re.fullmatch(r"\d{1,5}", port_text):
            continue
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            address = ipaddress.ip_address(host)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            port = int(port_text)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            bindings.setdefault(port, set()).add(str(address))
    return bindings


def _mapped_target_addresses(item, container_addresses):
    source = str(item.get("source") or "") if isinstance(item, dict) else ""
    if source == "podman-publish":
        raw_values = container_addresses if isinstance(container_addresses, list) else []
    else:
        target = str(item.get("target") or "").strip() if isinstance(item, dict) else ""
        if target.lower().startswith(("tcp:", "udp:")):
            target = target.split(":", 1)[1]
        host, separator, _port = target.rpartition(":")
        if not separator:
            return set()
        host = host.strip()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if host.lower() == "localhost":
            return {"127.0.0.1", "::1"}
        raw_values = [host]
    result = set()
    for value in raw_values[:32]:
        try:
            address = ipaddress.ip_address(str(value).split("/", 1)[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if not address.is_unspecified and not address.is_multicast:
                result.add(str(address))
        except (TypeError, ValueError):
            continue
    return result


def _listener_reaches_targets(bindings, port, target_addresses):
    targets = set()
    for value in target_addresses:
        try:
            targets.add(ipaddress.ip_address(value))
        except (TypeError, ValueError):
            continue
    for value in bindings.get(port, set()):
        try:
            listener = ipaddress.ip_address(value)
        except (TypeError, ValueError):
            continue
        if listener in targets:
            return True
        if listener == ipaddress.ip_address("0.0.0.0") and any(address.version == 4 for address in targets):
            return True
        if listener == ipaddress.ip_address("::") and any(address.version == 6 for address in targets):
            return True
    return False


def _targets_for_host(conn, host_id, node_id, now, pinned_endpoint_keys=None, daily_selection=None,
                      probe_families=None, family_coverage=None):
    pinned_endpoint_keys = set(pinned_endpoint_keys or ())
    daily_selection = daily_selection if isinstance(daily_selection, dict) else {}
    family_coverage = family_coverage if isinstance(family_coverage, dict) else {}
    supported_families = set(probe_families) if probe_families is not None else {"ipv4", "ipv6"}
    host_sample = conn.execute(
        "SELECT payload_json,ts FROM host_security WHERE host_id=? ORDER BY ts DESC,id DESC LIMIT 1", (host_id,)
    ).fetchone()
    inventory_reason = ""
    if not host_sample or now - int(host_sample["ts"] or 0) > STALE_SECONDS:
        inventory_reason = "宿主机网卡采样已过期"
    try:
        payload = json.loads(host_sample["payload_json"] or "{}") if host_sample else {}
        inventory = payload.get("host_firewall", {}).get("interface_inventory", {})
    except (TypeError, ValueError, AttributeError):
        inventory = {}
    if not isinstance(inventory, dict) or inventory.get("status") != "ready":
        inventory_reason = inventory_reason or "尚未收到可用的网卡地址清单"
        inventory = {}
    addresses, interface_by_ip = [], {}
    for interface in inventory.get("interfaces", [])[:64] if isinstance(inventory.get("interfaces"), list) else []:
        if not isinstance(interface, dict):
            continue
        name = str(interface.get("name") or "")[:32]
        for raw in interface.get("addresses", [])[:16] if isinstance(interface.get("addresses"), list) else []:
            address = _public_address(raw)
            if address:
                interface_by_ip[address] = name
                if address not in addresses:
                    addresses.append(address)
    latest = conn.execute(
        "SELECT runtime,project,container_name,payload_json,ts FROM reports WHERE host_id=? AND runtime IN ('incus','podman') AND ts>=? ORDER BY ts DESC,id DESC LIMIT 1200",
        (host_id, now - STALE_SECONDS),
    ).fetchall()
    newest, discovered = set(), {}
    socket_owners = {}
    has_public_container_ip = False
    discovery = {
        "direct_public_listener": 0,
        "direct_listener_address_unverified": 0,
        "podman_publish": 0,
        "incus_proxy": 0,
        "incus_forward": 0,
        "host_dnat": 0,
        "mapping_target_not_listening": 0,
        "mapping_listener_address_unverified": 0,
        "mapping_target_unknown": 0,
        "mapping_without_host_public_ip": 0,
        "ambiguous_sockets": 0,
    }

    def add_endpoint(address, port, interface, container, source, container_port):
        target = {"ip": address, "port": port, "interface": interface}
        target_id = _digest({"host_id": host_id, **target})[:24]
        endpoint = discovered.setdefault(target_id, {"id": target_id, **target, "owners": {}, "sources": [], "container_ports": []})
        endpoint["owners"][container["key"]] = container
        if source and source not in endpoint["sources"]:
            endpoint["sources"].append(source)
        if container_port and container_port not in endpoint["container_ports"]:
            endpoint["container_ports"].append(container_port)
        socket_owners.setdefault((address, port), set()).add(container["key"])

    for row in latest:
        key = (row["runtime"], row["project"], row["container_name"])
        if key in newest:
            continue
        newest.add(key)
        try:
            report = json.loads(row["payload_json"] or "{}")
            security = report.get("security", {})
        except (TypeError, ValueError, AttributeError):
            continue
        if not isinstance(report, dict):
            continue
        container_id = str(report.get("id") or report.get("container_id") or "")[:255]
        container = {
            "key": f"{row['runtime']}|{row['project']}|{container_id or row['container_name']}",
            "runtime": str(row["runtime"] or "")[:32],
            "project": str(row["project"] or "")[:255],
            "name": str(row["container_name"] or "")[:255],
            "container_id": container_id,
        }
        # A container with a directly assigned public address and a live TCP
        # listener is independently probeable, including routed/macvlan setups
        # that do not use a host-side proxy or published port.
        container_addresses = report.get("network_addresses", [])
        listening_ports = security.get("listening_ports", []) if isinstance(security, dict) else []
        public_container_ips = set()
        for value in container_addresses[:32] if isinstance(container_addresses, list) else []:
            ip = _public_address(value) if isinstance(value, str) else ""
            if ip:
                public_container_ips.add(ip)
        public_container_ips = sorted(public_container_ips)
        has_public_container_ip = has_public_container_ip or bool(public_container_ips)
        valid_ports = set()
        for value in listening_ports[:128] if isinstance(listening_ports, list) else []:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                valid_ports.add(port)
        listener_bindings = _tcp_listener_bindings(security)
        for ip in public_container_ips:
            for port in valid_ports:
                if not _listener_reaches_targets(listener_bindings, port, {ip}):
                    discovery["direct_listener_address_unverified"] += 1
                    continue
                add_endpoint(ip, port, "container", container, "direct-public-listener", port)
                discovery["direct_public_listener"] += 1
        exposures = security.get("network_exposure", []) if isinstance(security, dict) else []
        for exposure in exposures[:128] if isinstance(exposures, list) else []:
            bind, port = _listen_endpoint(exposure)
            if not port:
                continue
            target_port = _target_listener_port(exposure)
            if not target_port:
                discovery["mapping_target_unknown"] += 1
                continue
            if target_port not in valid_ports:
                discovery["mapping_target_not_listening"] += 1
                continue
            mapped_addresses = _mapped_target_addresses(exposure, container_addresses)
            if not mapped_addresses or not _listener_reaches_targets(listener_bindings, target_port, mapped_addresses):
                discovery["mapping_listener_address_unverified"] += 1
                continue
            source = str(exposure.get("source") or "")
            if source in {"podman-publish", "incus-proxy", "incus-forward", "host-dnat"}:
                discovery[source.replace("-", "_")] = discovery.get(source.replace("-", "_"), 0) + 1
            explicit = _public_address(bind)
            if explicit:
                target_ips = [explicit] if explicit in addresses else []
            elif bind in ("", "*"):
                target_ips = addresses
            elif bind == "0.0.0.0":
                target_ips = [address for address in addresses if ipaddress.ip_address(address).version == 4]
            elif bind in ("::", "::0"):
                target_ips = [address for address in addresses if ipaddress.ip_address(address).version == 6]
            else:
                target_ips = []
            if not target_ips:
                discovery["mapping_without_host_public_ip"] += 1
            for ip in target_ips:
                add_endpoint(ip, port, interface_by_ip.get(ip, ""), container, source, target_port)

    # Public endpoints must map to one unambiguous Incus/Podman container before
    # they can participate in a per-container sample.
    containers = {}
    eligible_endpoint_count = 0
    seen_sockets = set()
    for endpoint in discovered.values():
        socket = (endpoint["ip"], endpoint["port"])
        if socket in seen_sockets or len(socket_owners.get(socket, set())) != 1:
            if len(socket_owners.get(socket, set())) > 1:
                discovery["ambiguous_sockets"] += 1
            continue
        owners = endpoint.pop("owners", {})
        if len(owners) != 1:
            continue
        seen_sockets.add(socket)
        container = next(iter(owners.values()))
        container_key = container["key"]
        containers.setdefault(container_key, {"container": container, "targets": []})["targets"].append(endpoint)
        eligible_endpoint_count += 1

    sample_date = _utc_sample_date(now).isoformat()
    sample = {
        "policy": "daily_container_rotation",
        "date_utc": sample_date,
        "eligible_containers": len(containers),
        "sampled_containers": 0,
        "eligible_endpoints": eligible_endpoint_count,
        "sampled_endpoints": 0,
        "discovered_endpoints": len(discovered),
        "ambiguous_endpoints": sum(1 for owners in socket_owners.values() if len(owners) > 1),
        "discovery": discovery,
        "containers": [],
        "probe_family_coverage": family_coverage,
    }
    family_endpoint_counts = {"ipv4": 0, "ipv6": 0}
    probeable_containers = {}
    unprobeable_by_family = {"ipv4": 0, "ipv6": 0}
    for container_key, group in containers.items():
        usable_targets = []
        for target in group["targets"]:
            family = "ipv6" if ipaddress.ip_address(target["ip"]).version == 6 else "ipv4"
            family_endpoint_counts[family] += 1
            if family in supported_families:
                usable_targets.append(target)
            else:
                unprobeable_by_family[family] += 1
        if usable_targets:
            probeable_containers[container_key] = {**group, "targets": usable_targets}
    sample["endpoints_by_family"] = family_endpoint_counts
    sample["unprobeable_endpoints_by_family"] = unprobeable_by_family
    sample["probeable_containers"] = len(probeable_containers)
    sample["probeable_endpoints"] = sum(len(group["targets"]) for group in probeable_containers.values())
    containers = probeable_containers
    required_families = {family for family, count in family_endpoint_counts.items() if count > 0}
    family_reason = _family_coverage_reason(family_coverage, required_families)
    targets = []
    endpoint_containers = {}
    if containers:
        day_index = _utc_sample_date(now).toordinal()
        ordered_keys = sorted(
            containers,
            key=lambda key: (hashlib.sha256(f"{host_id}\0{key}".encode("utf-8")).hexdigest(), key),
        )
        offset = day_index % len(ordered_keys)
        rotated_keys = ordered_keys[offset:] + ordered_keys[:offset]
        pinned_by_container = {}
        for container_key, group in containers.items():
            matches = [target for target in group["targets"] if (target["ip"], target["port"]) in pinned_endpoint_keys]
            if matches:
                pinned_by_container[container_key] = sorted(matches, key=lambda target: target["id"])
        previous_endpoints = {}
        previous_keys = []
        for item in daily_selection.get("containers", []) if isinstance(daily_selection.get("containers"), list) else []:
            if not isinstance(item, dict):
                continue
            container_key = str(item.get("key") or "")
            if not container_key or container_key not in containers:
                continue
            previous_keys.append(container_key)
            points = set()
            for endpoint in item.get("endpoints", []) if isinstance(item.get("endpoints"), list) else []:
                if not isinstance(endpoint, dict):
                    continue
                try:
                    port = int(endpoint.get("port") or 0)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535 and isinstance(endpoint.get("ip"), str):
                    points.add((endpoint["ip"], port))
            previous_endpoints[container_key] = points
        selected_limit = min(DAILY_CONTAINER_SAMPLE_LIMIT, len(rotated_keys), MAX_TARGETS)
        priority_keys = ([key for key in rotated_keys if key in pinned_by_container]
                         + [key for key in previous_keys if key not in pinned_by_container]
                         + rotated_keys)
        selected_keys = []
        for key in priority_keys:
            if key not in selected_keys:
                selected_keys.append(key)
            if len(selected_keys) >= selected_limit:
                break
        sample["sampled_containers"] = len(selected_keys)
        for container_key in selected_keys:
            group = containers[container_key]
            ordered_endpoints = sorted(
                group["targets"],
                key=lambda target: (
                    hashlib.sha256(f"{container_key}\0{target['id']}".encode("utf-8")).hexdigest(),
                    target["id"],
                ),
            )
            selected_endpoints = pinned_by_container.get(container_key)
            if not selected_endpoints:
                preferred = previous_endpoints.get(container_key, set())
                selected_endpoints = [target for target in ordered_endpoints if (target["ip"], target["port"]) in preferred][:1]
            if not selected_endpoints:
                selected_endpoints = [ordered_endpoints[day_index % len(ordered_endpoints)]]
            # A container with many previously blocked listeners must not make
            # one daily sample exceed the existing per-cycle probe target cap.
            remaining_target_slots = MAX_TARGETS - len(targets)
            if remaining_target_slots <= 0:
                break
            selected_endpoints = selected_endpoints[:remaining_target_slots]
            container = group["container"]
            sample_container = {"key": container_key, "runtime": container["runtime"], "project": container["project"], "name": container["name"], "endpoints": []}
            for target in selected_endpoints:
                # Probe payloads intentionally remain limited to id/ip/port/interface;
                # the separately stored metadata is for admin evidence and display.
                targets.append({key: target[key] for key in ("id", "ip", "port", "interface")})
                endpoint_containers[target["id"]] = {
                    "runtime": container["runtime"], "project": container["project"],
                    "name": container["name"],
                    "sources": list(target.get("sources") or []),
                    "container_ports": list(target.get("container_ports") or []),
                }
                sample_container["endpoints"].append({"ip": target["ip"], "port": target["port"]})
            sample["containers"].append({
                **sample_container,
            })
        sample["sampled_containers"] = len(sample["containers"])
        sample["sampled_endpoints"] = len(targets)
        sample["follow_up_blocked_endpoint"] = any(key in pinned_by_container for key in selected_keys)
    sample_metadata = {"sample": sample, "endpoint_containers": endpoint_containers}
    if targets:
        partial = any(unprobeable_by_family.values()) or bool(family_reason)
        sample_metadata.update({
            "readiness": "ready_partial" if partial else "ready",
            "reason": family_reason if partial else "",
            "family_coverage_reason": family_reason,
            "next_step": "补足对应地址族探针路由；已覆盖端点继续自动抽测" if partial else "探测任务会按约 5 分钟周期运行",
        })
        return targets, "", sample_metadata
    if sample["eligible_endpoints"] and not sample["probeable_endpoints"]:
        reason = family_reason or "已发现公网 TCP 端点，但当前探针缺少对应 IP 地址族的独立网络覆盖"
        readiness = "probe_family_coverage_missing"
        next_step = "国内探针需具备目标地址族的可用默认路由，并来自足够的独立网段；Agent 会自动上报，服务端随后自动重试"
    elif not addresses and not has_public_container_ip:
        if inventory_reason:
            reason = inventory_reason
            readiness = "interface_inventory_unavailable"
            next_step = "检查 Agent 主机网卡清单采集与上报；如使用上游 NAT，需在宿主机配置中提供可读的公网转发映射"
        else:
            reason = "未发现公网 IP 地址；NAT 公网地址无法安全推断"
            readiness = "public_address_missing"
            next_step = "确认宿主机网卡或容器具有公网 IPv4/IPv6；上游 NAT 未在主机配置中登记时，系统不会猜测公网地址"
    elif sample["ambiguous_endpoints"]:
        reason = f"发现 {sample['ambiguous_endpoints']} 个 TCP 端点同时关联多个容器，无法安全确认归属"
        readiness = "ambiguous_container_mapping"
        next_step = "检查重复的端口发布/代理映射，确保公网 IP:端口唯一指向一个 Incus 或 Podman 容器"
    elif discovery["mapping_target_not_listening"]:
        reason = f"发现 {discovery['mapping_target_not_listening']} 个端口映射，但容器目标端口当前没有 TCP 监听"
        readiness = "public_tcp_endpoint_missing"
        next_step = "检查容器内服务是否运行，以及转发目标端口是否与实际 TCP 监听端口一致"
    elif discovery["direct_listener_address_unverified"] or discovery["mapping_listener_address_unverified"]:
        reason = f"发现 {discovery['direct_listener_address_unverified'] + discovery['mapping_listener_address_unverified']} 个监听端口，但监听地址与公网映射目标无法核实"
        readiness = "public_tcp_endpoint_missing"
        next_step = "确认 Agent 上报的 TCP 监听地址完整，并检查服务是否绑定到转发目标地址或对应协议的通配地址"
    elif discovery["mapping_without_host_public_ip"]:
        reason = f"发现 {discovery['mapping_without_host_public_ip']} 个容器转发，但宿主机没有可匹配的公网 IP"
        readiness = "public_address_missing"
        next_step = "若公网入口由上游 NAT 提供，需要 NAT 服务商 API 或主机可读的公网映射；系统不会猜测公网地址"
    else:
        reason = "未发现可确认的公网容器 TCP 端口：缺少实际监听端口或明确的 Incus/Podman TCP 映射"
        readiness = "public_tcp_endpoint_missing"
        next_step = "检查容器监听端口、Incus 代理/网络转发、Podman TCP 端口发布，以及容器公网地址与监听端口"
    sample_metadata.update({"readiness": readiness, "reason": reason, "next_step": next_step})
    return [], reason, sample_metadata


def initialize(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS gfw_probe_roles(
      node_id TEXT PRIMARY KEY,host_id TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('mainland','overseas')),
      updated_at INTEGER NOT NULL,region TEXT NOT NULL DEFAULT '',carrier TEXT NOT NULL DEFAULT '',
      source_network_id TEXT NOT NULL DEFAULT '',source_network_updated_at INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS gfw_cycles(
      id TEXT PRIMARY KEY,host_id TEXT NOT NULL,node_id TEXT NOT NULL,targets_json TEXT NOT NULL,status TEXT NOT NULL,
      created_at INTEGER NOT NULL,deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,result_json TEXT NOT NULL DEFAULT '{}');
    CREATE UNIQUE INDEX IF NOT EXISTS gfw_one_active_cycle ON gfw_cycles(host_id) WHERE status IN ('queued','running');
    CREATE INDEX IF NOT EXISTS gfw_cycles_host_time ON gfw_cycles(host_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS gfw_probe_jobs(
      id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,source_host_id TEXT NOT NULL,source_node_id TEXT NOT NULL,role TEXT NOT NULL,
      targets_json TEXT NOT NULL,targets_hash TEXT NOT NULL,lease TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,
      deadline_at INTEGER NOT NULL,finished_at INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',
      source_region TEXT NOT NULL DEFAULT '',source_carrier TEXT NOT NULL DEFAULT '',source_network_id TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS gfw_jobs_source_queue ON gfw_probe_jobs(source_node_id,status,created_at);
    CREATE TABLE IF NOT EXISTS gfw_probe_results(
      job_id TEXT NOT NULL,target_id TEXT NOT NULL,success INTEGER NOT NULL,latency_ms REAL,error TEXT NOT NULL,attempts INTEGER NOT NULL,
      PRIMARY KEY(job_id,target_id));
    CREATE TABLE IF NOT EXISTS gfw_states(
      host_id TEXT PRIMARY KEY,node_id TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'unassessed',blocked_since INTEGER NOT NULL DEFAULT 0,
      recovered_at INTEGER NOT NULL DEFAULT 0,normal_since INTEGER NOT NULL DEFAULT 0,last_cycle_at INTEGER NOT NULL DEFAULT 0,
      last_sample_at INTEGER NOT NULL DEFAULT 0,last_classification TEXT NOT NULL DEFAULT 'unknown',pending_block_count INTEGER NOT NULL DEFAULT 0,
      pending_block_since INTEGER NOT NULL DEFAULT 0,pending_recovery_count INTEGER NOT NULL DEFAULT 0,last_normal_duration INTEGER NOT NULL DEFAULT 0,
      blocked_count INTEGER NOT NULL DEFAULT 0,evidence_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE IF NOT EXISTS gfw_events(
      id INTEGER PRIMARY KEY AUTOINCREMENT,host_id TEXT NOT NULL,node_id TEXT NOT NULL,event_type TEXT NOT NULL,at INTEGER NOT NULL,
      duration_seconds INTEGER NOT NULL DEFAULT 0,normal_duration_seconds INTEGER NOT NULL DEFAULT 0,evidence_json TEXT NOT NULL DEFAULT '{}');
    CREATE INDEX IF NOT EXISTS gfw_events_host_time ON gfw_events(host_id,at DESC);
    """)
    columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(gfw_probe_roles)")}
    if "region" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN region TEXT NOT NULL DEFAULT ''")
    if "carrier" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN carrier TEXT NOT NULL DEFAULT ''")
    if "source_network_id" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN source_network_id TEXT NOT NULL DEFAULT ''")
    if "source_network_updated_at" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN source_network_updated_at INTEGER NOT NULL DEFAULT 0")
    if "ipv4_default_route" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN ipv4_default_route INTEGER")
    if "ipv6_default_route" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN ipv6_default_route INTEGER")
    if "route_capabilities_updated_at" not in columns:
        conn.execute("ALTER TABLE gfw_probe_roles ADD COLUMN route_capabilities_updated_at INTEGER NOT NULL DEFAULT 0")
    job_columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(gfw_probe_jobs)")}
    if "source_region" not in job_columns:
        conn.execute("ALTER TABLE gfw_probe_jobs ADD COLUMN source_region TEXT NOT NULL DEFAULT ''")
    if "source_carrier" not in job_columns:
        conn.execute("ALTER TABLE gfw_probe_jobs ADD COLUMN source_carrier TEXT NOT NULL DEFAULT ''")
    if "source_network_id" not in job_columns:
        conn.execute("ALTER TABLE gfw_probe_jobs ADD COLUMN source_network_id TEXT NOT NULL DEFAULT ''")


def _role_counts(conn, now):
    result = {"mainland": 0, "overseas": 0}
    for row in conn.execute("SELECT r.role,h.last_seen,o.payload FROM gfw_probe_roles r JOIN hosts h ON h.node_id=r.node_id LEFT JOIN ops_hosts o ON o.node=h.node_id"):
        if _probe_online(row["last_seen"], row["payload"], now):
            result[row["role"]] += 1
    return result


def _active_roles(conn, now):
    rows = conn.execute("SELECT r.host_id,r.node_id,r.role,r.region,r.carrier,r.source_network_id,r.source_network_updated_at,"
                        "r.ipv4_default_route,r.ipv6_default_route,r.route_capabilities_updated_at,h.last_seen,o.payload "
                        "FROM gfw_probe_roles r JOIN hosts h ON h.node_id=r.node_id LEFT JOIN ops_hosts o ON o.node=h.node_id ORDER BY r.role,r.host_id").fetchall()
    result = {"mainland": [], "overseas": []}
    for row in rows:
        if _probe_online(row["last_seen"], row["payload"], now):
            network_id, network_updated_at = _fresh_source_network(row, now)
            result[row["role"]].append({"host_id": row["host_id"], "node_id": row["node_id"],
                                         "region": str(row["region"] or "")[:80],
                                         "carrier": str(row["carrier"] or "")[:100],
                                         "network_id": network_id,
                                         "network_identity_updated_at": network_updated_at,
                                         "ipv4_default_route": _fresh_route_capability(row, "ipv4_default_route", now),
                                         "ipv6_default_route": _fresh_route_capability(row, "ipv6_default_route", now)})
    return result


def _source_coverage_for_host(roles, node_id):
    """Return probe sources available to test a host, excluding the host itself."""
    available = {
        role: [source for source in roles.get(role, []) if source["node_id"] != node_id]
        for role in ("mainland", "overseas")
    }
    required = {"mainland": MIN_MAINLAND, "overseas": MIN_OVERSEAS}
    missing = [role for role in required if len(available[role]) < required[role]]
    if not missing:
        return available, ""
    own_roles = [role for role in required if any(source["node_id"] == node_id for source in roles.get(role, []))]
    counts = f"国内 {len(available['mainland'])}/{MIN_MAINLAND}、海外 {len(available['overseas'])}/{MIN_OVERSEAS}"
    if own_roles:
        own_label = "国内" if own_roles[0] == "mainland" else "海外"
        reason = f"该主机本身是{own_label}探针，探针不会自测；排除本机后仅有 {counts} 个可用探测点"
    else:
        reason = f"独立探针覆盖不足：当前 {counts} 个可用探测点"
    return available, reason


def _source_network_coverage_reason(roles):
    for role, required, label in (("mainland", MIN_MAINLAND, "国内"), ("overseas", MIN_OVERSEAS, "海外")):
        sources = roles.get(role, [])
        networks = {str(source.get("network_id") or "") for source in sources if source.get("network_id")}
        if len(networks) < required:
            unknown = sum(1 for source in sources if not source.get("network_id"))
            return f"{label}探针已核验公网来源网段 {len(networks)}/{required}，另有 {unknown} 个来源待识别"
    return ""


def _select_probe_sources(sources, required):
    """Prefer one source per observed public network, then unknown sources for learning."""
    selected, used_networks, used_nodes = [], set(), set()
    for source in sources:
        network_id = str(source.get("network_id") or "")
        if network_id and network_id not in used_networks:
            selected.append(source)
            used_networks.add(network_id)
            used_nodes.add(source["node_id"])
            if len(selected) >= required:
                return selected
    for source in sources:
        if source["node_id"] in used_nodes or source.get("network_id"):
            continue
        selected.append(source)
        used_nodes.add(source["node_id"])
        if len(selected) >= required:
            return selected
    for source in sources:
        if source["node_id"] in used_nodes:
            continue
        selected.append(source)
        used_nodes.add(source["node_id"])
        if len(selected) >= required:
            break
    return selected


def _family_probe_plan(roles):
    """Choose independent networks per family, preferring reported default routes.

    A missing default route is only a routing-table hint: policy or host routes
    can still reach a particular public endpoint. Therefore every online source
    remains eligible for a bounded target-specific TCP attempt. The connect
    result is authoritative, and route errors never count as a block timeout.
    """
    source_plan = {"ipv4": {"mainland": [], "overseas": []}, "ipv6": {"mainland": [], "overseas": []}}
    coverage = {}
    required_by_role = {"mainland": MIN_MAINLAND, "overseas": MIN_OVERSEAS}
    for family, column in (("ipv4", "ipv4_default_route"), ("ipv6", "ipv6_default_route")):
        family_ready = True
        family_info = {}
        for role, required in required_by_role.items():
            candidates = sorted(
                roles.get(role, []),
                key=lambda source: (0 if source.get(column) is True else 1 if source.get(column) is None else 2,
                                    str(source.get("host_id") or "")),
            )
            selected = _select_probe_sources(candidates, required)
            networks = {str(item.get("network_id") or "") for item in selected if item.get("network_id")}
            ready = len(networks) >= required
            route_present_sources = sum(1 for item in candidates if item.get(column) is True)
            route_missing_sources = sum(1 for source in roles.get(role, []) if source.get(column) is False)
            route_unknown_sources = sum(1 for source in roles.get(role, []) if source.get(column) is None)
            if ready:
                selected = [item for item in selected if item.get("network_id")][:required]
            else:
                family_ready = False
            # Retain partial source selections so real connectivity results are
            # visible while the network threshold is incomplete. Aggregation
            # still stays unknown until all independent-network thresholds pass.
            source_plan[family][role] = selected
            family_info[role] = {
                "required_networks": required,
                "eligible_sources": len(candidates),
                "route_capable_sources": route_present_sources,
                "route_present_sources": route_present_sources,
                "route_missing_sources": route_missing_sources,
                "route_unknown_sources": route_unknown_sources,
                "verified_networks": len(networks),
                "ready": ready,
                "probeable": bool(selected),
            }
        coverage[family] = {"ready": family_ready, "probeable": any(item["probeable"] for item in family_info.values()), **family_info}
    return source_plan, coverage


def _family_coverage_reason(coverage, required_families=None):
    missing = []
    required_families = set(required_families) if required_families is not None else {"ipv4", "ipv6"}
    for family, label in (("ipv4", "IPv4"), ("ipv6", "IPv6")):
        if family not in required_families:
            continue
        info = coverage.get(family, {}) if isinstance(coverage, dict) else {}
        if not info or info.get("ready"):
            continue
        role_labels = (("mainland", "国内", MIN_MAINLAND), ("overseas", "海外", MIN_OVERSEAS))
        details = []
        for role, role_label, required in role_labels:
            role_info = info.get(role, {}) if isinstance(info.get(role), dict) else {}
            if role_info.get("ready"):
                continue
            details.append(f"{role_label} {int(role_info.get('verified_networks') or 0)}/{required} 个独立网段")
        if details:
            missing.append(f"{label}探针覆盖不足（{'、'.join(details)}）")
    if not missing:
        return ""
    return "目标端点的地址族缺少足够探针：" + "；".join(missing)


def _schedule(conn, now):
    roles = _active_roles(conn, now)
    hosts = conn.execute("SELECT host_id,node_id,last_seen FROM hosts WHERE node_id<>'' AND last_seen>=? ORDER BY COALESCE((SELECT last_cycle_at FROM gfw_states s WHERE s.host_id=hosts.host_id),0),host_id LIMIT 300", (now - STALE_SECONDS,)).fetchall()
    for host in hosts:
        active_cycles = int(conn.execute("SELECT COUNT(*) FROM gfw_cycles WHERE status IN ('queued','running')").fetchone()[0])
        if active_cycles >= MAX_ACTIVE_CYCLES:
            break
        state = conn.execute("SELECT last_cycle_at,state,evidence_json FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        last_cycle = int(state["last_cycle_at"] or 0) if state else 0
        if now - last_cycle < CYCLE_SECONDS:
            continue
        if conn.execute("SELECT 1 FROM gfw_cycles WHERE host_id=? AND status IN ('queued','running') LIMIT 1", (host["host_id"],)).fetchone():
            continue
        host_roles, coverage_reason = _source_coverage_for_host(roles, host["node_id"])
        family_source_plan, family_coverage = _family_probe_plan(host_roles)
        probe_families = {family for family, details in family_coverage.items() if details.get("probeable")}
        pinned_endpoint_keys = set()
        if state and state["state"] == "blocked":
            pinned_endpoint_keys = _blocked_endpoint_keys(state["evidence_json"])
        daily_selection = _same_day_sample(conn, host["host_id"], now)
        targets, _reason, sample_metadata = _targets_for_host(
            conn, host["host_id"], host["node_id"], now,
            pinned_endpoint_keys=pinned_endpoint_keys, daily_selection=daily_selection,
            probe_families=probe_families, family_coverage=family_coverage,
        )
        if not targets:
            preserved_blocked_endpoints = sorted([list(key) for key in pinned_endpoint_keys])
            target_readiness = {
                "status": sample_metadata.get("readiness", "public_tcp_endpoint_missing"),
                "reason": sample_metadata.get("reason") or _reason,
                "next_step": sample_metadata.get("next_step", ""),
                "family_coverage": family_coverage,
            }
            conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,last_classification,evidence_json) VALUES(?,?,?,'unknown',?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,last_classification='unknown',evidence_json=excluded.evidence_json",
                         (host["host_id"], host["node_id"], now, _json({"reason": _reason, "targets": [], "sample": sample_metadata["sample"], "target_readiness": target_readiness, "blocked_endpoint_keys": preserved_blocked_endpoints})))
            continue
        # Collect bounded partial samples even when the full network threshold is
        # missing. Their results remain unknown and cannot confirm block/recovery.
        cycle_id = str(uuid.uuid4())
        targets_json = _json(targets)
        conn.execute("INSERT INTO gfw_cycles(id,host_id,node_id,targets_json,status,created_at,deadline_at,result_json) VALUES(?,?,?,?,'queued',?,?,?)",
                     (cycle_id, host["host_id"], host["node_id"], targets_json, now, now + JOB_SECONDS, _json(sample_metadata)))
        try:
            pending_evidence = json.loads(state["evidence_json"] or "{}") if state else {}
        except (TypeError, ValueError):
            pending_evidence = {}
        if not isinstance(pending_evidence, dict):
            pending_evidence = {}
        if not state or state["state"] in {"unassessed", "unknown"}:
            pending_evidence["reason"] = ""
        pending_evidence.update({
            "sample": sample_metadata.get("sample", {}),
            "target_readiness": {
                "status": "ready_partial" if coverage_reason or sample_metadata.get("readiness") == "ready_partial" else sample_metadata.get("readiness", "ready"),
                "reason": "；".join(value for value in (sample_metadata.get("reason", ""), coverage_reason) if value),
                "next_step": "补足不同网络的探针；当前部分结果仅供排查，不用于确认阻断或恢复" if coverage_reason else sample_metadata.get("next_step", "探针任务已排队；等待探测结果回传"),
                "family_coverage": family_coverage,
            },
        })
        conn.execute("INSERT INTO gfw_states(host_id,node_id,last_cycle_at,evidence_json) VALUES(?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,last_cycle_at=excluded.last_cycle_at,evidence_json=excluded.evidence_json",
                     (host["host_id"], host["node_id"], now, _json(pending_evidence)))
        targets_by_source = {}
        for target in targets:
            family = "ipv6" if ipaddress.ip_address(target["ip"]).version == 6 else "ipv4"
            for role in ("mainland", "overseas"):
                for source in family_source_plan[family][role]:
                    key = (role, source["node_id"])
                    targets_by_source.setdefault(key, {"source": source, "targets": []})["targets"].append(target)
        for (role, _source_node_id), assignment in targets_by_source.items():
            source = assignment["source"]
            source_targets = assignment["targets"]
            source_targets_json = _json(source_targets)
            job_id = str(uuid.uuid4())
            conn.execute("INSERT INTO gfw_probe_jobs(id,cycle_id,source_host_id,source_node_id,role,targets_json,targets_hash,lease,status,created_at,deadline_at,source_region,source_carrier,source_network_id) VALUES(?,?,?,?,?,?,?,?, 'queued',?,?,?,?,?)",
                         (job_id, cycle_id, source["host_id"], source["node_id"], role, source_targets_json, _digest(source_targets), secrets.token_urlsafe(32), now, now + JOB_SECONDS, source.get("region", ""), source.get("carrier", ""), source.get("network_id", "")))


def _apply_cycle(conn, cycle, now):
    jobs = conn.execute("SELECT * FROM gfw_probe_jobs WHERE cycle_id=?", (cycle["id"],)).fetchall()
    if not jobs or any(job["status"] not in ("complete", "expired", "failed", "cancelled") for job in jobs):
        return False
    targets = json.loads(cycle["targets_json"])
    try:
        cycle_metadata = json.loads(cycle["result_json"] or "{}")
    except (TypeError, ValueError):
        cycle_metadata = {}
    sample_metadata = cycle_metadata.get("sample", {}) if isinstance(cycle_metadata, dict) else {}
    endpoint_containers = cycle_metadata.get("endpoint_containers", {}) if isinstance(cycle_metadata, dict) else {}
    if not isinstance(sample_metadata, dict):
        sample_metadata = {}
    if not isinstance(endpoint_containers, dict):
        endpoint_containers = {}
    job_target_ids = {}
    for job in jobs:
        try:
            job_targets = json.loads(job["targets_json"] or "[]")
            job_target_ids[job["id"]] = {str(item.get("id") or "") for item in job_targets if isinstance(item, dict)}
        except (TypeError, ValueError):
            job_target_ids[job["id"]] = set()
    evidence = []
    for target in targets:
        by_role = {"mainland": {"success": 0, "failed": 0, "timeout": 0, "total": 0, "independent_networks": 0, "network_success": 0, "network_timeout": 0},
                   "overseas": {"success": 0, "failed": 0, "timeout": 0, "total": 0, "independent_networks": 0, "network_success": 0, "network_timeout": 0}}
        network_outcomes = {"mainland": {}, "overseas": {}}
        probe_sources = []
        for job in jobs:
            if target["id"] not in job_target_ids.get(job["id"], set()):
                continue
            result = conn.execute("SELECT success,error,latency_ms FROM gfw_probe_results WHERE job_id=? AND target_id=?", (job["id"], target["id"])).fetchone()
            probe_sources.append({
                "source_host_id": str(job["source_host_id"] or "")[:200],
                "role": job["role"],
                "source_region": str(job["source_region"] or "")[:80],
                "source_carrier": str(job["source_carrier"] or "")[:100],
                "source_network_id": str(job["source_network_id"] or "")[:64],
                "job_status": job["status"],
                "success": bool(result["success"]) if result else None,
                "latency_ms": result["latency_ms"] if result else None,
                "error": str((result["error"] if result else job["error"]) or "")[:160],
            })
            if not result:
                continue
            stats = by_role[job["role"]]
            stats["total"] += 1
            stats["success" if result["success"] else "failed"] += 1
            if not result["success"] and str(result["error"] or "") == "timeout":
                stats["timeout"] += 1
            network_id = str(job["source_network_id"] or "")
            if network_id:
                network_outcomes[job["role"]].setdefault(network_id, []).append(
                    "success" if result["success"] else str(result["error"] or "network_error")
                )
        main, over = by_role["mainland"], by_role["overseas"]
        for role, outcomes in network_outcomes.items():
            stats = by_role[role]
            stats["independent_networks"] = len(outcomes)
            stats["network_success"] = sum(1 for values in outcomes.values() if "success" in values)
            stats["network_timeout"] = sum(1 for values in outcomes.values() if values and all(value == "timeout" for value in values))
        # A TCP refusal means the endpoint is closed or actively rejecting,
        # while a network error points to a probe-path problem. Results count
        # only when the source network was independently observed; multiple
        # agents on one egress network are one source, not separate evidence.
        is_blocked = main["network_timeout"] >= MIN_MAINLAND and over["network_success"] >= MIN_OVERSEAS
        is_normal = main["network_success"] >= MIN_MAINLAND and over["network_success"] >= MIN_OVERSEAS
        if is_blocked:
            status = "blocked"
        elif is_normal:
            status = "normal"
        else:
            status = "unknown"
        endpoint = {"ip": target["ip"], "port": target["port"], "interface": target.get("interface", ""),
                    "status": status, "mainland": main, "overseas": over, "probes": probe_sources}
        owner = endpoint_containers.get(target["id"])
        if isinstance(owner, dict):
            endpoint.update({"runtime": str(owner.get("runtime") or ""),
                             "project": str(owner.get("project") or ""),
                             "container_name": str(owner.get("name") or ""),
                             "mapping_sources": [str(value)[:40] for value in owner.get("sources", [])[:8]] if isinstance(owner.get("sources"), list) else [],
                             "container_ports": [int(value) for value in owner.get("container_ports", [])[:8] if str(value).isdigit()] if isinstance(owner.get("container_ports"), list) else []})
        evidence.append(endpoint)
    blocked_cycle = any(item.get("status") == "blocked" for item in evidence)
    successful_cycle = bool(evidence) and len(evidence) == len(targets) and all(item.get("status") == "normal" for item in evidence)
    classification = "blocked" if blocked_cycle else "normal" if successful_cycle else "unknown"
    prior = conn.execute("SELECT * FROM gfw_states WHERE host_id=?", (cycle["host_id"],)).fetchone()
    state = dict(prior) if prior else {"host_id": cycle["host_id"], "node_id": cycle["node_id"], "state": "unassessed",
        "blocked_since": 0, "recovered_at": 0, "normal_since": 0, "pending_block_count": 0, "last_classification": "unknown",
        "pending_block_since": 0, "pending_recovery_count": 0, "last_normal_duration": 0, "blocked_count": 0, "last_sample_at": 0}
    try:
        prior_evidence = json.loads(prior["evidence_json"] or "{}") if prior else {}
    except (TypeError, ValueError):
        prior_evidence = {}
    previous_targets = prior_evidence.get("targets", []) if isinstance(prior_evidence, dict) else []
    previous_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in previous_targets if isinstance(item, dict)}
    previous_blocked_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in previous_targets if isinstance(item, dict) and item.get("status") == "blocked"}
    try:
        anchored_blocked_keys = {(str(item[0]), int(item[1])) for item in prior_evidence.get("blocked_endpoint_keys", []) if isinstance(item, (list, tuple)) and len(item) == 2}
    except (TypeError, ValueError):
        anchored_blocked_keys = set()
    if state["state"] == "blocked" and not anchored_blocked_keys:
        anchored_blocked_keys = previous_blocked_keys
    current_blocked_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in evidence if item.get("status") == "blocked"}
    current_normal_keys = {(str(item.get("ip") or ""), int(item.get("port") or 0)) for item in evidence if item.get("status") == "normal"}
    reason = ""
    if state["last_sample_at"] and classification == "blocked" and not (previous_keys & current_blocked_keys):
        classification = "unknown"  # A changed public endpoint is not a consecutive blocked observation.
        reason = "公网 IP 或端口发生变化；新端点需重新连续确认，当前不计为阻断"
    if state["state"] == "blocked" and classification == "normal" and not (anchored_blocked_keys & current_normal_keys):
        classification = "unknown"  # Recovery must succeed on the endpoint that was blocked.
        reason = "原阻断 IP/端口已变化；新端点可达不能证明原端点已恢复"
    if state["state"] == "blocked" and classification == "blocked" and not (anchored_blocked_keys & current_blocked_keys):
        classification = "unknown"
        reason = "当前异常发生在不同 IP/端口；不能与原阻断端点合并计时"
    elif classification == "unknown" and not reason:
        failures = {}
        for job in jobs:
            if job["status"] not in ("failed", "expired"):
                continue
            code = str(job["error"] or ("probe deadline elapsed" if job["status"] == "expired" else "probe_worker_error"))
            label = PROBE_FAILURE_LABELS.get(code, "任务未完成")
            role = "国内" if job["role"] == "mainland" else "海外"
            key = (role, label)
            failures[key] = failures.get(key, 0) + 1
        if failures:
            reason = "探测任务未完成：" + "；".join(
                f"{role}探针{label} {count} 个"
                for (role, label), count in sorted(failures.items())
            ) + "；本轮不用于确认阻断或恢复"
        else:
            error_labels = {
                "family_unsupported": "探针系统不支持该 IP 地址族",
                "no_route": "探针缺少到目标的路由",
                "host_unreachable": "探针网络报告目标不可达",
                "local_policy_block": "探针本机策略拒绝连接",
                "network_error": "探针网络错误（内核未提供细分原因）",
            }
            observed_errors = {}
            for endpoint in evidence:
                family = "IPv6" if ipaddress.ip_address(endpoint["ip"]).version == 6 else "IPv4"
                for probe in endpoint.get("probes", []):
                    code = str(probe.get("error") or "")
                    if probe.get("success") is False and code in error_labels:
                        role_label = "国内" if probe.get("role") == "mainland" else "海外"
                        key = (role_label, family, error_labels[code])
                        observed_errors[key] = observed_errors.get(key, 0) + 1
            if observed_errors:
                reason = "探针连接路径未通过核验：" + "；".join(
                    f"{role}{family}{label} {count} 项"
                    for (role, family, label), count in sorted(observed_errors.items())[:5]
                ) + "；本轮不用于确认阻断或恢复"
            else:
                family_reason = str(sample_metadata.get("family_coverage_reason") or "")
                reason = (family_reason + "；" if family_reason else "") + "国内或海外探测样本不足/结果不一致；本轮不用于确认阻断或恢复"
    event = None
    if classification == "blocked":
        if state["state"] != "blocked":
            if state["last_classification"] == "blocked":
                state["pending_block_count"] += 1
            else:
                state["pending_block_count"] = 1
                state["pending_block_since"] = cycle["created_at"]
            state["pending_recovery_count"] = 0
            if state["pending_block_count"] >= 3:
                normal_start = state["recovered_at"] or state["normal_since"]
                first_block_signal = state["pending_block_since"] or cycle["created_at"]
                normal_duration = max(0, first_block_signal - normal_start) if normal_start else 0
                state.update(state="blocked", blocked_since=state["pending_block_since"], recovered_at=0,
                             pending_block_count=0, pending_block_since=0, pending_recovery_count=0,
                             last_normal_duration=normal_duration, blocked_count=state["blocked_count"] + 1)
                event = ("blocked", state["blocked_since"], 0, normal_duration)
        else:
            state["pending_recovery_count"] = 0
        state["last_classification"] = "blocked"
    elif classification == "normal":
        state["pending_block_count"] = 0
        state["pending_block_since"] = 0
        if state["state"] == "blocked":
            if state["last_classification"] == "normal":
                state["pending_recovery_count"] += 1
            else:
                state["pending_recovery_count"] = 1
            if state["pending_recovery_count"] >= 2:
                duration = max(0, cycle["created_at"] - state["blocked_since"])
                state.update(state="recovered", recovered_at=cycle["created_at"], normal_since=cycle["created_at"],
                             blocked_since=0, pending_recovery_count=0)
                event = ("recovered", cycle["created_at"], duration, 0)
        elif state["state"] == "unassessed":
            state.update(state="normal", normal_since=cycle["created_at"], pending_recovery_count=0)
        state["last_classification"] = "normal"
    else:
        state["pending_block_count"] = 0
        state["pending_block_since"] = 0
        state["pending_recovery_count"] = 0
        state["last_classification"] = "unknown"
    if state["state"] == "blocked":
        if classification == "blocked" and not anchored_blocked_keys:
            anchored_blocked_keys = current_blocked_keys
    else:
        anchored_blocked_keys = set()
    evidence_payload = {"targets": evidence, "classification": classification,
                        "blocked_endpoint_keys": sorted([list(key) for key in anchored_blocked_keys]),
                        "sample": sample_metadata}
    if reason:
        evidence_payload["reason"] = reason
    evidence_payload["probe_failures"] = [
        {"role": job["role"], "status": job["status"],
         "code": str(job["error"] or ("probe deadline elapsed" if job["status"] == "expired" else "probe_worker_error"))}
        for job in jobs if job["status"] in ("failed", "expired")
    ][:5]
    state.update(node_id=cycle["node_id"], last_sample_at=cycle["created_at"], evidence_json=_json(evidence_payload))
    conn.execute("""INSERT INTO gfw_states(host_id,node_id,state,blocked_since,recovered_at,normal_since,last_cycle_at,last_sample_at,
      last_classification,pending_block_count,pending_block_since,pending_recovery_count,last_normal_duration,blocked_count,evidence_json)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id) DO UPDATE SET node_id=excluded.node_id,state=excluded.state,
      blocked_since=excluded.blocked_since,recovered_at=excluded.recovered_at,normal_since=excluded.normal_since,last_cycle_at=excluded.last_cycle_at,
      last_sample_at=excluded.last_sample_at,last_classification=excluded.last_classification,pending_block_count=excluded.pending_block_count,
      pending_block_since=excluded.pending_block_since,pending_recovery_count=excluded.pending_recovery_count,last_normal_duration=excluded.last_normal_duration,
      blocked_count=excluded.blocked_count,evidence_json=excluded.evidence_json""",
      (cycle["host_id"], state["node_id"], state["state"], state["blocked_since"], state["recovered_at"], state["normal_since"],
       cycle["created_at"], state["last_sample_at"], state["last_classification"], state["pending_block_count"], state["pending_block_since"],
       state["pending_recovery_count"], state["last_normal_duration"], state["blocked_count"], state["evidence_json"]))
    if event:
        conn.execute("INSERT INTO gfw_events(host_id,node_id,event_type,at,duration_seconds,normal_duration_seconds,evidence_json) VALUES(?,?,?,?,?,?,?)",
                     (cycle["host_id"], cycle["node_id"], event[0], event[1], event[2], event[3], _json({"targets": evidence})))
    conn.execute("UPDATE gfw_cycles SET status=?,finished_at=?,result_json=? WHERE id=?",
                 ("complete" if classification != "unknown" else "partial", now,
                  _json({"classification": classification, "targets": evidence, "sample": sample_metadata}), cycle["id"]))
    # Longitudinal history is compact: keep the most recent 100 transitions per host.
    conn.execute("DELETE FROM gfw_events WHERE host_id=? AND id NOT IN (SELECT id FROM gfw_events WHERE host_id=? ORDER BY at DESC,id DESC LIMIT 100)",
                 (cycle["host_id"], cycle["host_id"]))
    return True


def _store_route_capabilities(conn, node_id, now, capabilities):
    if not node_id or not isinstance(capabilities, dict):
        return
    ipv4 = capabilities.get("ipv4_default_route")
    ipv6 = capabilities.get("ipv6_default_route")
    if type(ipv4) is not bool and type(ipv6) is not bool:
        return
    conn.execute(
        "UPDATE gfw_probe_roles SET ipv4_default_route=?,ipv6_default_route=?,route_capabilities_updated_at=? WHERE node_id=?",
        (int(ipv4) if type(ipv4) is bool else None,
         int(ipv6) if type(ipv6) is bool else None,
         now, node_id),
    )


def lease_job(conn, host_id, node_id, now, capabilities=None):
    conn.execute("DELETE FROM gfw_probe_results WHERE job_id IN (SELECT id FROM gfw_probe_jobs WHERE created_at<? AND status<>'running')", (now - 90 * 86400,))
    conn.execute("DELETE FROM gfw_probe_jobs WHERE created_at<? AND status<>'running'", (now - 90 * 86400,))
    conn.execute("DELETE FROM gfw_cycles WHERE created_at<? AND status NOT IN ('queued','running')", (now - 90 * 86400,))
    _store_route_capabilities(conn, node_id, now, capabilities)
    _schedule(conn, now)
    conn.execute("UPDATE gfw_probe_jobs SET status='expired',finished_at=?,error='probe deadline elapsed' WHERE status IN ('queued','running') AND deadline_at<=?", (now, now))
    cycles = conn.execute("SELECT * FROM gfw_cycles WHERE status IN ('queued','running') AND deadline_at<=? LIMIT 100", (now,)).fetchall()
    for cycle in cycles:
        _apply_cycle(conn, cycle, now)
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE source_host_id=? AND source_node_id=? AND status='queued' AND deadline_at>? ORDER BY created_at LIMIT 1", (host_id, node_id, now)).fetchone()
    if not row:
        return {"job": None}
    conn.execute("UPDATE gfw_probe_jobs SET status='running' WHERE id=? AND status='queued'", (row["id"],))
    cycle = conn.execute("SELECT host_id,node_id FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    conn.execute("UPDATE gfw_cycles SET status='running' WHERE id=? AND status='queued'", (row["cycle_id"],))
    targets = json.loads(row["targets_json"])
    return {"job": {"id": row["id"], "cycle_id": row["cycle_id"], "source_host_id": host_id, "source_node_id": node_id,
                     "target_host_id": cycle["host_id"], "target_node_id": cycle["node_id"], "role": row["role"],
                     "lease": row["lease"], "targets": targets, "targets_hash": row["targets_hash"], "deadline_at": row["deadline_at"]}}


def report(conn, payload, now, source_network_id=""):
    keys = {"job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash", "results"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise HTTPException(400, "invalid GFW probe report")
    if any(not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 256 for key in ("job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash")):
        raise HTTPException(400, "invalid GFW probe identity")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE id=?", (payload["job_id"],)).fetchone()
    if not row or row["cycle_id"] != payload["cycle_id"] or row["source_host_id"] != payload["source_host_id"] or row["source_node_id"] != payload["source_node_id"] or not secrets.compare_digest(row["lease"], str(payload["lease"])):
        raise HTTPException(403, "invalid GFW probe lease")
    targets = json.loads(row["targets_json"])
    if payload["targets_hash"] != row["targets_hash"] or row["status"] != "running" or row["deadline_at"] <= now:
        raise HTTPException(409, "GFW probe job is no longer active")
    role = conn.execute("SELECT role FROM gfw_probe_roles WHERE host_id=? AND node_id=?", (row["source_host_id"], row["source_node_id"])).fetchone()
    if not role or role["role"] != row["role"]:
        raise HTTPException(409, "probe node role changed")
    try:
        observed_network = ipaddress.ip_network(str(source_network_id or ""), strict=False)
        source_network_id = str(observed_network) if observed_network.is_global else ""
    except (TypeError, ValueError):
        source_network_id = ""
    # A report without a verifiable public source is still valid probe evidence,
    # but it must not erase a previously verified role identity. Its timestamp
    # remains unchanged and the usual freshness window will expire it naturally.
    if source_network_id:
        conn.execute("UPDATE gfw_probe_roles SET source_network_id=?,source_network_updated_at=? WHERE node_id=?",
                     (source_network_id[:64], now, row["source_node_id"]))
    conn.execute("UPDATE gfw_probe_jobs SET source_network_id=? WHERE id=? AND status='running'",
                 (source_network_id[:64], row["id"]))
    results = payload["results"]
    if not isinstance(results, list) or len(results) != len(targets):
        raise HTTPException(400, "incomplete GFW probe results")
    allowed = {target["id"] for target in targets}
    seen = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {"target_id", "success", "latency_ms", "error", "attempts"}:
            raise HTTPException(400, "invalid GFW result fields")
        target_id = result["target_id"]
        if target_id not in allowed or target_id in seen or type(result["success"]) is not bool or type(result["attempts"]) is not int or not 1 <= result["attempts"] <= 2:
            raise HTTPException(400, "invalid GFW result")
        if result["error"] not in PROBE_RESULT_ERROR_CODES:
            raise HTTPException(400, "invalid GFW result error")
        latency = result["latency_ms"]
        if latency is not None and (type(latency) not in (int, float) or not 0 <= latency <= 10000):
            raise HTTPException(400, "invalid GFW latency")
        if result["success"] and latency is None:
            raise HTTPException(400, "successful probe requires latency")
        seen.add(target_id)
    for result in results:
        conn.execute("INSERT INTO gfw_probe_results(job_id,target_id,success,latency_ms,error,attempts) VALUES(?,?,?,?,?,?)",
                     (row["id"], result["target_id"], int(result["success"]), result["latency_ms"], result["error"], result["attempts"]))
    conn.execute("UPDATE gfw_probe_jobs SET status='complete',finished_at=? WHERE id=?", (now, row["id"]))
    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    _apply_cycle(conn, cycle, now)
    conn.commit()
    return {"ok": True}


def report_failure(conn, payload, now):
    keys = {"job_id", "cycle_id", "source_host_id", "source_node_id", "lease", "targets_hash", "failure_code"}
    if not isinstance(payload, dict) or set(payload) != keys:
        raise HTTPException(400, "invalid GFW probe failure report")
    if any(not isinstance(payload[key], str) or not 1 <= len(payload[key]) <= 256 for key in keys):
        raise HTTPException(400, "invalid GFW probe failure identity")
    if payload["failure_code"] not in PROBE_FAILURE_CODES:
        raise HTTPException(400, "invalid GFW probe failure code")
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute("SELECT * FROM gfw_probe_jobs WHERE id=?", (payload["job_id"],)).fetchone()
    if (not row or row["cycle_id"] != payload["cycle_id"]
            or row["source_host_id"] != payload["source_host_id"]
            or row["source_node_id"] != payload["source_node_id"]
            or not secrets.compare_digest(row["lease"], payload["lease"])):
        raise HTTPException(403, "invalid GFW probe lease")
    if (payload["targets_hash"] != row["targets_hash"] or row["status"] != "running"
            or row["deadline_at"] <= now):
        raise HTTPException(409, "GFW probe job is no longer active")
    role = conn.execute("SELECT role FROM gfw_probe_roles WHERE host_id=? AND node_id=?",
                        (row["source_host_id"], row["source_node_id"])).fetchone()
    if not role or role["role"] != row["role"]:
        raise HTTPException(409, "probe node role changed")
    conn.execute("UPDATE gfw_probe_jobs SET status='failed',finished_at=?,error=? WHERE id=?",
                 (now, payload["failure_code"], row["id"]))
    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (row["cycle_id"],)).fetchone()
    _apply_cycle(conn, cycle, now)
    conn.commit()
    return {"ok": True}


def status_map(conn, now):
    counts = _role_counts(conn, now)
    active_roles = _active_roles(conn, now)
    history_30d = {}
    for row in conn.execute(
        "SELECT host_id,event_type,COUNT(*) AS event_count FROM gfw_events WHERE at>=? GROUP BY host_id,event_type",
        (now - 30 * 86400,),
    ):
        host_history = history_30d.setdefault(row["host_id"], {"blocked": 0, "recovered": 0})
        if row["event_type"] in host_history:
            host_history[row["event_type"]] = int(row["event_count"] or 0)
    verified_network_counts = {
        role: len({str(source.get("network_id") or "") for source in active_roles.get(role, []) if source.get("network_id")})
        for role in ("mainland", "overseas")
    }
    result = {}
    rows = conn.execute("SELECT * FROM hosts ORDER BY host_id LIMIT 500").fetchall()
    for host in rows:
        state_row = conn.execute("SELECT * FROM gfw_states WHERE host_id=? AND node_id=?", (host["host_id"], host["node_id"])).fetchone()
        history = [dict(event) for event in conn.execute("SELECT event_type,at,duration_seconds,normal_duration_seconds FROM gfw_events WHERE host_id=? ORDER BY at DESC,id DESC LIMIT 6", (host["host_id"],))]
        recent_history = history_30d.get(host["host_id"], {"blocked": 0, "recovered": 0})
        history_summary = {
            "window_days": 30,
            "blocked_count": int(recent_history.get("blocked", 0)),
            "recovered_count": int(recent_history.get("recovered", 0)),
        }
        host_sources, source_reason = _source_coverage_for_host(active_roles, host["node_id"])
        source_reason = source_reason or _source_network_coverage_reason(host_sources)
        _family_source_plan, host_family_coverage = _family_probe_plan(host_sources)
        source_counts = {role: len(sources) for role, sources in host_sources.items()}
        host_last_seen = int(host["last_seen"] or 0)
        host_online = host_last_seen > 0 and now - host_last_seen <= STALE_SECONDS
        last_sample_at = int(state_row["last_sample_at"] or 0) if state_row else 0
        try:
            cached_evidence = json.loads(state_row["evidence_json"] or "{}") if state_row else {}
        except (TypeError, ValueError):
            cached_evidence = {}
        target_readiness = cached_evidence.get("target_readiness", {}) if isinstance(cached_evidence, dict) else {}
        target_readiness = dict(target_readiness) if isinstance(target_readiness, dict) else {}
        cached_sample = cached_evidence.get("sample", {}) if isinstance(cached_evidence, dict) else {}
        if isinstance(cached_sample, dict):
            for key in ("eligible_containers", "sampled_containers", "eligible_endpoints", "sampled_endpoints", "ambiguous_endpoints"):
                target_readiness.setdefault(key, int(cached_sample.get(key) or 0))
            for key in ("endpoints_by_family", "unprobeable_endpoints_by_family", "probe_family_coverage"):
                if isinstance(cached_sample.get(key), dict):
                    target_readiness.setdefault(key, cached_sample[key])
            if isinstance(cached_sample.get("family_coverage_reason"), str):
                target_readiness.setdefault("family_coverage_reason", cached_sample["family_coverage_reason"])
            cached_discovery = cached_sample.get("discovery", {})
            if isinstance(cached_discovery, dict):
                target_readiness.setdefault("discovery", cached_discovery)
        if not host_online:
            target_readiness.update({"status": "host_offline", "reason": "母鸡 Agent 心跳已过期，当前不会为该主机调度探测", "next_step": "先恢复 Agent 上报；恢复后系统会自动发现端点并安排探测"})
        elif target_readiness.get("status") in {
            "public_tcp_endpoint_missing", "public_address_missing",
            "interface_inventory_unavailable", "ambiguous_container_mapping", "probe_family_coverage_missing",
        }:
            # A concrete endpoint-discovery diagnosis is more actionable than
            # probe coverage, so preserve it even when both conditions exist.
            pass
        elif source_reason:
            target_readiness.update({"status": "probe_coverage_missing", "reason": source_reason + "；本机不会作为自己的探测来源", "next_step": "恢复离线探针或补足不同主机上的国内/海外探针"})
        elif target_readiness.get("status") in {"probe_coverage_missing", "host_offline"}:
            target_readiness.update({"status": "awaiting_scheduler", "reason": "主机与探针覆盖已恢复，等待自动重新发现并调度", "next_step": "等待 Agent 下一轮轮询；系统将自动重试"})
        elif not target_readiness:
            if not state_row:
                target_readiness = {"status": "awaiting_scheduler", "reason": "服务端尚未执行该主机的首轮发现", "next_step": "等待一个 Agent 轮询周期；若持续无任务，检查服务端 GFW 调度日志"}
            else:
                cached_reason = str(cached_evidence.get("reason") or "") if isinstance(cached_evidence, dict) else ""
                sample = cached_evidence.get("sample", {}) if isinstance(cached_evidence, dict) else {}
                if "公网 IPv4" in cached_reason or "公网 IP 地址" in cached_reason:
                    readiness = "public_address_missing"
                    next_step = "确认宿主机或容器公网地址；上游 NAT 地址不会被自动猜测"
                elif "网卡" in cached_reason or "网卡地址清单" in cached_reason:
                    readiness = "interface_inventory_unavailable"
                    next_step = "检查 Agent 主机网卡清单采集与上报"
                elif "多个容器" in cached_reason:
                    readiness = "ambiguous_container_mapping"
                    next_step = "确保公网 IP:端口映射唯一指向一个 Incus 或 Podman 容器"
                elif "公网容器 TCP 端口" in cached_reason:
                    readiness = "public_tcp_endpoint_missing"
                    next_step = "检查容器监听端口和明确的 Incus/Podman TCP 映射"
                else:
                    readiness = "awaiting_scheduler"
                    next_step = "等待服务端下一轮发现；持续无任务时检查服务端 GFW 调度日志"
                target_readiness = {"status": readiness, "reason": cached_reason, "next_step": next_step}
                if isinstance(sample, dict):
                    for key in ("eligible_containers", "sampled_containers", "eligible_endpoints", "sampled_endpoints", "ambiguous_endpoints"):
                        target_readiness[key] = int(sample.get(key) or 0)
        if state_row:
            state = state_row["state"]
            stale = last_sample_at > 0 and now - last_sample_at > STALE_SECONDS
            coverage_insufficient = bool(source_reason)
            evidence = cached_evidence
            reason = str(evidence.get("reason") or "") if isinstance(evidence, dict) else ""
            sample = evidence.get("sample", {}) if isinstance(evidence, dict) else {}
            if not isinstance(sample, dict):
                sample = {}
            if stale:
                status = "stale"
            elif coverage_insufficient or not last_sample_at:
                status = "unassessed"
            elif state_row["pending_block_count"] or (last_sample_at and state_row["last_classification"] == "unknown"):
                status = "investigating"
            else:
                status = state
            if state == "blocked":
                since = int(state_row["blocked_since"] or 0)
            elif state == "recovered":
                since = int(state_row["recovered_at"] or 0)
            else:
                since = int(state_row["normal_since"] or 0)
            duration = max(0, now - since) if since else 0
            readiness_reason = str(target_readiness.get("reason") or "")
            readiness_status = str(target_readiness.get("status") or "")
            concrete_readiness = readiness_status in {
                "host_offline", "interface_inventory_unavailable", "public_address_missing",
                "public_tcp_endpoint_missing", "ambiguous_container_mapping",
                "probe_family_coverage_missing", "probe_coverage_missing", "ready_partial",
            }
            if concrete_readiness and readiness_reason:
                reason = readiness_reason
            elif coverage_insufficient:
                reason = source_reason + "；本机不会作为自己的探测来源"
                if stale:
                    reason = "探测数据已过期；" + reason
            elif not host_online:
                reason = "母鸡 Agent 心跳已过期；探测数据不会自动视为恢复"
            elif status == "investigating" and not reason:
                reason = "本轮证据不足或端点变化；当前不确认恢复，也不把未知样本计入持续时长"
            result[host["host_id"]] = {"status": status, "last_known_state": state, "stale": stale,
                "since": since, "duration_seconds": duration, "last_normal_duration_seconds": int(state_row["last_normal_duration"] or 0),
                "blocked_count": int(state_row["blocked_count"] or 0), "last_sample_at": int(state_row["last_sample_at"] or 0),
                "host_last_seen": host_last_seen,
                "last_classification": state_row["last_classification"], "pending_block_rounds": int(state_row["pending_block_count"] or 0),
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"],
                "available_mainland_sources": source_counts["mainland"], "available_overseas_sources": source_counts["overseas"],
                "verified_mainland_networks": verified_network_counts["mainland"],
                "verified_overseas_networks": verified_network_counts["overseas"],
                "probe_family_coverage": host_family_coverage,
                "evidence": evidence.get("targets", []) if isinstance(evidence, dict) else [], "sample": sample,
                "reason": reason or ("探测数据已过期" if stale else ""), "target_readiness": target_readiness, "history": history,
                "history_30d": history_summary}
        else:
            if not host_online:
                reason = "母鸡 Agent 心跳已过期，探测任务暂不调度"
            elif source_reason:
                reason = source_reason + "；本机不会作为自己的探测来源"
            elif target_readiness and target_readiness.get("reason"):
                reason = target_readiness["reason"]
            else:
                reason = "探针与端点覆盖已就绪，等待首轮自动 TCP 抽测"
            result[host["host_id"]] = {"status": "unassessed", "last_known_state": "unassessed", "stale": False,
                "since": 0, "duration_seconds": 0, "last_normal_duration_seconds": 0, "blocked_count": 0,
                "last_sample_at": 0, "last_classification": "unknown", "pending_block_rounds": 0,
                "mainland_sources": counts["mainland"], "overseas_sources": counts["overseas"], "evidence": [], "sample": {},
                "host_last_seen": host_last_seen,
                "available_mainland_sources": source_counts["mainland"], "available_overseas_sources": source_counts["overseas"],
                "verified_mainland_networks": verified_network_counts["mainland"],
                "verified_overseas_networks": verified_network_counts["overseas"],
                "probe_family_coverage": host_family_coverage,
                "reason": reason, "target_readiness": target_readiness, "history": history,
                "history_30d": history_summary}
    return result


def attach(app, db, verify_signature, signed_response):
    def admin(request):
        if getattr(request.state, "dashboard_role", "") != "admin":
            raise HTTPException(403, "仅管理员可配置 GFW 探测节点")

    @app.get("/api/v1/gfw-probes/manage")
    def manage(request: Request):
        admin(request)
        conn, now = db(), int(time.time())
        try:
            candidates = [dict(row) for row in conn.execute("SELECT host_id,node_id,agent_version,last_seen FROM hosts WHERE node_id<>'' ORDER BY host_id LIMIT 300")]
            role_rows = {row["node_id"]: dict(row) for row in conn.execute("SELECT node_id,role,region,carrier,source_network_id,source_network_updated_at FROM gfw_probe_roles")}
            active_roles = _active_roles(conn, now)
            probe_health = _probe_health_snapshot(conn, now)
            probe_by_node = {source["node_id"]: source for source in probe_health["sources"]}
            online_hosts = [item for item in candidates if now - int(item.get("last_seen") or 0) <= STALE_SECONDS]
            target_hosts = 0
            ready_hosts = 0
            partial_probe_hosts = 0
            independent_probe_hosts = 0
            target_endpoints = 0
            eligible_endpoints = 0
            eligible_containers = 0
            sampled_containers = 0
            discovery_totals = {
                "direct_public_listener": 0, "direct_listener_address_unverified": 0,
                "podman_publish": 0, "incus_proxy": 0,
                "incus_forward": 0, "host_dnat": 0, "mapping_target_not_listening": 0,
                "mapping_listener_address_unverified": 0,
                "mapping_target_unknown": 0, "mapping_without_host_public_ip": 0,
                "ambiguous_sockets": 0,
            }
            missing_reasons = {}
            probe_missing_reasons = {}
            family_missing_reasons = {}
            probe_job_counts = {"complete": 0, "failed": 0, "expired": 0, "queued": 0, "running": 0, "cancelled": 0}
            probe_jobs_since = now - 86400
            for job in conn.execute("SELECT status,COUNT(*) AS count FROM gfw_probe_jobs WHERE created_at>=? GROUP BY status", (probe_jobs_since,)):
                if job["status"] in probe_job_counts:
                    probe_job_counts[job["status"]] = int(job["count"] or 0)
            last_probe_job = conn.execute("SELECT MAX(finished_at) FROM gfw_probe_jobs WHERE created_at>=? AND status IN ('complete','failed','expired')", (probe_jobs_since,)).fetchone()
            latest_probe_job = conn.execute("SELECT status,created_at,finished_at,error FROM gfw_probe_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone()
            for item in online_hosts:
                _source_candidates, source_reason = _source_coverage_for_host(active_roles, item["node_id"])
                network_reason = _source_network_coverage_reason(_source_candidates)
                effective_source_reason = source_reason or network_reason
                _family_source_plan, family_coverage = _family_probe_plan(_source_candidates)
                if not effective_source_reason:
                    independent_probe_hosts += 1
                else:
                    probe_missing_reasons[effective_source_reason] = probe_missing_reasons.get(effective_source_reason, 0) + 1
                state = conn.execute("SELECT state,evidence_json FROM gfw_states WHERE host_id=? AND node_id=?",
                                     (item["host_id"], item["node_id"])).fetchone()
                pinned_endpoint_keys = _blocked_endpoint_keys(state["evidence_json"]) if state and state["state"] == "blocked" else set()
                daily_selection = _same_day_sample(conn, item["host_id"], now)
                targets, reason, sample_metadata = _targets_for_host(
                    conn, item["host_id"], item["node_id"], now,
                    pinned_endpoint_keys=pinned_endpoint_keys, daily_selection=daily_selection,
                    probe_families={family for family, details in family_coverage.items() if details.get("probeable")},
                    family_coverage=family_coverage,
                )
                sample = sample_metadata.get("sample", {})
                if isinstance(sample, dict):
                    eligible_endpoints += int(sample.get("eligible_endpoints") or 0)
                    eligible_containers += int(sample.get("eligible_containers") or 0)
                    sampled_containers += int(sample.get("sampled_containers") or 0)
                    discovery = sample.get("discovery", {})
                    if isinstance(discovery, dict):
                        for key in discovery_totals:
                            discovery_totals[key] += int(discovery.get(key) or 0)
                    endpoint_families = {
                        family for family, count in (sample.get("endpoints_by_family") or {}).items()
                        if family in {"ipv4", "ipv6"} and int(count or 0) > 0
                    }
                else:
                    endpoint_families = set()
                family_reason = _family_coverage_reason(family_coverage, endpoint_families)
                if family_reason:
                    family_missing_reasons[family_reason] = family_missing_reasons.get(family_reason, 0) + 1
                if targets:
                    target_hosts += 1
                    target_endpoints += len(targets)
                    full_family_coverage = bool(endpoint_families) and all(
                        bool(family_coverage.get(family, {}).get("ready")) for family in endpoint_families
                    )
                    if not effective_source_reason and full_family_coverage:
                        ready_hosts += 1
                    else:
                        partial_probe_hosts += 1
                else:
                    label = reason or "未发现可验证的公网 TCP 端点"
                    missing_reasons[label] = missing_reasons.get(label, 0) + 1
            role_health = probe_health["roles"]
            latest_role_results = {
                role: _latest_role_result(conn, role)
                for role in ("mainland", "overseas")
            }
            recommendations = []
            if role_health["mainland"]["online"] < MIN_MAINLAND:
                recommendations.append(f"国内探针在线 {role_health['mainland']['online']}/{MIN_MAINLAND}：恢复离线节点或配置更多不同网络来源的国内探针。")
            if role_health["overseas"]["online"] < MIN_OVERSEAS:
                recommendations.append(f"海外探针在线 {role_health['overseas']['online']}/{MIN_OVERSEAS}：恢复或配置至少 {MIN_OVERSEAS} 个海外探针。")
            for role, label, minimum in (("mainland", "国内", MIN_MAINLAND), ("overseas", "海外", MIN_OVERSEAS)):
                network_count = int(role_health[role].get("distinct_networks") or 0)
                if network_count < minimum:
                    recommendations.append(
                        f"{label}探针已核验公网来源网段 {network_count}/{minimum}；在线 Agent 会自动登记来源，身份不足时不输出 GFW 阻断结论。"
                    )
            if role_health["mainland"]["online_missing_carrier"] or role_health["mainland"]["online_missing_region"]:
                recommendations.append(
                    f"有在线国内探针缺少运营商标注 {role_health['mainland']['online_missing_carrier']} 个、地区标注 {role_health['mainland']['online_missing_region']} 个；"
                    "请在节点卡片填写，以便核对探测网络是否独立。缺少标注不会被伪装成已覆盖。"
                )
            if online_hosts and target_hosts < len(online_hosts):
                top_target_reason = sorted(missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[0][0] if missing_reasons else "未发现公网 TCP 端点"
                recommendations.append(f"{len(online_hosts) - target_hosts} 台在线母鸡没有可探测端点；最常见原因：{top_target_reason}。")
            if family_missing_reasons:
                top_family_reason, family_host_count = sorted(family_missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[0]
                recommendations.append(f"{family_host_count} 台母鸡的目标端点探针网段未达判定门槛；{top_family_reason}。系统会继续采集部分连通性回执，但不会据此确认阻断或恢复。")
            if ready_hosts and not probe_job_counts["complete"] and not probe_job_counts["queued"] and not probe_job_counts["running"]:
                if probe_job_counts["failed"] or probe_job_counts["expired"]:
                    recommendations.append("存在可探测主机但近 24 小时没有成功回传；检查探针 Agent 的 GFW TCP 探测能力与出站连接。")
                else:
                    recommendations.append("存在可探测主机但近 24 小时没有探测任务；检查服务端调度日志与 Agent 轮询状态。")
            if not recommendations:
                recommendations.append("探针角色、在线状态与端点覆盖均满足当前要求；系统会自动按轮换策略抽测。")
            latest_probe = {
                "status": str(latest_probe_job["status"] or "") if latest_probe_job else "",
                "created_at": int(latest_probe_job["created_at"] or 0) if latest_probe_job else 0,
                "finished_at": int(latest_probe_job["finished_at"] or 0) if latest_probe_job else 0,
                "error": str(latest_probe_job["error"] or "")[:240] if latest_probe_job else "",
            }
            return {"minimum_mainland": MIN_MAINLAND, "minimum_overseas": MIN_OVERSEAS,
                    "coverage": _role_counts(conn, now),
                    "target_coverage": {
                        "online_hosts": len(online_hosts),
                        "hosts_with_targets": target_hosts,
                        "hosts_with_independent_probes": independent_probe_hosts,
                        "hosts_ready_for_probe": ready_hosts,
                        "hosts_with_partial_probe_coverage": partial_probe_hosts,
                        "target_endpoints": target_endpoints,
                        "eligible_endpoints": eligible_endpoints,
                        "eligible_containers": eligible_containers,
                        "sampled_containers": sampled_containers,
                        "sample_limit_per_host": DAILY_CONTAINER_SAMPLE_LIMIT,
                        "sample_date_utc": _utc_sample_date(now).isoformat(),
                        "inventory_stale_seconds": STALE_SECONDS,
                        "discovery": discovery_totals,
                        "missing_reasons": [{"reason": reason, "hosts": count} for reason, count in sorted(missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[:5]],
                        "probe_missing_reasons": [{"reason": reason, "hosts": count} for reason, count in sorted(probe_missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[:5]],
                        "family_missing_reasons": [{"reason": reason, "hosts": count} for reason, count in sorted(family_missing_reasons.items(), key=lambda entry: (-entry[1], entry[0]))[:5]],
                    },
                    "probe_health": {"window_seconds": 86400, "jobs": probe_job_counts,
                                     "last_finished_at": int(last_probe_job[0] or 0) if last_probe_job else 0,
                                     "last_attempt": latest_probe,
                                     "roles": role_health,
                                     "latest_role_results": latest_role_results,
                                     "recommendations": recommendations},
                    "candidates": [{**item,
                                    "role": role_rows.get(item["node_id"], {}).get("role", "disabled"),
                                    "region": role_rows.get(item["node_id"], {}).get("region", ""),
                                    "carrier": role_rows.get(item["node_id"], {}).get("carrier", ""),
                                    "network_id": probe_by_node.get(item["node_id"], {}).get("network_id", ""),
                                    "network_identity_updated_at": probe_by_node.get(item["node_id"], {}).get("network_identity_updated_at", 0),
                                    "ipv4_default_route": probe_by_node.get(item["node_id"], {}).get("ipv4_default_route"),
                                    "ipv6_default_route": probe_by_node.get(item["node_id"], {}).get("ipv6_default_route"),
                                    "route_capabilities_updated_at": probe_by_node.get(item["node_id"], {}).get("route_capabilities_updated_at", 0),
                                    "probe_online": probe_by_node.get(item["node_id"], {}).get("online", False) if item["node_id"] in probe_by_node else now - int(item.get("last_seen") or 0) <= STALE_SECONDS,
                                    "last_seen_age_seconds": max(0, now - int(item.get("last_seen") or 0)) if item.get("last_seen") else None}
                                   for item in candidates]}
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probes/role")
    async def save_role(request: Request):
        admin(request)
        raw = await request.body()
        if len(raw) > 4096:
            raise HTTPException(413, "probe role request too large")
        try:
            payload = json.loads(raw)
        except Exception:
            raise HTTPException(400, "invalid JSON") from None
        if not isinstance(payload, dict) or not {"host_id", "node_id", "role"}.issubset(payload) or set(payload) - {"host_id", "node_id", "role", "region", "carrier"} or not all(isinstance(payload.get(k, ""), str) for k in payload):
            raise HTTPException(400, "invalid probe role")
        payload["region"] = str(payload.get("region") or "").strip()
        payload["carrier"] = str(payload.get("carrier") or "").strip()
        if (payload["role"] not in {"disabled", "mainland", "overseas"}
                or not 1 <= len(payload["host_id"]) <= 200 or not 1 <= len(payload["node_id"]) <= 128
                or len(payload["region"]) > 80 or len(payload["carrier"]) > 100
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in payload["region"] + payload["carrier"])):
            raise HTTPException(400, "invalid probe role")
        conn, now = db(), int(time.time())
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not conn.execute("SELECT 1 FROM hosts WHERE host_id=? AND node_id=?", (payload["host_id"], payload["node_id"])).fetchone():
                raise HTTPException(409, "主机身份已变化，请刷新节点列表")
            previous = conn.execute("SELECT role FROM gfw_probe_roles WHERE node_id=?", (payload["node_id"],)).fetchone()
            if previous and previous["role"] != payload["role"]:
                affected = conn.execute("SELECT DISTINCT cycle_id FROM gfw_probe_jobs WHERE source_node_id=? AND status='queued'", (payload["node_id"],)).fetchall()
                conn.execute("UPDATE gfw_probe_jobs SET status='cancelled',finished_at=?,error='probe role changed' WHERE source_node_id=? AND status='queued'", (now, payload["node_id"]))
                for cycle_row in affected:
                    cycle = conn.execute("SELECT * FROM gfw_cycles WHERE id=?", (cycle_row["cycle_id"],)).fetchone()
                    if cycle:
                        _apply_cycle(conn, cycle, now)
            if payload["role"] == "disabled":
                conn.execute("DELETE FROM gfw_probe_roles WHERE node_id=?", (payload["node_id"],))
            else:
                conn.execute("INSERT INTO gfw_probe_roles(node_id,host_id,role,updated_at,region,carrier) VALUES(?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET host_id=excluded.host_id,role=excluded.role,updated_at=excluded.updated_at,region=excluded.region,carrier=excluded.carrier",
                             (payload["node_id"], payload["host_id"], payload["role"], now, payload["region"], payload["carrier"]))
            conn.commit()
            return {"ok": True}
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probe/report")
    async def agent_report(request: Request):
        raw = await request.body()
        if len(raw) > 32768:
            raise HTTPException(413, "GFW probe report too large")
        ts = request.headers.get("x-timestamp", "")
        verify_signature(raw, ts, request.headers.get("x-signature", ""))
        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "invalid JSON") from None
        conn = db()
        try:
            return signed_response(report(conn, payload, int(time.time()), _request_source_network(request)), ts)
        finally:
            conn.close()

    @app.post("/api/v1/gfw-probe/failure")
    async def agent_failure(request: Request):
        raw = await request.body()
        if len(raw) > 8192:
            raise HTTPException(413, "GFW probe failure report too large")
        ts = request.headers.get("x-timestamp", "")
        verify_signature(raw, ts, request.headers.get("x-signature", ""))
        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(400, "invalid JSON") from None
        conn = db()
        try:
            return signed_response(report_failure(conn, payload, int(time.time())), ts)
        finally:
            conn.close()
