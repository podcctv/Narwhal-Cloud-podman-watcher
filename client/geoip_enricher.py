"""GeoIP lookup, bounded TTL/LRU caching, and socket IP enrichment helpers."""

from __future__ import annotations

import ipaddress
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, urlparse

import requests

try:
    import maxminddb
except ImportError:  # Optional at import time for source-only/test environments.
    maxminddb = None


_geoip_country_cache: Dict[str, Tuple[str, float]] = {}
_geoip_detail_cache: Dict[str, Tuple[Dict[str, str], float]] = {}
_geoip_reader = None
_geoip_reader_path = ""

_COUNTRY_NAMES_ZH = {
    "CN": "中国",
    "HK": "中国香港",
    "TW": "中国台湾",
    "MO": "中国澳门",
    "US": "美国",
    "JP": "日本",
    "SG": "新加坡",
    "KR": "韩国",
    "DE": "德国",
    "GB": "英国",
    "FR": "法国",
    "NL": "荷兰",
    "RU": "俄罗斯",
    "CA": "加拿大",
    "AU": "澳大利亚",
    "IN": "印度",
    "BR": "巴西",
    "MY": "马来西亚",
    "TH": "泰国",
    "VN": "越南",
    "ID": "印尼",
    "PH": "菲律宾",
    "TR": "土耳其",
    "IT": "意大利",
    "ES": "西班牙",
    "SE": "瑞典",
    "CH": "瑞士",
    "PL": "波兰",
    "UA": "乌克兰",
    "ZA": "南非",
    "AE": "阿联酋",
    "SA": "沙特",
    "MX": "墨西哥",
    "AR": "阿根廷",
    "CL": "智利",
}


_AGENT_NAMESPACES: List[Dict[str, Any]] = []


def register_agent_module(ns_or_mod: Any) -> None:
    """Register an agent facade module or namespace dict so patched attributes are honored."""
    ns = ns_or_mod if isinstance(ns_or_mod, dict) else getattr(ns_or_mod, "__dict__", None)
    if ns is not None and ns not in _AGENT_NAMESPACES:
        _AGENT_NAMESPACES.append(ns)


def _agent_attr(name: str, fallback: Any) -> Any:
    for ns in _AGENT_NAMESPACES:
        if name in ns and ns[name] is not fallback:
            return ns[name]
    for mod_name in ("client.agent", "agent", "narwhal_agent"):
        mod = sys.modules.get(mod_name)
        if mod is not None and hasattr(mod, name):
            val = getattr(mod, name)
            if val is not fallback:
                return val
    return fallback


def _fallback_is_public_source_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _fallback_is_trackable_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast)


def _fallback_parse_socket_endpoint(endpoint: str) -> Tuple[str, int]:
    raw = str(endpoint or "").strip()
    if not raw:
        return "", 0
    if raw.startswith("[") and "]:" in raw:
        host, _, port_str = raw[1:].partition("]:")
    elif ":" in raw:
        host, _, port_str = raw.rpartition(":")
    else:
        return raw, 0
    try:
        port = int(port_str)
    except ValueError:
        port = 0
    return host.strip("[]"), port


def _geoip_cache_limits() -> Tuple[int, float, float]:
    """Return bounded (max_entries, ttl_seconds, negative_ttl_seconds) for GeoIP caches."""
    try:
        max_entries = int(os.getenv("GEOIP_CACHE_MAX_ENTRIES", "4096"))
    except ValueError:
        max_entries = 4096
    try:
        ttl = float(os.getenv("GEOIP_CACHE_TTL_SECONDS", "86400"))
    except ValueError:
        ttl = 86400.0
    try:
        negative_ttl = float(os.getenv("GEOIP_NEGATIVE_CACHE_TTL_SECONDS", "900"))
    except ValueError:
        negative_ttl = 900.0
    return (
        max(100, min(50000, max_entries)),
        max(300.0, min(2592000.0, ttl)),
        max(60.0, min(86400.0, negative_ttl)),
    )


def _geoip_cache_get(ip: str, now: float) -> str:
    """Look up a cached country code for an IP, refreshing LRU order if valid."""
    cache = _agent_attr("_geoip_country_cache", _geoip_country_cache)
    cached = cache.get(ip)
    if cached is None:
        return ""
    country, expires_at = cached
    if expires_at <= now:
        cache.pop(ip, None)
        return ""
    cache.pop(ip, None)
    cache[ip] = (country, expires_at)
    return country


def _geoip_cache_put(ip: str, country: str, now: float) -> None:
    """Store a normalized country code in the bounded LRU GeoIP cache."""
    cache = _agent_attr("_geoip_country_cache", _geoip_country_cache)
    limits_fn = _agent_attr("_geoip_cache_limits", _geoip_cache_limits)
    max_entries, ttl, negative_ttl = limits_fn()
    normalized = country.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", normalized):
        normalized = "UN"
    cache.pop(ip, None)
    cache[ip] = (
        normalized,
        now + (negative_ttl if normalized == "UN" else ttl),
    )
    while len(cache) > max_entries:
        cache.pop(next(iter(cache)))


def _geoip_local_country_batch(ips: List[str]) -> Dict[str, str]:
    """Resolve country codes from a local MaxMind MMDB file if available."""
    global _geoip_reader, _geoip_reader_path
    mmdb = _agent_attr("maxminddb", maxminddb)
    if not ips or mmdb is None:
        return {}
    configured_path = os.getenv(
        "GEOIP_MMDB_PATH", "/usr/share/GeoIP/GeoLite2-Country.mmdb"
    ).strip()
    if not configured_path or not os.path.isfile(configured_path):
        return {}
    if _geoip_reader is None or _geoip_reader_path != configured_path:
        if _geoip_reader is not None:
            try:
                _geoip_reader.close()
            except Exception:
                pass
        try:
            _geoip_reader = mmdb.open_database(configured_path)
            _geoip_reader_path = configured_path
        except Exception:
            _geoip_reader = None
            _geoip_reader_path = ""
            return {}
    result: Dict[str, str] = {}
    for ip in ips:
        try:
            record = _geoip_reader.get(ip) or {}
            country = str((record.get("country") or {}).get("iso_code") or "")
        except Exception:
            country = ""
        if re.fullmatch(r"[A-Za-z]{2}", country):
            result[ip] = country.upper()
    return result


def _geoip_https_country_batch(ips: List[str]) -> Dict[str, str]:
    """Resolve country codes in batches over HTTPS when enabled."""
    if not ips or os.getenv("GEOIP_HTTPS_ENABLED", "true").strip().lower() in (
        "0", "false", "no", "off"
    ):
        return {}
    endpoint = os.getenv("GEOIP_HTTPS_ENDPOINT", "https://api.country.is/").strip()
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        return {}
    req = _agent_attr("requests", requests)
    app_version = _agent_attr("APP_VERSION", os.getenv("NARWHAL_VERSION", "dev").strip() or "dev")
    try:
        response = req.post(
            endpoint,
            json=ips[:100],
            headers={"User-Agent": f"Narwhal-Monitor/{app_version}"},
            timeout=8,
        )
        response.raise_for_status()
        values = response.json()
    except Exception:
        return {}
    if not isinstance(values, list):
        return {}
    result: Dict[str, str] = {}
    requested = set(ips)
    for item in values:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "")
        country = str(item.get("country") or "").upper()
        if ip in requested and re.fullmatch(r"[A-Z]{2}", country):
            result[ip] = country
    return result


def _geoip_country_map(ips: List[str]) -> Dict[str, str]:
    """Map IPs to ISO-2 country codes using cache, local MMDB, and optional HTTPS fallback."""
    if not ips:
        return {}
    now = time.monotonic()
    cache_get_fn = _agent_attr("_geoip_cache_get", _geoip_cache_get)
    cache_put_fn = _agent_attr("_geoip_cache_put", _geoip_cache_put)
    is_public_fn = _agent_attr("_is_public_source_ip", _fallback_is_public_source_ip)
    local_batch_fn = _agent_attr("_geoip_local_country_batch", _geoip_local_country_batch)
    https_batch_fn = _agent_attr("_geoip_https_country_batch", _geoip_https_country_batch)

    countries = {ip: cache_get_fn(ip, now) for ip in ips}
    unresolved = [ip for ip, country in countries.items() if not country]
    if unresolved:
        public_unresolved = [ip for ip in unresolved if is_public_fn(ip)]
        resolved = local_batch_fn(public_unresolved) if public_unresolved else {}
        still_unresolved = [ip for ip in public_unresolved if ip not in resolved]
        if still_unresolved:
            resolved.update(https_batch_fn(still_unresolved))
        for ip in unresolved:
            country = resolved.get(ip, "UN")
            cache_put_fn(ip, country, now)
            countries[ip] = country
    return {ip: (countries.get(ip) or "UN") for ip in ips}


def _geoip_country_batch(ip_counts: Dict[str, int]) -> List[Dict[str, int | str]]:
    """Aggregate per-IP connection counts by country, sorted descending."""
    if not ip_counts:
        return []
    country_map_fn = _agent_attr("_geoip_country_map", _geoip_country_map)
    countries = country_map_fn(list(ip_counts))

    country_counter: Dict[str, Dict[str, int | str]] = {}
    for ip, cnt in ip_counts.items():
        country = countries.get(ip) or "UN"
        if country not in country_counter:
            country_counter[country] = {"country": country, "connections": 0, "ip_count": 0}
        country_counter[country]["connections"] = int(country_counter[country]["connections"]) + int(cnt)
        country_counter[country]["ip_count"] = int(country_counter[country]["ip_count"]) + 1
    return sorted(country_counter.values(), key=lambda x: int(x["connections"]), reverse=True)


def _geoip_detail_map(ips: List[str]) -> Dict[str, Dict[str, str]]:
    """Resolve bounded public-IP location and ISP metadata for deep diagnostics."""
    is_public_fn = _agent_attr("_is_public_source_ip", _fallback_is_public_source_ip)
    public_ips = list(dict.fromkeys(ip for ip in ips if is_public_fn(ip)))[:100]
    if not public_ips:
        return {}
    https_enabled = os.getenv("GEOIP_HTTPS_ENABLED", "true").strip().lower() not in (
        "0", "false", "no", "off"
    )
    now = time.monotonic()
    limits_fn = _agent_attr("_geoip_cache_limits", _geoip_cache_limits)
    detail_cache = _agent_attr("_geoip_detail_cache", _geoip_detail_cache)
    country_map_fn = _agent_attr("_geoip_country_map", _geoip_country_map)
    req = _agent_attr("requests", requests)
    app_version = _agent_attr("APP_VERSION", os.getenv("NARWHAL_VERSION", "dev").strip() or "dev")

    max_entries, ttl, negative_ttl = limits_fn()
    result: Dict[str, Dict[str, str]] = {}
    unresolved: List[str] = []
    for ip in public_ips:
        cached = detail_cache.get(ip)
        if cached and cached[1] > now:
            result[ip] = dict(cached[0])
        else:
            detail_cache.pop(ip, None)
            unresolved.append(ip)

    endpoint = os.getenv("GEOIP_DETAIL_ENDPOINT", "https://ipwho.is/{ip}").strip()
    parsed = urlparse(endpoint.replace("{ip}", "1.1.1.1"))
    lookup_enabled = (
        "{ip}" in endpoint and parsed.scheme == "https" and bool(parsed.netloc)
        and not parsed.username and not parsed.password
    )

    def lookup(ip: str) -> Tuple[str, Dict[str, str]]:
        try:
            response = req.get(
                endpoint.replace("{ip}", quote(ip, safe="")),
                headers={"User-Agent": f"Narwhal-Monitor/{app_version}"},
                timeout=6,
            )
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict) or value.get("success") is False:
                return ip, {}
            connection = value.get("connection") if isinstance(value.get("connection"), dict) else {}
            country = str(value.get("country_code") or value.get("countryCode") or "").upper()
            return ip, {
                "country": country if re.fullmatch(r"[A-Z]{2}", country) else "UN",
                "region": str(value.get("region") or value.get("region_name") or "")[:120],
                "city": str(value.get("city") or "")[:120],
                "isp": str(connection.get("isp") or connection.get("org") or value.get("isp") or value.get("org") or "")[:160],
                "asn": str(connection.get("asn") or connection.get("asn_number") or value.get("asn") or "")[:40],
            }
        except Exception:
            return ip, {}

    if https_enabled and lookup_enabled and unresolved:
        with ThreadPoolExecutor(max_workers=min(8, len(unresolved))) as pool:
            futures = [pool.submit(lookup, ip) for ip in unresolved]
            for future in as_completed(futures):
                ip, detail = future.result()
                result[ip] = detail
                detail_cache[ip] = (dict(detail), now + (ttl if detail else negative_ttl))

    fallback_countries = country_map_fn([ip for ip in public_ips if not result.get(ip)])
    for ip in public_ips:
        if not result.get(ip):
            result[ip] = {"country": fallback_countries.get(ip, "UN"), "region": "", "city": "", "isp": "", "asn": ""}
    while len(detail_cache) > max_entries:
        detail_cache.pop(next(iter(detail_cache)))
    return result


def _format_geoip_badge(detail: Dict[str, Any]) -> Tuple[str, str, str, str, str, str, str]:
    """Format GeoIP metadata into normalized fields and a human-readable badge label."""
    country = str(detail.get("country") or "UN").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        country = "UN"
    country_names = _agent_attr("_COUNTRY_NAMES_ZH", _COUNTRY_NAMES_ZH)
    country_name = country_names.get(country, country if country != "UN" else "")
    region = str(detail.get("region") or "").strip()[:80]
    city = str(detail.get("city") or "").strip()[:80]
    isp = str(detail.get("isp") or "").strip()[:120]
    raw_asn = str(detail.get("asn") or "").strip()[:40]
    asn = (f"AS{raw_asn}" if raw_asn and not raw_asn.upper().startswith("AS") else raw_asn.upper()) if raw_asn else ""

    loc_parts: List[str] = []
    if country_name:
        loc_parts.append(country_name)
    if region and region.lower() not in {country.lower(), country_name.lower()}:
        loc_parts.append(region)
    elif city and city.lower() not in {country.lower(), country_name.lower()}:
        loc_parts.append(city)

    isp_parts: List[str] = []
    if isp:
        isp_parts.append(isp)
    if asn:
        isp_parts.append(asn)

    loc_text = "·".join(loc_parts)
    isp_text = " ".join(isp_parts)
    if loc_text and isp_text:
        geo_label = f"{loc_text} · {isp_text}"
    elif loc_text:
        geo_label = loc_text
    elif isp_text:
        geo_label = isp_text
    else:
        geo_label = ""
    return country, country_name, region, city, isp, asn, geo_label


def _enrich_socket_ips_geoip(security: Dict[str, object], allow_network: bool = True) -> None:
    """Populate country, province/region, and ISP/ASN metadata on top inbound/outbound socket IPs."""
    if not isinstance(security, dict):
        return
    is_trackable_fn = _agent_attr("_is_trackable_ip", _fallback_is_trackable_ip)
    is_public_fn = _agent_attr("_is_public_source_ip", _fallback_is_public_source_ip)
    parse_ep_fn = _agent_attr("_parse_socket_endpoint", _fallback_parse_socket_endpoint)
    detail_map_fn = _agent_attr("_geoip_detail_map", _geoip_detail_map)
    local_batch_fn = _agent_attr("_geoip_local_country_batch", _geoip_local_country_batch)
    detail_cache = _agent_attr("_geoip_detail_cache", _geoip_detail_cache)
    badge_fn = _agent_attr("_format_geoip_badge", _format_geoip_badge)

    comm_sockets = security.get("communication_sockets") if isinstance(security.get("communication_sockets"), list) else []
    inbound_top = security.get("inbound_top_ips") if isinstance(security.get("inbound_top_ips"), list) else []
    outbound_top = security.get("outbound_top_ips") if isinstance(security.get("outbound_top_ips"), list) else []

    if not outbound_top and comm_sockets:
        out_map: Dict[str, Dict[str, Any]] = {}
        for sock in comm_sockets:
            if not isinstance(sock, dict) or sock.get("direction") != "outbound":
                continue
            rip = str(sock.get("remote_ip") or "")
            if not is_trackable_fn(rip):
                continue
            _, rport = parse_ep_fn(str(sock.get("remote") or ""))
            state_str = str(sock.get("state") or "").upper()
            info = out_map.setdefault(
                rip,
                {"connections": 0, "established_connections": 0, "syn_sent_connections": 0, "ports": set()},
            )
            info["connections"] += 1
            if rport > 0:
                info["ports"].add(rport)
            if state_str in ("ESTAB", "ESTABLISHED") or sock.get("proto") == "udp":
                info["established_connections"] += 1
            elif state_str in ("SYN-SENT", "SYN_SENT"):
                info["syn_sent_connections"] += 1
        outbound_top = [
            {
                "ip": ip,
                "connections": int(info["connections"]),
                "established_connections": int(info["established_connections"]),
                "syn_sent_connections": int(info["syn_sent_connections"]),
                "ports": sorted(info["ports"])[:6],
            }
            for ip, info in sorted(
                out_map.items(),
                key=lambda item: (int(item[1]["connections"]), int(item[1]["established_connections"])),
                reverse=True,
            )[:20]
        ]
        security["outbound_top_ips"] = outbound_top

    if not inbound_top and comm_sockets:
        in_map: Dict[str, Dict[str, Any]] = {}
        for sock in comm_sockets:
            if not isinstance(sock, dict) or sock.get("direction") != "inbound":
                continue
            rip = str(sock.get("remote_ip") or "")
            if not is_trackable_fn(rip):
                continue
            state_str = str(sock.get("state") or "").upper()
            info = in_map.setdefault(
                rip,
                {"connections": 0, "established_connections": 0, "syn_recv_connections": 0, "local_ports": set()},
            )
            info["connections"] += 1
            _, lport = parse_ep_fn(str(sock.get("local") or ""))
            if lport > 0:
                info["local_ports"].add(lport)
            if state_str in ("ESTAB", "ESTABLISHED"):
                info["established_connections"] += 1
            elif state_str in ("SYN-RECV", "SYN_RECV"):
                info["syn_recv_connections"] += 1
        inbound_top = [
            {
                "ip": ip,
                "connections": int(info["connections"]),
                "established_connections": int(info["established_connections"]),
                "syn_recv_connections": int(info["syn_recv_connections"]),
                "local_ports": sorted(info["local_ports"])[:6],
            }
            for ip, info in sorted(
                in_map.items(),
                key=lambda item: (int(item[1]["connections"]), int(item[1]["established_connections"])),
                reverse=True,
            )[:20]
        ]
        security["inbound_top_ips"] = inbound_top

    candidate_ips: List[str] = []
    for item in list(inbound_top[:8]) + list(outbound_top[:8]):
        if not isinstance(item, dict):
            continue
        ip_str = str(item.get("ip") or "").strip()
        if not is_public_fn(ip_str):
            continue
        if not (item.get("isp") or item.get("region") or item.get("geo_label")):
            candidate_ips.append(ip_str)

    resolved_map: Dict[str, Dict[str, str]] = {}
    if candidate_ips:
        if allow_network:
            resolved_map = detail_map_fn(candidate_ips)
        else:
            now_mono = time.monotonic()
            local_countries = local_batch_fn(candidate_ips)
            for ip_str in dict.fromkeys(candidate_ips):
                cached = detail_cache.get(ip_str)
                if cached and cached[1] > now_mono:
                    resolved_map[ip_str] = dict(cached[0])
                elif local_countries.get(ip_str):
                    resolved_map[ip_str] = {
                        "country": str(local_countries[ip_str]),
                        "region": "",
                        "city": "",
                        "isp": "",
                        "asn": "",
                    }

    for ip_list in (inbound_top[:10], outbound_top[:10]):
        for item in ip_list:
            if not isinstance(item, dict):
                continue
            ip_str = str(item.get("ip") or "").strip()
            if not ip_str:
                continue
            merged = dict(resolved_map.get(ip_str) or {})
            for k in ("country", "region", "city", "isp", "asn"):
                if item.get(k) and not merged.get(k):
                    merged[k] = str(item.get(k))
            country, country_name, region, city, isp, asn, geo_label = badge_fn(merged)
            item["country"] = country
            item["country_name"] = country_name
            item["region"] = region
            item["city"] = city
            item["isp"] = isp
            item["asn"] = asn
            item["geo_label"] = geo_label
