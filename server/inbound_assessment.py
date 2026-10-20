"""Bounded, conservative classification of inbound source behaviour.

This classifies observed transport behaviour only. It cannot identify a customer
or prove intent; application authentication/access logs are required for that.
"""
from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from typing import Any, Iterable


LOOKBACK_SECONDS = 10 * 60
MAX_REPORTS = 60
MIN_REPEAT_SAMPLES = 2
MIN_REPEAT_SPAN_SECONDS = 15


def _public_ip(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address.compressed if address.is_global else ""
    except ValueError:
        return ""


def _ports(values: Any) -> set[int]:
    if not isinstance(values, list):
        return set()
    return {
        int(value)
        for value in values[:32]
        if type(value) is int and 0 < value <= 65535
    }


def _row_payload(row: Any) -> tuple[int, dict[str, Any]] | None:
    try:
        sampled_at = int(row["ts"])
        payload = json.loads(row["payload_json"] or "{}")
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return sampled_at, payload


def assess(rows: Iterable[Any], *, now: int, lookback_seconds: int = LOOKBACK_SECONDS) -> dict[str, Any]:
    """Summarize repeated source signals from a bounded set of report rows."""
    lower_bound = max(0, int(now) - max(60, min(int(lookback_seconds), 3600)))
    parsed_rows: dict[int, dict[str, Any]] = {}
    for row in list(rows)[:MAX_REPORTS]:
        parsed = _row_payload(row)
        if parsed is None:
            continue
        sampled_at, payload = parsed
        if lower_bound <= sampled_at <= int(now):
            parsed_rows[sampled_at] = payload

    source_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    valid_conntrack_times: set[int] = set()
    all_times: set[int] = set(parsed_rows)
    for sampled_at, payload in sorted(parsed_rows.items()):
        security = payload.get("security")
        if not isinstance(security, dict):
            continue
        signals = security.get("inbound_source_signals")
        if not isinstance(signals, list):
            continue
        if security.get("host_conntrack_available") is not True:
            continue
        valid_conntrack_times.add(sampled_at)
        listeners = _ports(security.get("listening_ports"))
        service_listeners = security.get("service_listeners")
        for item in service_listeners[:100] if isinstance(service_listeners, list) else []:
            # These source signals are TCP conntrack counters. Do not let a
            # UDP-only listener make a TCP destination look like service use.
            if isinstance(item, dict) and str(item.get("proto") or "").lower() == "tcp":
                listeners.update(_ports([item.get("port")]))
        for signal in signals[:20]:
            if not isinstance(signal, dict):
                continue
            evidence = signal.get("evidence_sources")
            if signal.get("scope") != "single_conntrack_snapshot" or not isinstance(evidence, list) or "host_conntrack" not in evidence:
                continue
            ip = _public_ip(signal.get("ip"))
            if not ip:
                continue
            container_ports = _ports(signal.get("container_ports"))
            service_ports = container_ports & listeners
            non_listener_ports = container_ports - listeners
            try:
                established = max(0, min(int(signal.get("tcp_established_flows") or 0), 1_000_000))
                unreplied = max(0, min(int(signal.get("tcp_unreplied_flows") or 0), 1_000_000))
                pending = max(0, min(int(signal.get("tcp_handshake_pending_flows") or 0), 1_000_000))
                reply_packets = max(0, min(int(signal.get("reply_packets") or 0), 1_000_000_000))
            except (TypeError, ValueError, OverflowError):
                continue
            incomplete = unreplied + pending
            service_activity = established > 0 and reply_packets > 0 and bool(service_ports)
            multiport_probe = (
                len(non_listener_ports) >= 3
                and incomplete >= 3
                and incomplete >= max(1, established * 2)
            )
            source_samples[ip].append({
                "sampled_at": sampled_at,
                "service_activity": service_activity,
                "multiport_probe": multiport_probe,
                "service_ports": sorted(service_ports),
                "non_listener_ports": sorted(non_listener_ports),
                "established": established,
                "incomplete": incomplete,
                "reply_packets": reply_packets,
            })

    assessments = []
    for ip, observations in source_samples.items():
        # Reports are de-duplicated by timestamp above. Keep one entry per
        # source/sample in case an agent ever emits duplicate source records.
        by_time = {int(item["sampled_at"]): item for item in observations}
        observations = [by_time[key] for key in sorted(by_time)]
        service_observations = [item for item in observations if item["service_activity"]]
        probe_observations = [item for item in observations if item["multiport_probe"]]
        span = observations[-1]["sampled_at"] - observations[0]["sampled_at"] if len(observations) > 1 else 0
        repeated = len(observations) >= MIN_REPEAT_SAMPLES and span >= MIN_REPEAT_SPAN_SECONDS
        repeated_service = repeated and len(service_observations) >= MIN_REPEAT_SAMPLES
        repeated_probe = repeated and len(probe_observations) >= MIN_REPEAT_SAMPLES
        if repeated and service_observations and probe_observations:
            classification = "mixed_repeated_service_and_probe_clues"
        elif repeated_service:
            classification = "repeated_bidirectional_service_port_activity"
        elif repeated_probe:
            classification = "repeated_uncompleted_multiport_probe"
        elif service_observations and probe_observations:
            classification = "mixed_single_sample_clues"
        else:
            classification = "insufficient_evidence"
        assessments.append({
            "ip": ip,
            "classification": classification,
            "confidence": "moderate" if repeated_service or repeated_probe or classification == "mixed_repeated_service_and_probe_clues" else "low",
            "sample_count": len(observations),
            "sample_span_seconds": max(0, span),
            "service_activity_samples": len(service_observations),
            "probe_clue_samples": len(probe_observations),
            "service_ports": sorted({port for item in observations for port in item["service_ports"]})[:16],
            "non_listener_ports": sorted({port for item in observations for port in item["non_listener_ports"]})[:16],
            "max_established_flows": max((item["established"] for item in observations), default=0),
            "max_incomplete_flows": max((item["incomplete"] for item in observations), default=0),
            "identity_confirmed": False,
        })

    assessments.sort(
        key=lambda item: (
            item["classification"] != "repeated_uncompleted_multiport_probe",
            item["classification"] != "mixed_repeated_service_and_probe_clues",
            item["sample_count"],
        ),
        reverse=False,
    )
    assessments = assessments[:20]
    conntrack_times = sorted(valid_conntrack_times)
    conntrack_span = conntrack_times[-1] - conntrack_times[0] if len(conntrack_times) > 1 else 0
    return {
        "status": "available"
        if len(valid_conntrack_times) >= MIN_REPEAT_SAMPLES and conntrack_span >= MIN_REPEAT_SPAN_SECONDS
        else "insufficient_history",
        "lookback_seconds": max(60, min(int(lookback_seconds), 3600)),
        "report_sample_count": len(all_times),
        "conntrack_sample_count": len(valid_conntrack_times),
        "conntrack_sample_span_seconds": max(0, conntrack_span),
        "first_sampled_at": min(all_times) if all_times else 0,
        "last_sampled_at": max(all_times) if all_times else 0,
        "minimum_repeat_samples": MIN_REPEAT_SAMPLES,
        "minimum_repeat_span_seconds": MIN_REPEAT_SPAN_SECONDS,
        "assessments": assessments,
        "identity_confirmed": False,
        "requires_application_auth_logs": True,
    }
