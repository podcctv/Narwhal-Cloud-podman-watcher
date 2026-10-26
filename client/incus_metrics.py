"""Parsing helpers for Incus OpenMetrics samples.

Keeping the parser independent lets runtime collection and unit fixtures use
the same mapping without coupling metric decoding to the agent orchestrator.
"""
import json
import re
from typing import Dict, Tuple

_PROM_LABEL_RE = re.compile(r'(\w+)="((?:\\.|[^"\\])*)"')


def parse_prometheus_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for match in _PROM_LABEL_RE.finditer(raw or ""):
        value = match.group(2)
        try:
            value = json.loads(f'"{value}"')
        except Exception:
            pass
        labels[match.group(1)] = value
    return labels


def parse_incus_metrics(text: str) -> Dict[Tuple[str, str], Dict[str, float]]:
    """Parse the subset of Incus OpenMetrics used by this agent."""
    result: Dict[Tuple[str, str], Dict[str, float]] = {}
    wanted = {
        "incus_cpu_seconds_total",
        "incus_cpu_effective_total",
        "incus_memory_MemTotal_bytes",
        "incus_memory_MemAvailable_bytes",
        "incus_network_receive_bytes_total",
        "incus_network_transmit_bytes_total",
        "incus_network_receive_packets_total",
        "incus_network_transmit_packets_total",
        "incus_filesystem_size_bytes",
        "incus_filesystem_avail_bytes",
    }
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)", line)
        if not match or match.group(1) not in wanted:
            continue
        metric, raw_labels, raw_value = match.groups()
        try:
            value = float(raw_value)
        except ValueError:
            continue
        labels = parse_prometheus_labels(raw_labels or "")
        if labels.get("type") not in (None, "container"):
            continue
        name = labels.get("name", "")
        if not name:
            continue
        project = labels.get("project", "default")
        item = result.setdefault(
            (project, name),
            {
                "cpu_seconds": 0.0,
                "effective_cpus": 0.0,
                "mem_bytes": 0.0,
                "mem_total_bytes": 0.0,
                "mem_available_bytes": -1.0,
                "net_rx_total_bytes": 0.0,
                "net_tx_total_bytes": 0.0,
                "net_rx_total_packets": 0.0,
                "net_tx_total_packets": 0.0,
                "fs_total_bytes": 0.0,
                "fs_avail_bytes": 0.0,
            },
        )
        if metric == "incus_cpu_seconds_total":
            if labels.get("mode", "") != "idle":
                item["cpu_seconds"] += value
        elif metric == "incus_cpu_effective_total":
            item["effective_cpus"] = value
        elif metric == "incus_memory_MemTotal_bytes":
            item["mem_total_bytes"] = value
        elif metric == "incus_memory_MemAvailable_bytes":
            item["mem_available_bytes"] = value
        elif metric == "incus_network_receive_bytes_total":
            if labels.get("device") != "lo":
                item["net_rx_total_bytes"] += value
        elif metric == "incus_network_transmit_bytes_total":
            if labels.get("device") != "lo":
                item["net_tx_total_bytes"] += value
        elif metric == "incus_network_receive_packets_total":
            if labels.get("device") != "lo":
                item["net_rx_total_packets"] += value
        elif metric == "incus_network_transmit_packets_total":
            if labels.get("device") != "lo":
                item["net_tx_total_packets"] += value
        elif metric == "incus_filesystem_size_bytes":
            item["fs_total_bytes"] = max(item["fs_total_bytes"], value)
        elif metric == "incus_filesystem_avail_bytes":
            item["fs_avail_bytes"] = max(item["fs_avail_bytes"], value)
    for item in result.values():
        total = float(item.get("mem_total_bytes", 0.0) or 0.0)
        available = float(item.get("mem_available_bytes", -1.0))
        if total > 0 and available >= 0:
            item["mem_bytes"] = max(0.0, min(total, total - available))
    return result
