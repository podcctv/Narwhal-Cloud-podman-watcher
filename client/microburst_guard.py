"""High-Frequency Micro-burst Traffic and Small-Packet Flood Sensor for Containers.

Monitors container network packet ratios and burst deltas (PPS spikes, small-packet
floods such as SYN/UDP reflection or amplification attacks) that evade normal
5-minute averaging.
"""

from __future__ import annotations

import time
from typing import Any

# State cache: key = f"{runtime}:{name}" -> history dict
_BURST_STATES: dict[str, dict[str, Any]] = {}
PPS_HIGH_WATERMARK = 5000       # >5,000 PPS instantaneous is a micro-burst
SMALL_PACKET_FLOOD_BYTES = 128  # Average packet size < 128 bytes during high PPS indicates flood


def detect_microburst(
    runtime: str,
    name: str,
    rx_packets: int,
    tx_packets: int,
    rx_bytes: int,
    tx_bytes: int,
    now: float | None = None,
) -> dict[str, Any]:
    """Detect high-frequency microburst or small-packet floods."""
    runtime_name = str(runtime or "").strip().lower()
    container_name = str(name or "").strip()
    if not container_name:
        return {"detected": False, "reason": "empty container name"}

    current_time = time.monotonic() if now is None else now
    key = f"{runtime_name}:{container_name}"

    prev = _BURST_STATES.get(key)
    _BURST_STATES[key] = {
        "ts": current_time,
        "rx_pkts": rx_packets,
        "tx_pkts": tx_packets,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }

    if not prev:
        return {
            "detected": False,
            "rx_pps": 0.0,
            "tx_pps": 0.0,
            "flood_type": "none",
            "threat_level": "normal",
        }

    dt = current_time - prev["ts"]
    if dt < 0.1:  # Protect against divide by near-zero
        return {
            "detected": False,
            "rx_pps": 0.0,
            "tx_pps": 0.0,
            "flood_type": "none",
            "threat_level": "normal",
        }

    delta_rx_pkts = max(0, rx_packets - prev["rx_pkts"])
    delta_tx_pkts = max(0, tx_packets - prev["tx_pkts"])
    delta_rx_bytes = max(0, rx_bytes - prev["rx_bytes"])
    delta_tx_bytes = max(0, tx_bytes - prev["tx_bytes"])

    rx_pps = round(delta_rx_pkts / dt, 1)
    tx_pps = round(delta_tx_pkts / dt, 1)

    avg_tx_pkt_size = round(delta_tx_bytes / delta_tx_pkts, 1) if delta_tx_pkts > 0 else 0.0
    avg_rx_pkt_size = round(delta_rx_bytes / delta_rx_pkts, 1) if delta_rx_pkts > 0 else 0.0

    detected = False
    flood_type = "none"
    threat_level = "normal"

    # 1. Outbound small packet flood (SYN flood, UDP reflection flood, DNS query flood)
    if tx_pps >= 3000 and 0 < avg_tx_pkt_size <= SMALL_PACKET_FLOOD_BYTES:
        detected = True
        flood_type = "outbound_small_packet_flood"
        threat_level = "critical" if tx_pps >= 8000 else "high"
    # 2. General high-rate micro-burst (>5000 PPS)
    elif tx_pps >= PPS_HIGH_WATERMARK:
        detected = True
        flood_type = "high_pps_outbound_burst"
        threat_level = "warning"
    # 3. Inbound flood
    elif rx_pps >= PPS_HIGH_WATERMARK:
        detected = True
        flood_type = "inbound_traffic_spike"
        threat_level = "info"

    return {
        "detected": detected,
        "flood_type": flood_type,
        "threat_level": threat_level,
        "rx_pps": rx_pps,
        "tx_pps": tx_pps,
        "avg_tx_packet_size": avg_tx_pkt_size,
        "avg_rx_packet_size": avg_rx_pkt_size,
        "sampled_interval_sec": round(dt, 2),
    }


def clear_state(runtime: str = "", name: str = "") -> None:
    if runtime and name:
        _BURST_STATES.pop(f"{runtime}:{name}", None)
    else:
        _BURST_STATES.clear()

