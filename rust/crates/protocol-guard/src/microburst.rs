//! High-frequency micro-burst traffic and small-packet flood sensor for containers.
//!
//! Migrated from `client/microburst_guard.py`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::JsonBuilder;

/// Instantaneous PPS watermark (>5,000 PPS is a micro-burst).
pub const PPS_HIGH_WATERMARK: f64 = 5000.0;
/// Average packet size threshold during high PPS indicating a small-packet flood.
pub const SMALL_PACKET_FLOOD_BYTES: f64 = 128.0;

#[derive(Debug, Clone, PartialEq)]
struct BurstSample {
    ts: f64,
    rx_pkts: u64,
    tx_pkts: u64,
    rx_bytes: u64,
    tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MicroburstResult {
    pub detected: bool,
    pub reason: String,
    pub flood_type: String,
    pub threat_level: String,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub avg_tx_packet_size: f64,
    pub avg_rx_packet_size: f64,
    pub sampled_interval_sec: f64,
    pub initialized: bool,
}

impl MicroburstResult {
    fn empty_name() -> Self {
        Self {
            detected: false,
            reason: "empty container name".to_string(),
            flood_type: "none".to_string(),
            threat_level: "normal".to_string(),
            rx_pps: 0.0,
            tx_pps: 0.0,
            avg_tx_packet_size: 0.0,
            avg_rx_packet_size: 0.0,
            sampled_interval_sec: 0.0,
            initialized: false,
        }
    }

    fn baseline() -> Self {
        Self {
            detected: false,
            reason: String::new(),
            flood_type: "none".to_string(),
            threat_level: "normal".to_string(),
            rx_pps: 0.0,
            tx_pps: 0.0,
            avg_tx_packet_size: 0.0,
            avg_rx_packet_size: 0.0,
            sampled_interval_sec: 0.0,
            initialized: false,
        }
    }

    /// Serializes to JSON matching `container.security.microburst`.
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.bool("detected", self.detected);
        if !self.reason.is_empty() {
            b.str("reason", &self.reason);
            return b.finish();
        }
        b.str("flood_type", &self.flood_type);
        b.str("threat_level", &self.threat_level);
        b.f64("rx_pps", self.rx_pps);
        b.f64("tx_pps", self.tx_pps);
        if self.initialized {
            b.f64("avg_tx_packet_size", self.avg_tx_packet_size);
            b.f64("avg_rx_packet_size", self.avg_rx_packet_size);
            b.f64("sampled_interval_sec", self.sampled_interval_sec);
        }
        b.finish()
    }
}

fn round_1(val: f64) -> f64 {
    if !val.is_finite() || val == 0.0 {
        0.0
    } else {
        let r = (val * 10.0).round() / 10.0;
        if r == 0.0 { 0.0 } else { r }
    }
}

fn round_2(val: f64) -> f64 {
    if !val.is_finite() || val == 0.0 {
        0.0
    } else {
        let r = (val * 100.0).round() / 100.0;
        if r == 0.0 { 0.0 } else { r }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MicroburstDetector {
    states: HashMap<String, BurstSample>,
}

impl MicroburstDetector {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    pub fn detect_microburst(
        &mut self,
        runtime: &str,
        name: &str,
        rx_packets: u64,
        tx_packets: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        now_secs: f64,
    ) -> MicroburstResult {
        let runtime_name = runtime.trim().to_ascii_lowercase();
        let container_name = name.trim();
        if container_name.is_empty() {
            return MicroburstResult::empty_name();
        }

        let key = format!("{runtime_name}:{container_name}");
        let prev = self.states.insert(
            key,
            BurstSample {
                ts: now_secs,
                rx_pkts: rx_packets,
                tx_pkts: tx_packets,
                rx_bytes,
                tx_bytes,
            },
        );

        let Some(prev) = prev else {
            return MicroburstResult::baseline();
        };

        let dt = now_secs - prev.ts;
        if !dt.is_finite() || dt < 0.1 {
            return MicroburstResult::baseline();
        }

        let delta_rx_pkts = rx_packets.saturating_sub(prev.rx_pkts);
        let delta_tx_pkts = tx_packets.saturating_sub(prev.tx_pkts);
        let delta_rx_bytes = rx_bytes.saturating_sub(prev.rx_bytes);
        let delta_tx_bytes = tx_bytes.saturating_sub(prev.tx_bytes);

        let rx_pps = round_1((delta_rx_pkts as f64) / dt);
        let tx_pps = round_1((delta_tx_pkts as f64) / dt);

        let avg_tx_pkt_size = if delta_tx_pkts > 0 {
            round_1((delta_tx_bytes as f64) / (delta_tx_pkts as f64))
        } else {
            0.0
        };
        let avg_rx_pkt_size = if delta_rx_pkts > 0 {
            round_1((delta_rx_bytes as f64) / (delta_rx_pkts as f64))
        } else {
            0.0
        };

        let mut detected = false;
        let mut flood_type = "none";
        let mut threat_level = "normal";

        if tx_pps >= 3000.0 && avg_tx_pkt_size > 0.0 && avg_tx_pkt_size <= SMALL_PACKET_FLOOD_BYTES
        {
            detected = true;
            flood_type = "outbound_small_packet_flood";
            threat_level = if tx_pps >= 8000.0 { "critical" } else { "high" };
        } else if tx_pps >= PPS_HIGH_WATERMARK {
            detected = true;
            flood_type = "high_pps_outbound_burst";
            threat_level = "warning";
        } else if rx_pps >= PPS_HIGH_WATERMARK {
            detected = true;
            flood_type = "inbound_traffic_spike";
            threat_level = "info";
        }

        MicroburstResult {
            detected,
            reason: String::new(),
            flood_type: flood_type.to_string(),
            threat_level: threat_level.to_string(),
            rx_pps,
            tx_pps,
            avg_tx_packet_size: avg_tx_pkt_size,
            avg_rx_packet_size: avg_rx_pkt_size,
            sampled_interval_sec: round_2(dt),
            initialized: true,
        }
    }

    pub fn clear_state(&mut self, runtime: &str, name: &str) {
        let rt = runtime.trim().to_ascii_lowercase();
        let nm = name.trim();
        if !rt.is_empty() && !nm.is_empty() {
            self.states.remove(&format!("{rt}:{nm}"));
            self.states.remove(&format!("{runtime}:{name}"));
        } else {
            self.states.clear();
        }
    }
}

static GLOBAL_DETECTOR: Mutex<Option<MicroburstDetector>> = Mutex::new(None);

fn with_global_detector<F, R>(f: F) -> R
where
    F: FnOnce(&mut MicroburstDetector) -> R,
{
    let mut guard = match GLOBAL_DETECTOR.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let detector = guard.get_or_insert_with(MicroburstDetector::new);
    f(detector)
}

/// Module-level helper matching `microburst_guard.detect_microburst(...)`.
pub fn detect_microburst(
    runtime: &str,
    name: &str,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    now_secs: f64,
) -> MicroburstResult {
    with_global_detector(|det| {
        det.detect_microburst(
            runtime, name, rx_packets, tx_packets, rx_bytes, tx_bytes, now_secs,
        )
    })
}

/// Module-level helper matching `microburst_guard.clear_state(...)`.
pub fn clear_state(runtime: &str, name: &str) {
    with_global_detector(|det| det.clear_state(runtime, name));
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_drivers::JsonVal;

    #[test]
    fn test_empty_container_name() {
        let mut det = MicroburstDetector::new();
        let res = det.detect_microburst("runman", "", 0, 0, 0, 0, 100.0);
        assert!(!res.detected);
        assert_eq!(res.reason, "empty container name");
        let parsed = JsonVal::parse(&res.to_json()).unwrap();
        assert_eq!(parsed.get_bool("detected"), Some(false));
        assert_eq!(parsed.get_str("reason"), Some("empty container name"));
    }

    #[test]
    fn test_first_sample_initializes_and_short_dt_ignored() {
        let mut det = MicroburstDetector::new();
        let res = det.detect_microburst("runman", "vm-1", 1000, 1000, 50000, 50000, 100.0);
        assert!(!res.detected);
        assert_eq!(res.threat_level, "normal");
        assert_eq!(res.flood_type, "none");

        // dt < 0.1s should also return baseline normal without dividing by near-zero
        let res_short = det.detect_microburst("runman", "vm-1", 9000, 9000, 90000, 90000, 100.05);
        assert!(!res_short.detected);
        assert_eq!(res_short.threat_level, "normal");
    }

    #[test]
    fn test_small_packet_flood_and_burst_detection() {
        let mut det = MicroburstDetector::new();
        det.detect_microburst("runman", "vm-attack", 1000, 1000, 100000, 100000, 100.0);

        // 4,000 packets sent in 1s with 40 bytes/packet -> high outbound_small_packet_flood
        let res = det.detect_microburst(
            "runman", "vm-attack", 1200, 5000, 110000, 260000, 101.0,
        );
        assert!(res.detected);
        assert_eq!(res.flood_type, "outbound_small_packet_flood");
        assert_eq!(res.threat_level, "high");
        assert_eq!(res.tx_pps, 4000.0);
        assert_eq!(res.avg_tx_packet_size, 40.0);
        assert_eq!(res.sampled_interval_sec, 1.0);

        let parsed = JsonVal::parse(&res.to_json()).unwrap();
        assert_eq!(parsed.get_bool("detected"), Some(true));
        assert_eq!(parsed.get_str("flood_type"), Some("outbound_small_packet_flood"));
        assert_eq!(parsed.get_f64("tx_pps"), Some(4000.0));

        // >= 8,000 PPS small-packet flood escalates to critical
        let res_crit = det.detect_microburst(
            "runman", "vm-attack", 1300, 13000, 120000, 740000, 102.0,
        );
        assert!(res_crit.detected);
        assert_eq!(res_crit.flood_type, "outbound_small_packet_flood");
        assert_eq!(res_crit.threat_level, "critical");

        // Large-packet outbound burst >= 5000 PPS -> high_pps_outbound_burst (warning)
        let res_burst = det.detect_microburst(
            "runman", "vm-attack", 1400, 19000, 130000, 9_740_000, 103.0,
        );
        assert!(res_burst.detected);
        assert_eq!(res_burst.flood_type, "high_pps_outbound_burst");
        assert_eq!(res_burst.threat_level, "warning");

        // Inbound spike >= 5000 PPS -> inbound_traffic_spike (info)
        let res_in = det.detect_microburst(
            "runman", "vm-attack", 7400, 19100, 6_130_000, 9_800_000, 104.0,
        );
        assert!(res_in.detected);
        assert_eq!(res_in.flood_type, "inbound_traffic_spike");
        assert_eq!(res_in.threat_level, "info");
    }

    #[test]
    fn test_normal_traffic_and_clear_state() {
        let mut det = MicroburstDetector::new();
        det.detect_microburst("incus", "c-normal", 1000, 1000, 1000000, 1000000, 100.0);
        let res = det.detect_microburst("incus", "c-normal", 1100, 1100, 1100000, 1100000, 101.0);
        assert!(!res.detected);
        assert_eq!(res.threat_level, "normal");

        det.clear_state("incus", "c-normal");
        let after_clear =
            det.detect_microburst("incus", "c-normal", 99999, 99999, 9999999, 9999999, 102.0);
        assert!(!after_clear.detected);
        assert!(!after_clear.initialized);
    }
}
