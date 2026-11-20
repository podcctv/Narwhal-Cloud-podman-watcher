//! Conservative, namespace-local VMess/Trojan/Speedtest inbound & outbound nftables guard.
//!
//! Migrated from `client/vmess_guard.py` and `client/agent.py` (lines 1041-1243, 2025-2279,
//! 3965-4380, 4445-4786).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use app_guard::socks_detector::{
    is_listener_exposed, is_loopback_host, parse_endpoint, parse_inbound_protocols_json,
    parse_process_configs_json,
};
use net_guard::{CommandRunner, LiveCommandRunner, NetToolPaths};
use proc_probe::json_escape;
use runtime_drivers::JsonVal;
use transport::sha256_hex;

use crate::util::{
    bounded_int_from_json, current_unix_f64, ip_sort_key, is_global_ip, is_safe_abs_unix_path,
    is_safe_domain, json_str_list, truncate_chars, JsonBuilder,
};

pub const SUPPORTED_RUNTIMES: &[&str] = &["incus", "podman", "runman"];
pub const SUPPORTED_ENGINES: &[&str] = &["xray", "v2ray", "sing-box"];
pub const SUPPORTED_PROTOCOLS: &[&str] = &["vmess", "trojan"];
pub const SUPPORTED_GUARD_TYPES: &[&str] = &["vmess", "trojan", "speedtest"];

pub const MAX_ENDPOINTS: usize = 32;
pub const MAX_DESTINATION_IPS: usize = 256;
pub const MAX_DOMAIN_TARGETS: usize = 160;
pub const PROTOCOL_CLOCK_SAMPLE_MAX_SECONDS: f64 = 8.0;

pub fn is_supported_runtime(runtime: &str) -> bool {
    SUPPORTED_RUNTIMES.contains(&runtime.trim().to_ascii_lowercase().as_str())
}

pub fn is_supported_engine(engine: &str) -> bool {
    SUPPORTED_ENGINES.contains(&engine.trim().to_ascii_lowercase().as_str())
}

pub fn is_supported_protocol(proto: &str) -> bool {
    SUPPORTED_PROTOCOLS.contains(&proto.trim().to_ascii_lowercase().as_str())
}

pub fn is_supported_guard_type(kind: &str) -> bool {
    SUPPORTED_GUARD_TYPES.contains(&kind.trim().to_ascii_lowercase().as_str())
}

fn is_safe_scan_reason(reason: &str) -> bool {
    let bytes = reason.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Checks whether `addr` falls within one of the RFC documentation/benchmark sink networks:
/// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, or `2001:db8::/32`.
pub fn is_in_domain_sink_network(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

fn parse_sink_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if let Ok(v4) = trimmed.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if let Ok(v6) = trimmed.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    None
}

// ===========================================================================
// 1. Data structures for planning, reconciliation, evidence, and alerts
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredProtocol {
    pub pid: u32,
    pub process: String,
    pub protocol: String,
    pub port: u16,
    pub listen: String,
    pub transports: Option<Vec<String>>,
    pub port_config_complete: bool,
    pub config_file: String,
}

impl ConfiguredProtocol {
    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let protocol = obj.get("protocol")?.as_str()?.trim().to_ascii_lowercase();
        let pid = bounded_int_from_json(obj.get("pid"), 2, 4_194_304)? as u32;
        let port = bounded_int_from_json(obj.get("port"), 1, 65535)? as u16;
        let process = obj
            .get("process")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let listen = obj
            .get("listen")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("*")
            .to_string();
        let transports = match obj.get("transports") {
            Some(JsonVal::Arr(arr)) if !arr.is_empty() => {
                let mut set = BTreeSet::new();
                let mut valid = true;
                for item in arr {
                    let s = item.as_str().unwrap_or("").trim().to_ascii_lowercase();
                    if matches!(s.as_str(), "tcp" | "udp") {
                        set.insert(s);
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && !set.is_empty() {
                    Some(set.into_iter().collect())
                } else {
                    None
                }
            }
            _ => None,
        };
        let port_config_complete = obj.get("port_config_complete").and_then(JsonVal::as_bool) == Some(true);
        let config_file = obj
            .get("config_file")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();

        Some(Self {
            pid,
            process,
            protocol,
            port,
            listen,
            transports,
            port_config_complete,
            config_file,
        })
    }

    pub fn to_configured_endpoint_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.u64("pid", self.pid as u64);
        b.str("process", &self.process);
        b.u64("port", self.port as u64);
        match &self.transports {
            Some(ts) => b.raw("transports", &json_str_list(ts)),
            None => b.raw("transports", "null"),
        }
        b.bool("port_config_complete", self.port_config_complete);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceListener {
    pub pid: u32,
    pub process: String,
    pub proto: String,
    pub local: String,
    pub port: u16,
    pub application_protocols: Vec<String>,
    pub application_protocol_evidence: String,
    pub protocol_port_config_complete_protocols: Vec<String>,
    pub protocol_process_scan_complete: bool,
    pub vmess_process_scan_complete: bool,
    pub speedtest_process_scan_complete: bool,
}

impl ServiceListener {
    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let pid = bounded_int_from_json(obj.get("pid"), 0, 4_194_304).unwrap_or(0) as u32;
        let port = bounded_int_from_json(obj.get("port"), 1, 65535).unwrap_or(0) as u16;
        let process = obj
            .get("process")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let proto = obj
            .get("proto")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let local = obj
            .get("local")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let application_protocols = obj
            .get("application_protocols")
            .and_then(JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonVal::as_str)
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let application_protocol_evidence = obj
            .get("application_protocol_evidence")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let protocol_port_config_complete_protocols = obj
            .get("protocol_port_config_complete_protocols")
            .and_then(JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonVal::as_str)
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let protocol_process_scan_complete =
            obj.get("protocol_process_scan_complete").and_then(JsonVal::as_bool) == Some(true);
        let vmess_process_scan_complete =
            obj.get("vmess_process_scan_complete").and_then(JsonVal::as_bool) == Some(true);
        let speedtest_process_scan_complete =
            obj.get("speedtest_process_scan_complete").and_then(JsonVal::as_bool) == Some(true);

        Some(Self {
            pid,
            process,
            proto,
            local,
            port,
            application_protocols,
            application_protocol_evidence,
            protocol_port_config_complete_protocols,
            protocol_process_scan_complete,
            vmess_process_scan_complete,
            speedtest_process_scan_complete,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessScanState {
    pub pid: u32,
    pub process: String,
    pub state: String,
    pub start_ticks: String,
    pub reason: String,
    pub config_files: Vec<String>,
    pub clock_sample_source: String,
    pub clock_sample_reason: String,
}

impl ProcessScanState {
    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let pid = bounded_int_from_json(obj.get("pid"), 2, 4_194_304).unwrap_or(0) as u32;
        let process = obj
            .get("process")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let state = obj
            .get("state")
            .and_then(JsonVal::as_str)
            .unwrap_or("partial")
            .to_ascii_lowercase();
        let start_ticks = obj
            .get("start_ticks")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let reason = obj
            .get("reason")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let config_files = obj
            .get("config_files")
            .and_then(JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonVal::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let clock_sample_source = obj
            .get("clock_sample_source")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        let clock_sample_reason = obj
            .get("clock_sample_reason")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();
        Some(Self {
            pid,
            process,
            state,
            start_ticks,
            reason,
            config_files,
            clock_sample_source,
            clock_sample_reason,
        })
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.u64("pid", self.pid as u64);
        b.str("process", &self.process);
        b.str("state", &self.state);
        b.str("start_ticks", &self.start_ticks);
        b.str("reason", &self.reason);
        b.raw("config_files", &json_str_list(&self.config_files));
        if !self.clock_sample_source.is_empty() {
            b.str("clock_sample_source", &self.clock_sample_source);
        }
        if !self.clock_sample_reason.is_empty() {
            b.str("clock_sample_reason", &self.clock_sample_reason);
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardEndpoint {
    pub proto: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

impl GuardEndpoint {
    pub fn new_port(proto: impl Into<String>, port: u16) -> Self {
        Self {
            proto: proto.into(),
            port,
            pid: None,
            process: None,
        }
    }

    pub fn new_attributed(
        proto: impl Into<String>,
        port: u16,
        pid: u32,
        process: impl Into<String>,
    ) -> Self {
        Self {
            proto: proto.into(),
            port,
            pid: Some(pid),
            process: Some(process.into()),
        }
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("proto", &self.proto);
        b.u64("port", self.port as u64);
        if let Some(pid) = self.pid {
            b.u64("pid", pid as u64);
        }
        if let Some(ref proc_name) = self.process {
            if !proc_name.is_empty() {
                b.str("process", proc_name);
            }
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEndpoint {
    pub pid: Option<u32>,
    pub port: u16,
    pub proto: Option<String>,
    pub process: Option<String>,
    pub reason: String,
}

impl PendingEndpoint {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        if let Some(pid) = self.pid {
            b.u64("pid", pid as u64);
        }
        b.u64("port", self.port as u64);
        if let Some(ref proto) = self.proto {
            if !proto.is_empty() {
                b.str("proto", proto);
            }
        }
        if let Some(ref proc_name) = self.process {
            if !proc_name.is_empty() {
                b.str("process", proc_name);
            }
        }
        if !self.reason.is_empty() {
            b.str("reason", &self.reason);
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainTarget {
    pub domain: String,
    pub ip: String,
}

impl DomainTarget {
    pub fn new(domain: impl Into<String>, ip: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            ip: ip.into(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("domain", &self.domain);
        b.str("ip", &self.ip);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainHit {
    pub domain: String,
    pub packets: u64,
    pub bytes: u64,
}

impl DomainHit {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("domain", &self.domain);
        b.u64("packets", self.packets);
        b.u64("bytes", self.bytes);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationHit {
    pub ip: String,
    pub packets: u64,
    pub bytes: u64,
}

impl DestinationHit {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("ip", &self.ip);
        b.u64("packets", self.packets);
        b.u64("bytes", self.bytes);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceChain {
    pub configuration: String,
    pub configured_endpoint_count: usize,
    pub complete_configured_endpoint_count: usize,
    pub process_owner_and_listener: String,
    pub public_exposure: String,
    pub firewall_readback: String,
    pub listener_inventory_source: String,
    pub listener_inventory_reason: String,
    pub pending_endpoint_count: usize,
}

impl EvidenceChain {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("configuration", &self.configuration);
        b.usize("configured_endpoint_count", self.configured_endpoint_count);
        b.usize(
            "complete_configured_endpoint_count",
            self.complete_configured_endpoint_count,
        );
        b.str("process_owner_and_listener", &self.process_owner_and_listener);
        b.str("public_exposure", &self.public_exposure);
        b.str("firewall_readback", &self.firewall_readback);
        b.str("listener_inventory_source", &self.listener_inventory_source);
        b.str("listener_inventory_reason", &self.listener_inventory_reason);
        b.usize("pending_endpoint_count", self.pending_endpoint_count);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolGuardPlan {
    pub detected: bool,
    pub protocol: String,
    pub state: String,
    pub reason: String,
    pub blocked_endpoints: Vec<GuardEndpoint>,
    pub pending_endpoints: Vec<PendingEndpoint>,
    pub configured_endpoints: Vec<ConfiguredProtocol>,
    pub release_eligible: bool,
    pub listener_inventory_source: String,
    pub listener_inventory_reason: String,
    pub protocol_inventory_reason: String,
    pub evidence_chain: Option<EvidenceChain>,
}

impl ProtocolGuardPlan {
    pub fn to_json(&self) -> String {
        let blocked_json: Vec<String> = self
            .blocked_endpoints
            .iter()
            .map(GuardEndpoint::to_json)
            .collect();
        let pending_json: Vec<String> = self
            .pending_endpoints
            .iter()
            .map(PendingEndpoint::to_json)
            .collect();
        let configured_json: Vec<String> = self
            .configured_endpoints
            .iter()
            .map(ConfiguredProtocol::to_configured_endpoint_json)
            .collect();

        let mut b = JsonBuilder::new();
        b.bool("detected", self.detected);
        b.str("protocol", &self.protocol);
        b.str("state", &self.state);
        if !self.reason.is_empty() {
            b.str("reason", &self.reason);
        }
        b.raw("blocked_endpoints", &format!("[{}]", blocked_json.join(",")));
        b.raw("pending_endpoints", &format!("[{}]", pending_json.join(",")));
        b.raw(
            "configured_endpoints",
            &format!("[{}]", configured_json.join(",")),
        );
        b.bool("release_eligible", self.release_eligible);
        if !self.listener_inventory_source.is_empty() {
            b.str("listener_inventory_source", &self.listener_inventory_source);
        }
        if !self.listener_inventory_reason.is_empty() {
            b.str("listener_inventory_reason", &self.listener_inventory_reason);
        }
        if !self.protocol_inventory_reason.is_empty() {
            b.str("protocol_inventory_reason", &self.protocol_inventory_reason);
        }
        if let Some(ref ec) = self.evidence_chain {
            b.raw("evidence_chain", &ec.to_json());
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconcileOutcome {
    pub state: String,
    pub reason: String,
    pub blocked_endpoints: Vec<GuardEndpoint>,
    pub blocked_destination_ips: Vec<String>,
    pub blocked_domain_targets: Vec<DomainTarget>,
    pub blocked_domain_hits: Vec<DomainHit>,
    pub blocked_destination_hits: Vec<DestinationHit>,
    pub pending_removal_endpoints: Vec<GuardEndpoint>,
}

// ===========================================================================
// 2. Publicly reachable listener & `plan(...)`
// ===========================================================================

/// Matches `vmess_guard._publicly_reachable_listener(listener, network_exposure)`.
/// `forwards` entries are `(target_or_connect, listen)`.
pub fn publicly_reachable_listener(local: &str, forwards: &[(String, String)]) -> bool {
    let (host, port) = parse_endpoint(local);
    if host.is_empty() || port == 0 {
        return false;
    }
    if !is_loopback_host(&host) {
        return true;
    }
    is_listener_exposed(local, forwards) == Some(true)
}

/// Builds only unambiguous protected-protocol targets from config + live listener evidence.
/// Matches `vmess_guard.plan(...)`.
pub fn plan(
    runtime: &str,
    configured_protocols: &[ConfiguredProtocol],
    listeners: &[ServiceListener],
    network_exposure: &[(String, String)],
    scan_state: &str,
    process_scan_states: Option<&[ProcessScanState]>,
    listener_inventory_complete: Option<bool>,
    application_protocol: &str,
) -> ProtocolGuardPlan {
    let app_proto = application_protocol.trim().to_ascii_lowercase();
    if !is_supported_protocol(&app_proto) {
        return ProtocolGuardPlan {
            detected: false,
            protocol: app_proto,
            state: "unverified".to_string(),
            reason: "protocol_not_supported".to_string(),
            release_eligible: false,
            ..Default::default()
        };
    }

    let runtime_lower = runtime.trim().to_ascii_lowercase();
    let mut protected = Vec::new();
    for item in configured_protocols.iter().take(100) {
        if item.protocol.to_ascii_lowercase() != app_proto {
            continue;
        }
        let proc_lower = item.process.to_ascii_lowercase();
        if (2..=4_194_304).contains(&item.pid)
            && item.port > 0
            && is_supported_engine(&proc_lower)
        {
            let transports = item.transports.as_ref().and_then(|ts| {
                if ts.is_empty() {
                    return None;
                }
                let mut set = BTreeSet::new();
                for t in ts {
                    let tl = t.trim().to_ascii_lowercase();
                    if matches!(tl.as_str(), "tcp" | "udp") {
                        set.insert(tl);
                    } else {
                        return None;
                    }
                }
                Some(set.into_iter().collect::<Vec<String>>())
            });
            protected.push(ConfiguredProtocol {
                pid: item.pid,
                process: proc_lower,
                protocol: app_proto.clone(),
                port: item.port,
                listen: if item.listen.is_empty() {
                    "*".to_string()
                } else {
                    item.listen.clone()
                },
                transports,
                port_config_complete: item.port_config_complete,
                config_file: item.config_file.clone(),
            });
        }
    }

    let detected = !protected.is_empty();
    let configured_endpoints: Vec<ConfiguredProtocol> =
        protected.iter().take(MAX_ENDPOINTS).cloned().collect();
    let mut result = ProtocolGuardPlan {
        detected,
        protocol: app_proto.clone(),
        state: "not_detected".to_string(),
        blocked_endpoints: Vec::new(),
        pending_endpoints: Vec::new(),
        configured_endpoints,
        release_eligible: false,
        ..Default::default()
    };

    let has_scoped_scan_states = process_scan_states.is_some();
    let listener_snapshot_complete = if has_scoped_scan_states {
        listener_inventory_complete == Some(true)
    } else {
        listener_inventory_complete != Some(false)
    };

    if !detected {
        if scan_state == "complete" && listener_snapshot_complete {
            result.release_eligible = is_supported_runtime(&runtime_lower);
            return result;
        }
        result.state = "unverified".to_string();
        result.reason = "configuration_scan_incomplete".to_string();
        return result;
    }

    if !is_supported_runtime(&runtime_lower) {
        result.state = "unverified".to_string();
        result.reason = "runtime_not_supported".to_string();
        return result;
    }

    if !listener_snapshot_complete {
        result.state = "unverified".to_string();
        result.reason = "listener_inventory_incomplete".to_string();
        result.pending_endpoints = protected
            .iter()
            .take(20)
            .map(|item| PendingEndpoint {
                pid: Some(item.pid),
                port: item.port,
                proto: None,
                process: Some(item.process.clone()),
                reason: "listener_inventory_incomplete".to_string(),
            })
            .collect();
        return result;
    }

    let process_states: Option<BTreeMap<(u32, String), &ProcessScanState>> =
        process_scan_states.map(|states| {
            let mut map = BTreeMap::new();
            for st in states {
                if (2..=4_194_304).contains(&st.pid) {
                    map.insert((st.pid, st.process.to_ascii_lowercase()), st);
                }
            }
            map
        });

    if process_states.is_none() && scan_state != "complete" {
        result.state = "unverified".to_string();
        result.reason = "configuration_scan_incomplete".to_string();
        result.pending_endpoints = protected
            .iter()
            .take(20)
            .map(|item| PendingEndpoint {
                pid: Some(item.pid),
                port: item.port,
                proto: None,
                process: Some(item.process.clone()),
                reason: "configuration_scan_incomplete".to_string(),
            })
            .collect();
        return result;
    }

    let mut desired: BTreeMap<(String, u16), GuardEndpoint> = BTreeMap::new();
    let mut pending: Vec<PendingEndpoint> = Vec::new();
    let mut saw_loopback_only = false;

    for configured in &protected {
        let pid = configured.pid;
        let process = &configured.process;
        let port = configured.port;

        let mut process_state_verified = process_states.is_none() && scan_state == "complete";
        if let Some(ref pmap) = process_states {
            let proc_state = pmap.get(&(pid, process.clone())).copied();
            let proc_state_name = proc_state
                .map(|s| {
                    if s.state.is_empty() {
                        "partial".to_string()
                    } else {
                        s.state.to_ascii_lowercase()
                    }
                })
                .unwrap_or_else(|| "missing".to_string());
            let start_ticks = proc_state.map(|s| s.start_ticks.as_str()).unwrap_or("");
            let mut reason = proc_state
                .map(|s| s.reason.clone())
                .unwrap_or_default();
            process_state_verified = proc_state_name == "complete"
                && !start_ticks.is_empty()
                && start_ticks.bytes().all(|b| b.is_ascii_digit());
            let port_config_verified = configured.port_config_complete;
            if !process_state_verified && !port_config_verified {
                if !is_safe_scan_reason(&reason) {
                    reason = if proc_state_name == "missing" {
                        "process_scan_state_missing".to_string()
                    } else if proc_state_name == "complete" {
                        "process_start_generation_unavailable".to_string()
                    } else {
                        "configuration_scan_incomplete".to_string()
                    };
                }
                pending.push(PendingEndpoint {
                    pid: Some(pid),
                    port,
                    proto: None,
                    process: Some(process.clone()),
                    reason,
                });
                continue;
            }
        }

        let configured_transports: Option<BTreeSet<String>> = configured
            .transports
            .as_ref()
            .map(|ts| ts.iter().cloned().collect());

        let matches: Vec<&ServiceListener> = listeners
            .iter()
            .filter(|item| {
                let p_lower = item.proto.to_ascii_lowercase();
                item.pid == pid
                    && item.process.to_ascii_lowercase() == *process
                    && item.port == port
                    && matches!(p_lower.as_str(), "tcp" | "udp")
                    && configured_transports
                        .as_ref()
                        .map_or(true, |set| set.contains(&p_lower))
            })
            .collect();

        if matches.is_empty() {
            pending.push(PendingEndpoint {
                pid: Some(pid),
                port,
                proto: None,
                process: Some(process.clone()),
                reason: "live_listener_not_confirmed".to_string(),
            });
            continue;
        }

        for listener in matches {
            let transport = listener.proto.to_ascii_lowercase();
            let protocols: BTreeSet<String> = listener
                .application_protocols
                .iter()
                .map(|v| v.to_ascii_lowercase())
                .collect();
            let port_config_listener_verified = listener
                .protocol_port_config_complete_protocols
                .iter()
                .any(|v| v.to_ascii_lowercase() == app_proto);

            let single_proto_match = protocols.len() == 1 && protocols.contains(&app_proto);
            if listener.application_protocol_evidence != "config_matches_live_pid_and_port"
                || !single_proto_match
                || !(process_state_verified || port_config_listener_verified)
            {
                pending.push(PendingEndpoint {
                    pid: Some(pid),
                    port,
                    proto: None,
                    process: Some(process.clone()),
                    reason: "listener_protocol_or_owner_ambiguous".to_string(),
                });
                continue;
            }

            let config_collision = configured_protocols.iter().any(|item| {
                if item.pid != pid
                    || item.process.to_ascii_lowercase() != *process
                    || item.port != port
                    || item.protocol.to_ascii_lowercase() == app_proto
                {
                    return false;
                }
                match &item.transports {
                    Some(ts) => ts.iter().any(|t| t.to_ascii_lowercase() == transport),
                    None => true,
                }
            });
            if config_collision {
                pending.push(PendingEndpoint {
                    pid: Some(pid),
                    port,
                    proto: Some(transport),
                    process: Some(process.clone()),
                    reason: "shared_configured_port".to_string(),
                });
                continue;
            }

            let co_collision = listeners
                .iter()
                .filter(|item| item.proto.to_ascii_lowercase() == transport && item.port == port)
                .any(|item| {
                    let item_protos: BTreeSet<String> = item
                        .application_protocols
                        .iter()
                        .map(|v| v.to_ascii_lowercase())
                        .collect();
                    let only_app = item_protos.len() == 1 && item_protos.contains(&app_proto);
                    item.pid != pid
                        || item.process.to_ascii_lowercase() != *process
                        || item.application_protocol_evidence
                            != "config_matches_live_pid_and_port"
                        || !only_app
                });
            if co_collision {
                pending.push(PendingEndpoint {
                    pid: Some(pid),
                    port,
                    proto: Some(transport),
                    process: Some(process.clone()),
                    reason: "shared_live_listener".to_string(),
                });
                continue;
            }

            if !publicly_reachable_listener(&listener.local, network_exposure) {
                saw_loopback_only = true;
                continue;
            }

            desired.insert(
                (transport.clone(), port),
                GuardEndpoint::new_attributed(transport, port, pid, process.clone()),
            );
        }
    }

    let blocked: Vec<GuardEndpoint> = desired.into_values().collect();
    pending.truncate(20);

    if !blocked.is_empty() && !pending.is_empty() {
        result.state = "partial".to_string();
        result.reason = "some_endpoints_are_ambiguous".to_string();
    } else if !blocked.is_empty() {
        result.state = "candidate".to_string();
    } else if saw_loopback_only && pending.is_empty() {
        result.state = "internal_only".to_string();
        result.reason = "loopback_only_listener".to_string();
    } else if !pending.is_empty() {
        result.state = "unverified".to_string();
        result.reason = pending[0].reason.clone();
    } else {
        result.state = "not_detected".to_string();
    }

    result.blocked_endpoints = blocked;
    result.pending_endpoints = pending;
    result
}

// ===========================================================================
// 3. Config / Process Clock Verification (`client/agent.py` lines 3965-4786)
// ===========================================================================

/// Extracts field 22 (`start_ticks`) from `/proc/<pid>/stat` even when `comm`
/// contains spaces or `)` characters.
pub fn proc_stat_start_ticks(stat_text: &str) -> String {
    let raw = stat_text.trim();
    let Some(closing) = raw.rfind(')') else {
        return String::new();
    };
    if raw.get(closing + 1..closing + 2) != Some(" ") {
        return String::new();
    }
    let Some(rest) = raw.get(closing + 2..) else {
        return String::new();
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() <= 19 {
        return String::new();
    }
    let ticks = fields[19];
    if !ticks.is_empty()
        && ticks.bytes().all(|b| b.is_ascii_digit())
        && ticks.parse::<u64>().unwrap_or(0) > 0
    {
        ticks.to_string()
    } else {
        String::new()
    }
}

/// Parses `CLOCK_BOOTTIME` offset from `/proc/<pid>/timens_offsets`.
pub fn proc_boottime_namespace_offset(snapshot: &str) -> Option<f64> {
    for line in snapshot.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != "boottime" {
            continue;
        }
        let seconds: i64 = fields[1].parse().ok()?;
        let nanoseconds: i64 = fields[2].parse().ok()?;
        if !(-1_000_000_000..=1_000_000_000).contains(&seconds)
            || !(0..1_000_000_000).contains(&nanoseconds)
        {
            return None;
        }
        return Some((seconds as f64) + (nanoseconds as f64) / 1_000_000_000.0);
    }
    None
}

/// Normalizes `reader_boottime` into the target process's time namespace.
pub fn normalize_proc_boottime_for_target(
    reader_boottime: f64,
    target_offsets: &str,
    reader_offsets: &str,
    target_namespace_id: &str,
    reader_namespace_id: &str,
) -> (Option<f64>, &'static str) {
    let target_id = target_namespace_id.trim();
    let reader_id = reader_namespace_id.trim();
    let target_offset = proc_boottime_namespace_offset(target_offsets);
    let reader_offset = proc_boottime_namespace_offset(reader_offsets);
    let same_namespace = !target_id.is_empty() && !reader_id.is_empty() && target_id == reader_id;
    if same_namespace {
        if let (Some(t), Some(r)) = (target_offset, reader_offset) {
            if (t - r).abs() > 1e-9 {
                return (None, "time_namespace_offset_inconsistent");
            }
        }
        return (Some(reader_boottime), "");
    }
    let (Some(t), Some(r)) = (target_offset, reader_offset) else {
        return (None, "time_namespace_offset_unavailable");
    };
    (Some(reader_boottime + t - r), "")
}

/// Verifies that config `mtime` and `ctime` plus 3s quantization/clock margin
/// strictly predate `process_start_bound`.
pub fn protocol_config_predates_process(
    metadata: &str,
    process_start_bound: Option<f64>,
) -> bool {
    let Some(bound) = process_start_bound else {
        return false;
    };
    let mut parts_rev = metadata.rsplitn(3, '|');
    let Some(ctime_str) = parts_rev.next() else {
        return false;
    };
    let Some(mtime_str) = parts_rev.next() else {
        return false;
    };
    let Some(_prefix) = parts_rev.next() else {
        return false;
    };
    if ctime_str.is_empty()
        || mtime_str.is_empty()
        || !ctime_str.bytes().all(|b| b.is_ascii_digit())
        || !mtime_str.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Ok(mtime) = mtime_str.parse::<i64>() else {
        return false;
    };
    let Ok(ctime) = ctime_str.parse::<i64>() else {
        return false;
    };
    let changed_upper_bound = mtime.max(ctime) + 3;
    mtime.min(ctime) > 0 && (changed_upper_bound as f64) < bound
}

/// Evaluates a paired in-container proc stat + uptime + timens snapshot.
/// Matches `agent._protocol_process_start_epoch_lower_bound`.
pub fn evaluate_clock_snapshot(
    snapshot_text: &str,
    start_ticks: &str,
    realtime_before: f64,
    realtime_after: f64,
    ticks_per_second: f64,
) -> Result<f64, &'static str> {
    if start_ticks.is_empty()
        || !start_ticks.bytes().all(|b| b.is_ascii_digit())
        || start_ticks.parse::<u64>().unwrap_or(0) == 0
    {
        return Err("process_start_ticks_invalid");
    }
    let sample_elapsed = realtime_after - realtime_before;
    if snapshot_text.trim().is_empty() {
        return Err(
            if sample_elapsed >= PROTOCOL_CLOCK_SAMPLE_MAX_SECONDS * 0.95 {
                "runtime_exec_timeout"
            } else {
                "runtime_exec_no_snapshot"
            },
        );
    }
    let raw_snapshot = snapshot_text.lines().collect::<Vec<&str>>().join("\n");
    let Some((process_stat, rem1)) = raw_snapshot.split_once("@@UPTIME@@") else {
        return Err("clock_snapshot_marker_missing");
    };
    if proc_stat_start_ticks(process_stat) != start_ticks {
        return Err("process_generation_changed");
    }
    let Some((uptime_text, rem2)) = rem1.split_once("@@TARGET_TIMENS@@") else {
        return Err("clock_snapshot_marker_missing");
    };
    let Some((target_timens_text, rem3)) = rem2.split_once("@@SELF_TIMENS@@") else {
        return Err("clock_snapshot_marker_missing");
    };
    let Some((self_timens_text, rem4)) = rem3.split_once("@@TARGET_TIME_NS@@") else {
        return Err("clock_snapshot_marker_missing");
    };
    let Some((target_time_ns, self_time_ns)) = rem4.split_once("@@SELF_TIME_NS@@") else {
        return Err("clock_snapshot_marker_missing");
    };

    let uptime_fields: Vec<&str> = uptime_text.split_whitespace().collect();
    if uptime_fields.len() != 2 {
        return Err("uptime_snapshot_invalid");
    }
    let Ok(raw_boottime) = uptime_fields[0].parse::<f64>() else {
        return Err("clock_snapshot_invalid");
    };
    let Ok(ticks_u64) = start_ticks.parse::<u64>() else {
        return Err("clock_snapshot_invalid");
    };
    if !(1.0..=100_000.0).contains(&ticks_per_second) {
        return Err("clock_tick_rate_invalid");
    }
    let process_start = (ticks_u64 as f64) / ticks_per_second;
    if !(raw_boottime > 0.0 && raw_boottime < 1e10) {
        return Err("namespace_uptime_invalid");
    }

    let target_ns_id = target_time_ns
        .trim()
        .lines()
        .last()
        .map(str::trim)
        .unwrap_or("");
    let self_ns_id = self_time_ns
        .trim()
        .lines()
        .last()
        .map(str::trim)
        .unwrap_or("");
    let (Some(namespace_boottime), namespace_reason) = normalize_proc_boottime_for_target(
        raw_boottime,
        target_timens_text,
        self_timens_text,
        target_ns_id,
        self_ns_id,
    ) else {
        return Err("time_namespace_offset_unavailable");
    };
    let _ = namespace_reason;
    if !(namespace_boottime > 0.0 && namespace_boottime < 1e10) {
        return Err("namespace_uptime_invalid");
    }
    if !(process_start > 0.0 && process_start <= namespace_boottime) {
        return Err("process_start_outside_namespace_uptime");
    }
    if !(realtime_before > 946_684_800.0 && realtime_after > 946_684_800.0) {
        return Err("realtime_clock_unavailable");
    }
    if !(0.0..=PROTOCOL_CLOCK_SAMPLE_MAX_SECONDS).contains(&sample_elapsed) {
        return Err("clock_sample_elapsed_invalid");
    }

    Ok(realtime_before - namespace_boottime + process_start
        - sample_elapsed
        - 1.0 / ticks_per_second
        - 0.01)
}

/// Evaluates `evaluate_clock_snapshot` while preserving exact `time_namespace_offset_inconsistent`
/// vs `time_namespace_offset_unavailable` diagnostic reason codes.
pub fn evaluate_clock_snapshot_detailed(
    snapshot_text: &str,
    start_ticks: &str,
    realtime_before: f64,
    realtime_after: f64,
    ticks_per_second: f64,
) -> Result<f64, &'static str> {
    if let Some((_, rem1)) = snapshot_text
        .lines()
        .collect::<Vec<&str>>()
        .join("\n")
        .split_once("@@UPTIME@@")
    {
        if let Some((uptime_text, rem2)) = rem1.split_once("@@TARGET_TIMENS@@") {
            if let Some((target_timens_text, rem3)) = rem2.split_once("@@SELF_TIMENS@@") {
                if let Some((self_timens_text, rem4)) = rem3.split_once("@@TARGET_TIME_NS@@") {
                    if let Some((target_time_ns, self_time_ns)) =
                        rem4.split_once("@@SELF_TIME_NS@@")
                    {
                        if let Some(Ok(raw_boottime)) = uptime_text
                            .split_whitespace()
                            .next()
                            .map(str::parse::<f64>)
                        {
                            let target_ns_id = target_time_ns
                                .trim()
                                .lines()
                                .last()
                                .map(str::trim)
                                .unwrap_or("");
                            let self_ns_id = self_time_ns
                                .trim()
                                .lines()
                                .last()
                                .map(str::trim)
                                .unwrap_or("");
                            let (norm, reason) = normalize_proc_boottime_for_target(
                                raw_boottime,
                                target_timens_text,
                                self_timens_text,
                                target_ns_id,
                                self_ns_id,
                            );
                            if norm.is_none() && !reason.is_empty() {
                                // Only return the timens reason if earlier checks pass
                                match evaluate_clock_snapshot(
                                    snapshot_text,
                                    start_ticks,
                                    realtime_before,
                                    realtime_after,
                                    ticks_per_second,
                                ) {
                                    Err("time_namespace_offset_unavailable") => return Err(reason),
                                    other => return other,
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    evaluate_clock_snapshot(
        snapshot_text,
        start_ticks,
        realtime_before,
        realtime_after,
        ticks_per_second,
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostProcProcessEntry {
    pub host_pid: u32,
    pub pid: u32,
    pub process: String,
    pub start_ticks: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostClockEvidence {
    pub start_ticks: String,
    pub host_pid: u32,
    pub epoch_lower_bound: Option<f64>,
    pub reason: String,
}

/// Evaluates host `/proc` clock fallback for a container process (`_host_proc_protocol_process_start_epoch_lower_bound`).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_host_proc_clock_lower_bound(
    init_pid: u32,
    namespace_pid: u32,
    process_name: &str,
    scope_complete: bool,
    processes: &[HostProcProcessEntry],
    stat_before: &str,
    status_text: &str,
    comm_text: &str,
    uptime_text: &str,
    stat_after: &str,
    target_timens_text: &str,
    self_timens_text: &str,
    target_time_ns: &str,
    self_time_ns: &str,
    realtime_before: f64,
    realtime_after: f64,
    ticks_per_second: f64,
) -> HostClockEvidence {
    let reject = |reason: &str| HostClockEvidence {
        start_ticks: String::new(),
        host_pid: 0,
        epoch_lower_bound: None,
        reason: reason.to_string(),
    };

    if init_pid <= 1 || namespace_pid <= 1 || namespace_pid > 4_194_304 {
        return reject("host_process_identity_invalid");
    }
    if !scope_complete {
        return reject("host_process_scope_incomplete");
    }
    let target_name = process_name.trim().to_ascii_lowercase();
    let matches: Vec<&HostProcProcessEntry> = processes
        .iter()
        .filter(|item| {
            item.pid == namespace_pid
                && item.process.trim().to_ascii_lowercase() == target_name
                && !item.start_ticks.is_empty()
                && item.start_ticks.bytes().all(|b| b.is_ascii_digit())
                && (2..=4_194_304).contains(&item.host_pid)
        })
        .collect();
    if matches.len() != 1 {
        return reject("host_process_owner_unverified");
    }
    let matched = matches[0];
    let host_pid = matched.host_pid;
    let expected_ticks = matched.start_ticks.clone();

    let observed_ticks = proc_stat_start_ticks(stat_before);
    if observed_ticks.is_empty()
        || observed_ticks != expected_ticks
        || proc_stat_start_ticks(stat_after) != expected_ticks
    {
        return reject("host_process_generation_changed");
    }
    if comm_text.trim().to_ascii_lowercase() != target_name {
        return reject("host_process_owner_changed");
    }

    let mut actual_ns_pid = host_pid;
    for line in status_text.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            if let Some(last_tok) = rest.split_whitespace().last() {
                if let Ok(parsed) = last_tok.parse::<u32>() {
                    actual_ns_pid = parsed;
                }
            }
            break;
        }
    }
    if actual_ns_pid != namespace_pid {
        return reject("host_process_namespace_pid_changed");
    }

    let uptime_fields: Vec<&str> = uptime_text.split_whitespace().collect();
    if uptime_fields.len() != 2 {
        return reject("host_process_uptime_invalid");
    }
    let Ok(raw_boottime) = uptime_fields[0].parse::<f64>() else {
        return reject("host_process_clock_unavailable");
    };
    let (Some(namespace_boottime), ns_reason) = normalize_proc_boottime_for_target(
        raw_boottime,
        target_timens_text,
        self_timens_text,
        target_time_ns,
        self_time_ns,
    ) else {
        return reject("time_namespace_offset_unavailable");
    };
    let _ = ns_reason;
    if !(1.0..=100_000.0).contains(&ticks_per_second) {
        return reject("clock_tick_rate_invalid");
    }
    let Ok(ticks_u64) = expected_ticks.parse::<u64>() else {
        return reject("host_process_clock_unavailable");
    };
    let process_start = (ticks_u64 as f64) / ticks_per_second;
    if !(namespace_boottime > 0.0 && namespace_boottime < 1e10) {
        return reject("host_process_uptime_invalid");
    }
    if !(process_start > 0.0 && process_start <= namespace_boottime) {
        return reject("host_process_start_outside_uptime");
    }
    if !(realtime_before > 946_684_800.0 && realtime_after > 946_684_800.0) {
        return reject("realtime_clock_unavailable");
    }
    let sample_elapsed = realtime_after - realtime_before;
    if !(0.0..=PROTOCOL_CLOCK_SAMPLE_MAX_SECONDS).contains(&sample_elapsed) {
        return reject("clock_sample_elapsed_invalid");
    }

    let lower_bound = realtime_before - namespace_boottime + process_start
        - sample_elapsed
        - 1.0 / ticks_per_second
        - 0.01;
    HostClockEvidence {
        start_ticks: expected_ticks,
        host_pid,
        epoch_lower_bound: Some(lower_bound),
        reason: String::new(),
    }
}

/// Trait for executing bounded guest commands during protocol configuration evidence collection.
pub trait ProtocolConfigRunner {
    fn exec_guest(&mut self, command: &str, timeout_secs: u64) -> String;
    fn process_start_epoch_lower_bound(
        &mut self,
        pid: u32,
        start_ticks: &str,
    ) -> Result<f64, String>;
    fn host_fallback_clock(
        &mut self,
        _pid: u32,
        _process: &str,
    ) -> Option<HostClockEvidence> {
        None
    }
    fn host_process_matches(
        &mut self,
        _pid: u32,
        _process: &str,
        _host_pid: u32,
        _start_ticks: &str,
    ) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProtocolConfigEvidence {
    pub configured_inbound_protocols: Vec<ConfiguredProtocol>,
    pub protocol_process_scan_states: Vec<ProcessScanState>,
    pub protocol_inventory_state: String,
    pub protocol_inventory_reason: String,
}

/// Collects and validates per-process configuration and generation evidence for `xray`, `v2ray`,
/// and `sing-box` processes (`_collect_socks_config_evidence`).
pub fn collect_protocol_config_evidence(
    process_output: &str,
    runner: &mut dyn ProtocolConfigRunner,
) -> ProtocolConfigEvidence {
    let has_process_snapshot = !process_output.trim().is_empty();
    if !has_process_snapshot {
        return ProtocolConfigEvidence {
            configured_inbound_protocols: Vec::new(),
            protocol_process_scan_states: Vec::new(),
            protocol_inventory_state: "unavailable".to_string(),
            protocol_inventory_reason: "process_snapshot_unavailable".to_string(),
        };
    }

    let raw_configs = parse_process_configs_json(process_output);
    let parsed_configs = JsonVal::parse(&raw_configs)
        .ok()
        .and_then(|v| v.as_arr().map(|a| a.to_vec()))
        .unwrap_or_default();

    let process_list_complete = parsed_configs.len() < 8;
    let mut protocol_complete = process_list_complete;
    let mut inventory_reason = if process_list_complete {
        String::new()
    } else {
        "process_scan_limit_exceeded".to_string()
    };

    let mut configured_inbound_protocols: Vec<ConfiguredProtocol> = Vec::new();
    let mut scan_states: BTreeMap<(u32, String), ProcessScanState> = BTreeMap::new();

    for proc_val in &parsed_configs {
        let Some(obj) = proc_val.as_obj() else {
            continue;
        };
        let pid = bounded_int_from_json(obj.get("pid"), 2, 4_194_304).unwrap_or(0) as u32;
        let process = obj
            .get("process")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if pid <= 1 || !is_supported_engine(&process) {
            continue;
        }
        scan_states.insert(
            (pid, process.clone()),
            ProcessScanState {
                pid,
                process,
                state: "partial".to_string(),
                ..Default::default()
            },
        );
    }

    for proc_val in &parsed_configs {
        let Some(obj) = proc_val.as_obj() else {
            continue;
        };
        let pid = bounded_int_from_json(obj.get("pid"), 2, 4_194_304).unwrap_or(0) as u32;
        let process = obj
            .get("process")
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if pid <= 1 || !is_supported_engine(&process) {
            continue;
        }

        let additional_configs = obj.get("additional_configs").and_then(JsonVal::as_bool) == Some(true);
        let mut scan_paths: Vec<String> = obj
            .get("paths")
            .and_then(JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonVal::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let config_dirs: Vec<String> = obj
            .get("config_dirs")
            .and_then(JsonVal::as_arr)
            .map(|arr| {
                arr.iter()
                    .filter_map(JsonVal::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let process_endpoint_start = configured_inbound_protocols.len();
        let mut process_scan_reason = if additional_configs {
            "unparsed_or_excess_config_arguments".to_string()
        } else {
            String::new()
        };
        let mut directory_scan_complete = true;

        for directory in config_dirs.iter().take(4) {
            if !is_safe_abs_unix_path(directory) {
                directory_scan_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_directory_path_invalid".to_string();
                }
                continue;
            }
            let find_cmd = format!(
                "find '{directory}' -maxdepth 1 \\( -type f -o -type l \\) \\( -name '*.json' -o -name '*.yaml' -o -name '*.yml' -o -name '*.conf' -o -name '*.cfg' \\) -print 2>/dev/null; rc=$?; [ $rc -eq 0 ] && echo @@CONFIG_DIR_SCAN_OK@@"
            );
            let listing = runner.exec_guest(&find_cmd, 2);
            let lines: Vec<&str> = listing
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            let complete_marker = lines.contains(&"@@CONFIG_DIR_SCAN_OK@@");
            let found_paths: Vec<&str> = lines
                .into_iter()
                .filter(|&l| l != "@@CONFIG_DIR_SCAN_OK@@")
                .collect();
            let dir_prefix = format!("{}/", directory.trim_end_matches('/'));
            let valid_paths: Vec<String> = found_paths
                .iter()
                .copied()
                .filter(|p| is_safe_abs_unix_path(p) && p.starts_with(&dir_prefix))
                .map(String::from)
                .collect();
            if !complete_marker
                || found_paths.len() != valid_paths.len()
                || valid_paths.len() > 32
            {
                directory_scan_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_directory_unreadable_or_truncated".to_string();
                }
            }
            for vp in valid_paths.into_iter().take(32) {
                if !scan_paths.contains(&vp) {
                    scan_paths.push(vp);
                }
            }
        }

        if scan_paths.len() > 32 {
            scan_paths.truncate(32);
            directory_scan_complete = false;
            if process_scan_reason.is_empty() {
                process_scan_reason = "config_file_limit_exceeded".to_string();
            }
        }

        let mut process_protocol_complete = process_list_complete
            && !scan_paths.is_empty()
            && !additional_configs
            && directory_scan_complete;
        let mut process_port_config_complete = process_protocol_complete;

        if !process_protocol_complete {
            protocol_complete = false;
            if process_scan_reason.is_empty() {
                process_scan_reason = "config_path_not_found_or_unreadable".to_string();
            }
            if inventory_reason.is_empty() {
                inventory_reason = process_scan_reason.clone();
            }
        }

        let stat_before_out = runner.exec_guest(&format!("cat /proc/{pid}/stat 2>/dev/null"), 2);
        let start_ticks_before = proc_stat_start_ticks(&stat_before_out);

        let mut clock_sample_reason = String::new();
        let mut clock_sample_source = String::new();
        let mut process_start_bound: Option<f64> = match runner
            .process_start_epoch_lower_bound(pid, &start_ticks_before)
        {
            Ok(bound) => Some(bound),
            Err(reason) => {
                clock_sample_reason = reason;
                None
            }
        };

        let mut host_clock_ev: Option<HostClockEvidence> = None;
        if process_start_bound.is_none() {
            if let Some(hc) = runner.host_fallback_clock(pid, &process) {
                if let Some(bound) = hc.epoch_lower_bound {
                    if bound > 0.0 {
                        process_start_bound = Some(bound);
                        clock_sample_source = "host_proc".to_string();
                    }
                }
                if process_start_bound.is_none() && !hc.reason.is_empty() {
                    clock_sample_reason = hc.reason.clone();
                }
                host_clock_ev = Some(hc);
            }
        }

        for path in &scan_paths {
            let meta_before = runner
                .exec_guest(&format!("stat -Lc '%d:%i:%s|%Y|%Z' '{path}' 2>/dev/null"), 2)
                .trim()
                .to_string();
            if meta_before.is_empty() {
                process_protocol_complete = false;
                protocol_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_file_metadata_unavailable".to_string();
                }
                if inventory_reason.is_empty() {
                    inventory_reason = process_scan_reason.clone();
                }
            }

            let raw = runner.exec_guest(&format!("head -c 262145 '{path}' 2>/dev/null"), 2);

            let meta_after = runner
                .exec_guest(&format!("stat -Lc '%d:%i:%s|%Y|%Z' '{path}' 2>/dev/null"), 2)
                .trim()
                .to_string();
            if meta_after.is_empty() {
                process_protocol_complete = false;
                protocol_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_file_metadata_unavailable".to_string();
                }
                if inventory_reason.is_empty() {
                    inventory_reason = process_scan_reason.clone();
                }
            } else if !meta_before.is_empty() && meta_after != meta_before {
                process_protocol_complete = false;
                process_port_config_complete = false;
                protocol_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_file_changed_during_scan".to_string();
                }
                if inventory_reason.is_empty() {
                    inventory_reason = process_scan_reason.clone();
                }
            }

            if meta_before.is_empty() || meta_after.is_empty() {
                let raw_after =
                    runner.exec_guest(&format!("head -c 262145 '{path}' 2>/dev/null"), 2);
                if raw_after != raw {
                    process_port_config_complete = false;
                    if process_scan_reason.is_empty() {
                        process_scan_reason = "config_file_changed_during_scan".to_string();
                    }
                }
            }

            if !meta_before.is_empty() && meta_after == meta_before {
                if process_start_bound.is_none() {
                    process_protocol_complete = false;
                    protocol_complete = false;
                    if process_scan_reason.is_empty() {
                        process_scan_reason = "config_process_clock_unavailable".to_string();
                    }
                    if inventory_reason.is_empty() {
                        inventory_reason = process_scan_reason.clone();
                    }
                } else if !protocol_config_predates_process(&meta_after, process_start_bound) {
                    process_protocol_complete = false;
                    protocol_complete = false;
                    if process_scan_reason.is_empty() {
                        process_scan_reason = "config_not_known_before_process_start".to_string();
                    }
                    if inventory_reason.is_empty() {
                        inventory_reason = process_scan_reason.clone();
                    }
                }
            }

            let parsed_doc_str = parse_inbound_protocols_json(&raw, &process);
            let parsed_doc = JsonVal::parse(&parsed_doc_str).ok();
            let is_parsed = parsed_doc
                .as_ref()
                .and_then(|d| d.get_bool("parsed"))
                == Some(true);
            if !is_parsed {
                process_protocol_complete = false;
                process_port_config_complete = false;
                protocol_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "config_parse_failed_or_too_large".to_string();
                }
                if inventory_reason.is_empty() {
                    inventory_reason = process_scan_reason.clone();
                }
            }
            if let Some(arr) = parsed_doc
                .as_ref()
                .and_then(|d| d.get("endpoints"))
                .and_then(JsonVal::as_arr)
            {
                for ep in arr {
                    if configured_inbound_protocols.len() < 100 {
                        let proto = ep
                            .get_str("protocol")
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let port = ep.get_u64("port").unwrap_or(0) as u16;
                        let listen = ep.get_str("listen").unwrap_or("*").to_string();
                        let transports = ep
                            .get("transports")
                            .and_then(JsonVal::as_arr)
                            .map(|ts| {
                                ts.iter()
                                    .filter_map(JsonVal::as_str)
                                    .map(String::from)
                                    .collect()
                            });
                        configured_inbound_protocols.push(ConfiguredProtocol {
                            pid,
                            process: process.clone(),
                            protocol: proto,
                            port,
                            listen,
                            transports,
                            port_config_complete: false,
                            config_file: path.clone(),
                        });
                    } else {
                        process_protocol_complete = false;
                        process_port_config_complete = false;
                        protocol_complete = false;
                        if process_scan_reason.is_empty() {
                            process_scan_reason = "endpoint_report_limit_exceeded".to_string();
                        }
                        if inventory_reason.is_empty() {
                            inventory_reason = process_scan_reason.clone();
                        }
                    }
                }
            }
            if additional_configs {
                process_protocol_complete = false;
                process_port_config_complete = false;
                protocol_complete = false;
            }
        }

        let stat_after_out = runner.exec_guest(&format!("cat /proc/{pid}/stat 2>/dev/null"), 2);
        let start_ticks_after = proc_stat_start_ticks(&stat_after_out);
        let host_start_ticks = host_clock_ev
            .as_ref()
            .map(|h| h.start_ticks.clone())
            .unwrap_or_default();
        let host_pid = host_clock_ev.as_ref().map(|h| h.host_pid).unwrap_or(0);
        let host_generation_stable = host_start_ticks.is_empty()
            || runner.host_process_matches(pid, &process, host_pid, &host_start_ticks);

        let start_ticks = if !start_ticks_before.is_empty()
            && start_ticks_after == start_ticks_before
            && (host_start_ticks.is_empty() || host_start_ticks == start_ticks_before)
            && host_generation_stable
        {
            if !host_start_ticks.is_empty() {
                host_start_ticks.clone()
            } else {
                start_ticks_before.clone()
            }
        } else if start_ticks_before.is_empty()
            && start_ticks_after.is_empty()
            && !host_start_ticks.is_empty()
            && host_generation_stable
        {
            host_start_ticks.clone()
        } else {
            String::new()
        };

        if start_ticks.is_empty() {
            process_protocol_complete = false;
            protocol_complete = false;
            if !start_ticks_before.is_empty()
                || !start_ticks_after.is_empty()
                || !host_start_ticks.is_empty()
            {
                process_port_config_complete = false;
                if process_scan_reason.is_empty() {
                    process_scan_reason = "process_changed_during_config_scan".to_string();
                }
            } else if process_scan_reason.is_empty() {
                process_scan_reason = "process_start_generation_unavailable".to_string();
            }
            if inventory_reason.is_empty() {
                inventory_reason = process_scan_reason.clone();
            }
        }

        for endpoint in &mut configured_inbound_protocols[process_endpoint_start..] {
            if is_supported_protocol(&endpoint.protocol) {
                endpoint.port_config_complete = process_port_config_complete;
            }
        }

        let mut sorted_files = scan_paths;
        sorted_files.sort();
        sorted_files.dedup();
        sorted_files.truncate(32);

        let final_state = if process_protocol_complete {
            "complete".to_string()
        } else {
            protocol_complete = false;
            "partial".to_string()
        };
        let final_reason = if process_protocol_complete {
            String::new()
        } else if !process_scan_reason.is_empty() {
            process_scan_reason
        } else {
            "scan_incomplete".to_string()
        };

        scan_states.insert(
            (pid, process.clone()),
            ProcessScanState {
                pid,
                process,
                state: final_state,
                start_ticks,
                reason: final_reason,
                config_files: sorted_files,
                clock_sample_source,
                clock_sample_reason: if process_start_bound.is_none() {
                    clock_sample_reason
                } else {
                    String::new()
                },
            },
        );
    }

    let protocol_inventory_state = if protocol_complete {
        "complete".to_string()
    } else if has_process_snapshot {
        "partial".to_string()
    } else {
        "unavailable".to_string()
    };

    ProtocolConfigEvidence {
        configured_inbound_protocols,
        protocol_process_scan_states: scan_states.into_values().collect(),
        protocol_inventory_reason: if protocol_inventory_state == "complete" {
            String::new()
        } else {
            inventory_reason
        },
        protocol_inventory_state,
    }
}

// ===========================================================================
// 4. Namespace pinning, readback parsers, and `reconcile(...)`
// ===========================================================================

/// Computes `pid_epoch(pid)` from `/proc`: `{boot_id}:{net_ns_link}:{pid}:{start_ticks}`.
/// Returns `""` if `/proc/{pid}/ns/net` equals `/proc/1/ns/net` or cannot be read.
pub fn pid_epoch(pid: u32) -> String {
    pid_epoch_from(Path::new("/proc"), pid)
}

/// Testable implementation of `pid_epoch` reading from `proc_root`.
pub fn pid_epoch_from(proc_root: &Path, pid: u32) -> String {
    if pid <= 1 {
        return String::new();
    }
    let pid_net_path = proc_root.join(pid.to_string()).join("ns").join("net");
    let init_net_path = proc_root.join("1").join("ns").join("net");

    let read_ns_token = |p: &Path| -> Option<String> {
        if let Ok(link) = fs::read_link(p) {
            return Some(link.to_string_lossy().into_owned());
        }
        // Fallback for non-symlink test fixtures
        fs::read_to_string(p).ok().map(|s| s.trim().to_string())
    };

    let Some(namespace) = read_ns_token(&pid_net_path) else {
        return String::new();
    };
    let Some(init_ns) = read_ns_token(&init_net_path) else {
        return String::new();
    };
    if namespace.is_empty() || namespace == init_ns {
        return String::new();
    }

    let boot_path = proc_root
        .join("sys")
        .join("kernel")
        .join("random")
        .join("boot_id");
    let Ok(boot_raw) = fs::read_to_string(boot_path) else {
        return String::new();
    };
    let boot = boot_raw.trim();
    if boot.is_empty() {
        return String::new();
    }

    let stat_path = proc_root.join(pid.to_string()).join("stat");
    let Ok(stat_raw) = fs::read_to_string(stat_path) else {
        return String::new();
    };
    let start = proc_stat_start_ticks(&stat_raw);
    if start.is_empty() {
        return String::new();
    }

    format!("{boot}:{namespace}:{pid}:{start}")
}

/// Holds an open `/proc/{pid}/ns/net` file handle and its `(dev, ino)` identity on Unix,
/// ensuring safe `#![forbid(unsafe_code)]` namespace pinning across `nsenter` calls.
#[derive(Debug)]
pub struct PinnedNetNamespace {
    _file: File,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl PinnedNetNamespace {
    pub fn open_and_pin(
        proc_root: &Path,
        pid: u32,
        expected_epoch: &str,
        epoch_fn: &mut dyn FnMut(u32) -> String,
    ) -> Option<Self> {
        if expected_epoch.is_empty() || epoch_fn(pid) != expected_epoch {
            return None;
        }
        let ns_path = proc_root.join(pid.to_string()).join("ns").join("net");
        let file = File::open(&ns_path).ok()?;
        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            let fmeta = file.metadata().ok()?;
            let pmeta = fs::metadata(&ns_path).ok()?;
            if (fmeta.dev(), fmeta.ino()) != (pmeta.dev(), pmeta.ino()) {
                return None;
            }
            (fmeta.dev(), fmeta.ino())
        };
        if epoch_fn(pid) != expected_epoch {
            return None;
        }
        Some(Self {
            _file: file,
            #[cfg(unix)]
            dev,
            #[cfg(unix)]
            ino,
        })
    }

    pub fn verify_unchanged(&self, proc_root: &Path, pid: u32) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let ns_path = proc_root.join(pid.to_string()).join("ns").join("net");
            let Ok(pmeta) = fs::metadata(ns_path) else {
                return false;
            };
            pmeta.dev() == self.dev && pmeta.ino() == self.ino
        }
        #[cfg(not(unix))]
        {
            let _ = (proc_root, pid);
            true
        }
    }
}

/// Extracts only `(transport, port)` tuples from this guard's owned nft comments.
/// Matches `vmess_guard._owned_endpoints(readback, marker)`.
pub fn owned_endpoints(readback: &str, marker: &str) -> BTreeSet<(String, u16)> {
    let mut endpoints = BTreeSet::new();
    for proto in ["tcp", "udp"] {
        let needle = format!("{marker}-{proto}-");
        let mut search_from = 0usize;
        while let Some(pos) = readback[search_from..].find(&needle) {
            let after_idx = search_from + pos + needle.len();
            let rest = &readback[after_idx..];
            let digit_len = rest
                .bytes()
                .take(6)
                .take_while(|b| b.is_ascii_digit())
                .count();
            if (1..=5).contains(&digit_len) {
                if let Ok(port) = rest[..digit_len].parse::<u16>() {
                    if port > 0 {
                        endpoints.insert((proto.to_string(), port));
                    }
                }
            }
            search_from = after_idx;
        }
    }
    endpoints
}

/// Extracts only exact public destination IPs from this table's output rules.
/// Matches `vmess_guard._owned_destinations(readback, marker)`.
pub fn owned_destinations(readback: &str, marker: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let needle = format!("comment \"{marker}-dst-");
    let mut search_from = 0usize;
    while let Some(pos) = readback[search_from..].find(&needle) {
        let start = search_from + pos + needle.len();
        let rest = &readback[start..];
        if let Some(end_quote) = rest.find('"') {
            let raw = &rest[..end_quote];
            if !raw.is_empty()
                && raw
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            {
                if let Ok(addr) = raw.parse::<IpAddr>() {
                    if is_global_ip(addr) {
                        result.insert(addr.to_string());
                    }
                }
            }
            search_from = start + end_quote + 1;
        } else {
            break;
        }
    }
    result
}

/// Normalizes and validates domain sink targets (`_normalize_domain_targets`).
pub fn normalize_domain_targets(values: &[DomainTarget]) -> Option<BTreeSet<(String, String)>> {
    let mut result = BTreeSet::new();
    for item in values {
        let domain = item
            .domain
            .trim()
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .to_string();
        let Ok(addr) = item.ip.trim().parse::<IpAddr>() else {
            continue;
        };
        if is_safe_domain(&domain) && is_in_domain_sink_network(addr) {
            result.insert((domain, addr.to_string()));
        }
        if result.len() > MAX_DOMAIN_TARGETS {
            return None;
        }
    }
    Some(result)
}

fn split_domain_and_ip_suffix(suffix: &str) -> Option<(String, IpAddr)> {
    let (domain_part, ip_part) = suffix.rsplit_once('-')?;
    if domain_part.is_empty() || domain_part.len() > 253 {
        return None;
    }
    if !ip_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':')
    {
        return None;
    }
    let addr = parse_sink_ip(ip_part)?;
    let domain = domain_part
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string();
    if !is_safe_domain(&domain) {
        return None;
    }
    Some((domain, addr))
}

/// Extracts `(domain, sink_ip)` tuples from this table's output rules.
/// Matches `vmess_guard._owned_domain_targets(readback, marker)`.
pub fn owned_domain_targets(readback: &str, marker: &str) -> BTreeSet<(String, String)> {
    let mut result = BTreeSet::new();
    let needle = format!("comment \"{marker}-domain-");
    let mut search_from = 0usize;
    while let Some(pos) = readback[search_from..].find(&needle) {
        let start = search_from + pos + needle.len();
        let rest = &readback[start..];
        if let Some(end_quote) = rest.find('"') {
            let suffix = &rest[..end_quote];
            if let Some((domain, addr)) = split_domain_and_ip_suffix(suffix) {
                if is_in_domain_sink_network(addr) {
                    result.insert((domain, addr.to_string()));
                }
            }
            search_from = start + end_quote + 1;
        } else {
            break;
        }
    }
    result
}

fn parse_counter_packets_bytes(line: &str) -> Option<(u64, u64)> {
    let needle = "counter packets ";
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(needle) {
        let abs = from + pos;
        let before_ok = abs == 0
            || !line.as_bytes()[abs - 1].is_ascii_alphanumeric()
                && line.as_bytes()[abs - 1] != b'_';
        if before_ok {
            let after_packets = &line[abs + needle.len()..];
            let pkt_digits = after_packets
                .bytes()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if pkt_digits > 0 {
                let packets = after_packets[..pkt_digits].parse::<u64>().ok()?;
                let after_pkt_num = &after_packets[pkt_digits..];
                if let Some(bytes_rest) = after_pkt_num.strip_prefix(" bytes ") {
                    let byte_digits = bytes_rest
                        .bytes()
                        .take_while(|b| b.is_ascii_digit())
                        .count();
                    let after_byte_idx = byte_digits;
                    let after_ok = after_byte_idx >= bytes_rest.len()
                        || (!bytes_rest.as_bytes()[after_byte_idx].is_ascii_alphanumeric()
                            && bytes_rest.as_bytes()[after_byte_idx] != b'_');
                    if byte_digits > 0 && after_ok {
                        let byte_count = bytes_rest[..byte_digits].parse::<u64>().ok()?;
                        return Some((packets, byte_count));
                    }
                }
            }
        }
        from = abs + needle.len();
    }
    None
}

/// Parses speedtest domain and destination IP counter hits from nftables readback.
/// Matches `vmess_guard._speedtest_activity(readback, marker)`.
pub fn speedtest_activity(readback: &str, marker: &str) -> (Vec<DomainHit>, Vec<DestinationHit>) {
    let mut domains: BTreeMap<String, DomainHit> = BTreeMap::new();
    let mut destinations: BTreeMap<String, (IpAddr, DestinationHit)> = BTreeMap::new();
    let comment_prefix = format!("comment \"{marker}-");

    for line in readback.lines() {
        let Some(c_pos) = line.find(&comment_prefix) else {
            continue;
        };
        let suffix_start = c_pos + comment_prefix.len();
        let Some(end_quote) = line[suffix_start..].find('"') else {
            continue;
        };
        let suffix = &line[suffix_start..suffix_start + end_quote];
        if suffix.is_empty() || suffix.contains(' ') {
            continue;
        }
        let Some((packets, byte_count)) = parse_counter_packets_bytes(line) else {
            continue;
        };
        if packets == 0 {
            continue;
        }

        if let Some(target_suffix) = suffix.strip_prefix("domain-") {
            if let Some((domain, _addr)) = split_domain_and_ip_suffix(target_suffix) {
                let entry = domains.entry(domain.clone()).or_insert(DomainHit {
                    domain,
                    packets: 0,
                    bytes: 0,
                });
                entry.packets = entry.packets.saturating_add(packets);
                entry.bytes = entry.bytes.saturating_add(byte_count);
            }
        } else if let Some(raw_ip) = suffix.strip_prefix("dst-") {
            if let Ok(addr) = raw_ip.parse::<IpAddr>() {
                if is_global_ip(addr) {
                    let key = addr.to_string();
                    let entry = destinations.entry(key.clone()).or_insert((
                        addr,
                        DestinationHit {
                            ip: key,
                            packets: 0,
                            bytes: 0,
                        },
                    ));
                    entry.1.packets = entry.1.packets.saturating_add(packets);
                    entry.1.bytes = entry.1.bytes.saturating_add(byte_count);
                }
            }
        }
    }

    let domain_vec: Vec<DomainHit> = domains.into_values().collect();
    let mut dest_vec: Vec<(IpAddr, DestinationHit)> = destinations.into_values().collect();
    dest_vec.sort_by_key(|(addr, _)| ip_sort_key(*addr));
    let dest_hits = dest_vec.into_iter().map(|(_, hit)| hit).collect();

    (domain_vec, dest_hits)
}

/// Returns exclusive live endpoints proven to belong to one protected protocol.
/// Matches `vmess_guard._confirmed_protocol_live_endpoints(live_listeners, application_protocol)`.
pub fn confirmed_protocol_live_endpoints(
    live_listeners: Option<&[ServiceListener]>,
    application_protocol: &str,
) -> BTreeSet<(String, u16)> {
    let Some(list) = live_listeners else {
        return BTreeSet::new();
    };
    let app_proto = application_protocol.trim().to_ascii_lowercase();
    let mut grouped: BTreeMap<(String, u16), Vec<&ServiceListener>> = BTreeMap::new();
    for item in list {
        let transport = item.proto.trim().to_ascii_lowercase();
        if !matches!(transport.as_str(), "tcp" | "udp") || item.port == 0 {
            continue;
        }
        grouped
            .entry((transport, item.port))
            .or_default()
            .push(item);
    }

    let mut confirmed = BTreeSet::new();
    for (endpoint, rows) in grouped {
        if rows.is_empty() {
            continue;
        }
        let confirmed_owner = if app_proto == "speedtest" {
            rows.iter().all(|item| {
                let protos: BTreeSet<String> = item
                    .application_protocols
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect();
                let proc_lower = item.process.trim().to_ascii_lowercase();
                protos.len() == 1
                    && protos.contains("speedtest")
                    && item.application_protocol_evidence == "config_matches_live_pid_and_port"
                    && item.speedtest_process_scan_complete
                    && (2..=4_194_304).contains(&item.pid)
                    && !proc_lower.is_empty()
                    && proc_lower != "unknown"
            })
        } else {
            rows.iter().all(|item| {
                let protos: BTreeSet<String> = item
                    .application_protocols
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect();
                let proc_lower = item.process.trim().to_ascii_lowercase();
                let scan_ok = item.protocol_process_scan_complete
                    || (app_proto == "vmess" && item.vmess_process_scan_complete)
                    || item
                        .protocol_port_config_complete_protocols
                        .iter()
                        .any(|p| p.to_ascii_lowercase() == app_proto);
                protos.len() == 1
                    && protos.contains(&app_proto)
                    && item.application_protocol_evidence == "config_matches_live_pid_and_port"
                    && scan_ok
                    && (2..=4_194_304).contains(&item.pid)
                    && is_supported_engine(&proc_lower)
            })
        };
        if confirmed_owner {
            confirmed.insert(endpoint);
        }
    }
    confirmed
}

/// Maps nftables diagnostic output to safe reason codes without leaking raw command output.
/// Matches `vmess_guard._firewall_failure_reason(completed, fallback)`.
pub fn firewall_failure_reason(diagnostic_output: Option<&str>, fallback: &str) -> String {
    let Some(raw) = diagnostic_output else {
        return fallback.to_string();
    };
    let diagnostic = raw.to_ascii_lowercase();
    if ["operation not permitted", "permission denied", "not permitted"]
        .iter()
        .any(|tok| diagnostic.contains(tok))
    {
        return "firewall_permission_denied".to_string();
    }
    if [
        "operation not supported",
        "not supported by kernel",
        "protocol not supported",
    ]
    .iter()
    .any(|tok| diagnostic.contains(tok))
    {
        return "firewall_kernel_unsupported".to_string();
    }
    if [
        "file exists",
        "resource busy",
        "device or resource busy",
    ]
    .iter()
    .any(|tok| diagnostic.contains(tok))
    {
        return "firewall_state_conflict".to_string();
    }
    if [
        "syntax error",
        "unexpected",
        "invalid argument",
        "unknown keyword",
    ]
    .iter()
    .any(|tok| diagnostic.contains(tok))
    {
        return "firewall_rule_validation_failed".to_string();
    }
    fallback.to_string()
}

fn parse_nft_table_names(stdout: &str) -> Result<BTreeSet<String>, ()> {
    let trimmed = stdout.trim();
    let payload = if trimmed.is_empty() { "{}" } else { trimmed };
    let parsed = JsonVal::parse(payload).map_err(|_| ())?;
    let obj = parsed.as_obj().ok_or(())?;
    let mut names = BTreeSet::new();
    if let Some(arr) = obj.get("nftables").and_then(JsonVal::as_arr) {
        for item in arr {
            if let Some(item_obj) = item.as_obj() {
                if let Some(table_obj) = item_obj.get("table").and_then(JsonVal::as_obj) {
                    if let Some(name) = table_obj.get("name").and_then(JsonVal::as_str) {
                        names.insert(name.to_string());
                    }
                }
            }
        }
    }
    Ok(names)
}

#[derive(Debug, Clone)]
pub struct ReconcileRequest<'a> {
    pub pid: u32,
    pub identity: &'a str,
    pub expected_epoch: &'a str,
    pub endpoints: Option<&'a [GuardEndpoint]>,
    pub destination_ips: Option<&'a [String]>,
    pub domain_targets: Option<&'a [DomainTarget]>,
    pub host_network: bool,
    pub release_if_absent: bool,
    pub live_listeners: Option<&'a [ServiceListener]>,
    pub preserve_existing: bool,
    pub application_protocol: &'a str,
}

impl<'a> ReconcileRequest<'a> {
    pub fn new(
        pid: u32,
        identity: &'a str,
        expected_epoch: &'a str,
        endpoints: Option<&'a [GuardEndpoint]>,
    ) -> Self {
        Self {
            pid,
            identity,
            expected_epoch,
            endpoints,
            destination_ips: None,
            domain_targets: None,
            host_network: false,
            release_if_absent: false,
            live_listeners: None,
            preserve_existing: false,
            application_protocol: "vmess",
        }
    }
}

/// Atomically reconciles an owned nft table in one isolated network namespace using live tools.
pub fn reconcile(req: &ReconcileRequest<'_>) -> ReconcileOutcome {
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    let mut epoch_fn = pid_epoch;
    reconcile_with(
        req,
        &tools,
        &mut runner,
        Path::new("/proc"),
        &mut epoch_fn,
    )
}

/// Testable implementation of `reconcile` with injected `CommandRunner`, `proc_root`, and `epoch_fn`.
pub fn reconcile_with(
    req: &ReconcileRequest<'_>,
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
    proc_root: &Path,
    epoch_fn: &mut dyn FnMut(u32) -> String,
) -> ReconcileOutcome {
    let mut result = ReconcileOutcome {
        state: "unverified".to_string(),
        reason: "firewall_apply_failed".to_string(),
        ..Default::default()
    };

    if req.pid <= 1 || req.identity.is_empty() {
        result.reason = "container_identity_unavailable".to_string();
        return result;
    }
    if req.host_network {
        result.reason = "shared_network_namespace".to_string();
        return result;
    }
    let app_proto = req.application_protocol.trim().to_ascii_lowercase();
    if !is_supported_guard_type(&app_proto) {
        result.reason = "protocol_not_supported".to_string();
        return result;
    }
    if req.expected_epoch.is_empty() || epoch_fn(req.pid) != req.expected_epoch {
        result.reason = "container_namespace_changed_or_shared".to_string();
        return result;
    }
    let (Some(ref nsenter_path), Some(ref nft_path)) = (&tools.nsenter_bin, &tools.nft_bin) else {
        result.reason = "firewall_dependency_unavailable".to_string();
        return result;
    };

    let mut endpoint_map: Option<BTreeMap<(String, u16), GuardEndpoint>> =
        req.endpoints.map(|eps| {
            let mut m = BTreeMap::new();
            for ep in eps {
                let tr = ep.proto.trim().to_ascii_lowercase();
                if matches!(tr.as_str(), "tcp" | "udp") && ep.port > 0 {
                    m.insert((tr.clone(), ep.port), GuardEndpoint::new_port(tr, ep.port));
                }
            }
            m
        });
    if let Some(ref em) = endpoint_map {
        if em.len() > MAX_ENDPOINTS {
            result.reason = "endpoint_limit_exceeded".to_string();
            return result;
        }
    }

    let mut normalized_destinations: Option<BTreeSet<String>> = None;
    if let Some(raw_ips) = req.destination_ips {
        let mut set = BTreeSet::new();
        for raw in raw_ips {
            if let Ok(addr) = raw.trim().parse::<IpAddr>() {
                if is_global_ip(addr) {
                    set.insert(addr.to_string());
                }
                if set.len() > MAX_DESTINATION_IPS {
                    result.reason = "destination_ip_limit_exceeded".to_string();
                    return result;
                }
            }
        }
        normalized_destinations = Some(set);
    }

    let normalized_domain_targets = match req.domain_targets {
        Some(targets) => match normalize_domain_targets(targets) {
            Some(s) => Some(s),
            None => {
                result.reason = "domain_target_limit_exceeded".to_string();
                return result;
            }
        },
        None => None,
    };

    let full_digest = sha256_hex(req.identity.as_bytes());
    let digest = &full_digest[..12];
    let table = format!("narwhal_{app_proto}_{digest}");
    let marker = format!("narwhal-{app_proto}-guard-v1-{digest}");

    let Some(pinned_ns) = PinnedNetNamespace::open_and_pin(
        proc_root,
        req.pid,
        req.expected_epoch,
        epoch_fn,
    ) else {
        result.reason = "container_namespace_changed_or_unavailable".to_string();
        return result;
    };

    let prefix = vec![
        nsenter_path.clone(),
        "-t".to_string(),
        req.pid.to_string(),
        "-n".to_string(),
        "--".to_string(),
        nft_path.clone(),
    ];

    reconcile_owned_table(
        &prefix,
        &table,
        &marker,
        &app_proto,
        &mut endpoint_map,
        normalized_destinations,
        normalized_domain_targets,
        req.pid,
        req.expected_epoch,
        runner,
        &pinned_ns,
        proc_root,
        epoch_fn,
        req.release_if_absent,
        req.live_listeners,
        req.preserve_existing,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconcile_owned_table(
    prefix: &[String],
    table: &str,
    marker: &str,
    application_protocol: &str,
    endpoint_map_opt: &mut Option<BTreeMap<(String, u16), GuardEndpoint>>,
    destination_ips: Option<BTreeSet<String>>,
    domain_targets: Option<BTreeSet<(String, String)>>,
    pid: u32,
    expected_epoch: &str,
    runner: &mut dyn CommandRunner,
    pinned_ns: &PinnedNetNamespace,
    proc_root: &Path,
    epoch_fn: &mut dyn FnMut(u32) -> String,
    release_if_absent: bool,
    live_listeners: Option<&[ServiceListener]>,
    preserve_existing: bool,
) -> ReconcileOutcome {
    let mut result = ReconcileOutcome {
        state: "unverified".to_string(),
        reason: "firewall_apply_failed".to_string(),
        ..Default::default()
    };

    let call = |runner: &mut dyn CommandRunner,
                pinned: &PinnedNetNamespace,
                extra: &[&str],
                stdin: Option<&str>|
     -> Option<(bool, String)> {
        if !pinned.verify_unchanged(proc_root, pid) {
            return None;
        }
        let mut cmd = prefix.to_vec();
        for arg in extra {
            cmd.push((*arg).to_string());
        }
        Some(runner.run(&cmd, stdin))
    };

    let current = call(
        runner,
        pinned_ns,
        &["-a", "list", "table", "inet", table],
        None,
    );
    let (exists, current_stdout) = match current {
        Some((true, out)) => (true, out),
        _ => (false, String::new()),
    };

    if exists && !current_stdout.contains(marker) {
        result.reason = "firewall_table_not_owned".to_string();
        return result;
    }

    if !exists {
        let Some((true, tables_out)) = call(runner, pinned_ns, &["-j", "list", "tables"], None)
        else {
            result.reason = "firewall_readback_unavailable".to_string();
            return result;
        };
        let Ok(names) = parse_nft_table_names(&tables_out) else {
            result.reason = "firewall_readback_invalid".to_string();
            return result;
        };
        if names.contains(table) {
            result.reason = "firewall_table_ownership_unverified".to_string();
            return result;
        }
    }

    let existing_endpoints = if exists {
        owned_endpoints(&current_stdout, marker)
    } else {
        BTreeSet::new()
    };
    let existing_destinations = if exists {
        owned_destinations(&current_stdout, marker)
    } else {
        BTreeSet::new()
    };
    let existing_domain_targets = if exists {
        owned_domain_targets(&current_stdout, marker)
    } else {
        BTreeSet::new()
    };
    let (domain_hits, destination_hits) = if application_protocol == "speedtest" && exists {
        speedtest_activity(&current_stdout, marker)
    } else {
        (Vec::new(), Vec::new())
    };

    let mut endpoint_map: BTreeMap<(String, u16), GuardEndpoint> = match endpoint_map_opt.take() {
        Some(m) => m,
        None => existing_endpoints
            .iter()
            .map(|(tr, port)| {
                (
                    (tr.clone(), *port),
                    GuardEndpoint::new_port(tr.clone(), *port),
                )
            })
            .collect(),
    };
    let requested_endpoints: BTreeSet<(String, u16)> = endpoint_map.keys().cloned().collect();

    let final_destinations = destination_ips.unwrap_or(existing_destinations);
    let final_domain_targets = domain_targets.unwrap_or(existing_domain_targets);

    if final_domain_targets.len() > MAX_DOMAIN_TARGETS {
        result.reason = "domain_target_limit_exceeded".to_string();
        return result;
    }
    if final_destinations.len() > MAX_DESTINATION_IPS {
        result.reason = "destination_ip_limit_exceeded".to_string();
        return result;
    }

    let live = confirmed_protocol_live_endpoints(live_listeners, application_protocol);
    if preserve_existing && exists {
        for (tr, port) in existing_endpoints.difference(&requested_endpoints) {
            if live.contains(&(tr.clone(), *port)) {
                endpoint_map.insert(
                    (tr.clone(), *port),
                    GuardEndpoint::new_port(tr.clone(), *port),
                );
            }
        }
    }

    if endpoint_map.is_empty() && final_destinations.is_empty() && final_domain_targets.is_empty() {
        if exists && release_if_absent {
            if live_listeners.is_none() {
                result.reason = "release_evidence_unavailable".to_string();
                return result;
            }
            let remaining: Vec<GuardEndpoint> = existing_endpoints
                .intersection(&live)
                .map(|(proto, port)| GuardEndpoint::new_port(proto.clone(), *port))
                .collect();
            if !remaining.is_empty() {
                result.state = "release_pending".to_string();
                result.reason = "guarded_port_still_has_listener".to_string();
                result.pending_removal_endpoints = remaining;
                return result;
            }
        }
        if exists && final_destinations.is_empty() {
            let removed = call(
                runner,
                pinned_ns,
                &["delete", "table", "inet", table],
                None,
            );
            let Some((true, tables_out)) =
                call(runner, pinned_ns, &["-j", "list", "tables"], None)
            else {
                result.reason = "firewall_remove_readback_failed".to_string();
                return result;
            };
            let Ok(names) = parse_nft_table_names(&tables_out) else {
                result.reason = "firewall_remove_readback_invalid".to_string();
                return result;
            };
            if names.contains(table) {
                result.state = if release_if_absent {
                    "release_pending".to_string()
                } else {
                    "unverified".to_string()
                };
                let remove_ok = matches!(removed, Some((true, _)));
                result.reason = if !remove_ok {
                    "firewall_remove_failed".to_string()
                } else {
                    "firewall_remove_readback_failed".to_string()
                };
                result.pending_removal_endpoints = existing_endpoints
                    .into_iter()
                    .map(|(proto, port)| GuardEndpoint::new_port(proto, port))
                    .collect();
                return result;
            }
        }
        if epoch_fn(pid) != expected_epoch || !pinned_ns.verify_unchanged(proc_root, pid) {
            result.reason = "container_namespace_changed".to_string();
            return result;
        }
        return ReconcileOutcome {
            state: "cleared".to_string(),
            reason: String::new(),
            ..Default::default()
        };
    }

    if endpoint_map.len() > MAX_ENDPOINTS {
        result.reason = "endpoint_limit_exceeded".to_string();
        return result;
    }

    let mut sorted_destinations: Vec<(IpAddr, String)> = final_destinations
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok().map(|ip| (ip, s.clone())))
        .collect();
    sorted_destinations.sort_by_key(|(ip, _)| ip_sort_key(*ip));

    let mut lines = Vec::new();
    if exists {
        lines.push(format!("delete table inet {table}"));
    }
    lines.push(format!("add table inet {table}"));
    if !endpoint_map.is_empty() {
        lines.push(format!(
            "add chain inet {table} input {{ type filter hook input priority -20; policy accept; }}"
        ));
    }
    let count_rule = if application_protocol == "speedtest" {
        " counter"
    } else {
        ""
    };
    for (transport, port) in endpoint_map.keys() {
        lines.push(format!(
            "add rule inet {table} input meta l4proto {transport} {transport} dport {port}{count_rule} drop comment \"{marker}-{transport}-{port}\""
        ));
    }
    if !sorted_destinations.is_empty() || !final_domain_targets.is_empty() {
        lines.push(format!(
            "add chain inet {table} output {{ type filter hook output priority -20; policy accept; }}"
        ));
        for (ip, destination) in &sorted_destinations {
            let family = if ip.is_ipv6() { "ip6" } else { "ip" };
            lines.push(format!(
                "add rule inet {table} output {family} daddr {destination}{count_rule} drop comment \"{marker}-dst-{destination}\""
            ));
        }
        for (domain, address) in &final_domain_targets {
            let is_v6 = address
                .parse::<IpAddr>()
                .map(|ip| ip.is_ipv6())
                .unwrap_or(false);
            let family = if is_v6 { "ip6" } else { "ip" };
            lines.push(format!(
                "add rule inet {table} output {family} daddr {address} counter drop comment \"{marker}-domain-{domain}-{address}\""
            ));
        }
    }

    let mut script = lines.join("\n");
    script.push('\n');

    let checked = call(runner, pinned_ns, &["--check", "-f", "-"], Some(&script));
    match checked {
        Some((true, _)) => {}
        Some((false, ref out)) => {
            result.reason = firewall_failure_reason(Some(out), "firewall_rule_validation_failed");
            return result;
        }
        None => {
            result.reason = firewall_failure_reason(None, "firewall_rule_validation_failed");
            return result;
        }
    }

    let applied = call(runner, pinned_ns, &["-f", "-"], Some(&script));
    match applied {
        Some((true, _)) => {}
        Some((false, ref out)) => {
            result.reason = firewall_failure_reason(Some(out), "firewall_apply_failed");
            return result;
        }
        None => {
            result.reason = firewall_failure_reason(None, "firewall_apply_failed");
            return result;
        }
    }

    let readback = call(
        runner,
        pinned_ns,
        &["-a", "list", "table", "inet", table],
        None,
    );
    let readback_stdout = match readback {
        Some((true, ref out)) if out.contains(marker) => out.as_str(),
        Some((_, ref out)) => {
            result.reason = firewall_failure_reason(Some(out), "firewall_readback_failed");
            return result;
        }
        None => {
            result.reason = firewall_failure_reason(None, "firewall_readback_failed");
            return result;
        }
    };

    for (transport, port) in endpoint_map.keys() {
        let token = format!("{marker}-{transport}-{port}");
        if !readback_stdout.contains(&token) {
            result.reason = "firewall_rule_readback_incomplete".to_string();
            return result;
        }
    }
    for (_, destination) in &sorted_destinations {
        let token = format!("{marker}-dst-{destination}");
        if !readback_stdout.contains(&token) {
            result.reason = "firewall_destination_readback_incomplete".to_string();
            return result;
        }
    }
    for (domain, address) in &final_domain_targets {
        let token = format!("{marker}-domain-{domain}-{address}");
        if !readback_stdout.contains(&token) {
            result.reason = "firewall_domain_target_readback_incomplete".to_string();
            return result;
        }
    }

    if epoch_fn(pid) != expected_epoch || !pinned_ns.verify_unchanged(proc_root, pid) {
        let removed = call(
            runner,
            pinned_ns,
            &["delete", "table", "inet", table],
            None,
        );
        result.reason = if matches!(removed, Some((true, _))) {
            "container_namespace_changed".to_string()
        } else {
            "container_namespace_changed_cleanup_failed".to_string()
        };
        return result;
    }

    ReconcileOutcome {
        state: "blocked".to_string(),
        reason: String::new(),
        blocked_endpoints: endpoint_map.into_values().collect(),
        blocked_destination_ips: sorted_destinations
            .into_iter()
            .map(|(_, s)| s)
            .collect(),
        blocked_domain_targets: final_domain_targets
            .into_iter()
            .map(|(domain, ip)| DomainTarget { domain, ip })
            .collect(),
        blocked_domain_hits: domain_hits,
        blocked_destination_hits: destination_hits,
        pending_removal_endpoints: Vec::new(),
    }
}

// ===========================================================================
// 5. `apply_protocol_guard_plan`, `finalize_protocol_guard_evidence`, & Alerts
// ===========================================================================

#[allow(clippy::too_many_arguments)]
pub fn apply_protocol_guard_plan_with(
    plan: &ProtocolGuardPlan,
    protocol: &str,
    runtime_name: &str,
    identity: &str,
    pid: u32,
    namespace_epoch: &str,
    host_or_shared_network: bool,
    auto_enabled: bool,
    scan_state: &str,
    listener_inventory_complete: bool,
    listeners: &[ServiceListener],
    tools: &NetToolPaths,
    runner: &mut dyn CommandRunner,
    proc_root: &Path,
    epoch_fn: &mut dyn FnMut(u32) -> String,
) -> ProtocolGuardPlan {
    let mut status = plan.clone();
    let rt_lower = runtime_name.trim().to_ascii_lowercase();
    let should_reconcile = is_supported_runtime(&rt_lower)
        && !host_or_shared_network
        && !namespace_epoch.is_empty()
        && (!auto_enabled
            || scan_state == "complete"
            || (listener_inventory_complete && plan.detected));

    if should_reconcile {
        let desired: &[GuardEndpoint] = if auto_enabled {
            &plan.blocked_endpoints
        } else {
            &[]
        };
        let req = ReconcileRequest {
            pid,
            identity,
            expected_epoch: namespace_epoch,
            endpoints: Some(desired),
            destination_ips: None,
            domain_targets: None,
            host_network: false,
            release_if_absent: auto_enabled && plan.release_eligible,
            live_listeners: Some(listeners),
            preserve_existing: auto_enabled && plan.detected && !plan.pending_endpoints.is_empty(),
            application_protocol: protocol,
        };
        let enforcement = reconcile_with(&req, tools, runner, proc_root, epoch_fn);

        if auto_enabled && plan.release_eligible {
            if enforcement.state == "cleared" {
                status.state = "not_detected".to_string();
                status.reason.clear();
                status.blocked_endpoints.clear();
                status.pending_endpoints.clear();
            } else {
                status.state = "release_pending".to_string();
                status.reason = if enforcement.reason.is_empty() {
                    "firewall_remove_unverified".to_string()
                } else {
                    enforcement.reason
                };
                status.blocked_endpoints.clear();
                status.pending_endpoints = enforcement
                    .pending_removal_endpoints
                    .into_iter()
                    .map(|ep| PendingEndpoint {
                        pid: ep.pid,
                        port: ep.port,
                        proto: Some(ep.proto),
                        process: ep.process,
                        reason: String::new(),
                    })
                    .collect();
            }
        } else if auto_enabled && plan.detected {
            if plan.state == "internal_only" {
                if enforcement.state == "cleared" {
                    status.state = "internal_only".to_string();
                    status.reason = "loopback_only_listener".to_string();
                    status.blocked_endpoints.clear();
                } else {
                    status.state = "release_pending".to_string();
                    status.reason = if enforcement.reason.is_empty() {
                        "firewall_remove_unverified".to_string()
                    } else {
                        enforcement.reason
                    };
                    status.blocked_endpoints.clear();
                    status.pending_endpoints = enforcement
                        .pending_removal_endpoints
                        .into_iter()
                        .map(|ep| PendingEndpoint {
                            pid: ep.pid,
                            port: ep.port,
                            proto: Some(ep.proto),
                            process: ep.process,
                            reason: String::new(),
                        })
                        .collect();
                }
            } else if enforcement.state == "blocked" {
                status.state = if !plan.pending_endpoints.is_empty() {
                    "partial".to_string()
                } else {
                    "blocked".to_string()
                };
                status.blocked_endpoints = plan
                    .blocked_endpoints
                    .iter()
                    .filter(|ep| {
                        enforcement
                            .blocked_endpoints
                            .iter()
                            .any(|live| live.proto == ep.proto && live.port == ep.port)
                    })
                    .cloned()
                    .collect();
                if status.state == "partial" {
                    status.reason = "some_endpoints_are_ambiguous".to_string();
                }
                if plan.state == "unverified" {
                    status.state = "unverified".to_string();
                    status.reason = if !enforcement.blocked_endpoints.is_empty() {
                        "previous_guard_rule_preserved".to_string()
                    } else if !plan.reason.is_empty() {
                        plan.reason.clone()
                    } else {
                        "firewall_apply_failed".to_string()
                    };
                    status.blocked_endpoints.clear();
                    let mut pending = plan.pending_endpoints.clone();
                    pending.truncate(20);
                    for live in &enforcement.blocked_endpoints {
                        if !pending.iter().any(|existing| {
                            existing.proto.as_deref() == Some(live.proto.as_str())
                                && existing.port == live.port
                        }) {
                            pending.push(PendingEndpoint {
                                pid: None,
                                port: live.port,
                                proto: Some(live.proto.clone()),
                                process: None,
                                reason: "previous_guard_rule_preserved".to_string(),
                            });
                        }
                    }
                    status.pending_endpoints = pending;
                }
            } else {
                status.state = "unverified".to_string();
                status.reason = if enforcement.reason.is_empty() {
                    "firewall_apply_failed".to_string()
                } else {
                    enforcement.reason
                };
                status.blocked_endpoints.clear();
            }
        } else if !auto_enabled {
            if enforcement.state == "cleared" {
                status.state = "disabled".to_string();
                status.reason = "automatic_block_disabled".to_string();
                status.blocked_endpoints.clear();
            } else {
                status.state = "release_pending".to_string();
                status.reason = if enforcement.reason.is_empty() {
                    "firewall_remove_unverified".to_string()
                } else {
                    enforcement.reason
                };
                status.blocked_endpoints.clear();
                status.pending_endpoints = enforcement
                    .pending_removal_endpoints
                    .into_iter()
                    .map(|ep| PendingEndpoint {
                        pid: ep.pid,
                        port: ep.port,
                        proto: Some(ep.proto),
                        process: ep.process,
                        reason: String::new(),
                    })
                    .collect();
            }
        } else if scan_state == "complete" && !plan.detected {
            status.state = "not_detected".to_string();
            status.reason.clear();
            status.blocked_endpoints.clear();
        }
    } else if plan.detected && auto_enabled {
        if host_or_shared_network {
            status.state = "unverified".to_string();
            status.reason = "shared_network_namespace".to_string();
            status.blocked_endpoints.clear();
        } else if namespace_epoch.is_empty() {
            status.state = "unverified".to_string();
            status.reason = "container_namespace_unavailable".to_string();
            status.blocked_endpoints.clear();
        }
    } else if auto_enabled && is_supported_runtime(&rt_lower) && plan.release_eligible {
        status.state = "release_pending".to_string();
        status.reason = if host_or_shared_network {
            "shared_network_namespace".to_string()
        } else {
            "container_namespace_unavailable".to_string()
        };
        status.blocked_endpoints.clear();
        status.pending_endpoints.clear();
    }

    status
}

/// Live wrapper around `apply_protocol_guard_plan_with`.
#[allow(clippy::too_many_arguments)]
pub fn apply_protocol_guard_plan(
    plan: &ProtocolGuardPlan,
    protocol: &str,
    runtime_name: &str,
    identity: &str,
    pid: u32,
    namespace_epoch: &str,
    host_or_shared_network: bool,
    auto_enabled: bool,
    scan_state: &str,
    listener_inventory_complete: bool,
    listeners: &[ServiceListener],
) -> ProtocolGuardPlan {
    let tools = NetToolPaths::discover();
    let mut runner = LiveCommandRunner;
    let mut epoch_fn = pid_epoch;
    apply_protocol_guard_plan_with(
        plan,
        protocol,
        runtime_name,
        identity,
        pid,
        namespace_epoch,
        host_or_shared_network,
        auto_enabled,
        scan_state,
        listener_inventory_complete,
        listeners,
        &tools,
        &mut runner,
        Path::new("/proc"),
        &mut epoch_fn,
    )
}

/// Populates `evidence_chain` on a `ProtocolGuardPlan` (`_finalize_protocol_guard_evidence`).
pub fn finalize_protocol_guard_evidence(status: &mut ProtocolGuardPlan) {
    let blocked_count = status.blocked_endpoints.len();
    let configured_count = status.configured_endpoints.len();
    let complete_configured_count = status
        .configured_endpoints
        .iter()
        .filter(|item| item.port_config_complete)
        .count();

    let state = if status.state.is_empty() {
        "unverified"
    } else {
        status.state.as_str()
    };
    let reason = status.reason.as_str();

    let readback = if blocked_count > 0 && matches!(state, "blocked" | "partial") {
        if state == "blocked" {
            "confirmed"
        } else {
            "partially_confirmed"
        }
    } else if state == "release_pending" {
        "removal_unverified"
    } else if matches!(state, "not_detected" | "internal_only" | "disabled") {
        "not_required"
    } else if reason.starts_with("firewall_") {
        "failed_or_unavailable"
    } else {
        "not_confirmed"
    };

    let configuration = if status.detected {
        if configured_count > 0 && complete_configured_count == configured_count {
            "confirmed"
        } else if complete_configured_count > 0 {
            "partially_confirmed"
        } else {
            "pending_or_unverified"
        }
    } else if state == "not_detected" && reason.is_empty() {
        "not_detected"
    } else {
        "not_detected_or_incomplete"
    };

    let src = if status.listener_inventory_source.is_empty() {
        "unknown".to_string()
    } else {
        truncate_chars(&status.listener_inventory_source, 80)
    };
    let inv_reason = truncate_chars(&status.listener_inventory_reason, 180);

    status.evidence_chain = Some(EvidenceChain {
        configuration: configuration.to_string(),
        configured_endpoint_count: configured_count,
        complete_configured_endpoint_count: complete_configured_count,
        process_owner_and_listener: if blocked_count > 0 {
            "confirmed_for_blocked_endpoints".to_string()
        } else {
            "pending_or_unverified".to_string()
        },
        public_exposure: if blocked_count > 0 {
            "confirmed_for_blocked_endpoints".to_string()
        } else {
            "pending_or_internal_only".to_string()
        },
        firewall_readback: readback.to_string(),
        listener_inventory_source: src,
        listener_inventory_reason: inv_reason,
        pending_endpoint_count: status.pending_endpoints.len(),
    });
}

/// Formats an endpoint label matching `agent._vmess_endpoint_label`.
pub fn vmess_endpoint_label(
    proto: Option<&str>,
    port: u16,
    pid: Option<u32>,
    process: Option<&str>,
    pending: bool,
) -> String {
    if port == 0 {
        return String::new();
    }
    let proto_lower = proto.unwrap_or("").trim().to_ascii_lowercase();
    let endpoint = if matches!(proto_lower.as_str(), "tcp" | "udp") {
        format!("{}/{port}", proto_lower.to_ascii_uppercase())
    } else {
        format!("端口/{port}")
    };
    let proc_lower = process.unwrap_or("").trim().to_ascii_lowercase();
    let pid_val = pid.unwrap_or(0);
    if is_supported_engine(&proc_lower) && (2..=4_194_304).contains(&pid_val) {
        if pending {
            format!("{proc_lower}（容器内 PID {pid_val}），待核实 {endpoint}")
        } else {
            format!("{proc_lower}（容器内 PID {pid_val}）监听 {endpoint}")
        }
    } else if pending {
        format!("待核实 {endpoint}")
    } else {
        endpoint
    }
}

/// Prefers concrete process-scan failure over generic listener status (`_vmess_unverified_reason_key`).
pub fn vmess_unverified_reason_key(
    plan: &ProtocolGuardPlan,
    process_scan_states: &[ProcessScanState],
    pending_endpoints: &[PendingEndpoint],
) -> String {
    let mut reason = plan.reason.clone();
    if reason == "configuration_scan_incomplete" && !plan.protocol_inventory_reason.is_empty() {
        reason = plan.protocol_inventory_reason.clone();
    }
    let is_generic = matches!(
        reason.as_str(),
        "listener_inventory_incomplete"
            | "configuration_scan_incomplete"
            | "process_snapshot_unavailable"
            | ""
    );
    if !is_generic {
        return reason;
    }

    let mut target_pids: BTreeSet<(String, u32)> = BTreeSet::new();
    let mut target_processes: BTreeSet<String> = BTreeSet::new();
    for ep in pending_endpoints {
        let proc_name = ep
            .process
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !proc_name.is_empty() {
            target_processes.insert(proc_name.clone());
            if let Some(pid) = ep.pid {
                if pid > 1 {
                    target_pids.insert((proc_name, pid));
                }
            }
        }
    }

    for item in process_scan_states {
        if item.state == "complete" {
            continue;
        }
        let proc_name = item.process.trim().to_ascii_lowercase();
        let pid = item.pid;
        if !target_pids.is_empty() && !target_pids.contains(&(proc_name.clone(), pid)) {
            continue;
        }
        if target_pids.is_empty()
            && !target_processes.is_empty()
            && !target_processes.contains(&proc_name)
        {
            continue;
        }
        if item.reason == "config_process_clock_unavailable" && !item.clock_sample_reason.is_empty()
        {
            return item.clock_sample_reason.clone();
        }
        if !item.reason.is_empty() {
            return item.reason.clone();
        }
    }

    if reason.is_empty() {
        "listener_inventory_incomplete".to_string()
    } else {
        reason
    }
}

fn vmess_unverified_reason_label(key: &str) -> &'static str {
    match key {
        "configuration_scan_incomplete" => "配置文件未能完整读取",
        "config_directory_unreadable_or_truncated" => "配置目录无法完整读取或文件清单超过安全上限",
        "config_directory_path_invalid" => "配置目录路径未通过安全校验",
        "config_file_limit_exceeded" => "配置文件数量超过单进程扫描上限",
        "unparsed_or_excess_config_arguments" => "进程启动参数包含未识别或过多的配置入口",
        "config_path_not_found_or_unreadable" => "没有可验证的配置文件路径，或路径不可读",
        "config_parse_failed_or_too_large" => "配置文件格式不受支持、解析失败或超过大小上限",
        "config_scan_timed_out" => "配置扫描达到时间上限",
        "config_file_metadata_unavailable" => "无法读取配置文件的完整时间与身份元数据",
        "config_file_changed_during_scan" => "扫描期间配置文件发生变化，不能确认已加载的版本",
        "config_process_clock_unavailable" => "无法用同一时钟基准确认配置文件与进程启动的先后顺序",
        "process_start_ticks_invalid" => "进程启动时钟 tick 数据无效",
        "runtime_exec_timeout" => "读取容器进程时钟超时",
        "runtime_exec_no_snapshot" => "容器未返回配对的进程与 uptime 时钟样本",
        "clock_snapshot_marker_missing" => "配对时钟样本不完整",
        "process_generation_changed" => "读取期间进程发生重启或 PID 被复用",
        "uptime_snapshot_invalid" => "容器 uptime 时钟样本无效",
        "clock_snapshot_invalid" => "进程与 uptime 时钟数据无法解析",
        "clock_tick_rate_invalid" => "内核时钟频率不在安全范围",
        "namespace_uptime_invalid" => "配对 uptime 样本不在安全范围",
        "process_start_outside_namespace_uptime" => "进程启动时间超出同次采样的 uptime 范围",
        "realtime_clock_unavailable" => "系统实时时钟不可用",
        "clock_sample_elapsed_invalid" => "运行时命令耗时超出安全范围",
        "clock_sample_error" => "读取容器进程时钟时发生错误",
        "host_process_identity_invalid" => "宿主机进程映射缺少有效的容器 PID 身份",
        "host_process_snapshot_unavailable" => "无法读取宿主机进程快照",
        "host_process_scope_incomplete" => "宿主机进程清单不完整，无法核实 Xray PID",
        "host_process_owner_unverified" => "宿主机进程清单中无法唯一匹配容器内的代理进程",
        "host_process_generation_changed" => "宿主机进程在取证期间发生重启或 PID 被复用",
        "host_process_owner_changed" => "宿主机 PID 对应的进程已变化",
        "host_process_namespace_pid_changed" => "宿主机进程不再对应原容器 PID",
        "host_process_clock_unavailable" => "宿主机进程启动时间或 uptime 无法读取",
        "host_process_uptime_invalid" => "宿主机 uptime 样本无效",
        "host_process_start_outside_uptime" => "宿主机进程启动 tick 超出 uptime 范围",
        "time_namespace_offset_unavailable" => "无法核对目标进程与采样进程的 time namespace 偏移",
        "time_namespace_offset_inconsistent" => "同一 time namespace 的 boottime 偏移在采样中不一致",
        "config_not_known_before_process_start" => "配置文件在进程启动后更新、时间过于接近或时间元数据不完整，不能确认进程已加载此版本",
        "process_changed_during_config_scan" => "扫描期间进程发生变化，不能确认配置仍属于当前进程",
        "endpoint_report_limit_exceeded" => "入站端点数量超过上报上限",
        "process_scan_limit_exceeded" => "协议进程数量达到扫描上限",
        "process_snapshot_unavailable" => "容器进程清单不可读或采集未完成",
        "process_scan_state_missing" => "未取得该进程的独立扫描状态",
        "process_start_generation_unavailable" => "无法确认该进程当前运行代次",
        "listener_inventory_incomplete" => "实时监听清单不完整，无法确认端口归属",
        "live_listener_not_confirmed" => "未找到配置对应的实时监听端口",
        "listener_protocol_or_owner_ambiguous" => "实时监听的进程或协议归属不唯一",
        "shared_configured_port" => "该端口还配置了其他协议",
        "shared_live_listener" => "该端口还被其他监听服务共用",
        "shared_network_namespace" => "容器与其他服务共用网络命名空间",
        "container_namespace_unavailable" => "容器网络命名空间不可用",
        "container_namespace_changed_or_unavailable" => "网络命名空间身份变化或无法固定",
        "container_namespace_changed_or_shared" => "容器网络命名空间身份无法确认",
        "container_namespace_changed_cleanup_failed" => "网络命名空间身份变化，规则清理未能确认",
        "firewall_dependency_unavailable" => "主机缺少 nftables 或 nsenter",
        "firewall_rule_validation_failed" => "nftables 规则校验未通过",
        "firewall_permission_denied" => "Agent 缺少目标网络命名空间所需的防火墙权限",
        "firewall_kernel_unsupported" => "当前内核或 nftables 不支持所需的规则操作",
        "firewall_state_conflict" => "防火墙规则状态冲突，需检查 Agent 专属规则表",
        "firewall_apply_failed" => "防火墙规则应用失败",
        "firewall_readback_failed" => "防火墙读回未确认规则生效",
        "firewall_readback_unavailable" => "无法读取 nftables 当前规则",
        "firewall_readback_invalid" => "nftables 返回的规则数据无效",
        "endpoint_limit_exceeded" => "待保护端口超过 Agent 安全上限",
        "previous_guard_rule_preserved" => "当前证据不足以确认旧 VMess 入口已消失，因此保留原端口阻断",
        _ => "端口归属或规则生效状态未能确认",
    }
}

fn trojan_unverified_reason_label(key: &str) -> &'static str {
    match key {
        "configuration_scan_incomplete" => "配置扫描不完整",
        "config_not_known_before_process_start" => "配置文件在进程启动后更新，无法确认当前进程已加载该版本",
        "config_file_changed_during_scan" => "配置文件在扫描期间发生变化",
        "config_file_metadata_unavailable" => "无法读取配置文件时间信息",
        "config_parse_failed_or_too_large" => "配置文件无法完整解析或超过大小上限",
        "listener_inventory_incomplete" => "实时监听清单不完整",
        "live_listener_not_confirmed" => "尚未找到配置对应的实时监听",
        "listener_protocol_or_owner_ambiguous" => "监听进程或协议归属不明确",
        "shared_configured_port" => "该端口还配置了其他协议",
        "shared_live_listener" => "该端口由其他监听服务共用",
        "firewall_permission_denied" => "Agent 缺少目标网络命名空间的防火墙权限",
        "firewall_kernel_unsupported" => "当前内核或 nftables 不支持该规则",
        "firewall_rule_validation_failed" => "nftables 规则校验失败",
        "firewall_apply_failed" => "防火墙规则应用失败",
        "firewall_readback_failed" => "无法读回确认规则生效",
        "shared_network_namespace" => "容器与其他服务共用网络命名空间",
        "container_namespace_unavailable" => "容器网络命名空间不可用",
        "previous_guard_rule_preserved" => "当前证据不足，旧的 Trojan 端口保护规则仍保留",
        _ => "端口归属或规则生效状态未能确认",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlertContainerContext {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub instance_id: String,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub connections: u64,
    pub http_requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolGuardAlert {
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub value: usize,
    pub threshold: usize,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub instance_id: String,
    pub alert_key: String,
    pub guard_field_name: String,
    pub guard_json: String,
    pub automatic_remediation: Option<(bool, bool, String)>,
    pub context: AlertContainerContext,
}

impl ProtocolGuardAlert {
    pub fn to_json(&self) -> String {
        let mut obs = JsonBuilder::new();
        obs.u64("rx_bps", self.context.rx_bps);
        obs.u64("tx_bps", self.context.tx_bps);
        obs.u64("connections", self.context.connections);
        obs.u64("http_requests", self.context.http_requests);
        obs.raw("configuration_risks", "[]");

        let mut b = JsonBuilder::new();
        b.str("type", &self.alert_type);
        b.str("severity", &self.severity);
        b.str("title", &self.title);
        b.str("message", &self.message);
        b.usize("value", self.value);
        b.usize("threshold", self.threshold);
        b.str("runtime", &self.runtime);
        b.str("project", &self.project);
        b.str("container_name", &self.container_name);
        b.str("instance_id", &truncate_chars(&self.instance_id, 200));
        b.raw("observation", &obs.finish());
        b.str("alert_key", &self.alert_key);
        if !self.guard_field_name.is_empty() && !self.guard_json.is_empty() {
            b.raw(&self.guard_field_name, &self.guard_json);
        }
        if let Some((attempted, succeeded, ref msg)) = self.automatic_remediation {
            let mut rem = JsonBuilder::new();
            rem.bool("attempted", attempted);
            rem.bool("succeeded", succeeded);
            rem.str("message", msg);
            b.raw("automatic_remediation", &rem.finish());
        }
        b.finish()
    }
}

/// Builds VMess security alerts matching `client/agent.py` lines 2025-2163.
pub fn build_vmess_alert(
    vmess: &ProtocolGuardPlan,
    scan_states: &[ProcessScanState],
    container: &AlertContainerContext,
) -> Option<ProtocolGuardAlert> {
    if !is_supported_runtime(&container.runtime) {
        return None;
    }
    let inst_id = truncate_chars(&container.instance_id, 200);
    if vmess.state == "release_pending" {
        let labels: Vec<String> = vmess
            .pending_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    ep.proto.as_deref(),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    true,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();
        let reason_label = match vmess.reason.as_str() {
            "guarded_port_still_has_listener" => "原受保护端口仍有进程监听，无法确认 VMess 服务已停止",
            "release_evidence_unavailable" => "缺少完整监听证据",
            "firewall_remove_failed" => "删除防火墙规则失败",
            "firewall_remove_readback_failed" => "删除后无法读回验证",
            "firewall_remove_readback_invalid" => "删除后的防火墙读回数据无效",
            "firewall_remove_unverified" => "无法确认防火墙规则已删除",
            "container_namespace_changed" => "容器网络命名空间发生变化，无法确认规则状态",
            "shared_network_namespace" => "容器与其他服务共用网络命名空间，不能安全修改端口规则",
            "container_namespace_unavailable" => "容器网络命名空间当前不可用",
            _ => "恢复条件尚未全部验证",
        };
        let mut detail = if vmess.detected {
            format!("当前只发现本地回环 VMess 监听，但无法确认旧端口阻断已解除：{reason_label}。")
        } else {
            format!("当前完整扫描未发现 VMess 入站，但无法确认旧端口阻断已解除：{reason_label}。")
        };
        if !labels.is_empty() {
            detail.push_str(&format!("待核实端口：{}。", labels.join("、")));
        }
        detail.push_str("只有确认端口无残留监听且规则删除后读回为空，Agent 才会报告恢复；未停止进程或容器。");

        return Some(ProtocolGuardAlert {
            alert_type: "vmess_block_release_unverified".to_string(),
            severity: "warning".to_string(),
            title: "VMess 端口恢复待核实".to_string(),
            message: detail,
            value: labels.len(),
            threshold: 0,
            runtime: container.runtime.clone(),
            project: container.project.clone(),
            container_name: container.name.clone(),
            instance_id: inst_id,
            alert_key: format!("vmess:release:{}", labels.join(",")),
            guard_field_name: "vmess_guard".to_string(),
            guard_json: vmess.to_json(),
            automatic_remediation: Some((
                true,
                false,
                "未确认规则已移除，旧规则保留".to_string(),
            )),
            context: container.clone(),
        });
    }

    if vmess.detected && matches!(vmess.state.as_str(), "blocked" | "partial" | "unverified") {
        let blocked_labels: Vec<String> = vmess
            .blocked_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    Some(&ep.proto),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    false,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();
        let pending_labels: Vec<String> = vmess
            .pending_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    ep.proto.as_deref(),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    true,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();

        if matches!(vmess.state.as_str(), "blocked" | "partial") && !blocked_labels.is_empty() {
            let title = if vmess.state == "blocked" {
                "VMess 入站端口已自动阻断"
            } else {
                "VMess 入站已部分阻断，仍有端口待核实"
            };
            let mut message = format!(
                "已从容器配置解析出 VMess 端口，并确认对应进程当前正在监听；已在该容器独立网络命名空间阻断：{}。未停止进程、容器或其他端口；建议迁移到 VLESS + Reality + Vision。",
                blocked_labels.join("、")
            );
            if !pending_labels.is_empty() || vmess.state == "partial" {
                let pend_text = if !pending_labels.is_empty() {
                    pending_labels.join("、")
                } else {
                    "具体端口暂无法确认".to_string()
                };
                message.push_str(&format!(" 另有入口待核实，未阻断：{pend_text}。"));
            }
            let mut all_labels = blocked_labels.clone();
            all_labels.extend(pending_labels);
            return Some(ProtocolGuardAlert {
                alert_type: "vmess_port_blocked".to_string(),
                severity: "warning".to_string(),
                title: title.to_string(),
                message,
                value: blocked_labels.len(),
                threshold: 0,
                runtime: container.runtime.clone(),
                project: container.project.clone(),
                container_name: container.name.clone(),
                instance_id: inst_id,
                alert_key: format!("vmess:{}", all_labels.join(",")),
                guard_field_name: "vmess_guard".to_string(),
                guard_json: vmess.to_json(),
                automatic_remediation: Some((
                    true,
                    vmess.state == "blocked",
                    "仅阻断配置端口与实时监听匹配且规则读回确认的 VMess 入口，未停止其他服务"
                        .to_string(),
                )),
                context: container.clone(),
            });
        }

        let labels: Vec<String> = if !pending_labels.is_empty() {
            pending_labels
        } else {
            vmess
                .pending_endpoints
                .iter()
                .filter(|ep| ep.port > 0)
                .map(|ep| ep.port.to_string())
                .collect()
        };
        let reason_key = vmess_unverified_reason_key(vmess, scan_states, &vmess.pending_endpoints);
        let reason = vmess_unverified_reason_label(&reason_key);
        let mut detail =
            format!("已检测到 VMess 配置，但未能安全确认端口保护：{reason}。未停止进程或容器。");
        if !labels.is_empty() {
            detail.push_str(&format!("待核实端口：{}。", labels.join("、")));
        }
        for item in scan_states
            .iter()
            .filter(|s| s.state != "complete")
            .take(4)
        {
            let proc_name = if item.process.is_empty() {
                "未知进程".to_string()
            } else {
                truncate_chars(&item.process, 40)
            };
            let pid_part = if item.pid > 0 {
                format!(" PID {}", item.pid)
            } else {
                String::new()
            };
            let scan_reason = if item.reason.is_empty() {
                "扫描证据不完整"
            } else {
                let l = vmess_unverified_reason_label(&item.reason);
                if l == "端口归属或规则生效状态未能确认" {
                    "扫描证据不完整"
                } else {
                    l
                }
            };
            detail.push_str(&format!("进程 {proc_name}{pid_part}：{scan_reason}。"));
            let safe_files: Vec<String> = item
                .config_files
                .iter()
                .take(4)
                .map(|p| truncate_chars(p, 180))
                .collect();
            if !safe_files.is_empty() {
                detail.push_str(&format!("已检查路径：{}。", safe_files.join("、")));
            }
        }
        detail.push_str("建议迁移到 VLESS + Reality + Vision。");

        return Some(ProtocolGuardAlert {
            alert_type: "vmess_block_unverified".to_string(),
            severity: "warning".to_string(),
            title: "VMess 入站保护待核实".to_string(),
            message: detail,
            value: labels.len(),
            threshold: 0,
            runtime: container.runtime.clone(),
            project: container.project.clone(),
            container_name: container.name.clone(),
            instance_id: inst_id,
            alert_key: format!("vmess:unverified:{}", labels.join(",")),
            guard_field_name: "vmess_guard".to_string(),
            guard_json: vmess.to_json(),
            automatic_remediation: None,
            context: container.clone(),
        });
    }

    None
}

/// Builds Trojan security alerts matching `client/agent.py` lines 2198-2278.
pub fn build_trojan_alert(
    trojan: &ProtocolGuardPlan,
    scan_states: &[ProcessScanState],
    container: &AlertContainerContext,
) -> Option<ProtocolGuardAlert> {
    if !is_supported_runtime(&container.runtime) {
        return None;
    }
    let inst_id = truncate_chars(&container.instance_id, 200);
    if trojan.state == "release_pending" {
        let labels: Vec<String> = trojan
            .pending_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    ep.proto.as_deref(),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    true,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();
        let mut detail = if !trojan.detected {
            "当前完整扫描未发现 Trojan 入站，但系统尚未确认旧端口阻断规则已安全删除。".to_string()
        } else {
            "当前仅发现本地回环 Trojan 监听，尚未确认旧端口规则可安全删除。".to_string()
        };
        if !labels.is_empty() {
            detail.push_str(&format!("待核实端口：{}。", labels.join("、")));
        }
        detail.push_str("规则只有在监听消失且 nftables 读回确认后才会移除；未停止进程或容器。");

        return Some(ProtocolGuardAlert {
            alert_type: "trojan_block_release_unverified".to_string(),
            severity: "warning".to_string(),
            title: "Trojan 端口恢复待核实".to_string(),
            message: detail,
            value: labels.len(),
            threshold: 0,
            runtime: container.runtime.clone(),
            project: container.project.clone(),
            container_name: container.name.clone(),
            instance_id: inst_id,
            alert_key: format!("trojan:release:{}", labels.join(",")),
            guard_field_name: "trojan_guard".to_string(),
            guard_json: trojan.to_json(),
            automatic_remediation: Some((
                true,
                false,
                "未确认 Trojan 规则已移除，旧规则保留".to_string(),
            )),
            context: container.clone(),
        });
    }

    if trojan.detected && matches!(trojan.state.as_str(), "blocked" | "partial" | "unverified") {
        let blocked_labels: Vec<String> = trojan
            .blocked_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    Some(&ep.proto),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    false,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();
        let pending_labels: Vec<String> = trojan
            .pending_endpoints
            .iter()
            .map(|ep| {
                vmess_endpoint_label(
                    ep.proto.as_deref(),
                    ep.port,
                    ep.pid,
                    ep.process.as_deref(),
                    true,
                )
            })
            .filter(|s| !s.is_empty())
            .collect();

        if matches!(trojan.state.as_str(), "blocked" | "partial") && !blocked_labels.is_empty() {
            let title = if trojan.state == "blocked" {
                "Trojan 入站端口已自动阻断"
            } else {
                "Trojan 入站已部分阻断，仍有端口待核实"
            };
            let mut message = format!(
                "已从容器配置解析出 Trojan 端口，并确认对应进程当前正在监听；已在该容器独立网络命名空间阻断：{}。未停止进程、容器或其他端口；这是网络保护策略，不代表认定用户滥用。",
                blocked_labels.join("、")
            );
            if !pending_labels.is_empty() {
                message.push_str(&format!(
                    " 另有入口待核实，未阻断：{}。",
                    pending_labels.join("、")
                ));
            }
            let mut all_labels = blocked_labels.clone();
            all_labels.extend(pending_labels);
            return Some(ProtocolGuardAlert {
                alert_type: "trojan_port_blocked".to_string(),
                severity: "warning".to_string(),
                title: title.to_string(),
                message,
                value: blocked_labels.len(),
                threshold: 0,
                runtime: container.runtime.clone(),
                project: container.project.clone(),
                container_name: container.name.clone(),
                instance_id: inst_id,
                alert_key: format!("trojan:{}", all_labels.join(",")),
                guard_field_name: "trojan_guard".to_string(),
                guard_json: trojan.to_json(),
                automatic_remediation: Some((
                    true,
                    trojan.state == "blocked",
                    "仅阻断配置端口与实时监听匹配且规则读回确认的 Trojan 入口，未停止其他服务"
                        .to_string(),
                )),
                context: container.clone(),
            });
        }

        let labels: Vec<String> = if !pending_labels.is_empty() {
            pending_labels
        } else {
            trojan
                .pending_endpoints
                .iter()
                .filter(|ep| ep.port > 0)
                .map(|ep| ep.port.to_string())
                .collect()
        };
        let reason_key = vmess_unverified_reason_key(trojan, scan_states, &trojan.pending_endpoints);
        let reason = trojan_unverified_reason_label(&reason_key);
        let mut detail = format!(
            "已在进程配置中发现 Trojan 入站，但尚未安全确认对应端口保护：{reason}。未停止进程或容器。"
        );
        if !labels.is_empty() {
            detail.push_str(&format!("待核实端口：{}。", labels.join("、")));
        }
        for item in scan_states
            .iter()
            .filter(|s| s.state != "complete")
            .take(3)
        {
            let proc_name = if item.process.is_empty() {
                "未知进程".to_string()
            } else {
                truncate_chars(&item.process, 40)
            };
            let pid_part = if item.pid > 0 {
                format!(" PID {}", item.pid)
            } else {
                String::new()
            };
            let scan_reason = if item.reason.is_empty() {
                "扫描证据不完整"
            } else {
                let l = trojan_unverified_reason_label(&item.reason);
                if l == "端口归属或规则生效状态未能确认" {
                    "扫描证据不完整"
                } else {
                    l
                }
            };
            detail.push_str(&format!("进程 {proc_name}{pid_part}：{scan_reason}。"));
            let safe_files: Vec<String> = item
                .config_files
                .iter()
                .take(3)
                .map(|p| truncate_chars(p, 180))
                .collect();
            if !safe_files.is_empty() {
                detail.push_str(&format!("已检查路径：{}。", safe_files.join("、")));
            }
        }

        return Some(ProtocolGuardAlert {
            alert_type: "trojan_block_unverified".to_string(),
            severity: "warning".to_string(),
            title: "Trojan 入站保护待核实".to_string(),
            message: detail,
            value: labels.len(),
            threshold: 0,
            runtime: container.runtime.clone(),
            project: container.project.clone(),
            container_name: container.name.clone(),
            instance_id: inst_id,
            alert_key: format!("trojan:unverified:{}", labels.join(",")),
            guard_field_name: "trojan_guard".to_string(),
            guard_json: trojan.to_json(),
            automatic_remediation: None,
            context: container.clone(),
        });
    }

    None
}

/// Suppresses unused import warning when `json_escape` is only used via `JsonBuilder`.
#[allow(dead_code)]
fn _keep_json_escape(s: &str) -> String {
    json_escape(s)
}

#[allow(dead_code)]
fn _keep_f64() -> f64 {
    current_unix_f64()
}

#[cfg(test)]
#[path = "vmess_tests.rs"]
mod tests;
