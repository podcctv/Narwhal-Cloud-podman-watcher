use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use runtime_drivers::JsonVal;

use crate::*;

// ---------------------------------------------------------------------------
// 6. Auto-throttle tier state machine (`auto_tier_rates`, `advance_direction`)
// ---------------------------------------------------------------------------

/// Return descending per-container caps (`50%`, `25%`, `5%`), ending at 1 Mbps where possible.
pub fn auto_tier_rates(base_mbps: u32) -> Vec<u32> {
    let mut rates: Vec<u32> = Vec::new();
    for pct in AUTO_TIER_PERCENTAGES {
        let computed = ((base_mbps as u64) * (pct as u64) / 100) as u32;
        let rate = computed.max(AUTO_MINIMUM_MBPS);
        if rate < base_mbps && rates.last().map_or(true, |&prev| rate < prev) {
            rates.push(rate);
        }
    }
    if base_mbps > AUTO_MINIMUM_MBPS && rates.last().map_or(true, |&prev| prev > AUTO_MINIMUM_MBPS)
    {
        rates.push(AUTO_MINIMUM_MBPS);
    }
    rates
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DirectionThrottleState {
    pub base_mbps: Option<u32>,
    pub stage: usize,
    pub high_seconds: u64,
    pub low_seconds: u64,
    pub last_sample_at: u64,
    pub last_usage_mbps: f64,
}

impl DirectionThrottleState {
    pub(crate) fn from_json(val: &JsonValue) -> Self {
        let Some(obj) = val.as_object() else {
            return Self::default();
        };
        let base_mbps = obj
            .get("base_mbps")
            .and_then(JsonValue::as_i64_lenient)
            .and_then(|v| u32::try_from(v).ok());
        let stage = obj
            .get("stage")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as usize)
            .unwrap_or(0);
        let high_seconds = obj
            .get("high_seconds")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let low_seconds = obj
            .get("low_seconds")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let last_sample_at = obj
            .get("last_sample_at")
            .and_then(JsonValue::as_i64_lenient)
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        let last_usage_mbps = obj
            .get("last_usage_mbps")
            .and_then(JsonValue::as_f64)
            .unwrap_or(0.0);
        Self {
            base_mbps,
            stage,
            high_seconds,
            low_seconds,
            last_sample_at,
            last_usage_mbps,
        }
    }

    pub(crate) fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        if let Some(base) = self.base_mbps {
            map.insert("base_mbps".to_string(), JsonValue::Number(base.to_string()));
        }
        map.insert("stage".to_string(), JsonValue::Number(self.stage.to_string()));
        map.insert(
            "high_seconds".to_string(),
            JsonValue::Number(self.high_seconds.to_string()),
        );
        map.insert(
            "low_seconds".to_string(),
            JsonValue::Number(self.low_seconds.to_string()),
        );
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        map.insert(
            "last_usage_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.last_usage_mbps)),
        );
        JsonValue::Object(map)
    }
}

/// Advance one direction's auto-throttle state by `sample_window_seconds` at `sample_at`.
pub fn advance_direction(
    record: &mut DirectionThrottleState,
    base_mbps: u32,
    usage_mbps: f64,
    sample_at: u64,
    sample_window_seconds: u64,
) {
    let tiers = auto_tier_rates(base_mbps);
    if let Some(prev_base) = record.base_mbps {
        if prev_base != base_mbps {
            record.stage = 0;
            record.high_seconds = 0;
            record.low_seconds = 0;
        }
    }
    record.base_mbps = Some(base_mbps);
    if tiers.is_empty() {
        record.stage = 0;
        record.high_seconds = 0;
        record.low_seconds = 0;
        record.last_sample_at = sample_at;
        return;
    }
    let stage = record.stage.min(tiers.len());
    let window = sample_window_seconds.clamp(1, 86_400);
    let current_limit = if stage > 0 {
        tiers[stage - 1]
    } else {
        base_mbps
    };
    let high_threshold = (current_limit as f64) * (AUTO_THRESHOLD_PERCENT as f64) / 100.0;
    let recovery_threshold = (current_limit as f64) * (AUTO_RECOVERY_PERCENT as f64) / 100.0;

    if stage < tiers.len() && usage_mbps >= high_threshold {
        let high_seconds = record.high_seconds.saturating_add(window);
        record.low_seconds = 0;
        if high_seconds >= AUTO_TRIGGER_SECONDS {
            record.stage = stage + 1;
            record.high_seconds = 0;
            record.low_seconds = 0;
        } else {
            record.high_seconds = high_seconds;
        }
    } else if stage > 0 && usage_mbps < recovery_threshold {
        let low_seconds = record.low_seconds.saturating_add(window);
        record.high_seconds = 0;
        if low_seconds >= AUTO_RECOVERY_SECONDS {
            record.stage = stage - 1;
            record.low_seconds = 0;
        } else {
            record.low_seconds = low_seconds;
        }
    } else {
        record.high_seconds = 0;
        record.low_seconds = 0;
    }
    record.last_sample_at = sample_at;
    record.last_usage_mbps = round3(usage_mbps);
}


// ---------------------------------------------------------------------------
// 10. Host link discovery & auto-throttle engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct HostLinkInfo {
    pub(crate) ifname: String,
    pub(crate) master_name: String,
    master_index: Option<u32>,
}

fn sysfs_host_links<R: TcRunner>(runner: &mut R) -> (BTreeMap<u32, HostLinkInfo>, String) {
    let root = Path::new("/sys/class/net");
    let names = match runner.list_dir(root) {
        Ok(list) => list,
        Err(err) => return (BTreeMap::new(), format!("cannot read /sys/class/net: {err}")),
    };
    let mut links = BTreeMap::new();
    for name in names.into_iter().take(512) {
        if !is_safe_sysfs_iface(&name) {
            continue;
        }
        let base = root.join(&name);
        let Ok(idx_raw) = runner.read_text(&base.join("ifindex")) else {
            continue;
        };
        let Ok(index) = idx_raw.trim().parse::<u32>() else {
            continue;
        };
        if index == 0 {
            continue;
        }
        let master_name = runner
            .read_link_basename(&base.join("master"))
            .unwrap_or_default();
        links.insert(
            index,
            HostLinkInfo {
                ifname: name,
                master_name,
                master_index: None,
            },
        );
    }
    let err = if links.is_empty() {
        "/sys/class/net contained no readable interfaces".to_string()
    } else {
        String::new()
    };
    (links, err)
}

fn proc_default_routes<R: TcRunner>(runner: &mut R) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    if let Ok(raw) = runner.read_text(Path::new("/proc/net/route")) {
        for line in raw.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 && fields[1] == "00000000" {
                let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
                if (flags & 0x1) != 0 && is_valid_iface_name(fields[0]) {
                    result.insert(fields[0].to_string());
                }
            }
        }
    }
    if let Ok(raw) = runner.read_text(Path::new("/proc/net/ipv6_route")) {
        for line in raw.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10
                && !fields[0].is_empty()
                && fields[0].bytes().all(|b| b == b'0')
                && fields[1] == "00"
                && is_valid_iface_name(fields[9])
            {
                result.insert(fields[9].to_string());
            }
        }
    }
    result
}

fn parse_host_links_array(val: &JsonVal) -> Option<BTreeMap<u32, HostLinkInfo>> {
    let JsonVal::Arr(arr) = val else {
        return None;
    };
    if arr.is_empty() {
        return None;
    }
    let mut map = BTreeMap::new();
    for item in arr.iter().take(512) {
        let Some(index) = item
            .get_u64("ifindex")
            .and_then(|v| u32::try_from(v).ok())
            .filter(|&i| i > 0)
        else {
            continue;
        };
        let ifname = item.get_str("ifname").unwrap_or("");
        if !is_valid_iface_name(ifname) {
            continue;
        }
        let (master_name, master_index) = match item.get("master") {
            Some(JsonVal::Str(s)) => (s.clone(), None),
            Some(JsonVal::Num(_)) => (
                String::new(),
                item.get_u64("master").and_then(|v| u32::try_from(v).ok()),
            ),
            _ => (String::new(), None),
        };
        map.insert(
            index,
            HostLinkInfo {
                ifname: ifname.to_string(),
                master_name,
                master_index,
            },
        );
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

pub(crate) fn host_link_snapshot<R: TcRunner>(
    runner: &mut R,
) -> (BTreeMap<u32, HostLinkInfo>, BTreeSet<String>, String) {
    let (code, output) = runner.run_cmd(&["ip", "-j", "link", "show"], DEFAULT_OUTPUT_LIMIT);
    let mut link_error = if code != 0 {
        format!("ip -j link show failed ({code}): {output}")
    } else {
        String::new()
    };
    let mut links = match JsonVal::parse(&output) {
        Ok(val) => parse_host_links_array(&val),
        Err(_) => {
            link_error = "ip -j link show returned invalid JSON".to_string();
            None
        }
    };

    if links.is_none() {
        let (fb_code, fb_output) =
            runner.run_cmd(&["ip", "-j", "address", "show"], DEFAULT_OUTPUT_LIMIT);
        let fb_parsed = if fb_code == 0 {
            JsonVal::parse(&fb_output)
                .ok()
                .and_then(|v| parse_host_links_array(&v))
        } else {
            None
        };
        if let Some(parsed) = fb_parsed {
            links = Some(parsed);
            link_error.clear();
        } else {
            link_error.push_str(&format!(
                "; ip -j address show failed ({fb_code}): {fb_output}"
            ));
        }
    }

    let return_links = if let Some(parsed) = links {
        parsed
    } else {
        let (sys_links, sys_err) = sysfs_host_links(runner);
        if sys_links.is_empty() {
            return (
                BTreeMap::new(),
                BTreeSet::new(),
                truncate_chars(&format!("{link_error}; {sys_err}"), 500),
            );
        }
        link_error.clear();
        sys_links
    };
    let _ = link_error;

    let (r_code, r_output) =
        runner.run_cmd(&["ip", "-j", "route", "show", "default"], DEFAULT_OUTPUT_LIMIT);
    let mut defaults = BTreeSet::new();
    if r_code == 0 {
        if let Ok(JsonVal::Arr(routes)) = JsonVal::parse(&r_output) {
            for route in routes {
                if let Some(dev) = route.get_str("dev") {
                    if is_valid_iface_name(dev) {
                        defaults.insert(dev.to_string());
                    }
                }
            }
        }
    }
    let mut route_error = if r_code != 0 {
        format!("ip -j route show default failed ({r_code}): {r_output}")
    } else {
        String::new()
    };
    if defaults.is_empty() {
        defaults.extend(proc_default_routes(runner));
        if !defaults.is_empty() {
            route_error.clear();
        }
    }
    (return_links, defaults, truncate_chars(&route_error, 500))
}

fn uses_selected_host_interface(
    selected: &str,
    peer_index: u32,
    host_links: &BTreeMap<u32, HostLinkInfo>,
    default_routes: &BTreeSet<String>,
    bridge_inventory: &[BridgeInterfaceInput],
) -> bool {
    if peer_index == 0 {
        return false;
    }
    let Some(peer) = host_links.get(&peer_index) else {
        return false;
    };
    let master_name = if let Some(midx) = peer.master_index {
        host_links
            .get(&midx)
            .map(|l| l.ifname.as_str())
            .unwrap_or("")
    } else {
        peer.master_name.as_str()
    };
    if peer.ifname == selected || master_name == selected {
        return true;
    }
    if !default_routes.contains(selected) || master_name.is_empty() {
        return false;
    }
    bridge_inventory.iter().any(|item| {
        item.kind == "bridge"
            && item.name == master_name
            && item
                .runtimes
                .iter()
                .any(|rt| RuntimeKind::parse(rt).is_some())
    })
}

fn finite_rate(val: Option<f64>) -> Option<f64> {
    val.filter(|&r| r.is_finite() && (0.0..1e15).contains(&r))
}

#[derive(Debug, Clone, Default)]
pub struct TrackedContainerState {
    pub identity: [String; 4],
    pub process_generation: String,
    pub namespace_inode: String,
    pub interface_index: u32,
    pub network_interface: String,
    pub state: String,
    pub sampling_state: String,
    pub message: String,
    pub last_sample_at: u64,
    pub directions: BTreeMap<String, DirectionThrottleState>,
}

impl TrackedContainerState {
    pub(crate) fn from_json(val: &JsonValue) -> Option<Self> {
        let obj = val.as_object()?;
        let id_arr = obj.get("identity").and_then(JsonValue::as_array)?;
        if id_arr.len() != 4 {
            return None;
        }
        let identity = [
            id_arr[0].as_str().unwrap_or("").to_string(),
            id_arr[1].as_str().unwrap_or("").to_string(),
            id_arr[2].as_str().unwrap_or("").to_string(),
            id_arr[3].as_str().unwrap_or("").to_string(),
        ];
        let mut directions = BTreeMap::new();
        if let Some(dir_obj) = obj.get("directions").and_then(JsonValue::as_object) {
            for (k, v) in dir_obj {
                if v.as_object().map_or(false, |m| !m.is_empty()) {
                    directions.insert(k.clone(), DirectionThrottleState::from_json(v));
                }
            }
        }
        Some(Self {
            identity,
            process_generation: obj
                .get("process_generation")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            namespace_inode: obj
                .get("namespace_inode")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            interface_index: obj
                .get("interface_index")
                .and_then(JsonValue::as_i64_lenient)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            network_interface: obj
                .get("network_interface")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            state: obj
                .get("state")
                .and_then(JsonValue::as_str)
                .unwrap_or("monitoring")
                .to_string(),
            sampling_state: obj
                .get("sampling_state")
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown")
                .to_string(),
            message: obj
                .get("message")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            last_sample_at: obj
                .get("last_sample_at")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as u64)
                .unwrap_or(0),
            directions,
        })
    }

    pub(crate) fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "identity".to_string(),
            JsonValue::Array(
                self.identity
                    .iter()
                    .map(|s| JsonValue::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "process_generation".to_string(),
            JsonValue::String(self.process_generation.clone()),
        );
        map.insert(
            "namespace_inode".to_string(),
            JsonValue::String(self.namespace_inode.clone()),
        );
        map.insert(
            "interface_index".to_string(),
            JsonValue::Number(self.interface_index.to_string()),
        );
        map.insert(
            "network_interface".to_string(),
            JsonValue::String(self.network_interface.clone()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "sampling_state".to_string(),
            JsonValue::String(self.sampling_state.clone()),
        );
        if !self.message.is_empty() {
            map.insert(
                "message".to_string(),
                JsonValue::String(self.message.clone()),
            );
        }
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        let mut dirs = BTreeMap::new();
        for (k, v) in &self.directions {
            dirs.insert(k.clone(), v.to_json_val());
        }
        map.insert("directions".to_string(), JsonValue::Object(dirs));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AutoThrottlePersistedState {
    pub interface: String,
    pub last_sample_at: u64,
    pub status: String,
    pub mapped_containers: usize,
    pub unmapped_containers: usize,
    pub unavailable_samples: usize,
    pub mapping_reason: String,
    pub mapping_error: String,
    pub containers: BTreeMap<String, TrackedContainerState>,
}

impl AutoThrottlePersistedState {
    pub(crate) fn from_json(val: &JsonValue) -> Option<Self> {
        let obj = val.as_object()?;
        let mut containers = BTreeMap::new();
        if let Some(c_obj) = obj.get("containers").and_then(JsonValue::as_object) {
            for (k, v) in c_obj {
                if let Some(tc) = TrackedContainerState::from_json(v) {
                    containers.insert(k.clone(), tc);
                }
            }
        }
        Some(Self {
            interface: obj
                .get("interface")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            last_sample_at: obj
                .get("last_sample_at")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as u64)
                .unwrap_or(0),
            status: obj
                .get("status")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            mapped_containers: obj
                .get("mapped_containers")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            unmapped_containers: obj
                .get("unmapped_containers")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            unavailable_samples: obj
                .get("unavailable_samples")
                .and_then(JsonValue::as_i64_lenient)
                .map(|v| v.max(0) as usize)
                .unwrap_or(0),
            mapping_reason: obj
                .get("mapping_reason")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            mapping_error: obj
                .get("mapping_error")
                .and_then(JsonValue::as_str)
                .unwrap_or("")
                .to_string(),
            containers,
        })
    }

    pub(crate) fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "last_sample_at".to_string(),
            JsonValue::Number(self.last_sample_at.to_string()),
        );
        if !self.status.is_empty() {
            map.insert("status".to_string(), JsonValue::String(self.status.clone()));
        }
        map.insert(
            "mapped_containers".to_string(),
            JsonValue::Number(self.mapped_containers.to_string()),
        );
        map.insert(
            "unmapped_containers".to_string(),
            JsonValue::Number(self.unmapped_containers.to_string()),
        );
        map.insert(
            "unavailable_samples".to_string(),
            JsonValue::Number(self.unavailable_samples.to_string()),
        );
        map.insert(
            "mapping_reason".to_string(),
            JsonValue::String(self.mapping_reason.clone()),
        );
        map.insert(
            "mapping_error".to_string(),
            JsonValue::String(self.mapping_error.clone()),
        );
        let mut c_map = BTreeMap::new();
        for (k, v) in &self.containers {
            c_map.insert(k.clone(), v.to_json_val());
        }
        map.insert("containers".to_string(), JsonValue::Object(c_map));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoThrottleStatusItem {
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub state: String,
    pub sampling_state: String,
    pub network_interface: String,
    pub upload_mbps: u32,
    pub download_mbps: u32,
    pub upload_current_mbps: f64,
    pub download_current_mbps: f64,
    pub upload_baseline_mbps: u32,
    pub download_baseline_mbps: u32,
    pub upload_high_seconds: u64,
    pub download_high_seconds: u64,
    pub upload_low_seconds: u64,
    pub download_low_seconds: u64,
}

impl AutoThrottleStatusItem {
    pub(crate) fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "runtime".to_string(),
            JsonValue::String(self.runtime.clone()),
        );
        map.insert(
            "project".to_string(),
            JsonValue::String(self.project.clone()),
        );
        map.insert(
            "container_name".to_string(),
            JsonValue::String(self.container_name.clone()),
        );
        map.insert(
            "container_id".to_string(),
            JsonValue::String(self.container_id.clone()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "sampling_state".to_string(),
            JsonValue::String(self.sampling_state.clone()),
        );
        map.insert(
            "network_interface".to_string(),
            JsonValue::String(self.network_interface.clone()),
        );
        map.insert(
            "upload_mbps".to_string(),
            JsonValue::Number(self.upload_mbps.to_string()),
        );
        map.insert(
            "download_mbps".to_string(),
            JsonValue::Number(self.download_mbps.to_string()),
        );
        map.insert(
            "upload_current_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.upload_current_mbps)),
        );
        map.insert(
            "download_current_mbps".to_string(),
            JsonValue::Number(format_f64_json(self.download_current_mbps)),
        );
        map.insert(
            "upload_baseline_mbps".to_string(),
            JsonValue::Number(self.upload_baseline_mbps.to_string()),
        );
        map.insert(
            "download_baseline_mbps".to_string(),
            JsonValue::Number(self.download_baseline_mbps.to_string()),
        );
        map.insert(
            "upload_high_seconds".to_string(),
            JsonValue::Number(self.upload_high_seconds.to_string()),
        );
        map.insert(
            "download_high_seconds".to_string(),
            JsonValue::Number(self.download_high_seconds.to_string()),
        );
        map.insert(
            "upload_low_seconds".to_string(),
            JsonValue::Number(self.upload_low_seconds.to_string()),
        );
        map.insert(
            "download_low_seconds".to_string(),
            JsonValue::Number(self.download_low_seconds.to_string()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AutoThrottleStatus {
    pub enabled: bool,
    pub state: String,
    pub interface: String,
    pub threshold_percent: u32,
    pub trigger_seconds: u64,
    pub tier_percentages: Vec<u32>,
    pub minimum_mbps: u32,
    pub recovery_percent: u32,
    pub recovery_seconds: u64,
    pub mapped_containers: Option<usize>,
    pub unmapped_containers: Option<usize>,
    pub unavailable_samples: Option<usize>,
    pub message: Option<String>,
    pub items: Vec<AutoThrottleStatusItem>,
}

impl AutoThrottleStatus {
    pub(crate) fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("enabled".to_string(), JsonValue::Bool(self.enabled));
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
        map.insert(
            "threshold_percent".to_string(),
            JsonValue::Number(self.threshold_percent.to_string()),
        );
        map.insert(
            "trigger_seconds".to_string(),
            JsonValue::Number(self.trigger_seconds.to_string()),
        );
        map.insert(
            "tier_percentages".to_string(),
            JsonValue::Array(
                self.tier_percentages
                    .iter()
                    .map(|p| JsonValue::Number(p.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "minimum_mbps".to_string(),
            JsonValue::Number(self.minimum_mbps.to_string()),
        );
        map.insert(
            "recovery_percent".to_string(),
            JsonValue::Number(self.recovery_percent.to_string()),
        );
        map.insert(
            "recovery_seconds".to_string(),
            JsonValue::Number(self.recovery_seconds.to_string()),
        );
        if let Some(v) = self.mapped_containers {
            map.insert(
                "mapped_containers".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(v) = self.unmapped_containers {
            map.insert(
                "unmapped_containers".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(v) = self.unavailable_samples {
            map.insert(
                "unavailable_samples".to_string(),
                JsonValue::Number(v.to_string()),
            );
        }
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        map.insert(
            "items".to_string(),
            JsonValue::Array(self.items.iter().map(AutoThrottleStatusItem::to_json_val).collect()),
        );
        JsonValue::Object(map)
    }
}

fn identity_key(id: &(String, String, String, String)) -> String {
    format!("{}\0{}\0{}\0{}", id.0, id.1, id.2, id.3)
}

pub(crate) fn compute_automatic_limits<R: TcRunner>(
    enabled: bool,
    host_limit: Option<&NormalizedLimit>,
    host_id: &str,
    containers: &[ContainerInput],
    traffic_samples: &[TrafficSampleInput],
    sample_at: u64,
    sample_interval_seconds: u64,
    bridge_inventory: &[BridgeInterfaceInput],
    state: &mut BandwidthState,
    runner: &mut R,
    peer_cache: &mut Option<Result<Vec<PeerEntry>, BandwidthError>>,
) -> (Vec<NormalizedLimit>, AutoThrottleStatus) {
    let host_limit = if enabled { host_limit } else { None };
    let enabled = enabled && host_limit.is_some();
    let interface = host_limit
        .map(|h| h.interface.clone())
        .unwrap_or_default();

    let mut auto_state = match state.auto_throttle_state.take() {
        Some(prev) if prev.interface == interface => prev,
        _ => AutoThrottlePersistedState {
            interface: interface.clone(),
            ..Default::default()
        },
    };

    if !enabled {
        state.auto_throttle_state = Some(AutoThrottlePersistedState {
            interface: String::new(),
            last_sample_at: sample_at,
            status: "disabled".to_string(),
            ..Default::default()
        });
        return (
            Vec::new(),
            AutoThrottleStatus {
                enabled: false,
                state: "disabled".to_string(),
                interface: String::new(),
                threshold_percent: AUTO_THRESHOLD_PERCENT,
                trigger_seconds: AUTO_TRIGGER_SECONDS,
                tier_percentages: AUTO_TIER_PERCENTAGES.to_vec(),
                minimum_mbps: AUTO_MINIMUM_MBPS,
                recovery_percent: AUTO_RECOVERY_PERCENT,
                recovery_seconds: AUTO_RECOVERY_SECONDS,
                mapped_containers: None,
                unmapped_containers: None,
                unavailable_samples: None,
                message: None,
                items: Vec::new(),
            },
        );
    }

    let host_limit = host_limit.expect("checked Some");
    let mut candidates: BTreeMap<(String, String, String, String), &ContainerInput> = BTreeMap::new();
    for item in containers {
        let id = item.identity();
        if RuntimeKind::parse(&id.0).is_some() && !id.2.is_empty() && !id.3.is_empty() {
            candidates.insert(id, item);
        }
    }

    let current_sample = sample_at;
    let previous_sample = auto_state.last_sample_at;
    if current_sample > previous_sample {
        let mut samples_map: BTreeMap<(String, String, String, String), &TrafficSampleInput> =
            BTreeMap::new();
        for s in traffic_samples {
            let id = s.identity();
            if RuntimeKind::parse(&id.0).is_some() && !id.2.is_empty() && !id.3.is_empty() {
                samples_map.insert(id, s);
            }
        }

        let (host_links, default_routes, host_network_error) = host_link_snapshot(runner);
        let mut mapping_reason = if host_links.is_empty() {
            "host_link_inventory_unavailable".to_string()
        } else {
            String::new()
        };
        if !host_network_error.is_empty() && mapping_reason.is_empty() {
            mapping_reason = "host_route_inventory_unavailable".to_string();
        }
        let host_namespace_inode = match runner.netns_inode(1) {
            Ok(ino) => ino.to_string(),
            Err(_) => {
                mapping_reason = "host_namespace_unavailable".to_string();
                String::new()
            }
        };

        let mut mapped_identities: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        let mut unmapped_identities: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        let mut unavailable_samples = 0usize;
        let mut namespace_owners: HashMap<String, Vec<(String, String, String, String)>> =
            HashMap::new();

        for identity in candidates.keys() {
            let item = NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: identity.0.clone(),
                project: identity.1.clone(),
                container_name: identity.2.clone(),
                container_id: identity.3.clone(),
                upload_mbps: 1,
                download_mbps: 1,
            };
            let key = identity_key(identity);
            let target = match resolve_container_cached(
                host_id,
                &item,
                containers,
                runner,
                peer_cache,
            ) {
                Ok(t) => t,
                Err(exc) => {
                    unmapped_identities.insert(identity.clone());
                    if let Some(prev) = auto_state.containers.get_mut(&key) {
                        prev.sampling_state = "target_unavailable".to_string();
                        prev.message = truncate_chars(exc.message(), 180);
                    }
                    continue;
                }
            };

            let ns_inode = target.namespace_inode.as_str();
            if ns_inode.is_empty()
                || host_namespace_inode.is_empty()
                || ns_inode == host_namespace_inode
            {
                unmapped_identities.insert(identity.clone());
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.state = "unmapped".to_string();
                    prev.sampling_state = if host_namespace_inode.is_empty() {
                        "host_namespace_unavailable".to_string()
                    } else {
                        "unsafe_shared_namespace".to_string()
                    };
                    prev.directions.clear();
                }
                continue;
            }

            let shared_with = namespace_owners.entry(ns_inode.to_string()).or_default();
            if !shared_with.is_empty() {
                for existing_id in shared_with.iter().chain(std::iter::once(identity)) {
                    mapped_identities.remove(existing_id);
                    unmapped_identities.insert(existing_id.clone());
                    let skey = identity_key(existing_id);
                    if let Some(srec) = auto_state.containers.get_mut(&skey) {
                        srec.state = "unmapped".to_string();
                        srec.sampling_state = "shared_network_namespace".to_string();
                        srec.directions.clear();
                    }
                }
                shared_with.push(identity.clone());
                continue;
            }
            shared_with.push(identity.clone());

            if !uses_selected_host_interface(
                &interface,
                target.peer_index,
                &host_links,
                &default_routes,
                bridge_inventory,
            ) {
                unmapped_identities.insert(identity.clone());
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.state = "unmapped".to_string();
                    prev.sampling_state = "interface_unmapped".to_string();
                    prev.directions.clear();
                }
                continue;
            }

            mapped_identities.insert(identity.clone());
            let Some(sample) = samples_map
                .get(identity)
                .filter(|s| s.traffic_counters_available)
            else {
                unavailable_samples += 1;
                if let Some(prev) = auto_state.containers.get_mut(&key) {
                    prev.sampling_state = "unavailable".to_string();
                }
                continue;
            };

            let same_process = auto_state.containers.get(&key).map_or(false, |prev| {
                prev.process_generation == target.process_generation
                    && prev.namespace_inode == target.namespace_inode
                    && prev.interface_index == target.interface_index
            });

            let mut record = if same_process {
                auto_state.containers.get(&key).cloned().unwrap_or_default()
            } else {
                TrackedContainerState {
                    identity: [
                        identity.0.clone(),
                        identity.1.clone(),
                        identity.2.clone(),
                        identity.3.clone(),
                    ],
                    process_generation: target.process_generation.clone(),
                    namespace_inode: target.namespace_inode.clone(),
                    interface_index: target.interface_index,
                    network_interface: target.interface.clone(),
                    ..Default::default()
                }
            };

            for (dir_name, rate_opt, base_mbps) in [
                ("upload", sample.net_tx_bps, host_limit.upload_mbps),
                ("download", sample.net_rx_bps, host_limit.download_mbps),
            ] {
                let Some(rate_bps) = finite_rate(rate_opt).filter(|_| base_mbps > 0) else {
                    record.directions.remove(dir_name);
                    continue;
                };
                let dir_state = record.directions.entry(dir_name.to_string()).or_default();
                if dir_state.last_sample_at >= current_sample {
                    continue;
                }
                advance_direction(
                    dir_state,
                    base_mbps,
                    rate_bps * 8.0 / 1_000_000.0,
                    current_sample,
                    sample_interval_seconds,
                );
            }

            let is_limited = record.directions.values().any(|d| d.stage > 0);
            record.identity = [
                identity.0.clone(),
                identity.1.clone(),
                identity.2.clone(),
                identity.3.clone(),
            ];
            record.process_generation = target.process_generation;
            record.namespace_inode = target.namespace_inode;
            record.interface_index = target.interface_index;
            record.network_interface = target.interface;
            record.state = if is_limited {
                "limited".to_string()
            } else {
                "monitoring".to_string()
            };
            record.sampling_state = "healthy".to_string();
            record.last_sample_at = current_sample;
            auto_state.containers.insert(key, record);
        }

        auto_state.last_sample_at = current_sample;
        auto_state.status = "monitoring".to_string();
        auto_state.mapped_containers = mapped_identities.len();
        auto_state.unmapped_containers = unmapped_identities.len();
        auto_state.unavailable_samples = unavailable_samples;
        auto_state.mapping_error = if !mapping_reason.is_empty() && !host_network_error.is_empty() {
            truncate_chars(&host_network_error, 500)
        } else {
            String::new()
        };
        auto_state.mapping_reason = mapping_reason;
    }

    auto_state.containers.retain(|_, rec| {
        !(current_sample > 0
            && rec.last_sample_at > 0
            && current_sample.saturating_sub(rec.last_sample_at) > PRUNE_DEPARTED_AFTER_SECS)
    });

    let mut auto_limits: Vec<NormalizedLimit> = Vec::new();
    let mut status_items: Vec<AutoThrottleStatusItem> = Vec::new();

    for rec in auto_state.containers.values() {
        let rt = &rec.identity[0];
        if RuntimeKind::parse(rt).is_none() {
            continue;
        }
        let upload_tiers = auto_tier_rates(host_limit.upload_mbps);
        let download_tiers = auto_tier_rates(host_limit.download_mbps);
        let upload_dir = rec.directions.get("upload");
        let download_dir = rec.directions.get("download");

        let upload_rate = upload_dir
            .filter(|d| d.stage >= 1 && d.stage <= upload_tiers.len())
            .map(|d| upload_tiers[d.stage - 1])
            .unwrap_or(0);
        let download_rate = download_dir
            .filter(|d| d.stage >= 1 && d.stage <= download_tiers.len())
            .map(|d| download_tiers[d.stage - 1])
            .unwrap_or(0);

        if upload_rate > 0 || download_rate > 0 {
            auto_limits.push(NormalizedLimit {
                scope: Scope::Container,
                interface: String::new(),
                runtime: rec.identity[0].clone(),
                project: rec.identity[1].clone(),
                container_name: rec.identity[2].clone(),
                container_id: rec.identity[3].clone(),
                upload_mbps: upload_rate,
                download_mbps: download_rate,
            });
        }

        status_items.push(AutoThrottleStatusItem {
            runtime: rec.identity[0].clone(),
            project: rec.identity[1].clone(),
            container_name: rec.identity[2].clone(),
            container_id: rec.identity[3].clone(),
            state: if rec.state.is_empty() {
                "monitoring".to_string()
            } else {
                rec.state.clone()
            },
            sampling_state: if rec.sampling_state.is_empty() {
                "unknown".to_string()
            } else {
                rec.sampling_state.clone()
            },
            network_interface: rec.network_interface.clone(),
            upload_mbps: upload_rate,
            download_mbps: download_rate,
            upload_current_mbps: upload_dir.map_or(0.0, |d| d.last_usage_mbps),
            download_current_mbps: download_dir.map_or(0.0, |d| d.last_usage_mbps),
            upload_baseline_mbps: host_limit.upload_mbps,
            download_baseline_mbps: host_limit.download_mbps,
            upload_high_seconds: upload_dir.map_or(0, |d| d.high_seconds),
            download_high_seconds: download_dir.map_or(0, |d| d.high_seconds),
            upload_low_seconds: upload_dir.map_or(0, |d| d.low_seconds),
            download_low_seconds: download_dir.map_or(0, |d| d.low_seconds),
        });
    }

    let status_state = if !auto_state.mapping_reason.is_empty() {
        "verification_unavailable"
    } else if auto_limits.is_empty() && auto_state.mapped_containers == 0 {
        "no_mapped_containers"
    } else if auto_limits.is_empty() && auto_state.unavailable_samples > 0 {
        "sampling_unavailable"
    } else if !auto_limits.is_empty() {
        "limited"
    } else {
        "monitoring"
    };

    let message = match auto_state.mapping_reason.as_str() {
        "host_namespace_unavailable" => {
            Some("宿主机网络命名空间不可读，已跳过自动限速路径核验".to_string())
        }
        "host_link_inventory_unavailable" => {
            let suffix = if auto_state.mapping_error.is_empty() {
                String::new()
            } else {
                format!("：{}", auto_state.mapping_error)
            };
            Some(format!(
                "宿主机网卡清单不可读，已跳过自动限速路径核验{suffix}"
            ))
        }
        "host_route_inventory_unavailable" => {
            let suffix = if auto_state.mapping_error.is_empty() {
                String::new()
            } else {
                format!("：{}", auto_state.mapping_error)
            };
            Some(format!(
                "宿主机路由清单不可读，无法确认容器是否经过所选网卡，已跳过自动限速路径核验{suffix}"
            ))
        }
        _ => None,
    };

    status_items.truncate(500);
    let status = AutoThrottleStatus {
        enabled: true,
        state: status_state.to_string(),
        interface,
        threshold_percent: AUTO_THRESHOLD_PERCENT,
        trigger_seconds: AUTO_TRIGGER_SECONDS,
        tier_percentages: AUTO_TIER_PERCENTAGES.to_vec(),
        minimum_mbps: AUTO_MINIMUM_MBPS,
        recovery_percent: AUTO_RECOVERY_PERCENT,
        recovery_seconds: AUTO_RECOVERY_SECONDS,
        mapped_containers: Some(auto_state.mapped_containers),
        unmapped_containers: Some(auto_state.unmapped_containers),
        unavailable_samples: Some(auto_state.unavailable_samples),
        message,
        items: status_items,
    };

    state.auto_throttle_state = Some(auto_state);
    (auto_limits, status)
}

pub fn merge_automatic_limits(
    manual_limits: &[NormalizedLimit],
    automatic_limits: &[NormalizedLimit],
) -> Vec<NormalizedLimit> {
    let mut merged = manual_limits.to_vec();
    let mut by_identity: HashMap<(String, String, String, String), usize> = HashMap::new();
    for (idx, item) in merged.iter().enumerate() {
        if item.scope == Scope::Container {
            by_identity.insert(
                (
                    item.runtime.clone(),
                    canonical_project(&item.runtime, &item.project).to_string(),
                    item.container_name.clone(),
                    item.container_id.clone(),
                ),
                idx,
            );
        }
    }
    for automatic in automatic_limits {
        let id = (
            automatic.runtime.clone(),
            canonical_project(&automatic.runtime, &automatic.project).to_string(),
            automatic.container_name.clone(),
            automatic.container_id.clone(),
        );
        if let Some(&idx) = by_identity.get(&id) {
            let current = &mut merged[idx];
            if automatic.upload_mbps > 0 {
                current.upload_mbps = if current.upload_mbps > 0 {
                    current.upload_mbps.min(automatic.upload_mbps)
                } else {
                    automatic.upload_mbps
                };
            }
            if automatic.download_mbps > 0 {
                current.download_mbps = if current.download_mbps > 0 {
                    current.download_mbps.min(automatic.download_mbps)
                } else {
                    automatic.download_mbps
                };
            }
        } else {
            by_identity.insert(id, merged.len());
            merged.push(automatic.clone());
        }
    }
    merged
}
