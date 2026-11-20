use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use runtime_drivers::ContainerSample;

use crate::*;

// ---------------------------------------------------------------------------
// 12. Status structs & reconciliation engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusItem {
    pub scope: String,
    pub target: String,
    pub interface: Option<String>,
    pub runtime: Option<String>,
    pub project: Option<String>,
    pub container_name: Option<String>,
    pub container_id: Option<String>,
    pub direction: Option<String>,
    pub rate_mbps: Option<u32>,
    pub state: String,
    pub message: Option<String>,
}

impl StatusItem {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        map.insert("target".to_string(), JsonValue::String(self.target.clone()));
        if let Some(ref v) = self.interface {
            map.insert("interface".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.runtime {
            map.insert("runtime".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.project {
            map.insert("project".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.container_name {
            map.insert("container_name".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.container_id {
            map.insert("container_id".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref v) = self.direction {
            map.insert("direction".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(v) = self.rate_mbps {
            map.insert("rate_mbps".to_string(), JsonValue::Number(v.to_string()));
        }
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        if let Some(ref v) = self.message {
            map.insert("message".to_string(), JsonValue::String(v.clone()));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryStatus {
    pub state: String,
}

impl RetryStatus {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert("attempts".to_string(), JsonValue::Null);
        map.insert("after_seconds".to_string(), JsonValue::Null);
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackAttemptResult {
    pub state: String,
    pub direction: String,
    pub message: Option<String>,
}

impl RollbackAttemptResult {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert(
            "direction".to_string(),
            JsonValue::String(self.direction.clone()),
        );
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackStatus {
    pub state: String,
    pub attempted: bool,
    pub results: Option<Vec<RollbackAttemptResult>>,
    pub restored: Option<usize>,
    pub errors: Option<Vec<String>>,
}

impl RollbackStatus {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        map.insert("attempted".to_string(), JsonValue::Bool(self.attempted));
        if let Some(ref res) = self.results {
            map.insert(
                "results".to_string(),
                JsonValue::Array(
                    res.iter()
                        .take(8)
                        .map(RollbackAttemptResult::to_json_val)
                        .collect(),
                ),
            );
        }
        if let Some(restored) = self.restored {
            map.insert(
                "restored".to_string(),
                JsonValue::Number(restored.to_string()),
            );
        }
        if let Some(ref errors) = self.errors {
            map.insert(
                "errors".to_string(),
                JsonValue::Array(
                    errors
                        .iter()
                        .take(5)
                        .map(|e| JsonValue::String(e.clone()))
                        .collect(),
                ),
            );
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLimitItem {
    pub scope: String,
    pub target: String,
    pub interface: String,
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub upload_mbps: u32,
    pub download_mbps: u32,
    pub last_confirmed_at: u64,
}

impl ActiveLimitItem {
    fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        map.insert("target".to_string(), JsonValue::String(self.target.clone()));
        map.insert(
            "interface".to_string(),
            JsonValue::String(self.interface.clone()),
        );
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
        map.insert(
            "upload_mbps".to_string(),
            JsonValue::Number(self.upload_mbps.to_string()),
        );
        map.insert(
            "download_mbps".to_string(),
            JsonValue::Number(self.download_mbps.to_string()),
        );
        map.insert(
            "last_confirmed_at".to_string(),
            JsonValue::Number(self.last_confirmed_at.to_string()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReconcileStatus {
    pub revision: i64,
    pub state: String,
    pub message: Option<String>,
    pub items: Vec<StatusItem>,
    pub retry: Option<RetryStatus>,
    pub rollback: Option<RollbackStatus>,
    pub auto_throttle: Option<AutoThrottleStatus>,
    pub updated_at: Option<u64>,
    pub active_limits: Option<Vec<ActiveLimitItem>>,
}

impl Default for ReconcileStatus {
    fn default() -> Self {
        Self {
            revision: 0,
            state: "unconfigured".to_string(),
            message: None,
            items: Vec::new(),
            retry: None,
            rollback: None,
            auto_throttle: None,
            updated_at: None,
            active_limits: None,
        }
    }
}

impl ReconcileStatus {
    pub fn to_json_val(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "revision".to_string(),
            JsonValue::Number(self.revision.to_string()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.clone()));
        if let Some(ref msg) = self.message {
            map.insert("message".to_string(), JsonValue::String(msg.clone()));
        }
        map.insert(
            "items".to_string(),
            JsonValue::Array(self.items.iter().map(StatusItem::to_json_val).collect()),
        );
        if let Some(ref retry) = self.retry {
            map.insert("retry".to_string(), retry.to_json_val());
        }
        if let Some(ref rollback) = self.rollback {
            map.insert("rollback".to_string(), rollback.to_json_val());
        }
        if let Some(ref auto) = self.auto_throttle {
            map.insert("auto_throttle".to_string(), auto.to_json_val());
        }
        if let Some(ts) = self.updated_at {
            map.insert("updated_at".to_string(), JsonValue::Number(ts.to_string()));
        }
        if let Some(ref active) = self.active_limits {
            map.insert(
                "active_limits".to_string(),
                JsonValue::Array(active.iter().map(ActiveLimitItem::to_json_val).collect()),
            );
        }
        JsonValue::Object(map)
    }

    pub fn to_json(&self) -> String {
        self.to_json_val().to_json()
    }
}

pub(crate) fn active_bandwidth_limits(
    entries: &BTreeMap<String, StoredEntry>,
    previous_status: Option<&JsonValue>,
) -> Vec<ActiveLimitItem> {
    let mut legacy_rates: HashMap<(String, String), BTreeMap<String, u32>> = HashMap::new();
    let mut legacy_full_rates: HashMap<(String, String, String, String), BTreeMap<String, u32>> =
        HashMap::new();

    if let Some(prev_items) = previous_status
        .and_then(|s| s.get("items"))
        .and_then(JsonValue::as_array)
    {
        for raw_item in prev_items {
            let Some(item) = raw_item.as_object() else {
                continue;
            };
            let state = item.get("state").and_then(JsonValue::as_str).unwrap_or("");
            if state != "applied" && state != "partial" {
                continue;
            }
            let scope = item.get("scope").and_then(JsonValue::as_str).unwrap_or("");
            let target = item
                .get("target")
                .or_else(|| item.get("container_name"))
                .or_else(|| item.get("interface"))
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if scope.is_empty() || target.is_empty() {
                continue;
            }
            let mut rates = BTreeMap::new();
            if let Some(dir) = item.get("direction").and_then(JsonValue::as_str) {
                if dir == "upload" || dir == "download" {
                    let rate = item
                        .get("rate_mbps")
                        .and_then(JsonValue::as_i64_lenient)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    if rate > 0 {
                        rates.insert(dir.to_string(), rate);
                    }
                }
            } else {
                for name in ["upload", "download"] {
                    let rate = item
                        .get(&format!("{name}_mbps"))
                        .and_then(JsonValue::as_i64_lenient)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    if rate > 0 {
                        rates.insert(name.to_string(), rate);
                    }
                }
            }
            if rates.is_empty() {
                continue;
            }
            let short_key = (scope.to_string(), target.to_string());
            let entry = legacy_rates.entry(short_key).or_default();
            for (k, v) in &rates {
                entry.insert(k.clone(), *v);
            }
            let runtime = item
                .get("runtime")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let project = item
                .get("project")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            let container_id = item
                .get("container_id")
                .and_then(JsonValue::as_str)
                .unwrap_or("");
            if scope == "container" && !runtime.is_empty() && !container_id.is_empty() {
                let full_key = (
                    scope.to_string(),
                    runtime.to_string(),
                    project.to_string(),
                    container_id.to_string(),
                );
                let full_entry = legacy_full_rates.entry(full_key).or_default();
                for (k, v) in &rates {
                    full_entry.insert(k.clone(), *v);
                }
            }
        }
    }

    let mut active = Vec::new();
    for entry in entries.values() {
        let scope = entry.scope.as_str();
        let target = if !entry.container_name.is_empty() {
            entry.container_name.as_str()
        } else {
            entry.interface.as_str()
        };
        if (scope != "host" && scope != "container") || target.is_empty() {
            continue;
        }
        let mut normalized_rates: BTreeMap<String, u32> = BTreeMap::new();
        for dir in ["upload", "download"] {
            if let Some(&r) = entry.rates_mbps.get(dir).filter(|&&r| r > 0) {
                normalized_rates.insert(dir.to_string(), r);
            }
        }
        if normalized_rates.is_empty() {
            if scope == "container" {
                let full_key = (
                    scope.to_string(),
                    entry.runtime.clone(),
                    entry.project.clone(),
                    entry.container_id.clone(),
                );
                if let Some(m) = legacy_full_rates.get(&full_key) {
                    normalized_rates = m.clone();
                } else if let Some(m) = legacy_rates.get(&(scope.to_string(), target.to_string()))
                {
                    normalized_rates = m.clone();
                }
            } else if let Some(m) = legacy_rates.get(&(scope.to_string(), target.to_string())) {
                normalized_rates = m.clone();
            }
        }
        if normalized_rates.is_empty() {
            continue;
        }
        active.push(ActiveLimitItem {
            scope: scope.to_string(),
            target: target.to_string(),
            interface: entry.interface.clone(),
            runtime: entry.runtime.clone(),
            project: entry.project.clone(),
            container_name: entry.container_name.clone(),
            container_id: entry.container_id.clone(),
            upload_mbps: *normalized_rates.get("upload").unwrap_or(&0),
            download_mbps: *normalized_rates.get("download").unwrap_or(&0),
            last_confirmed_at: entry.last_confirmed_at,
        });
    }
    active.sort_by(|a, b| {
        (
            a.scope.as_str(),
            a.runtime.as_str(),
            a.container_name.as_str(),
            a.interface.as_str(),
        )
            .cmp(&(
                b.scope.as_str(),
                b.runtime.as_str(),
                b.container_name.as_str(),
                b.interface.as_str(),
            ))
    });
    active
}

fn remove_entry<R: TcRunner>(
    entry: &StoredEntry,
    expected_host: &str,
    actual_host: &str,
    actual_node: &str,
    runner: &mut R,
) -> Result<Vec<Direction>, BandwidthError> {
    if expected_host != actual_host || entry.expected_node_id != actual_node {
        return Err(BandwidthError::policy(
            "stored tc ownership belongs to a different host enrollment",
        ));
    }
    if !is_valid_iface_name(&entry.interface) {
        return Err(BandwidthError::policy(
            "stored tc ownership has an invalid interface identity",
        ));
    }

    if entry.scope == "host" {
        match runner.host_ifindex(&entry.interface) {
            Ok(idx) => {
                if idx != entry.interface_index {
                    return Ok(Vec::new());
                }
            }
            Err(_) => {
                if entry.interface_index > 0 {
                    return Ok(Vec::new());
                }
                return Err(BandwidthError::policy(
                    "stored host interface identity could not be verified",
                ));
            }
        }
    } else {
        let pid = entry.pid;
        let ns_inode: u64 = entry.namespace_inode.parse().unwrap_or(0);
        if pid == 0 || ns_inode == 0 {
            return Err(BandwidthError::policy(
                "stored container network namespace identity is unavailable",
            ));
        }
        match runner.netns_inode(pid) {
            Err(NetnsError::NotFound) => return Ok(Vec::new()),
            Err(NetnsError::Unavailable(e)) => {
                return Err(BandwidthError::policy(format!(
                    "container network namespace cleanup could not be verified: {}",
                    truncate_chars(&e, 160)
                )))
            }
            Ok(current_ns) => {
                if current_ns != ns_inode {
                    return Err(BandwidthError::policy(
                        "container network namespace changed; prior filter cleanup cannot be verified",
                    ));
                }
            }
        }
        let (code, output) = call_with_prefix(
            runner,
            &entry.prefix,
            &["ip", "-j", "link", "show", "dev", &entry.interface],
        );
        if code != 0 {
            return Err(BandwidthError::policy(
                "container interface inventory is unavailable during cleanup",
            ));
        }
        let (current_idx, _) = parse_link_indices(&output).ok_or_else(|| {
            BandwidthError::policy("container interface identity could not be verified")
        })?;
        if current_idx == 0 {
            return Err(BandwidthError::policy(
                "container interface identity could not be verified",
            ));
        }
        if current_idx != entry.interface_index {
            return Ok(Vec::new());
        }
    }

    let mut removed: Vec<Direction> = Vec::new();
    for direction in Direction::BOTH {
        let pref = entry.filter_prefs.get(direction.as_str()).copied();
        match remove_filter(
            &entry.prefix,
            &entry.interface,
            &entry.owner_key,
            direction,
            pref,
            runner,
        ) {
            Ok(true) => removed.push(direction),
            Ok(false) => {}
            Err(remove_err) => {
                let mut rollback_errors: Vec<String> = Vec::new();
                for &rb_dir in removed.iter().rev() {
                    let rate = entry.rates_mbps.get(rb_dir.as_str()).copied().unwrap_or(0);
                    let res = if rate == 0 {
                        Err(BandwidthError::policy(format!(
                            "previous {} rate is unavailable",
                            rb_dir.as_str()
                        )))
                    } else {
                        apply_filter(
                            &entry.prefix,
                            &entry.interface,
                            &entry.owner_key,
                            rb_dir,
                            rate,
                            true,
                            entry.filter_prefs.get(rb_dir.as_str()).copied(),
                            runner,
                        )
                        .map(|_| ())
                    };
                    if let Err(rb_err) = res {
                        rollback_errors.push(format!(
                            "{}: {}",
                            rb_dir.as_str(),
                            truncate_chars(rb_err.message(), 120)
                        ));
                    }
                }
                let detail = if !rollback_errors.is_empty() {
                    format!(
                        "; rollback could not be verified: {}",
                        rollback_errors
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                } else if !removed.is_empty() {
                    let dirs = removed
                        .iter()
                        .rev()
                        .map(|d| d.as_str())
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("; removed filters restored and readback verified: {dirs}")
                } else {
                    String::new()
                };
                let rb_state = if !rollback_errors.is_empty() {
                    "failed"
                } else if !removed.is_empty() {
                    "verified"
                } else {
                    "not_needed"
                };
                return Err(BandwidthError::mutation(
                    format!(
                        "owned bandwidth filter cleanup failed: {}{detail}",
                        truncate_chars(remove_err.message(), 180)
                    ),
                    rb_state,
                ));
            }
        }
    }
    Ok(removed)
}

pub(crate) fn resolve_container_cached<R: TcRunner>(
    host_id: &str,
    item: &NormalizedLimit,
    containers: &[ContainerInput],
    runner: &mut R,
    peer_cache: &mut Option<Result<Vec<PeerEntry>, BandwidthError>>,
) -> Result<ResolvedTarget, BandwidthError> {
    if item.scope == Scope::Container {
        if peer_cache.is_none() {
            *peer_cache = Some(running_container_inventory(containers, runner));
        }
        let peers = match peer_cache.as_ref().expect("just populated") {
            Ok(p) => p.as_slice(),
            Err(e) => return Err(e.clone()),
        };
        return resolve_entry(host_id, item, containers, Some(peers), runner);
    }
    resolve_entry(host_id, item, containers, None, runner)
}

pub struct ReconcileRequest<'a> {
    pub policy_json: &'a str,
    pub host_id: &'a str,
    pub node_id: &'a str,
    pub containers: &'a [ContainerInput],
    pub state_path: &'a Path,
    pub traffic_samples: &'a [TrafficSampleInput],
    pub sample_at: u64,
    pub sample_interval_seconds: u64,
    pub bridge_inventory: &'a [BridgeInterfaceInput],
}

/// Reconcile bandwidth policy against kernel `tc` state using a provided `TcRunner`.
pub fn reconcile_with_runner<R: TcRunner>(
    req: &ReconcileRequest<'_>,
    runner: &mut R,
) -> ReconcileStatus {
    let mut state = read_state(req.state_path);
    if (!state.host_id.is_empty() && state.host_id != req.host_id)
        || (!state.expected_node_id.is_empty() && state.expected_node_id != req.node_id)
    {
        state = BandwidthState {
            schema: 1,
            host_id: req.host_id.to_string(),
            expected_node_id: req.node_id.to_string(),
            ..Default::default()
        };
    }
    state.host_id = req.host_id.to_string();
    state.expected_node_id = req.node_id.to_string();

    let previous_status = state.status.clone();
    let mut status = ReconcileStatus {
        revision: 0,
        state: "unconfigured".to_string(),
        message: None,
        items: Vec::new(),
        retry: Some(RetryStatus {
            state: "not_scheduled".to_string(),
        }),
        rollback: Some(RollbackStatus {
            state: "not_needed".to_string(),
            attempted: false,
            results: None,
            restored: None,
            errors: None,
        }),
        auto_throttle: None,
        updated_at: None,
        active_limits: None,
    };

    let normalized = match validate_policy(req.policy_json, req.host_id, req.node_id) {
        Ok(p) => p,
        Err(exc) => {
            status.state = "rejected".to_string();
            status.message = Some(exc.message().to_string());
            return status;
        }
    };
    status.revision = normalized.revision;

    let mut peer_cache: Option<Result<Vec<PeerEntry>, BandwidthError>> = None;
    let host_limit = normalized
        .limits
        .iter()
        .find(|item| item.scope == Scope::Host);
    let (automatic_limits, automatic_status) = compute_automatic_limits(
        normalized.auto_throttle_enabled,
        host_limit,
        req.host_id,
        req.containers,
        req.traffic_samples,
        req.sample_at,
        req.sample_interval_seconds.max(1),
        req.bridge_inventory,
        &mut state,
        runner,
        &mut peer_cache,
    );
    let effective_limits = merge_automatic_limits(&normalized.limits, &automatic_limits);
    status.auto_throttle = Some(automatic_status);

    let mut desired: Vec<(String, NormalizedLimit, ResolvedTarget)> = Vec::new();
    let mut desired_keys: HashSet<String> = HashSet::new();
    let mut requested_keys: HashSet<String> = HashSet::new();
    let mut cleanup_blocked_keys: HashSet<String> = HashSet::new();
    let mut failures = false;

    for item in &effective_limits {
        requested_keys.insert(item.key());
        match resolve_container_cached(
            req.host_id,
            item,
            req.containers,
            runner,
            &mut peer_cache,
        ) {
            Ok(target) => {
                let k = target.key.clone();
                if let Some(pos) = desired.iter().position(|(dk, _, _)| dk == &k) {
                    desired[pos] = (k, item.clone(), target);
                } else {
                    desired_keys.insert(k.clone());
                    desired.push((k, item.clone(), target));
                }
            }
            Err(exc) => {
                failures = true;
                status.items.push(StatusItem {
                    scope: item.scope.as_str().to_string(),
                    target: item.target_label().to_string(),
                    interface: None,
                    runtime: None,
                    project: None,
                    container_name: None,
                    container_id: None,
                    direction: None,
                    rate_mbps: None,
                    state: "failed".to_string(),
                    message: Some(truncate_chars(exc.message(), 240)),
                });
            }
        }
    }

    let mut rollback_operations: Vec<RollbackOperation> = Vec::new();
    let mut rollback_attempts: Vec<RollbackAttemptResult> = Vec::new();
    let existing_keys: Vec<String> = state.entries.keys().cloned().collect();

    for key in existing_keys {
        if requested_keys.contains(&key) && !desired_keys.contains(&key) {
            continue;
        }
        let Some(old) = state.entries.get(&key).cloned() else {
            continue;
        };
        let same_netns = desired.iter().find(|(dk, _, _)| dk == &key).map_or(
            false,
            |(_, _, new_target)| {
                old.namespace_inode == new_target.namespace_inode
                    && old.interface == new_target.interface
                    && old.interface_index == new_target.interface_index
            },
        );
        if same_netns {
            continue;
        }
        match remove_entry(&old, req.host_id, req.host_id, req.node_id, runner) {
            Ok(removed_dirs) => {
                for dir in removed_dirs {
                    rollback_operations.push(RollbackOperation {
                        prefix: old.prefix.clone(),
                        interface: old.interface.clone(),
                        owner_key: old.owner_key.clone(),
                        direction: dir,
                        previously_owned: true,
                        previous_rate_mbps: old.rates_mbps.get(dir.as_str()).copied(),
                        previous_pref: old.filter_prefs.get(dir.as_str()).copied(),
                    });
                }
                state.entries.remove(&key);
            }
            Err(exc) => {
                failures = true;
                cleanup_blocked_keys.insert(key.clone());
                if let Some(rb_state) = exc.rollback_state() {
                    if rb_state != "not_needed" {
                        rollback_attempts.push(RollbackAttemptResult {
                            state: rb_state.to_string(),
                            direction: "cleanup".to_string(),
                            message: Some(truncate_chars(exc.message(), 180)),
                        });
                    }
                }
                let target_label = if !old.container_name.is_empty() {
                    old.container_name.clone()
                } else {
                    old.interface.clone()
                };
                status.items.push(StatusItem {
                    scope: old.scope.clone(),
                    target: target_label,
                    interface: None,
                    runtime: None,
                    project: None,
                    container_name: None,
                    container_id: None,
                    direction: None,
                    rate_mbps: None,
                    state: "cleanup_failed".to_string(),
                    message: Some(truncate_chars(exc.message(), 240)),
                });
            }
        }
    }

    for (key, item, target) in &desired {
        if cleanup_blocked_keys.contains(key) {
            status.items.push(StatusItem {
                scope: item.scope.as_str().to_string(),
                target: item.target_label().to_string(),
                interface: None,
                runtime: None,
                project: None,
                container_name: None,
                container_id: None,
                direction: None,
                rate_mbps: None,
                state: "failed".to_string(),
                message: Some(
                    "旧的 tc 所有限额无法确认清理，已保留原记录并跳过新规则应用".to_string(),
                ),
            });
            continue;
        }

        let old = state.entries.get(key).cloned();
        let same_target = old.as_ref().map_or(false, |o| {
            o.namespace_inode == target.namespace_inode
                && o.interface == target.interface
                && o.interface_index == target.interface_index
        });

        if let Err(exc) = ensure_clsact(&target.prefix, &target.interface, runner) {
            failures = true;
            status.items.push(StatusItem {
                scope: item.scope.as_str().to_string(),
                target: item.target_label().to_string(),
                interface: Some(target.interface.clone()),
                runtime: Some(item.runtime.clone()),
                project: Some(item.project.clone()),
                container_name: Some(item.container_name.clone()),
                container_id: Some(item.container_id.clone()),
                direction: None,
                rate_mbps: None,
                state: "failed".to_string(),
                message: Some(truncate_chars(exc.message(), 240)),
            });
            continue;
        }

        let old_directions: BTreeSet<String> = if same_target {
            old.as_ref()
                .map(|o| o.directions.iter().cloned().collect())
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut rates: BTreeMap<String, u32> = BTreeMap::new();
        let mut filter_prefs: BTreeMap<String, u16> = BTreeMap::new();
        let mut confirmed_at: BTreeMap<String, u64> = BTreeMap::new();
        if same_target {
            if let Some(ref o) = old {
                for d in &old_directions {
                    if let Some(&r) = o.rates_mbps.get(d) {
                        rates.insert(d.clone(), r);
                    }
                    if let Some(&p) = o.filter_prefs.get(d) {
                        filter_prefs.insert(d.clone(), p);
                    }
                    if let Some(&c) = o.confirmed_at.get(d) {
                        confirmed_at.insert(d.clone(), c);
                    }
                }
            }
        }
        let mut installed = old_directions.clone();

        for direction in Direction::BOTH {
            let dir_str = direction.as_str();
            let rate = item.rate_for(direction);
            let owned = old_directions.contains(dir_str);
            let prev_rate = old
                .as_ref()
                .filter(|_| same_target)
                .and_then(|o| o.rates_mbps.get(dir_str).copied());
            let prev_pref = old
                .as_ref()
                .filter(|_| same_target)
                .and_then(|o| o.filter_prefs.get(dir_str).copied());

            if rate > 0 {
                let op = RollbackOperation {
                    prefix: target.prefix.clone(),
                    interface: target.interface.clone(),
                    owner_key: target.owner_key.clone(),
                    direction,
                    previously_owned: owned,
                    previous_rate_mbps: prev_rate,
                    previous_pref: prev_pref,
                };
                match apply_filter(
                    &target.prefix,
                    &target.interface,
                    &target.owner_key,
                    direction,
                    rate,
                    owned,
                    filter_prefs.get(dir_str).copied(),
                    runner,
                ) {
                    Ok(applied_pref) => {
                        let applied_pref = if (PREF_RANGE_START..PREF_RANGE_END)
                            .contains(&applied_pref)
                        {
                            applied_pref
                        } else {
                            filter_prefs
                                .get(dir_str)
                                .copied()
                                .filter(|&p| (PREF_RANGE_START..PREF_RANGE_END).contains(&p))
                                .unwrap_or_else(|| direction.default_pref())
                        };
                        installed.insert(dir_str.to_string());
                        rates.insert(dir_str.to_string(), rate);
                        filter_prefs.insert(dir_str.to_string(), applied_pref);
                        confirmed_at.insert(dir_str.to_string(), runner.now_unix());
                        rollback_operations.push(op);
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(rate),
                            state: "applied".to_string(),
                            message: None,
                        });
                    }
                    Err(exc) => {
                        match rollback_bandwidth_mutation(&op, runner) {
                            Ok(()) => rollback_attempts.push(RollbackAttemptResult {
                                state: "verified".to_string(),
                                direction: dir_str.to_string(),
                                message: None,
                            }),
                            Err(rb_exc) => rollback_attempts.push(RollbackAttemptResult {
                                state: "failed".to_string(),
                                direction: dir_str.to_string(),
                                message: Some(truncate_chars(rb_exc.message(), 180)),
                            }),
                        }
                        failures = true;
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(rate),
                            state: "failed".to_string(),
                            message: Some(truncate_chars(exc.message(), 240)),
                        });
                    }
                }
            } else if owned {
                let op = RollbackOperation {
                    prefix: target.prefix.clone(),
                    interface: target.interface.clone(),
                    owner_key: target.owner_key.clone(),
                    direction,
                    previously_owned: true,
                    previous_rate_mbps: prev_rate,
                    previous_pref: prev_pref,
                };
                match remove_filter(
                    &target.prefix,
                    &target.interface,
                    &target.owner_key,
                    direction,
                    filter_prefs.get(dir_str).copied(),
                    runner,
                ) {
                    Ok(_) => {
                        rollback_operations.push(op);
                        installed.remove(dir_str);
                        rates.remove(dir_str);
                        filter_prefs.remove(dir_str);
                        confirmed_at.remove(dir_str);
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(0),
                            state: "removed".to_string(),
                            message: None,
                        });
                    }
                    Err(exc) => {
                        failures = true;
                        status.items.push(StatusItem {
                            scope: item.scope.as_str().to_string(),
                            target: item.target_label().to_string(),
                            interface: Some(target.interface.clone()),
                            runtime: Some(item.runtime.clone()),
                            project: Some(item.project.clone()),
                            container_name: Some(item.container_name.clone()),
                            container_id: Some(item.container_id.clone()),
                            direction: Some(dir_str.to_string()),
                            rate_mbps: Some(0),
                            state: "failed".to_string(),
                            message: Some(truncate_chars(exc.message(), 240)),
                        });
                    }
                }
            }
        }

        if !installed.is_empty() {
            let last_confirmed_at = confirmed_at.values().copied().max().unwrap_or(0);
            state.entries.insert(
                key.clone(),
                StoredEntry {
                    key: target.key.clone(),
                    owner_key: target.owner_key.clone(),
                    expected_node_id: req.node_id.to_string(),
                    scope: target.scope.as_str().to_string(),
                    runtime: target.runtime.clone(),
                    project: target.project.clone(),
                    container_name: target.container_name.clone(),
                    container_id: target.container_id.clone(),
                    prefix: target.prefix.clone(),
                    pid: target.pid,
                    process_generation: target.process_generation.clone(),
                    interface: target.interface.clone(),
                    interface_index: target.interface_index,
                    peer_index: target.peer_index,
                    namespace_inode: target.namespace_inode.clone(),
                    directions: installed.into_iter().collect(),
                    rates_mbps: rates,
                    filter_prefs,
                    confirmed_at,
                    last_confirmed_at,
                },
            );
        } else {
            state.entries.remove(key);
        }
    }

    status.state = if failures {
        "failed"
    } else if !desired.is_empty() {
        "applied"
    } else {
        "unconfigured"
    }
    .to_string();
    status.retry = Some(RetryStatus {
        state: if failures {
            "next_agent_cycle"
        } else {
            "not_scheduled"
        }
        .to_string(),
    });
    if !rollback_attempts.is_empty() {
        let rb_failed = rollback_attempts.iter().any(|r| r.state == "failed");
        status.rollback = Some(RollbackStatus {
            state: if rb_failed { "failed" } else { "verified" }.to_string(),
            attempted: true,
            results: Some(rollback_attempts.into_iter().take(8).collect()),
            restored: None,
            errors: None,
        });
    }
    status.updated_at = Some(runner.now_unix());
    status.active_limits = Some(active_bandwidth_limits(
        &state.entries,
        previous_status.as_ref(),
    ));
    state.revision = normalized.revision;
    state.status = Some(status.to_json_val());

    if write_state_atomic(req.state_path, &state).is_err() {
        let mut rollback_errors = Vec::new();
        let mut restored = 0usize;
        for op in rollback_operations.iter().rev() {
            match rollback_bandwidth_mutation(op, runner) {
                Ok(()) => restored += 1,
                Err(exc) => rollback_errors.push(truncate_chars(exc.message(), 180)),
            }
        }
        let persisted = read_state(req.state_path);
        status.active_limits = Some(active_bandwidth_limits(
            &persisted.entries,
            persisted.status.as_ref(),
        ));
        status.rollback = Some(RollbackStatus {
            state: if rollback_errors.is_empty() {
                "verified"
            } else {
                "failed"
            }
            .to_string(),
            attempted: !rollback_operations.is_empty(),
            results: None,
            restored: Some(restored),
            errors: Some(rollback_errors.iter().take(5).cloned().collect()),
        });
        status.retry = Some(RetryStatus {
            state: "next_agent_cycle".to_string(),
        });
        status.state = "failed".to_string();
        status.message = Some(format!(
            "本地 tc 所有权状态保存失败；{}",
            if rollback_errors.is_empty() {
                "已恢复保存前的限额并逐项读回确认"
            } else {
                "回滚存在未确认项"
            }
        ));
    }

    status
}

/// Live entry point using `LiveRunner` against the real OS (`tc`, `ip`, `nsenter`, `/proc`, `/sys`).
pub fn reconcile_live(req: &ReconcileRequest<'_>) -> ReconcileStatus {
    let mut runner = LiveRunner;
    reconcile_with_runner(req, &mut runner)
}

/// Convenience live reconciliation wrapper accepting `runtime_drivers::ContainerSample`.
pub fn reconcile_live_samples(
    policy_json: &str,
    host_id: &str,
    node_id: &str,
    containers: &[ContainerSample],
    state_path: &Path,
    traffic_samples: &[TrafficSampleInput],
    sample_at: u64,
    sample_interval_seconds: u64,
    bridge_inventory: &[BridgeInterfaceInput],
) -> ReconcileStatus {
    let converted: Vec<ContainerInput> = containers.iter().map(ContainerInput::from).collect();
    let req = ReconcileRequest {
        policy_json,
        host_id,
        node_id,
        containers: &converted,
        state_path,
        traffic_samples,
        sample_at,
        sample_interval_seconds,
        bridge_inventory,
    };
    reconcile_live(&req)
}

/// Read the last persisted `status` JSON object from `state_path`, or return the unconfigured default.
pub fn last_status_json(state_path: &Path) -> String {
    let state = read_state(state_path);
    match state.status {
        Some(val) if val.as_object().is_some() => val.to_json(),
        _ => ReconcileStatus::default().to_json(),
    }
}
