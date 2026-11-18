#![allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proc_probe::json_escape;
use runtime_drivers::JsonVal;
use crate::*;

use super::util::{
    atomic_write_private, json_str, json_val_to_string, now_unix_secs, JsonObjBuilder,
};

pub const DEFAULT_RETENTION_DAYS: u16 = 14;
pub const MIN_RETENTION_DAYS: u16 = 14;
pub const MAX_RETENTION_DAYS: u16 = 90;
pub const DEFAULT_INTERVAL_HOURS: u16 = 24;
pub const MIN_INTERVAL_HOURS: u16 = 6;
pub const MAX_INTERVAL_HOURS: u16 = 168;

pub const DAY_SECONDS: i64 = 86_400;
pub const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_FILES: usize = 1000;
pub const MAX_VISITED_ENTRIES: usize = 20_000;
pub const SCAN_PLAN_MAX_AGE_SECS: i64 = 900;
pub const MAX_TARGETS_PER_RUN: usize = 5;
pub const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
pub const DEFAULT_STATE_PATH: &str = "/var/lib/narwhal-monitor/disk-cleanup.json";

pub const PROTECTED_CONTAINERS: &[&str] = &[
    "narwhal-monitor-client",
    "narwhal-monitor-server",
    "narwhal-monitor-caddy",
];
pub const ALLOWED_RUNTIMES: &[&str] = &["incus", "podman", "runman"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupPolicy {
    pub enabled: bool,
    pub include_containers: bool,
    pub retention_days: u16,
    pub interval_hours: u16,
}

impl Default for CleanupPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            include_containers: true,
            retention_days: DEFAULT_RETENTION_DAYS,
            interval_hours: DEFAULT_INTERVAL_HOURS,
        }
    }
}

impl CleanupPolicy {
    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.bool("enabled", self.enabled);
        b.bool("include_containers", self.include_containers);
        b.u64("retention_days", self.retention_days as u64);
        b.u64("interval_hours", self.interval_hours as u64);
        b.finish()
    }
}

/// Validate cleanup policy JSON (`retention_days` 14..=90, `interval_hours` 6..=168).
/// When `expected_node_id` is supplied, a mismatched or missing `node_id` fails closed to `CleanupPolicy::default()`.
pub fn validate_cleanup_policy(
    policy_json: &str,
    expected_node_id: Option<&str>,
) -> Result<CleanupPolicy, String> {
    let val = JsonVal::parse(policy_json.trim())
        .map_err(|_| "invalid cleanup policy JSON".to_string())?;
    let Some(obj) = val.as_obj() else {
        return Ok(CleanupPolicy::default());
    };
    if let Some(expected) = expected_node_id {
        let got = obj.get("node_id").and_then(JsonVal::as_str).unwrap_or("");
        if expected.is_empty() || got != expected {
            return Ok(CleanupPolicy::default());
        }
    }
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "enabled" | "include_containers" | "retention_days" | "interval_hours" | "node_id"
        ) {
            return Err(format!("unknown cleanup policy key: {key}"));
        }
    }
    let mut result = CleanupPolicy::default();
    if let Some(v) = obj.get("enabled") {
        result.enabled = v
            .as_bool()
            .ok_or_else(|| "boolean policy required for enabled".to_string())?;
    }
    if let Some(v) = obj.get("include_containers") {
        result.include_containers = v
            .as_bool()
            .ok_or_else(|| "boolean policy required for include_containers".to_string())?;
    }
    if let Some(v) = obj.get("retention_days") {
        let days = v
            .as_i64()
            .ok_or_else(|| "retention must be 14-90 days".to_string())?;
        if !(MIN_RETENTION_DAYS as i64..=MAX_RETENTION_DAYS as i64).contains(&days) {
            return Err("retention must be 14-90 days".to_string());
        }
        result.retention_days = days as u16;
    }
    if let Some(v) = obj.get("interval_hours") {
        let hours = v
            .as_i64()
            .ok_or_else(|| "interval must be 6-168 hours".to_string())?;
        if !(MIN_INTERVAL_HOURS as i64..=MAX_INTERVAL_HOURS as i64).contains(&hours) {
            return Err("interval must be 6-168 hours".to_string());
        }
        result.interval_hours = hours as u16;
    }
    Ok(result)
}

pub fn validate_cleanup_policy_json(
    policy_json: &str,
    expected_node_id: Option<&str>,
) -> String {
    match validate_cleanup_policy(policy_json, expected_node_id) {
        Ok(p) => {
            let mut b = JsonObjBuilder::new();
            b.bool("ok", true);
            b.raw("policy", &p.to_json());
            b.finish()
        }
        Err(err) => {
            let mut b = JsonObjBuilder::new();
            b.bool("ok", false);
            b.str("error", &err);
            b.finish()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupTarget {
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub stable_id: String,
    pub instance_id: String,
    pub pid: String,
    pub pid_start_ticks: String,
}

impl CleanupTarget {
    pub fn host() -> Self {
        Self {
            runtime: "host".to_string(),
            runtime_bin: String::new(),
            project: String::new(),
            name: "__host__".to_string(),
            id: "host".to_string(),
            stable_id: String::new(),
            instance_id: String::new(),
            pid: String::new(),
            pid_start_ticks: String::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.str("runtime", &self.runtime);
        b.str("runtime_bin", &self.runtime_bin);
        b.str("project", &self.project);
        b.str("name", &self.name);
        b.str("id", &self.id);
        b.str("stable_id", &self.stable_id);
        b.str("instance_id", &self.instance_id);
        b.str("pid", &self.pid);
        b.str("pid_start_ticks", &self.pid_start_ticks);
        b.finish()
    }

    fn from_json(val: &JsonVal) -> Result<Self, String> {
        let obj = val
            .as_obj()
            .ok_or_else(|| "invalid cleanup target object".to_string())?;
        let get_str = |k: &str| obj.get(k).and_then(JsonVal::as_str).unwrap_or("").to_string();
        Ok(Self {
            runtime: get_str("runtime"),
            runtime_bin: get_str("runtime_bin"),
            project: get_str("project"),
            name: get_str("name"),
            id: get_str("id"),
            stable_id: get_str("stable_id"),
            instance_id: get_str("instance_id"),
            pid: get_str("pid"),
            pid_start_ticks: get_str("pid_start_ticks"),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupRunItem {
    pub runtime: String,
    pub name: String,
    pub project: String,
    pub status: String,
    pub reason: String,
    pub instance_id: String,
    pub candidate_files: usize,
    pub candidate_bytes: u64,
    pub deleted_files: usize,
    pub unlinked_bytes: u64,
    pub freed_bytes: u64,
    pub skipped: usize,
    pub errors: usize,
    pub bounded: bool,
    pub extra_fields: BTreeMap<String, JsonVal>,
}

impl CleanupRunItem {
    fn from_json(val: &JsonVal) -> Result<Self, String> {
        let obj = val
            .as_obj()
            .ok_or_else(|| "invalid cleanup run item".to_string())?;
        let mut extra = BTreeMap::new();
        for (k, v) in obj {
            if !matches!(
                k.as_str(),
                "runtime"
                    | "name"
                    | "project"
                    | "status"
                    | "reason"
                    | "instance_id"
                    | "candidate_files"
                    | "candidate_bytes"
                    | "deleted_files"
                    | "unlinked_bytes"
                    | "freed_bytes"
                    | "skipped"
                    | "errors"
                    | "bounded"
            ) {
                extra.insert(k.clone(), v.clone());
            }
        }
        Ok(Self {
            runtime: obj.get("runtime").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            name: obj.get("name").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            project: obj.get("project").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            status: obj.get("status").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            reason: obj.get("reason").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            instance_id: obj.get("instance_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            candidate_files: obj.get("candidate_files").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
            candidate_bytes: obj.get("candidate_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
            deleted_files: obj.get("deleted_files").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
            unlinked_bytes: obj.get("unlinked_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
            freed_bytes: obj.get("freed_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
            skipped: obj.get("skipped").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
            errors: obj.get("errors").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
            bounded: obj.get("bounded").and_then(JsonVal::as_bool).unwrap_or(false),
            extra_fields: extra,
        })
    }

    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.str("runtime", &self.runtime);
        b.str("name", &self.name);
        b.str("project", &self.project);
        b.str("status", &self.status);
        if !self.reason.is_empty() {
            b.str("reason", &self.reason);
        }
        if !self.instance_id.is_empty() {
            b.str("instance_id", &self.instance_id);
        }
        b.usize("candidate_files", self.candidate_files);
        b.u64("candidate_bytes", self.candidate_bytes);
        b.usize("deleted_files", self.deleted_files);
        b.u64("unlinked_bytes", self.unlinked_bytes);
        b.u64("freed_bytes", self.freed_bytes);
        b.usize("skipped", self.skipped);
        b.usize("errors", self.errors);
        b.bool("bounded", self.bounded);
        for (k, v) in &self.extra_fields {
            b.raw(k, &json_val_to_string(v));
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupRunRecord {
    pub run_id: String,
    pub action_id: i64,
    pub node_id: String,
    pub mode: String,
    pub automatic: bool,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub targets: Vec<CleanupTarget>,
    pub items: Vec<CleanupRunItem>,
    pub plan_id: String,
    pub delivered: bool,
    pub error: String,
}

impl CleanupRunRecord {
    fn from_json(val: &JsonVal) -> Result<Self, String> {
        let obj = val
            .as_obj()
            .ok_or_else(|| "invalid cleanup run entry".to_string())?;
        let targets = match obj.get("targets") {
            Some(JsonVal::Arr(arr)) => {
                let mut v = Vec::with_capacity(arr.len());
                for t in arr {
                    v.push(CleanupTarget::from_json(t)?);
                }
                v
            }
            None => Vec::new(),
            _ => return Err("invalid cleanup state; no automatic deletion".to_string()),
        };
        let items = match obj.get("items") {
            Some(JsonVal::Arr(arr)) => {
                let mut v = Vec::with_capacity(arr.len());
                for item in arr {
                    v.push(CleanupRunItem::from_json(item)?);
                }
                v
            }
            None => Vec::new(),
            _ => return Err("invalid cleanup state; no automatic deletion".to_string()),
        };
        Ok(Self {
            run_id: obj.get("run_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            action_id: obj.get("action_id").and_then(JsonVal::as_i64).unwrap_or(0),
            node_id: obj.get("node_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            mode: obj.get("mode").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            automatic: obj.get("automatic").and_then(JsonVal::as_bool).unwrap_or(false),
            started_at: obj.get("started_at").and_then(JsonVal::as_i64).unwrap_or(0),
            finished_at: obj.get("finished_at").and_then(JsonVal::as_i64),
            status: obj.get("status").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            targets,
            items,
            plan_id: obj.get("plan_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            delivered: obj.get("delivered").and_then(JsonVal::as_bool).unwrap_or(false),
            error: obj.get("error").and_then(JsonVal::as_str).unwrap_or("").to_string(),
        })
    }

    pub fn to_json(&self) -> String {
        let targets_json: Vec<String> = self.targets.iter().map(CleanupTarget::to_json).collect();
        let items_json: Vec<String> = self.items.iter().map(CleanupRunItem::to_json).collect();
        let mut b = JsonObjBuilder::new();
        b.str("run_id", &self.run_id);
        b.i64("action_id", self.action_id);
        b.str("node_id", &self.node_id);
        b.str("mode", &self.mode);
        b.bool("automatic", self.automatic);
        b.i64("started_at", self.started_at);
        if let Some(fin) = self.finished_at {
            b.i64("finished_at", fin);
        }
        b.str("status", &self.status);
        b.raw("targets", &format!("[{}]", targets_json.join(",")));
        b.raw("items", &format!("[{}]", items_json.join(",")));
        b.str("plan_id", &self.plan_id);
        if self.delivered {
            b.bool("delivered", true);
        }
        if !self.error.is_empty() {
            b.str("error", &self.error);
        }
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CleanupJournalState {
    pub runs: Vec<CleanupRunRecord>,
    pub attempts: BTreeMap<String, f64>,
}

impl CleanupJournalState {
    pub fn to_json(&self) -> String {
        let runs_json: Vec<String> = self.runs.iter().map(CleanupRunRecord::to_json).collect();
        let mut att = JsonObjBuilder::new();
        for (k, v) in &self.attempts {
            att.f64(k, *v);
        }
        let mut b = JsonObjBuilder::new();
        b.raw("runs", &format!("[{}]", runs_json.join(",")));
        b.raw("attempts", &att.finish());
        b.finish()
    }
}

/// Read cleanup journal state fail-closed WITHOUT mutating `running` runs to `interrupted`.
pub fn read_cleanup_journal_readonly(path: &Path) -> Result<CleanupJournalState, String> {
    if !path.is_absolute() {
        return Err("journal path must be absolute".to_string());
    }
    if super::util::is_symlink_path(path) {
        return Err("journal symlink rejected".to_string());
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CleanupJournalState::default());
        }
        Err(_) => return Err("invalid cleanup journal".to_string()),
    };
    if !meta.is_file() || meta.len() > MAX_JOURNAL_BYTES {
        return Err("invalid cleanup journal".to_string());
    }
    let raw = fs::read_to_string(path).map_err(|_| "invalid cleanup journal".to_string())?;
    let val = JsonVal::parse(&raw).map_err(|_| "invalid cleanup journal schema".to_string())?;
    let Some(obj) = val.as_obj() else {
        return Err("invalid cleanup journal schema".to_string());
    };
    if obj.len() > 1000 {
        return Err("invalid cleanup journal schema".to_string());
    }

    let mut runs = Vec::new();
    if let Some(runs_val) = obj.get("runs") {
        let Some(arr) = runs_val.as_arr() else {
            return Err("invalid cleanup state; no automatic deletion".to_string());
        };
        if arr.len() > 20 {
            return Err("invalid cleanup state; no automatic deletion".to_string());
        }
        for r in arr {
            runs.push(CleanupRunRecord::from_json(r)?);
        }
    }

    let mut attempts = BTreeMap::new();
    if let Some(att_val) = obj.get("attempts") {
        let Some(att_obj) = att_val.as_obj() else {
            return Err("invalid cleanup state; no automatic deletion".to_string());
        };
        for (k, v) in att_obj {
            let ts = v
                .as_f64()
                .filter(|n| n.is_finite() && *n >= 0.0)
                .ok_or_else(|| "invalid cleanup timing state".to_string())?;
            attempts.insert(k.clone(), ts);
        }
    }

    Ok(CleanupJournalState { runs, attempts })
}

/// Load cleanup journal state fail-closed and mark any `running` run as `interrupted`.
pub fn load_cleanup_journal(path: &Path, now_epoch: i64) -> Result<CleanupJournalState, String> {
    let mut state = read_cleanup_journal_readonly(path)?;
    for rec in &mut state.runs {
        if rec.status == "running" {
            rec.status = "interrupted".to_string();
            rec.finished_at = Some(now_epoch);
        }
    }
    Ok(state)
}

/// Save cleanup journal state atomically (`0600` on Unix), bounded to 20 runs and 1000 attempts.
pub fn save_cleanup_journal(
    path: &Path,
    state: &mut CleanupJournalState,
) -> Result<(), String> {
    if state.runs.len() > 20 {
        let drain_count = state.runs.len() - 20;
        state.runs.drain(0..drain_count);
    }
    if state.attempts.len() > 1000 {
        let mut sorted: Vec<(String, f64)> =
            state.attempts.iter().map(|(k, &v)| (k.clone(), v)).collect();
        sorted.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        let keep_from = sorted.len() - 1000;
        let trimmed: BTreeMap<String, f64> = sorted.into_iter().skip(keep_from).collect();
        state.attempts = trimmed;
    }
    let payload = state.to_json();
    atomic_write_private(path, payload.as_bytes(), ".disk-cleanup-")
}

pub fn valid_container_name(name: &str) -> bool {
    (1..=200).contains(&name.len())
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-')
        })
}

/// Runtime environment check matching `client/disk_cleanup.py::available`.
pub fn live_disk_cleanup_available() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
    #[cfg(target_os = "linux")]
    {
        let is_root = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|line| {
                    let rest = line.strip_prefix("Uid:")?;
                    let euid = rest.split_whitespace().nth(1)?;
                    euid.parse::<u32>().ok()
                })
            })
            == Some(0);
        is_root
            && Path::new("/proc/self/fdinfo").is_dir()
            && Path::new("/opt/narwhal-monitor/client.env").is_file()
            && !Path::new("/.dockerenv").exists()
            && !Path::new("/run/.containerenv").exists()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupContainerCandidate {
    pub runtime: String,
    pub runtime_bin: String,
    pub project: String,
    pub name: String,
    pub id: String,
    pub stable_id: String,
    pub instance_id: String,
    pub pid: String,
    pub pid_start_ticks: String,
}

/// Select eligible host + container cleanup targets (excluding Docker & protected containers).
pub fn select_cleanup_targets(
    policy: &CleanupPolicy,
    containers: &[CleanupContainerCandidate],
) -> Vec<CleanupTarget> {
    let mut result = vec![CleanupTarget::host()];
    if policy.include_containers {
        for c in containers.iter().take(500) {
            if !ALLOWED_RUNTIMES.contains(&c.runtime.as_str())
                || PROTECTED_CONTAINERS.contains(&c.name.as_str())
            {
                continue;
            }
            if !valid_container_name(&c.name) {
                continue;
            }
            result.push(CleanupTarget {
                runtime: c.runtime.clone(),
                runtime_bin: c.runtime_bin.clone(),
                project: c.project.clone(),
                name: c.name.clone(),
                id: c.id.clone(),
                stable_id: c.stable_id.clone(),
                instance_id: c.instance_id.clone(),
                pid: c.pid.clone(),
                pid_start_ticks: c.pid_start_ticks.clone(),
            });
        }
    }
    result
}

/// Deterministic cooldown key matching `Controller.key` (Podman ID truncated to 12 chars).
pub fn cleanup_cooldown_key(target: &CleanupTarget) -> String {
    let mut identity = if target.runtime == "runman" {
        target.instance_id.as_str()
    } else if !target.stable_id.is_empty() {
        target.stable_id.as_str()
    } else {
        target.id.as_str()
    };
    if target.runtime == "podman" {
        let cut = identity
            .char_indices()
            .nth(12)
            .map(|(idx, _)| idx)
            .unwrap_or(identity.len());
        identity = &identity[..cut];
    }
    format!(
        "[{},{},{},{}]",
        json_str(&target.runtime),
        json_str(&target.project),
        json_str(&target.name),
        json_str(identity)
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupActionContext {
    pub host_available: bool,
    pub node_id: String,
    pub now_epoch: i64,
    pub journal_path: PathBuf,
    pub policy: CleanupPolicy,
    pub containers: Vec<CleanupContainerCandidate>,
    pub quarantined_identities: BTreeSet<String>,
    pub active_run_in_progress: bool,
}

impl Default for CleanupActionContext {
    fn default() -> Self {
        Self {
            host_available: false,
            node_id: String::new(),
            now_epoch: 0,
            journal_path: PathBuf::from(DEFAULT_STATE_PATH),
            policy: CleanupPolicy::default(),
            containers: Vec::new(),
            quarantined_identities: BTreeSet::new(),
            active_run_in_progress: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupActionOutcome {
    pub ok: bool,
    pub status: &'static str,
    pub message: String,
    pub run: Option<CleanupRunRecord>,
    pub targets: Vec<CleanupTarget>,
}

impl CleanupActionOutcome {
    fn fail(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            status: "failed",
            message: message.into(),
            run: None,
            targets: Vec::new(),
        }
    }

    pub fn to_json(&self) -> String {
        let targets_json: Vec<String> = self.targets.iter().map(CleanupTarget::to_json).collect();
        let mut b = JsonObjBuilder::new();
        b.bool("ok", self.ok);
        b.str("status", self.status);
        b.str("message", &self.message);
        match &self.run {
            Some(r) => b.raw("run", &r.to_json()),
            None => b.raw("run", "null"),
        }
        b.raw("targets", &format!("[{}]", targets_json.join(",")));
        b.finish()
    }
}

fn target_quarantined(target: &CleanupTarget, quarantined: &BTreeSet<String>) -> bool {
    if target.runtime == "host" || quarantined.is_empty() {
        return false;
    }
    [
        target.instance_id.as_str(),
        target.stable_id.as_str(),
        target.id.as_str(),
    ]
    .iter()
    .any(|id| !id.is_empty() && quarantined.contains(*id))
}

/// Validate and stage a `disk_cleanup_scan` or `disk_cleanup_execute` action with all safety checks.
pub fn execute_disk_cleanup_action(
    action_json: &str,
    ctx: &CleanupActionContext,
) -> CleanupActionOutcome {
    if !ctx.host_available {
        return CleanupActionOutcome::fail("native root host Agent required");
    }
    let Ok(val) = JsonVal::parse(action_json.trim()) else {
        return CleanupActionOutcome::fail("invalid cleanup action JSON");
    };
    let Some(obj) = val.as_obj() else {
        return CleanupActionOutcome::fail("invalid cleanup action object");
    };
    let action_type = obj
        .get("action_type")
        .and_then(JsonVal::as_str)
        .unwrap_or("");
    if !matches!(action_type, "disk_cleanup_scan" | "disk_cleanup_execute") {
        return CleanupActionOutcome::fail("unsupported cleanup action type");
    }
    let Some(action_id) = obj.get("id").and_then(JsonVal::as_i64).filter(|&id| id > 0) else {
        return CleanupActionOutcome::fail("invalid cleanup action id");
    };
    let params = obj.get("params").and_then(JsonVal::as_obj);
    let expected_node_id = params
        .and_then(|p| p.get("expected_node_id"))
        .and_then(JsonVal::as_str)
        .unwrap_or("");
    if ctx.node_id.is_empty() || expected_node_id != ctx.node_id {
        return CleanupActionOutcome::fail("cleanup node identity mismatch");
    }

    let now = if ctx.now_epoch == 0 {
        now_unix_secs()
    } else {
        ctx.now_epoch
    };

    let mut state = match read_cleanup_journal_readonly(&ctx.journal_path) {
        Ok(s) => s,
        Err(err) => return CleanupActionOutcome::fail(err),
    };

    if let Some(existing) = state.runs.iter().find(|r| r.action_id == action_id) {
        return CleanupActionOutcome {
            ok: true,
            status: "accepted",
            message: "cleanup action already accepted".to_string(),
            run: Some(existing.clone()),
            targets: existing.targets.clone(),
        };
    }

    if ctx.active_run_in_progress {
        return CleanupActionOutcome::fail("another cleanup task is running");
    }

    let execute = action_type == "disk_cleanup_execute";
    let plan_id = params
        .and_then(|p| p.get("plan_id"))
        .and_then(JsonVal::as_str)
        .unwrap_or("")
        .to_string();

    let targets = if execute {
        let confirmed = params
            .and_then(|p| p.get("confirmed"))
            .and_then(JsonVal::as_bool)
            == Some(true);
        let plan = state.runs.iter().find(|r| r.run_id == plan_id);
        let Some(plan_rec) = plan else {
            return CleanupActionOutcome::fail(
                "a completed fresh scan and confirmation are required",
            );
        };
        let fresh = now >= plan_rec.started_at
            && now.saturating_sub(plan_rec.started_at) <= SCAN_PLAN_MAX_AGE_SECS;
        if !confirmed
            || plan_rec.mode != "scan"
            || !matches!(plan_rec.status.as_str(), "scanned" | "partial")
            || plan_rec.node_id != ctx.node_id
            || !fresh
        {
            return CleanupActionOutcome::fail(
                "a completed fresh scan and confirmation are required",
            );
        }
        let clean_keys: BTreeSet<(String, String, String)> = plan_rec
            .items
            .iter()
            .filter(|item| item.status == "scanned")
            .map(|item| {
                (
                    item.runtime.clone(),
                    item.project.clone(),
                    item.name.clone(),
                )
            })
            .collect();

        let selected: Vec<CleanupTarget> = plan_rec
            .targets
            .iter()
            .filter(|t| {
                clean_keys.contains(&(t.runtime.clone(), t.project.clone(), t.name.clone()))
                    && !target_quarantined(t, &ctx.quarantined_identities)
                    && (t.runtime == "host"
                        || (ALLOWED_RUNTIMES.contains(&t.runtime.as_str())
                            && !PROTECTED_CONTAINERS.contains(&t.name.as_str())
                            && valid_container_name(&t.name)))
            })
            .cloned()
            .collect();
        if selected.is_empty() {
            return CleanupActionOutcome::fail("no safely scanned targets");
        }
        selected
    } else {
        select_cleanup_targets(&ctx.policy, &ctx.containers)
            .into_iter()
            .filter(|t| !target_quarantined(t, &ctx.quarantined_identities))
            .take(MAX_TARGETS_PER_RUN)
            .collect()
    };

    let run = CleanupRunRecord {
        run_id: format!("action-{action_id}"),
        action_id,
        node_id: ctx.node_id.clone(),
        mode: if execute { "clean" } else { "scan" }.to_string(),
        automatic: false,
        started_at: now,
        finished_at: None,
        status: "running".to_string(),
        targets: targets.clone(),
        items: Vec::new(),
        plan_id,
        delivered: false,
        error: String::new(),
    };
    state.runs.push(run.clone());
    if execute {
        for t in &targets {
            state.attempts.insert(cleanup_cooldown_key(t), now as f64);
        }
    }
    if let Err(err) = save_cleanup_journal(&ctx.journal_path, &mut state) {
        return CleanupActionOutcome::fail(err);
    }

    CleanupActionOutcome {
        ok: true,
        status: "running",
        message: "bounded cleanup worker accepted; await final receipt".to_string(),
        run: Some(run),
        targets,
    }
}

pub fn execute_disk_cleanup_action_json(
    action_json: &str,
    ctx: &CleanupActionContext,
) -> String {
    execute_disk_cleanup_action(action_json, ctx).to_json()
}

// -----------------------------------------------------------------------
// Allowlist matching & bounded directory sweep (`disk_cleanup_worker.py`)
// -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CleanupCategory {
    PackageCache,
    ArchivedLogs,
    CrashFiles,
}

impl CleanupCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PackageCache => "package_cache",
            Self::ArchivedLogs => "archived_logs",
            Self::CrashFiles => "crash_files",
        }
    }
}

struct AllowRule {
    category: CleanupCategory,
    rel_dir: &'static str,
    default_days: u16,
    max_depth: usize,
    matcher: fn(&str) -> bool,
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn match_archive_log(name: &str) -> bool {
    let stem = name
        .strip_suffix(".gz")
        .or_else(|| name.strip_suffix(".xz"))
        .or_else(|| name.strip_suffix(".bz2"))
        .or_else(|| name.strip_suffix(".zst"))
        .unwrap_or(name);
    let bases = [
        "syslog",
        "messages",
        "daemon.log",
        "kern.log",
        "debug",
        "dmesg",
        "boot.log",
        "access.log",
        "error.log",
    ];
    for base in bases {
        if let Some(rest) = stem.strip_prefix(base) {
            if let Some(d) = rest.strip_prefix('.') {
                return all_digits(d);
            }
            if let Some(d) = rest.strip_prefix('-') {
                return d.len() == 8 && all_digits(d);
            }
        }
    }
    false
}

fn match_caddy_log(name: &str) -> bool {
    let stem = name
        .strip_suffix(".gz")
        .or_else(|| name.strip_suffix(".xz"))
        .or_else(|| name.strip_suffix(".zst"))
        .unwrap_or(name);
    for base in ["access.log", "error.log"] {
        if let Some(rest) = stem.strip_prefix(base) {
            if let Some(d) = rest.strip_prefix('.') {
                return all_digits(d);
            }
            if let Some(d) = rest.strip_prefix('-') {
                return d.len() == 8 && all_digits(d);
            }
        }
    }
    for prefix in ["access-", "error-", "caddy-"] {
        if let Some(rest) = stem.strip_prefix(prefix) {
            if let Some(body) = rest.strip_suffix(".log") {
                let b = body.as_bytes();
                if b.len() >= 12
                    && b[0..4].iter().all(u8::is_ascii_digit)
                    && b[4] == b'-'
                    && b[5..7].iter().all(u8::is_ascii_digit)
                    && b[7] == b'-'
                    && b[8..10].iter().all(u8::is_ascii_digit)
                    && b[10] == b'T'
                    && b[11..].iter().all(|&c| c.is_ascii_digit() || c == b'.' || c == b'-')
                {
                    return true;
                }
            }
        }
    }
    false
}

fn match_journal_archive(name: &str) -> bool {
    let stem = name.strip_suffix('~').unwrap_or(name);
    let Some(body) = stem.strip_suffix(".journal") else {
        return false;
    };
    let Some((left, hex_part)) = body.split_once('@') else {
        return false;
    };
    let left_ok = left == "system"
        || left
            .strip_prefix("user-")
            .map(all_digits)
            .unwrap_or(false);
    let hex_ok = !hex_part.is_empty()
        && hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'));
    left_ok && hex_ok
}

fn match_deb(name: &str) -> bool {
    name.len() > 4 && name.ends_with(".deb")
}

fn match_apk(name: &str) -> bool {
    name.len() > 4 && name.ends_with(".apk")
}

fn match_pacman(name: &str) -> bool {
    let core = name.strip_suffix(".sig").unwrap_or(name);
    core.strip_suffix(".pkg.tar.xz")
        .or_else(|| core.strip_suffix(".pkg.tar.zst"))
        .map(|prefix| !prefix.is_empty())
        .unwrap_or(false)
}

fn match_rpm(name: &str) -> bool {
    name.len() > 4 && name.ends_with(".rpm")
}

fn match_crash(name: &str) -> bool {
    name.strip_suffix(".crash")
        .or_else(|| name.strip_suffix(".upload"))
        .or_else(|| name.strip_suffix(".uploaded"))
        .map(|p| !p.is_empty())
        .unwrap_or(false)
}

fn match_coredump(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("core.") else {
        return false;
    };
    rest.strip_suffix(".zst")
        .or_else(|| rest.strip_suffix(".lz4"))
        .or_else(|| rest.strip_suffix(".xz"))
        .map(|p| !p.is_empty())
        .unwrap_or(false)
}

const ALLOW_RULES: &[AllowRule] = &[
    AllowRule {
        category: CleanupCategory::PackageCache,
        rel_dir: "var/cache/apt/archives",
        default_days: 1,
        max_depth: 0,
        matcher: match_deb,
    },
    AllowRule {
        category: CleanupCategory::PackageCache,
        rel_dir: "var/cache/apk",
        default_days: 1,
        max_depth: 0,
        matcher: match_apk,
    },
    AllowRule {
        category: CleanupCategory::PackageCache,
        rel_dir: "var/cache/pacman/pkg",
        default_days: 1,
        max_depth: 0,
        matcher: match_pacman,
    },
    AllowRule {
        category: CleanupCategory::PackageCache,
        rel_dir: "var/cache/dnf",
        default_days: 1,
        max_depth: 3,
        matcher: match_rpm,
    },
    AllowRule {
        category: CleanupCategory::PackageCache,
        rel_dir: "var/cache/yum",
        default_days: 1,
        max_depth: 3,
        matcher: match_rpm,
    },
    AllowRule {
        category: CleanupCategory::ArchivedLogs,
        rel_dir: "var/log",
        default_days: 14,
        max_depth: 0,
        matcher: match_archive_log,
    },
    AllowRule {
        category: CleanupCategory::ArchivedLogs,
        rel_dir: "var/log/nginx",
        default_days: 14,
        max_depth: 0,
        matcher: match_archive_log,
    },
    AllowRule {
        category: CleanupCategory::ArchivedLogs,
        rel_dir: "var/log/apache2",
        default_days: 14,
        max_depth: 0,
        matcher: match_archive_log,
    },
    AllowRule {
        category: CleanupCategory::ArchivedLogs,
        rel_dir: "var/log/caddy",
        default_days: 14,
        max_depth: 0,
        matcher: match_caddy_log,
    },
    AllowRule {
        category: CleanupCategory::ArchivedLogs,
        rel_dir: "var/log/journal",
        default_days: 14,
        max_depth: 1,
        matcher: match_journal_archive,
    },
    AllowRule {
        category: CleanupCategory::CrashFiles,
        rel_dir: "var/crash",
        default_days: 14,
        max_depth: 0,
        matcher: match_crash,
    },
    AllowRule {
        category: CleanupCategory::CrashFiles,
        rel_dir: "var/lib/systemd/coredump",
        default_days: 14,
        max_depth: 0,
        matcher: match_coredump,
    },
];

/// Check whether a relative path under a root is matched by the static allowlist rules.
pub fn is_allowlisted_cleanup_file(rel_path: &str) -> Option<(CleanupCategory, u16)> {
    let normalized = rel_path.trim_start_matches('/').replace('\\', "/");
    if normalized.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return None;
    }
    let (dir_part, filename) = normalized.rsplit_once('/')?;
    for rule in ALLOW_RULES {
        if dir_part == rule.rel_dir && rule.max_depth == 0 && (rule.matcher)(filename) {
            return Some((rule.category, rule.default_days));
        }
        if rule.max_depth > 0 {
            if let Some(sub) = dir_part.strip_prefix(&format!("{}/", rule.rel_dir)) {
                let sub_segs: Vec<&str> = sub.split('/').collect();
                if sub_segs.len() <= rule.max_depth {
                    if rule.category == CleanupCategory::ArchivedLogs
                        && !(sub_segs.len() == 1
                            && sub_segs[0].len() == 32
                            && sub_segs[0]
                                .bytes()
                                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                    {
                        continue;
                    }
                    if (rule.matcher)(filename) {
                        return Some((rule.category, rule.default_days));
                    }
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupSweepResult {
    pub candidate_files: usize,
    pub candidate_bytes: u64,
    pub deleted_files: usize,
    pub unlinked_bytes: u64,
    pub skipped: usize,
    pub errors: usize,
    pub bounded: bool,
    pub status: String,
}

fn meta_latest_epoch(meta: &fs::Metadata) -> Option<i64> {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)?;
    #[cfg(unix)]
    let ctime = {
        use std::os::unix::fs::MetadataExt;
        meta.ctime()
    };
    #[cfg(not(unix))]
    let ctime = mtime;
    let atime = meta
        .accessed()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(mtime);
    Some(mtime.max(ctime).max(atime))
}

fn meta_allocated_bytes(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.blocks().saturating_mul(512)
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

fn meta_nlink(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        1
    }
}

fn open_nofollow_dir_chain(root: &Path, rel_dir: &str) -> Option<PathBuf> {
    let mut current = root.to_path_buf();
    let root_meta = fs::symlink_metadata(&current).ok()?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return None;
    }
    for comp in rel_dir.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return None;
        }
        current.push(comp);
        let meta = fs::symlink_metadata(&current).ok()?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return None;
        }
    }
    Some(current)
}

fn walk_allowlist_dir(
    dir: &Path,
    rule: &AllowRule,
    depth: usize,
    cutoff: i64,
    execute: bool,
    byte_budget: u64,
    file_budget: usize,
    busy_inodes: &BTreeSet<(u64, u64)>,
    visited: &mut usize,
    out: &mut CleanupSweepResult,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        out.errors += 1;
        return;
    };
    for entry in entries.flatten() {
        *visited += 1;
        if *visited > MAX_VISITED_ENTRIES {
            out.bounded = true;
            return;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            out.errors += 1;
            continue;
        };
        if meta.file_type().is_symlink() {
            out.skipped += 1;
            continue;
        }
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if depth > 0 && meta.is_dir() {
            if rule.category == CleanupCategory::ArchivedLogs
                && !(name_str.len() == 32
                    && name_str
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            {
                continue;
            }
            walk_allowlist_dir(
                &path,
                rule,
                depth - 1,
                cutoff,
                execute,
                byte_budget,
                file_budget,
                busy_inodes,
                visited,
                out,
            );
            if out.bounded {
                return;
            }
            continue;
        }
        if !meta.is_file() || !(rule.matcher)(&name_str) {
            continue;
        }
        if meta_nlink(&meta) != 1 {
            out.skipped += 1;
            continue;
        }
        let Some(latest) = meta_latest_epoch(&meta) else {
            out.skipped += 1;
            continue;
        };
        if latest > cutoff {
            out.skipped += 1;
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if busy_inodes.contains(&(meta.dev(), meta.ino())) {
                out.skipped += 1;
                continue;
            }
        }
        #[cfg(not(unix))]
        let _ = busy_inodes;

        let allocated = meta_allocated_bytes(&meta);
        out.candidate_files += 1;
        out.candidate_bytes = out.candidate_bytes.saturating_add(allocated);
        if execute {
            if out.deleted_files >= file_budget
                || out.unlinked_bytes.saturating_add(allocated) > byte_budget
            {
                out.bounded = true;
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                out.deleted_files += 1;
                out.unlinked_bytes = out.unlinked_bytes.saturating_add(allocated);
            } else {
                out.errors += 1;
            }
        }
    }
}

/// Bounded allowlist scan/cleanup under a verified root directory (never follows symlinks).
pub fn sweep_cleanup_root(
    root: &Path,
    execute: bool,
    retention_days: u16,
    byte_budget: u64,
    file_budget: usize,
    now_epoch: i64,
    busy_inodes: &BTreeSet<(u64, u64)>,
) -> Result<CleanupSweepResult, String> {
    if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&retention_days) {
        return Err("invalid retention".to_string());
    }
    if byte_budget > MAX_BYTES || file_budget > MAX_FILES {
        return Err("invalid cleanup budget".to_string());
    }
    let mut out = CleanupSweepResult {
        status: if execute { "succeeded" } else { "scanned" }.to_string(),
        ..CleanupSweepResult::default()
    };
    let mut visited = 0usize;
    for rule in ALLOW_RULES {
        let rel_path = Path::new(rule.rel_dir);
        if !root.join(rel_path).exists() {
            continue;
        }
        let Some(dir_path) = open_nofollow_dir_chain(root, rule.rel_dir) else {
            out.skipped += 1;
            continue;
        };
        let days = if rule.default_days == 14 {
            retention_days
        } else {
            rule.default_days
        };
        let cutoff = now_epoch.saturating_sub((days as i64) * DAY_SECONDS);
        walk_allowlist_dir(
            &dir_path,
            rule,
            rule.max_depth,
            cutoff,
            execute,
            byte_budget,
            file_budget,
            busy_inodes,
            &mut visited,
            &mut out,
        );
        if out.bounded {
            break;
        }
    }
    if out.errors > 0 || out.bounded {
        out.status = "partial".to_string();
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskUsageStats {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f64,
}

impl DiskUsageStats {
    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.u64("total_bytes", self.total_bytes);
        b.u64("available_bytes", self.available_bytes);
        b.f64("used_percent", (self.used_percent * 100.0).round() / 100.0);
        b.finish()
    }
}

/// Best-effort POSIX `df -P -k <path>` disk usage without unsafe FFI.
pub fn disk_usage_for_path(path: &Path) -> Option<DiskUsageStats> {
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("df")
            .args(["-P", "-k"])
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let data_line = stdout.lines().nth(1)?.trim();
        let cols: Vec<&str> = data_line.split_whitespace().collect();
        if cols.len() < 4 {
            return None;
        }
        let blocks_1k: u64 = cols[1].parse().ok()?;
        let used_1k: u64 = cols[2].parse().ok()?;
        let avail_1k: u64 = cols[3].parse().ok()?;
        let total_bytes = blocks_1k.saturating_mul(1024);
        let used_bytes = used_1k.saturating_mul(1024);
        let available_bytes = avail_1k.saturating_mul(1024);
        let denom = used_bytes.saturating_add(available_bytes);
        let used_percent = if denom > 0 {
            (100.0 * (used_bytes as f64) / (denom as f64) * 100.0).round() / 100.0
        } else {
            0.0
        };
        Some(DiskUsageStats {
            total_bytes,
            available_bytes,
            used_percent,
        })
    }
}

pub fn host_disk_usage_json(path: &Path) -> String {
    disk_usage_for_path(path)
        .map(|d| d.to_json())
        .unwrap_or_else(|| "{}".to_string())
}

/// Fail-closed enumeration of open regular file `(dev, ino)` across `/proc/*/fd`.
pub fn collect_busy_inodes(max_fds: usize) -> Result<BTreeSet<(u64, u64)>, String> {
    #[cfg(not(unix))]
    {
        let _ = max_fds;
        Ok(BTreeSet::new())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(proc_entries) = fs::read_dir("/proc") else {
            return Err("open-file check unavailable".to_string());
        };
        let mut busy = BTreeSet::new();
        let mut seen = 0usize;
        for entry in proc_entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let fd_dir = entry.path().join("fd");
            let fds = match fs::read_dir(&fd_dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err("open-file permissions unavailable".to_string());
                }
                Err(_) => continue,
            };
            for fd_entry in fds.flatten() {
                seen += 1;
                if seen > max_fds {
                    return Err("open-file check budget exhausted".to_string());
                }
                if let Ok(meta) = fs::metadata(fd_entry.path()) {
                    if meta.is_file() {
                        busy.insert((meta.dev(), meta.ino()));
                    }
                }
            }
        }
        Ok(busy)
    }
}

fn verify_target_root_for_cleanup(
    target: &CleanupTarget,
    host_root_override: Option<&Path>,
) -> Result<(PathBuf, String), String> {
    if target.runtime == "host" {
        let root = host_root_override
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let meta = fs::symlink_metadata(&root)
            .map_err(|_| "host root unavailable".to_string())?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err("invalid host filesystem root".to_string());
        }
        return Ok((root, "host".to_string()));
    }

    #[cfg(not(target_os = "linux"))]
    {
        Err("identity, mount, evidence or filesystem safety check unavailable".to_string())
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let pid: u32 = target
            .pid
            .trim()
            .parse()
            .ok()
            .filter(|&p| p > 1)
            .ok_or_else(|| "container is not running".to_string())?;
        let pid1_ns = fs::metadata("/proc/1/ns/pid")
            .map_err(|_| "host PID namespace unavailable".to_string())?;
        let c_ns = fs::metadata(format!("/proc/{pid}/ns/pid"))
            .map_err(|_| "container PID namespace unavailable".to_string())?;
        if (c_ns.dev(), c_ns.ino()) == (pid1_ns.dev(), pid1_ns.ino()) {
            return Err("shared host PID namespace".to_string());
        }
        if !target.pid_start_ticks.is_empty() {
            let raw_stat = fs::read_to_string(format!("/proc/{pid}/stat"))
                .map_err(|_| "container process unavailable".to_string())?;
            let ticks = raw_stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(19))
                .unwrap_or("");
            if ticks != target.pid_start_ticks {
                return Err("container restarted".to_string());
            }
        }
        let host_root_meta = fs::metadata("/")
            .map_err(|_| "host filesystem root unavailable".to_string())?;
        let guest_root = PathBuf::from(format!("/proc/{pid}/root"));
        let guest_meta = fs::metadata(&guest_root)
            .map_err(|_| "container root unavailable".to_string())?;
        if !guest_meta.is_dir()
            || (guest_meta.dev(), guest_meta.ino())
                == (host_root_meta.dev(), host_root_meta.ino())
        {
            return Err("host filesystem root refused".to_string());
        }
        let identity = if target.runtime == "runman" {
            target.instance_id.clone()
        } else if !target.stable_id.is_empty() {
            target.stable_id.clone()
        } else {
            target.id.clone()
        };
        if identity.is_empty() {
            return Err("container identity unavailable".to_string());
        }
        Ok((guest_root, identity))
    }
}

/// Execute bounded scan/clean across staged targets of `run_id` and persist terminal status to `journal_path`.
pub fn execute_and_finalize_cleanup_run(
    journal_path: &Path,
    run_id: &str,
    policy: &CleanupPolicy,
    host_root_override: Option<&Path>,
    now_epoch: i64,
) -> Result<CleanupRunRecord, String> {
    let state = read_cleanup_journal_readonly(journal_path)?;
    let Some(initial_run) = state.runs.iter().find(|r| r.run_id == run_id).cloned() else {
        return Err("cleanup run record not found".to_string());
    };
    if initial_run.status != "running" {
        return Ok(initial_run);
    }

    let execute = initial_run.mode == "clean";
    let busy_inodes = if host_root_override.is_some() {
        BTreeSet::new()
    } else {
        match collect_busy_inodes(50_000) {
            Ok(set) => set,
            Err(_) => {
                let mut st = read_cleanup_journal_readonly(journal_path)?;
                if let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) {
                    rec.status = "failed".to_string();
                    rec.finished_at = Some(now_epoch);
                    rec.error = "cleanup worker could not verify open files".to_string();
                    let snapshot = rec.clone();
                    let _ = save_cleanup_journal(journal_path, &mut st);
                    return Ok(snapshot);
                }
                return Err("cleanup run missing during failure update".to_string());
            }
        }
    };

    let mut remaining_bytes = MAX_BYTES;
    let mut remaining_files = MAX_FILES;
    let mut items = Vec::with_capacity(initial_run.targets.len());

    for target in &initial_run.targets {
        let mut item = CleanupRunItem {
            runtime: target.runtime.clone(),
            name: target.name.clone(),
            project: target.project.clone(),
            status: "skipped".to_string(),
            reason: String::new(),
            instance_id: String::new(),
            candidate_files: 0,
            candidate_bytes: 0,
            deleted_files: 0,
            unlinked_bytes: 0,
            freed_bytes: 0,
            skipped: 0,
            errors: 0,
            bounded: false,
            extra_fields: BTreeMap::new(),
        };
        match verify_target_root_for_cleanup(target, host_root_override) {
            Ok((root, identity)) => {
                let before_avail = disk_usage_for_path(&root);
                match sweep_cleanup_root(
                    &root,
                    execute,
                    policy.retention_days,
                    remaining_bytes,
                    remaining_files,
                    now_epoch,
                    &busy_inodes,
                ) {
                    Ok(sweep) => {
                        let after_avail = if execute {
                            disk_usage_for_path(&root)
                        } else {
                            before_avail
                        };
                        let freed = match (before_avail, after_avail) {
                            (Some(b), Some(a)) if execute => {
                                a.available_bytes.saturating_sub(b.available_bytes)
                            }
                            _ => 0,
                        };
                        item.status = sweep.status;
                        item.instance_id = identity;
                        item.candidate_files = sweep.candidate_files;
                        item.candidate_bytes = sweep.candidate_bytes;
                        item.deleted_files = sweep.deleted_files;
                        item.unlinked_bytes = sweep.unlinked_bytes;
                        item.freed_bytes = freed;
                        item.skipped = sweep.skipped;
                        item.errors = sweep.errors;
                        item.bounded = sweep.bounded;
                        remaining_bytes = remaining_bytes.saturating_sub(sweep.unlinked_bytes);
                        remaining_files = remaining_files.saturating_sub(sweep.deleted_files);
                    }
                    Err(_) => {
                        item.reason = "identity, mount, evidence or filesystem safety check unavailable"
                            .to_string();
                    }
                }
            }
            Err(_) => {
                item.reason =
                    "identity, mount, evidence or filesystem safety check unavailable"
                        .to_string();
            }
        }
        items.push(item);
    }

    let has_partial = items
        .iter()
        .any(|i| matches!(i.status.as_str(), "skipped" | "partial"));
    let final_status = if has_partial {
        "partial"
    } else if execute {
        "succeeded"
    } else {
        "scanned"
    };

    let mut st = read_cleanup_journal_readonly(journal_path)?;
    let fin_epoch = now_unix_secs().max(now_epoch);
    let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) else {
        return Err("cleanup run record missing during finalization".to_string());
    };
    rec.items = items;
    rec.status = final_status.to_string();
    rec.finished_at = Some(fin_epoch);
    let finalized = rec.clone();
    save_cleanup_journal(journal_path, &mut st)?;
    Ok(finalized)
}

pub fn mark_cleanup_run_delivered(journal_path: &Path, run_id: &str) -> Result<(), String> {
    let mut st = read_cleanup_journal_readonly(journal_path)?;
    if let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) {
        rec.delivered = true;
        save_cleanup_journal(journal_path, &mut st)?;
    }
    Ok(())
}

/// Stage an automatic scheduled cleanup run for due targets (`now - last_attempt >= interval_hours * 3600`).
/// Returns `Ok(Some(run_id))` when a new automatic run was staged, or `Ok(None)` when none are due.
pub fn stage_automatic_cleanup(
    journal_path: &Path,
    policy: &CleanupPolicy,
    node_id: &str,
    containers: &[CleanupContainerCandidate],
    quarantined_identities: &BTreeSet<String>,
    now_epoch: i64,
) -> Result<Option<String>, String> {
    if !policy.enabled || node_id.is_empty() {
        return Ok(None);
    }
    let mut st = read_cleanup_journal_readonly(journal_path)?;
    if st.runs.iter().any(|r| r.status == "running") {
        return Ok(None);
    }
    let interval_secs = (policy.interval_hours as f64) * 3600.0;
    let now_f = now_epoch as f64;
    let due: Vec<CleanupTarget> = select_cleanup_targets(policy, containers)
        .into_iter()
        .filter(|t| !target_quarantined(t, quarantined_identities))
        .filter(|t| {
            let last = st.attempts.get(&cleanup_cooldown_key(t)).copied().unwrap_or(0.0);
            now_f - last >= interval_secs
        })
        .take(MAX_TARGETS_PER_RUN)
        .collect();
    if due.is_empty() {
        return Ok(None);
    }
    let run_id = format!("{:032x}", (now_epoch as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let rec = CleanupRunRecord {
        run_id: run_id.clone(),
        action_id: 0,
        node_id: node_id.to_string(),
        mode: "clean".to_string(),
        automatic: true,
        started_at: now_epoch,
        finished_at: None,
        status: "running".to_string(),
        targets: due.clone(),
        items: Vec::new(),
        plan_id: String::new(),
        delivered: false,
        error: String::new(),
    };
    for t in &due {
        st.attempts.insert(cleanup_cooldown_key(t), now_f);
    }
    st.runs.push(rec);
    save_cleanup_journal(journal_path, &mut st)?;
    Ok(Some(run_id))
}
