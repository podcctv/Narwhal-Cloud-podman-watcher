#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use cgroup_probe::PsiStatus;
use guard_core::{
    GuardStage, IoContainerDecision, IoGuardAction, IoMaxLimits, MemoryContainerDecision,
    MemoryGuardAction, PsiSample,
};
use runtime_drivers::{ContainerSample, JsonVal};

use crate::cpu_guard_exec::{resolve_safe_container_cgroup, ContainerMetricsSummary};
use crate::{container_guard_key, json_escape};

const DEFAULT_MEMORY_GUARD_STATE_PATH: &str = "/var/lib/narwhal-agent/memory-guard-limits.json";
const DEFAULT_IO_GUARD_STATE_PATH: &str = "/var/lib/narwhal-agent/io-guard-limits.json";
const MIN_MEMORY_HIGH_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn memory_auto_limit_enabled_from_env() -> bool {
    std::env::var("SECURITY_MEMORY_AUTO_LIMIT_ENABLED")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

pub(crate) fn io_auto_limit_enabled_from_env() -> bool {
    std::env::var("SECURITY_IO_AUTO_LIMIT_ENABLED")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

pub(crate) fn default_memory_guard_state_path() -> PathBuf {
    std::env::var("NARWHAL_MEMORY_GUARD_RUST_STATE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MEMORY_GUARD_STATE_PATH))
}

pub(crate) fn default_io_guard_state_path() -> PathBuf {
    std::env::var("NARWHAL_IO_GUARD_RUST_STATE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_IO_GUARD_STATE_PATH))
}

fn container_identity_strings(c: &ContainerSample) -> (&str, String) {
    let identity = if !c.stable_id.is_empty() {
        c.stable_id.as_str()
    } else {
        c.id.as_str()
    };
    let inst_id = if !c.instance_id.is_empty() {
        c.instance_id.clone()
    } else if !c.stable_id.is_empty() {
        c.stable_id.clone()
    } else {
        c.id.clone()
    };
    (identity, inst_id)
}

pub(crate) fn read_container_memory_psi(
    proc_root: &Path,
    cgroup_root: &Path,
    c: &ContainerSample,
) -> PsiSample {
    let (identity, _) = container_identity_strings(c);
    let Ok(boundary) = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    ) else {
        return PsiSample::default();
    };
    match cgroup_probe::read_psi(&boundary.join("memory.pressure")) {
        PsiStatus::Ready { some, .. } => PsiSample {
            avg10: some.as_ref().map(|s| s.avg10),
            avg60: some.as_ref().and_then(|s| s.avg60),
        },
        _ => PsiSample::default(),
    }
}

pub(crate) fn read_container_memory_high(
    proc_root: &Path,
    cgroup_root: &Path,
    c: &ContainerSample,
) -> Option<u64> {
    let (identity, _) = container_identity_strings(c);
    let boundary = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    )
    .ok()?;
    let raw = fs::read_to_string(boundary.join("memory.high")).ok()?;
    let trimmed = raw.trim();
    if trimmed == "max" {
        None
    } else {
        trimmed.parse::<u64>().ok()
    }
}

fn parse_io_max_fields(tokens: &[&str]) -> Option<IoMaxLimits> {
    let mut lim = IoMaxLimits::default();
    for tok in tokens {
        let Some((k, v)) = tok.split_once('=') else {
            continue;
        };
        let parsed = if v == "max" {
            None
        } else {
            Some(v.parse::<u64>().ok()?)
        };
        match k {
            "rbps" => lim.rbps = parsed,
            "wbps" => lim.wbps = parsed,
            "riops" => lim.riops = parsed,
            "wiops" => lim.wiops = parsed,
            _ => {}
        }
    }
    Some(lim)
}

pub(crate) fn read_container_io_max_map(
    proc_root: &Path,
    cgroup_root: &Path,
    c: &ContainerSample,
) -> HashMap<String, IoMaxLimits> {
    let mut out = HashMap::new();
    let (identity, _) = container_identity_strings(c);
    let Ok(boundary) = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    ) else {
        return out;
    };
    let Ok(raw) = fs::read_to_string(boundary.join("io.max")) else {
        return out;
    };
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() || !is_valid_device(parts[0]) {
            continue;
        }
        if let Some(lim) = parse_io_max_fields(&parts[1..]) {
            out.insert(parts[0].to_string(), lim);
        }
    }
    out
}

fn write_atomic_json(path: &Path, tmp_prefix: &str, json: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("创建状态目录失败: {e}"))?;
        }
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".{tmp_prefix}-{}.tmp", std::process::id()));
    fs::write(&tmp, json.as_bytes()).map_err(|e| format!("写入状态失败: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| format!("替换状态失败: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. MemoryGuardEnforcer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnforcedMemoryRecord {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub instance_id: String,
    pub original_limit: String,
    pub applied_limit: String,
    pub tier: u8,
    pub readback_confirmed: bool,
    pub manual_override: bool,
    pub restore_failed: bool,
    pub last_error: String,
    pub applied_at: u64,
}

fn parse_valid_memory_high(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t == "max" || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())) {
        Some(t.to_string())
    } else {
        None
    }
}

fn read_memory_high(
    c: &ContainerSample,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<(PathBuf, String), String> {
    let (identity, _) = container_identity_strings(c);
    let boundary = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    )?;
    let raw = fs::read_to_string(boundary.join("memory.high"))
        .map_err(|e| format!("无法读取 memory.high（{}）", e.kind()))?;
    let val = parse_valid_memory_high(&raw)
        .ok_or_else(|| "memory.high 格式无法确认".to_string())?;
    Ok((boundary, val))
}

fn write_memory_high(boundary: &Path, value: &str) -> Result<(), String> {
    if parse_valid_memory_high(value).is_none() {
        return Err("memory.high 限值格式无效".to_string());
    }
    fs::write(boundary.join("memory.high"), value.as_bytes())
        .map_err(|e| format!("写入 memory.high 失败（{}）", e.kind()))
}

pub(crate) struct MemoryGuardEnforcer {
    state_path: PathBuf,
    pub(crate) records: HashMap<String, EnforcedMemoryRecord>,
}

impl MemoryGuardEnforcer {
    pub(crate) fn new(state_path: PathBuf) -> Self {
        let mut enforcer = Self {
            state_path,
            records: HashMap::new(),
        };
        enforcer.load_state();
        enforcer
    }

    fn load_state(&mut self) {
        let Ok(raw) = fs::read_to_string(&self.state_path) else {
            return;
        };
        let Ok(val) = JsonVal::parse(raw.trim()) else {
            return;
        };
        let Some(instances) = val.get("instances").and_then(JsonVal::as_obj) else {
            return;
        };
        for (k, v) in instances {
            self.records.insert(
                k.clone(),
                EnforcedMemoryRecord {
                    runtime: v.get_str("runtime").unwrap_or("").to_string(),
                    project: v.get_str("project").unwrap_or("").to_string(),
                    name: v.get_str("name").unwrap_or("").to_string(),
                    instance_id: v.get_str("instance_id").unwrap_or("").to_string(),
                    original_limit: v.get_str("original_limit").unwrap_or("max").to_string(),
                    applied_limit: v.get_str("applied_limit").unwrap_or("").to_string(),
                    tier: v.get_u64("tier").unwrap_or(1).clamp(1, 3) as u8,
                    readback_confirmed: v.get_bool("readback_confirmed").unwrap_or(false),
                    manual_override: v.get_bool("manual_override").unwrap_or(false),
                    restore_failed: v.get_bool("restore_failed").unwrap_or(false),
                    last_error: v.get_str("last_error").unwrap_or("").to_string(),
                    applied_at: v.get_u64("applied_at").unwrap_or(0),
                },
            );
        }
    }

    fn save_state(&self) -> Result<(), String> {
        let mut json = String::from("{\"schema\":1,\"instances\":{");
        for (idx, (k, r)) in self.records.iter().enumerate() {
            if idx > 0 {
                json.push(',');
            }
            let _ = write!(
                json,
                "\"{}\":{{\"runtime\":\"{}\",\"project\":\"{}\",\"name\":\"{}\",\"instance_id\":\"{}\",\"original_limit\":\"{}\",\"applied_limit\":\"{}\",\"tier\":{},\"readback_confirmed\":{},\"manual_override\":{},\"restore_failed\":{},\"last_error\":\"{}\",\"applied_at\":{}}}",
                json_escape(k),
                json_escape(&r.runtime),
                json_escape(&r.project),
                json_escape(&r.name),
                json_escape(&r.instance_id),
                json_escape(&r.original_limit),
                json_escape(&r.applied_limit),
                r.tier,
                r.readback_confirmed,
                r.manual_override,
                r.restore_failed,
                json_escape(&r.last_error),
                r.applied_at,
            );
        }
        json.push_str("}}");
        write_atomic_json(&self.state_path, "memory-guard-limits", &json)
    }

    pub(crate) fn execute_actions(
        &mut self,
        containers: &[ContainerSample],
        actions: &[MemoryGuardAction],
        proc_root: &Path,
        cgroup_root: &Path,
        timestamp: u64,
    ) {
        if actions.is_empty() {
            return;
        }
        let by_key: HashMap<String, &ContainerSample> = containers
            .iter()
            .map(|c| (container_guard_key(c), c))
            .collect();

        for action in actions {
            match action {
                MemoryGuardAction::ApplyMemoryHigh {
                    key,
                    tier,
                    target_bytes,
                } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let (_, inst_id) = container_identity_strings(c);
                    let rt = c.runtime.trim().to_ascii_lowercase();
                    let (boundary, original) = match read_memory_high(c, proc_root, cgroup_root) {
                        Ok(res) => res,
                        Err(err) => {
                            self.records.insert(
                                key.clone(),
                                EnforcedMemoryRecord {
                                    runtime: rt,
                                    project: c.project.clone(),
                                    name: c.name.clone(),
                                    instance_id: inst_id,
                                    original_limit: String::new(),
                                    applied_limit: String::new(),
                                    tier: *tier,
                                    readback_confirmed: false,
                                    manual_override: false,
                                    restore_failed: false,
                                    last_error: err,
                                    applied_at: timestamp,
                                },
                            );
                            let _ = self.save_state();
                            continue;
                        }
                    };
                    let target_str = (*target_bytes).max(MIN_MEMORY_HIGH_BYTES).to_string();
                    self.records.insert(
                        key.clone(),
                        EnforcedMemoryRecord {
                            runtime: rt,
                            project: c.project.clone(),
                            name: c.name.clone(),
                            instance_id: inst_id,
                            original_limit: original,
                            applied_limit: target_str.clone(),
                            tier: *tier,
                            readback_confirmed: false,
                            manual_override: false,
                            restore_failed: false,
                            last_error: String::new(),
                            applied_at: timestamp,
                        },
                    );
                    if let Err(err) = self.save_state() {
                        if let Some(r) = self.records.get_mut(key) {
                            r.last_error = err;
                        }
                        continue;
                    }
                    let write_res = write_memory_high(&boundary, &target_str);
                    let readback_res = read_memory_high(c, proc_root, cgroup_root);
                    if let Some(r) = self.records.get_mut(key) {
                        match (write_res, readback_res) {
                            (Ok(()), Ok((_, after))) if after == target_str => {
                                r.readback_confirmed = true;
                                r.last_error.clear();
                            }
                            (Err(e), _) => {
                                r.readback_confirmed = false;
                                r.last_error = e;
                            }
                            (Ok(()), Err(e)) => {
                                r.readback_confirmed = false;
                                r.last_error = format!("应用后读回 memory.high 失败: {e}");
                            }
                            (Ok(()), Ok((_, after))) => {
                                r.readback_confirmed = false;
                                r.last_error = format!(
                                    "memory.high 读回不一致: 期望 {target_str}, 实际 {after}"
                                );
                            }
                        }
                    }
                    let _ = self.save_state();
                }
                MemoryGuardAction::EscalateMemoryHigh {
                    key,
                    tier,
                    target_bytes,
                } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let Some(existing) = self.records.get(key).cloned() else {
                        continue;
                    };
                    if existing.manual_override {
                        continue;
                    }
                    match read_memory_high(c, proc_root, cgroup_root) {
                        Ok((boundary, before)) => {
                            if !existing.applied_limit.is_empty()
                                && before != existing.applied_limit
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "memory.high 在阶梯保护前发生人工更改；未覆盖。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let next_str = (*target_bytes).max(MIN_MEMORY_HIGH_BYTES).to_string();
                            let write_res = write_memory_high(&boundary, &next_str);
                            let readback_res = read_memory_high(c, proc_root, cgroup_root);
                            if let Some(r) = self.records.get_mut(key) {
                                match (write_res, readback_res) {
                                    (Ok(()), Ok((_, after))) if after == next_str => {
                                        r.applied_limit = next_str;
                                        r.tier = *tier;
                                        r.readback_confirmed = true;
                                        r.last_error.clear();
                                    }
                                    (Err(e), _) => r.last_error = e,
                                    (Ok(()), Err(e)) => {
                                        r.last_error = format!("阶梯 memory.high 读回失败: {e}");
                                    }
                                    (Ok(()), Ok(_)) => {
                                        r.last_error = "阶梯 memory.high 读回值未匹配".to_string();
                                    }
                                }
                            }
                            let _ = self.save_state();
                        }
                        Err(e) => {
                            if let Some(r) = self.records.get_mut(key) {
                                r.last_error = e;
                            }
                            let _ = self.save_state();
                        }
                    }
                }
                MemoryGuardAction::RestoreMemoryHigh { key, .. } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let Some(existing) = self.records.get(key).cloned() else {
                        continue;
                    };
                    if existing.manual_override {
                        self.records.remove(key);
                        let _ = self.save_state();
                        continue;
                    }
                    match read_memory_high(c, proc_root, cgroup_root) {
                        Ok((boundary, before)) => {
                            if before == existing.original_limit {
                                self.records.remove(key);
                                let _ = self.save_state();
                                continue;
                            }
                            if !existing.applied_limit.is_empty()
                                && before != existing.applied_limit
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "检测到人工更改 memory.high，系统保留该配置。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let write_res = write_memory_high(&boundary, &existing.original_limit);
                            let readback_res = read_memory_high(c, proc_root, cgroup_root);
                            match (write_res, readback_res) {
                                (Ok(()), Ok((_, after))) if after == existing.original_limit => {
                                    self.records.remove(key);
                                }
                                (Err(e), _) | (Ok(()), Err(e)) => {
                                    if let Some(r) = self.records.get_mut(key) {
                                        r.restore_failed = true;
                                        r.last_error = e;
                                    }
                                }
                                (Ok(()), Ok(_)) => {
                                    if let Some(r) = self.records.get_mut(key) {
                                        r.restore_failed = true;
                                        r.last_error =
                                            "原 memory.high 恢复后读回未确认一致".to_string();
                                    }
                                }
                            }
                            let _ = self.save_state();
                        }
                        Err(e) => {
                            if let Some(r) = self.records.get_mut(key) {
                                r.restore_failed = true;
                                r.last_error = e;
                            }
                            let _ = self.save_state();
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn build_status_and_alerts(
        &self,
        containers: &[ContainerSample],
        metrics_by_key: &HashMap<String, ContainerMetricsSummary>,
        decisions: &[MemoryContainerDecision],
        host_psi_some_avg10: Option<f64>,
    ) -> (HashMap<String, String>, Vec<String>) {
        let decision_by_key: HashMap<&str, &MemoryContainerDecision> =
            decisions.iter().map(|d| (d.key.as_str(), d)).collect();
        let mut status_by_key = HashMap::with_capacity(containers.len());
        let mut alerts = Vec::new();

        for c in containers {
            let key = container_guard_key(c);
            if key.is_empty() {
                continue;
            }
            let metrics = metrics_by_key.get(&key).cloned().unwrap_or_default();
            let dec = decision_by_key.get(key.as_str()).copied();
            let rec = self.records.get(&key);

            let tier = rec
                .map(|r| r.tier)
                .or_else(|| dec.map(|d| d.tier))
                .unwrap_or(0);
            let high_samples = dec.map(|d| d.high_samples).unwrap_or(0);
            let required_samples = dec.map(|d| d.required_samples).unwrap_or(3);
            let cooldown_remaining = dec.map(|d| d.cooldown_remaining_seconds).unwrap_or(0);

            let (state_str, message, readback_confirmed, orig_limit, active_limit, last_error, restore_failed) =
                if let Some(r) = rec {
                    if r.manual_override {
                        (
                            "manual_override",
                            if r.last_error.is_empty() {
                                "检测到人工更改 memory.high，系统保留该配置。"
                            } else {
                                r.last_error.as_str()
                            },
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    } else if r.restore_failed {
                        (
                            "restore_failed",
                            "内存压力已回落，但原 memory.high 未能恢复；保护设置仍在生效，需要管理员检查。",
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            true,
                        )
                    } else if r.readback_confirmed {
                        (
                            "limited",
                            "容器内存压力持续超过保护条件，已启用可恢复 memory.high 保护并读回确认。",
                            true,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    } else {
                        (
                            "apply_failed",
                            "已触发内存保护，但节点未能确认 memory.high 生效。",
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    }
                } else if let Some(d) = dec {
                    match d.stage {
                        GuardStage::Watching => (
                            "watching",
                            "检测到容器持续内存高占用与 PSI 压力，正在观察窗口内跟踪。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Active => (
                            "apply_failed",
                            "已触发内存保护，但节点未能确认 memory.high 生效。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Restored => (
                            "restored",
                            "内存压力已持续回落，原 memory.high 配置已恢复。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Cooldown => (
                            "cooldown",
                            "处于内存保护恢复冷却期。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForHostPsi => (
                            "waiting_for_host_psi",
                            "等待宿主机或容器内存 PSI 压力确认。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForPressure => (
                            "waiting_for_host_pressure",
                            "等待内存压力条件确认。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::SamplingUnavailable => (
                            "sampling_unavailable",
                            "内存 PSI 或 cgroup 用量采样暂不可用。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Normal | GuardStage::WaitingForOtherLimit | GuardStage::Unsupported => (
                            "normal",
                            "内存运行正常。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                    }
                } else {
                    ("normal", "内存运行正常。", false, "", "", "", false)
                };

            let status_json = format!(
                "{{\"state\":\"{}\",\"tier\":{},\"high_samples\":{},\"required_samples\":{},\"cooldown_remaining_seconds\":{},\"original_limit\":\"{}\",\"active_limit\":\"{}\",\"expected_limit\":\"{}\",\"readback_confirmed\":{},\"last_error\":\"{}\",\"message\":\"{}\"}}",
                json_escape(state_str),
                tier,
                high_samples,
                required_samples,
                cooldown_remaining,
                json_escape(orig_limit),
                json_escape(active_limit),
                json_escape(active_limit),
                readback_confirmed,
                json_escape(last_error),
                json_escape(message),
            );
            status_by_key.insert(key, status_json);

            let watching_alert = dec
                .map(|d| d.stage == GuardStage::Watching && d.high_samples >= 2)
                .unwrap_or(false);
            let active_or_failed = matches!(state_str, "limited" | "apply_failed" | "restore_failed");
            if watching_alert || active_or_failed {
                let (_, inst_id) = container_identity_strings(c);
                let alert_key = format!(
                    "memory-pressure:{}",
                    inst_id.chars().take(200).collect::<String>()
                );
                let (severity, title, alert_msg, attempted, succeeded) =
                    if watching_alert && !active_or_failed {
                        (
                            "warning",
                            "持续内存压力，正在监测并准备限额保护",
                            "检测到容器持续内存高占用与 PSI 压力，已进入自动 memory.high 保护观察窗口；没有停止进程或容器。",
                            false,
                            false,
                        )
                    } else if restore_failed {
                        (
                            "critical",
                            "内存保护需要检查",
                            "内存压力已回落，但原 memory.high 未能恢复；保护设置仍在生效，需要管理员检查。",
                            true,
                            false,
                        )
                    } else if readback_confirmed {
                        (
                            "warning",
                            "持续内存压力，已启用可恢复保护",
                            "容器持续处于高内存占用与 PSI 压力，已启用可恢复 memory.high 保护；没有停止进程或容器。",
                            true,
                            true,
                        )
                    } else {
                        (
                            "critical",
                            "内存保护需要检查",
                            "容器持续处于高内存压力，但节点未能确认 memory.high 限额生效。",
                            true,
                            false,
                        )
                    };
                let tier_pct_json = if readback_confirmed {
                    match tier {
                        1 => "90",
                        2 => "80",
                        3 => "70",
                        _ => "null",
                    }
                } else {
                    "null"
                };
                let host_psi_json = host_psi_some_avg10
                    .map(|p| format!("{p:.2}"))
                    .unwrap_or_else(|| "null".to_string());
                let alert_json = format!(
                    "{{\"type\":\"memory_pressure_protection\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"instance_id\":\"{}\",\"alert_key\":\"{}\",\"ongoing_protection\":true,\"memory_guard\":{{\"state\":\"{}\",\"tier\":{},\"tier_percent_of_max\":{},\"original_limit\":\"{}\",\"active_limit\":\"{}\",\"memory_current_bytes\":{},\"memory_max_bytes\":{},\"host_psi_some_avg10\":{},\"sample_count\":{},\"required_samples\":{},\"limit_applied\":{},\"restore_failed\":{},\"last_error\":\"{}\"}},\"automatic_remediation\":{{\"attempted\":{},\"succeeded\":{},\"action_type\":\"set_cgroup_memory_high\",\"message\":\"{}\"}}}}",
                    severity,
                    json_escape(title),
                    json_escape(alert_msg),
                    json_escape(&c.runtime),
                    json_escape(&c.project),
                    json_escape(&c.name),
                    json_escape(&inst_id),
                    json_escape(&alert_key),
                    json_escape(state_str),
                    if readback_confirmed { tier } else { 0 },
                    tier_pct_json,
                    json_escape(orig_limit),
                    json_escape(active_limit),
                    metrics.mem_bytes,
                    metrics.mem_limit_bytes,
                    host_psi_json,
                    high_samples.max(if readback_confirmed { required_samples } else { 0 }),
                    required_samples,
                    readback_confirmed,
                    restore_failed,
                    json_escape(last_error),
                    attempted,
                    succeeded,
                    json_escape(message),
                );
                alerts.push(alert_json);
            }
        }

        (status_by_key, alerts)
    }
}

// ---------------------------------------------------------------------------
// 2. IoGuardEnforcer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnforcedIoRecord {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub instance_id: String,
    pub device: String,
    pub original_limit: String,
    pub applied_limit: String,
    pub tier: u8,
    pub readback_confirmed: bool,
    pub manual_override: bool,
    pub restore_failed: bool,
    pub last_error: String,
    pub applied_at: u64,
}

fn is_valid_device(dev: &str) -> bool {
    let Some((maj, min)) = dev.trim().split_once(':') else {
        return false;
    };
    !maj.is_empty()
        && !min.is_empty()
        && maj.bytes().all(|b| b.is_ascii_digit())
        && min.bytes().all(|b| b.is_ascii_digit())
}

fn format_io_max_values(limits: &IoMaxLimits) -> String {
    let fmt_opt = |v: Option<u64>| -> String {
        v.map(|n| n.to_string())
            .unwrap_or_else(|| "max".to_string())
    };
    format!(
        "rbps={} wbps={} riops={} wiops={}",
        fmt_opt(limits.rbps),
        fmt_opt(limits.wbps),
        fmt_opt(limits.riops),
        fmt_opt(limits.wiops),
    )
}

fn read_io_max_device_line(
    c: &ContainerSample,
    device: &str,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<(PathBuf, String), String> {
    if !is_valid_device(device) {
        return Err("I/O 设备号格式无效".to_string());
    }
    let (identity, _) = container_identity_strings(c);
    let boundary = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    )?;
    let io_max_path = boundary.join("io.max");
    let raw = match fs::read_to_string(&io_max_path) {
        Ok(text) => text,
        Err(e) => return Err(format!("无法读取 io.max（{}）", e.kind())),
    };
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first().copied() == Some(device) {
            if let Some(lim) = parse_io_max_fields(&parts[1..]) {
                return Ok((boundary, format_io_max_values(&lim)));
            }
        }
    }
    Ok((
        boundary,
        "rbps=max wbps=max riops=max wiops=max".to_string(),
    ))
}

fn write_io_max_device_line(boundary: &Path, device: &str, values: &str) -> Result<(), String> {
    if !is_valid_device(device) {
        return Err("I/O 设备号格式无效".to_string());
    }
    let line = format!("{device} {values}");
    fs::write(boundary.join("io.max"), line.as_bytes())
        .map_err(|e| format!("写入 io.max 失败（{}）", e.kind()))
}

pub(crate) struct IoGuardEnforcer {
    state_path: PathBuf,
    pub(crate) records: HashMap<String, EnforcedIoRecord>,
}

impl IoGuardEnforcer {
    pub(crate) fn new(state_path: PathBuf) -> Self {
        let mut enforcer = Self {
            state_path,
            records: HashMap::new(),
        };
        enforcer.load_state();
        enforcer
    }

    fn load_state(&mut self) {
        let Ok(raw) = fs::read_to_string(&self.state_path) else {
            return;
        };
        let Ok(val) = JsonVal::parse(raw.trim()) else {
            return;
        };
        let Some(instances) = val.get("instances").and_then(JsonVal::as_obj) else {
            return;
        };
        for (k, v) in instances {
            self.records.insert(
                k.clone(),
                EnforcedIoRecord {
                    runtime: v.get_str("runtime").unwrap_or("").to_string(),
                    project: v.get_str("project").unwrap_or("").to_string(),
                    name: v.get_str("name").unwrap_or("").to_string(),
                    instance_id: v.get_str("instance_id").unwrap_or("").to_string(),
                    device: v.get_str("device").unwrap_or("").to_string(),
                    original_limit: v
                        .get_str("original_limit")
                        .unwrap_or("rbps=max wbps=max riops=max wiops=max")
                        .to_string(),
                    applied_limit: v.get_str("applied_limit").unwrap_or("").to_string(),
                    tier: v.get_u64("tier").unwrap_or(1).clamp(1, 3) as u8,
                    readback_confirmed: v.get_bool("readback_confirmed").unwrap_or(false),
                    manual_override: v.get_bool("manual_override").unwrap_or(false),
                    restore_failed: v.get_bool("restore_failed").unwrap_or(false),
                    last_error: v.get_str("last_error").unwrap_or("").to_string(),
                    applied_at: v.get_u64("applied_at").unwrap_or(0),
                },
            );
        }
    }

    fn save_state(&self) -> Result<(), String> {
        let mut json = String::from("{\"schema\":1,\"instances\":{");
        for (idx, (k, r)) in self.records.iter().enumerate() {
            if idx > 0 {
                json.push(',');
            }
            let _ = write!(
                json,
                "\"{}\":{{\"runtime\":\"{}\",\"project\":\"{}\",\"name\":\"{}\",\"instance_id\":\"{}\",\"device\":\"{}\",\"original_limit\":\"{}\",\"applied_limit\":\"{}\",\"tier\":{},\"readback_confirmed\":{},\"manual_override\":{},\"restore_failed\":{},\"last_error\":\"{}\",\"applied_at\":{}}}",
                json_escape(k),
                json_escape(&r.runtime),
                json_escape(&r.project),
                json_escape(&r.name),
                json_escape(&r.instance_id),
                json_escape(&r.device),
                json_escape(&r.original_limit),
                json_escape(&r.applied_limit),
                r.tier,
                r.readback_confirmed,
                r.manual_override,
                r.restore_failed,
                json_escape(&r.last_error),
                r.applied_at,
            );
        }
        json.push_str("}}");
        write_atomic_json(&self.state_path, "io-guard-limits", &json)
    }

    pub(crate) fn execute_actions(
        &mut self,
        containers: &[ContainerSample],
        actions: &[IoGuardAction],
        proc_root: &Path,
        cgroup_root: &Path,
        timestamp: u64,
    ) {
        if actions.is_empty() {
            return;
        }
        let by_key: HashMap<String, &ContainerSample> = containers
            .iter()
            .map(|c| (container_guard_key(c), c))
            .collect();

        for action in actions {
            match action {
                IoGuardAction::ApplyIoMax {
                    key,
                    device,
                    tier,
                    target,
                } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let (_, inst_id) = container_identity_strings(c);
                    let rt = c.runtime.trim().to_ascii_lowercase();
                    let target_str = format_io_max_values(target);
                    let (boundary, original) =
                        match read_io_max_device_line(c, device, proc_root, cgroup_root) {
                            Ok(res) => res,
                            Err(err) => {
                                self.records.insert(
                                    key.clone(),
                                    EnforcedIoRecord {
                                        runtime: rt,
                                        project: c.project.clone(),
                                        name: c.name.clone(),
                                        instance_id: inst_id,
                                        device: device.clone(),
                                        original_limit: String::new(),
                                        applied_limit: target_str,
                                        tier: *tier,
                                        readback_confirmed: false,
                                        manual_override: false,
                                        restore_failed: false,
                                        last_error: err,
                                        applied_at: timestamp,
                                    },
                                );
                                let _ = self.save_state();
                                continue;
                            }
                        };
                    self.records.insert(
                        key.clone(),
                        EnforcedIoRecord {
                            runtime: rt,
                            project: c.project.clone(),
                            name: c.name.clone(),
                            instance_id: inst_id,
                            device: device.clone(),
                            original_limit: original,
                            applied_limit: target_str.clone(),
                            tier: *tier,
                            readback_confirmed: false,
                            manual_override: false,
                            restore_failed: false,
                            last_error: String::new(),
                            applied_at: timestamp,
                        },
                    );
                    if let Err(err) = self.save_state() {
                        if let Some(r) = self.records.get_mut(key) {
                            r.last_error = err;
                        }
                        continue;
                    }
                    let write_res = write_io_max_device_line(&boundary, device, &target_str);
                    let readback_res = read_io_max_device_line(c, device, proc_root, cgroup_root);
                    if let Some(r) = self.records.get_mut(key) {
                        match (write_res, readback_res) {
                            (Ok(()), Ok((_, after))) if after == target_str => {
                                r.readback_confirmed = true;
                                r.last_error.clear();
                            }
                            (Err(e), _) => {
                                r.readback_confirmed = false;
                                r.last_error = e;
                            }
                            (Ok(()), Err(e)) => {
                                r.readback_confirmed = false;
                                r.last_error = format!("应用后读回 io.max 失败: {e}");
                            }
                            (Ok(()), Ok((_, after))) => {
                                r.readback_confirmed = false;
                                r.last_error = format!(
                                    "io.max 读回不一致: 期望 {target_str}, 实际 {after}"
                                );
                            }
                        }
                    }
                    let _ = self.save_state();
                }
                IoGuardAction::EscalateIoMax {
                    key,
                    device,
                    tier,
                    target,
                } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let Some(existing) = self.records.get(key).cloned() else {
                        continue;
                    };
                    if existing.manual_override {
                        continue;
                    }
                    match read_io_max_device_line(c, device, proc_root, cgroup_root) {
                        Ok((boundary, before)) => {
                            if !existing.applied_limit.is_empty()
                                && before != existing.applied_limit
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "io.max 在阶梯保护前发生人工更改；未覆盖。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let next_str = format_io_max_values(target);
                            let write_res = write_io_max_device_line(&boundary, device, &next_str);
                            let readback_res =
                                read_io_max_device_line(c, device, proc_root, cgroup_root);
                            if let Some(r) = self.records.get_mut(key) {
                                match (write_res, readback_res) {
                                    (Ok(()), Ok((_, after))) if after == next_str => {
                                        r.applied_limit = next_str;
                                        r.tier = *tier;
                                        r.readback_confirmed = true;
                                        r.last_error.clear();
                                    }
                                    (Err(e), _) => r.last_error = e,
                                    (Ok(()), Err(e)) => {
                                        r.last_error = format!("阶梯 io.max 读回失败: {e}");
                                    }
                                    (Ok(()), Ok(_)) => {
                                        r.last_error = "阶梯 io.max 读回值未匹配".to_string();
                                    }
                                }
                            }
                            let _ = self.save_state();
                        }
                        Err(e) => {
                            if let Some(r) = self.records.get_mut(key) {
                                r.last_error = e;
                            }
                            let _ = self.save_state();
                        }
                    }
                }
                IoGuardAction::RestoreIoMax { key, device, .. } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let Some(existing) = self.records.get(key).cloned() else {
                        continue;
                    };
                    if existing.manual_override {
                        self.records.remove(key);
                        let _ = self.save_state();
                        continue;
                    }
                    match read_io_max_device_line(c, device, proc_root, cgroup_root) {
                        Ok((boundary, before)) => {
                            if before == existing.original_limit {
                                self.records.remove(key);
                                let _ = self.save_state();
                                continue;
                            }
                            if !existing.applied_limit.is_empty()
                                && before != existing.applied_limit
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "检测到人工更改 io.max，系统保留该配置。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let write_res = write_io_max_device_line(
                                &boundary,
                                device,
                                &existing.original_limit,
                            );
                            let readback_res =
                                read_io_max_device_line(c, device, proc_root, cgroup_root);
                            match (write_res, readback_res) {
                                (Ok(()), Ok((_, after))) if after == existing.original_limit => {
                                    self.records.remove(key);
                                }
                                (Err(e), _) | (Ok(()), Err(e)) => {
                                    if let Some(r) = self.records.get_mut(key) {
                                        r.restore_failed = true;
                                        r.last_error = e;
                                    }
                                }
                                (Ok(()), Ok(_)) => {
                                    if let Some(r) = self.records.get_mut(key) {
                                        r.restore_failed = true;
                                        r.last_error =
                                            "原 io.max 恢复后读回未确认一致".to_string();
                                    }
                                }
                            }
                            let _ = self.save_state();
                        }
                        Err(e) => {
                            if let Some(r) = self.records.get_mut(key) {
                                r.restore_failed = true;
                                r.last_error = e;
                            }
                            let _ = self.save_state();
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn build_status_and_alerts(
        &self,
        containers: &[ContainerSample],
        decisions: &[IoContainerDecision],
        host_io_psi: Option<f64>,
    ) -> (HashMap<String, String>, Vec<String>) {
        let decision_by_key: HashMap<&str, &IoContainerDecision> =
            decisions.iter().map(|d| (d.key.as_str(), d)).collect();
        let mut status_by_key = HashMap::with_capacity(containers.len());
        let mut alerts = Vec::new();

        for c in containers {
            let key = container_guard_key(c);
            if key.is_empty() {
                continue;
            }
            let dec = decision_by_key.get(key.as_str()).copied();
            let rec = self.records.get(&key);

            let tier = rec
                .map(|r| r.tier)
                .or_else(|| dec.map(|d| d.tier))
                .unwrap_or(0);
            let device = rec
                .map(|r| r.device.as_str())
                .or_else(|| dec.and_then(|d| d.device.as_deref()))
                .unwrap_or("");
            let high_samples = dec.map(|d| d.high_samples).unwrap_or(0);
            let required_samples = dec.map(|d| d.required_samples).unwrap_or(2);
            let cooldown_remaining = dec.map(|d| d.cooldown_remaining_seconds).unwrap_or(0);
            let basis = dec.map(|d| d.pressure_basis).unwrap_or("none");

            let (state_str, message, readback_confirmed, orig_limit, active_limit, last_error, restore_failed) =
                if let Some(r) = rec {
                    if r.manual_override {
                        (
                            "manual_override",
                            if r.last_error.is_empty() {
                                "检测到人工更改 io.max，系统保留该配置。"
                            } else {
                                r.last_error.as_str()
                            },
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    } else if r.restore_failed {
                        (
                            "restore_failed",
                            "磁盘 I/O 压力已回落，但原 io.max 未能恢复；保护设置仍在生效，需要管理员检查。",
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            true,
                        )
                    } else if r.readback_confirmed {
                        (
                            "limited",
                            "容器持续产生高磁盘 I/O 压力，已临时限制 io.max 并读回确认。",
                            true,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    } else {
                        (
                            "apply_failed",
                            "已触发磁盘 I/O 保护，但节点未能确认 io.max 生效。",
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            false,
                        )
                    }
                } else if let Some(d) = dec {
                    match d.stage {
                        GuardStage::Watching => (
                            "watching",
                            "检测到容器磁盘 I/O 持续偏高，正在持续观察中。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Active => (
                            "apply_failed",
                            "已触发磁盘 I/O 保护，但节点未能确认 io.max 生效。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Restored => (
                            "restored",
                            "磁盘 I/O 压力已回落，原 io.max 配置已恢复。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Cooldown => (
                            "cooldown",
                            "处于磁盘 I/O 保护恢复冷却期。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForHostPsi => (
                            "waiting_for_host_psi",
                            "等待宿主机 I/O PSI 压力确认。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForPressure => (
                            "waiting_for_host_pressure",
                            "等待宿主机磁盘忙碌度达到保护门槛。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::SamplingUnavailable => (
                            "sampling_unavailable",
                            "磁盘 I/O 采样暂不可用。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Normal | GuardStage::WaitingForOtherLimit | GuardStage::Unsupported => (
                            "normal",
                            "磁盘 I/O 运行正常。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                    }
                } else {
                    ("normal", "磁盘 I/O 运行正常。", false, "", "", "", false)
                };

            let status_json = format!(
                "{{\"state\":\"{}\",\"device\":\"{}\",\"tier\":{},\"high_samples\":{},\"required_samples\":{},\"cooldown_remaining_seconds\":{},\"pressure_basis\":\"{}\",\"original_limit\":\"{}\",\"active_limit\":\"{}\",\"expected_limit\":\"{}\",\"readback_confirmed\":{},\"last_error\":\"{}\",\"message\":\"{}\"}}",
                json_escape(state_str),
                json_escape(device),
                tier,
                high_samples,
                required_samples,
                cooldown_remaining,
                json_escape(basis),
                json_escape(orig_limit),
                json_escape(active_limit),
                json_escape(active_limit),
                readback_confirmed,
                json_escape(last_error),
                json_escape(message),
            );
            status_by_key.insert(key, status_json);

            let watching_alert = dec
                .map(|d| d.stage == GuardStage::Watching && d.high_samples >= 2)
                .unwrap_or(false);
            let active_or_failed = matches!(state_str, "limited" | "apply_failed" | "restore_failed");
            if watching_alert || active_or_failed {
                let (_, inst_id) = container_identity_strings(c);
                let alert_key = format!(
                    "io-pressure:{}",
                    inst_id.chars().take(200).collect::<String>()
                );
                let (severity, title, alert_msg, attempted, succeeded) =
                    if watching_alert && !active_or_failed {
                        (
                            "warning",
                            "持续磁盘 I/O 压力，正在监测并准备限速保护",
                            "检测到容器磁盘 I/O 持续异常高负载，已进入自动 io.max 保护观察窗口；没有停止进程或容器。",
                            false,
                            false,
                        )
                    } else if restore_failed {
                        (
                            "critical",
                            "磁盘 I/O 保护需要检查",
                            "磁盘 I/O 压力已回落，但原 io.max 未能恢复；保护设置仍在生效，需要管理员检查。",
                            true,
                            false,
                        )
                    } else if readback_confirmed {
                        (
                            "warning",
                            "持续磁盘 I/O 压力，已启用容器保护",
                            "容器持续产生高磁盘 I/O 压力，系统已临时应用 io.max 保护；没有停止进程或容器。",
                            true,
                            true,
                        )
                    } else {
                        (
                            "critical",
                            "磁盘 I/O 保护需要检查",
                            "容器持续产生高磁盘 I/O 压力，但节点未能确认 io.max 生效。",
                            true,
                            false,
                        )
                    };
                let host_psi_json = host_io_psi
                    .map(|p| format!("{p:.2}"))
                    .unwrap_or_else(|| "null".to_string());
                let alert_json = format!(
                    "{{\"type\":\"io_pressure_protection\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"instance_id\":\"{}\",\"alert_key\":\"{}\",\"ongoing_protection\":true,\"io_guard\":{{\"state\":\"{}\",\"device\":\"{}\",\"tier\":{},\"original_limit\":\"{}\",\"active_limit\":\"{}\",\"host_io_psi_some_avg10\":{},\"pressure_basis\":\"{}\",\"sample_count\":{},\"required_samples\":{},\"limit_applied\":{},\"restore_failed\":{},\"last_error\":\"{}\"}},\"automatic_remediation\":{{\"attempted\":{},\"succeeded\":{},\"action_type\":\"set_cgroup_io_max\",\"message\":\"{}\"}}}}",
                    severity,
                    json_escape(title),
                    json_escape(alert_msg),
                    json_escape(&c.runtime),
                    json_escape(&c.project),
                    json_escape(&c.name),
                    json_escape(&inst_id),
                    json_escape(&alert_key),
                    json_escape(state_str),
                    json_escape(device),
                    if readback_confirmed { tier } else { 0 },
                    json_escape(orig_limit),
                    json_escape(active_limit),
                    host_psi_json,
                    json_escape(basis),
                    high_samples.max(if readback_confirmed { required_samples } else { 0 }),
                    required_samples,
                    readback_confirmed,
                    restore_failed,
                    json_escape(last_error),
                    attempted,
                    succeeded,
                    json_escape(message),
                );
                alerts.push(alert_json);
            }
        }

        (status_by_key, alerts)
    }
}
