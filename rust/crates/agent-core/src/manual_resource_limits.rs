#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use guard_core::IoMaxLimits;
use runtime_drivers::{ContainerSample, JsonVal};

use crate::cpu_guard_exec::{resolve_safe_container_cgroup, CpuGuardEnforcer};
use crate::resource_guard_exec::{IoGuardEnforcer, MemoryGuardEnforcer};
use crate::{container_guard_key, json_escape};

const DEFAULT_MANUAL_RESOURCE_STATE_PATH: &str =
    "/var/lib/narwhal-agent/manual-resource-limits.json";
const MAX_RESOURCE_POLICIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManualLimitMode {
    Cooperate,
    Lock,
}

impl Default for ManualLimitMode {
    fn default() -> Self {
        Self::Cooperate
    }
}

impl ManualLimitMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cooperate => "cooperate",
            Self::Lock => "lock",
        }
    }

    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "cooperate" => Ok(Self::Cooperate),
            "lock" => Ok(Self::Lock),
            other => Err(format!("不支持的联动模式: {other}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManualContainerResourceRule {
    pub runtime: String,
    pub project: String,
    pub container_name: String,
    pub container_id: String,
    pub mode: ManualLimitMode,
    pub cpu_cpus: Option<f64>,
    pub memory_high_mb: Option<u64>,
    pub io_device: String,
    pub io_read_mbps: Option<u64>,
    pub io_write_mbps: Option<u64>,
    pub io_read_iops: Option<u64>,
    pub io_write_iops: Option<u64>,
    pub note: String,
}

impl ManualContainerResourceRule {
    pub(crate) fn has_io_limits(&self) -> bool {
        self.io_read_mbps.is_some()
            || self.io_write_mbps.is_some()
            || self.io_read_iops.is_some()
            || self.io_write_iops.is_some()
    }

    pub(crate) fn target_io_limits(&self) -> IoMaxLimits {
        IoMaxLimits {
            rbps: self.io_read_mbps.map(|m| m.saturating_mul(1024 * 1024)),
            wbps: self.io_write_mbps.map(|m| m.saturating_mul(1024 * 1024)),
            riops: self.io_read_iops,
            wiops: self.io_write_iops,
        }
    }

    pub(crate) fn memory_high_bytes(&self) -> Option<u64> {
        self.memory_high_mb
            .map(|mb| mb.saturating_mul(1024 * 1024))
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ManualResourceLimitsPolicy {
    pub host_id: String,
    pub expected_node_id: String,
    pub revision: i64,
    pub limits: Vec<ManualContainerResourceRule>,
}

pub(crate) fn default_manual_resource_state_path() -> PathBuf {
    std::env::var("NARWHAL_MANUAL_RESOURCE_LIMITS_STATE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MANUAL_RESOURCE_STATE_PATH))
}

fn is_safe_container_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

pub(crate) fn is_valid_device_id(dev: &str) -> bool {
    let Some((maj, min)) = dev.trim().split_once(':') else {
        return false;
    };
    !maj.is_empty()
        && !min.is_empty()
        && maj.bytes().all(|b| b.is_ascii_digit())
        && min.bytes().all(|b| b.is_ascii_digit())
}

fn canonical_project(runtime: &str, project: &str) -> String {
    let trimmed = project.trim();
    if trimmed.is_empty() && matches!(runtime, "incus" | "runman") {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_opt_f64_in_range(
    obj: &JsonVal,
    key: &str,
    lo: f64,
    hi: f64,
) -> Result<Option<f64>, String> {
    let Some(val) = obj.get(key) else {
        return Ok(None);
    };
    if matches!(val, JsonVal::Null) {
        return Ok(None);
    }
    let Some(n) = val.as_f64() else {
        return Err(format!("{key} 必须是有效数字"));
    };
    if !n.is_finite() || n < lo || n > hi {
        return Err(format!("{key} 超出范围 ({lo}..={hi})"));
    }
    Ok(Some((n * 1000.0).round() / 1000.0))
}

fn parse_opt_u64_in_range(
    obj: &JsonVal,
    key: &str,
    lo: u64,
    hi: u64,
) -> Result<Option<u64>, String> {
    let Some(val) = obj.get(key) else {
        return Ok(None);
    };
    if matches!(val, JsonVal::Null) {
        return Ok(None);
    }
    let Some(n) = val.as_u64() else {
        return Err(format!("{key} 必须是正整数"));
    };
    if n < lo || n > hi {
        return Err(format!("{key} 超出范围 ({lo}..={hi})"));
    }
    Ok(Some(n))
}

pub(crate) fn parse_and_validate_policy_json(
    raw: &str,
    host_id: &str,
    node_id: &str,
) -> Result<ManualResourceLimitsPolicy, String> {
    let val = JsonVal::parse(raw.trim())
        .map_err(|e| format!("resource_limits JSON 解析失败: {e}"))?;
    let schema = val.get_u64("schema").unwrap_or(0);
    if schema != 1 {
        return Err("不支持的 resource_limits schema 版本".to_string());
    }
    let p_host = val.get_str("host_id").unwrap_or("");
    let p_node = val.get_str("expected_node_id").unwrap_or("");
    if p_host != host_id || p_node != node_id {
        return Err("resource_limits 主机/节点身份不匹配".to_string());
    }
    let revision = val
        .get("revision")
        .and_then(JsonVal::as_i64)
        .unwrap_or(0)
        .max(0);
    let Some(limits_arr) = val.get("limits").and_then(JsonVal::as_arr) else {
        return Err("resource_limits.limits 必须是数组".to_string());
    };
    if limits_arr.len() > MAX_RESOURCE_POLICIES {
        return Err("resource_limits 条目超过最大限制".to_string());
    }

    let mut rules = Vec::with_capacity(limits_arr.len());
    for item in limits_arr {
        let runtime = item
            .get_str("runtime")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !matches!(runtime.as_str(), "incus" | "podman" | "runman") {
            return Err("resource_limits 仅支持 incus/podman/runman".to_string());
        }
        let project = item.get_str("project").unwrap_or("").trim().to_string();
        if project.len() > 100 {
            return Err("resource_limits project 长度无效".to_string());
        }
        let container_name = item
            .get_str("container_name")
            .unwrap_or("")
            .trim()
            .to_string();
        if container_name.is_empty() || container_name.len() > 200 {
            return Err("resource_limits container_name 无效".to_string());
        }
        let container_id = item
            .get_str("container_id")
            .unwrap_or("")
            .trim()
            .to_string();
        if !is_safe_container_id(&container_id) {
            return Err("resource_limits container_id 无效".to_string());
        }
        let mode = ManualLimitMode::parse(item.get_str("mode").unwrap_or("cooperate"))?;
        let cpu_cpus = parse_opt_f64_in_range(item, "cpu_cpus", 0.05, 64.0)?;
        let memory_high_mb = parse_opt_u64_in_range(item, "memory_high_mb", 16, 1_048_576)?;
        let io_read_mbps = parse_opt_u64_in_range(item, "io_read_mbps", 1, 10_000)?;
        let io_write_mbps = parse_opt_u64_in_range(item, "io_write_mbps", 1, 10_000)?;
        let io_read_iops = parse_opt_u64_in_range(item, "io_read_iops", 10, 1_000_000)?;
        let io_write_iops = parse_opt_u64_in_range(item, "io_write_iops", 10, 1_000_000)?;
        let io_device = item.get_str("io_device").unwrap_or("").trim().to_string();
        if !io_device.is_empty() && !is_valid_device_id(&io_device) {
            return Err("resource_limits io_device 格式无效".to_string());
        }
        let note = item
            .get_str("note")
            .unwrap_or("")
            .trim()
            .chars()
            .take(120)
            .collect::<String>();
        if cpu_cpus.is_none()
            && memory_high_mb.is_none()
            && io_read_mbps.is_none()
            && io_write_mbps.is_none()
            && io_read_iops.is_none()
            && io_write_iops.is_none()
        {
            return Err("resource_limits 项至少需要一项限额".to_string());
        }
        rules.push(ManualContainerResourceRule {
            runtime,
            project,
            container_name,
            container_id,
            mode,
            cpu_cpus,
            memory_high_mb,
            io_device,
            io_read_mbps,
            io_write_mbps,
            io_read_iops,
            io_write_iops,
            note,
        });
    }

    Ok(ManualResourceLimitsPolicy {
        host_id: host_id.to_string(),
        expected_node_id: node_id.to_string(),
        revision,
        limits: rules,
    })
}

pub(crate) fn policy_to_json(policy: &ManualResourceLimitsPolicy) -> String {
    let mut out = String::from("{");
    let _ = write!(
        out,
        "\"schema\":1,\"host_id\":\"{}\",\"expected_node_id\":\"{}\",\"revision\":{},\"limits\":[",
        json_escape(&policy.host_id),
        json_escape(&policy.expected_node_id),
        policy.revision
    );
    for (idx, r) in policy.limits.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let cpu_json = r
            .cpu_cpus
            .map(|v| format!("{v:.3}"))
            .unwrap_or_else(|| "null".to_string());
        let opt_u64 = |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string());
        let _ = write!(
            out,
            "{{\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"container_id\":\"{}\",\"mode\":\"{}\",\"cpu_cpus\":{},\"memory_high_mb\":{},\"io_device\":\"{}\",\"io_read_mbps\":{},\"io_write_mbps\":{},\"io_read_iops\":{},\"io_write_iops\":{},\"note\":\"{}\"}}",
            json_escape(&r.runtime),
            json_escape(&r.project),
            json_escape(&r.container_name),
            json_escape(&r.container_id),
            r.mode.as_str(),
            cpu_json,
            opt_u64(r.memory_high_mb),
            json_escape(&r.io_device),
            opt_u64(r.io_read_mbps),
            opt_u64(r.io_write_mbps),
            opt_u64(r.io_read_iops),
            opt_u64(r.io_write_iops),
            json_escape(&r.note),
        );
    }
    out.push_str("]}");
    out
}

pub(crate) fn load_policy_state(
    path: &Path,
    host_id: &str,
    node_id: &str,
) -> ManualResourceLimitsPolicy {
    let Ok(raw) = fs::read_to_string(path) else {
        return ManualResourceLimitsPolicy {
            host_id: host_id.to_string(),
            expected_node_id: node_id.to_string(),
            revision: 0,
            limits: Vec::new(),
        };
    };
    parse_and_validate_policy_json(&raw, host_id, node_id).unwrap_or_else(|_| {
        ManualResourceLimitsPolicy {
            host_id: host_id.to_string(),
            expected_node_id: node_id.to_string(),
            revision: 0,
            limits: Vec::new(),
        }
    })
}

pub(crate) fn save_policy_state(
    path: &Path,
    policy: &ManualResourceLimitsPolicy,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("创建主动资源限制状态目录失败: {e}"))?;
        }
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".manual-resource-limits-{}.tmp", std::process::id()));
    let json = policy_to_json(policy);
    fs::write(&tmp, json.as_bytes()).map_err(|e| format!("写入主动资源限制状态失败: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| format!("替换主动资源限制状态失败: {e}"))?;
    Ok(())
}

pub(crate) fn rule_matches_container(
    rule: &ManualContainerResourceRule,
    c: &ContainerSample,
) -> bool {
    let rt = c.runtime.trim().to_ascii_lowercase();
    if rule.runtime != rt {
        return false;
    }
    if canonical_project(&rule.runtime, &rule.project) != canonical_project(&rt, &c.project) {
        return false;
    }
    if rule.container_name != c.name.trim() {
        return false;
    }
    if rt == "runman" {
        !c.instance_id.is_empty() && rule.container_id.eq_ignore_ascii_case(&c.instance_id)
    } else {
        rule.container_id == c.id
            || (!c.stable_id.is_empty() && rule.container_id == c.stable_id)
    }
}

pub(crate) fn find_matching_rule<'a>(
    policy: &'a ManualResourceLimitsPolicy,
    c: &ContainerSample,
) -> Option<&'a ManualContainerResourceRule> {
    policy.limits.iter().find(|r| rule_matches_container(r, c))
}

pub(crate) fn resolve_container_io_device(
    proc_root: &Path,
    cgroup_root: &Path,
    c: &ContainerSample,
    preferred: &str,
    existing_device: &str,
) -> Result<String, String> {
    if !preferred.trim().is_empty() {
        let dev = preferred.trim();
        if is_valid_device_id(dev) {
            return Ok(dev.to_string());
        }
        return Err(format!("无效的 I/O 设备号: {dev}"));
    }
    if is_valid_device_id(existing_device) {
        return Ok(existing_device.trim().to_string());
    }
    let identity = if !c.stable_id.is_empty() {
        c.stable_id.as_str()
    } else {
        c.id.as_str()
    };
    let boundary = resolve_safe_container_cgroup(
        proc_root,
        cgroup_root,
        c.pid,
        &c.runtime,
        identity,
        &c.name,
    )?;
    for fname in ["io.max", "io.stat"] {
        if let Ok(raw) = fs::read_to_string(boundary.join(fname)) {
            for line in raw.lines() {
                if let Some(first) = line.split_whitespace().next() {
                    if is_valid_device_id(first) {
                        return Ok(first.to_string());
                    }
                }
            }
        }
    }
    if let Ok(mountinfo) = fs::read_to_string(proc_root.join("self").join("mountinfo")) {
        for line in mountinfo.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[4] == "/" && is_valid_device_id(parts[2]) {
                if !parts[2].starts_with("0:") {
                    return Ok(parts[2].to_string());
                }
            }
        }
    }
    Err("未能识别容器所在磁盘设备号，请在限制表单中指定 io_device（如 8:0）".to_string())
}

pub(crate) fn build_manual_resource_limits_report_json(
    policy: &ManualResourceLimitsPolicy,
    containers: &[ContainerSample],
    cpu_enforcer: &CpuGuardEnforcer,
    mem_enforcer: &MemoryGuardEnforcer,
    io_enforcer: &IoGuardEnforcer,
    updated_at: u64,
) -> String {
    let mut items_json = Vec::with_capacity(policy.limits.len());
    let mut overall_state = if policy.limits.is_empty() {
        "unconfigured"
    } else {
        "applied"
    };

    for rule in &policy.limits {
        let matched = containers.iter().find(|c| rule_matches_container(rule, c));
        let (state, message, eff_cpu, eff_mem, eff_io) = if let Some(c) = matched {
            let key = container_guard_key(c);
            let mut failed_msgs: Vec<String> = Vec::new();
            let mut eff_cpu_str = String::new();
            let mut eff_mem_str = String::new();
            let mut eff_io_str = String::new();

            if rule.cpu_cpus.is_some() {
                if let Some(r) = cpu_enforcer.records.get(&key) {
                    eff_cpu_str = r.applied_limit.clone();
                    if !r.readback_confirmed && r.effective_source != "auto_over_manual" {
                        failed_msgs.push(if r.last_error.is_empty() {
                            "CPU 限额待读回确认".to_string()
                        } else {
                            r.last_error.clone()
                        });
                    }
                } else {
                    failed_msgs.push("CPU 限额尚未应用".to_string());
                }
            }
            if rule.memory_high_mb.is_some() {
                if let Some(r) = mem_enforcer.records.get(&key) {
                    eff_mem_str = r.applied_limit.clone();
                    if !r.readback_confirmed {
                        failed_msgs.push(if r.last_error.is_empty() {
                            "memory.high 限额待读回确认".to_string()
                        } else {
                            r.last_error.clone()
                        });
                    }
                } else {
                    failed_msgs.push("memory.high 尚未应用".to_string());
                }
            }
            if rule.has_io_limits() {
                if let Some(r) = io_enforcer.records.get(&key) {
                    eff_io_str = if r.device.is_empty() {
                        r.applied_limit.clone()
                    } else {
                        format!("{} {}", r.device, r.applied_limit)
                    };
                    if !r.readback_confirmed {
                        failed_msgs.push(if r.last_error.is_empty() {
                            "io.max 限额待读回确认".to_string()
                        } else {
                            r.last_error.clone()
                        });
                    }
                } else {
                    failed_msgs.push("io.max 尚未应用".to_string());
                }
            }

            if failed_msgs.is_empty() {
                (
                    "applied",
                    "主动资源限额已应用并读回确认".to_string(),
                    eff_cpu_str,
                    eff_mem_str,
                    eff_io_str,
                )
            } else {
                overall_state = "failed";
                (
                    "failed",
                    failed_msgs.join("；"),
                    eff_cpu_str,
                    eff_mem_str,
                    eff_io_str,
                )
            }
        } else {
            overall_state = "failed";
            (
                "failed",
                "未匹配到对应运行中容器（可能已停止、重建或代次已变化）".to_string(),
                String::new(),
                String::new(),
                String::new(),
            )
        };

        items_json.push(format!(
            "{{\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"container_id\":\"{}\",\"mode\":\"{}\",\"state\":\"{}\",\"message\":\"{}\",\"effective_cpu\":\"{}\",\"effective_memory\":\"{}\",\"effective_io\":\"{}\"}}",
            json_escape(&rule.runtime),
            json_escape(&rule.project),
            json_escape(&rule.container_name),
            json_escape(&rule.container_id),
            rule.mode.as_str(),
            state,
            json_escape(&message),
            json_escape(&eff_cpu),
            json_escape(&eff_mem),
            json_escape(&eff_io),
        ));
    }

    format!(
        "{{\"revision\":{},\"state\":\"{}\",\"updated_at\":{},\"items\":[{}]}}",
        policy.revision,
        overall_state,
        updated_at,
        items_json.join(","),
    )
}
