#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cgroup_probe::PsiStatus;
use guard_core::{
    CpuContainerDecision, CpuGuardAction, GuardStage, HostCpuSample,
};
use runtime_drivers::{ContainerSample, JsonVal};

use crate::manual_resource_limits::{
    find_matching_rule, ManualLimitMode, ManualResourceLimitsPolicy,
};
use crate::{container_guard_key, json_escape};

const DEFAULT_CPU_GUARD_STATE_PATH: &str = "/var/lib/narwhal-agent/cpu-guard-limits.json";

#[derive(Debug, Clone, Default)]
pub(crate) struct ContainerMetricsSummary {
    pub cpu_percent: f64,
    pub cpu_effective_cpus: f64,
    pub mem_bytes: u64,
    pub mem_limit_bytes: u64,
    pub mem_percent: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub conn_count: u64,
    pub traffic_counters_available: bool,
    pub traffic_rx_bytes: u64,
    pub traffic_tx_bytes: u64,
    pub traffic_epoch: String,
    pub top_cpu_pid: u32,
    pub top_cpu_percent: f64,
    pub top_cpu_process: String,
    pub top_cpu_command: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnforcedCpuRecord {
    pub runtime: String,
    pub project: String,
    pub name: String,
    pub instance_id: String,
    pub original_limit: String,
    pub applied_limit: String,
    pub applied_cpus: f64,
    pub tier: u8,
    pub readback_confirmed: bool,
    pub manual_override: bool,
    pub restore_failed: bool,
    pub last_error: String,
    pub applied_at: u64,
    pub manual_active: bool,
    pub manual_mode: ManualLimitMode,
    pub manual_cpus: Option<f64>,
    pub manual_limit: String,
    pub auto_active: bool,
    pub auto_cpus: Option<f64>,
    pub auto_limit: String,
    pub effective_source: String,
    pub manual_revision: i64,
}

pub(crate) fn cpu_auto_limit_enabled_from_env() -> bool {
    std::env::var("SECURITY_CPU_AUTO_LIMIT_ENABLED")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

pub(crate) fn default_cpu_guard_state_path() -> PathBuf {
    std::env::var("NARWHAL_CPU_GUARD_RUST_STATE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CPU_GUARD_STATE_PATH))
}

fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

fn is_valid_uuid_ci(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if ch != b'-' {
                    return false;
                }
            }
            _ => {
                if !ch.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn is_podman_hex_id(s: &str) -> bool {
    (12..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn podman_boundary(segment: &str, stable_id: &str) -> bool {
    let trimmed = segment.strip_suffix(".scope").unwrap_or(segment);
    let Some(cg_id) = trimmed.strip_prefix("libpod-") else {
        return false;
    };
    if !is_podman_hex_id(cg_id) || !is_podman_hex_id(stable_id) {
        return false;
    }
    let cid_l = stable_id.to_ascii_lowercase();
    let cg_l = cg_id.to_ascii_lowercase();
    cg_l.starts_with(&cid_l) || cid_l.starts_with(&cg_l)
}

/// Safely resolve the container's cgroup v2 directory boundary from `<proc_root>/<pid>/cgroup`.
pub(crate) fn resolve_safe_container_cgroup(
    proc_root: &Path,
    cgroup_root: &Path,
    pid: Option<u32>,
    runtime: &str,
    stable_id: &str,
    name: &str,
) -> Result<PathBuf, String> {
    let pid = pid
        .filter(|&p| p > 1)
        .ok_or_else(|| "容器宿主机 PID 不可用".to_string())?;
    let rt = runtime.trim().to_ascii_lowercase();
    if !matches!(rt.as_str(), "incus" | "podman" | "runman") {
        return Err("仅支持 Incus / Podman / Runman 容器资源 cgroup".to_string());
    }
    let identity = stable_id.trim();
    let cname = name.trim();
    if !is_safe_id(identity) {
        return Err("运行时容器 ID 不可用，无法安全关联资源 cgroup".to_string());
    }

    let cgroup_file = proc_root.join(pid.to_string()).join("cgroup");
    let raw = fs::read_to_string(&cgroup_file)
        .map_err(|e| format!("无法读取容器资源 cgroup 证据：{}", e.kind()))?;
    let relative = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::trim))
        .unwrap_or("");
    if relative.is_empty() || relative == "/" || relative.contains("(deleted)") {
        return Err("未能确认容器 cgroup v2 路径".to_string());
    }
    let parts: Vec<&str> = relative
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() || parts.iter().any(|p| matches!(*p, "." | "..")) {
        return Err("容器 cgroup 路径格式无效".to_string());
    }

    let canon_root = fs::canonicalize(cgroup_root)
        .map_err(|e| format!("无法读取 cgroup 根目录：{}", e.kind()))?;
    let mut process_cg = cgroup_root.to_path_buf();
    for p in &parts {
        process_cg.push(p);
    }
    let canon_proc_cg = fs::canonicalize(&process_cg)
        .map_err(|e| format!("无法解析容器 cgroup 路径：{}", e.kind()))?;
    if canon_proc_cg == canon_root || !canon_proc_cg.starts_with(&canon_root) {
        return Err("容器 cgroup 路径越出受控目录".to_string());
    }

    let boundary_len = match rt.as_str() {
        "incus" => {
            let exp_id = format!("lxc.payload.{identity}");
            let exp_name = if !cname.is_empty() && is_safe_id(cname) {
                Some(format!("lxc.payload.{cname}"))
            } else {
                None
            };
            let matches: Vec<usize> = parts
                .iter()
                .enumerate()
                .filter_map(|(i, p)| {
                    if *p == exp_id || exp_name.as_deref() == Some(*p) {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            if matches.len() != 1 {
                return Err("PID 所在路径中没有唯一匹配该容器 ID 的资源 cgroup".to_string());
            }
            matches[0] + 1
        }
        "podman" => {
            let matches: Vec<usize> = parts
                .iter()
                .enumerate()
                .filter_map(|(i, p)| if podman_boundary(p, identity) { Some(i) } else { None })
                .collect();
            if matches.len() != 1 {
                return Err("PID 所在路径中没有唯一匹配该容器 ID 的资源 cgroup".to_string());
            }
            matches[0] + 1
        }
        "runman" => {
            let vm_id = if cname.is_empty() { identity } else { cname };
            if !is_valid_uuid_ci(vm_id) || !identity.eq_ignore_ascii_case(vm_id) {
                return Err("Runman VM UUID 与稳定容器身份不匹配".to_string());
            }
            let expected = format!("runman-{}.service", vm_id.to_ascii_lowercase());
            let matches: Vec<usize> = parts
                .iter()
                .enumerate()
                .filter_map(|(i, p)| if *p == expected { Some(i) } else { None })
                .collect();
            if matches.len() != 1 {
                return Err("PID 所在路径中没有唯一匹配该容器 ID 的资源 cgroup".to_string());
            }
            let unit_idx = matches[0];
            if unit_idx == 0
                || parts[unit_idx - 1] != "system.slice"
                || parts.get(unit_idx + 1).copied() != Some("ct")
            {
                return Err("Runman PID 不在该实例专属的 system.slice/ct cgroup 内".to_string());
            }
            unit_idx + 2
        }
        _ => return Err("不支持的容器运行时".to_string()),
    };

    let mut boundary = cgroup_root.to_path_buf();
    for p in &parts[..boundary_len] {
        boundary.push(p);
    }
    let canon_boundary = fs::canonicalize(&boundary)
        .map_err(|e| format!("无法解析容器资源边界 cgroup：{}", e.kind()))?;
    if canon_boundary == canon_root || !canon_boundary.starts_with(&canon_root) {
        return Err("容器资源 cgroup 路径越出受控目录".to_string());
    }
    let events_raw = fs::read_to_string(canon_boundary.join("cgroup.events"))
        .map_err(|_| "运行时容器边界缺少 cgroup.events".to_string())?;
    if !events_raw.lines().any(|l| l.trim() == "populated 1") {
        return Err("容器资源 cgroup 当前没有活动进程".to_string());
    }
    Ok(canon_boundary)
}

pub(crate) fn read_container_cpu_psi_avg10(
    proc_root: &Path,
    cgroup_root: &Path,
    c: &ContainerSample,
) -> Option<f64> {
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
    )
    .ok()?;
    match cgroup_probe::read_psi(&boundary.join("cpu.pressure")) {
        PsiStatus::Ready { some: Some(sec), .. } => Some(sec.avg10),
        _ => None,
    }
}

fn parse_runman_cpu_max(raw: &str) -> Option<(Option<u64>, u64)> {
    let mut parts = raw.split_whitespace();
    let q_str = parts.next()?;
    let p_str = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let period = p_str.parse::<u64>().ok()?;
    if !(1000..=1_000_000).contains(&period) {
        return None;
    }
    if q_str == "max" {
        return Some((None, period));
    }
    let quota = q_str.parse::<u64>().ok()?;
    if !(1000..=1_000_000_000).contains(&quota) {
        return None;
    }
    Some((Some(quota), period))
}

fn format_runman_target_cpu_max(original: &str, target_cpus: f64) -> Option<String> {
    let (orig_quota, period) = parse_runman_cpu_max(original)?;
    if !target_cpus.is_finite() || target_cpus <= 0.0 {
        return None;
    }
    let applied_quota = ((target_cpus * period as f64).floor() as u64).max(1000);
    if let Some(oq) = orig_quota {
        if applied_quota >= oq {
            return None;
        }
    }
    Some(format!("{applied_quota} {period}"))
}

fn parse_incus_allowance_period_ms(original: &str) -> u64 {
    let trimmed = original.trim().to_ascii_lowercase();
    if let Some((_, p)) = trimmed.split_once('/') {
        let p = p.trim().trim_end_matches("ms").trim();
        if let Ok(val) = p.parse::<f64>() {
            if val.is_finite() && val >= 1.0 {
                return val.round() as u64;
            }
        }
    }
    100
}

fn format_incus_target_allowance(original: &str, target_cpus: f64) -> Option<String> {
    if !target_cpus.is_finite() || target_cpus <= 0.0 {
        return None;
    }
    let period_ms = parse_incus_allowance_period_ms(original).max(1);
    let quota_ms = ((target_cpus * period_ms as f64).floor() as u64).max(1);
    Some(format!("{quota_ms}ms/{period_ms}ms"))
}

fn parse_podman_quota_str(raw: &str) -> Option<(i64, i64, i64)> {
    let parts: Vec<&str> = raw.trim().split('|').collect();
    if parts.len() != 4 {
        return None;
    }
    let quota = parts[0].trim().parse::<i64>().ok()?;
    let period = parts[1].trim().parse::<i64>().ok()?;
    let nano_cpus = parts[2].trim().parse::<i64>().ok()?;
    Some((quota, period, nano_cpus))
}

fn format_podman_target_quota(original: &str, target_cpus: f64) -> Option<String> {
    let (orig_quota, orig_period, nano_cpus) = parse_podman_quota_str(original)?;
    if nano_cpus > 0 || !target_cpus.is_finite() || target_cpus <= 0.0 {
        return None;
    }
    let period = if orig_period > 0 { orig_period } else { 100_000 };
    let quota = ((target_cpus * period as f64).floor() as i64).max(1000);
    if orig_quota > 0 && quota >= orig_quota {
        return None;
    }
    Some(format!("{quota}|{period}|0|"))
}

fn limits_match(runtime: &str, current: &str, expected: &str) -> bool {
    match runtime {
        "runman" | "incus" => current.trim() == expected.trim(),
        "podman" => {
            let Some((cq, cp, cn)) = parse_podman_quota_str(current) else {
                return false;
            };
            let Some((eq, ep, en)) = parse_podman_quota_str(expected) else {
                return false;
            };
            cq == eq && cn == en && (ep <= 0 || cp == ep)
        }
        _ => current.trim() == expected.trim(),
    }
}

fn run_cli(bin: &str, args: &[String]) -> Result<String, String> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("无法执行 {bin}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(if msg.is_empty() {
            format!("{bin} 退出状态异常 ({})", output.status)
        } else {
            msg.chars().take(240).collect()
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn read_runtime_cpu_limit(
    c: &ContainerSample,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<String, String> {
    let rt = c.runtime.trim().to_ascii_lowercase();
    match rt.as_str() {
        "runman" => {
            let identity = if !c.stable_id.is_empty() {
                c.stable_id.as_str()
            } else {
                c.id.as_str()
            };
            let boundary = resolve_safe_container_cgroup(
                proc_root,
                cgroup_root,
                c.pid,
                &rt,
                identity,
                &c.name,
            )?;
            let raw = fs::read_to_string(boundary.join("cpu.max"))
                .map_err(|e| format!("无法读取 Runman cpu.max（{}）", e.kind()))?;
            let trimmed = raw.trim().to_string();
            if parse_runman_cpu_max(&trimmed).is_none() {
                return Err("Runman cpu.max 格式无法确认".to_string());
            }
            Ok(trimmed)
        }
        "incus" => {
            let bin = if c.runtime_bin.is_empty() {
                "incus"
            } else {
                c.runtime_bin.as_str()
            };
            let mut args = Vec::new();
            if !c.project.is_empty() {
                args.push("--project".to_string());
                args.push(c.project.clone());
            }
            args.extend([
                "config".to_string(),
                "get".to_string(),
                c.name.clone(),
                "limits.cpu.allowance".to_string(),
            ]);
            run_cli(bin, &args)
        }
        "podman" => {
            let bin = if c.runtime_bin.is_empty() {
                "podman"
            } else {
                c.runtime_bin.as_str()
            };
            let args = vec![
                "inspect".to_string(),
                "--format".to_string(),
                "{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.CpusetCpus}}".to_string(),
                c.name.clone(),
            ];
            let out = run_cli(bin, &args)?;
            if parse_podman_quota_str(&out).is_none() {
                return Err("Podman inspect 未返回可验证的 CPU quota".to_string());
            }
            Ok(out)
        }
        _ => Err("不支持的容器运行时 CPU 限额".to_string()),
    }
}

fn write_runtime_cpu_limit(
    c: &ContainerSample,
    value: &str,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<(), String> {
    let rt = c.runtime.trim().to_ascii_lowercase();
    match rt.as_str() {
        "runman" => {
            if parse_runman_cpu_max(value).is_none() {
                return Err("Runman cpu.max 限值格式无效".to_string());
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
                &rt,
                identity,
                &c.name,
            )?;
            fs::write(boundary.join("cpu.max"), value.as_bytes())
                .map_err(|e| format!("写入 Runman cpu.max 失败（{}）", e.kind()))
        }
        "incus" => {
            let bin = if c.runtime_bin.is_empty() {
                "incus"
            } else {
                c.runtime_bin.as_str()
            };
            let mut args = Vec::new();
            if !c.project.is_empty() {
                args.push("--project".to_string());
                args.push(c.project.clone());
            }
            if value.trim().is_empty() {
                args.extend([
                    "config".to_string(),
                    "unset".to_string(),
                    c.name.clone(),
                    "limits.cpu.allowance".to_string(),
                ]);
            } else {
                args.extend([
                    "config".to_string(),
                    "set".to_string(),
                    c.name.clone(),
                    "limits.cpu.allowance".to_string(),
                    value.trim().to_string(),
                ]);
            }
            let _ = run_cli(bin, &args)?;
            Ok(())
        }
        "podman" => {
            let Some((quota, period, _)) = parse_podman_quota_str(value) else {
                return Err("Podman CPU quota 格式无效".to_string());
            };
            let bin = if c.runtime_bin.is_empty() {
                "podman"
            } else {
                c.runtime_bin.as_str()
            };
            let mut args = vec!["update".to_string(), format!("--cpu-quota={quota}")];
            if period > 0 {
                args.push(format!("--cpu-period={period}"));
            }
            args.push(c.name.clone());
            let _ = run_cli(bin, &args)?;
            Ok(())
        }
        _ => Err("不支持的容器运行时 CPU 限额".to_string()),
    }
}

fn compute_target_limit_str(rt: &str, original: &str, target_cpus: f64) -> Option<String> {
    match rt {
        "runman" => format_runman_target_cpu_max(original, target_cpus),
        "incus" => format_incus_target_allowance(original, target_cpus),
        "podman" => format_podman_target_quota(original, target_cpus),
        _ => None,
    }
}

fn compute_manual_target_limit_str(rt: &str, original: &str, target_cpus: f64) -> Option<String> {
    if !target_cpus.is_finite() || target_cpus <= 0.0 {
        return None;
    }
    match rt {
        "runman" => {
            let (orig_quota, period) = parse_runman_cpu_max(original)?;
            let mut applied_quota = ((target_cpus * period as f64).floor() as u64).max(1000);
            if let Some(oq) = orig_quota {
                applied_quota = applied_quota.min(oq);
            }
            Some(format!("{applied_quota} {period}"))
        }
        "incus" => format_incus_target_allowance(original, target_cpus),
        "podman" => {
            let (orig_quota, orig_period, nano_cpus) = parse_podman_quota_str(original)?;
            if nano_cpus > 0 {
                return None;
            }
            let period = if orig_period > 0 { orig_period } else { 100_000 };
            let mut quota = ((target_cpus * period as f64).floor() as i64).max(1000);
            if orig_quota > 0 {
                quota = quota.min(orig_quota);
            }
            Some(format!("{quota}|{period}|0|"))
        }
        _ => None,
    }
}

pub(crate) struct CpuGuardEnforcer {
    state_path: PathBuf,
    pub(crate) records: HashMap<String, EnforcedCpuRecord>,
}

impl CpuGuardEnforcer {
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
            let rec = EnforcedCpuRecord {
                runtime: v.get_str("runtime").unwrap_or("").to_string(),
                project: v.get_str("project").unwrap_or("").to_string(),
                name: v.get_str("name").unwrap_or("").to_string(),
                instance_id: v.get_str("instance_id").unwrap_or("").to_string(),
                original_limit: v.get_str("original_limit").unwrap_or("").to_string(),
                applied_limit: v.get_str("applied_limit").unwrap_or("").to_string(),
                applied_cpus: v.get("applied_cpus").and_then(JsonVal::as_f64).unwrap_or(0.0),
                tier: v.get_u64("tier").unwrap_or(0).clamp(0, 3) as u8,
                readback_confirmed: v.get_bool("readback_confirmed").unwrap_or(false),
                manual_override: v.get_bool("manual_override").unwrap_or(false),
                restore_failed: v.get_bool("restore_failed").unwrap_or(false),
                last_error: v.get_str("last_error").unwrap_or("").to_string(),
                applied_at: v.get_u64("applied_at").unwrap_or(0),
                manual_active: v.get_bool("manual_active").unwrap_or(false),
                manual_mode: ManualLimitMode::parse(v.get_str("manual_mode").unwrap_or("cooperate"))
                    .unwrap_or_default(),
                manual_cpus: v.get("manual_cpus").and_then(JsonVal::as_f64),
                manual_limit: v.get_str("manual_limit").unwrap_or("").to_string(),
                auto_active: v.get_bool("auto_active").unwrap_or(false),
                auto_cpus: v.get("auto_cpus").and_then(JsonVal::as_f64),
                auto_limit: v.get_str("auto_limit").unwrap_or("").to_string(),
                effective_source: {
                    let s = v.get_str("effective_source").unwrap_or("");
                    if s.is_empty() {
                        if v.get_bool("manual_active").unwrap_or(false) {
                            "manual".to_string()
                        } else {
                            "auto".to_string()
                        }
                    } else {
                        s.to_string()
                    }
                },
                manual_revision: v.get("manual_revision").and_then(JsonVal::as_i64).unwrap_or(0),
            };
            self.records.insert(k.clone(), rec);
        }
    }

    fn save_state(&self) -> Result<(), String> {
        if let Some(parent) = self.state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("创建 CPU guard 状态目录失败: {e}"))?;
            }
        }
        let mut json = String::from("{\"schema\":1,\"instances\":{");
        for (idx, (k, r)) in self.records.iter().enumerate() {
            if idx > 0 {
                json.push(',');
            }
            let manual_cpus_json = r
                .manual_cpus
                .map(|c| format!("{c:.4}"))
                .unwrap_or_else(|| "null".to_string());
            let auto_cpus_json = r
                .auto_cpus
                .map(|c| format!("{c:.4}"))
                .unwrap_or_else(|| "null".to_string());
            let _ = write!(
                json,
                "\"{}\":{{\"runtime\":\"{}\",\"project\":\"{}\",\"name\":\"{}\",\"instance_id\":\"{}\",\"original_limit\":\"{}\",\"applied_limit\":\"{}\",\"applied_cpus\":{:.4},\"tier\":{},\"readback_confirmed\":{},\"manual_override\":{},\"restore_failed\":{},\"last_error\":\"{}\",\"applied_at\":{},\"manual_active\":{},\"manual_mode\":\"{}\",\"manual_cpus\":{},\"manual_limit\":\"{}\",\"auto_active\":{},\"auto_cpus\":{},\"auto_limit\":\"{}\",\"effective_source\":\"{}\",\"manual_revision\":{}}}",
                json_escape(k),
                json_escape(&r.runtime),
                json_escape(&r.project),
                json_escape(&r.name),
                json_escape(&r.instance_id),
                json_escape(&r.original_limit),
                json_escape(&r.applied_limit),
                r.applied_cpus,
                r.tier,
                r.readback_confirmed,
                r.manual_override,
                r.restore_failed,
                json_escape(&r.last_error),
                r.applied_at,
                r.manual_active,
                r.manual_mode.as_str(),
                manual_cpus_json,
                json_escape(&r.manual_limit),
                r.auto_active,
                auto_cpus_json,
                json_escape(&r.auto_limit),
                json_escape(&r.effective_source),
                r.manual_revision,
            );
        }
        json.push_str("}}");

        let dir = self.state_path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(format!(".cpu-guard-limits-{}.tmp", std::process::id()));
        fs::write(&tmp, json.as_bytes())
            .map_err(|e| format!("写入 CPU guard 状态失败: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp, &self.state_path)
            .map_err(|e| format!("替换 CPU guard 状态失败: {e}"))?;
        Ok(())
    }

    pub(crate) fn reconcile_manual_limits(
        &mut self,
        containers: &[ContainerSample],
        policy: &ManualResourceLimitsPolicy,
        proc_root: &Path,
        cgroup_root: &Path,
        timestamp: u64,
    ) {
        let mut by_key: HashMap<String, &ContainerSample> = HashMap::with_capacity(containers.len());
        for c in containers {
            let k = container_guard_key(c);
            if !k.is_empty() {
                by_key.insert(k, c);
            }
        }

        // 1. Apply/update manual CPU limits for matched running containers.
        for c in containers {
            let key = container_guard_key(c);
            if key.is_empty() {
                continue;
            }
            let Some(rule) = find_matching_rule(policy, c) else {
                continue;
            };
            let Some(manual_cpus) = rule.cpu_cpus else {
                continue;
            };
            let rt = c.runtime.trim().to_ascii_lowercase();
            let inst_id = if !c.instance_id.is_empty() {
                c.instance_id.clone()
            } else if !c.stable_id.is_empty() {
                c.stable_id.clone()
            } else {
                c.id.clone()
            };

            let existing_opt = self.records.get(&key).cloned();
            let (original, current_live) = match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                Ok(live) => {
                    if let Some(ref ex) = existing_opt {
                        let orig = if !ex.original_limit.is_empty() {
                            ex.original_limit.clone()
                        } else {
                            live.clone()
                        };
                        (orig, live)
                    } else {
                        (live.clone(), live)
                    }
                }
                Err(err) => {
                    let mut rec = existing_opt.unwrap_or(EnforcedCpuRecord {
                        runtime: rt,
                        project: c.project.clone(),
                        name: c.name.clone(),
                        instance_id: inst_id,
                        original_limit: String::new(),
                        applied_limit: String::new(),
                        applied_cpus: 0.0,
                        tier: 0,
                        readback_confirmed: false,
                        manual_override: false,
                        restore_failed: false,
                        last_error: String::new(),
                        applied_at: timestamp,
                        manual_active: true,
                        manual_mode: rule.mode,
                        manual_cpus: Some(manual_cpus),
                        manual_limit: String::new(),
                        auto_active: false,
                        auto_cpus: None,
                        auto_limit: String::new(),
                        effective_source: "manual".to_string(),
                        manual_revision: policy.revision,
                    });
                    rec.manual_active = true;
                    rec.manual_mode = rule.mode;
                    rec.manual_cpus = Some(manual_cpus);
                    rec.manual_revision = policy.revision;
                    rec.readback_confirmed = false;
                    rec.last_error = err;
                    self.records.insert(key, rec);
                    let _ = self.save_state();
                    continue;
                }
            };

            let Some(manual_limit_str) =
                compute_manual_target_limit_str(&rt, &original, manual_cpus)
            else {
                continue;
            };

            let (auto_active, auto_cpus, auto_limit) = existing_opt
                .as_ref()
                .map(|ex| (ex.auto_active, ex.auto_cpus, ex.auto_limit.clone()))
                .unwrap_or((false, None, String::new()));

            let auto_is_stricter = rule.mode == ManualLimitMode::Cooperate
                && auto_active
                && auto_cpus.is_some_and(|ac| ac < manual_cpus && !auto_limit.is_empty());

            let (desired_limit, desired_cpus, desired_source) = if auto_is_stricter {
                (
                    auto_limit.clone(),
                    auto_cpus.unwrap_or(manual_cpus),
                    "auto_over_manual".to_string(),
                )
            } else {
                (manual_limit_str.clone(), manual_cpus, "manual".to_string())
            };

            let revision_changed = existing_opt
                .as_ref()
                .map(|ex| {
                    !ex.manual_active
                        || ex.manual_revision != policy.revision
                        || ex.manual_mode != rule.mode
                        || ex.manual_limit != manual_limit_str
                })
                .unwrap_or(true);

            if !revision_changed
                && existing_opt
                    .as_ref()
                    .is_some_and(|ex| ex.readback_confirmed && limits_match(&rt, &current_live, &desired_limit))
            {
                continue;
            }

            let mut rec = existing_opt.unwrap_or(EnforcedCpuRecord {
                runtime: rt.clone(),
                project: c.project.clone(),
                name: c.name.clone(),
                instance_id: inst_id,
                original_limit: original.clone(),
                applied_limit: desired_limit.clone(),
                applied_cpus: desired_cpus,
                tier: 0,
                readback_confirmed: false,
                manual_override: false,
                restore_failed: false,
                last_error: String::new(),
                applied_at: timestamp,
                manual_active: true,
                manual_mode: rule.mode,
                manual_cpus: Some(manual_cpus),
                manual_limit: manual_limit_str.clone(),
                auto_active,
                auto_cpus,
                auto_limit,
                effective_source: desired_source.clone(),
                manual_revision: policy.revision,
            });
            rec.original_limit = original;
            rec.manual_active = true;
            rec.manual_mode = rule.mode;
            rec.manual_cpus = Some(manual_cpus);
            rec.manual_limit = manual_limit_str;
            rec.manual_override = false;
            rec.restore_failed = false;
            rec.manual_revision = policy.revision;
            rec.applied_limit = desired_limit.clone();
            rec.applied_cpus = desired_cpus;
            rec.effective_source = desired_source;
            rec.applied_at = timestamp;
            self.records.insert(key.clone(), rec);
            if let Err(err) = self.save_state() {
                if let Some(r) = self.records.get_mut(&key) {
                    r.last_error = err;
                }
                continue;
            }

            let write_res = if limits_match(&rt, &current_live, &desired_limit) {
                Ok(())
            } else {
                write_runtime_cpu_limit(c, &desired_limit, proc_root, cgroup_root)
            };
            let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
            if let Some(r) = self.records.get_mut(&key) {
                match (write_res, readback_res) {
                    (Ok(()), Ok(after)) if limits_match(&rt, &after, &desired_limit) => {
                        r.readback_confirmed = true;
                        r.last_error.clear();
                    }
                    (Err(e), _) => {
                        r.readback_confirmed = false;
                        r.last_error = e;
                    }
                    (Ok(()), Err(e)) => {
                        r.readback_confirmed = false;
                        r.last_error = format!("应用主动 CPU 限额后读回失败: {e}");
                    }
                    (Ok(()), Ok(after)) => {
                        r.readback_confirmed = false;
                        r.last_error = format!(
                            "主动 CPU 限额读回不一致: 期望 {desired_limit}, 实际 {after}"
                        );
                    }
                }
            }
            let _ = self.save_state();
        }

        // 2. Clear manual CPU limits removed from policy.
        let manual_keys: Vec<String> = self
            .records
            .iter()
            .filter_map(|(k, r)| if r.manual_active { Some(k.clone()) } else { None })
            .collect();

        for key in manual_keys {
            let Some(c) = by_key.get(&key).copied() else {
                continue;
            };
            let still_has_manual_cpu = find_matching_rule(policy, c)
                .and_then(|r| r.cpu_cpus)
                .is_some();
            if still_has_manual_cpu {
                continue;
            }
            let Some(existing) = self.records.get(&key).cloned() else {
                continue;
            };
            let rt = c.runtime.trim().to_ascii_lowercase();
            let (restore_target, keep_auto) = if existing.auto_active && !existing.auto_limit.is_empty()
            {
                (existing.auto_limit.clone(), true)
            } else {
                (existing.original_limit.clone(), false)
            };
            if restore_target.is_empty() {
                if !keep_auto {
                    self.records.remove(&key);
                    let _ = self.save_state();
                }
                continue;
            }
            let write_res = match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                Ok(before) if limits_match(&rt, &before, &restore_target) => Ok(()),
                Ok(_) => write_runtime_cpu_limit(c, &restore_target, proc_root, cgroup_root),
                Err(e) => Err(e),
            };
            let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
            match (write_res, readback_res) {
                (Ok(()), Ok(after)) if limits_match(&rt, &after, &restore_target) => {
                    if keep_auto {
                        if let Some(r) = self.records.get_mut(&key) {
                            r.manual_active = false;
                            r.manual_cpus = None;
                            r.manual_limit.clear();
                            r.manual_revision = policy.revision;
                            r.applied_limit = restore_target;
                            r.applied_cpus = existing.auto_cpus.unwrap_or(0.0);
                            r.effective_source = "auto".to_string();
                            r.readback_confirmed = true;
                            r.restore_failed = false;
                            r.last_error.clear();
                        }
                    } else {
                        self.records.remove(&key);
                    }
                }
                (Err(e), _) | (Ok(()), Err(e)) => {
                    if let Some(r) = self.records.get_mut(&key) {
                        r.restore_failed = true;
                        r.last_error = e;
                    }
                }
                (Ok(()), Ok(_)) => {
                    if let Some(r) = self.records.get_mut(&key) {
                        r.restore_failed = true;
                        r.last_error = "清除主动 CPU 限额后读回未确认一致".to_string();
                    }
                }
            }
            let _ = self.save_state();
        }
    }

    pub(crate) fn execute_actions(
        &mut self,
        containers: &[ContainerSample],
        actions: &[CpuGuardAction],
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
                CpuGuardAction::ApplyLimit {
                    key,
                    tier,
                    target_cpus,
                    ..
                } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let rt = c.runtime.trim().to_ascii_lowercase();
                    if let Some(existing) = self.records.get(key).cloned() {
                        if existing.manual_active {
                            let auto_str = compute_target_limit_str(
                                &rt,
                                &existing.original_limit,
                                *target_cpus,
                            )
                            .unwrap_or_default();
                            if existing.manual_mode == ManualLimitMode::Lock
                                || existing.manual_cpus.is_some_and(|mc| *target_cpus >= mc)
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.auto_active = true;
                                    r.auto_cpus = Some(*target_cpus);
                                    r.auto_limit = auto_str;
                                    r.tier = *tier;
                                    r.effective_source = "manual".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            if !auto_str.is_empty() {
                                let write_res =
                                    write_runtime_cpu_limit(c, &auto_str, proc_root, cgroup_root);
                                let readback_res =
                                    read_runtime_cpu_limit(c, proc_root, cgroup_root);
                                if let Some(r) = self.records.get_mut(key) {
                                    r.auto_active = true;
                                    r.auto_cpus = Some(*target_cpus);
                                    r.auto_limit = auto_str.clone();
                                    r.tier = *tier;
                                    match (write_res, readback_res) {
                                        (Ok(()), Ok(after)) if limits_match(&rt, &after, &auto_str) => {
                                            r.applied_limit = auto_str;
                                            r.applied_cpus = *target_cpus;
                                            r.effective_source = "auto_over_manual".to_string();
                                            r.readback_confirmed = true;
                                            r.last_error.clear();
                                        }
                                        (Err(e), _) | (Ok(()), Err(e)) => {
                                            r.readback_confirmed = false;
                                            r.last_error = e;
                                        }
                                        (Ok(()), Ok(after)) => {
                                            r.readback_confirmed = false;
                                            r.last_error = format!(
                                                "联合收紧读回不一致: 期望 {auto_str}, 实际 {after}"
                                            );
                                        }
                                    }
                                }
                                let _ = self.save_state();
                            }
                            continue;
                        }
                    }
                    let inst_id = if !c.instance_id.is_empty() {
                        c.instance_id.clone()
                    } else if !c.stable_id.is_empty() {
                        c.stable_id.clone()
                    } else {
                        c.id.clone()
                    };
                    let original = match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                        Ok(val) => val,
                        Err(err) => {
                            self.records.insert(
                                key.clone(),
                                EnforcedCpuRecord {
                                    runtime: rt,
                                    project: c.project.clone(),
                                    name: c.name.clone(),
                                    instance_id: inst_id,
                                    original_limit: String::new(),
                                    applied_limit: String::new(),
                                    applied_cpus: *target_cpus,
                                    tier: *tier,
                                    readback_confirmed: false,
                                    manual_override: false,
                                    restore_failed: false,
                                    last_error: err,
                                    applied_at: timestamp,
                                    manual_active: false,
                                    manual_mode: ManualLimitMode::Cooperate,
                                    manual_cpus: None,
                                    manual_limit: String::new(),
                                    auto_active: true,
                                    auto_cpus: Some(*target_cpus),
                                    auto_limit: String::new(),
                                    effective_source: "auto".to_string(),
                                    manual_revision: 0,
                                },
                            );
                            let _ = self.save_state();
                            continue;
                        }
                    };
                    let Some(target_limit) = compute_target_limit_str(&rt, &original, *target_cpus)
                    else {
                        continue;
                    };
                    let rec = EnforcedCpuRecord {
                        runtime: rt.clone(),
                        project: c.project.clone(),
                        name: c.name.clone(),
                        instance_id: inst_id,
                        original_limit: original.clone(),
                        applied_limit: target_limit.clone(),
                        applied_cpus: *target_cpus,
                        tier: *tier,
                        readback_confirmed: false,
                        manual_override: false,
                        restore_failed: false,
                        last_error: String::new(),
                        applied_at: timestamp,
                        manual_active: false,
                        manual_mode: ManualLimitMode::Cooperate,
                        manual_cpus: None,
                        manual_limit: String::new(),
                        auto_active: true,
                        auto_cpus: Some(*target_cpus),
                        auto_limit: target_limit.clone(),
                        effective_source: "auto".to_string(),
                        manual_revision: 0,
                    };
                    self.records.insert(key.clone(), rec);
                    if let Err(err) = self.save_state() {
                        if let Some(r) = self.records.get_mut(key) {
                            r.last_error = err;
                        }
                        continue;
                    }
                    let write_res = write_runtime_cpu_limit(c, &target_limit, proc_root, cgroup_root);
                    let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
                    if let Some(r) = self.records.get_mut(key) {
                        match (write_res, readback_res) {
                            (Ok(()), Ok(after)) if limits_match(&rt, &after, &target_limit) => {
                                r.readback_confirmed = true;
                                r.last_error.clear();
                            }
                            (Err(e), _) => {
                                r.readback_confirmed = false;
                                r.last_error = e;
                            }
                            (Ok(()), Err(e)) => {
                                r.readback_confirmed = false;
                                r.last_error = format!("应用后读回校验失败: {e}");
                            }
                            (Ok(()), Ok(after)) => {
                                r.readback_confirmed = false;
                                r.last_error =
                                    format!("应用后读回不一致: 期望 {target_limit}, 实际 {after}");
                            }
                        }
                    }
                    let _ = self.save_state();
                }
                CpuGuardAction::EscalateLimit {
                    key,
                    tier,
                    target_cpus,
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
                    let rt = c.runtime.trim().to_ascii_lowercase();
                    if existing.manual_active {
                        let auto_str = compute_target_limit_str(
                            &rt,
                            &existing.original_limit,
                            *target_cpus,
                        )
                        .unwrap_or_default();
                        if existing.manual_mode == ManualLimitMode::Lock
                            || existing.manual_cpus.is_some_and(|mc| *target_cpus >= mc)
                        {
                            if let Some(r) = self.records.get_mut(key) {
                                r.auto_active = true;
                                r.auto_cpus = Some(*target_cpus);
                                r.auto_limit = auto_str;
                                r.tier = *tier;
                                r.effective_source = "manual".to_string();
                            }
                            let _ = self.save_state();
                            continue;
                        }
                    }
                    match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                        Ok(before) => {
                            if !existing.applied_limit.is_empty()
                                && !limits_match(&rt, &before, &existing.applied_limit)
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "CPU 配额在阶梯保护执行前发生人工更改；未覆盖。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let Some(next_limit) =
                                compute_target_limit_str(&rt, &existing.original_limit, *target_cpus)
                            else {
                                continue;
                            };
                            let write_res =
                                write_runtime_cpu_limit(c, &next_limit, proc_root, cgroup_root);
                            let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
                            if let Some(r) = self.records.get_mut(key) {
                                match (write_res, readback_res) {
                                    (Ok(()), Ok(after))
                                        if limits_match(&rt, &after, &next_limit) =>
                                    {
                                        r.applied_limit = next_limit.clone();
                                        r.applied_cpus = *target_cpus;
                                        r.auto_active = true;
                                        r.auto_cpus = Some(*target_cpus);
                                        r.auto_limit = next_limit;
                                        r.tier = *tier;
                                        r.effective_source = if existing.manual_active {
                                            "auto_over_manual".to_string()
                                        } else {
                                            "auto".to_string()
                                        };
                                        r.readback_confirmed = true;
                                        r.last_error.clear();
                                    }
                                    (Err(e), _) => {
                                        r.last_error = e;
                                    }
                                    (Ok(()), Err(e)) => {
                                        r.last_error = format!("阶梯限额读回失败: {e}");
                                    }
                                    (Ok(()), Ok(_)) => {
                                        r.last_error = "阶梯限额读回值未匹配".to_string();
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
                CpuGuardAction::RestoreLimit { key, .. } => {
                    let Some(c) = by_key.get(key).copied() else {
                        continue;
                    };
                    let Some(existing) = self.records.get(key).cloned() else {
                        continue;
                    };
                    if existing.manual_override {
                        if !existing.manual_active {
                            self.records.remove(key);
                            let _ = self.save_state();
                        }
                        continue;
                    }
                    let rt = c.runtime.trim().to_ascii_lowercase();
                    if existing.manual_active {
                        let target_restore = existing.manual_limit.clone();
                        let write_res = if target_restore.is_empty() {
                            Ok(())
                        } else {
                            match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                                Ok(before) if limits_match(&rt, &before, &target_restore) => Ok(()),
                                Ok(_) => write_runtime_cpu_limit(
                                    c,
                                    &target_restore,
                                    proc_root,
                                    cgroup_root,
                                ),
                                Err(e) => Err(e),
                            }
                        };
                        let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
                        if let Some(r) = self.records.get_mut(key) {
                            r.auto_active = false;
                            r.auto_cpus = None;
                            r.auto_limit.clear();
                            r.tier = 0;
                            match (write_res, readback_res) {
                                (Ok(()), Ok(after))
                                    if target_restore.is_empty()
                                        || limits_match(&rt, &after, &target_restore) =>
                                {
                                    r.applied_limit = target_restore;
                                    r.applied_cpus = existing.manual_cpus.unwrap_or(0.0);
                                    r.effective_source = "manual".to_string();
                                    r.readback_confirmed = true;
                                    r.restore_failed = false;
                                    r.last_error.clear();
                                }
                                (Err(e), _) | (Ok(()), Err(e)) => {
                                    r.restore_failed = true;
                                    r.last_error = e;
                                }
                                (Ok(()), Ok(_)) => {
                                    r.restore_failed = true;
                                    r.last_error =
                                        "自动压力恢复至主动 CPU 限额后读回未确认一致".to_string();
                                }
                            }
                        }
                        let _ = self.save_state();
                        continue;
                    }
                    match read_runtime_cpu_limit(c, proc_root, cgroup_root) {
                        Ok(before) => {
                            if limits_match(&rt, &before, &existing.original_limit) {
                                self.records.remove(key);
                                let _ = self.save_state();
                                continue;
                            }
                            if !existing.applied_limit.is_empty()
                                && !limits_match(&rt, &before, &existing.applied_limit)
                            {
                                if let Some(r) = self.records.get_mut(key) {
                                    r.manual_override = true;
                                    r.readback_confirmed = false;
                                    r.last_error =
                                        "检测到人工更改 CPU 配置，系统保留该配置。".to_string();
                                }
                                let _ = self.save_state();
                                continue;
                            }
                            let write_res = write_runtime_cpu_limit(
                                c,
                                &existing.original_limit,
                                proc_root,
                                cgroup_root,
                            );
                            let readback_res = read_runtime_cpu_limit(c, proc_root, cgroup_root);
                            match (write_res, readback_res) {
                                (Ok(()), Ok(after))
                                    if limits_match(&rt, &after, &existing.original_limit) =>
                                {
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
                                            "原 CPU 配置恢复后读回未确认一致".to_string();
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_container_cpu_guard_status_and_alerts(
        &self,
        containers: &[ContainerSample],
        metrics_by_key: &HashMap<String, ContainerMetricsSummary>,
        decisions: &[CpuContainerDecision],
        host_cpu: &HostCpuSample,
        high_threshold_percent: f64,
        host_busy_threshold_percent: f64,
        host_psi_threshold_percent: f64,
        proc_root: &Path,
        _timestamp: u64,
    ) -> (HashMap<String, String>, Vec<String>) {
        let decision_by_key: HashMap<&str, &CpuContainerDecision> =
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

            let effective_cpus = if metrics.cpu_effective_cpus > 0.0 {
                metrics.cpu_effective_cpus
            } else {
                host_cpu.logical_cpus.max(1) as f64
            };
            let tier = rec
                .map(|r| r.tier)
                .or_else(|| dec.map(|d| d.tier))
                .unwrap_or(0);
            let high_samples = dec.map(|d| d.high_samples).unwrap_or(0);
            let required_samples = dec.map(|d| d.required_samples).unwrap_or(3);
            let cooldown_remaining = dec.map(|d| d.cooldown_remaining_seconds).unwrap_or(0);
            let basis = dec.map(|d| d.pressure_basis).unwrap_or("none");

            let (state_str, message, readback_confirmed, orig_limit, active_limit, last_error, restore_failed) =
                if let Some(r) = rec {
                    if r.manual_override {
                        (
                            "manual_override",
                            if r.last_error.is_empty() {
                                "检测到人工更改 CPU 配置，系统保留该配置。"
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
                            "容器 CPU 已回落，但原配额未能恢复；临时保护限额仍在生效，需要管理员检查。",
                            false,
                            r.original_limit.as_str(),
                            r.applied_limit.as_str(),
                            r.last_error.as_str(),
                            true,
                        )
                    } else if r.readback_confirmed {
                        if r.manual_active && r.effective_source == "manual" {
                            (
                                "manual_limited",
                                if r.auto_active {
                                    "已启用容器主动 CPU 限额并读回确认（当前严于自动压力限额）。"
                                } else {
                                    "已启用容器主动 CPU 限额并读回确认。"
                                },
                                true,
                                r.original_limit.as_str(),
                                r.applied_limit.as_str(),
                                r.last_error.as_str(),
                                false,
                            )
                        } else if r.manual_active && r.effective_source == "auto_over_manual" {
                            (
                                "limited",
                                "主动 CPU 限额生效中，且因持续高负载由自动保护进一步收紧。",
                                true,
                                r.original_limit.as_str(),
                                r.applied_limit.as_str(),
                                r.last_error.as_str(),
                                false,
                            )
                        } else {
                            (
                                "limited",
                                "容器 CPU 持续达到保护条件，已应用临时 CPU 限额并读回确认。",
                                true,
                                r.original_limit.as_str(),
                                r.applied_limit.as_str(),
                                r.last_error.as_str(),
                                false,
                            )
                        }
                    } else {
                        (
                            "apply_failed",
                            "已触发临时 CPU 保护，但节点未能确认限额生效。",
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
                            "检测到容器 CPU 持续偏高，正在持续观察中。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Active => (
                            "apply_failed",
                            "已触发 CPU 压力保护，但节点未能确认限额生效。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Restored => (
                            "restored",
                            "原 CPU 配置已恢复。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Cooldown => (
                            "cooldown",
                            "处于 CPU 保护恢复冷却期。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForHostPsi => (
                            "waiting_for_host_psi",
                            "等待宿主机 CPU PSI 压力确认。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::WaitingForPressure => (
                            "waiting_for_host_pressure",
                            "等待宿主机 CPU 忙碌度达到保护门槛。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::SamplingUnavailable => (
                            "sampling_unavailable",
                            "CPU 采样暂不可用或处于预热阶段。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                        GuardStage::Normal | GuardStage::WaitingForOtherLimit | GuardStage::Unsupported => (
                            "normal",
                            "CPU 运行正常。",
                            false,
                            "",
                            "",
                            "",
                            false,
                        ),
                    }
                } else {
                    ("normal", "CPU 运行正常。", false, "", "", "", false)
                };

            let manual_active = rec.map(|r| r.manual_active).unwrap_or(false);
            let manual_mode_str = rec
                .filter(|r| r.manual_active)
                .map(|r| r.manual_mode.as_str())
                .unwrap_or("");
            let manual_limit_str = rec
                .filter(|r| r.manual_active)
                .map(|r| r.manual_limit.as_str())
                .unwrap_or("");
            let manual_cpus_json = rec
                .filter(|r| r.manual_active)
                .and_then(|r| r.manual_cpus)
                .map(|v| format!("{v:.3}"))
                .unwrap_or_else(|| "null".to_string());
            let effective_source_str = rec
                .map(|r| r.effective_source.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(if dec.is_some_and(|d| d.stage == GuardStage::Active) {
                    "auto"
                } else {
                    "none"
                });
            let actual_limit_str = if readback_confirmed { active_limit } else { "" };

            let status_json = format!(
                "{{\"state\":\"{}\",\"tier\":{},\"effective_cpus\":{:.3},\"high_samples\":{},\"required_samples\":{},\"cooldown_remaining_seconds\":{},\"host_pressure_basis\":\"{}\",\"original_limit\":\"{}\",\"active_limit\":\"{}\",\"expected_limit\":\"{}\",\"actual_limit\":\"{}\",\"readback_confirmed\":{},\"manual_active\":{},\"manual_mode\":\"{}\",\"manual_limit\":\"{}\",\"manual_cpus\":{},\"effective_source\":\"{}\",\"last_error\":\"{}\",\"message\":\"{}\"}}",
                json_escape(state_str),
                tier,
                effective_cpus,
                high_samples,
                required_samples,
                cooldown_remaining,
                json_escape(basis),
                json_escape(orig_limit),
                json_escape(active_limit),
                json_escape(active_limit),
                json_escape(actual_limit_str),
                readback_confirmed,
                manual_active,
                json_escape(manual_mode_str),
                json_escape(manual_limit_str),
                manual_cpus_json,
                json_escape(effective_source_str),
                json_escape(last_error),
                json_escape(message),
            );
            status_by_key.insert(key.clone(), status_json);

            let watching_alert = dec
                .map(|d| d.stage == GuardStage::Watching && d.high_samples >= 2)
                .unwrap_or(false)
                && !manual_active;
            let active_or_failed = matches!(state_str, "limited" | "apply_failed" | "restore_failed");
            if watching_alert || active_or_failed {
                let top_proc_json = sample_top_cpu_process_json(proc_root, c.pid);
                let inst_id = if !c.instance_id.is_empty() {
                    c.instance_id.as_str()
                } else if !c.stable_id.is_empty() {
                    c.stable_id.as_str()
                } else {
                    c.id.as_str()
                };
                let alert_key_raw = format!("cpu-pressure:{}", &inst_id.chars().take(200).collect::<String>());
                let threshold_percent = effective_cpus * high_threshold_percent;
                let (severity, title, alert_msg, attempted, succeeded, watching_flag) =
                    if watching_alert && !active_or_failed {
                        (
                            "warning",
                            "持续高 CPU，正在监测并准备限额保护",
                            "检测到容器 CPU 持续异常高占用，已采样高占用进程并进入自动限额保护观察窗口；没有停止进程或容器。",
                            false,
                            false,
                            true,
                        )
                    } else if restore_failed {
                        (
                            "critical",
                            "持续高 CPU，保护需要检查",
                            "容器 CPU 已回落，但原配额未能恢复；临时保护限额仍在生效，需要管理员检查。",
                            true,
                            false,
                            false,
                        )
                    } else if readback_confirmed {
                        (
                            "warning",
                            "持续高 CPU，已启用临时保护",
                            "容器 CPU 已连续达到保护条件，系统已临时降低该容器 CPU 配额；没有停止进程或容器。",
                            true,
                            true,
                            false,
                        )
                    } else {
                        (
                            "critical",
                            "持续高 CPU，保护需要检查",
                            "主机与容器 CPU 指标已连续达到保护条件，但节点未能确认 CPU 限额生效；没有停止进程或容器。",
                            true,
                            false,
                            false,
                        )
                    };
                let tier_pct_json = if readback_confirmed {
                    match tier {
                        1 => "50",
                        2 => "25",
                        3 => "10",
                        _ => "null",
                    }
                } else {
                    "null"
                };
                let psi_json = host_cpu
                    .psi_some_avg10
                    .map(|p| format!("{p:.2}"))
                    .unwrap_or_else(|| "null".to_string());
                let load_json = host_cpu
                    .load_1m
                    .map(|l| format!("{l:.3}"))
                    .unwrap_or_else(|| "null".to_string());
                let alert_json = format!(
                    "{{\"type\":\"cpu_pressure_protection\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"value\":{:.2},\"threshold\":{:.2},\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"alert_key\":\"{}\",\"instance_id\":\"{}\",\"ongoing_protection\":true,\"cpu_guard\":{{\"container_cpu_percent\":{:.2},\"cpu_sample_available\":true,\"effective_cpus\":{:.3},\"host_busy_percent\":{:.2},\"host_logical_cpus\":{},\"host_load_1m\":{},\"host_cpu_psi_some_avg10\":{},\"host_cpu_psi_threshold_percent\":{:.2},\"host_pressure_basis\":\"{}\",\"sample_count\":{},\"required_samples\":{},\"threshold_percent_of_container_capacity\":{:.2},\"threshold_percent_of_one_cpu\":{:.2},\"host_busy_threshold_percent\":{:.2},\"top_process\":{},\"limit_applied\":{},\"tier\":{},\"tier_percent_of_original\":{},\"restore_failed\":{},\"last_error\":\"{}\",\"reason_is_user_abuse\":false}},\"automatic_remediation\":{{\"attempted\":{},\"succeeded\":{},\"watching\":{},\"original_limit\":\"{}\",\"applied_limit\":\"{}\",\"readback_confirmed\":{},\"message\":\"{}\"}}}}",
                    severity,
                    json_escape(title),
                    json_escape(alert_msg),
                    metrics.cpu_percent,
                    threshold_percent,
                    json_escape(&c.runtime),
                    json_escape(&c.project),
                    json_escape(&c.name),
                    json_escape(&alert_key_raw),
                    json_escape(inst_id),
                    metrics.cpu_percent,
                    effective_cpus,
                    host_cpu.busy_percent,
                    host_cpu.logical_cpus,
                    load_json,
                    psi_json,
                    host_psi_threshold_percent,
                    json_escape(basis),
                    high_samples.max(if readback_confirmed { required_samples } else { 0 }),
                    required_samples,
                    high_threshold_percent,
                    high_threshold_percent,
                    host_busy_threshold_percent,
                    top_proc_json,
                    readback_confirmed,
                    if readback_confirmed { tier } else { 0 },
                    tier_pct_json,
                    restore_failed,
                    json_escape(last_error),
                    attempted,
                    succeeded,
                    watching_flag,
                    json_escape(orig_limit),
                    json_escape(active_limit),
                    readback_confirmed,
                    json_escape(message),
                );
                alerts.push(alert_json);
            }
        }

        (status_by_key, alerts)
    }
}

fn sample_top_cpu_process_json(proc_root: &Path, init_pid: Option<u32>) -> String {
    let Some(pid) = init_pid.filter(|&p| p > 1) else {
        return "{}".to_string();
    };
    let snap_raw = proc_probe::collect_proc_snapshot_from_root(proc_root, pid, 4096, 100.0);
    let Ok(val) = JsonVal::parse(snap_raw.trim()) else {
        return "{}".to_string();
    };
    let Some(items) = val.get("items").and_then(JsonVal::as_arr) else {
        return "{}".to_string();
    };
    let mut best: Option<(&JsonVal, f64)> = None;
    for item in items {
        let cpu = item
            .get("cpu_percent")
            .and_then(JsonVal::as_f64)
            .or_else(|| item.get("lifetime_cpu_percent").and_then(JsonVal::as_f64))
            .unwrap_or(0.0);
        if best.map_or(true, |(_, b_cpu)| cpu > b_cpu) {
            best = Some((item, cpu));
        }
    }
    let Some((top, cpu)) = best else {
        return "{}".to_string();
    };
    let top_pid = top.get_u64("pid").unwrap_or(0);
    let proc_name = top.get_str("process").unwrap_or("unknown");
    let cmd = top.get_str("command").unwrap_or("");
    format!(
        "{{\"available\":true,\"source\":\"host_proc_snapshot\",\"pid\":{},\"cpu_percent\":{:.2},\"process\":\"{}\",\"command\":\"{}\"}}",
        top_pid,
        cpu,
        json_escape(proc_name),
        json_escape(cmd),
    )
}
