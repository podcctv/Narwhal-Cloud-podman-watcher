#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use proc_probe::json_escape;
use runtime_drivers::{runman_request, ContainerSample};
use transport::sha256_hex;

use crate::actions::{parse_json, JsonValue};

const AUDIT_INTERVAL_SECS: u64 = 300;
const RUNMAN_FIREWALL_SOCK: &str = "/run/narwhal-agent/firewall.sock";

#[derive(Debug, Clone)]
pub struct SecurityIndicatorItem {
    pub rule: String,
    pub component: String,
    pub severity: String,
    pub title: String,
    pub guidance: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuditEventItem {
    pub event_type: String,
    pub alert_key: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub component: String,
    pub evidence: Vec<String>,
}

pub struct HostAuditState {
    pub baseline_at: u64,
    pub last_audit_at: u64,
    pub last_rescan_handled: u64,
    pub rescan_requested_at: u64,
    pub file_hashes: BTreeMap<String, String>,
    pub ssh_log_offset: u64,
    pub cached_json: String,
    pub firewall_event_cursor: String,
}

impl Default for HostAuditState {
    fn default() -> Self {
        Self {
            baseline_at: 0,
            last_audit_at: 0,
            last_rescan_handled: 0,
            rescan_requested_at: 0,
            file_hashes: BTreeMap::new(),
            ssh_log_offset: 0,
            cached_json: String::new(),
            firewall_event_cursor: String::new(),
        }
    }
}

fn is_agent_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

pub fn parse_os_release(etc_root: &Path) -> (String, String, String) {
    let raw = fs::read_to_string(etc_root.join("os-release")).unwrap_or_default();
    let (mut id, mut name, mut ver) = (String::new(), String::new(), String::new());
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            match k.trim() {
                "ID" => id = val,
                "PRETTY_NAME" => name = val,
                "NAME" if name.is_empty() => name = val,
                "VERSION_ID" => ver = val,
                _ => {}
            }
        }
    }
    (id, name, ver)
}

fn count_ssh_keys_in_file(path: &Path) -> usize {
    let Ok(raw) = fs::read_to_string(path) else {
        return 0;
    };
    raw.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && (line.contains("ssh-") || line.contains("ecdsa-") || line.contains("sk-"))
        })
        .count()
}

fn inspect_passwd_and_ssh_keys(
    etc_root: &Path,
    home_root: &Path,
    root_ssh_dir: &Path,
) -> (usize, usize, Vec<String>, bool) {
    let mut user_accounts = 0usize;
    let mut non_root_uid0 = Vec::new();
    let passwd_ok = match fs::read_to_string(etc_root.join("passwd")) {
        Ok(raw) => {
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let cols: Vec<&str> = trimmed.split(':').collect();
                if cols.len() >= 7 {
                    user_accounts += 1;
                    if cols[2].trim() == "0" && cols[0].trim() != "root" {
                        non_root_uid0.push(cols[0].trim().to_string());
                    }
                }
            }
            true
        }
        Err(_) => false,
    };

    let mut ssh_keys = count_ssh_keys_in_file(&root_ssh_dir.join("authorized_keys"));
    if let Ok(entries) = fs::read_dir(home_root) {
        for entry in entries.filter_map(Result::ok) {
            let auth_path = entry.path().join(".ssh/authorized_keys");
            ssh_keys += count_ssh_keys_in_file(&auth_path);
        }
    }
    (user_accounts, ssh_keys, non_root_uid0, passwd_ok)
}

fn inspect_sshd_config_files(etc_root: &Path, indicators: &mut Vec<SecurityIndicatorItem>) -> usize {
    let mut checked = 0usize;
    let mut paths = Vec::new();
    let main_cfg = etc_root.join("ssh/sshd_config");
    if main_cfg.is_file() {
        paths.push(main_cfg);
    }
    let dropin_dir = etc_root.join("ssh/sshd_config.d");
    if let Ok(entries) = fs::read_dir(&dropin_dir) {
        let mut extra: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("conf") && p.is_file())
            .collect();
        extra.sort();
        paths.extend(extra);
    }

    let mut empty_pw_files = Vec::new();
    let mut pass_auth_files = Vec::new();
    for path in paths {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        let path_str = path.to_string_lossy().into_owned();
        for line in raw.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            if clean.is_empty() {
                continue;
            }
            let parts: Vec<&str> = clean.split_whitespace().collect();
            if parts.len() >= 2 {
                let key = parts[0].to_ascii_lowercase();
                let val = parts[1].to_ascii_lowercase();
                if key == "permitemptypasswords" && val == "yes" {
                    empty_pw_files.push(path_str.clone());
                } else if key == "passwordauthentication" && val == "yes" {
                    pass_auth_files.push(path_str.clone());
                }
            }
        }
    }

    if !empty_pw_files.is_empty() {
        indicators.push(SecurityIndicatorItem {
            rule: "ssh-empty-passwords".to_string(),
            component: "SSH 配置".to_string(),
            severity: "critical".to_string(),
            title: "SSHD 允许空密码登录 (PermitEmptyPasswords yes)".to_string(),
            guidance: "立即将 PermitEmptyPasswords 改为 no 并重载 sshd。".to_string(),
            evidence: empty_pw_files,
        });
    }
    if !pass_auth_files.is_empty() {
        indicators.push(SecurityIndicatorItem {
            rule: "ssh-password-auth".to_string(),
            component: "SSH 配置".to_string(),
            severity: "warning".to_string(),
            title: "SSHD 启用了密码认证 (PasswordAuthentication yes)".to_string(),
            guidance: "如已配置公钥认证，建议禁用 PasswordAuthentication 以降低暴力破解风险。".to_string(),
            evidence: pass_auth_files,
        });
    }
    checked
}

fn count_installed_packages_from(dpkg_status: &Path, apk_db: &Path) -> usize {
    if let Ok(raw) = fs::read_to_string(dpkg_status) {
        return raw.lines().filter(|l| l.starts_with("Package:")).count();
    }
    if let Ok(raw) = fs::read_to_string(apk_db) {
        return raw.lines().filter(|l| l.starts_with("P:")).count();
    }
    0
}

fn scan_ssh_log_activity(var_log_root: &Path, offset: &mut u64) -> (&'static str, usize, usize) {
    let candidate = if var_log_root.join("auth.log").is_file() {
        Some(var_log_root.join("auth.log"))
    } else if var_log_root.join("secure").is_file() {
        Some(var_log_root.join("secure"))
    } else {
        None
    };
    let Some(path) = candidate else {
        return (
            if Path::new("/run/log/journal").exists() {
                "available"
            } else {
                "unavailable"
            },
            0,
            0,
        );
    };
    let Ok(bytes) = fs::read(&path) else {
        return ("unavailable", 0, 0);
    };
    let total_len = bytes.len() as u64;
    if *offset == 0 || *offset > total_len {
        *offset = total_len;
        let tail = if bytes.len() > 32768 {
            &bytes[bytes.len() - 32768..]
        } else {
            &bytes[..]
        };
        let text = String::from_utf8_lossy(tail);
        let ssh_lines = text.lines().filter(|l| l.contains("sshd")).count();
        return ("available", ssh_lines, 0);
    }
    let slice = &bytes[*offset as usize..];
    *offset = total_len;
    let text = String::from_utf8_lossy(slice);
    let mut ssh_lines = 0usize;
    let mut accepted = 0usize;
    for line in text.lines() {
        if line.contains("sshd") {
            ssh_lines += 1;
            if line.contains("Accepted ") {
                accepted += 1;
            }
        }
    }
    ("available", ssh_lines, accepted)
}

pub fn collect_host_audit_with_roots(
    timestamp: u64,
    geoip_available: bool,
    etc_root: &Path,
    home_root: &Path,
    root_ssh_dir: &Path,
    var_log_root: &Path,
    dpkg_status: &Path,
    apk_db: &Path,
    state: &mut HostAuditState,
) -> String {
    let force_rescan = state.rescan_requested_at > state.last_rescan_handled;
    if !state.cached_json.is_empty()
        && !force_rescan
        && timestamp.saturating_sub(state.last_audit_at) < AUDIT_INTERVAL_SECS
    {
        return state.cached_json.clone();
    }

    let ssh_only = is_agent_container();
    let scope = if ssh_only { "agent_container" } else { "host" };
    let (os_id, os_name, os_version) = parse_os_release(etc_root);
    let (user_accounts, ssh_key_count, non_root_uid0, passwd_ok) =
        inspect_passwd_and_ssh_keys(etc_root, home_root, root_ssh_dir);

    let mut indicators: Vec<SecurityIndicatorItem> = Vec::new();
    if !non_root_uid0.is_empty() {
        indicators.push(SecurityIndicatorItem {
            rule: "non-root-uid0".to_string(),
            component: "系统账户".to_string(),
            severity: "critical".to_string(),
            title: "存在非 root 的 UID 0 特权账户".to_string(),
            guidance: "核实 /etc/passwd 中 UID 为 0 的账户来源，如未经授权立即锁定并审计。".to_string(),
            evidence: non_root_uid0,
        });
    }
    let config_files_checked = inspect_sshd_config_files(etc_root, &mut indicators);

    let critical_targets = [
        etc_root.join("passwd"),
        etc_root.join("group"),
        etc_root.join("sudoers"),
        etc_root.join("ssh/sshd_config"),
        etc_root.join("hosts"),
    ];
    let first_baseline = state.baseline_at == 0;
    let mut new_hashes = BTreeMap::new();
    let mut events: Vec<AuditEventItem> = Vec::new();
    for target in &critical_targets {
        if let Ok(bytes) = fs::read(target) {
            let key = target.to_string_lossy().into_owned();
            let digest = sha256_hex(&bytes);
            if !first_baseline {
                if let Some(prev) = state.file_hashes.get(&key) {
                    if prev != &digest {
                        events.push(AuditEventItem {
                            event_type: "host_config_changed".to_string(),
                            alert_key: format!("cfg-change:{}", &digest[..12]),
                            severity: "warning".to_string(),
                            title: format!("关键配置文件发生变更：{}", key),
                            message: format!("文件 {} 的 SHA-256 基线摘要发生变化，请核对是否为你授权的运维变更。", key),
                            component: "关键文件完整性".to_string(),
                            evidence: vec![key.clone()],
                        });
                    }
                }
            }
            new_hashes.insert(key, digest);
        }
    }
    let snapshot_files = new_hashes.len();
    if first_baseline && snapshot_files > 0 {
        state.baseline_at = timestamp;
    }
    state.file_hashes = new_hashes;

    let (ssh_log_status, ssh_events_last_period, new_ssh_login_events) =
        scan_ssh_log_activity(var_log_root, &mut state.ssh_log_offset);

    let packages_checked = if ssh_only {
        0
    } else {
        count_installed_packages_from(dpkg_status, apk_db)
    };

    let snapshot_status = if passwd_ok && snapshot_files > 0 {
        "ready"
    } else if passwd_ok || snapshot_files > 0 {
        "partial"
    } else {
        "unavailable"
    };
    let indicator_coverage = if config_files_checked > 0 && passwd_ok {
        "complete"
    } else {
        "partial"
    };
    let vuln_coverage = if ssh_only { "not_applicable" } else { "partial" };
    let vuln_status = if ssh_only { "not_applicable" } else { "skipped" };

    let critical_indicators = indicators
        .iter()
        .filter(|i| i.severity == "critical")
        .count();

    for (idx, ind) in indicators.iter().enumerate() {
        events.push(AuditEventItem {
            event_type: "host_security_finding".to_string(),
            alert_key: format!("indicator:{}:{}", ind.rule, idx),
            severity: ind.severity.clone(),
            title: ind.title.clone(),
            message: format!("{}：{}。{}", ind.component, ind.title, ind.guidance),
            component: ind.component.clone(),
            evidence: ind.evidence.clone(),
        });
    }

    let serialize_vec_str = |items: &[String]| -> String {
        let joined: Vec<String> = items
            .iter()
            .take(5)
            .map(|s| format!("\"{}\"", json_escape(s)))
            .collect();
        format!("[{}]", joined.join(","))
    };

    let events_json: Vec<String> = events
        .iter()
        .take(40)
        .map(|ev| {
            format!(
                "{{\"type\":\"{}\",\"alert_key\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"value\":1,\"threshold\":0,\"component\":\"{}\",\"evidence\":{}}}",
                json_escape(&ev.event_type),
                json_escape(&ev.alert_key),
                json_escape(&ev.severity),
                json_escape(&ev.title),
                json_escape(&ev.message),
                json_escape(&ev.component),
                serialize_vec_str(&ev.evidence),
            )
        })
        .collect();

    let indicators_json: Vec<String> = indicators
        .iter()
        .take(40)
        .map(|ind| {
            format!(
                "{{\"rule\":\"{}\",\"component\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\",\"guidance\":\"{}\",\"evidence\":{},\"instance_count\":1}}",
                json_escape(&ind.rule),
                json_escape(&ind.component),
                json_escape(&ind.severity),
                json_escape(&ind.title),
                json_escape(&ind.guidance),
                serialize_vec_str(&ind.evidence),
            )
        })
        .collect();

    let json = format!(
        "{{\"enabled\":true,\"scope\":\"{}\",\"os\":{{\"id\":\"{}\",\"name\":\"{}\",\"version_id\":\"{}\"}},\"rescan_requested_at\":{},\"snapshot_status\":\"{}\",\"snapshot_at\":{},\"baseline_at\":{},\"baseline_pending\":{},\"snapshot_files\":{},\"user_accounts\":{},\"ssh_key_count\":{},\"ssh_log_status\":\"{}\",\"ssh_events_last_period\":{},\"new_ssh_login_events\":{},\"country_lookup\":\"{}\",\"vulnerability_scan\":{{\"status\":\"{}\",\"coverage\":\"{}\",\"checked_at\":{},\"last_attempt_at\":{},\"packages_checked\":{},\"finding_count\":0,\"critical_count\":0,\"error\":\"rust_native_offline_no_osv_query\"}},\"security_indicator_scan\":{{\"status\":\"ready\",\"coverage\":\"{}\",\"checked_at\":{},\"last_attempt_at\":{},\"finding_count\":{},\"critical_count\":{},\"python_site_roots\":0,\"python_packages_checked\":0,\"config_files_checked\":{},\"ca_certificates_checked\":0,\"runtime_inventory\":{{\"engines\":[],\"images_checked\":0,\"status\":\"not_applicable\"}},\"error\":null}},\"recent_events\":[{}],\"recent_findings\":[],\"recent_indicators\":[{}]}}",
        scope,
        json_escape(&os_id),
        json_escape(&os_name),
        json_escape(&os_version),
        state.rescan_requested_at,
        snapshot_status,
        timestamp,
        state.baseline_at,
        first_baseline,
        snapshot_files,
        user_accounts,
        ssh_key_count,
        ssh_log_status,
        ssh_events_last_period,
        new_ssh_login_events,
        if geoip_available { "local_mmdb" } else { "unavailable" },
        vuln_status,
        vuln_coverage,
        timestamp,
        timestamp,
        packages_checked,
        indicator_coverage,
        timestamp,
        timestamp,
        indicators.len(),
        critical_indicators,
        config_files_checked,
        events_json.join(","),
        indicators_json.join(","),
    );

    state.last_audit_at = timestamp;
    state.last_rescan_handled = state.rescan_requested_at;
    state.cached_json = json.clone();
    json
}

pub fn collect_host_audit_json(
    timestamp: u64,
    geoip_available: bool,
    state: &mut HostAuditState,
) -> String {
    collect_host_audit_with_roots(
        timestamp,
        geoip_available,
        Path::new("/etc"),
        Path::new("/home"),
        Path::new("/root/.ssh"),
        Path::new("/var/log"),
        Path::new("/var/lib/dpkg/status"),
        Path::new("/lib/apk/db/installed"),
        state,
    )
}

fn valid_iface_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-'))
}

fn default_route_interfaces_from(proc_root: &Path) -> BTreeSet<String> {
    let mut devs = BTreeSet::new();
    if let Ok(raw) = fs::read_to_string(proc_root.join("net/route")) {
        for line in raw.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 8 && fields[1] == "00000000" && fields[7] == "00000000" {
                devs.insert(fields[0].to_string());
            }
        }
    }
    if let Ok(raw) = fs::read_to_string(proc_root.join("net/ipv6_route")) {
        let zero32 = "0".repeat(32);
        for line in raw.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10 && fields[0] == zero32 && fields[1] == "00" {
                devs.insert(fields[9].to_string());
            }
        }
    }
    devs
}

fn detect_runtime_bridges(containers: &[ContainerSample]) -> HashMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let mut map: HashMap<String, (BTreeSet<String>, BTreeSet<String>)> = HashMap::new();
    if Path::new("/run/narwhal-agent/connlimit.sock").exists()
        || containers.iter().any(|c| c.runtime.eq_ignore_ascii_case("runman"))
    {
        for br in ["runman-br0", "br-runman"] {
            if Path::new(&format!("/sys/class/net/{br}")).exists() {
                let entry = map.entry(br.to_string()).or_default();
                entry.0.insert("runman".to_string());
                entry.1.insert("default".to_string());
            }
        }
    }
    if Path::new("/sys/class/net/incusbr0").exists() {
        let entry = map.entry("incusbr0".to_string()).or_default();
        entry.0.insert("incus".to_string());
        entry.1.insert("incusbr0".to_string());
    }
    if Path::new("/sys/class/net/podman0").exists() {
        let entry = map.entry("podman0".to_string()).or_default();
        entry.0.insert("podman".to_string());
        entry.1.insert("podman".to_string());
    }
    map
}

fn collect_ip_addr_json_fallback() -> Option<JsonValue> {
    #[cfg(unix)]
    {
        let out = Command::new("ip").args(["-j", "address", "show"]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        parse_json(&text).ok()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

pub fn collect_interface_inventory_json(timestamp: u64, containers: &[ContainerSample]) -> String {
    let default_routes = default_route_interfaces_from(Path::new("/proc"));
    let runtime_bridges = detect_runtime_bridges(containers);

    if let Some(parsed_links) = collect_ip_addr_json_fallback() {
        if let Some(items) = parsed_links.as_array() {
            let mut iface_jsons = Vec::new();
            for link in items.iter().take(64) {
                let Some(name) = link.get("ifname").and_then(|v| v.as_str()) else {
                    continue;
                };
                if !valid_iface_name(name) {
                    continue;
                }
                let operstate = link
                    .get("operstate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_ascii_lowercase();
                let mtu_json = link
                    .get("mtu")
                    .and_then(|v| v.as_u64())
                    .filter(|&m| (1..=65535).contains(&m))
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "null".to_string());
                let raw_kind = link
                    .get("linkinfo")
                    .and_then(|v| v.get("info_kind"))
                    .and_then(|v| v.as_str())
                    .or_else(|| link.get("link_type").and_then(|v| v.as_str()))
                    .unwrap_or("unknown");
                let mut addrs = Vec::new();
                if let Some(addr_info) = link.get("addr_info").and_then(|v| v.as_array()) {
                    for info in addr_info.iter().take(16) {
                        if let Some(local) = info.get("local").and_then(|v| v.as_str()) {
                            let prefix = info.get("prefixlen").and_then(|v| v.as_u64());
                            let cidr = match prefix {
                                Some(p) => format!("{local}/{p}"),
                                None => local.to_string(),
                            };
                            addrs.push(format!("\"{}\"", json_escape(&cidr)));
                        }
                    }
                }
                let (rts, nets) = runtime_bridges
                    .get(name)
                    .map(|(r, n)| {
                        (
                            r.iter()
                                .map(|s| format!("\"{}\"", json_escape(s)))
                                .collect::<Vec<_>>(),
                            n.iter()
                                .map(|s| format!("\"{}\"", json_escape(s)))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .unwrap_or_default();
                let is_default = default_routes.contains(name);
                let kind = if !rts.is_empty() { "bridge" } else { raw_kind };
                iface_jsons.push(format!(
                    "{{\"name\":\"{}\",\"kind\":\"{}\",\"kernel_kind\":\"{}\",\"state\":\"{}\",\"mtu\":{},\"addresses\":[{}],\"is_default_route\":{},\"runtimes\":[{}],\"network_names\":[{}]}}",
                    json_escape(name),
                    json_escape(kind),
                    json_escape(raw_kind),
                    json_escape(&operstate),
                    mtu_json,
                    addrs.join(","),
                    is_default,
                    rts.join(","),
                    nets.join(","),
                ));
            }
            return format!(
                "{{\"status\":\"ready\",\"observed_at\":{},\"interfaces\":[{}]}}",
                timestamp,
                iface_jsons.join(",")
            );
        }
    }

    // Pure sysfs fallback when `ip -j` is absent (or on non-Linux tests)
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        let mut iface_jsons = Vec::new();
        for entry in entries.filter_map(Result::ok).take(64) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !valid_iface_name(&name) {
                continue;
            }
            let base = entry.path();
            let state = fs::read_to_string(base.join("operstate"))
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_ascii_lowercase();
            let mtu_json = fs::read_to_string(base.join("mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .filter(|&m| (1..=65535).contains(&m))
                .map(|m| m.to_string())
                .unwrap_or_else(|| "null".to_string());
            let is_bridge = base.join("bridge").is_dir();
            let raw_kind = if name == "lo" {
                "loopback"
            } else if is_bridge {
                "bridge"
            } else {
                "ether"
            };
            let is_default = default_routes.contains(&name);
            let (rts, nets) = runtime_bridges
                .get(&name)
                .map(|(r, n)| {
                    (
                        r.iter()
                            .map(|s| format!("\"{}\"", json_escape(s)))
                            .collect::<Vec<_>>(),
                        n.iter()
                            .map(|s| format!("\"{}\"", json_escape(s)))
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default();
            iface_jsons.push(format!(
                "{{\"name\":\"{}\",\"kind\":\"{}\",\"kernel_kind\":\"{}\",\"state\":\"{}\",\"mtu\":{},\"addresses\":[],\"is_default_route\":{},\"runtimes\":[{}],\"network_names\":[{}]}}",
                json_escape(&name),
                if !rts.is_empty() { "bridge" } else { raw_kind },
                raw_kind,
                json_escape(&state),
                mtu_json,
                is_default,
                rts.join(","),
                nets.join(","),
            ));
        }
        if !iface_jsons.is_empty() {
            return format!(
                "{{\"status\":\"ready\",\"observed_at\":{},\"interfaces\":[{}]}}",
                timestamp,
                iface_jsons.join(",")
            );
        }
    }

    format!("{{\"status\":\"unavailable\",\"observed_at\":{},\"interfaces\":[]}}", timestamp)
}

pub fn collect_host_firewall_full_json(
    timestamp: u64,
    containers: &[ContainerSample],
    state: &mut HostAuditState,
) -> String {
    let (available, backend) =
        if Path::new("/usr/sbin/nft").exists() || Path::new("/sbin/nft").exists() {
            (true, "nftables")
        } else if Path::new("/usr/sbin/iptables").exists()
            || Path::new("/sbin/iptables").exists()
            || Path::new("/proc/net/ip_tables_names").exists()
        {
            (true, "iptables")
        } else {
            (false, "none")
        };
    let inventory_json = collect_interface_inventory_json(timestamp, containers);

    let (readback_json, events_field) = if Path::new(RUNMAN_FIREWALL_SOCK).exists() {
        let rb = match runman_request(RUNMAN_FIREWALL_SOCK, "GET", "/v1/firewall/policy", None) {
            Ok((200, body)) => {
                let text = String::from_utf8_lossy(&body);
                let trimmed = text.trim();
                if trimmed.starts_with('{') && parse_json(trimmed).is_ok() {
                    format!(
                        "{{\"status\":\"ready\",\"observed_at\":{},\"snapshot\":{},\"reason\":\"\"}}",
                        timestamp, trimmed
                    )
                } else {
                    format!(
                        "{{\"status\":\"unavailable\",\"observed_at\":{},\"snapshot\":null,\"reason\":\"invalid_json\"}}",
                        timestamp
                    )
                }
            }
            Ok((404, _)) => format!(
                "{{\"status\":\"unavailable\",\"observed_at\":{},\"snapshot\":null,\"reason\":\"readback_endpoint_missing\"}}",
                timestamp
            ),
            Ok(_) => format!(
                "{{\"status\":\"unavailable\",\"observed_at\":{},\"snapshot\":null,\"reason\":\"readback_http_error\"}}",
                timestamp
            ),
            Err(_) => format!(
                "{{\"status\":\"unavailable\",\"observed_at\":{},\"snapshot\":null,\"reason\":\"socket_error\"}}",
                timestamp
            ),
        };
        let cursor = state.firewall_event_cursor.as_str();
        let ev_path = format!("/v1/firewall/events?cursor={cursor}&limit=100");
        let ev = match runman_request(RUNMAN_FIREWALL_SOCK, "GET", &ev_path, None) {
            Ok((200, body)) => {
                let text = String::from_utf8_lossy(&body);
                if let Ok(parsed) = parse_json(text.trim()) {
                    if let Some(next_c) = parsed.get("next_cursor").and_then(JsonValue::as_str) {
                        if next_c.len() <= 160 {
                            state.firewall_event_cursor = next_c.to_string();
                        }
                    }
                    let events_arr = parsed
                        .get("events")
                        .map(JsonValue::to_json)
                        .unwrap_or_else(|| "[]".to_string());
                    let dropped = parsed.get("dropped").and_then(JsonValue::as_u64).unwrap_or(0);
                    let dropped_total = parsed
                        .get("dropped_total")
                        .and_then(JsonValue::as_u64)
                        .unwrap_or(0);
                    format!(
                        ",\"events_api\":\"ready\",\"next_cursor\":\"{}\",\"dropped\":{},\"dropped_total\":{},\"events\":{}",
                        json_escape(&state.firewall_event_cursor),
                        dropped,
                        dropped_total,
                        events_arr
                    )
                } else {
                    ",\"events_api\":\"unavailable\",\"events\":[]".to_string()
                }
            }
            Ok((404, _)) => ",\"events_api\":\"unsupported\",\"events\":[]".to_string(),
            _ => ",\"events_api\":\"unavailable\",\"events\":[]".to_string(),
        };
        (rb, ev)
    } else {
        (
            format!(
                "{{\"status\":\"unavailable\",\"observed_at\":{},\"snapshot\":null,\"reason\":\"{}\"}}",
                timestamp,
                if cfg!(unix) { "socket_missing" } else { "platform_unsupported" }
            ),
            format!(
                ",\"events_api\":\"{}\",\"events\":[]",
                if cfg!(unix) { "unavailable" } else { "unsupported" }
            ),
        )
    };

    format!(
        "{{\"available\":{},\"backend\":\"{}\",\"interface_inventory\":{},\"readback\":{}{}}}",
        available,
        backend,
        inventory_json,
        readback_json,
        events_field
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_audit_indicators_and_baseline_change_detection() {
        let dir = std::env::temp_dir().join("narwhal-host-audit-test");
        let _ = fs::remove_dir_all(&dir);
        let etc = dir.join("etc");
        let home = dir.join("home");
        let root_ssh = dir.join("root/.ssh");
        let var_log = dir.join("var/log");
        fs::create_dir_all(etc.join("ssh/sshd_config.d")).unwrap();
        fs::create_dir_all(&root_ssh).unwrap();
        fs::create_dir_all(home.join("alice/.ssh")).unwrap();
        fs::create_dir_all(&var_log).unwrap();

        fs::write(etc.join("os-release"), "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\nVERSION_ID=\"12\"\n").unwrap();
        fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/tmp:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .unwrap();
        fs::write(etc.join("group"), "root:x:0:\n").unwrap();
        fs::write(etc.join("hosts"), "127.0.0.1 localhost\n").unwrap();
        fs::write(
            etc.join("ssh/sshd_config"),
            "PermitEmptyPasswords yes\nPasswordAuthentication yes\n",
        )
        .unwrap();
        fs::write(root_ssh.join("authorized_keys"), "ssh-ed25519 AAAAC3Nza root@test\n").unwrap();
        fs::write(home.join("alice/.ssh/authorized_keys"), "ssh-rsa AAAAB3Nza alice@test\n").unwrap();
        fs::write(var_log.join("auth.log"), "Nov 16 12:00:00 host sshd[1]: Accepted publickey for root\n").unwrap();
        let dpkg = dir.join("dpkg-status");
        fs::write(&dpkg, "Package: bash\nStatus: install ok installed\n\nPackage: curl\nStatus: install ok installed\n").unwrap();
        let apk = dir.join("apk-installed");

        let mut state = HostAuditState::default();
        let json1 = collect_host_audit_with_roots(
            1_700_000_000,
            true,
            &etc,
            &home,
            &root_ssh,
            &var_log,
            &dpkg,
            &apk,
            &mut state,
        );
        assert!(json1.contains("\"enabled\":true"));
        assert!(json1.contains("\"id\":\"debian\""));
        assert!(json1.contains("\"user_accounts\":3"));
        assert!(json1.contains("\"ssh_key_count\":2"));
        assert!(json1.contains("\"packages_checked\":2"));
        assert!(json1.contains("ssh-empty-passwords"));
        assert!(json1.contains("non-root-uid0"));
        assert!(json1.contains("\"baseline_pending\":true"));

        // Cached within 300s unless rescan requested; mutate hosts and force rescan
        fs::write(etc.join("hosts"), "127.0.0.1 localhost\n10.0.0.5 added\n").unwrap();
        state.rescan_requested_at = 1_700_000_010;
        let json2 = collect_host_audit_with_roots(
            1_700_000_015,
            true,
            &etc,
            &home,
            &root_ssh,
            &var_log,
            &dpkg,
            &apk,
            &mut state,
        );
        assert!(json2.contains("\"baseline_pending\":false"));
        assert!(json2.contains("host_config_changed"));

        let _ = fs::remove_dir_all(&dir);
    }
}
