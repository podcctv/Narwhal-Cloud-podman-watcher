#![forbid(unsafe_code)]

//! Pure-Rust, `std`-only container service configuration auditor.
//!
//! Security & privacy boundaries:
//! - Only inspects configuration files actively referenced by running processes
//!   (via `/proc/<pid>/cmdline` + `/proc/<pid>/root` or bounded test root).
//! - Rejects symlinks escaping the container root and caps reads at 256 KiB.
//! - Extracts only sanitized metadata (`engine`, `protocol`, `port`, `sni`,
//!   `auth_configured`); never exports UUIDs, passwords, keys, or raw config text.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use admission_guard::sni::{is_allowed_sni_with_override, normalize_sni};
use proc_probe::json_escape;
use runtime_drivers::JsonVal;

const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_SNIS_PER_INBOUND: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInboundSummary {
    pub protocol: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub sni_list: Vec<String>,
    pub auth_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfigSummary {
    pub engine: String,
    pub pid: u32,
    pub inbounds: Vec<ServiceInboundSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceViolation {
    pub code: &'static str,
    pub severity: &'static str,
    pub engine: String,
    pub protocol: String,
    pub port: u16,
    pub sni: Option<String>,
    pub title: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerServiceAudit {
    pub services: Vec<ServiceConfigSummary>,
    pub violations: Vec<ServiceViolation>,
}

impl ContainerServiceAudit {
    pub fn to_json(&self) -> String {
        let mut svcs = String::from("[");
        for (i, s) in self.services.iter().enumerate() {
            if i > 0 {
                svcs.push(',');
            }
            let mut inbs = String::from("[");
            for (j, inb) in s.inbounds.iter().enumerate() {
                if j > 0 {
                    inbs.push(',');
                }
                let mut snis = String::from("[");
                for (k, sni) in inb.sni_list.iter().enumerate() {
                    if k > 0 {
                        snis.push(',');
                    }
                    let _ = write!(snis, "\"{}\"", json_escape(sni));
                }
                snis.push(']');
                let _ = write!(
                    inbs,
                    "{{\"protocol\":\"{}\",\"port\":{},\"tls_enabled\":{},\"sni_list\":{},\"auth_configured\":{}}}",
                    json_escape(&inb.protocol),
                    inb.port,
                    inb.tls_enabled,
                    snis,
                    inb.auth_configured
                );
            }
            inbs.push(']');
            let _ = write!(
                svcs,
                "{{\"engine\":\"{}\",\"pid\":{},\"inbounds\":{}}}",
                json_escape(&s.engine),
                s.pid,
                inbs
            );
        }
        svcs.push(']');
        format!(
            "{{\"services\":{},\"violations_count\":{}}}",
            svcs,
            self.violations.len()
        )
    }

    pub fn alerts_to_json_items(
        &self,
        runtime: &str,
        project: &str,
        container_name: &str,
        instance_id: &str,
    ) -> Vec<String> {
        self.violations
            .iter()
            .map(|v| {
                let sni_field = v
                    .sni
                    .as_deref()
                    .map(|s| format!(",\"sni\":\"{}\"", json_escape(s)))
                    .unwrap_or_default();
                format!(
                    "{{\"type\":\"{}\",\"runtime\":\"{}\",\"project\":\"{}\",\"container_name\":\"{}\",\"instance_id\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\",\"message\":\"{}\",\"engine\":\"{}\",\"protocol\":\"{}\",\"dst_port\":{}{}}}",
                    json_escape(v.code),
                    json_escape(runtime),
                    json_escape(project),
                    json_escape(container_name),
                    json_escape(instance_id),
                    json_escape(v.severity),
                    json_escape(&v.title),
                    json_escape(&v.message),
                    json_escape(&v.engine),
                    json_escape(&v.protocol),
                    v.port,
                    sni_field
                )
            })
            .collect()
    }
}

pub fn detect_engine_from_cmd(comm: &str, argv: &[String]) -> Option<&'static str> {
    let bin = argv
        .first()
        .and_then(|s| Path::new(s).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or(comm)
        .to_ascii_lowercase();
    let comm_l = comm.to_ascii_lowercase();
    for cand in [bin.as_str(), comm_l.as_str()] {
        if cand.contains("sing-box") {
            return Some("sing-box");
        }
        if cand == "xray" || cand.starts_with("xray-") {
            return Some("xray");
        }
        if cand == "v2ray" || cand.starts_with("v2ray-") {
            return Some("v2ray");
        }
        if cand.contains("hysteria") {
            return Some("hysteria2");
        }
        if cand.contains("tuic") {
            return Some("tuic");
        }
        if cand == "gost" || cand.starts_with("gost-") {
            return Some("gost");
        }
        if cand.contains("mihomo") || cand == "clash" || cand.starts_with("clash-") {
            return Some("mihomo");
        }
        if cand == "frps" || cand == "frpc" {
            return Some(if cand == "frps" { "frps" } else { "frpc" });
        }
        if cand.contains("3x-ui") || cand == "x-ui" || cand.contains("marzban") {
            return Some("proxy-panel");
        }
    }
    None
}

pub fn extract_config_path_from_argv(engine: &str, argv: &[String]) -> Option<String> {
    let mut i = 1usize;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if matches!(arg, "-c" | "--config" | "-config" | "-conf" | "-C" | "-confdir" | "-D" | "-db" | "--db") {
            if let Some(next) = argv.get(i + 1) {
                if !next.is_empty() && !next.starts_with('-') {
                    return Some(next.clone());
                }
            }
        } else if let Some(rest) = arg
            .strip_prefix("--config=")
            .or_else(|| arg.strip_prefix("-config="))
            .or_else(|| arg.strip_prefix("-confdir="))
            .or_else(|| arg.strip_prefix("-c="))
        {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
        i += 1;
    }
    match engine {
        "sing-box" => Some("/etc/sing-box/config.json".to_string()),
        "xray" => Some("/etc/xray/config.json".to_string()),
        "v2ray" => Some("/etc/v2ray/config.json".to_string()),
        "hysteria2" => Some("/etc/hysteria/config.yaml".to_string()),
        "proxy-panel" => Some("/etc/x-ui/x-ui.db".to_string()),
        _ => None,
    }
}

fn resolve_contained_path(container_root: &Path, cwd: &str, raw_cfg: &str) -> Option<PathBuf> {
    let rel = if raw_cfg.starts_with('/') {
        PathBuf::from(raw_cfg)
    } else if !cwd.is_empty() {
        Path::new(cwd).join(raw_cfg)
    } else {
        return None;
    };
    let mut clean = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            Component::Normal(p) => clean.push(p),
            Component::Prefix(_) => return None,
        }
    }
    let candidate = container_root.join(clean);
    let canon_root = fs::canonicalize(container_root).ok()?;
    let canon_target = fs::canonicalize(&candidate).ok()?;
    if !canon_target.starts_with(&canon_root) {
        return None;
    }
    Some(canon_target)
}

fn read_bounded_bytes(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_CONFIG_BYTES));
    f.by_ref()
        .take(MAX_CONFIG_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn read_bounded_utf8(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > MAX_CONFIG_BYTES as u64 {
        return None;
    }
    let mut f = File::open(path).ok()?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_CONFIG_BYTES));
    f.by_ref()
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > MAX_CONFIG_BYTES {
        return None;
    }
    String::from_utf8(buf).ok()
}

fn push_unique_sni(out: &mut Vec<String>, seen: &mut BTreeSet<String>, raw: &str) {
    if out.len() >= MAX_SNIS_PER_INBOUND {
        return;
    }
    if let Some(norm) = normalize_sni(raw) {
        if seen.insert(norm.clone()) {
            out.push(norm);
        }
    }
}

fn parse_port_val(v: Option<&JsonVal>) -> u16 {
    let Some(val) = v else {
        return 0;
    };
    if let Some(n) = val.as_u64() {
        return u16::try_from(n).unwrap_or(0);
    }
    if let Some(s) = val.as_str() {
        if let Ok(p) = s.trim().parse::<u16>() {
            return p;
        }
    }
    0
}

fn extract_snis_from_json_tls(tls: &JsonVal) -> (bool, Vec<String>) {
    let enabled = tls.get("enabled").and_then(JsonVal::as_bool).unwrap_or(true);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for key in ["server_name", "serverName", "sni"] {
        if let Some(s) = tls.get(key).and_then(JsonVal::as_str) {
            push_unique_sni(&mut out, &mut seen, s);
        }
    }
    for key in ["server_names", "serverNames"] {
        if let Some(arr) = tls.get(key).and_then(JsonVal::as_arr) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    push_unique_sni(&mut out, &mut seen, s);
                }
            }
        }
    }
    if let Some(reality) = tls.get("reality").or_else(|| tls.get("realitySettings")) {
        if let Some(hs) = reality.get("handshake") {
            if let Some(s) = hs.get("server").and_then(JsonVal::as_str) {
                push_unique_sni(&mut out, &mut seen, s);
            }
        }
        if let Some(s) = reality.get("server_name").and_then(JsonVal::as_str) {
            push_unique_sni(&mut out, &mut seen, s);
        }
        if let Some(arr) = reality.get("serverNames").and_then(JsonVal::as_arr) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    push_unique_sni(&mut out, &mut seen, s);
                }
            }
        }
    }
    (enabled || !out.is_empty(), out)
}

pub fn parse_json_service_inbounds(engine: &str, raw: &str) -> Vec<ServiceInboundSummary> {
    let Ok(root) = JsonVal::parse(raw.trim()) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    if engine == "tuic" {
        let port = root
            .get("server")
            .and_then(JsonVal::as_str)
            .and_then(|s| s.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);
        let auth_ok = root
            .get("users")
            .and_then(JsonVal::as_obj)
            .is_some_and(|u| !u.is_empty());
        out.push(ServiceInboundSummary {
            protocol: "tuic".to_string(),
            port,
            tls_enabled: true,
            sni_list: Vec::new(),
            auth_configured: auth_ok,
        });
        return out;
    }

    let Some(inbounds) = root.get("inbounds").and_then(JsonVal::as_arr) else {
        return out;
    };

    for inb in inbounds.iter().take(64) {
        let proto = inb
            .get("type")
            .or_else(|| inb.get("protocol"))
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if proto.is_empty() {
            continue;
        }
        let port = parse_port_val(inb.get("listen_port").or_else(|| inb.get("port")));
        let mut tls_enabled = false;
        let mut sni_list = Vec::new();
        if let Some(tls) = inb.get("tls") {
            let (en, snis) = extract_snis_from_json_tls(tls);
            tls_enabled = en;
            sni_list = snis;
        } else if let Some(stream) = inb.get("streamSettings") {
            let sec = stream
                .get("security")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            if sec == "tls" || sec == "reality" {
                tls_enabled = true;
            }
            if let Some(ts) = stream
                .get("tlsSettings")
                .or_else(|| stream.get("realitySettings"))
            {
                let (en, snis) = extract_snis_from_json_tls(ts);
                tls_enabled = tls_enabled || en;
                sni_list = snis;
            }
        }

        let auth_configured = if matches!(proto.as_str(), "socks" | "http" | "mixed") {
            let has_users = inb
                .get("users")
                .and_then(JsonVal::as_arr)
                .is_some_and(|a| !a.is_empty());
            let has_accounts = inb
                .get("settings")
                .and_then(|s| s.get("accounts"))
                .and_then(JsonVal::as_arr)
                .is_some_and(|a| !a.is_empty());
            let auth_mode = inb
                .get("settings")
                .and_then(|s| s.get("auth"))
                .and_then(JsonVal::as_str)
                .unwrap_or("");
            has_users || has_accounts || auth_mode == "password"
        } else {
            true
        };

        out.push(ServiceInboundSummary {
            protocol: proto,
            port,
            tls_enabled,
            sni_list,
            auth_configured,
        });
    }
    out
}

pub fn parse_yaml_service_inbounds(engine: &str, raw: &str) -> Vec<ServiceInboundSummary> {
    let mut port = 0u16;
    let mut sni_list = Vec::new();
    let mut seen = BTreeSet::new();
    let mut tls_enabled = matches!(engine, "hysteria2" | "tuic");

    for line in raw.lines().take(512) {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if key == "listen" || key == "bindport" || key == "server_port" {
                if let Some(p_str) = val.rsplit(':').next() {
                    if let Ok(p) = p_str.trim().parse::<u16>() {
                        if port == 0 {
                            port = p;
                        }
                    }
                }
            } else if matches!(key.as_str(), "sni" | "server_name" | "servername") && !val.is_empty()
            {
                tls_enabled = true;
                push_unique_sni(&mut sni_list, &mut seen, val);
            }
        } else if let Some(item) = trimmed.strip_prefix("- ") {
            let val = item.trim().trim_matches(|c| c == '"' || c == '\'');
            if val.contains('.') && !val.contains(' ') && val.len() <= 253 {
                push_unique_sni(&mut sni_list, &mut seen, val);
            }
        }
    }

    vec![ServiceInboundSummary {
        protocol: engine.to_string(),
        port,
        tls_enabled,
        sni_list,
        auth_configured: true,
    }]
}

pub fn parse_toml_or_ini_service_inbounds(engine: &str, raw: &str) -> Vec<ServiceInboundSummary> {
    let mut port: u16 = 0;
    let mut protocol = engine.to_string();
    let mut tls_enabled = false;
    let mut sni_list = Vec::new();
    let mut seen_sni = BTreeSet::new();
    let mut auth_configured = false;

    for raw_line in raw.lines().take(512) {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('[') || line.starts_with(';') {
            continue;
        }
        let Some((k_raw, v_raw)) = line.split_once('=') else {
            continue;
        };
        let key = k_raw.trim().to_ascii_lowercase();
        let val = v_raw.trim().trim_matches('"').trim_matches('\'').trim();
        if val.is_empty() {
            continue;
        }
        if matches!(
            key.as_str(),
            "bindport" | "bind_port" | "serverport" | "server_port" | "port" | "listen_port"
        ) {
            if let Ok(p) = val.parse::<u16>() {
                port = p;
            }
        } else if key == "listen" {
            if let Some(p) = val
                .rsplit(':')
                .next()
                .and_then(|s| s.trim().parse::<u16>().ok())
            {
                port = p;
            }
        } else if matches!(key.as_str(), "type" | "protocol") {
            let lower = val.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "vmess" | "trojan" | "vless" | "socks" | "socks5" | "http" | "mixed" | "shadowsocks"
            ) {
                protocol = if lower == "socks5" {
                    "socks".to_string()
                } else {
                    lower
                };
            }
        } else if matches!(
            key.as_str(),
            "sni" | "servername" | "server_name" | "custom_domains"
        ) {
            for part in val.split(',') {
                push_unique_sni(&mut sni_list, &mut seen_sni, part.trim());
            }
            if !sni_list.is_empty() {
                tls_enabled = true;
            }
        } else if matches!(
            key.as_str(),
            "auth.token" | "token" | "password" | "auth_password" | "user" | "username"
        ) {
            auth_configured = true;
        } else if key == "tls" && val.eq_ignore_ascii_case("true") {
            tls_enabled = true;
        }
    }

    let is_open_proto = matches!(protocol.as_str(), "socks" | "http" | "mixed");
    vec![ServiceInboundSummary {
        protocol,
        port,
        tls_enabled,
        sni_list,
        auth_configured: auth_configured || !is_open_proto,
    }]
}

pub fn parse_panel_db_inbounds(raw: &[u8]) -> Vec<ServiceInboundSummary> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut seen_snis = BTreeSet::new();
    let mut sni_list = Vec::new();
    let mut tls_enabled = false;

    for key in ["\"serverName\"", "\"server_name\"", "\"sni\""] {
        let mut rest = text.as_ref();
        while let Some(pos) = rest.find(key) {
            let after_key = &rest[pos + key.len()..];
            if let Some(colon) = after_key.find(':') {
                let after_colon = after_key[colon + 1..].trim_start();
                if let Some(stripped) = after_colon.strip_prefix('"') {
                    if let Some(end_q) = stripped.find('"') {
                        push_unique_sni(&mut sni_list, &mut seen_snis, &stripped[..end_q]);
                        tls_enabled = true;
                    }
                }
            }
            rest = &rest[pos + key.len()..];
            if sni_list.len() >= MAX_SNIS_PER_INBOUND {
                break;
            }
        }
    }

    for arr_key in ["\"serverNames\"", "\"server_names\""] {
        let mut rest = text.as_ref();
        while let Some(pos) = rest.find(arr_key) {
            let after_key = &rest[pos + arr_key.len()..];
            if let Some(open_b) = after_key.find('[') {
                if let Some(close_b) = after_key[open_b + 1..].find(']') {
                    let inside = &after_key[open_b + 1..open_b + 1 + close_b];
                    for part in inside.split(',') {
                        let clean = part.trim().trim_matches('"').trim();
                        push_unique_sni(&mut sni_list, &mut seen_snis, clean);
                        if !clean.is_empty() {
                            tls_enabled = true;
                        }
                    }
                }
            }
            rest = &rest[pos + arr_key.len()..];
            if sni_list.len() >= MAX_SNIS_PER_INBOUND {
                break;
            }
        }
    }

    let mut found_protos = BTreeSet::new();
    for proto in ["vmess", "trojan", "vless", "shadowsocks", "socks", "http"] {
        let needle = format!("\"{proto}\"");
        if text.contains(&needle) || text.contains(proto) {
            if matches!(proto, "vmess" | "trojan") {
                found_protos.insert(proto.to_string());
            } else if text.contains(&needle) {
                found_protos.insert(proto.to_string());
            }
        }
    }

    if found_protos.is_empty() && !sni_list.is_empty() {
        found_protos.insert("vless".to_string());
    }

    for proto in found_protos.into_iter().take(16) {
        out.push(ServiceInboundSummary {
            protocol: proto,
            port: 0,
            tls_enabled,
            sni_list: sni_list.clone(),
            auth_configured: true,
        });
    }
    out
}

pub fn evaluate_service_violations(svc: &ServiceConfigSummary) -> Vec<ServiceViolation> {
    evaluate_service_violations_with_policy(svc, None, None)
}

pub fn evaluate_service_violations_with_policy(
    svc: &ServiceConfigSummary,
    allowed_snis: Option<&[String]>,
    disallowed_protocols: Option<&[String]>,
) -> Vec<ServiceViolation> {
    let mut out = Vec::new();
    if matches!(svc.engine.as_str(), "frps" | "frpc") {
        out.push(ServiceViolation {
            code: "service_tunnel_relay",
            severity: "warning",
            engine: svc.engine.clone(),
            protocol: svc.engine.clone(),
            port: svc.inbounds.first().map(|i| i.port).unwrap_or(0),
            sni: None,
            title: "检测到容器运行内网穿透服务".to_string(),
            message: format!(
                "检测到容器内运行 {}（PID {}）转发/穿透服务，请确认是否符合平台服务规范。",
                svc.engine, svc.pid
            ),
        });
    }

    for inb in &svc.inbounds {
        let proto_disallowed = match disallowed_protocols {
            Some(list) => list.iter().any(|p| p.eq_ignore_ascii_case(&inb.protocol)),
            None => matches!(inb.protocol.as_str(), "vmess" | "trojan"),
        };
        if proto_disallowed {
            out.push(ServiceViolation {
                code: "service_disallowed_protocol",
                severity: "warning",
                engine: svc.engine.clone(),
                protocol: inb.protocol.clone(),
                port: inb.port,
                sni: None,
                title: "容器配置了受限入站协议".to_string(),
                message: format!(
                    "检测到 {} 配置了 {} 入站协议（端口 {}），该协议已被平台策略限制，请更换为合规协议。",
                    svc.engine, inb.protocol, inb.port
                ),
            });
        }
        if matches!(inb.protocol.as_str(), "socks" | "http" | "mixed") && !inb.auth_configured {
            out.push(ServiceViolation {
                code: "service_open_proxy",
                severity: "warning",
                engine: svc.engine.clone(),
                protocol: inb.protocol.clone(),
                port: inb.port,
                sni: None,
                title: "容器配置了无认证开放代理".to_string(),
                message: format!(
                    "检测到 {} 在端口 {} 配置了未启用认证的 {} 代理，存在被匿名滥用风险，请立即配置强密码。",
                    svc.engine, inb.port, inb.protocol
                ),
            });
        }
        for sni in &inb.sni_list {
            if !is_allowed_sni_with_override(sni, allowed_snis) {
                out.push(ServiceViolation {
                    code: "service_disallowed_sni",
                    severity: "warning",
                    engine: svc.engine.clone(),
                    protocol: inb.protocol.clone(),
                    port: inb.port,
                    sni: Some(sni.clone()),
                    title: "容器服务配置了非白名单 SNI".to_string(),
                    message: format!(
                        "检测到 {}（{}/{}）配置的伪装域名 SNI（{}）不在平台白名单内，入站连接将被直接阻断，请尽快更换。",
                        svc.engine, inb.protocol, inb.port, sni
                    ),
                });
            }
        }
    }
    out
}

pub fn audit_container_services(
    proc_root: &Path,
    pids: &[u32],
    container_init_pid: Option<u32>,
) -> ContainerServiceAudit {
    audit_container_services_with_policy(proc_root, pids, container_init_pid, None, None)
}

pub fn audit_container_services_with_policy(
    proc_root: &Path,
    pids: &[u32],
    container_init_pid: Option<u32>,
    allowed_snis: Option<&[String]>,
    disallowed_protocols: Option<&[String]>,
) -> ContainerServiceAudit {
    let mut audit = ContainerServiceAudit::default();
    let Some(init_pid) = container_init_pid.filter(|&p| p > 0) else {
        return audit;
    };
    let root_dir = proc_root.join(init_pid.to_string()).join("root");

    for &pid in pids.iter().take(64) {
        let pdir = proc_root.join(pid.to_string());
        let Ok(comm_raw) = fs::read_to_string(pdir.join("comm")) else {
            continue;
        };
        let comm = comm_raw.trim();
        let Ok(cmd_bytes) = fs::read(pdir.join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = cmd_bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        let Some(engine) = detect_engine_from_cmd(comm, &argv) else {
            continue;
        };
        let cwd = fs::read_link(pdir.join("cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut inbounds = Vec::new();
        if let Some(cfg_path) = extract_config_path_from_argv(engine, &argv) {
            if let Some(safe_path) = resolve_contained_path(&root_dir, &cwd, &cfg_path) {
                if safe_path.is_dir() {
                    if let Ok(entries) = fs::read_dir(&safe_path) {
                        for entry in entries.flatten().take(16) {
                            let ep = entry.path();
                            let ext = ep.extension().and_then(|s| s.to_str()).unwrap_or("");
                            if !matches!(ext, "json" | "yaml" | "yml" | "toml" | "ini" | "conf") {
                                continue;
                            }
                            if let Some(raw_cfg) = read_bounded_utf8(&ep) {
                                if raw_cfg.trim_start().starts_with('{') {
                                    inbounds.extend(parse_json_service_inbounds(engine, &raw_cfg));
                                } else if matches!(ext, "toml" | "ini" | "conf") {
                                    inbounds.extend(parse_toml_or_ini_service_inbounds(engine, &raw_cfg));
                                } else {
                                    inbounds.extend(parse_yaml_service_inbounds(engine, &raw_cfg));
                                }
                            }
                        }
                    }
                } else {
                    let ext = safe_path.extension().and_then(|s| s.to_str()).unwrap_or("");
                    if matches!(ext, "db" | "sqlite" | "sqlite3") {
                        if let Some(raw_bytes) = read_bounded_bytes(&safe_path) {
                            inbounds = parse_panel_db_inbounds(&raw_bytes);
                        }
                    } else if let Some(raw_cfg) = read_bounded_utf8(&safe_path) {
                        if raw_cfg.trim_start().starts_with('{') {
                            inbounds = parse_json_service_inbounds(engine, &raw_cfg);
                        } else if matches!(ext, "toml" | "ini" | "conf") {
                            inbounds = parse_toml_or_ini_service_inbounds(engine, &raw_cfg);
                        } else {
                            inbounds = parse_yaml_service_inbounds(engine, &raw_cfg);
                        }
                    }
                }
            }
        }
        let svc = ServiceConfigSummary {
            engine: engine.to_string(),
            pid,
            inbounds,
        };
        let mut viols =
            evaluate_service_violations_with_policy(&svc, allowed_snis, disallowed_protocols);
        audit.violations.append(&mut viols);
        audit.services.push(svc);
    }
    audit
}

pub fn collect_pid_ns_map(proc_root: &Path) -> HashMap<String, Vec<u32>> {
    let mut map: HashMap<String, Vec<u32>> = HashMap::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        let Ok(pid) = s.parse::<u32>() else {
            continue;
        };
        if let Ok(ns) = fs::read_link(entry.path().join("ns").join("pid")) {
            map.entry(ns.to_string_lossy().into_owned())
                .or_default()
                .push(pid);
        }
    }
    map
}

pub fn audit_container_with_pid_ns(
    proc_root: &Path,
    pid_ns_map: &HashMap<String, Vec<u32>>,
    container_init_pid: Option<u32>,
) -> ContainerServiceAudit {
    audit_container_with_pid_ns_policy(proc_root, pid_ns_map, container_init_pid, None, None)
}

pub fn audit_container_with_pid_ns_policy(
    proc_root: &Path,
    pid_ns_map: &HashMap<String, Vec<u32>>,
    container_init_pid: Option<u32>,
    allowed_snis: Option<&[String]>,
    disallowed_protocols: Option<&[String]>,
) -> ContainerServiceAudit {
    let Some(init_pid) = container_init_pid.filter(|&p| p > 0) else {
        return ContainerServiceAudit::default();
    };
    let Ok(ns) = fs::read_link(proc_root.join(init_pid.to_string()).join("ns").join("pid")) else {
        return audit_container_services_with_policy(
            proc_root,
            &[init_pid],
            Some(init_pid),
            allowed_snis,
            disallowed_protocols,
        );
    };
    let ns_key = ns.to_string_lossy();
    let fallback = [init_pid];
    let pids = pid_ns_map
        .get(ns_key.as_ref())
        .map(Vec::as_slice)
        .unwrap_or(&fallback);
    audit_container_services_with_policy(
        proc_root,
        pids,
        Some(init_pid),
        allowed_snis,
        disallowed_protocols,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_service_audit_detects_disallowed_sni_vmess_and_open_socks() {
        let cfg = r#"{
            "inbounds": [
                {
                    "type": "vless",
                    "listen_port": 443,
                    "tls": {
                        "enabled": true,
                        "server_name": "www.apple.com",
                        "reality": { "enabled": true, "private_key": "SECRET_PRIV_KEY" }
                    }
                },
                {
                    "type": "vmess",
                    "listen_port": 10086,
                    "users": [{ "uuid": "SECRET-UUID-1234" }]
                },
                {
                    "type": "socks",
                    "listen_port": 1080
                },
                {
                    "type": "vless",
                    "listen_port": 8443,
                    "tls": {
                        "enabled": true,
                        "server_name": "crates.io"
                    }
                }
            ]
        }"#;
        let inbounds = parse_json_service_inbounds("sing-box", cfg);
        assert_eq!(inbounds.len(), 4);
        let svc = ServiceConfigSummary {
            engine: "sing-box".to_string(),
            pid: 123,
            inbounds,
        };
        let viols = evaluate_service_violations(&svc);
        let codes: Vec<&str> = viols.iter().map(|v| v.code).collect();
        assert_eq!(
            codes,
            vec![
                "service_disallowed_sni",
                "service_disallowed_protocol",
                "service_open_proxy"
            ]
        );
        let audit = ContainerServiceAudit {
            services: vec![svc],
            violations: viols,
        };
        let json = audit.to_json();
        assert!(!json.contains("SECRET_PRIV_KEY"));
        assert!(!json.contains("SECRET-UUID-1234"));
        assert!(json.contains("www.apple.com"));
        assert!(json.contains("crates.io"));
    }

    #[test]
    fn test_yaml_and_proc_root_containment_audit() {
        let base = std::env::temp_dir().join(format!("narwhal_svc_audit_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let proc_dir = base.join("proc");
        let p_init = proc_dir.join("100");
        let root_dir = p_init.join("root");
        let etc_hy = root_dir.join("etc").join("hysteria");
        fs::create_dir_all(&etc_hy).unwrap();
        fs::write(
            etc_hy.join("config.yaml"),
            "listen: :443\ntls:\n  sni: bad.example.org\n",
        )
        .unwrap();

        let p_hy = proc_dir.join("201");
        fs::create_dir_all(&p_hy).unwrap();
        fs::write(p_hy.join("comm"), "hysteria\n").unwrap();
        fs::write(
            p_hy.join("cmdline"),
            b"/usr/local/bin/hysteria\0server\0-c\0/etc/hysteria/config.yaml\0",
        )
        .unwrap();

        let audit = audit_container_services(&proc_dir, &[201], Some(100));
        assert_eq!(audit.services.len(), 1);
        assert_eq!(audit.services[0].engine, "hysteria2");
        assert_eq!(audit.violations.len(), 1);
        assert_eq!(audit.violations[0].code, "service_disallowed_sni");
        assert_eq!(audit.violations[0].sni.as_deref(), Some("bad.example.org"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_confdir_and_proxy_panel_detection() {
        let argv = vec![
            "/usr/local/bin/xray".to_string(),
            "run".to_string(),
            "-confdir".to_string(),
            "/etc/xray/conf.d".to_string(),
        ];
        assert_eq!(
            extract_config_path_from_argv("xray", &argv).as_deref(),
            Some("/etc/xray/conf.d")
        );
        assert_eq!(
            detect_engine_from_cmd("x-ui", &[]),
            Some("proxy-panel")
        );
        assert_eq!(
            detect_engine_from_cmd("3x-ui", &[]),
            Some("proxy-panel")
        );
        assert_eq!(
            detect_engine_from_cmd("marzban", &[]),
            Some("proxy-panel")
        );

        let base = std::env::temp_dir().join(format!("narwhal_confdir_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let proc_dir = base.join("proc");
        let root_dir = proc_dir.join("100").join("root");
        let conf_d = root_dir.join("etc").join("xray").join("conf.d");
        fs::create_dir_all(&conf_d).unwrap();
        fs::write(
            conf_d.join("01_inbounds.json"),
            r#"{"inbounds":[{"protocol":"vmess","port":10086,"settings":{"clients":[{"id":"SECRET"}]}}]}"#,
        )
        .unwrap();
        fs::write(
            conf_d.join("02_tls.json"),
            r#"{"inbounds":[{"protocol":"vless","port":443,"streamSettings":{"tlsSettings":{"serverName":"evil.example.com"}}}]}"#,
        )
        .unwrap();

        let p_xray = proc_dir.join("202");
        fs::create_dir_all(&p_xray).unwrap();
        fs::write(p_xray.join("comm"), "xray\n").unwrap();
        fs::write(
            p_xray.join("cmdline"),
            b"/usr/local/bin/xray\0run\0-confdir\0/etc/xray/conf.d\0",
        )
        .unwrap();

        let audit = audit_container_services(&proc_dir, &[202], Some(100));
        assert_eq!(audit.services.len(), 1);
        assert_eq!(audit.services[0].inbounds.len(), 2);
        let codes: Vec<&str> = audit.violations.iter().map(|v| v.code).collect();
        assert!(codes.contains(&"service_disallowed_protocol"));
        assert!(codes.contains(&"service_disallowed_sni"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_toml_and_ini_service_audit() {
        let frp_toml = "bindPort = 7000\nauth.token = \"SECRET_FRP_TOKEN\"\n";
        let inbounds = parse_toml_or_ini_service_inbounds("frps", frp_toml);
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].port, 7000);
        assert!(inbounds[0].auth_configured);

        let socks_ini = "type = socks5\nlisten = 0.0.0.0:1080\n";
        let s_inb = parse_toml_or_ini_service_inbounds("gost", socks_ini);
        assert_eq!(s_inb.len(), 1);
        assert_eq!(s_inb[0].protocol, "socks");
        assert_eq!(s_inb[0].port, 1080);
        assert!(!s_inb[0].auth_configured);
    }

    #[test]
    fn test_proxy_panel_sqlite_db_sanitized_audit() {
        let mut fake_sqlite = b"SQLite format 3\0\x04\x00some_binary_header".to_vec();
        fake_sqlite.extend_from_slice(
            br#"{"clients":[{"id":"SECRET-UUID-999","password":"SECRET-PASS"}]}|{"network":"tcp","security":"reality","realitySettings":{"serverNames":["bad-panel.example.com","crates.io"]}}|trojan"#,
        );
        let inbounds = parse_panel_db_inbounds(&fake_sqlite);
        assert!(!inbounds.is_empty());
        assert!(inbounds.iter().any(|i| i.protocol == "trojan"));
        assert!(inbounds[0].sni_list.contains(&"bad-panel.example.com".to_string()));
        let svc = ServiceConfigSummary {
            engine: "proxy-panel".to_string(),
            pid: 555,
            inbounds,
        };
        let viols = evaluate_service_violations(&svc);
        let codes: Vec<&str> = viols.iter().map(|v| v.code).collect();
        assert!(codes.contains(&"service_disallowed_protocol"));
        assert!(codes.contains(&"service_disallowed_sni"));
        let audit = ContainerServiceAudit {
            services: vec![svc],
            violations: viols,
        };
        let json = audit.to_json();
        assert!(!json.contains("SECRET-UUID-999"));
        assert!(!json.contains("SECRET-PASS"));
    }
}
