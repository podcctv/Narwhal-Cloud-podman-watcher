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
    atomic_write_private, json_str_array, now_unix_secs, percent_decode,
    posix_basename, shlex_split, JsonObjBuilder,
};

pub const MAX_CONFIG_BYTES: usize = 262_144;
pub const FAMILIES: &[&str] = &["xray", "v2ray", "sing-box", "gost"];
pub const WEAK_PASSWORDS: &[&str] = &[
    "123456", "12345678", "123123", "admin", "admin123", "changeme", "default", "guest",
    "letmein", "pass", "password", "qwerty", "root", "socks", "socks5", "test", "toor",
];

pub const DEFAULT_PANEL_ALLOWLIST_FILE: &str = "/opt/narwhal-monitor/panel-allowlist.json";
pub const DEFAULT_PANEL_AUTO_REMEDIATE_FILE: &str =
    "/opt/narwhal-monitor/panel-auto-remediate.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordProfile {
    pub available: bool,
    pub reason: String,
    pub length: usize,
    pub lowercase: usize,
    pub uppercase: usize,
    pub digits: usize,
    pub symbols: usize,
    pub other: usize,
    pub repeated_digits: usize,
    pub max_digit_frequency: usize,
    pub longest_identical_run: usize,
}

impl PasswordProfile {
    pub fn unavailable(reason: &str) -> Self {
        Self {
            available: false,
            reason: reason.to_string(),
            length: 0,
            lowercase: 0,
            uppercase: 0,
            digits: 0,
            symbols: 0,
            other: 0,
            repeated_digits: 0,
            max_digit_frequency: 0,
            longest_identical_run: 0,
        }
    }

    pub fn to_json(&self) -> String {
        self.to_json_with_account_index(None)
    }

    fn to_json_with_account_index(&self, account_index: Option<usize>) -> String {
        let mut b = JsonObjBuilder::new();
        b.bool("available", self.available);
        if !self.available {
            b.str("reason", &self.reason);
        } else {
            b.usize("length", self.length);
            b.usize("lowercase", self.lowercase);
            b.usize("uppercase", self.uppercase);
            b.usize("digits", self.digits);
            b.usize("symbols", self.symbols);
            b.usize("other", self.other);
            b.usize("repeated_digits", self.repeated_digits);
            b.usize("max_digit_frequency", self.max_digit_frequency);
            b.usize("longest_identical_run", self.longest_identical_run);
        }
        if let Some(idx) = account_index {
            b.usize("account_index", idx);
        }
        b.finish()
    }
}

/// Compute aggregate password composition counts without leaking characters, order, or hashes.
pub fn password_profile(value: Option<&str>) -> PasswordProfile {
    let Some(pw) = value else {
        return PasswordProfile::unavailable("密码缺失、外部引用或超过统计上限");
    };
    let char_len = pw.chars().count();
    if char_len > 4096 || pw.contains("${") {
        return PasswordProfile::unavailable("密码缺失、外部引用或超过统计上限");
    }
    let mut digit_counts = [0usize; 10];
    let mut lowercase = 0usize;
    let mut uppercase = 0usize;
    let mut digits = 0usize;
    let mut symbols = 0usize;
    let mut other = 0usize;
    let mut longest = 0usize;
    let mut current = 0usize;
    let mut prev: Option<char> = None;

    for ch in pw.chars() {
        if Some(ch) == prev {
            current += 1;
        } else {
            current = 1;
            prev = Some(ch);
        }
        if current > longest {
            longest = current;
        }
        if ch.is_ascii_lowercase() {
            lowercase += 1;
        } else if ch.is_ascii_uppercase() {
            uppercase += 1;
        } else if ch.is_ascii_digit() {
            digits += 1;
            digit_counts[(ch as u8 - b'0') as usize] += 1;
        } else if ch.is_ascii_punctuation() {
            symbols += 1;
        } else {
            other += 1;
        }
    }

    let repeated_digits: usize = digit_counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| n - 1)
        .sum();
    let max_digit_frequency = digit_counts.iter().copied().max().unwrap_or(0);

    PasswordProfile {
        available: true,
        reason: String::new(),
        length: char_len,
        lowercase,
        uppercase,
        digits,
        symbols,
        other,
        repeated_digits,
        max_digit_frequency,
        longest_identical_run: longest,
    }
}

pub fn password_profile_json(value: Option<&str>) -> String {
    password_profile(value).to_json()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandalonePanel {
    pub pid: u32,
    pub process: String,
    pub panel: String,
    pub auth_assessment: &'static str,
    pub auto_stop_eligible: bool,
}

impl StandalonePanel {
    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.u64("pid", self.pid as u64);
        b.str("process", &self.process);
        b.str("panel", &self.panel);
        b.str("auth_assessment", self.auth_assessment);
        b.bool("auto_stop_eligible", self.auto_stop_eligible);
        b.finish()
    }
}

fn panel_alias(name: &str) -> Option<&'static str> {
    match name {
        "sui" | "s-ui" => Some("S-ui"),
        "x-ui" | "3x-ui" => Some("X-ui"),
        _ => None,
    }
}

fn split_ps_4_fields(line: &str) -> Option<(&str, &str, &str, &str)> {
    let s = line.trim();
    let mut iter = s.split_whitespace();
    let p0 = iter.next()?;
    let p1 = iter.next()?;
    let p2 = iter.next()?;
    let p2_ptr = p2.as_ptr() as usize;
    let s_ptr = s.as_ptr() as usize;
    let after_p2 = (p2_ptr - s_ptr) + p2.len();
    let rest = s[after_p2..].trim_start();
    if rest.is_empty() {
        return None;
    }
    Some((p0, p1, p2, rest))
}

/// Detect standalone management panel binaries by exact `comm` and `argv[0]` basename.
pub fn standalone_panels(ps_output: &str) -> Vec<StandalonePanel> {
    let mut found = Vec::new();
    for line in ps_output.lines() {
        let Some((pid_str, stat_str, comm_raw, args_raw)) = split_ps_4_fields(line) else {
            continue;
        };
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid <= 1 || stat_str.to_ascii_lowercase().contains('z') {
            continue;
        }
        let Ok(tokens) = shlex_split(args_raw, false) else {
            continue;
        };
        let comm = comm_raw.to_ascii_lowercase();
        let executable = tokens
            .first()
            .map(|t| posix_basename(t).to_ascii_lowercase())
            .unwrap_or_default();
        if let (Some(p1), Some(p2)) = (panel_alias(&comm), panel_alias(&executable)) {
            if p1 == p2 {
                found.push(StandalonePanel {
                    pid,
                    process: comm,
                    panel: p1.to_string(),
                    auth_assessment: "not_assessed",
                    auto_stop_eligible: false,
                });
            }
        }
        if found.len() >= 20 {
            break;
        }
    }
    found
}

pub fn standalone_panels_json(ps_output: &str) -> String {
    let panels = standalone_panels(ps_output);
    let items: Vec<String> = panels.iter().map(StandalonePanel::to_json).collect();
    format!("[{}]", items.join(","))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GostEndpoint {
    pub port: u16,
    pub listen: String,
    pub auth_state: &'static str,
    pub password_profiles: Vec<PasswordProfile>,
}

impl GostEndpoint {
    pub fn to_json(&self) -> String {
        let profiles: Vec<String> = self
            .password_profiles
            .iter()
            .map(PasswordProfile::to_json)
            .collect();
        let mut b = JsonObjBuilder::new();
        b.u64("port", self.port as u64);
        b.str("listen", &self.listen);
        b.str("auth_state", self.auth_state);
        b.raw("password_profiles", &format!("[{}]", profiles.join(",")));
        b.finish()
    }
}

/// Parse a GOST v2 inbound listener URL without exposing credentials.
pub fn gost_url(value: &str) -> Option<GostEndpoint> {
    let (scheme_raw, rest) = value.split_once("://")?;
    let scheme = scheme_raw.to_ascii_lowercase();
    let base_scheme = scheme.split('+').next().unwrap_or("");
    if !matches!(base_scheme, "socks" | "socks5") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, hp)) => (Some(u), hp),
        None => (None, authority),
    };
    let password_raw = userinfo.and_then(|u| u.split_once(':').map(|(_, p)| p));

    let (host, port_str) = if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, after) = stripped.split_once(']')?;
        let p_str = after.strip_prefix(':')?;
        (h, p_str)
    } else {
        let (h, p_str) = hostport.rsplit_once(':')?;
        (h, p_str)
    };
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port_str.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }

    let listen = if host.is_empty() { "*" } else { host };
    let profile = match password_raw {
        Some(raw_pw) => password_profile(Some(&percent_decode(raw_pw, false))),
        None => PasswordProfile::unavailable("入站 URL 未提供内联密码；以握手结果为准"),
    };

    Some(GostEndpoint {
        port,
        listen: listen.to_string(),
        auth_state: "unknown",
        password_profiles: vec![profile],
    })
}

pub fn gost_url_json(value: &str) -> String {
    match gost_url(value) {
        Some(ep) => ep.to_json(),
        None => "null".to_string(),
    }
}

pub fn parse_endpoint(value: &str) -> (String, u16) {
    let mut text = value.trim();
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("tcp:") || lower.starts_with("udp:") {
        text = text.split_once(':').map(|(_, r)| r).unwrap_or("");
    }
    let Some((host_raw, port_raw)) = text.rsplit_once(':') else {
        return (String::new(), 0);
    };
    let Ok(port) = port_raw.trim().parse::<u16>() else {
        return (String::new(), 0);
    };
    if port == 0 {
        return (String::new(), 0);
    }
    let host = host_raw.trim_matches(|c| c == '[' || c == ']').to_string();
    (host, port)
}

pub fn is_loopback_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6
                        .to_ipv4_mapped()
                        .map(|v4| v4.is_loopback())
                        .unwrap_or(false)
            }
        };
    }
    host.eq_ignore_ascii_case("localhost")
}

/// Determine whether a listener is exposed beyond loopback directly or via forwarding rules.
pub fn is_listener_exposed(local: &str, forwards: &[(String, String)]) -> Option<bool> {
    let (host, port) = parse_endpoint(local);
    if host.is_empty() || port == 0 {
        return None;
    }
    if !is_loopback_host(&host) {
        return Some(true);
    }
    for (target, listen) in forwards {
        let (target_host, target_port) = parse_endpoint(target);
        let (listen_host, _) = parse_endpoint(listen);
        if target_port == port
            && is_loopback_host(&target_host)
            && !listen_host.is_empty()
            && !is_loopback_host(&listen_host)
        {
            return Some(true);
        }
    }
    Some(false)
}

pub fn socks_greeting_mode(response: &[u8]) -> &'static str {
    match response {
        [0x05, 0x00] => "no_auth",
        [0x05, 0x02] => "auth_required",
        _ => "unknown",
    }
}

/// Strip JSONC (`// ...` and `/* ... */`) comments while preserving quoted strings.
pub fn strip_jsonc_comments(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            out.push('"');
            i += 1;
            while i < bytes.len() {
                let rest = &raw[i..];
                let ch = rest.chars().next().unwrap_or('"');
                out.push(ch);
                i += ch.len_utf8();
                if ch == '\\' && i < bytes.len() {
                    let next_ch = raw[i..].chars().next().unwrap_or('\\');
                    out.push(next_ch);
                    i += next_ch.len_utf8();
                } else if ch == '"' {
                    break;
                }
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\r' && bytes[i] != b'\n' {
                i += 1;
            }
            out.push(' ');
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            if let Some(end_rel) = raw[i + 2..].find("*/") {
                i += 2 + end_rel + 2;
                out.push(' ');
                continue;
            }
        }
        let ch = raw[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn profiles_json(users: Option<&[JsonVal]>, key: &str) -> String {
    let Some(list) = users.filter(|u| !u.is_empty()) else {
        return format!(
            "[{}]",
            PasswordProfile::unavailable("未找到内联入站认证账号；可能使用外部认证").to_json()
        );
    };
    let mut items = Vec::new();
    for (i, u) in list.iter().take(20).enumerate() {
        let pw = u.as_obj().and_then(|m| m.get(key)).and_then(JsonVal::as_str);
        items.push(password_profile(pw).to_json_with_account_index(Some(i + 1)));
    }
    if list.len() > 20 {
        items.push(
            PasswordProfile::unavailable("仅展示前 20 个账号，未统计其余账号").to_json(),
        );
    }
    format!("[{}]", items.join(","))
}

fn auth_strength(users: Option<&[JsonVal]>, user_key: &str, pw_key: &str) -> &'static str {
    let Some(list) = users.filter(|u| !u.is_empty()) else {
        return "unknown";
    };
    if list.len() > 100 {
        return "unknown";
    }
    let mut weak_found = false;
    for u in list {
        let Some(obj) = u.as_obj() else {
            return "unknown";
        };
        let Some(username) = obj.get(user_key).and_then(JsonVal::as_str) else {
            return "unknown";
        };
        if username.is_empty() {
            return "unknown";
        }
        let Some(pw) = obj.get(pw_key).and_then(JsonVal::as_str) else {
            return "unknown";
        };
        if pw.chars().count() < 8 || WEAK_PASSWORDS.contains(&pw.to_ascii_lowercase().as_str()) {
            weak_found = true;
        }
    }
    if weak_found {
        "weak_password"
    } else {
        "configured"
    }
}

fn valid_port_from_json(val: Option<&JsonVal>) -> Option<u16> {
    match val {
        Some(JsonVal::Num(n)) if n.is_finite() && n.fract() == 0.0 => {
            if *n > 0.0 && *n < 65536.0 {
                Some(*n as u16)
            } else {
                None
            }
        }
        Some(JsonVal::Str(s)) => {
            let t = s.trim();
            if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
                t.parse::<u16>().ok().filter(|&p| p > 0)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn unparsed_config_json() -> String {
    "{\"parsed\":false,\"endpoints\":[],\"single_purpose\":false}".to_string()
}

fn parse_gost_json_config(raw: &str) -> String {
    let Ok(val) = JsonVal::parse(raw) else {
        return unparsed_config_json();
    };
    let Some(obj) = val.as_obj() else {
        return unparsed_config_json();
    };
    let services_val = obj.get("services").or_else(|| obj.get("serveNodes"));
    let Some(services) = services_val.and_then(JsonVal::as_arr) else {
        return unparsed_config_json();
    };
    if services.is_empty() || services.len() > 100 {
        return unparsed_config_json();
    }
    let mut endpoints = Vec::new();
    for service in services {
        if let Some(s) = service.as_str() {
            if let Some(ep) = gost_url(s) {
                endpoints.push(ep.to_json());
            }
            continue;
        }
        let Some(svc_obj) = service.as_obj() else {
            continue;
        };
        let Some(handler) = svc_obj.get("handler").and_then(JsonVal::as_obj) else {
            continue;
        };
        let htype = handler.get("type").and_then(JsonVal::as_str).unwrap_or("");
        if !matches!(htype, "socks" | "socks5") {
            continue;
        }
        let addr = svc_obj.get("addr").and_then(JsonVal::as_str).unwrap_or("");
        let (host, port) = parse_endpoint(addr);
        if port == 0 {
            continue;
        }
        let has_auther = handler
            .get("auther")
            .map(|v| match v {
                JsonVal::Null => false,
                JsonVal::Bool(b) => *b,
                JsonVal::Str(s) => !s.is_empty(),
                JsonVal::Arr(a) => !a.is_empty(),
                JsonVal::Obj(o) => !o.is_empty(),
                JsonVal::Num(n) => *n != 0.0,
            })
            .unwrap_or(false);
        let facts = if has_auther {
            format!(
                "[{}]",
                PasswordProfile::unavailable("使用外部 auther，配置未包含可统计的入站密码")
                    .to_json()
            )
        } else {
            let auth_user = handler.get("auth").filter(|v| v.as_obj().is_some()).cloned();
            let slice_vec: Vec<JsonVal> = auth_user.into_iter().collect();
            profiles_json(Some(&slice_vec), "password")
        };
        let mut b = JsonObjBuilder::new();
        b.u64("port", port as u64);
        b.str("listen", if host.is_empty() { "*" } else { &host });
        b.str("auth_state", "unknown");
        b.raw("password_profiles", &facts);
        endpoints.push(b.finish());
    }
    let single_purpose = services.len() == 1 && endpoints.len() == 1;
    let mut out = JsonObjBuilder::new();
    out.bool("parsed", true);
    out.raw("endpoints", &format!("[{}]", endpoints.join(",")));
    out.bool("single_purpose", single_purpose);
    out.finish()
}

/// Parse inbound SOCKS listeners from `xray`, `v2ray`, `sing-box`, or JSON `gost` configs.
pub fn parse_socks_config_json(raw: &str, process: &str) -> String {
    if !FAMILIES.contains(&process) || raw.len() > MAX_CONFIG_BYTES {
        return unparsed_config_json();
    }
    if process == "gost" {
        return parse_gost_json_config(raw);
    }
    let stripped = strip_jsonc_comments(raw);
    let Ok(val) = JsonVal::parse(&stripped) else {
        return unparsed_config_json();
    };
    let Some(obj) = val.as_obj() else {
        return unparsed_config_json();
    };
    let inbounds = match obj.get("inbounds") {
        Some(JsonVal::Arr(arr)) if arr.len() <= 100 && arr.iter().all(|i| i.as_obj().is_some()) => arr,
        None => &[][..],
        _ => return unparsed_config_json(),
    };

    let mut parsed = true;
    let mut endpoints = Vec::new();
    for inbound in inbounds {
        let kind = if matches!(process, "xray" | "v2ray") {
            inbound.get_str("protocol")
        } else {
            inbound.get_str("type")
        }
        .unwrap_or("None")
        .to_ascii_lowercase();
        if !matches!(kind.as_str(), "socks" | "mixed")
            || (kind == "mixed" && process != "sing-box")
        {
            continue;
        }
        let port_val = if matches!(process, "xray" | "v2ray") {
            inbound.get("port")
        } else {
            inbound.get("listen_port")
        };
        let Some(port) = valid_port_from_json(port_val) else {
            parsed = false;
            continue;
        };
        let mut mode = "unknown";
        let mut password_facts: Option<String> = None;
        if matches!(process, "xray" | "v2ray") {
            if let Some(settings) = inbound.get("settings").and_then(JsonVal::as_obj) {
                let auth = settings
                    .get("auth")
                    .and_then(JsonVal::as_str)
                    .unwrap_or("noauth");
                if auth == "noauth" {
                    mode = "no_auth";
                } else if auth == "password" {
                    let users = settings
                        .get("users")
                        .or_else(|| settings.get("accounts"))
                        .and_then(JsonVal::as_arr);
                    mode = auth_strength(users, "user", "pass");
                    password_facts = Some(profiles_json(users, "pass"));
                }
            }
        } else {
            let users_val = inbound.get("users");
            let users_arr = users_val.and_then(JsonVal::as_arr);
            if users_val.is_none() || users_arr.map(|a| a.is_empty()) == Some(true) {
                mode = "no_auth";
            } else {
                mode = auth_strength(users_arr, "username", "password");
                password_facts = Some(profiles_json(users_arr, "password"));
            }
        }
        let listen = inbound.get_str("listen").unwrap_or("*");
        let mut eb = JsonObjBuilder::new();
        eb.u64("port", port as u64);
        eb.str("listen", listen);
        eb.str("auth_state", mode);
        if let Some(pf) = password_facts {
            eb.raw("password_profiles", &pf);
        }
        endpoints.push(eb.finish());
    }
    let single_purpose = inbounds.len() == 1 && endpoints.len() == 1;
    let mut out = JsonObjBuilder::new();
    out.bool("parsed", parsed);
    out.raw("endpoints", &format!("[{}]", endpoints.join(",")));
    out.bool("single_purpose", single_purpose);
    out.finish()
}

fn valid_protocol_label(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn map_xray_network(network: &str, stream_settings: Option<&BTreeMap<String, JsonVal>>) -> Option<&'static str> {
    match network {
        "tcp" | "raw" | "ws" | "websocket" | "grpc" | "http" | "h2" | "httpupgrade" => {
            Some("tcp")
        }
        "kcp" | "mkcp" | "quic" | "h3" | "hysteria" => Some("udp"),
        "xhttp" => {
            let ss = stream_settings?;
            let tls_settings = ss.get("tlsSettings").and_then(JsonVal::as_obj);
            let alpn = tls_settings.and_then(|t| t.get("alpn"));
            let security = ss.get("security").and_then(JsonVal::as_str).unwrap_or("");
            if alpn.is_none() {
                Some("tcp")
            } else if security == "tls" {
                let arr = alpn.and_then(JsonVal::as_arr).filter(|a| !a.is_empty())?;
                let mut normalized = Vec::with_capacity(arr.len());
                for v in arr {
                    normalized.push(v.as_str()?.trim().to_ascii_lowercase());
                }
                if normalized.len() == 1 && normalized[0] == "h3" {
                    Some("udp")
                } else if normalized.iter().any(|v| v == "h3") {
                    None
                } else {
                    Some("tcp")
                }
            } else if security == "reality" {
                Some("tcp")
            } else {
                None
            }
        }
        "masque" => None,
        _ => None,
    }
}

fn parse_network_list(val: &JsonVal) -> Option<Vec<String>> {
    match val {
        JsonVal::Str(s) => Some(
            s.split(',')
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect(),
        ),
        JsonVal::Arr(arr) => {
            let mut out = Vec::new();
            for item in arr {
                let s = item.as_str()?.trim().to_ascii_lowercase();
                if !s.is_empty() {
                    out.push(s);
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// Parse non-secret inbound protocol, bind address, port, and transport metadata.
pub fn parse_inbound_protocols_json(raw: &str, process: &str) -> String {
    let proc_lower = process.to_ascii_lowercase();
    let empty = "{\"parsed\":false,\"endpoints\":[]}".to_string();
    if !matches!(proc_lower.as_str(), "xray" | "v2ray" | "sing-box")
        || raw.len() > MAX_CONFIG_BYTES
    {
        return empty;
    }
    let stripped = strip_jsonc_comments(raw);
    let Ok(val) = JsonVal::parse(&stripped) else {
        return empty;
    };
    let Some(obj) = val.as_obj() else {
        return empty;
    };
    let inbounds = match obj.get("inbounds") {
        Some(JsonVal::Arr(arr)) if arr.len() <= 100 && arr.iter().all(|i| i.as_obj().is_some()) => arr,
        None => &[][..],
        _ => return empty,
    };

    let mut endpoints = Vec::new();
    for inbound in inbounds {
        let (protocol_key, port_key) = if proc_lower == "sing-box" {
            ("type", "listen_port")
        } else {
            ("protocol", "port")
        };
        let Some(protocol) = inbound.get_str(protocol_key) else {
            continue;
        };
        if !valid_protocol_label(protocol) {
            continue;
        }
        let Some(port) = valid_port_from_json(inbound.get(port_key)) else {
            continue;
        };
        let listen_raw = inbound.get_str("listen").unwrap_or("*");
        let listen = if listen_raw.chars().count() > 128
            || listen_raw.chars().any(|c| (c as u32) < 32)
            || listen_raw.is_empty()
        {
            "*"
        } else {
            listen_raw
        };
        let proto_lower = protocol.to_ascii_lowercase();
        let mut transports: Option<Vec<String>> = None;

        if matches!(proc_lower.as_str(), "xray" | "v2ray") {
            let ss = inbound.get("streamSettings").and_then(JsonVal::as_obj);
            let configured_network = if let Some(m) = ss.and_then(|s| s.get("method")) {
                Some(m.clone())
            } else if let Some(n) = inbound.get("network") {
                Some(n.clone())
            } else {
                match ss.and_then(|s| s.get("network")) {
                    Some(n) => Some(n.clone()),
                    None => Some(JsonVal::Str(
                        if proc_lower == "v2ray" { "tcp" } else { "raw" }.to_string(),
                    )),
                }
            };
            if let Some(net_val) = configured_network {
                if let Some(nets) = parse_network_list(&net_val) {
                    if !nets.is_empty() {
                        let mut mapped = BTreeSet::new();
                        let mut all_ok = true;
                        for net in &nets {
                            if let Some(t) = map_xray_network(net, ss) {
                                mapped.insert(t.to_string());
                            } else {
                                all_ok = false;
                                break;
                            }
                        }
                        if all_ok && !mapped.is_empty() {
                            transports = Some(mapped.into_iter().collect());
                        }
                    }
                }
            }
        } else if let Some(net_val) = inbound.get("network") {
            if let Some(nets) = parse_network_list(net_val) {
                if !nets.is_empty() && nets.iter().all(|n| matches!(n.as_str(), "tcp" | "udp")) {
                    let uniq: BTreeSet<String> = nets.into_iter().collect();
                    transports = Some(uniq.into_iter().collect());
                }
            }
        } else if matches!(proto_lower.as_str(), "trojan" | "vmess") {
            transports = Some(vec!["tcp".to_string()]);
        }

        let mut eb = JsonObjBuilder::new();
        eb.str("protocol", &proto_lower);
        eb.u64("port", port as u64);
        eb.str("listen", listen);
        if let Some(ts) = transports {
            eb.raw("transports", &json_str_array(&ts));
        }
        endpoints.push(eb.finish());
    }

    let mut out = JsonObjBuilder::new();
    out.bool("parsed", true);
    out.raw("endpoints", &format!("[{}]", endpoints.join(",")));
    out.finish()
}

fn valid_abs_unix_path(value: &str) -> bool {
    value.starts_with('/')
        && (2..=241).contains(&value.len())
        && value[1..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
        && !value.split('/').any(|seg| seg == "..")
}

fn has_config_ext(value: &str) -> bool {
    [".json", ".yaml", ".yml", ".conf", ".cfg"]
        .iter()
        .any(|ext| value.ends_with(ext))
}

/// Parse explicit config paths and config dirs from `ps` output without matching arbitrary args.
pub fn parse_process_configs_json(ps_output: &str) -> String {
    let mut rows = Vec::new();
    for line in ps_output.lines() {
        let Some((pid_str, stat_str, comm_raw, args_raw)) = split_ps_4_fields(line) else {
            continue;
        };
        if !pid_str.bytes().all(|b| b.is_ascii_digit())
            || stat_str.to_ascii_lowercase().contains('z')
        {
            continue;
        }
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let Ok(tokens) = shlex_split(args_raw, false) else {
            continue;
        };
        let process = comm_raw.to_ascii_lowercase();
        let valid_proc = FAMILIES.contains(&process.as_str())
            || matches!(process.as_str(), "danted" | "sockd" | "3proxy");
        let exe_matches = tokens
            .first()
            .map(|t| posix_basename(t).to_ascii_lowercase() == process)
            .unwrap_or(false);
        if !valid_proc || !exe_matches {
            continue;
        }

        let mut paths = Vec::new();
        let mut config_dirs = Vec::new();
        let mut unparsed = false;

        for (idx, token) in tokens.iter().enumerate() {
            let mut value = "";
            let mut directory = "";
            if (matches!(
                token.as_str(),
                "-confdir" | "--config-dir" | "--config-directory"
            ) || (process == "sing-box" && token == "-C"))
                && idx + 1 < tokens.len()
            {
                directory = tokens[idx + 1].as_str();
            } else if let Some(rest) = token
                .strip_prefix("--config-dir=")
                .or_else(|| token.strip_prefix("--config-directory="))
                .or_else(|| token.strip_prefix("-confdir="))
            {
                directory = rest;
            }
            if !directory.is_empty() {
                if valid_abs_unix_path(directory) {
                    let trimmed = directory.trim_end_matches('/');
                    config_dirs.push(if trimmed.is_empty() { "/" } else { trimmed }.to_string());
                } else {
                    unparsed = true;
                }
                continue;
            }

            let is_file_flag = matches!(
                token.as_str(),
                "-c" | "-f" | "-config" | "--config" | "-conf" | "--config-file"
            ) || (process != "sing-box" && token == "-C");
            if is_file_flag && idx + 1 < tokens.len() {
                value = tokens[idx + 1].as_str();
            } else if let Some(rest) = token
                .strip_prefix("--config=")
                .or_else(|| token.strip_prefix("-config="))
                .or_else(|| token.strip_prefix("--config-file="))
            {
                value = rest;
            }
            if !value.is_empty() {
                if valid_abs_unix_path(value) && has_config_ext(value) {
                    paths.push(value.to_string());
                } else {
                    unparsed = true;
                }
            }
        }
        if process == "3proxy" {
            for t in tokens.iter().skip(1) {
                if t.ends_with(".cfg") && valid_abs_unix_path(t) {
                    paths.push(t.clone());
                }
            }
        }

        let any_flag = tokens.iter().any(|t| {
            t.starts_with("-c")
                || t.starts_with("-C")
                || t.starts_with("-f")
                || t.starts_with("--config")
                || t.starts_with("-config")
                || t.starts_with("-confdir")
        });
        if paths.is_empty() && config_dirs.is_empty() && !any_flag {
            match process.as_str() {
                "danted" => paths.push("/etc/danted.conf".to_string()),
                "sockd" => paths.push("/etc/sockd.conf".to_string()),
                "3proxy" => paths.push("/etc/3proxy/3proxy.cfg".to_string()),
                "gost" => {
                    paths.push("/etc/gost/config.json".to_string());
                    paths.push("/etc/gost/config.yaml".to_string());
                }
                other => paths.push(format!("/etc/{other}/config.json")),
            }
        } else if paths.is_empty() && config_dirs.is_empty() {
            unparsed = true;
        }

        let mut uniq_paths = Vec::new();
        for p in paths {
            if !uniq_paths.contains(&p) {
                uniq_paths.push(p);
            }
        }
        let mut uniq_dirs = Vec::new();
        for d in config_dirs {
            if !uniq_dirs.contains(&d) {
                uniq_dirs.push(d);
            }
        }

        let additional = unparsed || uniq_paths.len() > 16 || uniq_dirs.len() > 4;
        let bounded_paths: Vec<String> = uniq_paths.into_iter().take(16).collect();
        let bounded_dirs: Vec<String> = uniq_dirs.into_iter().take(4).collect();

        let mut rb = JsonObjBuilder::new();
        rb.u64("pid", pid as u64);
        rb.str("process", &process);
        rb.raw("paths", &json_str_array(&bounded_paths));
        rb.raw("config_dirs", &json_str_array(&bounded_dirs));
        rb.bool("additional_configs", additional);
        rows.push(rb.finish());

        if rows.len() >= 8 {
            break;
        }
    }
    format!("[{}]", rows.join(","))
}

pub fn legacy_profiles_json(raw: &str, process: &str) -> String {
    if matches!(process, "danted" | "sockd") {
        return format!(
            "[{}]",
            PasswordProfile::unavailable("Dante 使用系统/PAM 认证；不能从密码哈希还原长度或组成")
                .to_json()
        );
    }
    if process == "3proxy" && raw.len() <= MAX_CONFIG_BYTES {
        let mut found = Vec::new();
        for line in raw.lines() {
            let Ok(tokens) = shlex_split(line, true) else {
                continue;
            };
            if tokens.first().map(String::as_str) != Some("users") {
                continue;
            }
            for token in tokens.iter().skip(1).take(20) {
                let parts: Vec<&str> = token.splitn(3, ':').collect();
                let prof = if parts.len() == 3 && parts[1] == "CL" {
                    password_profile(Some(parts[2]))
                } else {
                    PasswordProfile::unavailable("加密或外部密码，不能还原组成")
                };
                found.push(prof.to_json());
                if found.len() >= 20 {
                    return format!("[{}]", found.join(","));
                }
            }
        }
        if !found.is_empty() {
            return format!("[{}]", found.join(","));
        }
    }
    format!(
        "[{}]",
        PasswordProfile::unavailable(
            "配置未读取、格式不支持或认证保存在外部；未按空密码处理"
        )
        .to_json()
    )
}

pub fn gost_cli_json(ps_output: &str, pid: u32) -> String {
    let pid_str = pid.to_string();
    for line in ps_output.lines() {
        let Some((p0, _, _, args_raw)) = split_ps_4_fields(line) else {
            continue;
        };
        if p0 != pid_str {
            continue;
        }
        let Ok(tokens) = shlex_split(args_raw, false) else {
            return "null".to_string();
        };
        let mut listeners = Vec::new();
        for (i, token) in tokens.iter().enumerate() {
            if token == "-L" && i + 1 < tokens.len() {
                listeners.push(tokens[i + 1].as_str());
            } else if let Some(rest) = token.strip_prefix("-L=") {
                listeners.push(rest);
            }
        }
        if !listeners.is_empty() {
            let entries: Vec<GostEndpoint> =
                listeners.iter().take(100).filter_map(|v| gost_url(v)).collect();
            let no_cfg = !tokens.iter().any(|t| {
                matches!(t.as_str(), "-C" | "-c" | "--config") || t.starts_with("--config=")
            });
            let single_purpose = listeners.len() == 1 && entries.len() == 1 && no_cfg;
            let ep_json: Vec<String> = entries.iter().map(GostEndpoint::to_json).collect();
            let mut b = JsonObjBuilder::new();
            b.bool("parsed", listeners.len() <= 100);
            b.raw("endpoints", &format!("[{}]", ep_json.join(",")));
            b.bool("single_purpose", single_purpose);
            return b.finish();
        }
    }
    "null".to_string()
}

// -----------------------------------------------------------------------
// Panel pairing domain allowlist & env/state updates (no secrets exposed)
// -----------------------------------------------------------------------

/// Validate a panel domain hostname or IP address matching `client/agent.py::_valid_panel_domain`.
pub fn valid_panel_domain(value: &str) -> bool {
    let candidate = value.trim().to_ascii_lowercase();
    let candidate = candidate.trim_end_matches('.');
    if candidate.is_empty() || candidate.len() > 253 {
        return false;
    }
    if candidate.parse::<IpAddr>().is_ok() {
        return true;
    }
    candidate.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

pub fn panel_domain_allowed(domain: &str, allowed_domains: &[String]) -> bool {
    let candidate = domain.trim().to_ascii_lowercase();
    let candidate = candidate.trim_end_matches('.');
    if candidate.is_empty() {
        return false;
    }
    for raw in allowed_domains {
        let trimmed = raw.trim().to_ascii_lowercase();
        let allowed = trimmed.trim_start_matches("*.").trim_end_matches('.');
        if !allowed.is_empty()
            && (candidate == allowed || candidate.ends_with(&format!(".{allowed}")))
        {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelDomainAction {
    Allow,
    Disallow,
}

impl PanelDomainAction {
    pub fn parse(action: &str) -> Result<Self, String> {
        match action.trim() {
            "allow" | "allow_panel_domains" => Ok(Self::Allow),
            "disallow" | "disallow_panel_domains" => Ok(Self::Disallow),
            other => Err(format!("unsupported panel domain action: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow_panel_domains",
            Self::Disallow => "disallow_panel_domains",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelDomainStore {
    pub allowlist_path: PathBuf,
    pub auto_remediate_path: Option<PathBuf>,
    pub env_file_path: Option<PathBuf>,
    pub env_allowed_domains: Vec<String>,
}

impl Default for PanelDomainStore {
    fn default() -> Self {
        Self {
            allowlist_path: PathBuf::from(DEFAULT_PANEL_ALLOWLIST_FILE),
            auto_remediate_path: Some(PathBuf::from(DEFAULT_PANEL_AUTO_REMEDIATE_FILE)),
            env_file_path: None,
            env_allowed_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelDomainOutcome {
    pub ok: bool,
    pub action: &'static str,
    pub allowlist: Vec<String>,
    pub auto_remediate: Vec<String>,
    pub message: String,
}

impl PanelDomainOutcome {
    pub fn to_json(&self) -> String {
        let mut b = JsonObjBuilder::new();
        b.bool("ok", self.ok);
        b.str("action", self.action);
        b.raw("allowlist", &json_str_array(&self.allowlist));
        b.raw("auto_remediate", &json_str_array(&self.auto_remediate));
        b.str("message", &self.message);
        b.finish()
    }
}

fn normalize_exact_domains(domains: &[String]) -> BTreeSet<String> {
    domains
        .iter()
        .map(|d| d.trim().to_ascii_lowercase().trim_end_matches('.').to_string())
        .filter(|d| valid_panel_domain(d))
        .collect()
}

fn read_domain_list_file(path: &Path, strip_wildcard: bool) -> Result<BTreeSet<String>, String> {
    if !path.is_absolute() {
        return Err("panel domain policy path must be absolute".to_string());
    }
    if super::util::is_symlink_path(path) {
        return Err("panel domain policy symlink rejected".to_string());
    }
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(_) => return Ok(BTreeSet::new()),
    };
    let Ok(val) = JsonVal::parse(&raw) else {
        return Ok(BTreeSet::new());
    };
    let arr_opt = if let Some(obj) = val.as_obj() {
        obj.get("domains").and_then(JsonVal::as_arr)
    } else {
        val.as_arr()
    };
    let mut set = BTreeSet::new();
    if let Some(arr) = arr_opt {
        for item in arr {
            if let Some(s) = item.as_str() {
                let mut norm = s.trim().to_ascii_lowercase();
                if strip_wildcard {
                    norm = norm.trim_start_matches("*.").to_string();
                }
                norm = norm.trim_end_matches('.').to_string();
                if valid_panel_domain(&norm) {
                    set.insert(norm);
                }
            }
        }
    }
    Ok(set)
}

fn write_domain_list_file(
    path: &Path,
    domains: &[String],
    now_epoch: u64,
    prefix: &str,
) -> Result<(), String> {
    let mut b = JsonObjBuilder::new();
    b.raw("domains", &json_str_array(domains));
    b.u64("updated_at", now_epoch);
    let mut payload = b.finish();
    payload.push('\n');
    atomic_write_private(path, payload.as_bytes(), prefix)
}

fn read_env_allowed_domains_only(env_path: &Path) -> Result<BTreeSet<String>, String> {
    if !env_path.is_absolute() {
        return Err("env file path must be absolute".to_string());
    }
    if super::util::is_symlink_path(env_path) {
        return Err("env file symlink rejected".to_string());
    }
    let raw = match fs::read_to_string(env_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(_) => return Err("unable to read client environment file".to_string()),
    };
    let mut set = BTreeSet::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            if key.trim() == "SECURITY_ALLOWED_PANEL_DOMAINS" {
                let unquoted = value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                for item in unquoted.split(',') {
                    let norm = item
                        .trim()
                        .to_ascii_lowercase()
                        .trim_start_matches("*.")
                        .trim_end_matches('.')
                        .to_string();
                    if valid_panel_domain(&norm) {
                        set.insert(norm);
                    }
                }
            }
        }
    }
    Ok(set)
}

/// Update only `SECURITY_ALLOWED_PANEL_DOMAINS` in `env_path`, preserving all other lines
/// verbatim without reading, logging, or exposing any secret values.
fn update_env_allowed_domains_only(
    env_path: &Path,
    domains: &[String],
) -> Result<(), String> {
    if !env_path.is_absolute() {
        return Err("env file path must be absolute".to_string());
    }
    if super::util::is_symlink_path(env_path) {
        return Err("env file symlink rejected".to_string());
    }
    let existing = match fs::read_to_string(env_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err("unable to read client environment file".to_string()),
    };
    let joined = domains.join(",");
    if joined
        .chars()
        .any(|c| matches!(c, '\r' | '\n' | '=' | '\\' | '"' | '\''))
    {
        return Err("invalid panel domain characters for env file".to_string());
    }

    let mut lines: Vec<String> = Vec::new();
    let mut updated = false;
    for line in existing.lines() {
        let key = line.split('=').next().unwrap_or("").trim();
        if key == "SECURITY_ALLOWED_PANEL_DOMAINS" {
            lines.push(format!("SECURITY_ALLOWED_PANEL_DOMAINS={joined}"));
            updated = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !updated {
        lines.push(format!("SECURITY_ALLOWED_PANEL_DOMAINS={joined}"));
    }
    let mut content = lines.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    atomic_write_private(env_path, content.as_bytes(), ".client-env-")
}

/// Execute `allow_panel_domains` or `disallow_panel_domains` updates atomically across
/// the JSON state files and optional env file without exposing secrets.
pub fn manage_panel_domains(
    store: &PanelDomainStore,
    action: PanelDomainAction,
    domains: &[String],
    now_epoch: u64,
) -> Result<PanelDomainOutcome, String> {
    let normalized = normalize_exact_domains(domains);
    let effective_now = if now_epoch == 0 {
        now_unix_secs().max(0) as u64
    } else {
        now_epoch
    };

    match action {
        PanelDomainAction::Allow => {
            if normalized.is_empty() {
                return Err("no valid panel domains supplied".to_string());
            }
            let mut auto_rem = if let Some(ref auto_path) = store.auto_remediate_path {
                let mut set = read_domain_list_file(auto_path, false)?;
                for d in &normalized {
                    set.remove(d);
                }
                let list: Vec<String> = set.iter().cloned().collect();
                write_domain_list_file(auto_path, &list, effective_now, ".panel-auto-remediate-")?;
                set
            } else {
                BTreeSet::new()
            };

            let mut allow_set = read_domain_list_file(&store.allowlist_path, true)?;
            for d in &store.env_allowed_domains {
                let norm = d
                    .trim()
                    .to_ascii_lowercase()
                    .trim_start_matches("*.")
                    .trim_end_matches('.')
                    .to_string();
                if valid_panel_domain(&norm) {
                    allow_set.insert(norm);
                }
            }
            if let Some(ref env_path) = store.env_file_path {
                for d in read_env_allowed_domains_only(env_path)? {
                    allow_set.insert(d);
                }
            }
            // Auto-remediate exclusions apply to pre-existing defaults, then newly allowed domains are merged.
            allow_set.retain(|d| !auto_rem.contains(d));
            for d in &normalized {
                auto_rem.remove(d);
                allow_set.insert(d.clone());
            }
            let merged: Vec<String> = allow_set.into_iter().collect();
            write_domain_list_file(
                &store.allowlist_path,
                &merged,
                effective_now,
                ".panel-allowlist-",
            )?;
            if let Some(ref env_path) = store.env_file_path {
                update_env_allowed_domains_only(env_path, &merged)?;
            }

            let auto_vec: Vec<String> = auto_rem.into_iter().collect();
            let msg = format!(
                "allowed {} exact domain(s); allowlist now contains {}",
                domains.len(),
                merged.len()
            );
            Ok(PanelDomainOutcome {
                ok: true,
                action: action.as_str(),
                allowlist: merged,
                auto_remediate: auto_vec,
                message: msg,
            })
        }
        PanelDomainAction::Disallow => {
            let mut allow_set = read_domain_list_file(&store.allowlist_path, false)?;
            for d in &normalized {
                allow_set.remove(d);
            }
            let remaining: Vec<String> = allow_set.into_iter().collect();
            write_domain_list_file(
                &store.allowlist_path,
                &remaining,
                effective_now,
                ".panel-allowlist-",
            )?;

            if let Some(ref env_path) = store.env_file_path {
                let mut env_set = read_env_allowed_domains_only(env_path)?;
                if env_path.is_file() {
                    for d in &normalized {
                        env_set.remove(d);
                    }
                    let env_remaining: Vec<String> = env_set.into_iter().collect();
                    update_env_allowed_domains_only(env_path, &env_remaining)?;
                }
            }

            let auto_vec = if let Some(ref auto_path) = store.auto_remediate_path {
                read_domain_list_file(auto_path, false)?.into_iter().collect()
            } else {
                Vec::new()
            };
            let msg = format!(
                "removed {} exact domain(s) from the node allowlist; allowlist now contains {}",
                domains.len(),
                remaining.len()
            );
            Ok(PanelDomainOutcome {
                ok: true,
                action: action.as_str(),
                allowlist: remaining,
                auto_remediate: auto_vec,
                message: msg,
            })
        }
    }
}

pub fn manage_panel_domains_json(
    store: &PanelDomainStore,
    action_str: &str,
    domains: &[String],
    now_epoch: u64,
) -> String {
    let Ok(action) = PanelDomainAction::parse(action_str) else {
        let mut b = JsonObjBuilder::new();
        b.bool("ok", false);
        b.str("action", action_str);
        b.raw("allowlist", "[]");
        b.raw("auto_remediate", "[]");
        b.str("message", "unsupported panel domain action");
        return b.finish();
    };
    match manage_panel_domains(store, action, domains, now_epoch) {
        Ok(outcome) => outcome.to_json(),
        Err(err) => {
            let mut b = JsonObjBuilder::new();
            b.bool("ok", false);
            b.str("action", action.as_str());
            b.raw("allowlist", "[]");
            b.raw("auto_remediate", "[]");
            b.str("message", &err);
            b.finish()
        }
    }
}
