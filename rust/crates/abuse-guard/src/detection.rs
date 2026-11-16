use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use runtime_drivers::JsonVal;
use transport::sha256_hex;

use crate::py_ast::{collect_active_nodes, parse_reachable_module, ActiveNode, Expr, Stmt};

pub const SOURCE_LIMIT: usize = 65536;
pub const NODE_LIMIT: usize = crate::py_ast::NODE_LIMIT;

pub const SCANNERS: &[&str] = &["masscan", "zmap", "nmap", "rustscan"];
pub const AUTH_TOOLS: &[&str] = &["hydra", "medusa", "ncrack", "patator"];
pub const SENSITIVE_PORTS: &[u16] = &[
    21, 22, 23, 25, 110, 139, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211, 27017,
];
pub const IDENTITY_KEYS: &[&str] = &[
    "idcard",
    "id_card",
    "idnumber",
    "id_number",
    "identity_number",
    "idno",
    "id_no",
    "idcardno",
    "identitycard",
    "identityno",
    "certificateno",
    "certificate_no",
    "身份证",
    "身份证号",
];
pub const USERNAME_KEYS: &[&str] = &["username", "user", "login", "email", "account"];
pub const PASSWORD_KEYS: &[&str] = &["password", "passwd", "pwd", "pass"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFeatures {
    pub http_calls: usize,
    pub enumeration: bool,
    pub dictionary_inputs: bool,
    pub identity_generator: bool,
    pub concurrency: usize,
    pub corroborating_samples: Option<u32>,
}

impl SourceFeatures {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("http_calls".to_string(), JsonVal::Num(self.http_calls as f64));
        map.insert("enumeration".to_string(), JsonVal::Bool(self.enumeration));
        map.insert(
            "dictionary_inputs".to_string(),
            JsonVal::Bool(self.dictionary_inputs),
        );
        map.insert(
            "identity_generator".to_string(),
            JsonVal::Bool(self.identity_generator),
        );
        map.insert(
            "concurrency".to_string(),
            JsonVal::Num(self.concurrency as f64),
        );
        if let Some(samples) = self.corroborating_samples {
            map.insert(
                "corroborating_samples".to_string(),
                JsonVal::Num(samples as f64),
            );
        }
        JsonVal::Obj(map)
    }

    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        Some(Self {
            http_calls: obj.get("http_calls").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
            enumeration: obj
                .get("enumeration")
                .and_then(JsonVal::as_bool)
                .unwrap_or(false),
            dictionary_inputs: obj
                .get("dictionary_inputs")
                .and_then(JsonVal::as_bool)
                .unwrap_or(false),
            identity_generator: obj
                .get("identity_generator")
                .and_then(JsonVal::as_bool)
                .unwrap_or(false),
            concurrency: obj
                .get("concurrency")
                .and_then(JsonVal::as_u64)
                .unwrap_or(0) as usize,
            corroborating_samples: obj
                .get("corroborating_samples")
                .and_then(JsonVal::as_u64)
                .and_then(|v| u32::try_from(v).ok()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEvidence {
    pub available: bool,
    pub reason: Option<String>,
    pub sha256: Option<String>,
    pub kinds: Vec<String>,
    pub features: Option<SourceFeatures>,
    pub target_hosts: Vec<String>,
    pub targets_by_kind: BTreeMap<String, Vec<String>>,
}

impl SourceEvidence {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("available".to_string(), JsonVal::Bool(self.available));
        if let Some(ref reason) = self.reason {
            map.insert("reason".to_string(), JsonVal::Str(reason.clone()));
        }
        if let Some(ref sha) = self.sha256 {
            map.insert("sha256".to_string(), JsonVal::Str(sha.clone()));
        }
        if self.available {
            map.insert(
                "kinds".to_string(),
                JsonVal::Arr(self.kinds.iter().cloned().map(JsonVal::Str).collect()),
            );
            if let Some(ref feat) = self.features {
                map.insert("features".to_string(), feat.to_json_val());
            }
            map.insert(
                "target_hosts".to_string(),
                JsonVal::Arr(
                    self.target_hosts
                        .iter()
                        .cloned()
                        .map(JsonVal::Str)
                        .collect(),
                ),
            );
            let mut tbk = BTreeMap::new();
            for (k, v) in &self.targets_by_kind {
                tbk.insert(
                    k.clone(),
                    JsonVal::Arr(v.iter().cloned().map(JsonVal::Str).collect()),
                );
            }
            map.insert("targets_by_kind".to_string(), JsonVal::Obj(tbk));
        }
        JsonVal::Obj(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRecord {
    pub pid: u32,
    pub remote_ip: String,
    pub remote: String,
    pub state: String,
    pub proto: String,
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessRecord {
    pub pid: u32,
    pub start_ticks: String,
    pub executable: String,
    pub cwd: String,
    pub argv: Vec<String>,
    pub source: Option<String>,
    pub target_ips: BTreeMap<String, Vec<String>>,
    pub host_pid: Option<u32>,
    pub source_coverage: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: String,
    pub confidence: String,
    pub basis: String,
    pub pid: u32,
    pub start_ticks: String,
    pub tool: Option<String>,
    pub source_sha256: Option<String>,
    pub features: Option<SourceFeatures>,
    pub target_hosts: Vec<String>,
    pub target_count: Option<usize>,
    pub public_target_count: Option<usize>,
    pub private_target_count: Option<usize>,
    pub owned_http_connections: Option<usize>,
    pub pending_attempts: Option<usize>,
    pub vertical_ports: Option<usize>,
    pub horizontal_targets: Option<usize>,
    pub pending_ratio: Option<f64>,
    pub failed_ratio: Option<f64>,
}

impl Finding {
    pub fn to_json_val(&self) -> JsonVal {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), JsonVal::Str(self.kind.clone()));
        map.insert(
            "confidence".to_string(),
            JsonVal::Str(self.confidence.clone()),
        );
        map.insert("basis".to_string(), JsonVal::Str(self.basis.clone()));
        if self.pid > 0 {
            map.insert("pid".to_string(), JsonVal::Num(self.pid as f64));
        }
        if !self.start_ticks.is_empty() {
            map.insert(
                "start_ticks".to_string(),
                JsonVal::Str(self.start_ticks.clone()),
            );
        }
        if let Some(ref tool) = self.tool {
            map.insert("tool".to_string(), JsonVal::Str(tool.clone()));
        }
        if let Some(ref sha) = self.source_sha256 {
            map.insert("source_sha256".to_string(), JsonVal::Str(sha.clone()));
        }
        if let Some(ref feat) = self.features {
            map.insert("features".to_string(), feat.to_json_val());
        }
        if !self.target_hosts.is_empty() {
            map.insert(
                "target_hosts".to_string(),
                JsonVal::Arr(
                    self.target_hosts
                        .iter()
                        .cloned()
                        .map(JsonVal::Str)
                        .collect(),
                ),
            );
        }
        if let Some(v) = self.target_count {
            map.insert("target_count".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.public_target_count {
            map.insert("public_target_count".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.private_target_count {
            map.insert("private_target_count".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.owned_http_connections {
            map.insert("owned_http_connections".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.pending_attempts {
            map.insert("pending_attempts".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.vertical_ports {
            map.insert("vertical_ports".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.horizontal_targets {
            map.insert("horizontal_targets".to_string(), JsonVal::Num(v as f64));
        }
        if let Some(v) = self.pending_ratio {
            map.insert("pending_ratio".to_string(), JsonVal::Num(v));
        }
        if let Some(v) = self.failed_ratio {
            map.insert("failed_ratio".to_string(), JsonVal::Num(v));
        }
        JsonVal::Obj(map)
    }

    pub fn from_json_val(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let kind = obj.get("kind")?.as_str()?.to_string();
        if kind.is_empty() {
            return None;
        }
        Some(Self {
            kind,
            confidence: obj
                .get("confidence")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            basis: obj
                .get("basis")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            pid: obj
                .get("pid")
                .and_then(JsonVal::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            start_ticks: obj
                .get("start_ticks")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string(),
            tool: obj
                .get("tool")
                .and_then(JsonVal::as_str)
                .map(ToString::to_string),
            source_sha256: obj
                .get("source_sha256")
                .and_then(JsonVal::as_str)
                .map(ToString::to_string),
            features: obj.get("features").and_then(SourceFeatures::from_json_val),
            target_hosts: obj
                .get("target_hosts")
                .and_then(JsonVal::as_arr)
                .map(|arr| {
                    arr.iter()
                        .filter_map(JsonVal::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            target_count: obj
                .get("target_count")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            public_target_count: obj
                .get("public_target_count")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            private_target_count: obj
                .get("private_target_count")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            owned_http_connections: obj
                .get("owned_http_connections")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            pending_attempts: obj
                .get("pending_attempts")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            vertical_ports: obj
                .get("vertical_ports")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            horizontal_targets: obj
                .get("horizontal_targets")
                .and_then(JsonVal::as_u64)
                .map(|v| v as usize),
            pending_ratio: obj.get("pending_ratio").and_then(JsonVal::as_f64),
            failed_ratio: obj.get("failed_ratio").and_then(JsonVal::as_f64),
        })
    }
}

// ---------------------------------------------------------------------------
// IP & URL classification
// ---------------------------------------------------------------------------

fn unwrap_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn is_ipv4_reserved(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_ipv4_private_python(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0 && o[3] < 8)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0 && (o[3] & 0xfe) == 170)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240
}

fn is_ipv4_global(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    !is_cgnat && !is_ipv4_private_python(ip) && !ip.is_multicast()
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_reserved_python(ip: Ipv6Addr) -> bool {
    let s0 = ip.segments()[0];
    // ::/8 (0x0000..=0x00ff), 100::/8 (0x0100..=0x01ff),
    // 200::/7 (0x0200..=0x03ff), 400::/6 (0x0400..=0x07ff),
    // 800::/5 (0x0800..=0x0fff), 1000::/4 (0x1000..=0x1fff),
    // 4000::/3 (0x4000..=0x5fff), 6000::/3 (0x6000..=0x7fff),
    // 8000::/3 (0x8000..=0x9fff), A000::/3 (0xa000..=0xbfff),
    // C000::/3 (0xc000..=0xdfff), E000::/4 (0xe000..=0xefff),
    // F000::/5 (0xf000..=0xf7ff), F800::/6 (0xf800..=0xfbff),
    // FE00::/9 (0xfe00..=0xfe7f)
    s0 <= 0x1fff || (0x4000..=0xfbff).contains(&s0) || (0xfe00..=0xfe7f).contains(&s0)
}

fn is_ipv6_private_python(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_ipv4_private_python(v4);
    }
    let seg = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff)
        || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) // 100::/64
        || (seg[0] == 0x2001 && seg[1] < 0x0200) // 2001::/23 (covers 2001:2::/48, 2001:10::/28)
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7
        || is_ipv6_link_local(ip)
}

fn is_ipv6_global(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_ipv4_global(v4);
    }
    !is_ipv6_private_python(ip) && !ip.is_multicast() && !is_ipv6_reserved_python(ip)
}

fn is_ip_global(ip: IpAddr) -> bool {
    match unwrap_mapped(ip) {
        IpAddr::V4(v4) => is_ipv4_global(v4),
        IpAddr::V6(v6) => is_ipv6_global(v6),
    }
}

fn is_ip_target_allowed(ip: IpAddr) -> bool {
    match unwrap_mapped(ip) {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !is_ipv4_reserved(v4)
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !is_ipv6_link_local(v6)
                && !v6.is_multicast()
                && !v6.is_unspecified()
                && !is_ipv6_reserved_python(v6)
        }
    }
}

pub fn public_ip(value: &str) -> String {
    let raw = value.split('%').next().unwrap_or("");
    let Ok(parsed) = raw.parse::<IpAddr>() else {
        return String::new();
    };
    let unwrapped = unwrap_mapped(parsed);
    if is_ip_global(unwrapped) {
        unwrapped.to_string()
    } else {
        String::new()
    }
}

/// Include lateral unicast targets; exclude local/link/control addresses.
pub fn target_ip(value: &str) -> String {
    let raw = value.split('%').next().unwrap_or("");
    let Ok(parsed) = raw.parse::<IpAddr>() else {
        return String::new();
    };
    let unwrapped = unwrap_mapped(parsed);
    if is_ip_target_allowed(unwrapped) {
        unwrapped.to_string()
    } else {
        String::new()
    }
}

fn url_split_parts(value: &str) -> Option<(String, String, String)> {
    let (scheme_raw, rest) = value.split_once("://")?;
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let after_auth = &rest[auth_end..];
    let path_end = after_auth.find(['?', '#']).unwrap_or(after_auth.len());
    let path = after_auth[..path_end].to_string();

    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    Some((
        scheme,
        host.to_ascii_lowercase().trim_end_matches('.').to_string(),
        path,
    ))
}

/// No DNS queries, HTTP requests, query strings or user-info in evidence.
pub fn url_host(value: &str) -> String {
    let Some((scheme, host, _)) = url_split_parts(value) else {
        return String::new();
    };
    if scheme != "http" && scheme != "https" {
        return String::new();
    }
    if host.is_empty() {
        return String::new();
    }
    if host.parse::<IpAddr>().is_ok() {
        return public_ip(&host);
    }
    if !(1..=253).contains(&host.len())
        || !host.contains('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return String::new();
    }
    if host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".invalid")
        || host.ends_with(".test")
    {
        return String::new();
    }
    host
}

// ---------------------------------------------------------------------------
// Bounded Python source analyzer (`source_evidence`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum LitVal {
    Str(String),
    Int(i64),
}

fn eval_literal(expr: &Expr, constants: &BTreeMap<String, LitVal>) -> Option<LitVal> {
    match expr {
        Expr::ConstStr(s) if s.chars().count() <= 4096 => Some(LitVal::Str(s.clone())),
        Expr::ConstInt(i) if i.abs() <= 1_000_000 => Some(LitVal::Int(*i)),
        Expr::Name(id) => constants.get(id).cloned(),
        Expr::Add(left, right) => match (eval_literal(left, constants), eval_literal(right, constants)) {
            (Some(LitVal::Str(mut l)), Some(LitVal::Str(r))) => {
                l.push_str(&r);
                if l.chars().count() <= 4096 {
                    Some(LitVal::Str(l))
                } else {
                    None
                }
            }
            (Some(LitVal::Int(l)), Some(LitVal::Int(r))) => {
                let sum = l.checked_add(r)?;
                if sum.abs() <= 1_000_000 {
                    Some(LitVal::Int(sum))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn matches_auth_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    const WORDS: &[&str] = &[
        "authenticate",
        "sessions",
        "session",
        "signin",
        "login",
        "token",
        "auth",
    ];
    for (idx, &b) in bytes.iter().enumerate() {
        if b != b'/' {
            continue;
        }
        let rest = &lower[idx + 1..];
        for word in WORDS {
            if let Some(after) = rest.strip_prefix(word) {
                if after.is_empty() || after.starts_with('/') || after.starts_with('?') {
                    return true;
                }
            }
        }
    }
    false
}

fn matches_dictionary_input(s: &str) -> bool {
    let lower = s.to_lowercase();
    const PATTERNS: &[&str] = &[
        "password",
        "passlist",
        "wordlist",
        "users",
        "usernames",
        "密码",
        "字典",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
}

fn matches_identity_generator(s: &str) -> bool {
    let lower = s.to_lowercase();
    const PREFIXES: &[&str] = &["generate", "gen", "random", "枚举", "生成"];
    const SUFFIXES: &[&str] = &[
        "id_card",
        "idcard",
        "id_number",
        "idnumber",
        "id_no",
        "idno",
        "identity",
        "身份证",
    ];
    for prefix in PREFIXES {
        let mut search_start = 0usize;
        while let Some(rel) = lower[search_start..].find(prefix) {
            let after_idx = search_start + rel + prefix.len();
            let tail = &lower[after_idx..];
            // Single-line semantics of regex `.`
            let line = tail.split('\n').next().unwrap_or("");
            if SUFFIXES.iter().any(|suf| line.contains(suf)) {
                return true;
            }
            search_start = after_idx;
        }
    }
    false
}

fn dict_string_keys(entries: &[crate::py_ast::DictEntry]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in entries {
        if let Some(Expr::ConstStr(s)) = entry.key.as_ref() {
            out.insert(s.to_lowercase());
        }
    }
    out
}

fn qualified_name(expr: &Expr, imports: &BTreeMap<String, String>) -> String {
    let Some(name) = expr.dotted_name() else {
        return String::new();
    };
    let (head, tail) = match name.split_once('.') {
        Some((h, t)) => (h, Some(t)),
        None => (name.as_str(), None),
    };
    let resolved_head = imports.get(head).map(String::as_str).unwrap_or(head);
    match tail {
        Some(t) => format!("{resolved_head}.{t}"),
        None => resolved_head.to_string(),
    }
}

fn sets_intersect(a: &BTreeSet<String>, list: &[&str]) -> bool {
    list.iter().any(|k| a.contains(*k))
}

/// Classify a running Python entrypoint; raw source exists only in memory.
pub fn source_evidence(source: Option<&str>) -> SourceEvidence {
    let Some(source) = source else {
        return SourceEvidence {
            available: false,
            reason: Some("source_unavailable_or_truncated".to_string()),
            sha256: None,
            kinds: Vec::new(),
            features: None,
            target_hosts: Vec::new(),
            targets_by_kind: BTreeMap::new(),
        };
    };
    if source.len() > SOURCE_LIMIT {
        return SourceEvidence {
            available: false,
            reason: Some("source_unavailable_or_truncated".to_string()),
            sha256: None,
            kinds: Vec::new(),
            features: None,
            target_hosts: Vec::new(),
            targets_by_kind: BTreeMap::new(),
        };
    }

    let digest = sha256_hex(source.as_bytes());
    let Ok(reachable_stmts) = parse_reachable_module(source) else {
        return SourceEvidence {
            available: false,
            reason: Some("source_unparseable".to_string()),
            sha256: Some(digest),
            kinds: Vec::new(),
            features: None,
            target_hosts: Vec::new(),
            targets_by_kind: BTreeMap::new(),
        };
    };
    let Ok(nodes) = collect_active_nodes(&reachable_stmts) else {
        return SourceEvidence {
            available: false,
            reason: Some("source_unparseable".to_string()),
            sha256: Some(digest),
            kinds: Vec::new(),
            features: None,
            target_hosts: Vec::new(),
            targets_by_kind: BTreeMap::new(),
        };
    };

    let mut imports: BTreeMap<String, String> = BTreeMap::new();
    let mut assignments: BTreeMap<String, Vec<&Expr>> = BTreeMap::new();
    for node in &nodes {
        if let ActiveNode::Stmt(stmt) = node {
            match stmt {
                Stmt::Import { names } => {
                    for (name, asname) in names {
                        let key = asname.as_ref().unwrap_or(name).clone();
                        imports.insert(key, name.clone());
                    }
                }
                Stmt::ImportFrom {
                    module: Some(module),
                    names,
                } => {
                    for (name, asname) in names {
                        let key = asname.as_ref().unwrap_or(name).clone();
                        imports.insert(key, format!("{module}.{name}"));
                    }
                }
                Stmt::Assign { targets, value } => {
                    for t in targets {
                        if let Expr::Name(id) = t {
                            assignments.entry(id.clone()).or_default().push(value);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut constants: BTreeMap<String, LitVal> = BTreeMap::new();
    for _ in 0..4 {
        for node in &nodes {
            if let ActiveNode::Stmt(Stmt::Assign { targets, value }) = node {
                if let Some(lit) = eval_literal(value, &constants) {
                    for t in targets {
                        if let Expr::Name(id) = t {
                            if assignments.get(id).is_some_and(|v| v.len() == 1) {
                                constants.insert(id.clone(), lit.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut sessions: BTreeSet<String> = BTreeSet::new();
    for node in &nodes {
        match node {
            ActiveNode::Stmt(Stmt::Assign {
                targets,
                value: Expr::Call { func, .. },
            }) => {
                let q = qualified_name(func, &imports);
                if matches!(
                    q.as_str(),
                    "requests.Session"
                        | "httpx.Client"
                        | "httpx.AsyncClient"
                        | "aiohttp.ClientSession"
                ) {
                    for t in targets {
                        if let Expr::Name(id) = t {
                            sessions.insert(id.clone());
                        }
                    }
                }
            }
            ActiveNode::Stmt(Stmt::With { items, .. }) => {
                for item in items {
                    if let Expr::Call { func, .. } = &item.context_expr {
                        let q = qualified_name(func, &imports);
                        if matches!(
                            q.as_str(),
                            "requests.Session"
                                | "aiohttp.ClientSession"
                                | "httpx.AsyncClient"
                                | "httpx.Client"
                        ) {
                            if let Some(ref var) = item.optional_var {
                                sessions.insert(var.clone());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let mut keys: BTreeSet<String> = BTreeSet::new();
    let mut workers: Vec<usize> = Vec::new();
    let mut request_count: usize = 0;
    let mut auth_endpoints: usize = 0;
    let mut identity_hosts: BTreeSet<String> = BTreeSet::new();
    let mut auth_hosts: BTreeSet<String> = BTreeSet::new();
    let mut enumeration = false;
    let mut dictionary_inputs = false;
    let mut identity_generator = false;
    let mut has_loop = false;

    for node in &nodes {
        match node {
            ActiveNode::Stmt(stmt) => match stmt {
                Stmt::For { .. } | Stmt::While { .. } => {
                    has_loop = true;
                }
                Stmt::FuncDef { name, .. } => {
                    if matches_identity_generator(name) {
                        identity_generator = true;
                    }
                }
                _ => {}
            },
            ActiveNode::Expr(expr) => match expr {
                Expr::Comprehension { .. } => {
                    has_loop = true;
                }
                Expr::Dict(entries) => {
                    keys.extend(dict_string_keys(entries));
                }
                Expr::Call {
                    func,
                    args,
                    keywords,
                } => {
                    let call = qualified_name(func, &imports);
                    let (root, method) = match call.split_once('.') {
                        Some((r, m)) => (r, m),
                        None => (call.as_str(), ""),
                    };
                    let raw_name = func.dotted_name().unwrap_or_default();
                    let raw_root = raw_name.split('.').next().unwrap_or("");
                    let method_leaf = method.rsplit('.').next().unwrap_or("");
                    let is_http = (matches!(root, "requests" | "httpx" | "aiohttp")
                        || sessions.contains(raw_root))
                        && matches!(method_leaf, "get" | "post" | "request" | "put");

                    if is_http {
                        request_count += 1;
                        let mut payload_keys: BTreeSet<String> = BTreeSet::new();
                        for kw in keywords {
                            if matches!(kw.arg.as_deref(), Some("data" | "json" | "params")) {
                                let mut payload = &kw.value;
                                if let Expr::Name(id) = payload {
                                    if let Some(list) = assignments.get(id) {
                                        if list.len() == 1 {
                                            payload = list[0];
                                        }
                                    }
                                }
                                if let Expr::Dict(entries) = payload {
                                    payload_keys.extend(dict_string_keys(entries));
                                }
                            }
                        }

                        let url_candidates = args.iter().chain(
                            keywords
                                .iter()
                                .filter(|kw| kw.arg.as_deref() == Some("url"))
                                .map(|kw| &kw.value),
                        );
                        for cand in url_candidates {
                            if let Some(LitVal::Str(url)) = eval_literal(cand, &constants) {
                                let host = url_host(&url);
                                if !host.is_empty() {
                                    let path = url_split_parts(&url)
                                        .map(|(_, _, p)| p)
                                        .unwrap_or_default();
                                    let authentication = matches_auth_path(&path);
                                    if authentication {
                                        auth_endpoints += 1;
                                    }
                                    if sets_intersect(&payload_keys, IDENTITY_KEYS) {
                                        identity_hosts.insert(host.clone());
                                    }
                                    if authentication
                                        && sets_intersect(&payload_keys, USERNAME_KEYS)
                                        && sets_intersect(&payload_keys, PASSWORD_KEYS)
                                    {
                                        auth_hosts.insert(host);
                                    }
                                }
                            }
                        }
                    }

                    if call.ends_with(".ThreadPoolExecutor")
                        || call.ends_with(".ProcessPoolExecutor")
                        || call.ends_with(".Semaphore")
                        || matches!(
                            call.as_str(),
                            "ThreadPoolExecutor" | "ProcessPoolExecutor" | "Semaphore"
                        )
                    {
                        let mut candidates: Vec<&Expr> = keywords
                            .iter()
                            .filter(|kw| kw.arg.as_deref() == Some("max_workers"))
                            .map(|kw| &kw.value)
                            .collect();
                        if let Some(first) = args.first() {
                            candidates.push(first);
                        }
                        for cand in candidates {
                            if let Some(LitVal::Int(v)) = eval_literal(cand, &constants) {
                                if v > 0 && v < 1_000_000 {
                                    workers.push(v as usize);
                                }
                            }
                        }
                    }

                    if matches!(
                        call.as_str(),
                        "itertools.product"
                            | "builtins.range"
                            | "range"
                            | "random.randint"
                            | "random.choice"
                            | "random.choices"
                            | "secrets.randbelow"
                    ) {
                        enumeration = true;
                    }

                    if matches!(call.as_str(), "open" | "pathlib.Path") {
                        if let Some(Expr::ConstStr(arg_str)) = args.first() {
                            if matches_dictionary_input(arg_str) {
                                dictionary_inputs = true;
                            }
                        }
                    }

                    if matches_identity_generator(&call) {
                        identity_generator = true;
                    }
                }
                _ => {}
            },
        }
    }

    let max_workers = workers.into_iter().max().unwrap_or(0);
    let concurrent = max_workers >= 20;
    let mut kinds = Vec::new();
    if !identity_hosts.is_empty()
        && request_count > 0
        && has_loop
        && enumeration
        && identity_generator
        && sets_intersect(&keys, IDENTITY_KEYS)
        && concurrent
    {
        kinds.push("identity_enumeration".to_string());
    }
    if !auth_hosts.is_empty()
        && auth_endpoints > 0
        && request_count > 0
        && has_loop
        && sets_intersect(&keys, USERNAME_KEYS)
        && sets_intersect(&keys, PASSWORD_KEYS)
        && dictionary_inputs
    {
        kinds.push(
            if enumeration {
                "credential_stuffing"
            } else {
                "authentication_bruteforce"
            }
            .to_string(),
        );
    }

    let target_hosts: Vec<String> = identity_hosts
        .union(&auth_hosts)
        .take(10)
        .cloned()
        .collect();
    let mut targets_by_kind = BTreeMap::new();
    for kind in &kinds {
        let hosts: Vec<String> = if kind == "identity_enumeration" {
            identity_hosts.iter().take(10).cloned().collect()
        } else {
            auth_hosts.iter().take(10).cloned().collect()
        };
        targets_by_kind.insert(kind.clone(), hosts);
    }

    SourceEvidence {
        available: true,
        reason: None,
        sha256: Some(digest),
        kinds,
        features: Some(SourceFeatures {
            http_calls: request_count,
            enumeration,
            dictionary_inputs,
            identity_generator,
            concurrency: max_workers,
            corroborating_samples: None,
        }),
        target_hosts,
        targets_by_kind,
    }
}

// ---------------------------------------------------------------------------
// Tool & Network & Process Evidence
// ---------------------------------------------------------------------------

enum ParsedNetwork {
    V4 {
        canonical: String,
        net: Ipv4Addr,
        bcast: Ipv4Addr,
    },
    V6 {
        canonical: String,
        net: Ipv6Addr,
        bcast: Ipv6Addr,
    },
}

fn parse_ip_network_lenient(raw: &str) -> Option<ParsedNetwork> {
    if raw.contains('%') {
        return None;
    }
    if let Some((ip_part, prefix_part)) = raw.split_once('/') {
        let prefix: u8 = prefix_part.parse().ok()?;
        match ip_part.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return None;
                }
                let mask: u32 = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let net_u32 = u32::from(v4) & mask;
                let bcast_u32 = net_u32 | !mask;
                let net = Ipv4Addr::from(net_u32);
                let bcast = Ipv4Addr::from(bcast_u32);
                Some(ParsedNetwork::V4 {
                    canonical: format!("{net}/{prefix}"),
                    net,
                    bcast,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return None;
                }
                let mask: u128 = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                let net_u128 = u128::from(v6) & mask;
                let bcast_u128 = net_u128 | !mask;
                let net = Ipv6Addr::from(net_u128);
                let bcast = Ipv6Addr::from(bcast_u128);
                Some(ParsedNetwork::V6 {
                    canonical: format!("{net}/{prefix}"),
                    net,
                    bcast,
                })
            }
        }
    } else {
        match raw.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => Some(ParsedNetwork::V4 {
                canonical: format!("{v4}/32"),
                net: v4,
                bcast: v4,
            }),
            IpAddr::V6(v6) => Some(ParsedNetwork::V6 {
                canonical: format!("{v6}/128"),
                net: v6,
                bcast: v6,
            }),
        }
    }
}

pub fn tool_evidence(argv: &[String]) -> Vec<Finding> {
    if argv.is_empty() || argv.len() > 256 {
        return Vec::new();
    }
    let tool = argv[0].rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    let is_scanner = SCANNERS.contains(&tool.as_str());
    let is_auth = AUTH_TOOLS.contains(&tool.as_str());
    if !is_scanner && !is_auth {
        return Vec::new();
    }

    let args: Vec<String> = argv[1..]
        .iter()
        .map(|v| v.chars().take(1024).collect())
        .collect();
    for arg in &args {
        if matches!(arg.as_str(), "--help" | "--version" | "-V" | "-sL")
            || (tool != "medusa" && arg == "-h")
        {
            return Vec::new();
        }
    }

    const IGNORED_OPTIONS: &[&str] = &[
        "--exclude",
        "--excludefile",
        "-S",
        "--source-ip",
        "-D",
        "-oN",
        "-oX",
        "-oG",
        "-oA",
        "-p",
        "--ports",
        "--rate",
        "--max-rate",
        "-l",
        "-L",
        "-P",
        "-u",
        "-U",
        "-m",
        "-M",
        "-t",
        "-T",
        "-I",
        "-iL",
        "--adapter-ip",
    ];

    let mut public_targets: BTreeMap<String, bool> = BTreeMap::new();
    let mut skip_value = false;
    for raw_arg in &args {
        if skip_value {
            skip_value = false;
            continue;
        }
        if IGNORED_OPTIONS.contains(&raw_arg.as_str()) {
            skip_value = true;
            continue;
        }
        let mut value = raw_arg.as_str();
        if tool == "patator" {
            if let Some(host_val) = value.strip_prefix("host=") {
                value = host_val;
            } else if value.contains('=') {
                continue;
            }
        }
        if value.starts_with('-') {
            if tool == "medusa" && value.starts_with("-h") && value.len() > 2 {
                value = &value[2..];
            } else if tool == "rustscan" && value.starts_with("--addresses=") {
                value = &value["--addresses=".len()..];
            } else {
                continue;
            }
        }
        let candidate = if value.contains("://") {
            url_split_parts(value).map(|(_, h, _)| h).unwrap_or_default()
        } else {
            value.to_string()
        };
        if let Some(net) = parse_ip_network_lenient(&candidate) {
            let (canonical, net_ip, bcast_ip) = match net {
                ParsedNetwork::V4 {
                    canonical,
                    net,
                    bcast,
                } => (canonical, IpAddr::V4(net), IpAddr::V4(bcast)),
                ParsedNetwork::V6 {
                    canonical,
                    net,
                    bcast,
                } => (canonical, IpAddr::V6(net), IpAddr::V6(bcast)),
            };
            if is_ip_target_allowed(unwrap_mapped(net_ip))
                && is_ip_target_allowed(unwrap_mapped(bcast_ip))
            {
                public_targets.insert(canonical, is_ip_global(net_ip));
            }
        }
    }

    if public_targets.is_empty() {
        return Vec::new();
    }

    let public_count = public_targets.values().filter(|&&g| g).count();
    let private_count = public_targets.len() - public_count;
    vec![Finding {
        kind: if is_scanner {
            "outbound_scan"
        } else {
            "authentication_bruteforce"
        }
        .to_string(),
        confidence: "high".to_string(),
        basis: "active_prohibited_tool".to_string(),
        pid: 0,
        start_ticks: String::new(),
        tool: Some(tool),
        source_sha256: None,
        features: None,
        target_hosts: Vec::new(),
        target_count: Some(public_targets.len()),
        public_target_count: Some(public_count),
        private_target_count: Some(private_count),
        owned_http_connections: None,
        pending_attempts: None,
        vertical_ports: None,
        horizontal_targets: None,
        pending_ratio: None,
        failed_ratio: None,
    }]
}

/// Require same-process TCP SYN fanout; inbound/CDN/TLS counts do not qualify.
pub fn network_evidence(sockets: &[SocketRecord]) -> Vec<Finding> {
    let mut owners: BTreeMap<u32, Vec<(String, u16, String)>> = BTreeMap::new();
    for item in sockets.iter().take(2000) {
        if item.direction != "outbound" || item.proto != "tcp" || item.pid < 1 {
            continue;
        }
        let ip = target_ip(&item.remote_ip);
        if ip.is_empty() {
            continue;
        }
        let Some(port_str) = item.remote.rsplit(':').next() else {
            continue;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let state = item.state.to_ascii_lowercase().replace('_', "-");
        owners.entry(item.pid).or_default().push((ip, port, state));
    }

    let mut findings = Vec::new();
    for (pid, flows) in owners {
        let mut attempts: BTreeSet<(String, u16)> = BTreeSet::new();
        let mut total: BTreeSet<(String, u16)> = BTreeSet::new();
        for (ip, port, state) in flows {
            if state == "syn-sent" || state == "syn-sent2" {
                attempts.insert((ip.clone(), port));
            }
            total.insert((ip, port));
        }
        let total_len = total.len().max(1);
        let ratio = (attempts.len() as f64) / (total_len as f64);
        if attempts.len() < 32 || ratio < 0.9 {
            continue;
        }

        let mut by_ip: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
        let mut by_port: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
        let mut unique_ips: BTreeSet<String> = BTreeSet::new();
        for (ip, port) in &attempts {
            by_ip.entry(ip.clone()).or_default().insert(*port);
            by_port.entry(*port).or_default().insert(ip.clone());
            unique_ips.insert(ip.clone());
        }
        let vertical = by_ip.values().map(BTreeSet::len).max().unwrap_or(0);
        let horizontal = by_port
            .iter()
            .filter(|(port, _)| SENSITIVE_PORTS.contains(port))
            .map(|(_, ips)| ips.len())
            .max()
            .unwrap_or(0);
        if vertical >= 32 || horizontal >= 64 {
            let public_target_count = unique_ips
                .iter()
                .filter(|ip| !public_ip(ip).is_empty())
                .count();
            let private_target_count = unique_ips.len() - public_target_count;
            let rounded_ratio = (ratio * 1000.0).round() / 1000.0;
            findings.push(Finding {
                kind: "outbound_scan".to_string(),
                confidence: "corroboration_required".to_string(),
                basis: "same_process_pending_fanout".to_string(),
                pid,
                start_ticks: String::new(),
                tool: None,
                source_sha256: None,
                features: None,
                target_hosts: Vec::new(),
                target_count: None,
                public_target_count: Some(public_target_count),
                private_target_count: Some(private_target_count),
                owned_http_connections: None,
                pending_attempts: Some(attempts.len()),
                vertical_ports: Some(vertical),
                horizontal_targets: Some(horizontal),
                pending_ratio: Some(rounded_ratio),
                failed_ratio: None,
            });
        }
    }
    findings
}

/// No raw argv/source in results. Source features need live process-owned egress.
pub fn evaluate_process(process: &ProcessRecord, sockets: &[SocketRecord]) -> Vec<Finding> {
    if process.pid < 1 || process.start_ticks.is_empty() {
        return Vec::new();
    }
    let exe_name = process
        .executable
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let argv0_name = process
        .argv
        .first()
        .map(|s| s.rsplit('/').next().unwrap_or("").to_ascii_lowercase())
        .unwrap_or_default();
    let mut result = if !process.argv.is_empty() && exe_name == argv0_name {
        tool_evidence(&process.argv)
    } else {
        Vec::new()
    };

    if let Some(ref src) = process.source {
        let source = source_evidence(Some(src));
        let active_egress: Vec<&SocketRecord> = sockets
            .iter()
            .filter(|s| {
                s.pid == process.pid
                    && s.direction == "outbound"
                    && !public_ip(&s.remote_ip).is_empty()
                    && s.proto == "tcp"
                    && matches!(
                        s.remote.rsplit(':').next(),
                        Some("80" | "443" | "8080" | "8443")
                    )
            })
            .collect();
        if !active_egress.is_empty() {
            let mut peers: BTreeSet<String> = BTreeSet::new();
            for s in &active_egress {
                peers.insert(s.remote_ip.clone());
                let pub_norm = public_ip(&s.remote_ip);
                if !pub_norm.is_empty() {
                    peers.insert(pub_norm);
                }
            }
            for kind in &source.kinds {
                let Some(hosts) = source.targets_by_kind.get(kind) else {
                    continue;
                };
                let mut matched_hosts = Vec::new();
                for host in hosts {
                    let mut candidates: BTreeSet<String> = BTreeSet::new();
                    let lit = public_ip(host);
                    if !lit.is_empty() {
                        candidates.insert(lit);
                    }
                    if let Some(resolved) = process.target_ips.get(host) {
                        for ip in resolved {
                            candidates.insert(ip.clone());
                        }
                    }
                    if candidates.iter().any(|c| peers.contains(c)) {
                        matched_hosts.push(host.clone());
                    }
                }
                if matched_hosts.is_empty() {
                    continue;
                }
                result.push(Finding {
                    kind: kind.clone(),
                    confidence: "high".to_string(),
                    basis: "running_entrypoint_and_owned_public_http".to_string(),
                    pid: process.pid,
                    start_ticks: String::new(),
                    tool: None,
                    source_sha256: source.sha256.clone(),
                    features: source.features.clone(),
                    target_hosts: matched_hosts,
                    target_count: None,
                    public_target_count: None,
                    private_target_count: None,
                    owned_http_connections: Some(active_egress.len()),
                    pending_attempts: None,
                    vertical_ports: None,
                    horizontal_targets: None,
                    pending_ratio: None,
                    failed_ratio: None,
                });
            }
        }
    }

    let ticks: String = process.start_ticks.chars().take(32).collect();
    for finding in &mut result {
        finding.pid = process.pid;
        finding.start_ticks = ticks.clone();
    }
    result
}
