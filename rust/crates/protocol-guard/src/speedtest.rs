//! Service-specific speed-test restrictions for isolated Incus/Podman/Runman containers.
//!
//! Migrated from `client/speedtest_guard.py` and `client/agent.py` (lines 2164-2197).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use net_guard::{CommandRunner, LiveCommandRunner, NetToolPaths};
use runtime_drivers::JsonVal;
use transport::{sha256_hex, TransportClient, TransportConfig};

use crate::util::{
    atomic_write_private, current_unix_secs, ip_sort_key, is_global_ip, is_safe_domain,
    json_str_list, resolve_env_path, truncate_chars, JsonBuilder,
};
use crate::vmess::{
    pid_epoch, reconcile_with, AlertContainerContext, DomainTarget, GuardEndpoint,
    ProtocolGuardAlert, ReconcileRequest, ServiceListener,
};

pub const SUPPORTED_RUNTIMES: &[&str] = &["incus", "podman", "runman"];
pub const SUPPORTED_SERVICES: &[&str] = &[
    "ookla",
    "cloudflare",
    "fast",
    "tcpquality",
    "iperf3_server",
    "librespeed",
    "openspeedtest",
    "ookla_server",
];
pub const INBOUND_SERVICES: &[&str] = &[
    "iperf3_server",
    "librespeed",
    "openspeedtest",
    "ookla_server",
];

pub const SERVICE_DOMAINS: &[(&str, &[&str])] = &[
    ("ookla", &["speedtest.net"]),
    ("cloudflare", &["speed.cloudflare.com"]),
    ("fast", &["fast.com", "www.fast.com"]),
    ("tcpquality", &["tcpquality.ibsgss.uk"]),
];

pub const FALLBACK_LEASEWEB_DOMAINS: &[&str] = &[
    "speedtest.hkg12.hk.leaseweb.net",
    "speedtest.tyo11.jp.leaseweb.net",
    "speedtest.sin1.sg.leaseweb.net",
    "speedtest.lax12.us.leaseweb.net",
    "speedtest.dal13.us.leaseweb.net",
    "speedtest.chi11.us.leaseweb.net",
    "speedtest.mtl2.ca.leaseweb.net",
    "speedtest.mia11.us.leaseweb.net",
    "speedtest.fra1.de.leaseweb.net",
    "speedtest.lon1.uk.leaseweb.net",
    "speedtest.ams1.nl.leaseweb.net",
    "speedtest.syd12.au.leaseweb.net",
];

pub const POLICY_FILE_ENV: &str = "NARWHAL_SPEEDTEST_POLICY_FILE";
pub const DEFAULT_POLICY_FILE: &str = "/var/lib/narwhal-agent/speedtest-service-policy.json";

pub const TARGET_CACHE_FILE_ENV: &str = "NARWHAL_SPEEDTEST_TARGET_CACHE_FILE";
pub const DEFAULT_TARGET_CACHE_FILE: &str = "/var/lib/narwhal-agent/speedtest-target-cache.json";

pub const HOSTS_BEGIN: &str = "# >>> NARWHAL SPEEDTEST TARGETS BEGIN >>>";
pub const HOSTS_END: &str = "# <<< NARWHAL SPEEDTEST TARGETS END <<<";

pub const TARGET_CACHE_TTL_SECONDS: i64 = 6 * 60 * 60;
pub const TARGET_RETRY_SECONDS: i64 = 10 * 60;
pub const MAX_TARGET_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TARGET_IPS: usize = 128;
pub const MAX_TARGET_DOMAINS: usize = 64;
pub const TCPQUALITY_LEASEWEB_PATTERN: &str = "speedtest.*.leaseweb.net";
pub const GET_NODES_URL: &str = "https://tcpquality.ibsgss.uk/getNodes?format=tsv&scope=tos";
pub const TCPQUALITY_CORE_URL: &str =
    "https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality-core.sh";

pub fn is_supported_runtime(rt: &str) -> bool {
    SUPPORTED_RUNTIMES.contains(&rt.trim().to_ascii_lowercase().as_str())
}

pub fn is_supported_service(svc: &str) -> bool {
    SUPPORTED_SERVICES.contains(&svc.trim().to_ascii_lowercase().as_str())
}

pub fn is_inbound_service(svc: &str) -> bool {
    INBOUND_SERVICES.contains(&svc.trim().to_ascii_lowercase().as_str())
}

pub fn service_domains_for(service: &str) -> &'static [&'static str] {
    let lower = service.trim().to_ascii_lowercase();
    for (name, domains) in SERVICE_DOMAINS {
        if *name == lower {
            return domains;
        }
    }
    &[]
}

/// Validates a LeaseWeb speedtest hostname matching `^speedtest(?:\.[a-z0-9-]+)+\.leaseweb\.net$`.
pub fn valid_leaseweb_domain(value: &str) -> String {
    let cleaned = value.trim().to_ascii_lowercase();
    let cleaned = cleaned.trim_end_matches('.');
    if cleaned.len() > 253 {
        return String::new();
    }
    let Some(rest) = cleaned.strip_prefix("speedtest.") else {
        return String::new();
    };
    let Some(mid) = rest.strip_suffix(".leaseweb.net") else {
        return String::new();
    };
    if mid.is_empty() {
        return String::new();
    }
    for seg in mid.split('.') {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return String::new();
        }
    }
    cleaned.to_string()
}

/// Assigns each protected hostname a deterministic RFC documentation IPv4/IPv6 sentinel pair:
/// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`.
pub fn domain_sentinel_targets<S: AsRef<str>>(domains: &[S]) -> Vec<DomainTarget> {
    let extra_service_domains: usize = SERVICE_DOMAINS.iter().map(|(_, d)| d.len()).sum();
    let maximum = MAX_TARGET_DOMAINS + extra_service_domains;

    let mut uniq = BTreeSet::new();
    for raw in domains {
        let candidate = raw
            .as_ref()
            .trim()
            .to_ascii_lowercase()
            .trim_end_matches('.')
            .to_string();
        if is_safe_domain(&candidate) {
            uniq.insert(candidate);
        }
    }

    let v4_bases: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];
    let v6_base: u128 = u128::from_be_bytes(
        "2001:db8::"
            .parse::<Ipv6Addr>()
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
            .octets(),
    );

    let mut result = Vec::new();
    for (index, domain) in uniq.into_iter().take(maximum).enumerate() {
        let network_index = index / 254;
        let host_index = index % 254;
        if network_index >= v4_bases.len() {
            break;
        }
        let b = v4_bases[network_index];
        let ipv4 = Ipv4Addr::new(b[0], b[1], b[2], (host_index + 1) as u8).to_string();
        let ipv6 = Ipv6Addr::from(v6_base + (index as u128) + 1).to_string();
        result.push(DomainTarget::new(domain.clone(), ipv4));
        result.push(DomainTarget::new(domain, ipv6));
    }
    result
}

pub fn public_ips<S: AsRef<str>>(values: &[S]) -> Vec<String> {
    let mut unique: BTreeMap<(u8, u128), String> = BTreeMap::new();
    for val in values {
        let Ok(addr) = val.as_ref().trim().parse::<IpAddr>() else {
            continue;
        };
        if is_global_ip(addr) {
            unique.insert(ip_sort_key(addr), addr.to_string());
        }
        if unique.len() >= MAX_TARGET_IPS {
            break;
        }
    }
    unique.into_values().collect()
}

// ===========================================================================
// 1. Policy Normalization, Loading, and Atomic `0o600` Persistence
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpeedtestPolicy {
    pub revision: i64,
    pub services: Vec<String>,
    pub runtimes: Vec<String>,
    pub invalid: bool,
}

impl SpeedtestPolicy {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.i64("revision", self.revision);
        b.raw("services", &json_str_list(&self.services));
        b.raw("runtimes", &json_str_list(&self.runtimes));
        if self.invalid {
            b.bool("invalid", true);
        }
        b.finish()
    }
}

pub fn resolve_policy_path() -> PathBuf {
    resolve_env_path(POLICY_FILE_ENV, DEFAULT_POLICY_FILE)
}

pub fn resolve_target_cache_path() -> PathBuf {
    resolve_env_path(TARGET_CACHE_FILE_ENV, DEFAULT_TARGET_CACHE_FILE)
}

/// Normalizes a speedtest policy `JsonVal`, filtering only supported services and runtimes.
pub fn normalize_policy(value: &JsonVal) -> SpeedtestPolicy {
    let Some(obj) = value.as_obj() else {
        return SpeedtestPolicy::default();
    };
    let revision = obj
        .get("revision")
        .and_then(JsonVal::as_i64)
        .filter(|&r| r >= 0)
        .unwrap_or(0);

    let mut services = BTreeSet::new();
    if let Some(arr) = obj.get("services").and_then(JsonVal::as_arr) {
        for item in arr {
            let s = item
                .as_str()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if is_supported_service(&s) {
                services.insert(s);
            }
        }
    }

    let mut runtimes = BTreeSet::new();
    if let Some(arr) = obj.get("runtimes").and_then(JsonVal::as_arr) {
        for item in arr {
            let r = item
                .as_str()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if is_supported_runtime(&r) {
                runtimes.insert(r);
            }
        }
    }

    let invalid = obj.get("invalid").and_then(JsonVal::as_bool) == Some(true);

    SpeedtestPolicy {
        revision,
        services: services.into_iter().collect(),
        runtimes: runtimes.into_iter().collect(),
        invalid,
    }
}

/// Loads the host-scoped speedtest policy from disk (`None` if file does not exist).
pub fn load_policy(path: Option<&Path>) -> Option<SpeedtestPolicy> {
    let default_buf;
    let target = match path {
        Some(p) => p,
        None => {
            default_buf = resolve_policy_path();
            &default_buf
        }
    };
    let raw = match fs::read_to_string(target) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::NotFound => return None,
        Err(_) => {
            return Some(SpeedtestPolicy {
                invalid: true,
                ..Default::default()
            })
        }
    };
    let Ok(val) = JsonVal::parse(raw.trim()) else {
        return Some(SpeedtestPolicy {
            invalid: true,
            ..Default::default()
        });
    };
    let mut policy = normalize_policy(&val);
    let Some(obj) = val.as_obj() else {
        policy.invalid = true;
        return Some(policy);
    };
    let rev_ok = obj.get("revision").and_then(JsonVal::as_i64).is_some();
    let raw_services = obj.get("services").and_then(JsonVal::as_arr);
    let raw_runtimes = obj.get("runtimes").and_then(JsonVal::as_arr);

    let invalid = !rev_ok
        || raw_services.is_none()
        || raw_runtimes.is_none()
        || raw_services.unwrap().iter().any(|item| {
            !is_supported_service(item.as_str().unwrap_or(""))
        })
        || raw_runtimes.unwrap().iter().any(|item| {
            !is_supported_runtime(item.as_str().unwrap_or(""))
        })
        || (!policy.services.is_empty() && policy.runtimes.is_empty());

    if invalid {
        policy.invalid = true;
    }
    Some(policy)
}

/// Atomically persists a host-scoped speedtest policy (`0o600` permissions) without exposing contents.
pub fn save_policy(value: &JsonVal, path: Option<&Path>) -> (bool, String) {
    let default_buf;
    let target = match path {
        Some(p) => p,
        None => {
            default_buf = resolve_policy_path();
            &default_buf
        }
    };
    let Some(obj) = value.as_obj() else {
        return (
            false,
            "speed-test policy revision is missing or invalid".to_string(),
        );
    };
    let Some(rev) = obj.get("revision").and_then(JsonVal::as_i64) else {
        return (
            false,
            "speed-test policy revision is missing or invalid".to_string(),
        );
    };
    if rev < 1 {
        return (
            false,
            "speed-test policy revision is missing or invalid".to_string(),
        );
    }

    let raw_services = match obj.get("services") {
        Some(JsonVal::Arr(arr)) => arr.as_slice(),
        None => &[][..],
        _ => {
            return (
                false,
                "speed-test service or runtime selection is invalid".to_string(),
            )
        }
    };
    let raw_runtimes = match obj.get("runtimes") {
        Some(JsonVal::Arr(arr)) => arr.as_slice(),
        None => &[][..],
        _ => {
            return (
                false,
                "speed-test service or runtime selection is invalid".to_string(),
            )
        }
    };

    if raw_services
        .iter()
        .any(|item| !is_supported_service(item.as_str().unwrap_or("")))
    {
        return (
            false,
            "unsupported speed-test service selection".to_string(),
        );
    }
    if raw_runtimes
        .iter()
        .any(|item| !is_supported_runtime(item.as_str().unwrap_or("")))
    {
        return (
            false,
            "unsupported container runtime selection".to_string(),
        );
    }

    let mut policy = normalize_policy(value);
    policy.invalid = false;
    if !policy.services.is_empty() && policy.runtimes.is_empty() {
        return (
            false,
            "select Incus and/or Podman before applying speed-test restrictions".to_string(),
        );
    }

    match atomic_write_private(target, policy.to_json().as_bytes(), ".speedtest-policy-") {
        Ok(()) => (true, "speed-test service policy saved".to_string()),
        Err(_) => (
            false,
            "speed-test service policy could not be persisted".to_string(),
        ),
    }
}

pub fn domains_for_services<S: AsRef<str>>(services: &[S]) -> Vec<String> {
    let mut selected = BTreeSet::new();
    for s in services {
        let lower = s.as_ref().trim().to_ascii_lowercase();
        if is_supported_service(&lower) {
            selected.insert(lower);
        }
    }
    let mut result = Vec::new();
    for svc in selected {
        for &domain in service_domains_for(&svc) {
            let d = domain.to_string();
            if !result.contains(&d) {
                result.push(d);
            }
        }
    }
    result
}

// ===========================================================================
// 2. TcpQuality Script/Nodes Parsing & Target Inventory Cache
// ===========================================================================

fn extract_first_ipv4_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let cand = &s[start..i];
            if cand.matches('.').count() == 3 {
                if let Ok(v4) = cand.parse::<Ipv4Addr>() {
                    return Some(v4.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Parses `runTcpQuality-core.sh` for LeaseWeb iPerf hostnames and domestic TOS fallback IPs.
pub fn parse_tcpquality_script(source: &str) -> (Vec<String>, Vec<String>) {
    if source.len() > MAX_TARGET_BYTES || !source.contains("INTERNATIONAL_IPERF_TARGETS") {
        return (Vec::new(), Vec::new());
    }

    let mut domains = BTreeSet::new();
    let mut in_block = false;
    let mut block_text = String::new();

    for line in source.lines() {
        let trimmed_start = line.trim_start();
        if !in_block {
            if let Some(rest) = line.strip_prefix("INTERNATIONAL_IPERF_TARGETS") {
                let after_eq = rest.trim_start();
                if let Some(after_open) = after_eq
                    .strip_prefix('=')
                    .map(str::trim_start)
                    .and_then(|s| s.strip_prefix('('))
                {
                    in_block = true;
                    block_text.push_str(after_open);
                    block_text.push('\n');
                }
            }
        } else if line.starts_with(')') || trimmed_start == ")" {
            break;
        } else {
            block_text.push_str(line);
            block_text.push('\n');
        }
    }

    let mut search = block_text.as_str();
    while let Some(open_q) = search.find('\'') {
        let rest = &search[open_q + 1..];
        let Some(close_q) = rest.find('\'') else {
            break;
        };
        let row = &rest[..close_q];
        if (1..=1024).contains(&row.len()) && !row.contains('\r') && !row.contains('\n') {
            let fields: Vec<&str> = row.split('|').collect();
            for &idx in &[3usize, 6, 8] {
                if let Some(&field) = fields.get(idx) {
                    let domain = valid_leaseweb_domain(field);
                    if !domain.is_empty() {
                        domains.insert(domain);
                    }
                }
            }
        }
        search = &rest[close_q + 1..];
    }

    let mut fallback_ips = Vec::new();
    for carrier in ["CT", "CU", "CM"] {
        let prefix = format!("SPEEDTEST_TOS_{carrier}_IP");
        for line in source.lines() {
            if let Some(rest) = line.strip_prefix(&prefix) {
                let trimmed = rest.trim_start();
                if let Some(rhs) = trimmed.strip_prefix('=') {
                    if let Some(ip) = extract_first_ipv4_literal(rhs) {
                        fallback_ips.push(ip);
                        break;
                    }
                }
            }
        }
    }

    let domain_list: Vec<String> = domains.into_iter().take(MAX_TARGET_DOMAINS).collect();
    (domain_list, public_ips(&fallback_ips))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TcpQualityNodesInventory {
    pub target_ips: Vec<String>,
    pub regions: Vec<String>,
}

/// Parses `getNodes?format=tsv&scope=tos` response into public domestic target IPs and regions.
pub fn parse_tcpquality_nodes(source: &str) -> TcpQualityNodesInventory {
    const CARRIERS: &[&str] = &[
        "电信",
        "ct",
        "chinatelecom",
        "china telecom",
        "联通",
        "cu",
        "chinaunicom",
        "china unicom",
        "移动",
        "cm",
        "chinamobile",
        "china mobile",
    ];
    const ALLOWED_REGIONS: &[&str] = &["cn-beijing", "cn-shanghai", "cn-guangzhou"];

    let mut ips = Vec::new();
    let mut regions = BTreeSet::new();

    for line in source.lines().take(10_000) {
        let clean_line = line.trim_end_matches('\r');
        let mut fields: Vec<&str> = clean_line.split('\t').collect();
        if fields.len() < 7 {
            fields = clean_line.split('|').collect();
        }
        if fields.len() < 7 || fields[0].trim().eq_ignore_ascii_case("type") {
            continue;
        }
        let kind = fields[0].trim().to_ascii_lowercase();
        let family = fields[1].trim();
        if !matches!(kind.as_str(), "tos" | "tosutil" | "speedtest") || family != "4" {
            continue;
        }
        let carrier = fields[3].trim().to_ascii_lowercase();
        if !CARRIERS.contains(&carrier.as_str()) {
            continue;
        }
        let target = fields
            .get(7)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let region = ALLOWED_REGIONS
            .iter()
            .copied()
            .find(|&r| target.contains(r))
            .unwrap_or(if target.is_empty() { "cn-beijing" } else { "" });

        if !region.is_empty() && fields.len() > 5 {
            let row_ips = public_ips(&[fields[5].trim()]);
            if !row_ips.is_empty() {
                ips.extend(row_ips);
                regions.insert(region.to_string());
            }
        }
    }

    TcpQualityNodesInventory {
        target_ips: public_ips(&ips),
        regions: regions.into_iter().collect(),
    }
}

/// Trait for bounded HTTPS fetching with host verification.
pub trait HttpsFetcher {
    fn fetch_https(&mut self, url: &str, allowed_host: &str) -> Result<String, String>;
}

/// Live HTTPS fetcher backed by `transport::TransportClient`.
pub struct LiveHttpsFetcher;

impl HttpsFetcher for LiveHttpsFetcher {
    fn fetch_https(&mut self, url: &str, allowed_host: &str) -> Result<String, String> {
        let Some(rest) = url.strip_prefix("https://") else {
            return Err("upstream_redirect_rejected".to_string());
        };
        let (host_part, path_part) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if !host_part.eq_ignore_ascii_case(allowed_host) {
            return Err("upstream_redirect_rejected".to_string());
        }
        let origin = format!("https://{allowed_host}");
        let cfg = TransportConfig::new(origin, "")
            .with_timeout(Duration::from_secs(5))
            .with_max_response_bytes(MAX_TARGET_BYTES);
        let client = TransportClient::new(cfg).map_err(|e| e.to_string())?;
        let resp = client
            .get_signed(path_part, false)
            .map_err(|e| e.to_string())?;
        if resp.status != 200 {
            return Err(format!("http_status_{}", resp.status));
        }
        let text = String::from_utf8(resp.body).map_err(|_| "invalid_utf8".to_string())?;
        Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
    }
}

/// Trait for resolving LeaseWeb speedtest domain names into IP addresses.
pub trait DnsResolver {
    fn resolve_domain(&mut self, domain: &str) -> Vec<IpAddr>;
}

/// Live DNS resolver backed by `std::net::ToSocketAddrs`.
pub struct LiveDnsResolver;

impl DnsResolver for LiveDnsResolver {
    fn resolve_domain(&mut self, domain: &str) -> Vec<IpAddr> {
        match (domain, 80u16).to_socket_addrs() {
            Ok(iter) => iter.map(|sa| sa.ip()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

pub fn resolve_target_domains(domains: &[String], resolver: &mut dyn DnsResolver) -> Vec<String> {
    let mut raw_ips = Vec::new();
    for domain in domains.iter().take(MAX_TARGET_DOMAINS) {
        for ip in resolver.resolve_domain(domain) {
            if is_global_ip(ip) {
                raw_ips.push(ip.to_string());
            }
            if raw_ips.len() >= MAX_TARGET_IPS {
                break;
            }
        }
        if raw_ips.len() >= MAX_TARGET_IPS {
            break;
        }
    }
    public_ips(&raw_ips)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetInventory {
    pub schema: i64,
    pub refreshed_at: i64,
    pub source: String,
    pub script_sha256: String,
    pub domains: Vec<String>,
    pub target_ips: Vec<String>,
    pub state: String,
    pub reason: String,
}

impl TargetInventory {
    pub fn to_cache_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.i64("schema", 1);
        b.i64("refreshed_at", self.refreshed_at);
        b.str("source", &self.source);
        b.str("script_sha256", &self.script_sha256);
        b.raw("domains", &json_str_list(&self.domains));
        b.raw("target_ips", &json_str_list(&self.target_ips));
        b.finish()
    }
}

pub fn read_target_cache(path: &Path) -> Option<TargetInventory> {
    let raw = fs::read_to_string(path).ok()?;
    let val = JsonVal::parse(raw.trim()).ok()?;
    let obj = val.as_obj()?;
    if obj.get("schema").and_then(JsonVal::as_i64) != Some(1) {
        return None;
    }
    let refreshed_at = obj.get("refreshed_at").and_then(JsonVal::as_i64).unwrap_or(0);
    let mut domains_set = BTreeSet::new();
    if let Some(arr) = obj.get("domains").and_then(JsonVal::as_arr) {
        for item in arr {
            let d = valid_leaseweb_domain(item.as_str().unwrap_or(""));
            if !d.is_empty() {
                domains_set.insert(d);
            }
        }
    }
    let domains: Vec<String> = domains_set.into_iter().take(MAX_TARGET_DOMAINS).collect();
    let raw_ips: Vec<String> = obj
        .get("target_ips")
        .and_then(JsonVal::as_arr)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonVal::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    let ips = public_ips(&raw_ips);
    if refreshed_at <= 0 || domains.is_empty() || ips.is_empty() {
        return None;
    }
    let source = truncate_chars(
        obj.get("source")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("cache"),
        80,
    );
    let script_sha256 = truncate_chars(
        obj.get("script_sha256")
            .and_then(JsonVal::as_str)
            .unwrap_or(""),
        64,
    );

    Some(TargetInventory {
        schema: 1,
        refreshed_at,
        source,
        script_sha256,
        domains,
        target_ips: ips,
        state: "stale".to_string(),
        reason: String::new(),
    })
}

pub fn write_target_cache(path: &Path, inv: &TargetInventory) -> bool {
    atomic_write_private(path, inv.to_cache_json().as_bytes(), ".speedtest-targets-").is_ok()
}

#[derive(Debug, Default, Clone)]
pub struct TargetInventoryCacheState {
    pub memory: Option<TargetInventory>,
    pub retry_after: i64,
}

static TARGET_CACHE_STATE: Mutex<TargetInventoryCacheState> = Mutex::new(TargetInventoryCacheState {
    memory: None,
    retry_after: 0,
});

/// Evaluates and caches bounded TcpQuality target inventory (`tcpquality_target_inventory`).
pub fn tcpquality_target_inventory_with(
    now_unix: i64,
    force_refresh: bool,
    cache_path: &Path,
    state: &mut TargetInventoryCacheState,
    fetcher: &mut dyn HttpsFetcher,
    resolver: &mut dyn DnsResolver,
) -> TargetInventory {
    let cached = state.memory.clone().or_else(|| read_target_cache(cache_path));
    state.memory = cached.clone();

    if let Some(ref c) = cached {
        if now_unix.saturating_sub(c.refreshed_at) < TARGET_CACHE_TTL_SECONDS {
            if c.state == "partial" {
                let mut out = c.clone();
                if out.reason.is_empty() {
                    out.reason = "upstream_inventory_incomplete".to_string();
                }
                return out;
            }
            let mut out = c.clone();
            out.state = "fresh".to_string();
            out.reason.clear();
            return out;
        }
    }

    if !force_refresh && now_unix < state.retry_after {
        if let Some(ref c) = cached {
            let mut out = c.clone();
            out.state = if c.state == "partial" {
                "partial".to_string()
            } else {
                "stale".to_string()
            };
            out.reason = "refresh_backoff".to_string();
            return out;
        }
    }

    state.retry_after = now_unix + TARGET_RETRY_SECONDS;

    let source_text = fetcher
        .fetch_https(TCPQUALITY_CORE_URL, "raw.githubusercontent.com")
        .unwrap_or_default();
    let nodes_text = fetcher
        .fetch_https(GET_NODES_URL, "tcpquality.ibsgss.uk")
        .unwrap_or_default();

    let (mut domains, script_fallback_ips) = parse_tcpquality_script(&source_text);
    let script_targets_valid = !source_text.is_empty() && !domains.is_empty();
    let nodes_inventory = parse_tcpquality_nodes(&nodes_text);
    let nodes_ips = nodes_inventory.target_ips;

    if domains.is_empty() && source_text.is_empty() {
        domains = FALLBACK_LEASEWEB_DOMAINS
            .iter()
            .map(|&s| s.to_string())
            .collect();
    }
    let mut combined_tos = nodes_ips.clone();
    combined_tos.extend(script_fallback_ips);
    let tos_ips = public_ips(&combined_tos);

    if domains.is_empty() {
        domains = FALLBACK_LEASEWEB_DOMAINS
            .iter()
            .map(|&s| s.to_string())
            .collect();
    }
    let mut valid_domains = BTreeSet::new();
    for item in &domains {
        let d = valid_leaseweb_domain(item);
        if !d.is_empty() {
            valid_domains.insert(d);
        }
    }
    let domains: Vec<String> = valid_domains.into_iter().take(MAX_TARGET_DOMAINS).collect();
    let leaseweb_ips = resolve_target_domains(&domains, resolver);

    let mut all_new_ips = tos_ips;
    all_new_ips.extend(leaseweb_ips.clone());
    let new_ips = public_ips(&all_new_ips);

    let has_all_regions = nodes_inventory.regions.len() == 3
        && nodes_inventory.regions.contains(&"cn-beijing".to_string())
        && nodes_inventory.regions.contains(&"cn-shanghai".to_string())
        && nodes_inventory.regions.contains(&"cn-guangzhou".to_string());

    let complete = script_targets_valid
        && !nodes_text.is_empty()
        && !nodes_ips.is_empty()
        && has_all_regions
        && !leaseweb_ips.is_empty();

    if let Some(ref c) = cached {
        if !complete && c.state != "partial" {
            let mut out = c.clone();
            out.state = "stale".to_string();
            out.reason = "upstream_inventory_incomplete".to_string();
            return out;
        }
    }

    if new_ips.is_empty() {
        if let Some(ref c) = cached {
            if c.state != "partial" {
                let mut out = c.clone();
                out.state = "stale".to_string();
                out.reason = "target_resolution_failed".to_string();
                return out;
            }
        }
        let mut fb_domains = vec!["tcpquality.ibsgss.uk".to_string()];
        fb_domains.extend(FALLBACK_LEASEWEB_DOMAINS.iter().map(|&s| s.to_string()));
        let fallback = TargetInventory {
            schema: 1,
            refreshed_at: now_unix,
            source: "fallback".to_string(),
            script_sha256: String::new(),
            domains: fb_domains,
            target_ips: Vec::new(),
            state: "partial".to_string(),
            reason: "upstream_unavailable".to_string(),
        };
        state.memory = Some(fallback.clone());
        return fallback;
    }

    let script_sha = if source_text.is_empty() {
        String::new()
    } else {
        sha256_hex(source_text.as_bytes())
    };

    if complete {
        let value = TargetInventory {
            schema: 1,
            refreshed_at: now_unix,
            source: "tcpquality_script+getNodes".to_string(),
            script_sha256: script_sha,
            domains,
            target_ips: new_ips,
            state: "fresh".to_string(),
            reason: String::new(),
        };
        write_target_cache(cache_path, &value);
        state.memory = Some(value.clone());
        return value;
    }

    if let Some(ref c) = cached {
        if c.state != "partial" {
            let mut out = c.clone();
            out.state = "stale".to_string();
            out.reason = "upstream_inventory_incomplete".to_string();
            return out;
        }
    }

    let mut partial_domains = vec!["tcpquality.ibsgss.uk".to_string()];
    partial_domains.extend(domains);
    let partial = TargetInventory {
        schema: 1,
        refreshed_at: now_unix,
        source: "tcpquality_partial_fallback".to_string(),
        script_sha256: script_sha,
        domains: partial_domains,
        target_ips: new_ips,
        state: "partial".to_string(),
        reason: "upstream_inventory_incomplete".to_string(),
    };
    state.memory = Some(partial.clone());
    partial
}

/// Live convenience wrapper for `tcpquality_target_inventory_with`.
pub fn tcpquality_target_inventory(now_unix: Option<i64>, force_refresh: bool) -> TargetInventory {
    let now = now_unix.unwrap_or_else(current_unix_secs);
    let cache_path = resolve_target_cache_path();
    let mut fetcher = LiveHttpsFetcher;
    let mut resolver = LiveDnsResolver;
    let mut guard = match TARGET_CACHE_STATE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    tcpquality_target_inventory_with(
        now,
        force_refresh,
        &cache_path,
        &mut guard,
        &mut fetcher,
        &mut resolver,
    )
}

// ===========================================================================
// 3. `/etc/hosts` Script, Inbound Service Probes, & `reconcile_container`
// ===========================================================================

/// Generates the managed `/etc/hosts` reconciliation shell script (`_hosts_script`).
pub fn hosts_script<S: AsRef<str>>(domains: &[S]) -> String {
    let targets = domain_sentinel_targets(domains);
    let mut domain_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for item in targets {
        domain_map.entry(item.domain).or_default().push(item.ip);
    }
    let sorted_domains: Vec<String> = domain_map.keys().cloned().collect();

    let mut block_lines = Vec::new();
    block_lines.push(HOSTS_BEGIN.to_string());
    for domain in &sorted_domains {
        if let Some(ips) = domain_map.get(domain) {
            for ip in ips {
                block_lines.push(format!("{ip} {domain}"));
            }
        }
    }
    block_lines.push(HOSTS_END.to_string());
    let block = block_lines.join("\n");
    let expected = if sorted_domains.is_empty() {
        ""
    } else {
        block.as_str()
    };

    let mut lines = vec![
        "set -eu".to_string(),
        "f=/etc/hosts".to_string(),
        "[ -f \"$f\" ] && [ ! -L \"$f\" ] || { echo hosts_file_unavailable; exit 21; }".to_string(),
        format!("begin='{HOSTS_BEGIN}'"),
        format!("end='{HOSTS_END}'"),
        "bc=$(grep -Fxc \"$begin\" \"$f\" || true)".to_string(),
        "ec=$(grep -Fxc \"$end\" \"$f\" || true)".to_string(),
        "[ \"$bc:$ec\" = 0:0 ] || [ \"$bc:$ec\" = 1:1 ] || { echo hosts_marker_invalid; exit 22; }"
            .to_string(),
        format!("current=$(sed -n '/^{HOSTS_BEGIN}$/,/^{HOSTS_END}$/p' \"$f\")"),
        "expected=$(cat <<'NARWHAL_EXPECTED'".to_string(),
        expected.to_string(),
        "NARWHAL_EXPECTED".to_string(),
        ")".to_string(),
        "if [ \"$current\" = \"$expected\" ]; then echo hosts_policy_readback_ok; exit 0; fi"
            .to_string(),
        "tmp=$(mktemp /etc/hosts.narwhal.XXXXXX) || { echo hosts_tempfile_failed; exit 23; }"
            .to_string(),
        "if ! awk -v begin=\"$begin\" -v end=\"$end\" '".to_string(),
        "  $0 == begin { if (skip) exit 31; skip=1; next }".to_string(),
        "  $0 == end { if (!skip) exit 32; skip=0; next }".to_string(),
        "  !skip { print }".to_string(),
        "  END { if (skip) exit 33 }".to_string(),
        "' \"$f\" > \"$tmp\"; then rm -f \"$tmp\"; echo hosts_marker_invalid; exit 22; fi"
            .to_string(),
    ];

    if !sorted_domains.is_empty() {
        lines.push("cat >> \"$tmp\" <<'NARWHAL_BLOCK'".to_string());
        lines.push(block);
        lines.push("NARWHAL_BLOCK".to_string());
    }
    lines.push("chmod --reference=\"$f\" \"$tmp\" 2>/dev/null || chmod 0644 \"$tmp\"".to_string());
    lines.push(
        "mv -f \"$tmp\" \"$f\" || { rm -f \"$tmp\"; echo hosts_replace_failed; exit 24; }"
            .to_string(),
    );

    if !sorted_domains.is_empty() {
        lines.push(
            "grep -Fqx \"$begin\" \"$f\" && grep -Fqx \"$end\" \"$f\" || { echo hosts_readback_failed; exit 25; }"
                .to_string(),
        );
        for domain in &sorted_domains {
            if let Some(ips) = domain_map.get(domain) {
                for ip in ips {
                    lines.push(format!(
                        "grep -Fqx '{ip} {domain}' \"$f\" || {{ echo hosts_readback_failed; exit 25; }}"
                    ));
                }
            }
        }
    }
    lines.push("echo hosts_policy_readback_ok".to_string());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Trait for executing guest shell scripts inside a container (`speedtest_guard` runner).
pub trait GuestScriptRunner {
    fn run_script(&mut self, script: &str) -> (bool, String);
}

impl<F> GuestScriptRunner for F
where
    F: FnMut(&str) -> (bool, String),
{
    fn run_script(&mut self, script: &str) -> (bool, String) {
        self(script)
    }
}

/// Checks web root `index.html` files for LibreSpeed / OpenSpeedTest markers (`_service_config_markers`).
pub fn service_config_markers(
    runner: &mut dyn GuestScriptRunner,
) -> (BTreeSet<String>, Vec<String>, bool) {
    let script = "set -eu\n\
found=0\n\
for f in /config/www/index.html /var/www/html/index.html /var/www/html/openspeedtest/index.html /app/index.html /app/public/index.html /usr/share/nginx/html/index.html /usr/share/nginx/html/openspeedtest/index.html /usr/share/caddy/index.html /usr/share/openspeedtest/index.html /opt/openspeedtest/index.html; do\n\
  [ -f \"$f\" ] || continue\n\
  if grep -Eiq 'LibreSpeed|librespeed' \"$f\" 2>/dev/null; then printf 'librespeed:%s\\n' \"$f\"; found=1; fi\n\
  if grep -Eiq 'OpenSpeedTest|openspeedtest' \"$f\" 2>/dev/null; then printf 'openspeedtest:%s\\n' \"$f\"; found=1; fi\n\
done\n\
[ \"$found\" -eq 1 ] || exit 1\n";

    let (ok, output) = runner.run_script(script);
    let mut services = BTreeSet::new();
    let mut markers = Vec::new();
    for line in output.lines() {
        if let Some((svc, path)) = line.split_once(':') {
            if matches!(svc, "librespeed" | "openspeedtest") && path.starts_with('/') {
                services.insert(svc.to_string());
                markers.push(truncate_chars(path, 180));
            }
        }
    }
    let complete = ok && !markers.is_empty();
    markers.truncate(8);
    (services, markers, complete)
}

/// Determines whether `pid` is running `iperf3`/`iperf` in server or client mode (`_iperf_mode`).
pub fn iperf_mode(runner: &mut dyn GuestScriptRunner, pid: u32) -> &'static str {
    if !(2..=4_194_304).contains(&pid) {
        return "unverified";
    }
    let script = format!(
        "set -eu\n\
p='{pid}'\n\
[ -r \"/proc/$p/comm\" ] && [ -r \"/proc/$p/cmdline\" ] || exit 31\n\
comm=$(cat \"/proc/$p/comm\" 2>/dev/null || true)\n\
case \"$comm\" in iperf3|iperf) ;; *) echo changed; exit 32 ;; esac\n\
args=$(tr '\\000' ' ' < \"/proc/$p/cmdline\" 2>/dev/null || true)\n\
case \" $args \" in\n\
  *' --server '*|*' -s '*|*' -sD '*|*' --server=*) echo server ;;\n\
  *' --client '*|*' -c '*|*' --client=*) echo client ;;\n\
  *) echo other ;;\n\
esac\n"
    );
    let (ok, output) = runner.run_script(&script);
    if !ok {
        return "unverified";
    }
    match output.trim().lines().last().unwrap_or("") {
        "server" => "server",
        "client" => "client",
        "other" => "other",
        "changed" => "changed",
        _ => "unverified",
    }
}

/// Determines whether `pid` is running Ookla Server (`_ookla_server_mode`).
pub fn ookla_server_mode(runner: &mut dyn GuestScriptRunner, pid: u32) -> &'static str {
    if !(2..=4_194_304).contains(&pid) {
        return "unverified";
    }
    let script = format!(
        "set -eu\n\
p='{pid}'\n\
[ -r \"/proc/$p/comm\" ] && [ -r \"/proc/$p/cmdline\" ] && [ -e \"/proc/$p/exe\" ] || exit 31\n\
comm=$(cat \"/proc/$p/comm\" 2>/dev/null || true)\n\
exe=$(readlink \"/proc/$p/exe\" 2>/dev/null || true)\n\
args=$(tr '\\000' ' ' < \"/proc/$p/cmdline\" 2>/dev/null || true)\n\
value=$(printf '%s %s %s' \"$comm\" \"$exe\" \"$args\" | tr '[:upper:]' '[:lower:]')\n\
case \"$value\" in *ooklaserver*|*ookla-server*) echo server ;; *) echo other ;; esac\n"
    );
    let (ok, output) = runner.run_script(&script);
    if !ok {
        return "unverified";
    }
    match output.trim().lines().last().unwrap_or("") {
        "server" => "server",
        "other" => "other",
        _ => "unverified",
    }
}

/// Matches container image string against `librespeed` and `openspeedtest` (`_image_services`).
pub fn image_services(image: &str) -> BTreeSet<String> {
    let lower = image.trim().to_ascii_lowercase();
    let mut services = BTreeSet::new();
    if lower.contains("librespeed") {
        services.insert("librespeed".to_string());
    }
    if lower.contains("openspeedtest") || lower.contains("open-speedtest") {
        services.insert("openspeedtest".to_string());
    }
    services
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedSpeedtestAttempt {
    pub service: String,
    pub target: String,
    pub packets: u64,
}

impl BlockedSpeedtestAttempt {
    pub fn to_json(&self) -> String {
        let mut b = JsonBuilder::new();
        b.str("service", &self.service);
        b.str("target", &self.target);
        b.u64("packets", self.packets);
        b.finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpeedtestGuardStatus {
    pub state: String,
    pub reason: String,
    pub observed_at: i64,
    pub policy_revision: i64,
    pub services: Vec<String>,
    pub detected_services: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub hosts_state: String,
    pub domain_targets_state: String,
    pub domain_target_pattern: String,
    pub domain_target_count: usize,
    pub blocked_endpoints: Vec<GuardEndpoint>,
    pub blocked_destination_ips: Vec<String>,
    pub blocked_attempts: Vec<BlockedSpeedtestAttempt>,
    pub destination_state: String,
    pub target_inventory_state: String,
    pub target_inventory_reason: String,
    pub target_inventory_refreshed_at: Option<i64>,
    pub target_inventory_source: String,
    pub target_domains: Vec<String>,
    pub target_ip_count: usize,
    pub listener_inventory_complete: bool,
    pub configuration_evidence: Vec<String>,
    pub reason_detail: String,
}

impl SpeedtestGuardStatus {
    pub fn to_json(&self) -> String {
        let ep_json: Vec<String> = self
            .blocked_endpoints
            .iter()
            .map(GuardEndpoint::to_json)
            .collect();
        let att_json: Vec<String> = self
            .blocked_attempts
            .iter()
            .map(BlockedSpeedtestAttempt::to_json)
            .collect();

        let mut b = JsonBuilder::new();
        b.str("state", &self.state);
        b.str("reason", &self.reason);
        b.i64("observed_at", self.observed_at);
        b.i64("policy_revision", self.policy_revision);
        b.raw("services", &json_str_list(&self.services));
        b.raw("detected_services", &json_str_list(&self.detected_services));
        b.raw("blocked_domains", &json_str_list(&self.blocked_domains));
        b.str("hosts_state", &self.hosts_state);
        b.str("domain_targets_state", &self.domain_targets_state);
        b.str("domain_target_pattern", &self.domain_target_pattern);
        b.usize("domain_target_count", self.domain_target_count);
        b.raw("blocked_endpoints", &format!("[{}]", ep_json.join(",")));
        b.raw(
            "blocked_destination_ips",
            &json_str_list(&self.blocked_destination_ips),
        );
        b.raw("blocked_attempts", &format!("[{}]", att_json.join(",")));
        b.str("destination_state", &self.destination_state);
        b.str("target_inventory_state", &self.target_inventory_state);
        b.str("target_inventory_reason", &self.target_inventory_reason);
        match self.target_inventory_refreshed_at {
            Some(ts) => b.i64("target_inventory_refreshed_at", ts),
            None => b.raw("target_inventory_refreshed_at", "null"),
        }
        b.str("target_inventory_source", &self.target_inventory_source);
        b.raw("target_domains", &json_str_list(&self.target_domains));
        b.usize("target_ip_count", self.target_ip_count);
        b.bool(
            "listener_inventory_complete",
            self.listener_inventory_complete,
        );
        b.raw(
            "configuration_evidence",
            &json_str_list(&self.configuration_evidence),
        );
        b.str("reason_detail", &self.reason_detail);
        b.finish()
    }
}

#[derive(Debug, Default, Clone)]
pub struct SpeedtestReconcileCaches {
    pub hosts_cache: BTreeMap<(String, String, String), (i64, Vec<String>)>,
    pub cleanup_cache: BTreeSet<((String, String, String), i64)>,
    pub guard_cleanup_cache: BTreeSet<((String, String, String), i64)>,
}

#[derive(Debug, Clone)]
pub struct SpeedtestContainerInput<'a> {
    pub runtime: &'a str,
    pub name: &'a str,
    pub project: &'a str,
    pub identity: &'a str,
    pub pid: u32,
    pub namespace_epoch: &'a str,
    pub network_shared: bool,
    pub image: &'a str,
    pub listeners: &'a [ServiceListener],
    pub listener_inventory_complete: bool,
    pub policy: &'a SpeedtestPolicy,
    pub observed_at: Option<i64>,
}

/// Reconciles speed-test outbound domain/IP rules and inbound service port rules for one container.
#[allow(clippy::too_many_arguments)]
pub fn reconcile_container_with(
    input: &SpeedtestContainerInput<'_>,
    guest_runner: Option<&mut dyn GuestScriptRunner>,
    target_inventory_override: Option<TargetInventory>,
    caches: &mut SpeedtestReconcileCaches,
    tools: &NetToolPaths,
    host_runner: &mut dyn CommandRunner,
    proc_root: &Path,
    epoch_fn: &mut dyn FnMut(u32) -> String,
) -> SpeedtestGuardStatus {
    let now = input.observed_at.unwrap_or_else(current_unix_secs);
    let runtime = input.runtime.trim().to_ascii_lowercase();
    let name = truncate_chars(input.name, 200);
    let identity_str = if input.identity.is_empty() {
        truncate_chars(&name, 240)
    } else {
        truncate_chars(input.identity, 240)
    };

    if input.policy.invalid {
        return SpeedtestGuardStatus {
            state: "unverified".to_string(),
            reason: "policy_invalid".to_string(),
            observed_at: now,
            hosts_state: "unverified".to_string(),
            destination_state: "unverified".to_string(),
            listener_inventory_complete: false,
            ..Default::default()
        };
    }

    if !is_supported_runtime(&runtime) || name.is_empty() {
        return SpeedtestGuardStatus {
            state: "unsupported".to_string(),
            reason: "runtime_not_supported".to_string(),
            observed_at: now,
            ..Default::default()
        };
    }

    let selected: Vec<String> = if input.policy.runtimes.contains(&runtime) {
        input.policy.services.clone()
    } else {
        Vec::new()
    };
    let mut selected_domains = domains_for_services(&selected);
    let has_tcpquality = selected.iter().any(|s| s == "tcpquality");

    let target_inventory: Option<TargetInventory> = if has_tcpquality {
        Some(
            target_inventory_override
                .unwrap_or_else(|| tcpquality_target_inventory(Some(now), false)),
        )
    } else {
        None
    };

    let mut requested_destination_ips = Vec::new();
    if let Some(ref inv) = target_inventory {
        for d in &inv.domains {
            if !selected_domains.contains(d) {
                selected_domains.push(d.clone());
            }
        }
        if matches!(inv.state.as_str(), "fresh" | "stale" | "partial") {
            requested_destination_ips = public_ips(&inv.target_ips);
        }
    }

    let listener_rows: Vec<&ServiceListener> = input
        .listeners
        .iter()
        .filter(|l| {
            matches!(l.proto.to_ascii_lowercase().as_str(), "tcp" | "udp")
                && l.port > 0
                && l.pid <= 4_194_304
        })
        .collect();

    let mut endpoint_targets: BTreeMap<(String, u16), BTreeSet<u32>> = BTreeMap::new();
    let mut detected = BTreeSet::new();
    let mut pending = false;
    let complete = input.listener_inventory_complete;
    let mut config_paths = Vec::new();
    let web_processes = ["nginx", "httpd", "apache2", "lighttpd", "caddy", "openresty"];

    let mut guest_runner = guest_runner;
    if !selected.is_empty() && complete {
        if let Some(ref mut gr) = guest_runner {
            let img_services = image_services(input.image);
            let candidate_web = !img_services.is_empty()
                || listener_rows
                    .iter()
                    .any(|item| web_processes.contains(&item.process.to_ascii_lowercase().as_str()));
            let wants_web_service = selected
                .iter()
                .any(|s| matches!(s.as_str(), "librespeed" | "openspeedtest"));

            let (config_services, markers, config_complete) =
                if candidate_web && wants_web_service {
                    service_config_markers(*gr)
                } else {
                    (BTreeSet::new(), Vec::new(), true)
                };
            config_paths = markers;
            if candidate_web && !config_complete && wants_web_service {
                pending = true;
            }

            let confirmed_web_services: BTreeSet<String> = img_services
                .intersection(&config_services)
                .filter(|s| selected.contains(*s))
                .cloned()
                .collect();

            for item in &listener_rows {
                let proc_lower = item.process.to_ascii_lowercase();
                if !web_processes.contains(&proc_lower.as_str()) || item.pid <= 1 {
                    continue;
                }
                for svc in &confirmed_web_services {
                    detected.insert(svc.clone());
                    endpoint_targets
                        .entry((item.proto.to_ascii_lowercase(), item.port))
                        .or_default()
                        .insert(item.pid);
                }
            }

            if selected.iter().any(|s| s == "iperf3_server") {
                for item in &listener_rows {
                    let proc_lower = item.process.to_ascii_lowercase();
                    if !matches!(proc_lower.as_str(), "iperf3" | "iperf") || item.pid <= 1 {
                        continue;
                    }
                    match iperf_mode(*gr, item.pid) {
                        "server" => {
                            detected.insert("iperf3_server".to_string());
                            endpoint_targets
                                .entry((item.proto.to_ascii_lowercase(), item.port))
                                .or_default()
                                .insert(item.pid);
                        }
                        "unverified" => pending = true,
                        _ => {}
                    }
                }
            }

            if selected.iter().any(|s| s == "ookla_server") {
                for item in &listener_rows {
                    let proc_lower = item.process.to_ascii_lowercase();
                    if !matches!(proc_lower.as_str(), "ooklaserver" | "ookla_server")
                        || item.pid <= 1
                    {
                        continue;
                    }
                    match ookla_server_mode(*gr, item.pid) {
                        "server" => {
                            detected.insert("ookla_server".to_string());
                            endpoint_targets
                                .entry((item.proto.to_ascii_lowercase(), item.port))
                                .or_default()
                                .insert(item.pid);
                        }
                        "unverified" => pending = true,
                        _ => {}
                    }
                }
            }
        } else if selected.iter().any(|s| is_inbound_service(s)) {
            pending = true;
        }
    } else if selected.iter().any(|s| is_inbound_service(s)) {
        pending = true;
    }

    let mut live_listeners = Vec::new();
    for item in &listener_rows {
        let key = (item.proto.to_ascii_lowercase(), item.port);
        let is_owner = item.pid > 1
            && endpoint_targets
                .get(&key)
                .map_or(false, |set| set.contains(&item.pid));
        live_listeners.push(ServiceListener {
            pid: item.pid,
            process: item.process.to_ascii_lowercase(),
            proto: key.0,
            local: item.local.clone(),
            port: item.port,
            application_protocols: if is_owner {
                vec!["speedtest".to_string()]
            } else {
                Vec::new()
            },
            application_protocol_evidence: if is_owner {
                "config_matches_live_pid_and_port".to_string()
            } else {
                String::new()
            },
            protocol_port_config_complete_protocols: Vec::new(),
            protocol_process_scan_complete: is_owner && complete,
            vmess_process_scan_complete: false,
            speedtest_process_scan_complete: is_owner && complete,
        });
    }

    let endpoints: Vec<GuardEndpoint> = endpoint_targets
        .keys()
        .map(|(proto, port)| GuardEndpoint::new_port(proto.clone(), *port))
        .collect();

    let current_epoch = if input.pid > 1 {
        epoch_fn(input.pid)
    } else {
        String::new()
    };
    let effective_epoch = if !current_epoch.is_empty() {
        current_epoch.as_str()
    } else {
        input.namespace_epoch
    };

    let cache_key = (
        runtime.clone(),
        identity_str.clone(),
        effective_epoch.to_string(),
    );
    let cleanup_key = (cache_key.clone(), input.policy.revision);

    let has_inbound_guard = selected.iter().any(|s| is_inbound_service(s));
    let has_namespace_guard =
        has_inbound_guard || has_tcpquality || !selected_domains.is_empty();
    let should_cleanup_guard =
        !has_namespace_guard && !caches.guard_cleanup_cache.contains(&cleanup_key);

    let requested_domain_targets = domain_sentinel_targets(&selected_domains);

    let guard = if !selected.is_empty() && has_namespace_guard {
        let endpoint_req: Option<&[GuardEndpoint]> = if complete && !pending {
            Some(&endpoints)
        } else {
            None
        };
        let dest_req: Option<&[String]> = if has_tcpquality {
            if target_inventory
                .as_ref()
                .map(|t| t.state.as_str())
                == Some("fresh")
            {
                Some(&requested_destination_ips)
            } else {
                None
            }
        } else {
            Some(&[])
        };
        let preserve = !complete
            || pending
            || target_inventory
                .as_ref()
                .map_or(false, |t| t.state != "fresh");
        let req = ReconcileRequest {
            pid: input.pid,
            identity: &identity_str,
            expected_epoch: effective_epoch,
            endpoints: endpoint_req,
            destination_ips: dest_req,
            domain_targets: Some(&requested_domain_targets),
            host_network: input.network_shared,
            release_if_absent: complete && !pending,
            live_listeners: if complete && !pending {
                Some(&live_listeners)
            } else {
                None
            },
            preserve_existing: preserve,
            application_protocol: "speedtest",
        };
        reconcile_with(&req, tools, host_runner, proc_root, epoch_fn)
    } else if should_cleanup_guard {
        let req = ReconcileRequest {
            pid: input.pid,
            identity: &identity_str,
            expected_epoch: effective_epoch,
            endpoints: Some(&[]),
            destination_ips: Some(&[]),
            domain_targets: Some(&[]),
            host_network: input.network_shared,
            release_if_absent: false,
            live_listeners: if complete {
                Some(&live_listeners)
            } else {
                None
            },
            preserve_existing: false,
            application_protocol: "speedtest",
        };
        let g = reconcile_with(&req, tools, host_runner, proc_root, epoch_fn);
        if g.state == "cleared" {
            caches.guard_cleanup_cache.insert(cleanup_key.clone());
        }
        g
    } else {
        crate::vmess::ReconcileOutcome {
            state: "cleared".to_string(),
            reason: String::new(),
            ..Default::default()
        }
    };

    let domains_key = (input.policy.revision, selected_domains.clone());
    let mut blocked_domains = Vec::new();
    let should_update_hosts = caches.hosts_cache.get(&cache_key) != Some(&domains_key);
    let hosts_state = if !selected_domains.is_empty()
        || should_update_hosts
        || !caches.cleanup_cache.contains(&cleanup_key)
    {
        if let Some(ref mut gr) = guest_runner {
            let script = hosts_script(&selected_domains);
            let (ok, output) = gr.run_script(&script);
            if ok && output.contains("hosts_policy_readback_ok") {
                blocked_domains = selected_domains.clone();
                caches.hosts_cache.insert(cache_key, domains_key);
                caches.cleanup_cache.insert(cleanup_key);
                if selected_domains.is_empty() {
                    "cleared".to_string()
                } else {
                    "blocked".to_string()
                }
            } else {
                "unverified".to_string()
            }
        } else {
            "unverified".to_string()
        }
    } else {
        blocked_domains = selected_domains.clone();
        if selected_domains.is_empty() {
            "cleared".to_string()
        } else {
            "blocked".to_string()
        }
    };

    let domain_target_keys: BTreeSet<(&str, &str)> = guard
        .blocked_domain_targets
        .iter()
        .map(|dt| (dt.domain.as_str(), dt.ip.as_str()))
        .collect();
    let domain_targets_ok = selected_domains.is_empty()
        || (guard.state == "blocked"
            && domain_target_keys.len() == requested_domain_targets.len()
            && requested_domain_targets
                .iter()
                .all(|dt| domain_target_keys.contains(&(dt.domain.as_str(), dt.ip.as_str()))));

    let effective_domains = if hosts_state == "blocked" && domain_targets_ok {
        selected_domains.clone()
    } else {
        Vec::new()
    };

    let destination_state = if has_tcpquality {
        if requested_destination_ips.is_empty() {
            "unverified".to_string()
        } else {
            let blocked_ip_set: BTreeSet<&str> = guard
                .blocked_destination_ips
                .iter()
                .map(String::as_str)
                .collect();
            let all_present = requested_destination_ips
                .iter()
                .all(|ip| blocked_ip_set.contains(ip.as_str()));
            if guard.state == "blocked" && all_present {
                if target_inventory
                    .as_ref()
                    .map(|t| t.state.as_str())
                    == Some("fresh")
                {
                    "blocked".to_string()
                } else {
                    "stale".to_string()
                }
            } else {
                "unverified".to_string()
            }
        }
    } else {
        "not_required".to_string()
    };

    let mut state = if !effective_domains.is_empty()
        || !guard.blocked_endpoints.is_empty()
        || !guard.blocked_destination_ips.is_empty()
    {
        "blocked".to_string()
    } else {
        "not_detected".to_string()
    };
    let mut reason = guard.reason.clone();

    if !selected_domains.is_empty() && (hosts_state == "unverified" || !domain_targets_ok) {
        state = if !guard.blocked_endpoints.is_empty() || !guard.blocked_destination_ips.is_empty()
        {
            "partial".to_string()
        } else {
            "unverified".to_string()
        };
        reason = if hosts_state == "unverified" {
            "hosts_policy_unverified".to_string()
        } else {
            "domain_drop_readback_unverified".to_string()
        };
    }

    if !selected.is_empty() && pending {
        state = if !guard.blocked_endpoints.is_empty()
            || !blocked_domains.is_empty()
            || !guard.blocked_destination_ips.is_empty()
        {
            "partial".to_string()
        } else {
            "unverified".to_string()
        };
        if reason.is_empty() {
            reason = "service_evidence_incomplete".to_string();
        }
    }

    if has_tcpquality
        && (destination_state != "blocked"
            || target_inventory
                .as_ref()
                .map_or(true, |t| t.state != "fresh"))
    {
        state = if !blocked_domains.is_empty()
            || !guard.blocked_destination_ips.is_empty()
            || !guard.blocked_endpoints.is_empty()
        {
            "partial".to_string()
        } else {
            "unverified".to_string()
        };
        if reason.is_empty() {
            reason = target_inventory
                .as_ref()
                .map(|t| t.reason.clone())
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| {
                    if target_inventory.is_none() {
                        "target_inventory_unavailable".to_string()
                    } else {
                        "target_inventory_stale".to_string()
                    }
                });
        }
    }

    let detected_inbound = detected.iter().any(|s| is_inbound_service(s));
    if has_inbound_guard && detected_inbound && guard.state != "blocked" {
        state = if !blocked_domains.is_empty() || !guard.blocked_destination_ips.is_empty() {
            "partial".to_string()
        } else {
            "unverified".to_string()
        };
        if reason.is_empty() {
            reason = "firewall_readback_unverified".to_string();
        }
    }

    let mut blocked_attempts = Vec::new();
    if guard.state == "blocked" && !selected.is_empty() {
        let mut services_by_domain: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for svc_name in &selected {
            for &domain in service_domains_for(svc_name) {
                services_by_domain
                    .entry(domain.to_string())
                    .or_default()
                    .insert(svc_name.clone());
            }
        }
        if has_tcpquality {
            if let Some(ref inv) = target_inventory {
                for domain in &inv.domains {
                    services_by_domain
                        .entry(domain.clone())
                        .or_default()
                        .insert("tcpquality".to_string());
                }
            }
        }

        let mut attempts_by_key: BTreeMap<(String, String), u64> = BTreeMap::new();
        for hit in &guard.blocked_domain_hits {
            if hit.packets == 0 {
                continue;
            }
            let domain = hit.domain.to_ascii_lowercase();
            let mut candidates = services_by_domain
                .get(&domain)
                .cloned()
                .unwrap_or_default();
            if candidates.is_empty()
                && has_tcpquality
                && !valid_leaseweb_domain(&domain).is_empty()
            {
                candidates.insert("tcpquality".to_string());
            }
            for svc_name in candidates {
                *attempts_by_key
                    .entry((svc_name, domain.clone()))
                    .or_insert(0) += hit.packets;
            }
        }

        if has_tcpquality {
            for hit in &guard.blocked_destination_hits {
                if hit.packets == 0 {
                    continue;
                }
                *attempts_by_key
                    .entry(("tcpquality".to_string(), hit.ip.clone()))
                    .or_insert(0) += hit.packets;
            }
        }

        blocked_attempts = attempts_by_key
            .into_iter()
            .take(32)
            .map(|((service, target), packets)| BlockedSpeedtestAttempt {
                service,
                target,
                packets,
            })
            .collect();
    }

    let domain_targets_state = if domain_targets_ok
        && !selected_domains.is_empty()
        && guard.state == "blocked"
    {
        "blocked".to_string()
    } else if !selected_domains.is_empty() {
        "unverified".to_string()
    } else {
        "not_required".to_string()
    };

    let show_config_evidence = !selected.is_empty()
        && selected
            .iter()
            .any(|s| matches!(s.as_str(), "librespeed" | "openspeedtest"));

    SpeedtestGuardStatus {
        state,
        reason,
        observed_at: now,
        policy_revision: input.policy.revision,
        services: selected,
        detected_services: detected.into_iter().collect(),
        blocked_domains: effective_domains,
        hosts_state,
        domain_targets_state,
        domain_target_pattern: if has_tcpquality {
            TCPQUALITY_LEASEWEB_PATTERN.to_string()
        } else {
            String::new()
        },
        domain_target_count: requested_domain_targets.len(),
        blocked_endpoints: guard.blocked_endpoints.into_iter().take(32).collect(),
        blocked_destination_ips: guard
            .blocked_destination_ips
            .into_iter()
            .take(MAX_TARGET_IPS)
            .collect(),
        blocked_attempts,
        destination_state,
        target_inventory_state: target_inventory
            .as_ref()
            .map(|t| t.state.clone())
            .unwrap_or_else(|| "not_required".to_string()),
        target_inventory_reason: target_inventory
            .as_ref()
            .map(|t| t.reason.clone())
            .unwrap_or_default(),
        target_inventory_refreshed_at: target_inventory.as_ref().map(|t| t.refreshed_at),
        target_inventory_source: target_inventory
            .as_ref()
            .map(|t| t.source.clone())
            .unwrap_or_default(),
        target_domains: target_inventory
            .as_ref()
            .map(|t| t.domains.iter().take(MAX_TARGET_DOMAINS).cloned().collect())
            .unwrap_or_default(),
        target_ip_count: target_inventory
            .as_ref()
            .map(|t| t.target_ips.len())
            .unwrap_or(0),
        listener_inventory_complete: complete,
        configuration_evidence: if show_config_evidence {
            config_paths.into_iter().take(8).collect()
        } else {
            Vec::new()
        },
        reason_detail: if pending {
            "service evidence incomplete".to_string()
        } else {
            String::new()
        },
    }
}

static RECONCILE_CACHES: Mutex<Option<SpeedtestReconcileCaches>> = Mutex::new(None);

/// Live convenience wrapper for `reconcile_container_with`.
pub fn reconcile_container(
    input: &SpeedtestContainerInput<'_>,
    guest_runner: Option<&mut dyn GuestScriptRunner>,
) -> SpeedtestGuardStatus {
    let tools = NetToolPaths::discover();
    let mut host_runner = LiveCommandRunner;
    let mut epoch_fn = pid_epoch;
    let mut guard = match RECONCILE_CACHES.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let caches = guard.get_or_insert_with(SpeedtestReconcileCaches::default);
    reconcile_container_with(
        input,
        guest_runner,
        None,
        caches,
        &tools,
        &mut host_runner,
        Path::new("/proc"),
        &mut epoch_fn,
    )
}

fn speedtest_service_alert_name(service: &str) -> &'static str {
    match service {
        "ookla" => "Ookla Speedtest",
        "cloudflare" => "Cloudflare Speed Test",
        "fast" => "FAST.com",
        "tcpquality" => "TcpQuality / Lisaweb",
        "iperf3_server" => "iPerf3 服务端",
        "librespeed" => "LibreSpeed",
        "openspeedtest" => "OpenSpeedTest",
        "ookla_server" => "Ookla 自建测速服务",
        _ => "测速服务",
    }
}

/// Builds the `speedtest_attempt_blocked` alert matching `client/agent.py` lines 2164-2197.
pub fn build_speedtest_attempt_blocked_alert(
    speedtest: &SpeedtestGuardStatus,
    container: &AlertContainerContext,
) -> Option<ProtocolGuardAlert> {
    if !is_supported_runtime(&container.runtime) {
        return None;
    }
    let mut targets = BTreeSet::new();
    for item in speedtest.blocked_attempts.iter().take(32) {
        if is_supported_service(&item.service) && !item.target.is_empty() && item.packets > 0 {
            targets.insert((item.service.clone(), item.target.clone()));
        }
    }
    if targets.is_empty() {
        return None;
    }

    let target_labels: Vec<String> = targets
        .iter()
        .take(8)
        .map(|(svc, target)| format!("{}（{target}）", speedtest_service_alert_name(svc)))
        .collect();
    let has_leaseweb = targets
        .iter()
        .any(|(svc, target)| svc == "tcpquality" && !valid_leaseweb_domain(target).is_empty());

    let suffix = if has_leaseweb {
        "；Leaseweb 目标匹配规则：speedtest.*.leaseweb.net。这是管理员设置的资源保护策略，不代表认定用户滥用；未停止进程或容器。"
    } else {
        "。这是管理员设置的资源保护策略，不代表认定用户滥用；未停止进程或容器。"
    };
    let detail = format!(
        "检测到容器发起了受限测速目标的连接请求，网络规则已拦截：{}{}",
        target_labels.join("、"),
        suffix
    );

    let key_parts: Vec<String> = targets
        .iter()
        .map(|(svc, target)| format!("{svc}:{target}"))
        .collect();

    Some(ProtocolGuardAlert {
        alert_type: "speedtest_attempt_blocked".to_string(),
        severity: "warning".to_string(),
        title: "测速连接请求已拦截".to_string(),
        message: detail,
        value: 1,
        threshold: 1,
        runtime: container.runtime.clone(),
        project: container.project.clone(),
        container_name: container.name.clone(),
        instance_id: truncate_chars(&container.instance_id, 200),
        alert_key: format!("speedtest-attempt:{}", key_parts.join(",")),
        guard_field_name: "speedtest_guard".to_string(),
        guard_json: speedtest.to_json(),
        automatic_remediation: None,
        context: container.clone(),
    })
}

#[cfg(test)]
#[path = "speedtest_tests.rs"]
mod tests;
