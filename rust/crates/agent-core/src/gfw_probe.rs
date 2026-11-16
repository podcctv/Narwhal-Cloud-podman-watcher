#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use net_probe::is_global_ipv4;
use proc_probe::json_escape;
use transport::{sha256_hex, TransportClient};

use crate::actions::{parse_json, JsonValue};

static GFW_WORKER_BUSY: AtomicBool = AtomicBool::new(false);

const FAILURE_CODES: &[&str] = &[
    "probe_source_identity_mismatch",
    "invalid_probe_identity",
    "invalid_probe_lease",
    "invalid_probe_deadline",
    "invalid_target_count",
    "invalid_target_fields",
    "invalid_target_endpoint",
    "invalid_target_identity",
    "invalid_targets_hash",
    "incomplete_probe_results",
    "probe_runtime_unavailable",
    "probe_worker_busy",
    "probe_worker_error",
];

#[derive(Debug, Clone)]
pub struct GfwProbeTarget {
    pub id: String,
    pub ip: IpAddr,
    pub port: u16,
    pub interface: String,
}

#[derive(Debug, Clone)]
pub struct GfwProbeJob {
    pub id: String,
    pub cycle_id: String,
    pub source_host_id: String,
    pub source_node_id: String,
    pub target_host_id: String,
    pub target_node_id: String,
    pub lease: String,
    pub deadline_at: u64,
    pub targets_hash: String,
    pub targets: Vec<GfwProbeTarget>,
}

#[derive(Debug, Clone)]
pub struct GfwProbeResultItem {
    pub target_id: String,
    pub success: bool,
    pub latency_ms: Option<f64>,
    pub error: String,
    pub attempts: u32,
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn gfw_probe_available() -> bool {
    #[cfg(unix)]
    {
        Path::new("/proc/self/ns/net").exists()
            && !Path::new("/.dockerenv").exists()
            && !Path::new("/run/.containerenv").exists()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub fn route_capabilities_from(proc_root: &Path) -> (Option<bool>, Option<bool>) {
    let v4 = fs::read_to_string(proc_root.join("net/route"))
        .ok()
        .map(|raw| {
            raw.lines().skip(1).any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                fields.len() >= 8
                    && fields[1] == "00000000"
                    && fields[7] == "00000000"
                    && u64::from_str_radix(fields[3], 16)
                        .map(|flags| (flags & 1) != 0)
                        .unwrap_or(false)
            })
        });
    let v6 = fs::read_to_string(proc_root.join("net/ipv6_route"))
        .ok()
        .map(|raw| {
            let zero32 = "0".repeat(32);
            raw.lines().any(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                fields.len() >= 10
                    && fields[0] == zero32
                    && fields[1] == "00"
                    && u64::from_str_radix(fields[8], 16)
                        .map(|flags| (flags & 1) != 0)
                        .unwrap_or(false)
            })
        });
    (v4, v6)
}

fn opt_bool_json(val: Option<bool>) -> &'static str {
    match val {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    }
}

pub fn route_capabilities_json(proc_root: &Path) -> String {
    let (v4, v6) = route_capabilities_from(proc_root);
    format!(
        "{{\"ipv4_default_route\":{},\"ipv6_default_route\":{}}}",
        opt_bool_json(v4),
        opt_bool_json(v6)
    )
}

fn is_job_uuid_like(s: &str) -> bool {
    s.len() == 36
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
}

fn is_valid_lease(s: &str) -> bool {
    (32..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_safe_identity_text(s: &str, max_bytes: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_bytes
        && !s.chars().any(|c| (c as u32) < 32 || (c as u32) == 127)
}

fn is_global_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ipv4(mapped);
            }
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unicast_link_local()
                && !v6.is_unique_local()
        }
    }
}

fn canonical_target_json(target: &GfwProbeTarget) -> String {
    // Keys sorted alphabetically matching Python json.dumps(..., sort_keys=True, separators=(",", ":"))
    format!(
        "{{\"id\":\"{}\",\"interface\":\"{}\",\"ip\":\"{}\",\"port\":{}}}",
        json_escape(&target.id),
        json_escape(&target.interface),
        json_escape(&target.ip.to_string()),
        target.port
    )
}

fn canonical_target_identity_hash(
    host_id: &str,
    ip: &str,
    port: u16,
    interface: &str,
) -> String {
    let payload = format!(
        "{{\"host_id\":\"{}\",\"interface\":\"{}\",\"ip\":\"{}\",\"port\":{}}}",
        json_escape(host_id),
        json_escape(interface),
        json_escape(ip),
        port
    );
    sha256_hex(payload.as_bytes())[..24].to_string()
}

pub fn validate_job(
    job: &JsonValue,
    host_id: &str,
    node_id: &str,
    now_secs: u64,
) -> Result<GfwProbeJob, &'static str> {
    let obj = job.as_object().ok_or("probe_source_identity_mismatch")?;
    let source_host = obj
        .get("source_host_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let source_node = obj
        .get("source_node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if source_host != host_id || source_node != node_id {
        return Err("probe_source_identity_mismatch");
    }

    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| is_job_uuid_like(s))
        .ok_or("invalid_probe_identity")?
        .to_string();
    let cycle_id = obj
        .get("cycle_id")
        .and_then(|v| v.as_str())
        .filter(|s| is_job_uuid_like(s))
        .ok_or("invalid_probe_identity")?
        .to_string();
    let target_host_id = obj
        .get("target_host_id")
        .and_then(|v| v.as_str())
        .filter(|s| is_safe_identity_text(s, 200))
        .ok_or("invalid_probe_identity")?
        .to_string();
    let target_node_id = obj
        .get("target_node_id")
        .and_then(|v| v.as_str())
        .filter(|s| is_safe_identity_text(s, 128))
        .ok_or("invalid_probe_identity")?
        .to_string();

    let role = obj.get("role").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(role, "mainland" | "overseas") {
        return Err("invalid_probe_lease");
    }
    let lease = obj
        .get("lease")
        .and_then(|v| v.as_str())
        .filter(|s| is_valid_lease(s))
        .ok_or("invalid_probe_lease")?
        .to_string();

    let deadline_at = obj
        .get("deadline_at")
        .and_then(|v| v.as_u64())
        .ok_or("invalid_probe_deadline")?;
    if deadline_at <= now_secs || deadline_at - now_secs > 660 {
        return Err("invalid_probe_deadline");
    }

    let raw_targets = obj
        .get("targets")
        .and_then(|v| v.as_array())
        .ok_or("invalid_target_count")?;
    if !(1..=8).contains(&raw_targets.len()) {
        return Err("invalid_target_count");
    }

    let mut targets = Vec::with_capacity(raw_targets.len());
    let mut seen_ids = BTreeSet::new();
    let mut canonical_list = String::from("[");
    for (idx, raw_t) in raw_targets.iter().enumerate() {
        let t_obj = raw_t.as_object().ok_or("invalid_target_fields")?;
        if t_obj.len() != 4
            || !t_obj.contains_key("id")
            || !t_obj.contains_key("ip")
            || !t_obj.contains_key("port")
            || !t_obj.contains_key("interface")
        {
            return Err("invalid_target_fields");
        }
        let t_id = t_obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("invalid_target_endpoint")?
            .to_string();
        let t_iface = t_obj
            .get("interface")
            .and_then(|v| v.as_str())
            .filter(|s| s.len() <= 32)
            .ok_or("invalid_target_endpoint")?
            .to_string();
        let port_u64 = t_obj
            .get("port")
            .and_then(|v| v.as_u64())
            .filter(|p| (1..=65535).contains(p))
            .ok_or("invalid_target_endpoint")?;
        let port = port_u64 as u16;
        let ip_raw = t_obj
            .get("ip")
            .and_then(|v| v.as_str())
            .ok_or("invalid_target_endpoint")?;
        let ip: IpAddr = ip_raw.parse().map_err(|_| "invalid_target_endpoint")?;
        if !is_global_ip(ip) {
            return Err("invalid_target_endpoint");
        }
        let expected_id = canonical_target_identity_hash(&target_host_id, &ip.to_string(), port, &t_iface);
        if t_id != expected_id || !seen_ids.insert(t_id.clone()) {
            return Err("invalid_target_identity");
        }
        let target = GfwProbeTarget {
            id: t_id,
            ip,
            port,
            interface: t_iface,
        };
        if idx > 0 {
            canonical_list.push(',');
        }
        canonical_list.push_str(&canonical_target_json(&target));
        targets.push(target);
    }
    canonical_list.push(']');

    let targets_hash = obj
        .get("targets_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if sha256_hex(canonical_list.as_bytes()) != targets_hash {
        return Err("invalid_targets_hash");
    }

    Ok(GfwProbeJob {
        id,
        cycle_id,
        source_host_id: host_id.to_string(),
        source_node_id: node_id.to_string(),
        target_host_id,
        target_node_id,
        lease,
        deadline_at,
        targets_hash,
        targets,
    })
}

fn classify_connect_error(err: &std::io::Error) -> &'static str {
    match err.kind() {
        ErrorKind::TimedOut => "timeout",
        ErrorKind::ConnectionRefused => "refused",
        ErrorKind::PermissionDenied => "local_policy_block",
        _ => match err.raw_os_error() {
            Some(97) => "family_unsupported",        // EAFNOSUPPORT
            Some(93) => "family_unsupported",        // EPROTONOSUPPORT
            Some(101) | Some(100) | Some(99) | Some(19) => "no_route", // ENETUNREACH/ENETDOWN/EADDRNOTAVAIL/ENODEV
            Some(113) | Some(112) => "host_unreachable",               // EHOSTUNREACH/EHOSTDOWN
            _ => "network_error",
        },
    }
}

pub fn probe_target_tcp(target: &GfwProbeTarget) -> GfwProbeResultItem {
    let sock_addr = match target.ip {
        IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), target.port),
        IpAddr::V6(v6) => SocketAddr::new(IpAddr::V6(v6), target.port),
    };
    let mut attempts = 0u32;
    let mut last_error = "timeout";
    let mut latency_ms: Option<f64> = None;

    for _ in 0..2 {
        attempts += 1;
        let started = Instant::now();
        match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(2)) {
            Ok(_) => {
                latency_ms = Some((started.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0);
                break;
            }
            Err(err) => {
                last_error = classify_connect_error(&err);
            }
        }
        if attempts < 2 {
            thread::sleep(Duration::from_millis(100));
        }
    }

    let success = latency_ms.is_some();
    GfwProbeResultItem {
        target_id: target.id.clone(),
        success,
        latency_ms,
        error: if success {
            String::new()
        } else {
            last_error.to_string()
        },
        attempts,
    }
}

fn serialize_failure_json(
    job: &JsonValue,
    host_id: &str,
    node_id: &str,
    failure_code: &str,
) -> Option<String> {
    let obj = job.as_object()?;
    if obj.get("source_host_id").and_then(|v| v.as_str()) != Some(host_id)
        || obj.get("source_node_id").and_then(|v| v.as_str()) != Some(node_id)
    {
        return None;
    }
    let job_id = obj.get("id").and_then(|v| v.as_str()).filter(|s| is_safe_identity_text(s, 256))?;
    let cycle_id = obj.get("cycle_id").and_then(|v| v.as_str()).filter(|s| is_safe_identity_text(s, 256))?;
    let lease = obj.get("lease").and_then(|v| v.as_str()).filter(|s| is_safe_identity_text(s, 256))?;
    let targets_hash = obj.get("targets_hash").and_then(|v| v.as_str()).filter(|s| is_safe_identity_text(s, 256))?;
    let code = if FAILURE_CODES.contains(&failure_code) {
        failure_code
    } else {
        "probe_worker_error"
    };
    Some(format!(
        "{{\"job_id\":\"{}\",\"cycle_id\":\"{}\",\"source_host_id\":\"{}\",\"source_node_id\":\"{}\",\"lease\":\"{}\",\"targets_hash\":\"{}\",\"failure_code\":\"{}\"}}",
        json_escape(job_id),
        json_escape(cycle_id),
        json_escape(host_id),
        json_escape(node_id),
        json_escape(lease),
        json_escape(targets_hash),
        json_escape(code),
    ))
}

fn serialize_report_json(job: &GfwProbeJob, results: &[GfwProbeResultItem]) -> String {
    let mut sorted: Vec<&GfwProbeResultItem> = results.iter().collect();
    sorted.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    let mut results_json = String::from("[");
    for (idx, item) in sorted.iter().enumerate() {
        if idx > 0 {
            results_json.push(',');
        }
        let latency_str = match item.latency_ms {
            Some(ms) => format!("{:.2}", ms),
            None => "null".to_string(),
        };
        results_json.push_str(&format!(
            "{{\"target_id\":\"{}\",\"success\":{},\"latency_ms\":{},\"error\":\"{}\",\"attempts\":{}}}",
            json_escape(&item.target_id),
            item.success,
            latency_str,
            json_escape(&item.error),
            item.attempts,
        ));
    }
    results_json.push(']');
    format!(
        "{{\"job_id\":\"{}\",\"cycle_id\":\"{}\",\"source_host_id\":\"{}\",\"source_node_id\":\"{}\",\"lease\":\"{}\",\"targets_hash\":\"{}\",\"results\":{}}}",
        json_escape(&job.id),
        json_escape(&job.cycle_id),
        json_escape(&job.source_host_id),
        json_escape(&job.source_node_id),
        json_escape(&job.lease),
        json_escape(&job.targets_hash),
        results_json,
    )
}

pub fn handle_poll_gfw_probe(
    poll_body: &str,
    host_id: &str,
    node_id: &str,
    client: &TransportClient,
) {
    let Ok(root) = parse_json(poll_body) else {
        return;
    };
    let Some(config_val) = root.get("gfw_probe") else {
        return;
    };
    let Some(job_val) = config_val.get("job") else {
        return;
    };
    if job_val.as_object().is_none() {
        return;
    }

    if GFW_WORKER_BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        if let Some(fail_json) = serialize_failure_json(job_val, host_id, node_id, "probe_worker_busy") {
            let _ = client.post_json_signed("/api/v1/gfw-probe/failure", fail_json.as_bytes());
        }
        return;
    }

    let now = current_unix_secs();
    let result = (|| -> Result<String, &'static str> {
        let job = validate_job(job_val, host_id, node_id, now)?;
        if !gfw_probe_available() {
            return Err("probe_runtime_unavailable");
        }
        let mut results: Vec<GfwProbeResultItem> = Vec::with_capacity(job.targets.len());
        for chunk in job.targets.chunks(4) {
            thread::scope(|scope| {
                let mut handles = Vec::with_capacity(chunk.len());
                for t in chunk {
                    handles.push(scope.spawn(move || probe_target_tcp(t)));
                }
                for h in handles {
                    if let Ok(item) = h.join() {
                        results.push(item);
                    }
                }
            });
        }
        if results.len() != job.targets.len() {
            return Err("incomplete_probe_results");
        }
        Ok(serialize_report_json(&job, &results))
    })();

    GFW_WORKER_BUSY.store(false, Ordering::Release);

    match result {
        Ok(report_json) => {
            let _ = client.post_json_signed("/api/v1/gfw-probe/report", report_json.as_bytes());
        }
        Err(failure_code) => {
            if let Some(fail_json) = serialize_failure_json(job_val, host_id, node_id, failure_code) {
                let _ = client.post_json_signed("/api/v1/gfw-probe/failure", fail_json.as_bytes());
            }
        }
    }
}

/// Prevent dead_code lint on non-Linux hosts if private IP check helper isn't called elsewhere
pub fn gfw_target_ip_allowed(ip: IpAddr) -> bool {
    let _ = (Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
    let _ = HashMap::<String, String>::new();
    is_global_ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_route_capabilities_and_target_validation() {
        let dir = std::env::temp_dir().join(format!(
            "narwhal-gfw-test-{}",
            current_unix_secs()
        ));
        let net_dir = dir.join("net");
        fs::create_dir_all(&net_dir).unwrap();
        fs::write(
            net_dir.join("route"),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\n",
        )
        .unwrap();
        fs::write(
            net_dir.join("ipv6_route"),
            "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0\n",
        )
        .unwrap();

        let cap_json = route_capabilities_json(&dir);
        assert!(cap_json.contains("\"ipv4_default_route\":true"));
        assert!(cap_json.contains("\"ipv6_default_route\":false"));

        // Verify valid target identity & targets_hash matching Python gfw_probe._digest
        let tid = canonical_target_identity_hash("target-host", "1.1.1.1", 443, "eth0");
        let target_json = format!(
            "{{\"id\":\"{}\",\"interface\":\"eth0\",\"ip\":\"1.1.1.1\",\"port\":443}}",
            tid
        );
        let thash = sha256_hex(format!("[{target_json}]").as_bytes());
        let now = 1_700_000_000u64;
        let job_str = format!(
            "{{\"id\":\"00000000-0000-4000-8000-000000000001\",\"cycle_id\":\"00000000-0000-4000-8000-000000000002\",\"source_host_id\":\"src-h\",\"source_node_id\":\"src-n\",\"target_host_id\":\"target-host\",\"target_node_id\":\"target-node\",\"role\":\"mainland\",\"lease\":\"abcdefghijklmnopqrstuvwxyz012345\",\"deadline_at\":{},\"targets\":[{}],\"targets_hash\":\"{}\"}}",
            now + 120,
            target_json,
            thash
        );
        let parsed = parse_json(&job_str).unwrap();
        let validated = validate_job(&parsed, "src-h", "src-n", now).expect("valid job");
        assert_eq!(validated.targets.len(), 1);
        assert_eq!(validated.targets[0].port, 443);

        // Private target IP must be rejected even if hashes match.
        let priv_id = canonical_target_identity_hash("target-host", "10.0.0.1", 80, "eth0");
        let priv_target = format!(
            "{{\"id\":\"{}\",\"interface\":\"eth0\",\"ip\":\"10.0.0.1\",\"port\":80}}",
            priv_id
        );
        let priv_hash = sha256_hex(format!("[{priv_target}]").as_bytes());
        let bad_job = parse_json(&format!(
            "{{\"id\":\"00000000-0000-4000-8000-000000000001\",\"cycle_id\":\"00000000-0000-4000-8000-000000000002\",\"source_host_id\":\"src-h\",\"source_node_id\":\"src-n\",\"target_host_id\":\"target-host\",\"target_node_id\":\"target-node\",\"role\":\"mainland\",\"lease\":\"abcdefghijklmnopqrstuvwxyz012345\",\"deadline_at\":{},\"targets\":[{}],\"targets_hash\":\"{}\"}}",
            now + 120,
            priv_target,
            priv_hash
        )).unwrap();
        assert_eq!(
            validate_job(&bad_job, "src-h", "src-n", now).unwrap_err(),
            "invalid_target_endpoint"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_probe_target_tcp_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = GfwProbeTarget {
            id: "t1".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            interface: "lo".to_string(),
        };
        let res = probe_target_tcp(&target);
        assert!(res.success);
        assert_eq!(res.attempts, 1);
        assert!(res.latency_ms.is_some());
    }
}
