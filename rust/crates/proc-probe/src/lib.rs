#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn extract_ppid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return trimmed.parse::<u32>().ok();
            }
            return None;
        }
    }
    None
}

pub fn parse_proc_stat(stat: &str) -> Option<(String, f64)> {
    let close_paren = stat.rfind(')')?;
    let after = stat.get(close_paren + 1..)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    if fields.len() <= 19 {
        return None;
    }
    let start_ticks = fields[19];
    if start_ticks.is_empty() || !start_ticks.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let utime: f64 = fields[11].parse().ok()?;
    let stime: f64 = fields[12].parse().ok()?;
    if !utime.is_finite() || !stime.is_finite() {
        return None;
    }
    Some((start_ticks.to_string(), utime + stime))
}

fn read_bounded_text(path: &Path, limit: usize) -> String {
    let Ok(file) = fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::with_capacity(limit.min(8192));
    if file.take(limit as u64).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn read_cmdline(path: &Path, limit: usize) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(limit.min(8192));
    file.take(limit as u64).read_to_end(&mut buf).ok()?;
    for b in &mut buf {
        if *b == 0 {
            *b = b' ';
        }
    }
    Some(String::from_utf8_lossy(&buf).trim().to_string())
}

fn extract_nspid(status: &str, host_pid: u32, init_pid: u32) -> u32 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("NSpid:") {
            let mut last_num: Option<u32> = None;
            for tok in rest.split_whitespace() {
                if let Ok(val) = tok.parse::<u32>() {
                    last_num = Some(val);
                }
            }
            if let Some(val) = last_num {
                return val;
            }
        }
    }
    if host_pid == init_pid {
        1
    } else {
        host_pid
    }
}

fn extract_uid(status: &str) -> String {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                if !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) {
                    return first.to_string();
                }
            }
        }
    }
    "-".to_string()
}

fn extract_state(status: &str) -> String {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            if let Some(first) = rest.split_whitespace().next() {
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    "-".to_string()
}

fn extract_vm_rss_bytes(status: &str) -> u64 {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Some(first) = rest.split_whitespace().next() {
                if let Ok(kb) = first.parse::<u64>() {
                    return kb.saturating_mul(1024);
                }
            }
        }
    }
    0
}

fn format_f64(val: f64) -> String {
    if val.is_finite() {
        format!("{val:.6}")
    } else {
        "0.0".to_string()
    }
}

struct ProcItem {
    host_pid: u32,
    pid: u32,
    ppid: u32,
    user: String,
    state: String,
    cpu_seconds: f64,
    lifetime_cpu_percent: f64,
    rss_bytes: u64,
    process: String,
    command: String,
    start_ticks: String,
}

pub fn collect_proc_snapshot(init_pid: u32, scan_limit: usize, clock_ticks: f64) -> String {
    collect_proc_snapshot_from_root(Path::new("/proc"), init_pid, scan_limit, clock_ticks)
}

pub fn collect_proc_snapshot_from_root(
    proc_root: &Path,
    init_pid: u32,
    scan_limit: usize,
    clock_ticks: f64,
) -> String {
    let safe_clock_ticks = if clock_ticks.is_finite() && clock_ticks > 0.0 {
        clock_ticks
    } else {
        100.0
    };

    if init_pid <= 1 || !proc_root.join(init_pid.to_string()).is_dir() {
        return format!(
            "{{\"available\":false,\"proc_scan_complete\":false,\"status_scan_complete\":false,\"uptime\":0.0,\"clock_ticks\":{},\"items\":[]}}",
            format_f64(safe_clock_ticks)
        );
    }

    let mut proc_scan_complete = true;
    let mut all_proc_ids: Vec<u32> = Vec::new();
    match fs::read_dir(proc_root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(s) = name.to_str() {
                    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                        if let Ok(pid) = s.parse::<u32>() {
                            all_proc_ids.push(pid);
                        }
                    }
                }
            }
            all_proc_ids.sort_unstable();
        }
        Err(_) => {
            proc_scan_complete = false;
        }
    }

    if all_proc_ids.len() > scan_limit {
        proc_scan_complete = false;
        all_proc_ids.truncate(scan_limit);
    }

    let mut parent_map: HashMap<u32, u32> = HashMap::with_capacity(all_proc_ids.len());
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut status_map: HashMap<u32, String> = HashMap::with_capacity(all_proc_ids.len());
    let mut status_scan_complete = true;

    for &host_pid in &all_proc_ids {
        let pid_dir = proc_root.join(host_pid.to_string());
        let status = read_bounded_text(&pid_dir.join("status"), 8192);
        if let Some(ppid) = extract_ppid(&status) {
            parent_map.insert(host_pid, ppid);
            children_map.entry(ppid).or_default().push(host_pid);
            status_map.insert(host_pid, status);
        } else if pid_dir.exists() {
            status_scan_complete = false;
        }
    }

    let uptime_text = read_bounded_text(&proc_root.join("uptime"), 128);
    let uptime: f64 = uptime_text
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0);

    let mut descendants: HashSet<u32> = HashSet::new();
    descendants.insert(init_pid);
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(init_pid);

    while let Some(current_pid) = queue.pop_front() {
        if descendants.len() > scan_limit {
            break;
        }
        if let Some(children) = children_map.get(&current_pid) {
            for &child_pid in children {
                if descendants.insert(child_pid) {
                    queue.push_back(child_pid);
                    if descendants.len() > scan_limit {
                        break;
                    }
                }
            }
        }
    }

    if descendants.len() > scan_limit {
        proc_scan_complete = false;
    }

    let mut sorted_descendants: Vec<u32> = descendants.into_iter().collect();
    sorted_descendants.sort_unstable();

    let mut items: Vec<ProcItem> = Vec::with_capacity(sorted_descendants.len());
    for host_pid in sorted_descendants {
        let pid_dir = proc_root.join(host_pid.to_string());
        let status = match status_map.get(&host_pid) {
            Some(s) => s.clone(),
            None => read_bounded_text(&pid_dir.join("status"), 8192),
        };
        let namespace_pid = extract_nspid(&status, host_pid, init_pid);
        let user = extract_uid(&status);
        let state = extract_state(&status);
        let rss_bytes = extract_vm_rss_bytes(&status);

        let raw_comm = read_bounded_text(&pid_dir.join("comm"), 256);
        let trimmed_comm: String = raw_comm.trim().chars().take(120).collect();
        let comm = if trimmed_comm.is_empty() {
            "unknown".to_string()
        } else {
            trimmed_comm
        };

        let command = match read_cmdline(&pid_dir.join("cmdline"), 8192) {
            Some(cmd) if !cmd.is_empty() => cmd,
            _ => comm.clone(),
        };

        let stat_text = read_bounded_text(&pid_dir.join("stat"), 4096);
        let mut cpu_seconds = 0.0_f64;
        let mut lifetime_cpu_percent = 0.0_f64;
        let mut start_ticks = String::new();

        if let Some((parsed_start_ticks, total_ticks)) = parse_proc_stat(&stat_text) {
            start_ticks = parsed_start_ticks;
            cpu_seconds = (total_ticks / safe_clock_ticks).max(0.0);
            if uptime > 0.0 {
                if let Ok(start_f64) = start_ticks.parse::<f64>() {
                    let lifetime = (uptime - (start_f64 / safe_clock_ticks)).max(0.001);
                    lifetime_cpu_percent = ((cpu_seconds / lifetime) * 100.0).max(0.0);
                }
            }
        }

        items.push(ProcItem {
            host_pid,
            pid: namespace_pid,
            ppid: *parent_map.get(&host_pid).unwrap_or(&0),
            user,
            state,
            cpu_seconds,
            lifetime_cpu_percent,
            rss_bytes,
            process: comm,
            command,
            start_ticks,
        });
    }

    let namespace_by_host: HashMap<u32, u32> =
        items.iter().map(|item| (item.host_pid, item.pid)).collect();
    for item in &mut items {
        item.ppid = *namespace_by_host.get(&item.ppid).unwrap_or(&0);
    }

    items.sort_by(|a, b| {
        b.lifetime_cpu_percent
            .partial_cmp(&a.lifetime_cpu_percent)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.host_pid.cmp(&b.host_pid))
    });

    let available = !items.is_empty();
    let mut out = String::with_capacity(256 + items.len() * 192);
    let _ = write!(
        out,
        "{{\"available\":{},\"proc_scan_complete\":{},\"status_scan_complete\":{},\"uptime\":{},\"clock_ticks\":{},\"items\":[",
        available,
        proc_scan_complete,
        status_scan_complete,
        format_f64(uptime),
        format_f64(safe_clock_ticks),
    );

    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"host_pid\":{},\"pid\":{},\"ppid\":{},\"user\":\"{}\",\"state\":\"{}\",\"cpu_seconds\":{},\"lifetime_cpu_percent\":{},\"rss_bytes\":{},\"process\":\"{}\",\"command\":\"{}\",\"start_ticks\":\"{}\"}}",
            item.host_pid,
            item.pid,
            item.ppid,
            json_escape(&item.user),
            json_escape(&item.state),
            format_f64(item.cpu_seconds),
            format_f64(item.lifetime_cpu_percent),
            item.rss_bytes,
            json_escape(&item.process),
            json_escape(&item.command),
            json_escape(&item.start_ticks),
        );
    }

    out.push_str("]}");
    out
}

fn decode_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let raw = hex.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let s = std::str::from_utf8(pair).ok()?;
        let byte = u8::from_str_radix(s, 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

pub fn decode_hex_ip_port(endpoint: &str, is_v6: bool) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = endpoint.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let bytes = decode_hex_bytes(ip_hex)?;

    if !is_v6 {
        if bytes.len() != 4 {
            return None;
        }
        let addr = Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]);
        return Some((addr.to_string(), port));
    }

    if bytes.len() != 16 {
        return None;
    }
    let mut norm = [0u8; 16];
    for chunk in 0..4 {
        let base = chunk * 4;
        norm[base] = bytes[base + 3];
        norm[base + 1] = bytes[base + 2];
        norm[base + 2] = bytes[base + 1];
        norm[base + 3] = bytes[base];
    }
    if norm[..10] == [0u8; 10] && norm[10] == 0xff && norm[11] == 0xff {
        let mapped = Ipv4Addr::new(norm[12], norm[13], norm[14], norm[15]);
        return Some((mapped.to_string(), port));
    }
    Some((Ipv6Addr::from(norm).to_string(), port))
}

fn parse_socket_inode(target: &str) -> Option<u64> {
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    inner.parse::<u64>().ok()
}

struct SocketMeta {
    proto: &'static str,
    state_hex: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
}

struct ProcSocketItem {
    pid: u32,
    inode: u64,
    proto: &'static str,
    state_hex: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
}

pub fn collect_proc_sockets(init_pid: u32, pids: &[u32], max_fds: usize) -> String {
    collect_proc_sockets_from(Path::new("/proc"), init_pid, pids, max_fds)
}

pub fn collect_proc_sockets_from(
    proc_root: &Path,
    init_pid: u32,
    pids: &[u32],
    max_fds: usize,
) -> String {
    if init_pid == 0 {
        return "{\"available\":false,\"inode_count\":0,\"fd_scanned\":0,\"truncated\":false,\"sockets\":[]}".to_string();
    }

    let net_dir = proc_root.join(init_pid.to_string()).join("net");
    let tables = [
        ("tcp", false, "tcp"),
        ("tcp6", true, "tcp"),
        ("udp", false, "udp"),
        ("udp6", true, "udp"),
    ];

    let mut read_files: usize = 0;
    let mut inode_map: HashMap<u64, SocketMeta> = HashMap::new();

    for (filename, is_v6, proto) in tables {
        let Ok(content) = fs::read_to_string(net_dir.join(filename)) else {
            continue;
        };
        read_files += 1;
        for line in content.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let Some((local_ip, local_port)) = decode_hex_ip_port(parts[1], is_v6) else {
                continue;
            };
            let Some((remote_ip, remote_port)) = decode_hex_ip_port(parts[2], is_v6) else {
                continue;
            };
            let Ok(inode) = parts[9].parse::<u64>() else {
                continue;
            };
            if inode == 0 {
                continue;
            }
            let state_hex = parts[3].to_ascii_uppercase();
            inode_map.insert(
                inode,
                SocketMeta {
                    proto,
                    state_hex,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                },
            );
        }
    }

    if read_files == 0 {
        return "{\"available\":false,\"inode_count\":0,\"fd_scanned\":0,\"truncated\":false,\"sockets\":[]}".to_string();
    }

    let inode_count = inode_map.len();
    let mut fd_scanned: usize = 0;
    let mut truncated = false;
    let mut seen: HashSet<(u32, u64)> = HashSet::new();
    let mut sockets: Vec<ProcSocketItem> = Vec::new();

    'outer: for &pid in pids {
        let fd_dir = proc_root.join(pid.to_string()).join("fd");
        let Ok(entries) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if fd_scanned >= max_fds {
                truncated = true;
                break 'outer;
            }
            fd_scanned += 1;
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let Some(target_str) = target.to_str() else {
                continue;
            };
            let Some(inode) = parse_socket_inode(target_str) else {
                continue;
            };
            if let Some(meta) = inode_map.get(&inode) {
                if seen.insert((pid, inode)) {
                    sockets.push(ProcSocketItem {
                        pid,
                        inode,
                        proto: meta.proto,
                        state_hex: meta.state_hex.clone(),
                        local_ip: meta.local_ip.clone(),
                        local_port: meta.local_port,
                        remote_ip: meta.remote_ip.clone(),
                        remote_port: meta.remote_port,
                    });
                }
            }
        }
    }

    sockets.sort_by(|a, b| a.pid.cmp(&b.pid).then_with(|| a.inode.cmp(&b.inode)));

    let mut out = String::with_capacity(128 + sockets.len() * 144);
    let _ = write!(
        out,
        "{{\"available\":true,\"inode_count\":{},\"fd_scanned\":{},\"truncated\":{},\"sockets\":[",
        inode_count, fd_scanned, truncated,
    );
    for (idx, item) in sockets.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"pid\":{},\"inode\":{},\"proto\":\"{}\",\"state_hex\":\"{}\",\"local_ip\":\"{}\",\"local_port\":{},\"remote_ip\":\"{}\",\"remote_port\":{}}}",
            item.pid,
            item.inode,
            item.proto,
            json_escape(&item.state_hex),
            json_escape(&item.local_ip),
            item.local_port,
            json_escape(&item.remote_ip),
            item.remote_port,
        );
    }
    out.push_str("]}");
    out
}

pub fn collect_pid_metrics(pid: u32) -> String {
    collect_pid_metrics_from(Path::new("/proc"), pid)
}

fn read_u64_file(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
}

fn parse_pair_table(
    content: &str,
    wanted: &[(&str, &[&str])],
    out: &mut Vec<(String, u64)>,
) {
    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0usize;
    while idx + 1 < lines.len() {
        let header: Vec<&str> = lines[idx].split_whitespace().collect();
        let values: Vec<&str> = lines[idx + 1].split_whitespace().collect();
        idx += 2;
        if header.is_empty() || values.is_empty() || header[0] != values[0] {
            continue;
        }
        let proto = header[0].trim_end_matches(':');
        let Some((_, fields)) = wanted.iter().find(|(p, _)| *p == proto) else {
            continue;
        };
        for &field in *fields {
            if let Some(pos) = header[1..].iter().position(|h| *h == field) {
                let val = values
                    .get(pos + 1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                out.push((format!("{proto}_{field}"), val));
            }
        }
    }
}

pub fn collect_pid_metrics_from(proc_root: &Path, pid: u32) -> String {
    if pid == 0 {
        return "{\"available\":false,\"error\":\"invalid pid\"}".to_string();
    }
    let pid_dir = proc_root.join(pid.to_string());
    if !pid_dir.is_dir() {
        return "{\"available\":false,\"error\":\"pid directory not found\"}".to_string();
    }

    let cgroup_base = pid_dir.join("root/sys/fs/cgroup");
    let mut mem_bytes: u64 = 0;
    let mut mem_percent: f64 = 0.0;
    for (usage_rel, limit_rel) in [
        ("memory.current", "memory.max"),
        ("memory/memory.usage_in_bytes", "memory/memory.limit_in_bytes"),
    ] {
        if let Some(usage) = read_u64_file(&cgroup_base.join(usage_rel)) {
            if usage > 0 {
                mem_bytes = usage;
                if let Some(limit) = read_u64_file(&cgroup_base.join(limit_rel)) {
                    if limit > 0 && limit < (1u64 << 60) {
                        mem_percent = (usage as f64 / limit as f64) * 100.0;
                    }
                }
                break;
            }
        }
    }

    let mut process_count: u64 = 0;
    for rel in ["pids.current", "pids/pids.current"] {
        if let Some(val) = read_u64_file(&cgroup_base.join(rel)) {
            process_count = val;
            break;
        }
    }

    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;
    let mut rx_packets: u64 = 0;
    let mut tx_packets: u64 = 0;
    if let Ok(net_dev) = fs::read_to_string(pid_dir.join("net/dev")) {
        for line in net_dev.lines().skip(2) {
            let Some((iface, rest)) = line.split_once(':') else {
                continue;
            };
            if iface.trim() == "lo" {
                continue;
            }
            let cols: Vec<&str> = rest.split_whitespace().collect();
            if cols.len() < 16 {
                continue;
            }
            if let (Ok(rb), Ok(rp), Ok(tb), Ok(tp)) = (
                cols[0].parse::<u64>(),
                cols[1].parse::<u64>(),
                cols[8].parse::<u64>(),
                cols[9].parse::<u64>(),
            ) {
                rx_bytes = rx_bytes.saturating_add(rb);
                rx_packets = rx_packets.saturating_add(rp);
                tx_bytes = tx_bytes.saturating_add(tb);
                tx_packets = tx_packets.saturating_add(tp);
            }
        }
    }

    let mut protocols: Vec<(String, u64)> = Vec::new();
    if let Ok(snmp) = fs::read_to_string(pid_dir.join("net/snmp")) {
        parse_pair_table(
            &snmp,
            &[
                (
                    "Tcp",
                    &[
                        "ActiveOpens",
                        "AttemptFails",
                        "EstabResets",
                        "OutRsts",
                        "InSegs",
                        "OutSegs",
                        "RetransSegs",
                    ],
                ),
                (
                    "Udp",
                    &[
                        "InDatagrams",
                        "OutDatagrams",
                        "NoPorts",
                        "InErrors",
                        "RcvbufErrors",
                        "SndbufErrors",
                    ],
                ),
            ],
            &mut protocols,
        );
    }
    if let Ok(netstat) = fs::read_to_string(pid_dir.join("net/netstat")) {
        parse_pair_table(
            &netstat,
            &[(
                "TcpExt",
                &[
                    "TCPInDataOctets",
                    "TCPOutDataOctets",
                    "SyncookiesSent",
                    "ListenOverflows",
                    "ListenDrops",
                ],
            )],
            &mut protocols,
        );
    }

    let mut out = format!(
        "{{\"available\":true,\"mem_bytes\":{mem_bytes},\"mem_percent\":{mem_percent:.4},\"process_count\":{process_count},\"net\":{{\"rx_bytes\":{rx_bytes},\"tx_bytes\":{tx_bytes},\"rx_packets\":{rx_packets},\"tx_packets\":{tx_packets}}},\"protocols\":{{"
    );
    for (idx, (k, v)) in protocols.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{}\":{}", json_escape(k), v);
    }
    out.push_str("}}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_temp_proc(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "narwhal_proc_probe_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(
            json_escape("a\"b\\c\nd\re\tf\x08g\x0ch\x01"),
            "a\\\"b\\\\c\\nd\\re\\tf\\bg\\fh\\u0001"
        );
    }

    #[test]
    fn test_extract_ppid() {
        let status = "Name:\tbash\nState:\tS (sleeping)\nTgid:\t100\nPid:\t100\nPPid:\t42\nUid:\t0\t0\t0\t0\n";
        assert_eq!(extract_ppid(status), Some(42));
        assert_eq!(extract_ppid("Name:\tinit\nPPid:\tabc\n"), None);
        assert_eq!(extract_ppid("Name:\tinit\n"), None);
    }

    #[test]
    fn test_parse_proc_stat_with_nested_parens_and_spaces() {
        // 22 fields total in /proc/pid/stat: pid (comm) state(0) ppid(1) ... utime(11) stime(12) ... starttime(19)
        let stat = "1234 (foo (bar) baz) S 100 100 100 0 -1 4194304 10 0 0 0 150 50 0 0 20 0 1 0 98765 1024 10";
        let parsed = parse_proc_stat(stat).expect("should parse stat");
        assert_eq!(parsed.0, "98765");
        assert!((parsed.1 - 200.0).abs() < 1e-6);

        assert!(parse_proc_stat("1234 (broken").is_none());
        assert!(parse_proc_stat("1234 (short) S 1 2 3").is_none());
    }

    #[test]
    fn test_collect_proc_snapshot_bfs_descendants() {
        let root = make_temp_proc("bfs");
        fs::write(root.join("uptime"), "1000.00 500.00\n").unwrap();

        // PID 100: container init
        let p100 = root.join("100");
        fs::create_dir_all(&p100).unwrap();
        fs::write(
            p100.join("status"),
            "Name:\tinit\nState:\tS (sleeping)\nPid:\t100\nPPid:\t1\nNSpid:\t100\t1\nUid:\t0\t0\nVmRSS:\t1024 kB\n",
        )
        .unwrap();
        fs::write(p100.join("comm"), "init\n").unwrap();
        fs::write(p100.join("cmdline"), b"/sbin/init\0--quiet\0").unwrap();
        fs::write(
            p100.join("stat"),
            "100 (init) S 1 100 100 0 -1 0 0 0 0 0 100 50 0 0 20 0 1 0 10000 0 0",
        )
        .unwrap();

        // PID 101: child of 100
        let p101 = root.join("101");
        fs::create_dir_all(&p101).unwrap();
        fs::write(
            p101.join("status"),
            "Name:\txray\nState:\tR (running)\nPid:\t101\nPPid:\t100\nNSpid:\t101\t15\nUid:\t1000\t1000\nVmRSS:\t2048 kB\n",
        )
        .unwrap();
        fs::write(p101.join("comm"), "xray\n").unwrap();
        fs::write(p101.join("cmdline"), b"/usr/bin/xray\0-c\0config.json\0").unwrap();
        fs::write(
            p101.join("stat"),
            "101 (xray) R 100 100 100 0 -1 0 0 0 0 0 500 100 0 0 20 0 1 0 20000 0 0",
        )
        .unwrap();

        // PID 200: unrelated host process (child of 1)
        let p200 = root.join("200");
        fs::create_dir_all(&p200).unwrap();
        fs::write(
            p200.join("status"),
            "Name:\tsshd\nState:\tS (sleeping)\nPid:\t200\nPPid:\t1\nUid:\t0\t0\n",
        )
        .unwrap();

        let json = collect_proc_snapshot_from_root(&root, 100, 20000, 100.0);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"proc_scan_complete\":true"));
        assert!(json.contains("\"status_scan_complete\":true"));
        assert!(json.contains("\"host_pid\":101,\"pid\":15,\"ppid\":1"));
        assert!(json.contains("\"host_pid\":100,\"pid\":1,\"ppid\":0"));
        assert!(json.contains("\"rss_bytes\":2097152"));
        assert!(json.contains("\"command\":\"/usr/bin/xray -c config.json\""));
        assert!(!json.contains("sshd"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_decode_hex_ip_port() {
        assert_eq!(
            decode_hex_ip_port("0100007F:01BB", false),
            Some(("127.0.0.1".to_string(), 443))
        );
        assert_eq!(
            decode_hex_ip_port("00000000:0000", false),
            Some(("0.0.0.0".to_string(), 0))
        );
        assert_eq!(
            decode_hex_ip_port("0000000000000000FFFF00000100007F:1F90", true),
            Some(("127.0.0.1".to_string(), 8080))
        );
        assert_eq!(
            decode_hex_ip_port("00000000000000000000000001000000:0035", true),
            Some(("::1".to_string(), 53))
        );
        assert_eq!(decode_hex_ip_port("bad", false), None);
        assert_eq!(decode_hex_ip_port("0100007F:ZZZZ", false), None);
        assert_eq!(decode_hex_ip_port("0100:0050", false), None);
    }

    #[test]
    fn test_parse_socket_inode() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("socket:[0]"), Some(0));
        assert_eq!(parse_socket_inode("pipe:[12345]"), None);
        assert_eq!(parse_socket_inode("socket:[]"), None);
        assert_eq!(parse_socket_inode("socket:[12a4]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
    }

    #[test]
    fn test_collect_proc_sockets_unavailable() {
        let root = make_temp_proc("sockets_unavail");
        let json_zero = collect_proc_sockets_from(&root, 0, &[100], 64);
        assert_eq!(
            json_zero,
            "{\"available\":false,\"inode_count\":0,\"fd_scanned\":0,\"truncated\":false,\"sockets\":[]}"
        );

        let json_missing = collect_proc_sockets_from(&root, 999, &[999], 64);
        assert_eq!(
            json_missing,
            "{\"available\":false,\"inode_count\":0,\"fd_scanned\":0,\"truncated\":false,\"sockets\":[]}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_collect_proc_sockets_net_tables_without_fds() {
        let root = make_temp_proc("sockets_tables");
        let net_dir = root.join("100").join("net");
        fs::create_dir_all(&net_dir).unwrap();
        fs::write(
            net_dir.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 0100007F:01BB C0A80102:C822 01 00000000:00000000 00:00000000 00000000  1000        0 55501 1 00000000 0 0 0 0 0\n\
               1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 00000000 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            net_dir.join("udp6"),
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 55502 2\n",
        )
        .unwrap();

        let json = collect_proc_sockets_from(&root, 100, &[100], 100);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"inode_count\":2"));
        assert!(json.contains("\"fd_scanned\":0"));
        assert!(json.contains("\"truncated\":false"));
        assert!(json.contains("\"sockets\":[]"));

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn test_collect_proc_sockets_with_fd_symlinks_and_max_fds() {
        use std::os::unix::fs::symlink;

        let root = make_temp_proc("sockets_fds");
        let net_dir = root.join("100").join("net");
        fs::create_dir_all(&net_dir).unwrap();
        fs::write(
            net_dir.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 0100007F:01BB 0200007F:C822 01 00000000:00000000 00:00000000 00000000  1000        0 70001 1\n",
        )
        .unwrap();
        fs::write(
            net_dir.join("udp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
               0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 70002 2\n",
        )
        .unwrap();

        let fd100 = root.join("100").join("fd");
        fs::create_dir_all(&fd100).unwrap();
        symlink("socket:[70001]", fd100.join("3")).unwrap();
        symlink("socket:[70001]", fd100.join("4")).unwrap();
        symlink("pipe:[99999]", fd100.join("5")).unwrap();

        let fd101 = root.join("101").join("fd");
        fs::create_dir_all(&fd101).unwrap();
        symlink("socket:[70002]", fd101.join("3")).unwrap();

        let json = collect_proc_sockets_from(&root, 100, &[100, 101], 10);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"inode_count\":2"));
        assert!(json.contains("\"fd_scanned\":4"));
        assert!(json.contains("\"truncated\":false"));
        assert!(json.contains(
            "{\"pid\":100,\"inode\":70001,\"proto\":\"tcp\",\"state_hex\":\"01\",\"local_ip\":\"127.0.0.1\",\"local_port\":443,\"remote_ip\":\"127.0.0.2\",\"remote_port\":51234}"
        ));
        assert!(json.contains(
            "{\"pid\":101,\"inode\":70002,\"proto\":\"udp\",\"state_hex\":\"07\",\"local_ip\":\"0.0.0.0\",\"local_port\":53,\"remote_ip\":\"0.0.0.0\",\"remote_port\":0}"
        ));

        let json_trunc = collect_proc_sockets_from(&root, 100, &[100, 101], 2);
        assert!(json_trunc.contains("\"fd_scanned\":2"));
        assert!(json_trunc.contains("\"truncated\":true"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_collect_pid_metrics_from() {
        let root = make_temp_proc("pid_metrics");
        let cg = root.join("555/root/sys/fs/cgroup");
        let net = root.join("555/net");
        fs::create_dir_all(&cg).unwrap();
        fs::create_dir_all(&net).unwrap();
        fs::write(cg.join("memory.current"), "1048576\n").unwrap();
        fs::write(cg.join("memory.max"), "4194304\n").unwrap();
        fs::write(cg.join("pids.current"), "17\n").unwrap();
        fs::write(
            net.join("dev"),
            "Inter-|   Receive                                                |  Transmit\n\
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                lo: 999 9 0 0 0 0 0 0 999 9 0 0 0 0 0 0\n\
              eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
        )
        .unwrap();
        fs::write(
            net.join("snmp"),
            "Tcp: RtoAlgorithm RtoMin ActiveOpens InSegs OutSegs\n\
             Tcp: 1 200 42 100 200\n\
             Udp: InDatagrams OutDatagrams NoPorts\n\
             Udp: 11 22 3\n",
        )
        .unwrap();
        fs::write(
            net.join("netstat"),
            "TcpExt: SyncookiesSent ListenDrops\n\
             TcpExt: 5 2\n",
        )
        .unwrap();

        let json = collect_pid_metrics_from(&root, 555);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"mem_bytes\":1048576"));
        assert!(json.contains("\"mem_percent\":25.0000"));
        assert!(json.contains("\"process_count\":17"));
        assert!(json.contains("\"rx_bytes\":1000"));
        assert!(json.contains("\"tx_bytes\":2000"));
        assert!(json.contains("\"rx_packets\":10"));
        assert!(json.contains("\"tx_packets\":20"));
        assert!(json.contains("\"Tcp_ActiveOpens\":42"));
        assert!(json.contains("\"Udp_InDatagrams\":11"));
        assert!(json.contains("\"TcpExt_SyncookiesSent\":5"));

        let _ = fs::remove_dir_all(&root);
    }
}
