#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::io::Read as _;
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
}
