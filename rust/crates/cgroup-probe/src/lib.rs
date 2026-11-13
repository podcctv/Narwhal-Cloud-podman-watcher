#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct PsiSection {
    pub avg10: f64,
    pub avg60: Option<f64>,
    pub avg300: Option<f64>,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PsiStatus {
    Ready {
        some: Option<PsiSection>,
        full: Option<PsiSection>,
    },
    Unavailable {
        reason: &'static str,
    },
    Unsupported,
}

fn parse_psi_line(line: &str) -> Option<(&'static str, PsiSection)> {
    let mut parts = line.split_whitespace();
    let kind = match parts.next()? {
        "some" => "some",
        "full" => "full",
        _ => return None,
    };

    let mut avg10: Option<f64> = None;
    let mut avg60: Option<f64> = None;
    let mut avg300: Option<f64> = None;
    let mut total: Option<u64> = None;

    for field in parts {
        let Some((key, raw)) = field.split_once('=') else {
            continue;
        };
        match key {
            "avg10" => {
                if let Ok(v) = raw.parse::<f64>() {
                    if v.is_finite() && v >= 0.0 {
                        avg10 = Some(v);
                    }
                }
            }
            "avg60" => {
                if let Ok(v) = raw.parse::<f64>() {
                    if v.is_finite() && v >= 0.0 {
                        avg60 = Some(v);
                    }
                }
            }
            "avg300" => {
                if let Ok(v) = raw.parse::<f64>() {
                    if v.is_finite() && v >= 0.0 {
                        avg300 = Some(v);
                    }
                }
            }
            "total" => {
                if let Ok(v) = raw.parse::<u64>() {
                    total = Some(v);
                }
            }
            _ => {}
        }
    }

    let avg10 = avg10?;
    Some((
        kind,
        PsiSection {
            avg10,
            avg60,
            avg300,
            total,
        },
    ))
}

pub fn parse_psi(raw: &str) -> PsiStatus {
    let mut some: Option<PsiSection> = None;
    let mut full: Option<PsiSection> = None;

    for line in raw.lines().take(2) {
        if let Some((kind, section)) = parse_psi_line(line) {
            match kind {
                "some" => some = Some(section),
                "full" => full = Some(section),
                _ => {}
            }
        }
    }

    if some.is_none() && full.is_none() {
        PsiStatus::Unsupported
    } else {
        PsiStatus::Ready { some, full }
    }
}

pub fn read_psi(path: &Path) -> PsiStatus {
    match fs::read_to_string(path) {
        Ok(raw) => parse_psi(&raw),
        Err(err) => {
            let reason = match err.kind() {
                ErrorKind::NotFound => "FileNotFoundError",
                ErrorKind::PermissionDenied => "PermissionError",
                _ => "OSError",
            };
            PsiStatus::Unavailable { reason }
        }
    }
}

fn push_psi_section(out: &mut String, name: &str, section: &PsiSection) {
    let _ = write!(out, "\"{name}\":{{\"avg10\":{:.2}", section.avg10);
    if let Some(v) = section.avg60 {
        let _ = write!(out, ",\"avg60\":{v:.2}");
    }
    if let Some(v) = section.avg300 {
        let _ = write!(out, ",\"avg300\":{v:.2}");
    }
    if let Some(v) = section.total {
        let _ = write!(out, ",\"total\":{v}");
    }
    out.push('}');
}

fn push_psi_status(out: &mut String, status: &PsiStatus) {
    match status {
        PsiStatus::Unavailable { reason } => {
            let _ = write!(
                out,
                "{{\"status\":\"unavailable\",\"reason\":{}}}",
                json_escape(reason)
            );
        }
        PsiStatus::Unsupported => {
            out.push_str("{\"status\":\"unsupported\"}");
        }
        PsiStatus::Ready { some, full } => {
            out.push_str("{\"status\":\"ready\"");
            if let Some(sec) = some {
                out.push(',');
                push_psi_section(out, "some", sec);
            }
            if let Some(sec) = full {
                out.push(',');
                push_psi_section(out, "full", sec);
            }
            out.push('}');
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCpuCounters {
    pub total: u64,
    pub busy: u64,
    pub iowait: u64,
}

pub fn parse_proc_stat_cpu(raw: &str) -> Option<HostCpuCounters> {
    let first = raw.lines().next()?;
    let mut parts = first.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let mut values = [0u64; 8];
    let mut count = 0usize;
    for tok in parts.take(8) {
        values[count] = tok.parse::<u64>().ok()?;
        count += 1;
    }
    if count < 5 {
        return None;
    }
    let total: u64 = values[..count].iter().sum();
    let iowait = values[4];
    let idle = values[3].saturating_add(iowait);
    let busy = total.saturating_sub(idle);
    Some(HostCpuCounters {
        total,
        busy,
        iowait,
    })
}

pub fn collect_psi_snapshot(proc_root: &Path, cgroup_dir: Option<&Path>) -> String {
    let host_cpu_psi = read_psi(&proc_root.join("pressure").join("cpu"));
    let host_mem_psi = read_psi(&proc_root.join("pressure").join("memory"));
    let host_io_psi = read_psi(&proc_root.join("pressure").join("io"));

    let host_stat = fs::read_to_string(proc_root.join("stat"))
        .ok()
        .and_then(|raw| parse_proc_stat_cpu(&raw));

    let mut out = String::with_capacity(512);
    out.push_str("{\"available\":true,\"host_psi\":{\"cpu\":");
    push_psi_status(&mut out, &host_cpu_psi);
    out.push_str(",\"memory\":");
    push_psi_status(&mut out, &host_mem_psi);
    out.push_str(",\"io\":");
    push_psi_status(&mut out, &host_io_psi);
    out.push('}');

    match host_stat {
        Some(c) => {
            let _ = write!(
                out,
                ",\"host_cpu\":{{\"available\":true,\"total\":{},\"busy\":{},\"iowait\":{}}}",
                c.total, c.busy, c.iowait
            );
        }
        None => {
            out.push_str(",\"host_cpu\":{\"available\":false}");
        }
    }

    if let Some(dir) = cgroup_dir {
        let cg_cpu = read_psi(&dir.join("cpu.pressure"));
        let cg_mem = read_psi(&dir.join("memory.pressure"));
        let cg_io = read_psi(&dir.join("io.pressure"));
        out.push_str(",\"cgroup_psi\":{\"cpu\":");
        push_psi_status(&mut out, &cg_cpu);
        out.push_str(",\"memory\":");
        push_psi_status(&mut out, &cg_mem);
        out.push_str(",\"io\":");
        push_psi_status(&mut out, &cg_io);
        out.push('}');
    } else {
        out.push_str(",\"cgroup_psi\":null");
    }

    out.push('}');
    out
}

pub fn collect_cgroup_metrics(cgroup_dir: &Path) -> String {
    if !cgroup_dir.is_dir() {
        return "{\"available\":false,\"reason\":\"cgroup_dir_missing\"}".to_string();
    }

    let mut usage_usec: Option<u64> = None;
    let mut user_usec: Option<u64> = None;
    let mut system_usec: Option<u64> = None;
    let mut nr_periods: Option<u64> = None;
    let mut nr_throttled: Option<u64> = None;
    let mut throttled_usec: Option<u64> = None;

    if let Ok(raw) = fs::read_to_string(cgroup_dir.join("cpu.stat")) {
        for line in raw.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(val) = parts.next().and_then(|v| v.parse::<u64>().ok()) else {
                continue;
            };
            match key {
                "usage_usec" => usage_usec = Some(val),
                "user_usec" => user_usec = Some(val),
                "system_usec" => system_usec = Some(val),
                "nr_periods" => nr_periods = Some(val),
                "nr_throttled" => nr_throttled = Some(val),
                "throttled_usec" => throttled_usec = Some(val),
                _ => {}
            }
        }
    }

    let mut cpu_max_raw: Option<String> = None;
    let mut cpu_quota_usec: Option<u64> = None;
    let mut cpu_period_usec: Option<u64> = None;
    if let Ok(raw) = fs::read_to_string(cgroup_dir.join("cpu.max")) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            cpu_max_raw = Some(trimmed.to_string());
            let mut parts = trimmed.split_whitespace();
            if let Some(q) = parts.next() {
                if q != "max" {
                    cpu_quota_usec = q.parse::<u64>().ok();
                }
            }
            if let Some(p) = parts.next() {
                cpu_period_usec = p.parse::<u64>().ok();
            }
        }
    }

    let mem_current = fs::read_to_string(cgroup_dir.join("memory.current"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());
    let mem_max = fs::read_to_string(cgroup_dir.join("memory.max"))
        .ok()
        .and_then(|s| {
            let t = s.trim();
            if t == "max" {
                None
            } else {
                t.parse::<u64>().ok()
            }
        });

    let mut mem_anon: Option<u64> = None;
    let mut mem_file: Option<u64> = None;
    let mut mem_inactive_file: Option<u64> = None;
    if let Ok(raw) = fs::read_to_string(cgroup_dir.join("memory.stat")) {
        for line in raw.lines() {
            let mut parts = line.split_whitespace();
            let Some(key) = parts.next() else { continue };
            let Some(val) = parts.next().and_then(|v| v.parse::<u64>().ok()) else {
                continue;
            };
            match key {
                "anon" => mem_anon = Some(val),
                "file" => mem_file = Some(val),
                "inactive_file" => mem_inactive_file = Some(val),
                _ => {}
            }
        }
    }

    let mut io_rbytes: u64 = 0;
    let mut io_wbytes: u64 = 0;
    let mut io_rios: u64 = 0;
    let mut io_wios: u64 = 0;
    let mut io_available = false;
    let mut io_devices_json = String::from("[");
    let mut io_first_dev = true;
    if let Ok(raw) = fs::read_to_string(cgroup_dir.join("io.stat")) {
        io_available = true;
        for line in raw.lines() {
            let mut parts = line.split_whitespace();
            let Some(dev) = parts.next() else { continue };
            let mut dev_rbytes: Option<u64> = None;
            let mut dev_wbytes: Option<u64> = None;
            let mut dev_rios: Option<u64> = None;
            let mut dev_wios: Option<u64> = None;
            let mut dev_dbytes: Option<u64> = None;
            let mut dev_dios: Option<u64> = None;
            for field in parts {
                let Some((k, v)) = field.split_once('=') else {
                    continue;
                };
                if let Ok(n) = v.parse::<u64>() {
                    match k {
                        "rbytes" => {
                            io_rbytes = io_rbytes.saturating_add(n);
                            dev_rbytes = Some(n);
                        }
                        "wbytes" => {
                            io_wbytes = io_wbytes.saturating_add(n);
                            dev_wbytes = Some(n);
                        }
                        "rios" => {
                            io_rios = io_rios.saturating_add(n);
                            dev_rios = Some(n);
                        }
                        "wios" => {
                            io_wios = io_wios.saturating_add(n);
                            dev_wios = Some(n);
                        }
                        "dbytes" => dev_dbytes = Some(n),
                        "dios" => dev_dios = Some(n),
                        _ => {}
                    }
                }
            }
            if dev_rbytes.is_some()
                || dev_wbytes.is_some()
                || dev_rios.is_some()
                || dev_wios.is_some()
                || dev_dbytes.is_some()
                || dev_dios.is_some()
            {
                if !io_first_dev {
                    io_devices_json.push(',');
                }
                io_first_dev = false;
                let _ = write!(io_devices_json, "{{\"dev\":{}", json_escape(dev));
                if let Some(v) = dev_rbytes {
                    let _ = write!(io_devices_json, ",\"rbytes\":{v}");
                }
                if let Some(v) = dev_wbytes {
                    let _ = write!(io_devices_json, ",\"wbytes\":{v}");
                }
                if let Some(v) = dev_rios {
                    let _ = write!(io_devices_json, ",\"rios\":{v}");
                }
                if let Some(v) = dev_wios {
                    let _ = write!(io_devices_json, ",\"wios\":{v}");
                }
                if let Some(v) = dev_dbytes {
                    let _ = write!(io_devices_json, ",\"dbytes\":{v}");
                }
                if let Some(v) = dev_dios {
                    let _ = write!(io_devices_json, ",\"dios\":{v}");
                }
                io_devices_json.push('}');
            }
        }
    }
    io_devices_json.push(']');

    let opt_u64 = |v: Option<u64>| -> String {
        v.map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_string())
    };
    let opt_str = |v: &Option<String>| -> String {
        v.as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_string())
    };

    format!(
        "{{\"available\":true,\"cpu_stat\":{{\"usage_usec\":{},\"user_usec\":{},\"system_usec\":{},\"nr_periods\":{},\"nr_throttled\":{},\"throttled_usec\":{}}},\"cpu_max\":{{\"raw\":{},\"quota_usec\":{},\"period_usec\":{}}},\"memory\":{{\"current_bytes\":{},\"max_bytes\":{},\"anon_bytes\":{},\"file_bytes\":{},\"inactive_file_bytes\":{}}},\"io\":{{\"available\":{},\"rbytes\":{},\"wbytes\":{},\"rios\":{},\"wios\":{},\"devices\":{}}}}}",
        opt_u64(usage_usec),
        opt_u64(user_usec),
        opt_u64(system_usec),
        opt_u64(nr_periods),
        opt_u64(nr_throttled),
        opt_u64(throttled_usec),
        opt_str(&cpu_max_raw),
        opt_u64(cpu_quota_usec),
        opt_u64(cpu_period_usec),
        opt_u64(mem_current),
        opt_u64(mem_max),
        opt_u64(mem_anon),
        opt_u64(mem_file),
        opt_u64(mem_inactive_file),
        io_available,
        io_rbytes,
        io_wbytes,
        io_rios,
        io_wios,
        io_devices_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("narwhal_cg_test_{name}_{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn test_parse_psi_ready_and_unsupported() {
        let raw = "some avg10=12.50 avg60=5.00 avg300=1.25 total=987654\nfull avg10=2.50 avg60=1.00 avg300=0.25 total=12345\n";
        let status = parse_psi(raw);
        match status {
            PsiStatus::Ready {
                some: Some(s),
                full: Some(f),
            } => {
                assert!((s.avg10 - 12.5).abs() < 1e-6);
                assert_eq!(s.total, Some(987654));
                assert!((f.avg10 - 2.5).abs() < 1e-6);
            }
            other => panic!("unexpected psi status: {other:?}"),
        }
        assert_eq!(parse_psi("invalid\n"), PsiStatus::Unsupported);
    }

    #[test]
    fn test_parse_proc_stat_cpu() {
        let raw = "cpu  1000 100 300 8000 200 10 20 0 0 0\ncpu0 500 50 150 4000 100 5 10 0 0 0\n";
        let counters = parse_proc_stat_cpu(raw).expect("proc stat");
        assert_eq!(counters.total, 9630);
        assert_eq!(counters.iowait, 200);
        assert_eq!(counters.busy, 1430);
    }

    #[test]
    fn test_collect_psi_snapshot_and_cgroup_metrics() {
        let base = make_temp_dir("snapshot");
        let proc_dir = base.join("proc");
        let pressure_dir = proc_dir.join("pressure");
        let cg_dir = base.join("cgroup");
        fs::create_dir_all(&pressure_dir).expect("pressure dir");
        fs::create_dir_all(&cg_dir).expect("cgroup dir");

        fs::write(
            pressure_dir.join("cpu"),
            "some avg10=4.20 avg60=2.10 avg300=0.50 total=100\n",
        )
        .unwrap();
        fs::write(proc_dir.join("stat"), "cpu  100 0 50 800 50 0 0 0\n").unwrap();
        fs::write(
            cg_dir.join("cpu.pressure"),
            "some avg10=15.00 avg60=8.00 avg300=2.00 total=200\n",
        )
        .unwrap();
        fs::write(
            cg_dir.join("cpu.stat"),
            "usage_usec 500000\nnr_periods 10\nnr_throttled 2\nthrottled_usec 4000\n",
        )
        .unwrap();
        fs::write(cg_dir.join("cpu.max"), "50000 100000\n").unwrap();
        fs::write(cg_dir.join("memory.current"), "1048576\n").unwrap();
        fs::write(cg_dir.join("memory.max"), "max\n").unwrap();
        fs::write(cg_dir.join("memory.stat"), "anon 600000\ninactive_file 200000\n").unwrap();
        fs::write(
            cg_dir.join("io.stat"),
            "8:0 rbytes=1000 wbytes=2000 rios=10 wios=20\n8:16 rbytes=500 wbytes=500 rios=5 wios=5\n",
        )
        .unwrap();

        let psi_json = collect_psi_snapshot(&proc_dir, Some(&cg_dir));
        assert!(psi_json.contains("\"available\":true"));
        assert!(psi_json.contains("\"total\":1000"));
        assert!(psi_json.contains("\"avg10\":15.00"));
        assert!(psi_json.contains("\"reason\":\"FileNotFoundError\""));

        let cg_json = collect_cgroup_metrics(&cg_dir);
        assert!(cg_json.contains("\"usage_usec\":500000"));
        assert!(cg_json.contains("\"quota_usec\":50000"));
        assert!(cg_json.contains("\"period_usec\":100000"));
        assert!(cg_json.contains("\"max_bytes\":null"));
        assert!(cg_json.contains("\"rbytes\":1500"));
        assert!(cg_json.contains("\"wbytes\":2500"));

        let _ = fs::remove_dir_all(&base);
    }
}

