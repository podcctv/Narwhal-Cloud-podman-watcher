#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryMetrics {
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    pub mem_free_bytes: Option<u64>,
    pub buffers_bytes: Option<u64>,
    pub cached_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
}

impl MemoryMetrics {
    fn has_any(&self) -> bool {
        self.mem_total_bytes.is_some()
            || self.mem_available_bytes.is_some()
            || self.mem_free_bytes.is_some()
            || self.buffers_bytes.is_some()
            || self.cached_bytes.is_some()
            || self.swap_total_bytes.is_some()
            || self.swap_free_bytes.is_some()
    }
}

pub fn parse_meminfo(raw: &str) -> Option<MemoryMetrics> {
    let mut metrics = MemoryMetrics::default();

    for line in raw.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(val_str) = parts.next() else {
            continue;
        };
        let Ok(val) = val_str.parse::<u64>() else {
            continue;
        };
        let unit = parts.next().unwrap_or("kB");
        let bytes = if unit.eq_ignore_ascii_case("kb") {
            val.saturating_mul(1024)
        } else if unit.eq_ignore_ascii_case("mb") {
            val.saturating_mul(1024 * 1024)
        } else if unit.eq_ignore_ascii_case("gb") {
            val.saturating_mul(1024 * 1024 * 1024)
        } else {
            val
        };

        match key.trim() {
            "MemTotal" => metrics.mem_total_bytes = Some(bytes),
            "MemAvailable" => metrics.mem_available_bytes = Some(bytes),
            "MemFree" => metrics.mem_free_bytes = Some(bytes),
            "Buffers" => metrics.buffers_bytes = Some(bytes),
            "Cached" => metrics.cached_bytes = Some(bytes),
            "SwapTotal" => metrics.swap_total_bytes = Some(bytes),
            "SwapFree" => metrics.swap_free_bytes = Some(bytes),
            _ => {}
        }
    }

    if metrics.has_any() {
        Some(metrics)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadAvgMetrics {
    pub m1: f64,
    pub m5: f64,
    pub m15: f64,
}

pub fn parse_loadavg(raw: &str) -> Option<LoadAvgMetrics> {
    let mut parts = raw.split_whitespace();
    let m1 = parts.next()?.parse::<f64>().ok()?;
    let m5 = parts.next()?.parse::<f64>().ok()?;
    let m15 = parts.next()?.parse::<f64>().ok()?;
    if !(m1.is_finite() && m1 >= 0.0 && m5.is_finite() && m5 >= 0.0 && m15.is_finite() && m15 >= 0.0) {
        return None;
    }
    Some(LoadAvgMetrics { m1, m5, m15 })
}

pub fn parse_uptime(raw: &str) -> Option<f64> {
    let first = raw.split_whitespace().next()?;
    let secs = first.parse::<f64>().ok()?;
    if secs.is_finite() && secs >= 0.0 {
        Some(secs)
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuMetrics {
    pub total: u64,
    pub busy: u64,
    pub iowait: u64,
}

pub fn parse_proc_stat_cpu(raw: &str) -> Option<CpuMetrics> {
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("cpu") {
            continue;
        }
        let mut values = [0u64; 8];
        let mut count = 0usize;
        for tok in parts.take(8) {
            values[count] = tok.parse::<u64>().ok()?;
            count += 1;
        }
        if count < 4 {
            return None;
        }
        let mut total = 0u64;
        for &v in &values[..count] {
            total = total.saturating_add(v);
        }
        let iowait = if count >= 5 { values[4] } else { 0 };
        let idle = values[3].saturating_add(iowait);
        let busy = total.saturating_sub(idle);
        return Some(CpuMetrics {
            total,
            busy,
            iowait,
        });
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInterfaceMetrics {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetMetrics {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub interfaces: Vec<NetInterfaceMetrics>,
}

pub fn parse_net_dev(raw: &str) -> Option<NetMetrics> {
    let mut saw_table = false;
    let mut metrics = NetMetrics::default();

    for line in raw.lines() {
        let Some((iface_raw, rest)) = line.split_once(':') else {
            continue;
        };
        saw_table = true;
        let iface = iface_raw.trim();
        if iface.is_empty() || iface == "lo" {
            continue;
        }
        let mut cols = rest.split_whitespace();
        let Some(rx_str) = cols.next() else {
            continue;
        };
        let Ok(rx_bytes) = rx_str.parse::<u64>() else {
            continue;
        };
        let Some(tx_str) = cols.nth(7) else {
            continue;
        };
        let Ok(tx_bytes) = tx_str.parse::<u64>() else {
            continue;
        };

        metrics.rx_bytes = metrics.rx_bytes.saturating_add(rx_bytes);
        metrics.tx_bytes = metrics.tx_bytes.saturating_add(tx_bytes);
        metrics.interfaces.push(NetInterfaceMetrics {
            name: iface.to_string(),
            rx_bytes,
            tx_bytes,
        });
    }

    if saw_table {
        Some(metrics)
    } else {
        None
    }
}

fn push_opt_u64(out: &mut String, key: &str, val: Option<u64>) {
    match val {
        Some(v) => {
            let _ = write!(out, ",\"{key}\":{v}");
        }
        None => {
            let _ = write!(out, ",\"{key}\":null");
        }
    }
}

pub fn collect_host_metrics(proc_root: &Path) -> String {
    let uptime = fs::read_to_string(proc_root.join("uptime"))
        .ok()
        .and_then(|raw| parse_uptime(&raw));
    let load = fs::read_to_string(proc_root.join("loadavg"))
        .ok()
        .and_then(|raw| parse_loadavg(&raw));
    let cpu = fs::read_to_string(proc_root.join("stat"))
        .ok()
        .and_then(|raw| parse_proc_stat_cpu(&raw));
    let memory = fs::read_to_string(proc_root.join("meminfo"))
        .ok()
        .and_then(|raw| parse_meminfo(&raw));
    let net = fs::read_to_string(proc_root.join("net").join("dev"))
        .ok()
        .and_then(|raw| parse_net_dev(&raw));

    let available =
        uptime.is_some() || load.is_some() || cpu.is_some() || memory.is_some() || net.is_some();

    let mut out = String::with_capacity(512);
    let _ = write!(out, "{{\"available\":{available},\"uptime_seconds\":");
    match uptime {
        Some(secs) => {
            let _ = write!(out, "{secs}");
        }
        None => out.push_str("null"),
    }

    out.push_str(",\"load\":");
    match load {
        Some(l) => {
            let _ = write!(
                out,
                "{{\"available\":true,\"m1\":{},\"m5\":{},\"m15\":{}}}",
                l.m1, l.m5, l.m15
            );
        }
        None => out.push_str("{\"available\":false}"),
    }

    out.push_str(",\"cpu\":");
    match cpu {
        Some(c) => {
            let _ = write!(
                out,
                "{{\"available\":true,\"total\":{},\"busy\":{},\"iowait\":{}}}",
                c.total, c.busy, c.iowait
            );
        }
        None => out.push_str("{\"available\":false}"),
    }

    out.push_str(",\"memory\":");
    match memory {
        Some(m) => {
            out.push_str("{\"available\":true");
            push_opt_u64(&mut out, "mem_total_bytes", m.mem_total_bytes);
            push_opt_u64(&mut out, "mem_available_bytes", m.mem_available_bytes);
            push_opt_u64(&mut out, "mem_free_bytes", m.mem_free_bytes);
            push_opt_u64(&mut out, "buffers_bytes", m.buffers_bytes);
            push_opt_u64(&mut out, "cached_bytes", m.cached_bytes);
            push_opt_u64(&mut out, "swap_total_bytes", m.swap_total_bytes);
            push_opt_u64(&mut out, "swap_free_bytes", m.swap_free_bytes);
            out.push('}');
        }
        None => out.push_str("{\"available\":false}"),
    }

    out.push_str(",\"net\":");
    match net {
        Some(n) => {
            let _ = write!(
                out,
                "{{\"available\":true,\"rx_bytes\":{},\"tx_bytes\":{},\"interfaces\":[",
                n.rx_bytes, n.tx_bytes
            );
            for (idx, iface) in n.interfaces.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    "{{\"name\":{},\"rx_bytes\":{},\"tx_bytes\":{}}}",
                    json_escape(&iface.name),
                    iface.rx_bytes,
                    iface.tx_bytes
                );
            }
            out.push_str("]}");
        }
        None => out.push_str("{\"available\":false,\"rx_bytes\":0,\"tx_bytes\":0,\"interfaces\":[]}"),
    }

    out.push('}');
    out
}

pub fn collect_diskstats(proc_root: &Path) -> String {
    let Ok(raw) = fs::read_to_string(proc_root.join("diskstats")) else {
        return "{\"available\":false,\"devices\":{}}".to_string();
    };
    let mut out = String::with_capacity(512);
    out.push_str("{\"available\":true,\"devices\":{");
    let mut first = true;
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 14 {
            continue;
        }
        let Ok(major) = fields[0].parse::<u64>() else {
            continue;
        };
        let Ok(minor) = fields[1].parse::<u64>() else {
            continue;
        };
        let Ok(rios) = fields[3].parse::<u64>() else {
            continue;
        };
        let Ok(rsectors) = fields[5].parse::<u64>() else {
            continue;
        };
        let Ok(wios) = fields[7].parse::<u64>() else {
            continue;
        };
        let Ok(wsectors) = fields[9].parse::<u64>() else {
            continue;
        };
        let Ok(busy_ms) = fields[12].parse::<u64>() else {
            continue;
        };
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "\"{major}:{minor}\":{{\"rios\":{rios},\"rsectors\":{rsectors},\"wios\":{wios},\"wsectors\":{wsectors},\"busy_ms\":{busy_ms}}}"
        );
    }
    out.push_str("}}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn temp_proc_dir(label: &str) -> PathBuf {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "host-metrics-test-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("net")).expect("create temp proc dir");
        dir
    }

    #[test]
    fn collect_full_host_metrics_from_temp_proc() {
        let dir = temp_proc_dir("full");
        fs::write(
            dir.join("meminfo"),
            "\
MemTotal:       16384000 kB
MemFree:         1000000 kB
MemAvailable:    8000000 kB
Buffers:          500000 kB
Cached:          4000000 kB
SwapTotal:       2097152 kB
SwapFree:        1048576 kB
",
        )
        .unwrap();
        fs::write(dir.join("loadavg"), "0.42 0.37 0.31 1/512 12345\n").unwrap();
        fs::write(dir.join("uptime"), "12345.67 98765.43\n").unwrap();
        fs::write(
            dir.join("stat"),
            "\
cpu  1000 100 300 8000 200 10 20 30 5 0
cpu0 500 50 150 4000 100 5 10 15 2 0
",
        )
        .unwrap();
        fs::write(
            dir.join("net").join("dev"),
            "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999   12345    0    0    0     0          0         0  9999999   12345    0    0    0     0       0          0
  eth0: 1000000     100    0    0    0     0          0         0   250000      50    0    0    0     0       0          0
  eth1:  500000      40    0    0    0     0          0         0   125000      25    0    0    0     0       0          0
",
        )
        .unwrap();

        let json = collect_host_metrics(&dir);
        let _ = fs::remove_dir_all(&dir);

        assert!(json.starts_with("{\"available\":true,"));
        assert!(json.contains("\"uptime_seconds\":12345.67,"));
        assert!(json.contains("\"load\":{\"available\":true,\"m1\":0.42,\"m5\":0.37,\"m15\":0.31}"));
        // total = 1000+100+300+8000+200+10+20+30 = 9660; idle = 8000+200 = 8200; busy = 1460
        assert!(json.contains("\"cpu\":{\"available\":true,\"total\":9660,\"busy\":1460,\"iowait\":200}"));
        assert!(json.contains("\"mem_total_bytes\":16777216000"));
        assert!(json.contains("\"mem_available_bytes\":8192000000"));
        assert!(json.contains("\"mem_free_bytes\":1024000000"));
        assert!(json.contains("\"buffers_bytes\":512000000"));
        assert!(json.contains("\"cached_bytes\":4096000000"));
        assert!(json.contains("\"swap_total_bytes\":2147483648"));
        assert!(json.contains("\"swap_free_bytes\":1073741824"));
        assert!(json.contains(
            "\"net\":{\"available\":true,\"rx_bytes\":1500000,\"tx_bytes\":375000,\"interfaces\":[{\"name\":\"eth0\",\"rx_bytes\":1000000,\"tx_bytes\":250000},{\"name\":\"eth1\",\"rx_bytes\":500000,\"tx_bytes\":125000}]}"
        ));
        assert!(!json.contains("\"name\":\"lo\""));
    }

    #[test]
    fn missing_proc_root_returns_valid_unavailable_json() {
        let dir = std::env::temp_dir().join(format!(
            "host-metrics-missing-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);

        let json = collect_host_metrics(&dir);
        assert_eq!(
            json,
            "{\"available\":false,\"uptime_seconds\":null,\"load\":{\"available\":false},\"cpu\":{\"available\":false},\"memory\":{\"available\":false},\"net\":{\"available\":false,\"rx_bytes\":0,\"tx_bytes\":0,\"interfaces\":[]}}"
        );
    }

    #[test]
    fn partial_meminfo_and_four_field_stat() {
        let dir = temp_proc_dir("partial");
        fs::write(
            dir.join("meminfo"),
            "MemTotal: 1024 kB\nMemFree: 512 kB\n",
        )
        .unwrap();
        fs::write(dir.join("stat"), "cpu 100 20 30 850\n").unwrap();
        fs::write(
            dir.join("net").join("dev"),
            "Inter-|\n face |\n    lo: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n",
        )
        .unwrap();

        let json = collect_host_metrics(&dir);
        let _ = fs::remove_dir_all(&dir);

        assert!(json.starts_with("{\"available\":true,"));
        assert!(json.contains("\"uptime_seconds\":null"));
        assert!(json.contains("\"load\":{\"available\":false}"));
        assert!(json.contains("\"cpu\":{\"available\":true,\"total\":1000,\"busy\":150,\"iowait\":0}"));
        assert!(json.contains("\"mem_total_bytes\":1048576"));
        assert!(json.contains("\"mem_available_bytes\":null"));
        assert!(json.contains("\"mem_free_bytes\":524288"));
        assert!(json.contains("\"net\":{\"available\":true,\"rx_bytes\":0,\"tx_bytes\":0,\"interfaces\":[]}"));
    }

    #[test]
    fn rejects_negative_or_non_finite_load_and_uptime() {
        assert_eq!(parse_loadavg("NaN 0.1 0.2"), None);
        assert_eq!(parse_loadavg("-0.5 0.1 0.2"), None);
        assert_eq!(parse_loadavg("0.1 0.2"), None);
        assert_eq!(parse_uptime("inf 10.0"), None);
        assert_eq!(parse_uptime("-1.0 10.0"), None);
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn collect_diskstats_parses_devices() {
        let dir = temp_proc_dir("diskstats");
        fs::write(
            dir.join("diskstats"),
            "   8       0 sda 100 0 800 50 200 0 1600 80 0 120 130 0 0 0 0\n",
        )
        .unwrap();
        let json = collect_diskstats(&dir);
        let _ = fs::remove_dir_all(&dir);
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"8:0\":{\"rios\":100,\"rsectors\":800,\"wios\":200,\"wsectors\":1600,\"busy_ms\":120}"));
    }
}
