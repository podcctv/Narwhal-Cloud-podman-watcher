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

use super::util::{format_utc8_datetime, now_unix_secs, parse_utc_legacy_epoch};

pub const START_MARKER: &str = "# >>> NARWHAL SECURITY ALERT BEGIN >>>";
pub const END_MARKER: &str = "# <<< NARWHAL SECURITY ALERT END <<<";
pub const SHELL_START_MARKER: &str = "# >>> NARWHAL SHELL BANNER BEGIN >>>";
pub const SHELL_END_MARKER: &str = "# <<< NARWHAL SHELL BANNER END <<<";
pub const CHANNEL: &str = "https://t.me/flanker_channel";

const FONT_FLANKER: [&[&str; 5]; 7] = [
    &[" _____ ", "|  ___|", "| |_   ", "|  _|  ", "|_|    "], // F
    &[" _     ", "| |    ", "| |    ", "| |___ ", "|_____|"], // L
    &[
        "    _    ",
        "   / \\   ",
        "  / _ \\  ",
        " / ___ \\ ",
        "/_/   \\_\\",
    ], // A
    &[" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"], // N
    &[" _  __ ", "| |/ / ", "| ' /  ", "| . \\  ", "|_|\\_\\ "], // K
    &[" _____ ", "| ____|", "|  _|  ", "| |___ ", "|_____|"], // E
    &[" ____  ", "|  _ \\ ", "| |_) |", "|  _ < ", "|_| \\_\\"], // R
];

const FONT_HOSTING: [&[&str; 5]; 7] = [
    &[" _   _ ", "| | | |", "| |_| |", "|  _  |", "|_| |_|"], // H
    &["  ___  ", " / _ \\ ", "| | | |", "| |_| |", " \\___/ "], // O
    &[" ____  ", "/ ___| ", "\\___ \\ ", " ___) |", "|____/ "], // S
    &[" _____ ", "|_   _|", "  | |  ", "  | |  ", "  |_|  "], // T
    &[" ___ ", "|_ _|", " | | ", " | | ", "|___|"],         // I
    &[" _   _ ", "| \\ | |", "|  \\| |", "| |\\  |", "|_| \\_|"], // N
    &["  ____ ", " / ___|", "| |  _ ", "| |_| |", " \\____|"], // G
];

fn is_unicode_format_cf(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn is_combining_mark(c: char) -> bool {
    matches!(
        c as u32,
        0x0300..=0x036F
            | 0x0483..=0x0487
            | 0x0591..=0x05BD
            | 0x05BF
            | 0x05C1..=0x05C2
            | 0x05C4..=0x05C5
            | 0x05C7
            | 0x0610..=0x061A
            | 0x064B..=0x065F
            | 0x0670
            | 0x06D6..=0x06DC
            | 0x06DF..=0x06E4
            | 0x06E7..=0x06E8
            | 0x06EA..=0x06ED
            | 0x0711
            | 0x0730..=0x074A
            | 0x0901..=0x0902
            | 0x093C
            | 0x0941..=0x0948
            | 0x094D
            | 0x0951..=0x0954
            | 0x1AB0..=0x1ACE
            | 0x1DC0..=0x1DFF
            | 0x20D0..=0x20F0
            | 0xFE20..=0xFE2F
    )
}

fn is_east_asian_wide_or_fullwidth(c: char) -> bool {
    matches!(
        c as u32,
        0x1100..=0x115F
            | 0x231A..=0x231B
            | 0x2329..=0x232A
            | 0x23E9..=0x23EC
            | 0x23F0
            | 0x23F3
            | 0x25FD..=0x25FE
            | 0x2614..=0x2615
            | 0x2648..=0x2653
            | 0x267F
            | 0x2693
            | 0x26A1
            | 0x26AA..=0x26AB
            | 0x26BD..=0x26BE
            | 0x26C4..=0x26C5
            | 0x26CE
            | 0x26D4
            | 0x26EA
            | 0x26F2..=0x26F3
            | 0x26F5
            | 0x26FA
            | 0x26FD
            | 0x2705
            | 0x270A..=0x270B
            | 0x2728
            | 0x274C
            | 0x274E
            | 0x2753..=0x2755
            | 0x2757
            | 0x2795..=0x2797
            | 0x27B0
            | 0x27BF
            | 0x2B1B..=0x2B1C
            | 0x2B50
            | 0x2B55
            | 0x2E80..=0x2E99
            | 0x2E9B..=0x2EF3
            | 0x2F00..=0x2FD5
            | 0x2FF0..=0x2FFF
            | 0x3000..=0x303E
            | 0x3041..=0x3096
            | 0x3099..=0x30FF
            | 0x3105..=0x312F
            | 0x3131..=0x318E
            | 0x3190..=0x31E3
            | 0x31F0..=0x321E
            | 0x3220..=0x3247
            | 0x3250..=0x4DBF
            | 0x4E00..=0xA48C
            | 0xA490..=0xA4C6
            | 0xA960..=0xA97C
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE52
            | 0xFE54..=0xFE66
            | 0xFE68..=0xFE6B
            | 0xFF01..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x16FE0..=0x16FE4
            | 0x17000..=0x187F7
            | 0x18800..=0x18CD5
            | 0x18D00..=0x18D08
            | 0x1AFF0..=0x1B2FB
            | 0x1F004
            | 0x1F0CF
            | 0x1F18E
            | 0x1F191..=0x1F19A
            | 0x1F200..=0x1F202
            | 0x1F210..=0x1F23B
            | 0x1F240..=0x1F248
            | 0x1F250..=0x1F251
            | 0x1F260..=0x1F265
            | 0x1F300..=0x1F64F
            | 0x1F680..=0x1F6FF
            | 0x1F900..=0x1FAFF
            | 0x20000..=0x2FFFD
            | 0x30000..=0x3FFFD
    )
}

fn strip_ansi_osc_and_csi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() {
            if bytes[i + 1] == b']' {
                // OSC sequence: ESC ] [^\x07]* (BEL | ESC \)
                let mut j = i + 2;
                let mut end = None;
                while j < bytes.len() {
                    if bytes[j] == 0x07 {
                        end = Some(j + 1);
                        break;
                    }
                    if bytes[j] == 0x1b && j + 1 < bytes.len() && bytes[j + 1] == b'\\' {
                        end = Some(j + 2);
                        break;
                    }
                    j += 1;
                }
                if let Some(after) = end {
                    i = after;
                    continue;
                }
            } else if bytes[i + 1] == b'[' {
                // CSI sequence: ESC [ [0-?]* [ -/]* [@-~]
                let mut j = i + 2;
                while j < bytes.len() && (0x30..=0x3f).contains(&bytes[j]) {
                    j += 1;
                }
                while j < bytes.len() && (0x20..=0x2f).contains(&bytes[j]) {
                    j += 1;
                }
                if j < bytes.len() && (0x40..=0x7e).contains(&bytes[j]) {
                    i = j + 1;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        if !ch.is_control() && !is_unicode_format_cf(ch) {
            out.push(ch);
        }
        i += ch.len_utf8();
    }
    out
}

fn redact_secrets(text: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "password",
        "api_key",
        "api-key",
        "passwd",
        "apikey",
        "secret",
        "token",
    ];
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        let slice = &text[i..];
        let matched_kw = KEYWORDS.iter().find(|&&kw| {
            slice
                .get(..kw.len())
                .map(|prefix| prefix.eq_ignore_ascii_case(kw))
                .unwrap_or(false)
        });
        if let Some(&kw) = matched_kw {
            let mut pos = i + kw.len();
            while let Some(ch) = text[pos..].chars().next() {
                if ch.is_whitespace() {
                    pos += ch.len_utf8();
                } else {
                    break;
                }
            }
            if matches!(text[pos..].chars().next(), Some(':' | '=')) {
                pos += 1;
                while let Some(ch) = text[pos..].chars().next() {
                    if ch.is_whitespace() {
                        pos += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                let val_start = pos;
                while let Some(ch) = text[pos..].chars().next() {
                    if !ch.is_whitespace() {
                        pos += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if pos > val_start {
                    out.push_str(&text[i..val_start]);
                    out.push_str("[REDACTED]");
                    i = pos;
                    continue;
                }
            }
        }
        let ch = slice.chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Strip ANSI OSC/CSI escapes and Cc/Cf control chars, redact secret tokens, and cap length.
pub fn safe_banner_text(value: &str, limit: usize) -> String {
    let stripped = strip_ansi_osc_and_csi(value);
    let redacted = redact_secrets(&stripped);
    redacted.chars().take(limit).collect()
}

pub fn safe_banner_text_default(value: &str) -> String {
    safe_banner_text(value, 300)
}

/// Format a Unix epoch (or legacy `"%Y-%m-%d %H:%M:%S UTC"` string) in fixed UTC+8.
pub fn beijing_time(epoch: Option<f64>, legacy: &str) -> String {
    let resolved = match epoch {
        Some(e) => {
            if !e.is_finite() {
                return String::new();
            }
            e
        }
        None => match parse_utc_legacy_epoch(legacy) {
            Some(ts) => ts as f64,
            None => return String::new(),
        },
    };
    format_utc8_datetime(resolved)
}

pub fn cell_width(text: &str) -> usize {
    text.chars()
        .map(|c| {
            if is_combining_mark(c) {
                0
            } else if is_east_asian_wide_or_fullwidth(c) {
                2
            } else {
                1
            }
        })
        .sum()
}

pub fn wrap_cells(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut cells = 0usize;
    for c in text.chars() {
        let size = if is_combining_mark(c) {
            0
        } else if is_east_asian_wide_or_fullwidth(c) {
            2
        } else {
            1
        };
        if cells + size > width {
            lines.push(std::mem::take(&mut current));
            cells = 0;
        }
        current.push(c);
        cells += size;
    }
    lines.push(current);
    lines
}

pub fn observed_epoch(time_epoch: Option<f64>, timestamp: &str) -> Option<i64> {
    if let Some(v) = time_epoch {
        if v.is_finite() {
            return Some(v as i64);
        }
        return None;
    }
    parse_utc_legacy_epoch(timestamp)
}

pub fn relative_age(epoch: Option<i64>, now: i64, english: bool) -> String {
    let Some(ep) = epoch else {
        return if english { "time unknown" } else { "时间待核实" }.to_string();
    };
    if ep < 0 || now < ep {
        return if english { "time unknown" } else { "时间待核实" }.to_string();
    }
    let minutes = (now - ep) / 60;
    if minutes < 1 {
        return if english { "just now" } else { "刚刚" }.to_string();
    }
    if minutes < 60 {
        return if english {
            format!("{minutes} minutes ago")
        } else {
            format!("{minutes}分钟前")
        };
    }
    let hours = minutes / 60;
    if hours < 24 {
        return if english {
            format!("{hours}h {}m ago", minutes % 60)
        } else {
            format!("{hours}小时{}分钟前", minutes % 60)
        };
    }
    if english {
        format!("{}d {}h ago", hours / 24, hours % 24)
    } else {
        format!("{}天{}小时前", hours / 24, hours % 24)
    }
}

fn replace_word_currently_ci(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let needle = "currently";
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(needle) {
        let abs = pos + rel;
        let before_ok = abs == 0 || !is_word(bytes[abs - 1]);
        let after_idx = abs + needle.len();
        let after_ok = after_idx >= bytes.len() || !is_word(bytes[after_idx]);
        if before_ok && after_ok {
            out.push_str(&text[last..abs]);
            out.push_str("at the time");
            last = after_idx;
            pos = after_idx;
        } else {
            pos = abs + 1;
        }
    }
    out.push_str(&text[last..]);
    out
}

pub fn historical_detail(detail: &str) -> String {
    let safe = safe_banner_text(detail, 300)
        .replace("当前", "当时")
        .replace("目前", "当时");
    replace_word_currently_ci(&safe)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MotdCustomerDetails {
    pub domains: Vec<String>,
    pub programs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MotdEntry {
    pub entry_type: String,
    pub title: String,
    pub detail: String,
    pub metrics: String,
    pub state: String,
    pub severity: String,
    pub historical: bool,
    pub time_epoch: Option<f64>,
    pub timestamp: String,
    pub recovered_at_epoch: Option<f64>,
    pub first_seen_epoch: Option<f64>,
    pub customer: MotdCustomerDetails,
}

impl Default for MotdEntry {
    fn default() -> Self {
        Self {
            entry_type: String::new(),
            title: String::new(),
            detail: String::new(),
            metrics: String::new(),
            state: "active".to_string(),
            severity: "warning".to_string(),
            historical: false,
            time_epoch: None,
            timestamp: String::new(),
            recovered_at_epoch: None,
            first_seen_epoch: None,
            customer: MotdCustomerDetails::default(),
        }
    }
}

impl MotdEntry {
    pub fn from_json(val: &JsonVal) -> Option<Self> {
        let obj = val.as_obj()?;
        let str_field = |k: &str| {
            obj.get(k)
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string()
        };
        let state = obj
            .get("state")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("active")
            .to_string();
        let severity = obj
            .get("severity")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("warning")
            .to_string();
        let mut customer = MotdCustomerDetails::default();
        if let Some(c_obj) = obj.get("customer").and_then(JsonVal::as_obj) {
            for (target, key) in [
                (&mut customer.domains, "domains"),
                (&mut customer.programs, "programs"),
            ] {
                if let Some(arr) = c_obj.get(key).and_then(JsonVal::as_arr) {
                    for item in arr.iter().take(4) {
                        if let Some(s) = item.as_str() {
                            target.push(s.to_string());
                        }
                    }
                }
            }
        }
        Some(Self {
            entry_type: str_field("type"),
            title: str_field("title"),
            detail: str_field("detail"),
            metrics: str_field("metrics"),
            state,
            severity,
            historical: obj.get("historical").and_then(JsonVal::as_bool) == Some(true),
            time_epoch: obj.get("time_epoch").and_then(JsonVal::as_f64),
            timestamp: str_field("timestamp"),
            recovered_at_epoch: obj.get("recovered_at_epoch").and_then(JsonVal::as_f64),
            first_seen_epoch: obj.get("first_seen_epoch").and_then(JsonVal::as_f64),
            customer,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MotdRenderOptions {
    pub language: String,
    pub width: usize,
    pub color: bool,
    pub stale: bool,
    pub sampled_at: Option<f64>,
    pub now_epoch: Option<f64>,
    pub dynamic_history_age: bool,
}

impl Default for MotdRenderOptions {
    fn default() -> Self {
        Self {
            language: "zh".to_string(),
            width: 72,
            color: false,
            stale: false,
            sampled_at: None,
            now_epoch: None,
            dynamic_history_age: false,
        }
    }
}

impl MotdRenderOptions {
    pub fn from_env() -> Self {
        let language = env::var("SECURITY_MOTD_LANGUAGE")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "zh".to_string());
        let width = env::var("SECURITY_MOTD_WIDTH")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(72)
            .clamp(12, 100);
        let color_flag = env::var("SECURITY_MOTD_COLOR")
            .ok()
            .map(|s| matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        let no_color = env::var_os("NO_COLOR").is_some();
        let term_dumb = env::var("TERM").ok().as_deref() == Some("dumb");
        Self {
            language,
            width,
            color: color_flag && !no_color && !term_dumb,
            stale: false,
            sampled_at: None,
            now_epoch: None,
            dynamic_history_age: false,
        }
    }
}

fn format_python_g(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_string();
    }
    if v == 0.0 {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e6 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.6}");
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

fn parse_number_token(s: &str) -> Option<(f64, usize)> {
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    if bytes.first() == Some(&b'-') {
        idx += 1;
    }
    let int_start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == int_start {
        return None;
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        let dot_idx = idx;
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            idx = dot_idx;
        }
    }
    let val = s[..idx].parse::<f64>().ok()?;
    Some((val, idx))
}

fn extract_numbers(text: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut i = 0usize;
    while i < text.len() {
        if let Some((num, consumed)) = parse_number_token(&text[i..]) {
            set.insert(format_python_g(num));
            i += consumed;
        } else {
            let ch = text[i..].chars().next().unwrap_or('\0');
            i += ch.len_utf8();
        }
    }
    set
}

fn extract_metric_kv(text: &str) -> BTreeMap<&'static str, String> {
    let mut map = BTreeMap::new();
    let keys = ["duration_seconds", "threshold", "value"];
    let mut i = 0usize;
    while i < text.len() {
        let slice = &text[i..];
        let mut matched = false;
        for &k in &keys {
            if let Some(after_k) = slice.strip_prefix(k) {
                if let Some(after_eq) = after_k.strip_prefix('=') {
                    if let Some((num, consumed)) = parse_number_token(after_eq) {
                        map.insert(k, format_python_g(num));
                        i += k.len() + 1 + consumed;
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            let ch = slice.chars().next().unwrap_or('\0');
            i += ch.len_utf8();
        }
    }
    map
}

fn customer_metrics(entry: &MotdEntry, english: bool) -> String {
    let numbers = extract_numbers(&safe_banner_text(&entry.detail, 300));
    let values = extract_metric_kv(&safe_banner_text(&entry.metrics, 300));
    let unit: Option<(&str, &str, &str)> = match entry.entry_type.as_str() {
        "container_connection_count" | "connections" => Some(("连接", "条", "Connections")),
        "hy2_high_concurrency" => Some(("UDP 并发", "条", "UDP connections")),
        "cpu" => Some(("CPU", "%", "CPU")),
        "memory" => Some(("内存占用", "%", "Memory")),
        "process_fanout_abuse" => Some(("进程", "个", "Processes")),
        "inbound_ip_fanout" => Some(("访问来源", "个 IP", "Client IPs")),
        "outbound_fanout" => Some(("外部地址", "个 IP", "External IPs")),
        _ => None,
    };
    let mut result = Vec::new();
    if let (Some(u), Some(val_str)) = (unit, values.get("value")) {
        if !numbers.contains(val_str) {
            let mut line = if english {
                format!("{} {val_str}", u.2)
            } else {
                format!("{} {val_str} {}", u.0, u.1)
            };
            if let Some(th_str) = values.get("threshold") {
                if english {
                    line.push_str(&format!(" (warning {th_str})"));
                } else {
                    line.push_str(&format!("（预警 {th_str} {}）", u.1));
                }
            }
            result.push(line);
        }
    }
    if let Some(dur_str) = values.get("duration_seconds") {
        if let Ok(dur) = dur_str.parse::<f64>() {
            let minutes = dur / 60.0;
            if minutes >= 0.0 {
                let min_fmt = format_python_g(minutes);
                result.push(if english {
                    format!("Duration {min_fmt} min")
                } else {
                    format!("持续 {min_fmt} 分钟")
                });
            }
        }
    }
    result.join("；")
}

fn strip_metric_tokens(reason: &str) -> String {
    let bytes = reason.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = String::with_capacity(reason.len());
    let mut i = 0usize;
    while i < reason.len() {
        let slice = &reason[i..];
        let at_word_boundary = i == 0 || !is_word(bytes[i - 1]);
        if at_word_boundary {
            let mut matched_len = None;
            for prefix in ["value=", "threshold=", "duration_seconds="] {
                if slice.starts_with(prefix) {
                    let mut end = prefix.len();
                    while end < slice.len() {
                        let ch = slice[end..].chars().next().unwrap_or(' ');
                        if ch.is_whitespace() {
                            break;
                        }
                        end += ch.len_utf8();
                    }
                    matched_len = Some(end);
                    break;
                }
            }
            if let Some(len) = matched_len {
                i += len;
                continue;
            }
        }
        let ch = slice.chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out.trim_matches(|c| matches!(c, ' ' | '/' | '；' | ';'))
        .to_string()
}

fn extract_panel_field(items: &[String], label: &str, reason: &str) -> String {
    if !items.is_empty() {
        return items
            .iter()
            .take(4)
            .map(|v| safe_banner_text(v, 100))
            .collect::<Vec<_>>()
            .join("、");
    }
    let Some(pos) = reason.find(label) else {
        return String::new();
    };
    let after = &reason[pos + label.len()..];
    let trimmed = after.trim_start();
    if trimmed.len() == after.len() {
        return String::new();
    }
    let end = trimmed.find(['；', ';']).unwrap_or(trimmed.len());
    safe_banner_text(&trimmed[..end], 200)
}

fn default_zh_title(entry_type: &str) -> Option<&'static str> {
    match entry_type {
        "cc_attack" => Some("HTTP 访问异常"),
        "socks_weak_auth" => Some("代理认证风险"),
        "socks_auth_unknown" => Some("代理认证待确认"),
        "container_connection_count" | "connections" => Some("容器连接数偏高"),
        "cpu" => Some("CPU 占用偏高"),
        "memory" => Some("内存占用偏高"),
        "malicious_process" => Some("可疑程序"),
        "outbound_fanout" => Some("外部连接偏多"),
        "port_scan" => Some("疑似端口扫描"),
        "vmess_port_blocked" => Some("VMess 入站端口已自动阻断"),
        "vmess_block_unverified" => Some("VMess 入站保护待核实"),
        "vmess_block_release_unverified" => Some("VMess 端口恢复待核实"),
        "trojan_port_blocked" => Some("Trojan 入站端口已自动阻断"),
        "trojan_block_unverified" => Some("Trojan 入站保护待核实"),
        "trojan_block_release_unverified" => Some("Trojan 端口恢复待核实"),
        "speedtest_attempt_blocked" => Some("测速连接请求已拦截"),
        "sni_whitelist_violation" => Some("入站 SNI 不在白名单，已阻断"),
        _ => None,
    }
}

fn customer_copy(entry: &MotdEntry, english: bool) -> (String, String, Vec<String>, String) {
    let mut title = safe_banner_text(
        if entry.title.is_empty() {
            &entry.entry_type
        } else {
            &entry.title
        },
        300,
    );
    let mut reason = safe_banner_text(&entry.detail, 300);
    if entry.entry_type == "user_notice" {
        return (
            title,
            safe_banner_text(&entry.detail, 1600),
            Vec::new(),
            String::new(),
        );
    }
    if !english && (entry.title.is_empty() || title == entry.entry_type) {
        if let Some(mapped) = default_zh_title(&entry.entry_type) {
            title = mapped.to_string();
        } else if title.is_empty() {
            title = "运行异常".to_string();
        }
    }
    let mut extra = Vec::new();
    let mut advice = if english {
        "Please check the related settings and background tasks."
    } else {
        "请检查相关设置和后台任务；需要协助时请联系管理员。"
    };

    match entry.entry_type.as_str() {
        "unauthorized_panel_pairing" => {
            let domains = extract_panel_field(
                &entry.customer.domains,
                "未授权面板域名",
                &reason,
            );
            let programs = extract_panel_field(
                &entry.customer.programs,
                "节点程序特征",
                &reason,
            );
            title = if english {
                "Suspected third-party panel integration"
            } else {
                "疑似第三方面板对接"
            }
            .to_string();
            let program = if !programs.is_empty() {
                programs
            } else if english {
                "A panel component".to_string()
            } else {
                "面板对接组件".to_string()
            };
            if !domains.is_empty() {
                reason = if english {
                    format!("{program} points to a panel outside the allowed list.")
                } else {
                    format!("{program} 配置的面板地址不在允许列表内。")
                };
                extra.push(format!(
                    "{}{domains}",
                    if english { "Panel: " } else { "面板：" }
                ));
            } else {
                reason = if english {
                    format!("Panel integration indicators found for {program}; authorization needs review.")
                } else {
                    format!("检测到 {program} 面板对接特征，需确认是否经过允许。")
                };
            }
            advice = if english {
                "Please confirm whether you configured this panel and contact the administrator to review it."
            } else {
                "请确认该面板是否为你自行配置；如需继续使用，请联系管理员核实。"
            };
        }
        "container_connection_count" | "connections" | "hy2_high_concurrency" => {
            advice = if english {
                "Please check shared proxy accounts, background tasks and unexpected connections."
            } else {
                "请检查代理账号共享、后台任务及异常连接。"
            };
        }
        "socks_weak_auth" | "socks_auth_unknown" => {
            advice = if english {
                "Please secure the proxy authentication or disable the unwanted service."
            } else {
                "请检查代理认证，设置安全密码，或关闭不需要的代理。"
            };
        }
        "vmess_port_blocked" => {
            advice = if english {
                "This is a platform network-policy notice, not an abuse finding. VMess inbound traffic on the listed ports was blocked without stopping other services. Please migrate the service to VLESS + Reality + Vision."
            } else {
                "这是平台网络策略提醒，不代表认定您有滥用行为。系统只阻断了列出的 VMess 入站端口，没有停止进程、容器或其他端口。建议迁移到 VLESS + Reality + Vision。"
            };
        }
        "vmess_block_unverified" => {
            advice = if english {
                "The service was not stopped because the port or network ownership could not be verified. Please review the listed port and migrate to VLESS + Reality + Vision."
            } else {
                "由于端口或网络归属无法确认，系统没有自动阻断。请核对提示的端口；确认后可迁移到 VLESS + Reality + Vision。"
            };
        }
        "vmess_block_release_unverified" => {
            advice = if english {
                "The previous network rule is being kept because the service stop or rule removal could not be verified. Please contact the administrator to review the listed port."
            } else {
                "由于尚不能确认服务已停止或规则已删除，系统暂时保留了原端口阻断。请联系管理员核实提示的端口；其他服务和容器未停止。"
            };
        }
        "trojan_port_blocked" => {
            advice = if english {
                "This is a network-policy notice, not an abuse finding. Only the verified Trojan listener ports were blocked; other services were left running. Please contact the administrator if you need help."
            } else {
                "这是网络保护策略提醒，不代表认定您有滥用行为。系统只阻断了已确认的 Trojan 监听端口，其他服务仍在运行；如需继续使用，请联系管理员确认端口策略。"
            };
        }
        "trojan_block_unverified" => {
            advice = if english {
                "The service was not stopped because its live listener or firewall rule could not be verified. Please ask the administrator to review the listed process and port."
            } else {
                "由于实时监听或防火墙规则无法核实，系统没有确认封锁。请管理员根据提示的进程和端口复核。"
            };
        }
        "trojan_block_release_unverified" => {
            advice = if english {
                "The previous network rule remains until the listener is confirmed absent and rule removal is verified."
            } else {
                "旧端口规则会保留，直到确认监听已消失且规则删除结果可读回验证。"
            };
        }
        "sni_whitelist_violation" => {
            advice = if english {
                "Inbound TLS/QUIC connections must use one of the allowed whitelist SNIs (dl-cdn.alpinelinux.org, deb.debian.org, crates.io, pypi.org, rubygems.org, addons.mozilla.org, formulae.brew.sh, static.rust-lang.org, cpan.org). Disallowed or CN missing-SNI handshakes are blocked."
            } else {
                "容器入站协议伪装必须使用以下白名单 SNI 之一（dl-cdn.alpinelinux.org、deb.debian.org、crates.io、pypi.org、rubygems.org、addons.mozilla.org、formulae.brew.sh、static.rust-lang.org、cpan.org），其他 SNI 或 CN 来源无 SNI 握手已被阻断。"
            };
        }
        "speedtest_service_blocked" => {
            advice = if english {
                "This is an administrator-configured resource policy, not an abuse finding. Only the listed DNS targets, destination IPs, or verified service listeners were restricted after local readback; no process or container was stopped."
            } else {
                "这是管理员设置的资源保护策略，不代表认定用户滥用。仅对消息列出的出站域名、测速目标 IP 或已确认入站服务入口应用了限制，并经本地读回确认；没有停止进程或容器。如业务需要访问这些目标，请联系管理员。"
            };
        }
        "speedtest_attempt_blocked" => {
            advice = if english {
                "The requested speed-test connection was blocked by the administrator resource policy. This is not an abuse finding. Contact the administrator if you need an exception."
            } else {
                "这次测速目标连接已被管理员设置的资源保护规则拦截，不代表认定您有滥用行为。如确有业务需要，请联系管理员申请临时放行。"
            };
        }
        "malicious_process" | "confirmed_abuse" => {
            advice = if english {
                "Please review the program source and startup tasks; contact the administrator before restoring access."
            } else {
                "请检查程序来源及启动任务；如已隔离，请联系管理员复核后恢复。"
            };
        }
        "cpu" | "memory" | "process_fanout_abuse" => {
            advice = if english {
                "Please check resource usage and repeated background tasks."
            } else {
                "请检查资源占用及重复运行的后台任务。"
            };
        }
        _ => {}
    }

    reason = strip_metric_tokens(&reason);
    (title, reason, extra, advice.to_string())
}

fn state_label(state: &str, english: bool) -> &'static str {
    let pair = match state {
        "active" => ("待检查，尚未确认恢复", "Needs review; recovery unconfirmed"),
        "awaiting_report" => (
            "已执行处理，等待复查确认",
            "Action executed; awaiting verification",
        ),
        "verified" => ("已恢复", "RECOVERED"),
        "resolved" => (
            "本轮未检出，待复查",
            "NOT OBSERVED; AWAITING VERIFICATION",
        ),
        "recurring" => ("风险复发 / 处置失败", "RECURRING / FAILED"),
        _ => ("证据不足，未确认恢复", "UNVERIFIED"),
    };
    if english {
        pair.1
    } else {
        pair.0
    }
}

pub fn select_motd_entries(entries: &[MotdEntry]) -> Vec<MotdEntry> {
    let mut notices: Vec<MotdEntry> = entries
        .iter()
        .filter(|e| e.entry_type == "user_notice")
        .cloned()
        .collect();
    notices.sort_by(|a, b| {
        let ta = a.time_epoch.unwrap_or(0.0);
        let tb = b.time_epoch.unwrap_or(0.0);
        tb.total_cmp(&ta)
    });
    notices.truncate(1);

    let mut current: Vec<MotdEntry> = entries
        .iter()
        .filter(|e| !e.historical && e.entry_type != "user_notice")
        .cloned()
        .collect();
    current.sort_by(|a, b| {
        let active_a = !matches!(a.state.as_str(), "active" | "recurring");
        let active_b = !matches!(b.state.as_str(), "active" | "recurring");
        let crit_a = a.severity != "critical";
        let crit_b = b.severity != "critical";
        let ta = a.time_epoch.unwrap_or(0.0);
        let tb = b.time_epoch.unwrap_or(0.0);
        active_a
            .cmp(&active_b)
            .then(crit_a.cmp(&crit_b))
            .then_with(|| tb.total_cmp(&ta))
    });
    current.truncate(3usize.saturating_sub(notices.len()));

    let mut history: Vec<MotdEntry> = entries
        .iter()
        .filter(|e| e.historical)
        .cloned()
        .collect();
    history.sort_by(|a, b| {
        let ra = a.recovered_at_epoch.or(a.time_epoch).unwrap_or(0.0);
        let rb = b.recovered_at_epoch.or(b.time_epoch).unwrap_or(0.0);
        rb.total_cmp(&ra)
    });
    history.truncate(1);

    let mut out = notices;
    out.extend(current);
    out.extend(history);
    out
}

fn tint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn render_font_word(word_glyphs: &[&[&str; 5]], out_lines: &mut Vec<String>, inner: usize, color: bool) {
    let sizes: Vec<usize> = word_glyphs
        .iter()
        .map(|g| g.iter().map(|r| r.len()).max().unwrap_or(0))
        .collect();
    for i in 0..5 {
        let row_str: String = word_glyphs
            .iter()
            .zip(sizes.iter())
            .map(|(g, &size)| format!("{:<width$}", g[i], width = size))
            .collect::<Vec<_>>()
            .join(" ");
        push_row(out_lines, &row_str, "32", true, inner, color);
    }
}

fn push_row(
    out_lines: &mut Vec<String>,
    text: &str,
    code: &str,
    center: bool,
    inner: usize,
    color: bool,
) {
    let available = if center {
        inner
    } else {
        inner.saturating_sub(4).max(1)
    };
    for part in wrap_cells(text, available) {
        let extra = inner.saturating_sub(cell_width(&part));
        let left = if center { extra / 2 } else { 2.min(extra) };
        let right = extra.saturating_sub(left);
        let body = format!("{}{}{}", " ".repeat(left), part, " ".repeat(right));
        out_lines.push(format!(
            "{}{}{}",
            tint("│", "32", color),
            tint(&body, code, color),
            tint("│", "32", color)
        ));
    }
}

/// Render the closed MOTD security card directly from typed `MotdEntry` items.
pub fn render_motd_banner_entries(
    entries: &[MotdEntry],
    options: &MotdRenderOptions,
) -> String {
    let width = options.width.clamp(12, 100);
    let english = options.language == "en";
    let color = options.color;
    let ordered = select_motd_entries(entries);
    let inner = width - 2;
    let mut lines = Vec::new();
    let ref_now = options
        .sampled_at
        .map(|s| s as i64)
        .or_else(|| options.now_epoch.map(|n| n as i64))
        .unwrap_or_else(now_unix_secs);

    let border = |left: &str, right: &str| {
        tint(&format!("{left}{}{right}", "─".repeat(inner)), "32", color)
    };

    lines.push(border("╭", "╮"));
    if inner >= 61 {
        push_row(&mut lines, "", "37", false, inner, color);
        render_font_word(&FONT_FLANKER, &mut lines, inner, color);
        push_row(&mut lines, "", "37", false, inner, color);
        render_font_word(&FONT_HOSTING, &mut lines, inner, color);
        push_row(&mut lines, "", "37", false, inner, color);
    } else {
        push_row(&mut lines, "FLANKER HOSTING", "32", true, inner, color);
    }
    push_row(&mut lines, "弗兰克托管", "37", true, inner, color);
    lines.push(border("├", "┤"));

    let outstanding: Vec<&MotdEntry> = ordered
        .iter()
        .filter(|e| e.state != "verified")
        .collect();
    let (status, status_color) = if options.stale {
        (
            if english {
                "Monitoring sample expired; current status unknown".to_string()
            } else {
                "监测数据已过期，当前状态未知".to_string()
            },
            "33",
        )
    } else if !outstanding.is_empty() {
        let msg = if english {
            format!("{} security notice(s) need review", outstanding.len())
        } else {
            format!("有 {} 项安全提醒待确认", outstanding.len())
        };
        let sc = if outstanding
            .iter()
            .any(|e| e.severity == "critical" && matches!(e.state.as_str(), "active" | "recurring"))
        {
            "31"
        } else {
            "33"
        };
        (msg, sc)
    } else {
        (
            if english {
                "No anomalies currently detected".to_string()
            } else {
                "目前容器无异常".to_string()
            },
            "32",
        )
    };

    push_row(
        &mut lines,
        &format!(
            "{}{status}",
            if english { "Status: " } else { "状态：" }
        ),
        status_color,
        false,
        inner,
        color,
    );
    let sampled_beijing = options
        .sampled_at
        .map(|s| beijing_time(Some(s), ""))
        .unwrap_or_default();
    if options.sampled_at.is_some() {
        push_row(
            &mut lines,
            &format!(
                "{}{sampled_beijing}",
                if english {
                    "Updated (UTC+8): "
                } else {
                    "更新（北京时间）："
                }
            ),
            "37",
            false,
            inner,
            color,
        );
    }

    for e in &ordered {
        push_row(&mut lines, "", "37", false, inner, color);
        let state = e.state.as_str();
        let code = if state == "verified" {
            "32"
        } else if matches!(state, "active" | "recurring") && e.severity == "critical" {
            "31"
        } else {
            "33"
        };
        let historical = state == "verified";
        let (title, reason, extra, advice) = customer_copy(e, english);
        if historical {
            push_row(
                &mut lines,
                if english {
                    "Historical alert · Recovered"
                } else {
                    "历史告警 · 已恢复"
                },
                code,
                false,
                inner,
                color,
            );
            push_row(&mut lines, &title, code, false, inner, color);
            let hist_reason = historical_detail(&reason);
            push_row(
                &mut lines,
                &format!(
                    "{}{hist_reason}",
                    if english {
                        "At the time: "
                    } else {
                        "当时情况："
                    }
                ),
                code,
                false,
                inner,
                color,
            );
            let ep = observed_epoch(e.time_epoch, &e.timestamp);
            if options.dynamic_history_age && ep.map(|v| v >= 0).unwrap_or(false) {
                lines.push(format!("@@AGE:{}:{}", ep.unwrap_or(0), usize::from(english)));
            } else {
                let reference = if options.sampled_at.is_some() && ep.is_some() {
                    if english {
                        " (as of update)"
                    } else {
                        "（截至更新时间）"
                    }
                } else {
                    ""
                };
                push_row(
                    &mut lines,
                    &format!(
                        "{}{}{reference}",
                        if english {
                            "Last occurred: "
                        } else {
                            "最近发生："
                        },
                        relative_age(ep, ref_now, english)
                    ),
                    "37",
                    false,
                    inner,
                    color,
                );
            }
            let rec_ep = observed_epoch(e.recovered_at_epoch, "");
            if let Some(rec_v) = rec_ep.filter(|&v| v >= 0) {
                if options.dynamic_history_age {
                    lines.push(format!("@@AGE:{rec_v}:{}:1", usize::from(english)));
                } else {
                    push_row(
                        &mut lines,
                        &format!(
                            "{}{}",
                            if english {
                                "Recovered: "
                            } else {
                                "恢复于："
                            },
                            relative_age(Some(rec_v), ref_now, english)
                        ),
                        "37",
                        false,
                        inner,
                        color,
                    );
                }
                let first_ep = observed_epoch(e.first_seen_epoch, "");
                if let Some(first_v) = first_ep {
                    if first_v >= 0
                        && first_v <= rec_v
                        && !e.metrics.contains("duration_seconds=")
                    {
                        let minutes = ((rec_v - first_v) as f64 / 60.0).round() as i64;
                        let dur_msg = if english {
                            format!("Alert duration about {minutes} minutes")
                        } else {
                            format!("告警持续约 {minutes} 分钟")
                        };
                        push_row(&mut lines, &dur_msg, code, false, inner, color);
                    }
                }
            }
        } else {
            push_row(&mut lines, &format!("【{title}】"), code, false, inner, color);
            push_row(
                &mut lines,
                &format!(
                    "{}{reason}",
                    if english { "Cause: " } else { "原因：" }
                ),
                code,
                false,
                inner,
                color,
            );
        }

        for detail in &extra {
            push_row(&mut lines, detail, code, false, inner, color);
        }
        if !historical {
            push_row(
                &mut lines,
                &format!(
                    "{}{}",
                    if english { "Handling: " } else { "处理：" },
                    state_label(state, english)
                ),
                code,
                false,
                inner,
                color,
            );
            push_row(
                &mut lines,
                &format!(
                    "{}{advice}",
                    if english { "Advice: " } else { "建议：" }
                ),
                code,
                false,
                inner,
                color,
            );
        }
        let metrics = customer_metrics(e, english);
        if !metrics.is_empty() {
            let prefix = if historical {
                if english {
                    "Historical data: "
                } else {
                    "当时数据："
                }
            } else {
                ""
            };
            push_row(&mut lines, &format!("{prefix}{metrics}"), code, false, inner, color);
        }
        let detected = beijing_time(e.time_epoch, &e.timestamp);
        if !detected.is_empty()
            && (options.stale || state == "verified" || detected != sampled_beijing)
        {
            let label = if english {
                "Last observed (UTC+8): "
            } else if historical {
                "发生时间（北京时间）："
            } else {
                "最近发生（北京时间）："
            };
            push_row(&mut lines, &format!("{label}{detected}"), "37", false, inner, color);
        }
        let recovered = if e.recovered_at_epoch.is_some() {
            beijing_time(e.recovered_at_epoch, "")
        } else {
            String::new()
        };
        if !recovered.is_empty() {
            push_row(
                &mut lines,
                &format!(
                    "{}{recovered}",
                    if english {
                        "Recovered (UTC+8): "
                    } else {
                        "恢复（北京时间）："
                    }
                ),
                "37",
                false,
                inner,
                color,
            );
        }
    }

    lines.push(border("├", "┤"));
    push_row(
        &mut lines,
        &format!(
            "{}{CHANNEL}",
            if english { "Channel: " } else { "频道：" }
        ),
        "37",
        false,
        inner,
        color,
    );
    lines.push(border("╰", "╯"));

    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Parse JSON array of MOTD entries and render the MOTD card.
pub fn render_motd_banner(entries_json: &str, options: &MotdRenderOptions) -> String {
    let entries: Vec<MotdEntry> = JsonVal::parse(entries_json.trim())
        .ok()
        .and_then(|v| {
            v.as_arr()
                .map(|arr| arr.iter().filter_map(MotdEntry::from_json).collect())
        })
        .unwrap_or_default();
    render_motd_banner_entries(&entries, options)
}

fn merge_marker_block(
    original: &str,
    start_marker: &str,
    end_marker: &str,
    block_content: &str,
    error_msg: &str,
) -> Result<String, String> {
    let mut cleaned = String::with_capacity(original.len());
    let mut rest = original;
    while let Some(start_idx) = rest.find(start_marker) {
        let after_start = &rest[start_idx + start_marker.len()..];
        if !after_start.starts_with('\n') {
            return Err(error_msg.to_string());
        }
        let search_body = &after_start[1..];
        let Some(end_rel) = search_body.find(end_marker) else {
            return Err(error_msg.to_string());
        };
        cleaned.push_str(&rest[..start_idx]);
        let after_end = &search_body[end_rel + end_marker.len()..];
        rest = after_end.strip_prefix('\n').unwrap_or(after_end);
    }
    cleaned.push_str(rest);
    if cleaned.contains(start_marker) || cleaned.contains(end_marker) {
        return Err(error_msg.to_string());
    }
    if block_content.is_empty() {
        Ok(cleaned)
    } else {
        Ok(format!(
            "{start_marker}\n{block_content}\n{end_marker}\n{cleaned}"
        ))
    }
}

/// Merge or clear the Narwhal MOTD marker block while preserving all user content verbatim.
pub fn merge_motd_banner(original: &str, banner: &str) -> Result<String, String> {
    merge_marker_block(
        original,
        START_MARKER,
        END_MARKER,
        banner.trim_end(),
        "MOTD 标记不完整，保留原文件并拒绝覆盖",
    )
}

pub fn shell_hook() -> &'static str {
    "# NARWHAL MANAGED INTERACTIVE BANNER v1\ncase $- in\n  *i*) if [ -z \"${NARWHAL_BANNER_SHOWN:-}\" ] && [ -t 1 ] && [ -r /etc/narwhal-banner.sh ]; then\n         NARWHAL_BANNER_SHOWN=1\n         COLUMNS=${COLUMNS:-80} /bin/sh /etc/narwhal-banner.sh\n       fi;;\nesac\n"
}

pub fn merge_shell_hook(original: &str, hook: &str) -> Result<String, String> {
    merge_marker_block(
        original,
        SHELL_START_MARKER,
        SHELL_END_MARKER,
        hook.trim_end_matches('\n'),
        "shell hook markers incomplete",
    )
}
