#![forbid(unsafe_code)]

//! Pure-Rust, `std`-only operations, security, audit, and policy subsystems
//! for Narwhal Cloud Container Watcher.
//!
//! Migrated from:
//! - `client/incus_health.py` & `client/operations.py` (`incus_health`)
//! - `client/socks_detector.py` & `client/agent.py` panel pairing helpers (`socks_detector`)
//! - `client/disk_cleanup.py` & `client/disk_cleanup_worker.py` (`disk_cleanup`)
//! - `client/security_banner.py` (`security_banner`)

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

// ===========================================================================
// Shared internal utilities (JSON building, atomic IO, time, parsing)
// ===========================================================================

mod util {
    use super::*;

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn json_str(s: &str) -> String {
        format!("\"{}\"", json_escape(s))
    }

    pub(crate) fn json_f64(v: f64) -> String {
        if !v.is_finite() {
            return "0.0".to_string();
        }
        if v == 0.0 {
            return "0.0".to_string();
        }
        if v.fract() == 0.0 && v.abs() < 1e15 {
            format!("{v:.1}")
        } else {
            format!("{v}")
        }
    }

    pub(crate) fn json_str_array(items: &[String]) -> String {
        let mut out = String::from("[");
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&json_str(item));
        }
        out.push(']');
        out
    }

    pub(crate) fn json_val_to_string(val: &JsonVal) -> String {
        match val {
            JsonVal::Null => "null".to_string(),
            JsonVal::Bool(b) => if *b { "true" } else { "false" }.to_string(),
            JsonVal::Num(n) => {
                if !n.is_finite() {
                    "0".to_string()
                } else if *n == 0.0 {
                    "0".to_string()
                } else if n.fract() == 0.0 && n.abs() <= (i64::MAX as f64) {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            JsonVal::Str(s) => json_str(s),
            JsonVal::Arr(arr) => {
                let mut out = String::from("[");
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&json_val_to_string(item));
                }
                out.push(']');
                out
            }
            JsonVal::Obj(map) => {
                let mut out = String::from("{");
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&json_str(k));
                    out.push(':');
                    out.push_str(&json_val_to_string(v));
                }
                out.push('}');
                out
            }
        }
    }

    pub(crate) struct JsonObjBuilder {
        buf: String,
        has_fields: bool,
    }

    impl JsonObjBuilder {
        pub(crate) fn new() -> Self {
            Self {
                buf: String::from("{"),
                has_fields: false,
            }
        }

        fn sep(&mut self, key: &str) {
            if self.has_fields {
                self.buf.push(',');
            }
            self.has_fields = true;
            self.buf.push_str(&json_str(key));
            self.buf.push(':');
        }

        pub(crate) fn str(&mut self, key: &str, val: &str) {
            self.sep(key);
            self.buf.push_str(&json_str(val));
        }

        pub(crate) fn bool(&mut self, key: &str, val: bool) {
            self.sep(key);
            self.buf.push_str(if val { "true" } else { "false" });
        }

        pub(crate) fn i64(&mut self, key: &str, val: i64) {
            self.sep(key);
            let _ = write!(self.buf, "{val}");
        }

        pub(crate) fn u64(&mut self, key: &str, val: u64) {
            self.sep(key);
            let _ = write!(self.buf, "{val}");
        }

        pub(crate) fn usize(&mut self, key: &str, val: usize) {
            self.sep(key);
            let _ = write!(self.buf, "{val}");
        }

        pub(crate) fn f64(&mut self, key: &str, val: f64) {
            self.sep(key);
            self.buf.push_str(&json_f64(val));
        }

        pub(crate) fn raw(&mut self, key: &str, raw_json: &str) {
            self.sep(key);
            self.buf.push_str(raw_json);
        }

        pub(crate) fn finish(mut self) -> String {
            self.buf.push('}');
            self.buf
        }
    }

    pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
        s.chars().take(max_chars).collect()
    }

    pub(crate) fn bounded_env_f64(name: &str, default: f64, minimum: f64, maximum: f64) -> f64 {
        let value = env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(default);
        value.max(minimum).min(maximum)
    }

    pub(crate) fn now_unix_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    pub(crate) fn is_symlink_path(path: &Path) -> bool {
        match fs::symlink_metadata(path) {
            Ok(meta) => meta.file_type().is_symlink(),
            Err(_) => false,
        }
    }

    /// Atomically write a private (`0600` on Unix) file without following symlinks.
    pub(crate) fn atomic_write_private(
        path: &Path,
        content: &[u8],
        prefix: &str,
    ) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("path must be absolute: {}", path.display()));
        }
        let parent = path
            .parent()
            .ok_or_else(|| "target path has no parent directory".to_string())?;
        if is_symlink_path(path) {
            return Err("refusing to overwrite symlink target".to_string());
        }
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create state directory: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }

        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!("{prefix}{}-{}.tmp", std::process::id(), seq);
        let tmp_path = parent.join(tmp_name);

        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = opts
            .open(&tmp_path)
            .map_err(|e| format!("failed to create temp file: {e}"))?;

        let write_res = (|| -> Result<(), String> {
            file.write_all(content)
                .map_err(|e| format!("failed to write temp file: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("failed to fsync temp file: {e}"))?;
            Ok(())
        })();

        drop(file);

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) {
                let _ = fs::remove_file(&tmp_path);
                return Err(format!("failed to chmod temp file: {e}"));
            }
        }

        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("failed to replace target file: {e}"));
        }
        Ok(())
    }

    pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
        let m = month as i64;
        let d = day as i64;
        let y = year - if m <= 2 { 1 } else { 0 };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    pub(crate) fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
        let z = days_since_epoch + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = mp + if mp < 10 { 3 } else { -9 };
        let year = y + if m <= 2 { 1 } else { 0 };
        (year, m as u32, d as u32)
    }

    fn is_leap_year(year: i64) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }

    fn days_in_month(year: i64, month: u32) -> u32 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if is_leap_year(year) {
                    29
                } else {
                    28
                }
            }
            _ => 0,
        }
    }

    pub(crate) fn parse_ymd_hms(date_part: &str, time_part: &str) -> Option<(i64, f64)> {
        let d_bytes = date_part.as_bytes();
        if d_bytes.len() != 10 || d_bytes[4] != b'-' || d_bytes[7] != b'-' {
            return None;
        }
        let year: i64 = date_part[0..4].parse().ok()?;
        let month: u32 = date_part[5..7].parse().ok()?;
        let day: u32 = date_part[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }

        let (hms, frac) = match time_part.split_once('.') {
            Some((left, right)) => {
                if right.is_empty() || !right.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let frac_val: f64 = format!("0.{right}").parse().ok()?;
                (left, frac_val)
            }
            None => (time_part, 0.0),
        };
        let t_bytes = hms.as_bytes();
        if t_bytes.len() != 8 || t_bytes[2] != b':' || t_bytes[5] != b':' {
            return None;
        }
        let hour: i64 = hms[0..2].parse().ok()?;
        let min: i64 = hms[3..5].parse().ok()?;
        let sec: i64 = hms[6..8].parse().ok()?;
        if !(0..=23).contains(&hour) || !(0..=59).contains(&min) || !(0..=59).contains(&sec) {
            return None;
        }

        let days = days_from_civil(year, month, day);
        let whole = days * 86_400 + hour * 3600 + min * 60 + sec;
        Some((whole, frac))
    }

    /// Parse ISO-8601 / RFC3339 timestamps emitted by Incus (`Z`, `+HH:MM`, `-HH:MM`, or naive).
    pub(crate) fn parse_iso8601_epoch(raw: &str) -> Option<f64> {
        let s = raw.trim();
        if s.len() < 19 {
            return None;
        }
        let bytes = s.as_bytes();
        if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
            return None;
        }
        let date_part = &s[0..10];
        let rest = &s[11..];

        let (time_part, tz_offset_secs) = if let Some(stripped) =
            rest.strip_suffix('Z').or_else(|| rest.strip_suffix('z'))
        {
            (stripped, 0i64)
        } else if let Some(tz_idx) = rest.rfind(['+', '-']) {
            let (tp, tz) = rest.split_at(tz_idx);
            let sign: i64 = if tz.starts_with('-') { -1 } else { 1 };
            let tz_digits = &tz[1..];
            let (hh, mm) = if let Some((h, m)) = tz_digits.split_once(':') {
                if h.len() != 2 || m.len() != 2 {
                    return None;
                }
                (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?)
            } else if tz_digits.len() == 4 {
                (
                    tz_digits[0..2].parse::<i64>().ok()?,
                    tz_digits[2..4].parse::<i64>().ok()?,
                )
            } else {
                return None;
            };
            if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) {
                return None;
            }
            (tp, sign * (hh * 3600 + mm * 60))
        } else {
            (rest, 0i64)
        };

        let (whole, frac) = parse_ymd_hms(date_part, time_part)?;
        Some((whole - tz_offset_secs) as f64 + frac)
    }

    pub(crate) fn parse_utc_legacy_epoch(raw: &str) -> Option<i64> {
        let trimmed = raw.trim();
        let body = trimmed.strip_suffix(" UTC")?;
        let (date_part, time_part) = body.split_once(' ')?;
        if time_part.contains('.') {
            return None;
        }
        let (whole, _) = parse_ymd_hms(date_part, time_part)?;
        Some(whole)
    }

    pub(crate) fn format_utc8_datetime(epoch: f64) -> String {
        if !epoch.is_finite() {
            return String::new();
        }
        let secs_f = epoch.floor();
        if secs_f < -62_135_596_800.0 || secs_f > 253_402_300_799.0 {
            return String::new();
        }
        let utc8_secs = (secs_f as i64).saturating_add(8 * 3600);
        let days = utc8_secs.div_euclid(86_400);
        let rem = utc8_secs.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        if !(1..=9999).contains(&year) {
            return String::new();
        }
        let hour = rem / 3600;
        let min = (rem % 3600) / 60;
        let sec = rem % 60;
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
    }

    pub(crate) fn has_word_match(haystack_lower: &str, words: &[&str]) -> bool {
        let bytes = haystack_lower.as_bytes();
        let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        for &word in words {
            let wlen = word.len();
            let mut offset = 0usize;
            while let Some(pos) = haystack_lower[offset..].find(word) {
                let abs = offset + pos;
                let before_ok = abs == 0 || !is_word(bytes[abs - 1]);
                let after_idx = abs + wlen;
                let after_ok = after_idx >= bytes.len() || !is_word(bytes[after_idx]);
                if before_ok && after_ok {
                    return true;
                }
                offset = abs + 1;
            }
        }
        false
    }

    pub(crate) fn percent_decode(raw: &str, plus_as_space: bool) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if plus_as_space && bytes[i] == b'+' {
                out.push(b' ');
                i += 1;
            } else if bytes[i] == b'%' && i + 2 < bytes.len() {
                let h1 = (bytes[i + 1] as char).to_digit(16);
                let h2 = (bytes[i + 2] as char).to_digit(16);
                if let (Some(a), Some(b)) = (h1, h2) {
                    out.push(((a << 4) | b) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    pub(crate) fn posix_basename(path: &str) -> &str {
        match path.rsplit_once('/') {
            Some((_, base)) => base,
            None => path,
        }
    }

    /// Minimal POSIX `shlex.split(..., comments=..., posix=True)` implementation.
    pub(crate) fn shlex_split(input: &str, comments: bool) -> Result<Vec<String>, ()> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut has_token = false;
        let mut in_single = false;
        let mut in_double = false;
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if in_single {
                if c == '\'' {
                    in_single = false;
                } else {
                    current.push(c);
                }
                continue;
            }
            if in_double {
                if c == '"' {
                    in_double = false;
                } else if c == '\\' {
                    match chars.peek().copied() {
                        Some(next @ ('"' | '\\' | '$' | '`')) => {
                            chars.next();
                            current.push(next);
                        }
                        Some('\n') => {
                            chars.next();
                        }
                        Some(_) => {
                            current.push('\\');
                            current.push(chars.next().unwrap_or('\\'));
                        }
                        None => return Err(()),
                    }
                } else {
                    current.push(c);
                }
                continue;
            }

            if comments && !has_token && c == '#' {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
                continue;
            }

            match c {
                '\'' => {
                    in_single = true;
                    has_token = true;
                }
                '"' => {
                    in_double = true;
                    has_token = true;
                }
                '\\' => match chars.next() {
                    Some('\n') => {}
                    Some(next) => {
                        current.push(next);
                        has_token = true;
                    }
                    None => return Err(()),
                },
                ch if ch.is_whitespace() => {
                    if has_token {
                        tokens.push(std::mem::take(&mut current));
                        has_token = false;
                    }
                }
                ch => {
                    current.push(ch);
                    has_token = true;
                }
            }
        }

        if in_single || in_double {
            return Err(());
        }
        if has_token {
            tokens.push(current);
        }
        Ok(tokens)
    }
}

// ===========================================================================
// 1. Incus Runtime Health (`client/incus_health.py` + `client/operations.py`)
// ===========================================================================

pub mod incus_health {
    use super::util::{
        bounded_env_f64, has_word_match, json_str, json_val_to_string, parse_iso8601_epoch,
        percent_decode, truncate_chars, JsonObjBuilder,
    };
    use super::*;

    pub const INCUS_ALERT_TYPES: &[&str] = &[
        "incus_instance_error",
        "incus_lifecycle_operation_stuck",
        "incus_lifecycle_operation_unverified",
        "incus_api_unavailable",
        "incus_operation_inventory_unavailable",
        "incus_api_slow",
    ];

    pub const DEFAULT_COMMAND_TIMEOUT_SECONDS: f64 = 8.0;
    pub const DEFAULT_STUCK_OPERATION_SECONDS: f64 = 300.0;
    pub const DEFAULT_SLOW_API_MILLISECONDS: f64 = 3000.0;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct IncusHealthConfig {
        pub command_timeout_seconds: f64,
        pub stuck_operation_seconds: f64,
        pub slow_api_milliseconds: f64,
    }

    impl Default for IncusHealthConfig {
        fn default() -> Self {
            Self {
                command_timeout_seconds: DEFAULT_COMMAND_TIMEOUT_SECONDS,
                stuck_operation_seconds: DEFAULT_STUCK_OPERATION_SECONDS,
                slow_api_milliseconds: DEFAULT_SLOW_API_MILLISECONDS,
            }
        }
    }

    impl IncusHealthConfig {
        pub fn from_env() -> Self {
            Self {
                command_timeout_seconds: bounded_env_f64(
                    "INCUS_HEALTH_COMMAND_TIMEOUT_SECONDS",
                    DEFAULT_COMMAND_TIMEOUT_SECONDS,
                    3.0,
                    15.0,
                ),
                stuck_operation_seconds: bounded_env_f64(
                    "INCUS_STUCK_OPERATION_SECONDS",
                    DEFAULT_STUCK_OPERATION_SECONDS,
                    60.0,
                    3600.0,
                ),
                slow_api_milliseconds: bounded_env_f64(
                    "INCUS_SLOW_API_MILLISECONDS",
                    DEFAULT_SLOW_API_MILLISECONDS,
                    500.0,
                    10000.0,
                ),
            }
        }

        pub fn normalized(&self) -> Self {
            let finite = |v: f64, d: f64| if v.is_finite() { v } else { d };
            Self {
                command_timeout_seconds: finite(
                    self.command_timeout_seconds,
                    DEFAULT_COMMAND_TIMEOUT_SECONDS,
                )
                .clamp(3.0, 15.0),
                stuck_operation_seconds: finite(
                    self.stuck_operation_seconds,
                    DEFAULT_STUCK_OPERATION_SECONDS,
                )
                .clamp(60.0, 3600.0),
                slow_api_milliseconds: finite(
                    self.slow_api_milliseconds,
                    DEFAULT_SLOW_API_MILLISECONDS,
                )
                .clamp(500.0, 10000.0),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct IncusScan {
        pub ok: bool,
        pub items: Vec<JsonVal>,
        pub latency_ms: f64,
        pub error: String,
    }

    impl IncusScan {
        pub fn unavailable(error: &str, latency_ms: f64) -> Self {
            Self {
                ok: false,
                items: Vec::new(),
                latency_ms: if latency_ms.is_finite() && latency_ms >= 0.0 {
                    (latency_ms * 10.0).round() / 10.0
                } else {
                    0.0
                },
                error: error.to_string(),
            }
        }

        /// Parse a `client/incus_health.py` scan envelope JSON (`{"ok":...,"items":[...],"latency_ms":...,"error":...}`).
        pub fn from_json(raw: &str) -> Self {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Self::unavailable("not_checked", 0.0);
            }
            let Ok(val) = JsonVal::parse(trimmed) else {
                return Self::unavailable("invalid_json", 0.0);
            };
            let Some(obj) = val.as_obj() else {
                return Self::unavailable("not_checked", 0.0);
            };
            let ok = obj.get("ok").and_then(JsonVal::as_bool) == Some(true);
            let latency_ms = obj
                .get("latency_ms")
                .and_then(JsonVal::as_f64)
                .filter(|v| v.is_finite() && *v >= 0.0)
                .unwrap_or(0.0);
            let error = obj
                .get("error")
                .and_then(JsonVal::as_str)
                .unwrap_or("")
                .to_string();
            let items = if ok {
                obj.get("items")
                    .and_then(JsonVal::as_arr)
                    .map(|arr| arr.iter().filter(|x| x.as_obj().is_some()).cloned().collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            Self {
                ok,
                items,
                latency_ms,
                error,
            }
        }

        /// Parse raw `incus ... --format=json` CLI output matching `_run_json`.
        pub fn from_cli_output(
            exit_ok: bool,
            stdout: &str,
            latency_ms: f64,
            error_hint: &str,
        ) -> Self {
            let rounded = if latency_ms.is_finite() && latency_ms >= 0.0 {
                (latency_ms * 10.0).round() / 10.0
            } else {
                0.0
            };
            if !exit_ok {
                let err = if error_hint.is_empty() {
                    "command_failed"
                } else {
                    error_hint
                };
                return Self::unavailable(err, rounded);
            }
            let Ok(val) = JsonVal::parse(stdout.trim()) else {
                return Self::unavailable("invalid_json", rounded);
            };
            let Some(arr) = val.as_arr() else {
                return Self::unavailable("invalid_shape", rounded);
            };
            if arr.iter().any(|item| item.as_obj().is_none()) {
                return Self::unavailable("invalid_shape", rounded);
            }
            Self {
                ok: true,
                items: arr.to_vec(),
                latency_ms: rounded,
                error: String::new(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct IncusSnapshotReport {
        pub status: String,
        pub scan_status: String,
        pub snapshot_json: String,
        pub health_json: String,
        pub operations_health_json: String,
        pub alerts_json: String,
        pub error_instance_count: usize,
        pub active_lifecycle_operation_count: usize,
        pub stuck_lifecycle_operation_count: usize,
    }

    fn all_projects(project: &str) -> bool {
        let trimmed = project.trim();
        trimmed.is_empty() || matches!(trimmed.to_ascii_lowercase().as_str(), "all" | "*")
    }

    fn instance_project(instance: &JsonVal, default_project: &str) -> String {
        let raw = instance
            .get_str("project")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(default_project);
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            "default".to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn instance_name(instance: &JsonVal) -> String {
        instance
            .get_str("name")
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    }

    fn instance_status(instance: &JsonVal) -> String {
        instance
            .get_str("status")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_ascii_lowercase()
    }

    fn instance_uuid(instance: &JsonVal) -> String {
        let raw = instance
            .get("config")
            .and_then(|c| c.get_str("volatile.uuid"))
            .map(str::trim)
            .unwrap_or("");
        truncate_chars(raw, 100)
    }

    fn operation_is_running(operation: &JsonVal) -> bool {
        if operation
            .get_str("status")
            .map(|s| s.trim().eq_ignore_ascii_case("running"))
            == Some(true)
        {
            return true;
        }
        if operation.get_i64("status_code") == Some(103) {
            return true;
        }
        if operation
            .get_str("status_code")
            .and_then(|s| s.trim().parse::<i64>().ok())
            == Some(103)
        {
            return true;
        }
        false
    }

    pub fn incus_lifecycle_action(operation: &JsonVal) -> Option<&'static str> {
        let metadata = operation.get("metadata");
        let desc = operation.get_str("description").unwrap_or("");
        let m_action = metadata.and_then(|m| m.get_str("action")).unwrap_or("");
        let m_name = metadata.and_then(|m| m.get_str("name")).unwrap_or("");
        let combined = format!("{desc} {m_action} {m_name}").to_ascii_lowercase();

        if has_word_match(&combined, &["restart", "restarting", "reboot", "rebooting"]) {
            Some("restart")
        } else if has_word_match(&combined, &["stop", "stopping"]) {
            Some("stop")
        } else if has_word_match(&combined, &["start", "starting"]) {
            Some("start")
        } else if has_word_match(&combined, &["delete", "deleting", "remove", "removing"]) {
            Some("delete")
        } else {
            None
        }
    }

    pub fn parse_incus_created_epoch(raw: &str) -> Option<f64> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        parse_iso8601_epoch(trimmed)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct OperationTarget {
        name: String,
        project: String,
    }

    fn extract_resource_urls(operation: &JsonVal) -> Vec<String> {
        let Some(resources) = operation.get("resources") else {
            return Vec::new();
        };
        let raw_val = resources
            .get("instances")
            .filter(|v| match v {
                JsonVal::Arr(a) => !a.is_empty(),
                JsonVal::Str(s) => !s.is_empty(),
                _ => false,
            })
            .or_else(|| resources.get("containers"));
        match raw_val {
            Some(JsonVal::Str(s)) => vec![s.clone()],
            Some(JsonVal::Arr(arr)) => arr
                .iter()
                .filter_map(JsonVal::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn operation_targets(operation: &JsonVal, default_project: &str) -> Vec<OperationTarget> {
        let mut targets = Vec::new();
        for resource in extract_resource_urls(operation) {
            let without_frag = resource.split('#').next().unwrap_or(&resource);
            let (path_and_auth, query) = without_frag
                .split_once('?')
                .unwrap_or((without_frag, ""));
            let path = if let Some((_, after_scheme)) = path_and_auth.split_once("://") {
                match after_scheme.find('/') {
                    Some(idx) => &after_scheme[idx..],
                    None => "",
                }
            } else {
                path_and_auth
            };
            let components: Vec<String> = path
                .split('/')
                .filter(|p| !p.is_empty())
                .map(|p| percent_decode(p, false))
                .collect();

            let mut name = String::new();
            for kind in ["instances", "containers"] {
                if let Some(pos) = components.iter().position(|c| c == kind) {
                    if pos + 1 < components.len() {
                        name = components[pos + 1].clone();
                        break;
                    }
                }
            }
            if name.is_empty() {
                continue;
            }
            let mut project = String::new();
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if percent_decode(k, true) == "project" {
                        let decoded = percent_decode(v, true);
                        if !decoded.is_empty() {
                            project = decoded;
                            break;
                        }
                    }
                }
            }
            if project.is_empty() {
                project = default_project.to_string();
            }
            targets.push(OperationTarget {
                name: truncate_chars(&name, 200),
                project: truncate_chars(&project, 100),
            });
        }
        targets
    }

    enum ObsVal {
        Str(String),
        I64(i64),
        U64(u64),
        F64(f64),
        Bool(bool),
    }

    impl ObsVal {
        fn to_json(&self) -> String {
            match self {
                Self::Str(s) => json_str(s),
                Self::I64(v) => format!("{v}"),
                Self::U64(v) => format!("{v}"),
                Self::F64(v) => super::util::json_f64(*v),
                Self::Bool(b) => if *b { "true" } else { "false" }.to_string(),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_alert_json(
        alert_type: &str,
        severity: &str,
        title: &str,
        message: &str,
        project: &str,
        name: &str,
        alert_key: &str,
        value: f64,
        threshold: f64,
        top_instance_id: Option<&str>,
        observation: Vec<(&str, ObsVal)>,
    ) -> String {
        let mut obs_buf = String::from("{");
        for (i, (k, v)) in observation.iter().enumerate() {
            if i > 0 {
                obs_buf.push(',');
            }
            obs_buf.push_str(&json_str(k));
            obs_buf.push(':');
            obs_buf.push_str(&v.to_json());
        }
        obs_buf.push('}');

        let mut b = JsonObjBuilder::new();
        b.str("type", alert_type);
        b.str("severity", severity);
        b.str("title", title);
        b.str("message", message);
        b.f64("value", value);
        b.f64("threshold", threshold);
        b.str("runtime", "incus");
        b.str("project", &truncate_chars(project, 100));
        b.str("container_name", &truncate_chars(name, 200));
        b.str("alert_key", &truncate_chars(alert_key, 240));
        b.raw("observation", &obs_buf);
        if let Some(inst_id) = top_instance_id {
            if !inst_id.is_empty() {
                b.str("instance_id", &truncate_chars(inst_id, 100));
            }
        }
        b.finish()
    }

    /// Build the Incus health snapshot, `operations.health` entry, and alerts JSON
    /// matching `client/incus_health.py` and `client/operations.py`.
    pub fn build_incus_snapshot(
        instance_scan: &IncusScan,
        operation_scan: &IncusScan,
        project: &str,
        now_epoch: f64,
        config: &IncusHealthConfig,
    ) -> IncusSnapshotReport {
        let cfg = config.normalized();
        let now = if now_epoch.is_finite() && now_epoch >= 0.0 {
            now_epoch
        } else {
            super::util::now_unix_secs() as f64
        };

        let instance_ok = instance_scan.ok;
        let operation_ok = operation_scan.ok;
        let scan_status = if instance_ok && operation_ok {
            "complete"
        } else if instance_ok || operation_ok {
            "partial"
        } else {
            "unavailable"
        };

        let selected_all = all_projects(project);
        let selected_project = if selected_all {
            ""
        } else {
            let trimmed = project.trim();
            if trimmed.is_empty() {
                "default"
            } else {
                trimmed
            }
        };

        let instances: Vec<&JsonVal> = if instance_ok {
            instance_scan
                .items
                .iter()
                .filter(|item| item.as_obj().is_some())
                .collect()
        } else {
            Vec::new()
        };

        let mut container_targets: BTreeSet<(String, String)> = BTreeSet::new();
        for inst in &instances {
            let name = instance_name(inst);
            if !name.is_empty() {
                container_targets.insert((instance_project(inst, "default"), name));
            }
        }

        let mut error_instances_json: Vec<String> = Vec::new();
        let mut alerts_json_items: Vec<String> = Vec::new();

        for inst in &instances {
            if instance_status(inst) != "error" {
                continue;
            }
            let name = instance_name(inst);
            if name.is_empty() {
                continue;
            }
            let item_project = instance_project(inst, "default");
            let identity = instance_uuid(inst);
            let pid_val = inst.get("state").and_then(|s| s.get("pid"));
            let pid_str = match pid_val {
                Some(JsonVal::Num(n)) if n.is_finite() => {
                    if n.fract() == 0.0 {
                        format!("{}", *n as i64)
                    } else {
                        format!("{n}")
                    }
                }
                Some(JsonVal::Str(s)) if !s.is_empty() => s.clone(),
                _ => "unknown".to_string(),
            };
            let raw_status = inst
                .get_str("status")
                .filter(|s| !s.is_empty())
                .unwrap_or("Error");

            let mut eb = JsonObjBuilder::new();
            eb.str("name", &name);
            eb.str("project", &item_project);
            eb.str("status", raw_status);
            match pid_val {
                Some(v) => eb.raw("pid", &json_val_to_string(v)),
                None => eb.raw("pid", "null"),
            }
            eb.str("instance_id", &identity);
            error_instances_json.push(eb.finish());

            let log_hint = if identity.is_empty() {
                "/var/log/incus/<instance-id>/lxc.log".to_string()
            } else {
                format!("/var/log/incus/{identity}/lxc.log")
            };
            let id_key = if identity.is_empty() {
                "unknown"
            } else {
                identity.as_str()
            };
            let pid_obs = match pid_val {
                Some(JsonVal::Num(n)) if n.is_finite() => {
                    if n.fract() == 0.0 {
                        ObsVal::I64(*n as i64)
                    } else {
                        ObsVal::F64(*n)
                    }
                }
                Some(JsonVal::Str(s)) if !s.is_empty() => ObsVal::Str(s.clone()),
                _ => ObsVal::Str("unknown".to_string()),
            };

            alerts_json_items.push(build_alert_json(
                "incus_instance_error",
                "critical",
                "Incus 实例进入 ERROR，自动停止已暂停",
                &format!(
                    "Incus 报告 {item_project}/{name} 状态为 ERROR（PID={pid_str}）。Watcher 不会再次提交 stop/restart/delete；保留实例现场并人工检查 {log_hint}、forkexec.log、控制台日志及对应 Incus 操作。"
                ),
                &item_project,
                &name,
                &format!("instance:{item_project}:{name}:{id_key}"),
                0.0,
                0.0,
                if identity.is_empty() {
                    None
                } else {
                    Some(identity.as_str())
                },
                vec![
                    ("status", ObsVal::Str("error".to_string())),
                    ("pid", pid_obs),
                    ("instance_id", ObsVal::Str(identity.clone())),
                    ("automatic_action", ObsVal::Str("alert_only".to_string())),
                ],
            ));
        }

        let operation_rows: Vec<&JsonVal> = if operation_ok {
            operation_scan
                .items
                .iter()
                .filter(|item| item.as_obj().is_some())
                .collect()
        } else {
            Vec::new()
        };

        let mut active_lifecycle_json: Vec<String> = Vec::new();
        let mut stuck_operations_json: Vec<String> = Vec::new();
        let stuck_after = cfg.stuck_operation_seconds;

        for op in &operation_rows {
            if !operation_is_running(op) {
                continue;
            }
            let Some(action) = incus_lifecycle_action(op) else {
                continue;
            };
            let default_proj = if selected_all {
                "default"
            } else {
                selected_project
            };
            let targets = operation_targets(op, default_proj);
            let matched_targets: Vec<OperationTarget> = targets
                .iter()
                .filter(|t| container_targets.contains(&(t.project.clone(), t.name.clone())))
                .cloned()
                .collect();
            if matched_targets.is_empty() && !targets.is_empty() {
                continue;
            }
            let created_raw = op.get_str("created_at").unwrap_or("");
            let created_epoch = parse_incus_created_epoch(created_raw).filter(|v| *v != 0.0);
            let age = created_epoch.map(|c| {
                let diff = now - c;
                if diff <= 0.0 {
                    0u64
                } else {
                    diff as u64
                }
            });
            let op_id = truncate_chars(
                op.get_str("id").filter(|s| !s.is_empty()).unwrap_or("unknown"),
                100,
            );
            let description = truncate_chars(
                op.get_str("description")
                    .filter(|s| !s.is_empty())
                    .unwrap_or(action),
                200,
            );
            let may_cancel = op.get_bool("may_cancel") == Some(true);
            let created_str = truncate_chars(created_raw, 80);

            let iter_targets = if matched_targets.is_empty() {
                vec![OperationTarget {
                    name: String::new(),
                    project: String::new(),
                }]
            } else {
                matched_targets
            };

            for target in iter_targets {
                let target_known = !target.name.is_empty();
                let mut sb = JsonObjBuilder::new();
                sb.str("id", &op_id);
                sb.str("name", &target.name);
                sb.str("project", &target.project);
                sb.str("action", action);
                sb.str("description", &description);
                sb.str("created_at", &created_str);
                match age {
                    Some(a) => sb.u64("age_seconds", a),
                    None => sb.raw("age_seconds", "null"),
                }
                sb.bool("may_cancel", may_cancel);
                sb.bool("target_known", target_known);
                let summary_json = sb.finish();
                active_lifecycle_json.push(summary_json.clone());

                let target_label = if target_known {
                    format!("{}/{}", target.project, target.name)
                } else {
                    "目标实例未知".to_string()
                };

                let Some(age_secs) = age else {
                    alerts_json_items.push(build_alert_json(
                        "incus_lifecycle_operation_unverified",
                        "warning",
                        "Incus 生命周期操作时长无法核实",
                        &format!(
                            "Incus 操作 {op_id}（{description}）仍在运行，但创建时间缺失或无法解析，目标为 {target_label}。自动停止已暂停；先核对操作状态和实例日志。"
                        ),
                        &target.project,
                        &target.name,
                        &format!("operation:{op_id}:age-unknown"),
                        0.0,
                        0.0,
                        None,
                        vec![
                            ("operation_id", ObsVal::Str(op_id.clone())),
                            ("operation_action", ObsVal::Str(action.to_string())),
                            ("target_known", ObsVal::Bool(target_known)),
                            ("may_cancel", ObsVal::Bool(may_cancel)),
                        ],
                    ));
                    continue;
                };

                if (age_secs as f64) < stuck_after {
                    continue;
                }
                stuck_operations_json.push(summary_json);
                let cancel_label = if may_cancel { "可取消" } else { "不可取消" };
                alerts_json_items.push(build_alert_json(
                    "incus_lifecycle_operation_stuck",
                    "critical",
                    "Incus 实例状态变更操作长时间未完成",
                    &format!(
                        "Incus 操作 {op_id}（{description}）已运行约 {age_secs} 秒，目标为 {target_label}，状态显示{cancel_label}。Watcher 不会重复提交停止/重启；不要用 operation delete 当作强制解锁，也不会自动重启 Incus 守护进程。"
                    ),
                    &target.project,
                    &target.name,
                    &format!("operation:{op_id}"),
                    0.0,
                    stuck_after,
                    None,
                    vec![
                        ("age_seconds", ObsVal::U64(age_secs)),
                        ("operation_id", ObsVal::Str(op_id.clone())),
                        ("operation_action", ObsVal::Str(action.to_string())),
                        ("may_cancel", ObsVal::Bool(may_cancel)),
                    ],
                ));
            }
        }

        if !instance_ok {
            let cmd_status = if instance_scan.error.is_empty() {
                "unavailable"
            } else {
                instance_scan.error.as_str()
            };
            alerts_json_items.push(build_alert_json(
                "incus_api_unavailable",
                "warning",
                "Incus 实例状态读取失败",
                "Watcher 未能在限定时间内取得完整 Incus 容器清单；容器状态保持未知，已暂停本轮 Incus 自动停机判断。检查 incus CLI/守护进程和 systemd 状态。",
                "",
                "",
                "api:instances",
                0.0,
                0.0,
                None,
                vec![("command_status", ObsVal::Str(cmd_status.to_string()))],
            ));
        }

        if !operation_ok {
            let cmd_status = if operation_scan.error.is_empty() {
                "unavailable"
            } else {
                operation_scan.error.as_str()
            };
            alerts_json_items.push(build_alert_json(
                "incus_operation_inventory_unavailable",
                "warning",
                "Incus 后台操作清单读取失败",
                "Watcher 无法确认 Incus 是否已有启动、停止、重启或删除操作；本轮会暂停所有 Incus 自动停机，不会冒险重复提交。检查 Incus API 与 incus.service。",
                "",
                "",
                "api:operations",
                0.0,
                0.0,
                None,
                vec![("command_status", ObsVal::Str(cmd_status.to_string()))],
            ));
        }

        let inst_lat = if instance_scan.latency_ms.is_finite() && instance_scan.latency_ms >= 0.0 {
            instance_scan.latency_ms
        } else {
            0.0
        };
        let op_lat = if operation_scan.latency_ms.is_finite() && operation_scan.latency_ms >= 0.0 {
            operation_scan.latency_ms
        } else {
            0.0
        };

        for (label, scan_ok, latency) in [
            ("instances", instance_ok, inst_lat),
            ("operations", operation_ok, op_lat),
        ] {
            if scan_ok && latency >= cfg.slow_api_milliseconds {
                alerts_json_items.push(build_alert_json(
                    "incus_api_slow",
                    "warning",
                    "Incus 管理 API 响应变慢",
                    &format!(
                        "Incus {label} 查询耗时约 {latency:.0} ms。Watcher 只记录与告警，不会重启 Incus 服务。"
                    ),
                    "",
                    "",
                    &format!("api:slow:{label}"),
                    0.0,
                    cfg.slow_api_milliseconds,
                    None,
                    vec![
                        ("latency_ms", ObsVal::F64(latency)),
                        ("query", ObsVal::Str(label.to_string())),
                    ],
                ));
            }
        }

        let status = if scan_status == "unavailable" {
            "unavailable"
        } else if !alerts_json_items.is_empty() {
            "degraded"
        } else if scan_status != "complete" {
            "partial"
        } else {
            "healthy"
        };

        let error_count = error_instances_json.len();
        let active_count = active_lifecycle_json.len();
        let stuck_count = stuck_operations_json.len();

        let bounded_error_instances = format!(
            "[{}]",
            error_instances_json
                .into_iter()
                .take(100)
                .collect::<Vec<_>>()
                .join(",")
        );
        let bounded_active_ops = format!(
            "[{}]",
            active_lifecycle_json
                .into_iter()
                .take(100)
                .collect::<Vec<_>>()
                .join(",")
        );
        let bounded_stuck_ops = format!(
            "[{}]",
            stuck_operations_json
                .into_iter()
                .take(100)
                .collect::<Vec<_>>()
                .join(",")
        );
        let alerts_json = format!(
            "[{}]",
            alerts_json_items
                .into_iter()
                .take(200)
                .collect::<Vec<_>>()
                .join(",")
        );

        let mut lat_b = JsonObjBuilder::new();
        lat_b.f64("instances", inst_lat);
        lat_b.f64("operations", op_lat);
        let latency_obj_json = lat_b.finish();

        let mut snap = JsonObjBuilder::new();
        snap.str("status", status);
        snap.str("scan_status", scan_status);
        snap.i64("observed_at", now as i64);
        snap.str(
            "project_scope",
            if selected_all {
                "all"
            } else {
                selected_project
            },
        );
        snap.usize("instance_count", instances.len());
        snap.usize("error_instance_count", error_count);
        snap.raw("error_instances", &bounded_error_instances);
        snap.usize("operation_count", operation_rows.len());
        snap.usize("active_lifecycle_operation_count", active_count);
        snap.usize("stuck_lifecycle_operation_count", stuck_count);
        snap.raw("active_lifecycle_operations", &bounded_active_ops);
        snap.raw("stuck_lifecycle_operations", &bounded_stuck_ops);
        snap.raw("api_latency_ms", &latency_obj_json);
        snap.f64("command_timeout_seconds", cfg.command_timeout_seconds);
        snap.f64("stuck_operation_threshold_seconds", stuck_after);
        snap.raw(
            "automatic_recovery",
            "{\"error_instance\":\"alert_only\",\"duplicate_lifecycle_actions\":\"blocked\",\"incus_daemon_restart\":\"manual_only\"}",
        );
        snap.raw("alerts", &alerts_json);
        let snapshot_json = snap.finish();

        let ops_health_status = if status == "healthy" && scan_status == "complete" {
            "healthy"
        } else if scan_status == "unavailable" {
            "unavailable"
        } else {
            "warning"
        };

        let mut det = JsonObjBuilder::new();
        det.str("scan_status", scan_status);
        det.usize("instances", instances.len());
        det.usize("error_instances", error_count);
        det.usize("active_lifecycle_operations", active_count);
        det.usize("stuck_lifecycle_operations", stuck_count);
        det.raw("api_latency_ms", &latency_obj_json);
        let details_json = det.finish();

        let mut oh = JsonObjBuilder::new();
        oh.str("source", "incus_runtime");
        oh.str("status", ops_health_status);
        oh.raw("details", &details_json);
        oh.str(
            "guidance",
            "状态变更异常仅告警并保留现场；先核对实例日志和 Incus 操作，不重复停止，不自动重启 Incus 守护进程。",
        );
        let operations_health_json = oh.finish();

        IncusSnapshotReport {
            status: status.to_string(),
            scan_status: scan_status.to_string(),
            health_json: snapshot_json.clone(),
            snapshot_json,
            operations_health_json,
            alerts_json,
            error_instance_count: error_count,
            active_lifecycle_operation_count: active_count,
            stuck_lifecycle_operation_count: stuck_count,
        }
    }

    /// Build Incus runtime snapshot JSON matching `client/incus_health.py::build_snapshot`.
    pub fn build_incus_snapshot_json(
        instance_scan_json: &str,
        operation_scan_json: &str,
        project: &str,
        now_epoch: f64,
    ) -> String {
        let inst = IncusScan::from_json(instance_scan_json);
        let ops = IncusScan::from_json(operation_scan_json);
        let cfg = IncusHealthConfig::from_env();
        build_incus_snapshot(&inst, &ops, project, now_epoch, &cfg).snapshot_json
    }

    /// Build both `(operations_health_json, alerts_json)` from raw scan inputs.
    pub fn build_incus_health_and_alerts_json(
        instance_scan_json: &str,
        operation_scan_json: &str,
        project: &str,
        now_epoch: f64,
    ) -> (String, String) {
        let inst = IncusScan::from_json(instance_scan_json);
        let ops = IncusScan::from_json(operation_scan_json);
        let cfg = IncusHealthConfig::from_env();
        let report = build_incus_snapshot(&inst, &ops, project, now_epoch, &cfg);
        (report.operations_health_json, report.alerts_json)
    }

    /// Build the `operations.health` `"incus_runtime"` object matching `client/operations.py`.
    pub fn build_incus_operations_health_json(snapshot_json: &str) -> String {
        let Ok(val) = JsonVal::parse(snapshot_json) else {
            return String::new();
        };
        let Some(obj) = val.as_obj() else {
            return String::new();
        };
        let scan_status = obj
            .get("scan_status")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        let runtime_status = obj
            .get("status")
            .and_then(JsonVal::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown");
        let health_status = if runtime_status == "healthy" && scan_status == "complete" {
            "healthy"
        } else if scan_status == "unavailable" {
            "unavailable"
        } else {
            "warning"
        };

        let api_latency_raw = obj
            .get("api_latency_ms")
            .filter(|v| v.as_obj().is_some())
            .map(json_val_to_string)
            .unwrap_or_else(|| "{}".to_string());

        let mut det = JsonObjBuilder::new();
        det.str("scan_status", scan_status);
        det.i64(
            "instances",
            obj.get("instance_count").and_then(JsonVal::as_i64).unwrap_or(0),
        );
        det.i64(
            "error_instances",
            obj.get("error_instance_count")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0),
        );
        det.i64(
            "active_lifecycle_operations",
            obj.get("active_lifecycle_operation_count")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0),
        );
        det.i64(
            "stuck_lifecycle_operations",
            obj.get("stuck_lifecycle_operation_count")
                .and_then(JsonVal::as_i64)
                .unwrap_or(0),
        );
        det.raw("api_latency_ms", &api_latency_raw);

        let mut oh = JsonObjBuilder::new();
        oh.str("source", "incus_runtime");
        oh.str("status", health_status);
        oh.raw("details", &det.finish());
        oh.str(
            "guidance",
            "状态变更异常仅告警并保留现场；先核对实例日志和 Incus 操作，不重复停止，不自动重启 Incus 守护进程。",
        );
        oh.finish()
    }

    /// Pure fail-closed preflight matching `client/incus_health.py::stop_preflight`.
    pub fn evaluate_incus_stop_preflight(
        instance_scan: &IncusScan,
        operation_scan: &IncusScan,
        project: &str,
        name: &str,
        config: &IncusHealthConfig,
    ) -> Result<(), String> {
        let cfg = config.normalized();
        let proj = {
            let p = project.trim();
            if p.is_empty() {
                "default"
            } else {
                p
            }
        };
        let target_name = name.trim();
        if all_projects(proj) || target_name.is_empty() {
            return Err("Incus stop skipped: exact project and instance identity are required".to_string());
        }
        if !instance_scan.ok {
            return Err("Incus stop skipped: current instance state could not be verified".to_string());
        }
        if instance_scan.latency_ms >= cfg.slow_api_milliseconds {
            return Err("Incus stop skipped: instance query is slow; leave lifecycle state untouched".to_string());
        }
        let matches: Vec<&JsonVal> = instance_scan
            .items
            .iter()
            .filter(|item| instance_name(item) == target_name)
            .collect();
        if matches.len() != 1 {
            return Err("Incus stop skipped: the exact instance could not be identified".to_string());
        }
        let instance = matches[0];
        let kind = instance
            .get_str("type")
            .unwrap_or("container")
            .to_ascii_lowercase();
        if !matches!(kind.as_str(), "container" | "") {
            return Err("Incus stop skipped: target is not a container".to_string());
        }
        if instance_status(instance) != "running" {
            let st = instance.get_str("status").unwrap_or("unknown");
            return Err(format!(
                "Incus stop skipped: target state is {st}; no repeated stop submitted"
            ));
        }

        if !operation_scan.ok {
            return Err("Incus stop skipped: pending lifecycle operations could not be checked".to_string());
        }
        if operation_scan.latency_ms >= cfg.slow_api_milliseconds {
            return Err("Incus stop skipped: operation query is slow; leave lifecycle state untouched".to_string());
        }
        for op in &operation_scan.items {
            if !operation_is_running(op) || incus_lifecycle_action(op).is_none() {
                continue;
            }
            let targets = operation_targets(op, proj);
            if targets.is_empty()
                || targets
                    .iter()
                    .any(|t| t.project == proj && t.name == target_name)
            {
                let op_id = op.get_str("id").filter(|s| !s.is_empty()).unwrap_or("unknown");
                return Err(format!(
                    "Incus stop skipped: lifecycle operation {op_id} is already running for this target or has an unknown target"
                ));
            }
        }
        Ok(())
    }
}

// ===========================================================================
// 2. SOCKS Detector & Panel Pairing (`client/socks_detector.py` + `client/agent.py`)
// ===========================================================================

pub mod socks_detector {
    use super::util::{
        atomic_write_private, json_str_array, now_unix_secs, percent_decode,
        posix_basename, shlex_split, JsonObjBuilder,
    };
    use super::*;

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
}

// ===========================================================================
// 3. Disk Cleanup (`client/disk_cleanup.py` + `client/disk_cleanup_worker.py`)
// ===========================================================================

pub mod disk_cleanup {
    use super::util::{
        atomic_write_private, json_str, json_val_to_string, now_unix_secs, JsonObjBuilder,
    };
    use super::*;

    pub const DEFAULT_RETENTION_DAYS: u16 = 14;
    pub const MIN_RETENTION_DAYS: u16 = 14;
    pub const MAX_RETENTION_DAYS: u16 = 90;
    pub const DEFAULT_INTERVAL_HOURS: u16 = 24;
    pub const MIN_INTERVAL_HOURS: u16 = 6;
    pub const MAX_INTERVAL_HOURS: u16 = 168;

    pub const DAY_SECONDS: i64 = 86_400;
    pub const MAX_BYTES: u64 = 512 * 1024 * 1024;
    pub const MAX_FILES: usize = 1000;
    pub const MAX_VISITED_ENTRIES: usize = 20_000;
    pub const SCAN_PLAN_MAX_AGE_SECS: i64 = 900;
    pub const MAX_TARGETS_PER_RUN: usize = 5;
    pub const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
    pub const DEFAULT_STATE_PATH: &str = "/var/lib/narwhal-monitor/disk-cleanup.json";

    pub const PROTECTED_CONTAINERS: &[&str] = &[
        "narwhal-monitor-client",
        "narwhal-monitor-server",
        "narwhal-monitor-caddy",
    ];
    pub const ALLOWED_RUNTIMES: &[&str] = &["incus", "podman", "runman"];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CleanupPolicy {
        pub enabled: bool,
        pub include_containers: bool,
        pub retention_days: u16,
        pub interval_hours: u16,
    }

    impl Default for CleanupPolicy {
        fn default() -> Self {
            Self {
                enabled: false,
                include_containers: true,
                retention_days: DEFAULT_RETENTION_DAYS,
                interval_hours: DEFAULT_INTERVAL_HOURS,
            }
        }
    }

    impl CleanupPolicy {
        pub fn to_json(&self) -> String {
            let mut b = JsonObjBuilder::new();
            b.bool("enabled", self.enabled);
            b.bool("include_containers", self.include_containers);
            b.u64("retention_days", self.retention_days as u64);
            b.u64("interval_hours", self.interval_hours as u64);
            b.finish()
        }
    }

    /// Validate cleanup policy JSON (`retention_days` 14..=90, `interval_hours` 6..=168).
    /// When `expected_node_id` is supplied, a mismatched or missing `node_id` fails closed to `CleanupPolicy::default()`.
    pub fn validate_cleanup_policy(
        policy_json: &str,
        expected_node_id: Option<&str>,
    ) -> Result<CleanupPolicy, String> {
        let val = JsonVal::parse(policy_json.trim())
            .map_err(|_| "invalid cleanup policy JSON".to_string())?;
        let Some(obj) = val.as_obj() else {
            return Ok(CleanupPolicy::default());
        };
        if let Some(expected) = expected_node_id {
            let got = obj.get("node_id").and_then(JsonVal::as_str).unwrap_or("");
            if expected.is_empty() || got != expected {
                return Ok(CleanupPolicy::default());
            }
        }
        for key in obj.keys() {
            if !matches!(
                key.as_str(),
                "enabled" | "include_containers" | "retention_days" | "interval_hours" | "node_id"
            ) {
                return Err(format!("unknown cleanup policy key: {key}"));
            }
        }
        let mut result = CleanupPolicy::default();
        if let Some(v) = obj.get("enabled") {
            result.enabled = v
                .as_bool()
                .ok_or_else(|| "boolean policy required for enabled".to_string())?;
        }
        if let Some(v) = obj.get("include_containers") {
            result.include_containers = v
                .as_bool()
                .ok_or_else(|| "boolean policy required for include_containers".to_string())?;
        }
        if let Some(v) = obj.get("retention_days") {
            let days = v
                .as_i64()
                .ok_or_else(|| "retention must be 14-90 days".to_string())?;
            if !(MIN_RETENTION_DAYS as i64..=MAX_RETENTION_DAYS as i64).contains(&days) {
                return Err("retention must be 14-90 days".to_string());
            }
            result.retention_days = days as u16;
        }
        if let Some(v) = obj.get("interval_hours") {
            let hours = v
                .as_i64()
                .ok_or_else(|| "interval must be 6-168 hours".to_string())?;
            if !(MIN_INTERVAL_HOURS as i64..=MAX_INTERVAL_HOURS as i64).contains(&hours) {
                return Err("interval must be 6-168 hours".to_string());
            }
            result.interval_hours = hours as u16;
        }
        Ok(result)
    }

    pub fn validate_cleanup_policy_json(
        policy_json: &str,
        expected_node_id: Option<&str>,
    ) -> String {
        match validate_cleanup_policy(policy_json, expected_node_id) {
            Ok(p) => {
                let mut b = JsonObjBuilder::new();
                b.bool("ok", true);
                b.raw("policy", &p.to_json());
                b.finish()
            }
            Err(err) => {
                let mut b = JsonObjBuilder::new();
                b.bool("ok", false);
                b.str("error", &err);
                b.finish()
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CleanupTarget {
        pub runtime: String,
        pub runtime_bin: String,
        pub project: String,
        pub name: String,
        pub id: String,
        pub stable_id: String,
        pub instance_id: String,
        pub pid: String,
        pub pid_start_ticks: String,
    }

    impl CleanupTarget {
        pub fn host() -> Self {
            Self {
                runtime: "host".to_string(),
                runtime_bin: String::new(),
                project: String::new(),
                name: "__host__".to_string(),
                id: "host".to_string(),
                stable_id: String::new(),
                instance_id: String::new(),
                pid: String::new(),
                pid_start_ticks: String::new(),
            }
        }

        pub fn to_json(&self) -> String {
            let mut b = JsonObjBuilder::new();
            b.str("runtime", &self.runtime);
            b.str("runtime_bin", &self.runtime_bin);
            b.str("project", &self.project);
            b.str("name", &self.name);
            b.str("id", &self.id);
            b.str("stable_id", &self.stable_id);
            b.str("instance_id", &self.instance_id);
            b.str("pid", &self.pid);
            b.str("pid_start_ticks", &self.pid_start_ticks);
            b.finish()
        }

        fn from_json(val: &JsonVal) -> Result<Self, String> {
            let obj = val
                .as_obj()
                .ok_or_else(|| "invalid cleanup target object".to_string())?;
            let get_str = |k: &str| obj.get(k).and_then(JsonVal::as_str).unwrap_or("").to_string();
            Ok(Self {
                runtime: get_str("runtime"),
                runtime_bin: get_str("runtime_bin"),
                project: get_str("project"),
                name: get_str("name"),
                id: get_str("id"),
                stable_id: get_str("stable_id"),
                instance_id: get_str("instance_id"),
                pid: get_str("pid"),
                pid_start_ticks: get_str("pid_start_ticks"),
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct CleanupRunItem {
        pub runtime: String,
        pub name: String,
        pub project: String,
        pub status: String,
        pub reason: String,
        pub instance_id: String,
        pub candidate_files: usize,
        pub candidate_bytes: u64,
        pub deleted_files: usize,
        pub unlinked_bytes: u64,
        pub freed_bytes: u64,
        pub skipped: usize,
        pub errors: usize,
        pub bounded: bool,
        pub extra_fields: BTreeMap<String, JsonVal>,
    }

    impl CleanupRunItem {
        fn from_json(val: &JsonVal) -> Result<Self, String> {
            let obj = val
                .as_obj()
                .ok_or_else(|| "invalid cleanup run item".to_string())?;
            let mut extra = BTreeMap::new();
            for (k, v) in obj {
                if !matches!(
                    k.as_str(),
                    "runtime"
                        | "name"
                        | "project"
                        | "status"
                        | "reason"
                        | "instance_id"
                        | "candidate_files"
                        | "candidate_bytes"
                        | "deleted_files"
                        | "unlinked_bytes"
                        | "freed_bytes"
                        | "skipped"
                        | "errors"
                        | "bounded"
                ) {
                    extra.insert(k.clone(), v.clone());
                }
            }
            Ok(Self {
                runtime: obj.get("runtime").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                name: obj.get("name").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                project: obj.get("project").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                status: obj.get("status").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                reason: obj.get("reason").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                instance_id: obj.get("instance_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                candidate_files: obj.get("candidate_files").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
                candidate_bytes: obj.get("candidate_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
                deleted_files: obj.get("deleted_files").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
                unlinked_bytes: obj.get("unlinked_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
                freed_bytes: obj.get("freed_bytes").and_then(JsonVal::as_u64).unwrap_or(0),
                skipped: obj.get("skipped").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
                errors: obj.get("errors").and_then(JsonVal::as_u64).unwrap_or(0) as usize,
                bounded: obj.get("bounded").and_then(JsonVal::as_bool).unwrap_or(false),
                extra_fields: extra,
            })
        }

        pub fn to_json(&self) -> String {
            let mut b = JsonObjBuilder::new();
            b.str("runtime", &self.runtime);
            b.str("name", &self.name);
            b.str("project", &self.project);
            b.str("status", &self.status);
            if !self.reason.is_empty() {
                b.str("reason", &self.reason);
            }
            if !self.instance_id.is_empty() {
                b.str("instance_id", &self.instance_id);
            }
            b.usize("candidate_files", self.candidate_files);
            b.u64("candidate_bytes", self.candidate_bytes);
            b.usize("deleted_files", self.deleted_files);
            b.u64("unlinked_bytes", self.unlinked_bytes);
            b.u64("freed_bytes", self.freed_bytes);
            b.usize("skipped", self.skipped);
            b.usize("errors", self.errors);
            b.bool("bounded", self.bounded);
            for (k, v) in &self.extra_fields {
                b.raw(k, &json_val_to_string(v));
            }
            b.finish()
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct CleanupRunRecord {
        pub run_id: String,
        pub action_id: i64,
        pub node_id: String,
        pub mode: String,
        pub automatic: bool,
        pub started_at: i64,
        pub finished_at: Option<i64>,
        pub status: String,
        pub targets: Vec<CleanupTarget>,
        pub items: Vec<CleanupRunItem>,
        pub plan_id: String,
        pub delivered: bool,
        pub error: String,
    }

    impl CleanupRunRecord {
        fn from_json(val: &JsonVal) -> Result<Self, String> {
            let obj = val
                .as_obj()
                .ok_or_else(|| "invalid cleanup run entry".to_string())?;
            let targets = match obj.get("targets") {
                Some(JsonVal::Arr(arr)) => {
                    let mut v = Vec::with_capacity(arr.len());
                    for t in arr {
                        v.push(CleanupTarget::from_json(t)?);
                    }
                    v
                }
                None => Vec::new(),
                _ => return Err("invalid cleanup state; no automatic deletion".to_string()),
            };
            let items = match obj.get("items") {
                Some(JsonVal::Arr(arr)) => {
                    let mut v = Vec::with_capacity(arr.len());
                    for item in arr {
                        v.push(CleanupRunItem::from_json(item)?);
                    }
                    v
                }
                None => Vec::new(),
                _ => return Err("invalid cleanup state; no automatic deletion".to_string()),
            };
            Ok(Self {
                run_id: obj.get("run_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                action_id: obj.get("action_id").and_then(JsonVal::as_i64).unwrap_or(0),
                node_id: obj.get("node_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                mode: obj.get("mode").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                automatic: obj.get("automatic").and_then(JsonVal::as_bool).unwrap_or(false),
                started_at: obj.get("started_at").and_then(JsonVal::as_i64).unwrap_or(0),
                finished_at: obj.get("finished_at").and_then(JsonVal::as_i64),
                status: obj.get("status").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                targets,
                items,
                plan_id: obj.get("plan_id").and_then(JsonVal::as_str).unwrap_or("").to_string(),
                delivered: obj.get("delivered").and_then(JsonVal::as_bool).unwrap_or(false),
                error: obj.get("error").and_then(JsonVal::as_str).unwrap_or("").to_string(),
            })
        }

        pub fn to_json(&self) -> String {
            let targets_json: Vec<String> = self.targets.iter().map(CleanupTarget::to_json).collect();
            let items_json: Vec<String> = self.items.iter().map(CleanupRunItem::to_json).collect();
            let mut b = JsonObjBuilder::new();
            b.str("run_id", &self.run_id);
            b.i64("action_id", self.action_id);
            b.str("node_id", &self.node_id);
            b.str("mode", &self.mode);
            b.bool("automatic", self.automatic);
            b.i64("started_at", self.started_at);
            if let Some(fin) = self.finished_at {
                b.i64("finished_at", fin);
            }
            b.str("status", &self.status);
            b.raw("targets", &format!("[{}]", targets_json.join(",")));
            b.raw("items", &format!("[{}]", items_json.join(",")));
            b.str("plan_id", &self.plan_id);
            if self.delivered {
                b.bool("delivered", true);
            }
            if !self.error.is_empty() {
                b.str("error", &self.error);
            }
            b.finish()
        }
    }

    #[derive(Debug, Clone, PartialEq, Default)]
    pub struct CleanupJournalState {
        pub runs: Vec<CleanupRunRecord>,
        pub attempts: BTreeMap<String, f64>,
    }

    impl CleanupJournalState {
        pub fn to_json(&self) -> String {
            let runs_json: Vec<String> = self.runs.iter().map(CleanupRunRecord::to_json).collect();
            let mut att = JsonObjBuilder::new();
            for (k, v) in &self.attempts {
                att.f64(k, *v);
            }
            let mut b = JsonObjBuilder::new();
            b.raw("runs", &format!("[{}]", runs_json.join(",")));
            b.raw("attempts", &att.finish());
            b.finish()
        }
    }

    /// Read cleanup journal state fail-closed WITHOUT mutating `running` runs to `interrupted`.
    pub fn read_cleanup_journal_readonly(path: &Path) -> Result<CleanupJournalState, String> {
        if !path.is_absolute() {
            return Err("journal path must be absolute".to_string());
        }
        if super::util::is_symlink_path(path) {
            return Err("journal symlink rejected".to_string());
        }
        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CleanupJournalState::default());
            }
            Err(_) => return Err("invalid cleanup journal".to_string()),
        };
        if !meta.is_file() || meta.len() > MAX_JOURNAL_BYTES {
            return Err("invalid cleanup journal".to_string());
        }
        let raw = fs::read_to_string(path).map_err(|_| "invalid cleanup journal".to_string())?;
        let val = JsonVal::parse(&raw).map_err(|_| "invalid cleanup journal schema".to_string())?;
        let Some(obj) = val.as_obj() else {
            return Err("invalid cleanup journal schema".to_string());
        };
        if obj.len() > 1000 {
            return Err("invalid cleanup journal schema".to_string());
        }

        let mut runs = Vec::new();
        if let Some(runs_val) = obj.get("runs") {
            let Some(arr) = runs_val.as_arr() else {
                return Err("invalid cleanup state; no automatic deletion".to_string());
            };
            if arr.len() > 20 {
                return Err("invalid cleanup state; no automatic deletion".to_string());
            }
            for r in arr {
                runs.push(CleanupRunRecord::from_json(r)?);
            }
        }

        let mut attempts = BTreeMap::new();
        if let Some(att_val) = obj.get("attempts") {
            let Some(att_obj) = att_val.as_obj() else {
                return Err("invalid cleanup state; no automatic deletion".to_string());
            };
            for (k, v) in att_obj {
                let ts = v
                    .as_f64()
                    .filter(|n| n.is_finite() && *n >= 0.0)
                    .ok_or_else(|| "invalid cleanup timing state".to_string())?;
                attempts.insert(k.clone(), ts);
            }
        }

        Ok(CleanupJournalState { runs, attempts })
    }

    /// Load cleanup journal state fail-closed and mark any `running` run as `interrupted`.
    pub fn load_cleanup_journal(path: &Path, now_epoch: i64) -> Result<CleanupJournalState, String> {
        let mut state = read_cleanup_journal_readonly(path)?;
        for rec in &mut state.runs {
            if rec.status == "running" {
                rec.status = "interrupted".to_string();
                rec.finished_at = Some(now_epoch);
            }
        }
        Ok(state)
    }

    /// Save cleanup journal state atomically (`0600` on Unix), bounded to 20 runs and 1000 attempts.
    pub fn save_cleanup_journal(
        path: &Path,
        state: &mut CleanupJournalState,
    ) -> Result<(), String> {
        if state.runs.len() > 20 {
            let drain_count = state.runs.len() - 20;
            state.runs.drain(0..drain_count);
        }
        if state.attempts.len() > 1000 {
            let mut sorted: Vec<(String, f64)> =
                state.attempts.iter().map(|(k, &v)| (k.clone(), v)).collect();
            sorted.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            let keep_from = sorted.len() - 1000;
            let trimmed: BTreeMap<String, f64> = sorted.into_iter().skip(keep_from).collect();
            state.attempts = trimmed;
        }
        let payload = state.to_json();
        atomic_write_private(path, payload.as_bytes(), ".disk-cleanup-")
    }

    pub fn valid_container_name(name: &str) -> bool {
        (1..=200).contains(&name.len())
            && name.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'+' | b'-')
            })
    }

    /// Runtime environment check matching `client/disk_cleanup.py::available`.
    pub fn live_disk_cleanup_available() -> bool {
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
        #[cfg(target_os = "linux")]
        {
            let is_root = fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines().find_map(|line| {
                        let rest = line.strip_prefix("Uid:")?;
                        let euid = rest.split_whitespace().nth(1)?;
                        euid.parse::<u32>().ok()
                    })
                })
                == Some(0);
            is_root
                && Path::new("/proc/self/fdinfo").is_dir()
                && Path::new("/opt/narwhal-monitor/client.env").is_file()
                && !Path::new("/.dockerenv").exists()
                && !Path::new("/run/.containerenv").exists()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CleanupContainerCandidate {
        pub runtime: String,
        pub runtime_bin: String,
        pub project: String,
        pub name: String,
        pub id: String,
        pub stable_id: String,
        pub instance_id: String,
        pub pid: String,
        pub pid_start_ticks: String,
    }

    /// Select eligible host + container cleanup targets (excluding Docker & protected containers).
    pub fn select_cleanup_targets(
        policy: &CleanupPolicy,
        containers: &[CleanupContainerCandidate],
    ) -> Vec<CleanupTarget> {
        let mut result = vec![CleanupTarget::host()];
        if policy.include_containers {
            for c in containers.iter().take(500) {
                if !ALLOWED_RUNTIMES.contains(&c.runtime.as_str())
                    || PROTECTED_CONTAINERS.contains(&c.name.as_str())
                {
                    continue;
                }
                if !valid_container_name(&c.name) {
                    continue;
                }
                result.push(CleanupTarget {
                    runtime: c.runtime.clone(),
                    runtime_bin: c.runtime_bin.clone(),
                    project: c.project.clone(),
                    name: c.name.clone(),
                    id: c.id.clone(),
                    stable_id: c.stable_id.clone(),
                    instance_id: c.instance_id.clone(),
                    pid: c.pid.clone(),
                    pid_start_ticks: c.pid_start_ticks.clone(),
                });
            }
        }
        result
    }

    /// Deterministic cooldown key matching `Controller.key` (Podman ID truncated to 12 chars).
    pub fn cleanup_cooldown_key(target: &CleanupTarget) -> String {
        let mut identity = if target.runtime == "runman" {
            target.instance_id.as_str()
        } else if !target.stable_id.is_empty() {
            target.stable_id.as_str()
        } else {
            target.id.as_str()
        };
        if target.runtime == "podman" {
            let cut = identity
                .char_indices()
                .nth(12)
                .map(|(idx, _)| idx)
                .unwrap_or(identity.len());
            identity = &identity[..cut];
        }
        format!(
            "[{},{},{},{}]",
            json_str(&target.runtime),
            json_str(&target.project),
            json_str(&target.name),
            json_str(identity)
        )
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct CleanupActionContext {
        pub host_available: bool,
        pub node_id: String,
        pub now_epoch: i64,
        pub journal_path: PathBuf,
        pub policy: CleanupPolicy,
        pub containers: Vec<CleanupContainerCandidate>,
        pub quarantined_identities: BTreeSet<String>,
        pub active_run_in_progress: bool,
    }

    impl Default for CleanupActionContext {
        fn default() -> Self {
            Self {
                host_available: false,
                node_id: String::new(),
                now_epoch: 0,
                journal_path: PathBuf::from(DEFAULT_STATE_PATH),
                policy: CleanupPolicy::default(),
                containers: Vec::new(),
                quarantined_identities: BTreeSet::new(),
                active_run_in_progress: false,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct CleanupActionOutcome {
        pub ok: bool,
        pub status: &'static str,
        pub message: String,
        pub run: Option<CleanupRunRecord>,
        pub targets: Vec<CleanupTarget>,
    }

    impl CleanupActionOutcome {
        fn fail(message: impl Into<String>) -> Self {
            Self {
                ok: false,
                status: "failed",
                message: message.into(),
                run: None,
                targets: Vec::new(),
            }
        }

        pub fn to_json(&self) -> String {
            let targets_json: Vec<String> = self.targets.iter().map(CleanupTarget::to_json).collect();
            let mut b = JsonObjBuilder::new();
            b.bool("ok", self.ok);
            b.str("status", self.status);
            b.str("message", &self.message);
            match &self.run {
                Some(r) => b.raw("run", &r.to_json()),
                None => b.raw("run", "null"),
            }
            b.raw("targets", &format!("[{}]", targets_json.join(",")));
            b.finish()
        }
    }

    fn target_quarantined(target: &CleanupTarget, quarantined: &BTreeSet<String>) -> bool {
        if target.runtime == "host" || quarantined.is_empty() {
            return false;
        }
        [
            target.instance_id.as_str(),
            target.stable_id.as_str(),
            target.id.as_str(),
        ]
        .iter()
        .any(|id| !id.is_empty() && quarantined.contains(*id))
    }

    /// Validate and stage a `disk_cleanup_scan` or `disk_cleanup_execute` action with all safety checks.
    pub fn execute_disk_cleanup_action(
        action_json: &str,
        ctx: &CleanupActionContext,
    ) -> CleanupActionOutcome {
        if !ctx.host_available {
            return CleanupActionOutcome::fail("native root host Agent required");
        }
        let Ok(val) = JsonVal::parse(action_json.trim()) else {
            return CleanupActionOutcome::fail("invalid cleanup action JSON");
        };
        let Some(obj) = val.as_obj() else {
            return CleanupActionOutcome::fail("invalid cleanup action object");
        };
        let action_type = obj
            .get("action_type")
            .and_then(JsonVal::as_str)
            .unwrap_or("");
        if !matches!(action_type, "disk_cleanup_scan" | "disk_cleanup_execute") {
            return CleanupActionOutcome::fail("unsupported cleanup action type");
        }
        let Some(action_id) = obj.get("id").and_then(JsonVal::as_i64).filter(|&id| id > 0) else {
            return CleanupActionOutcome::fail("invalid cleanup action id");
        };
        let params = obj.get("params").and_then(JsonVal::as_obj);
        let expected_node_id = params
            .and_then(|p| p.get("expected_node_id"))
            .and_then(JsonVal::as_str)
            .unwrap_or("");
        if ctx.node_id.is_empty() || expected_node_id != ctx.node_id {
            return CleanupActionOutcome::fail("cleanup node identity mismatch");
        }

        let now = if ctx.now_epoch == 0 {
            now_unix_secs()
        } else {
            ctx.now_epoch
        };

        let mut state = match read_cleanup_journal_readonly(&ctx.journal_path) {
            Ok(s) => s,
            Err(err) => return CleanupActionOutcome::fail(err),
        };

        if let Some(existing) = state.runs.iter().find(|r| r.action_id == action_id) {
            return CleanupActionOutcome {
                ok: true,
                status: "accepted",
                message: "cleanup action already accepted".to_string(),
                run: Some(existing.clone()),
                targets: existing.targets.clone(),
            };
        }

        if ctx.active_run_in_progress {
            return CleanupActionOutcome::fail("another cleanup task is running");
        }

        let execute = action_type == "disk_cleanup_execute";
        let plan_id = params
            .and_then(|p| p.get("plan_id"))
            .and_then(JsonVal::as_str)
            .unwrap_or("")
            .to_string();

        let targets = if execute {
            let confirmed = params
                .and_then(|p| p.get("confirmed"))
                .and_then(JsonVal::as_bool)
                == Some(true);
            let plan = state.runs.iter().find(|r| r.run_id == plan_id);
            let Some(plan_rec) = plan else {
                return CleanupActionOutcome::fail(
                    "a completed fresh scan and confirmation are required",
                );
            };
            let fresh = now >= plan_rec.started_at
                && now.saturating_sub(plan_rec.started_at) <= SCAN_PLAN_MAX_AGE_SECS;
            if !confirmed
                || plan_rec.mode != "scan"
                || !matches!(plan_rec.status.as_str(), "scanned" | "partial")
                || plan_rec.node_id != ctx.node_id
                || !fresh
            {
                return CleanupActionOutcome::fail(
                    "a completed fresh scan and confirmation are required",
                );
            }
            let clean_keys: BTreeSet<(String, String, String)> = plan_rec
                .items
                .iter()
                .filter(|item| item.status == "scanned")
                .map(|item| {
                    (
                        item.runtime.clone(),
                        item.project.clone(),
                        item.name.clone(),
                    )
                })
                .collect();

            let selected: Vec<CleanupTarget> = plan_rec
                .targets
                .iter()
                .filter(|t| {
                    clean_keys.contains(&(t.runtime.clone(), t.project.clone(), t.name.clone()))
                        && !target_quarantined(t, &ctx.quarantined_identities)
                        && (t.runtime == "host"
                            || (ALLOWED_RUNTIMES.contains(&t.runtime.as_str())
                                && !PROTECTED_CONTAINERS.contains(&t.name.as_str())
                                && valid_container_name(&t.name)))
                })
                .cloned()
                .collect();
            if selected.is_empty() {
                return CleanupActionOutcome::fail("no safely scanned targets");
            }
            selected
        } else {
            select_cleanup_targets(&ctx.policy, &ctx.containers)
                .into_iter()
                .filter(|t| !target_quarantined(t, &ctx.quarantined_identities))
                .take(MAX_TARGETS_PER_RUN)
                .collect()
        };

        let run = CleanupRunRecord {
            run_id: format!("action-{action_id}"),
            action_id,
            node_id: ctx.node_id.clone(),
            mode: if execute { "clean" } else { "scan" }.to_string(),
            automatic: false,
            started_at: now,
            finished_at: None,
            status: "running".to_string(),
            targets: targets.clone(),
            items: Vec::new(),
            plan_id,
            delivered: false,
            error: String::new(),
        };
        state.runs.push(run.clone());
        if execute {
            for t in &targets {
                state.attempts.insert(cleanup_cooldown_key(t), now as f64);
            }
        }
        if let Err(err) = save_cleanup_journal(&ctx.journal_path, &mut state) {
            return CleanupActionOutcome::fail(err);
        }

        CleanupActionOutcome {
            ok: true,
            status: "running",
            message: "bounded cleanup worker accepted; await final receipt".to_string(),
            run: Some(run),
            targets,
        }
    }

    pub fn execute_disk_cleanup_action_json(
        action_json: &str,
        ctx: &CleanupActionContext,
    ) -> String {
        execute_disk_cleanup_action(action_json, ctx).to_json()
    }

    // -----------------------------------------------------------------------
    // Allowlist matching & bounded directory sweep (`disk_cleanup_worker.py`)
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum CleanupCategory {
        PackageCache,
        ArchivedLogs,
        CrashFiles,
    }

    impl CleanupCategory {
        pub fn as_str(&self) -> &'static str {
            match self {
                Self::PackageCache => "package_cache",
                Self::ArchivedLogs => "archived_logs",
                Self::CrashFiles => "crash_files",
            }
        }
    }

    struct AllowRule {
        category: CleanupCategory,
        rel_dir: &'static str,
        default_days: u16,
        max_depth: usize,
        matcher: fn(&str) -> bool,
    }

    fn all_digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }

    fn match_archive_log(name: &str) -> bool {
        let stem = name
            .strip_suffix(".gz")
            .or_else(|| name.strip_suffix(".xz"))
            .or_else(|| name.strip_suffix(".bz2"))
            .or_else(|| name.strip_suffix(".zst"))
            .unwrap_or(name);
        let bases = [
            "syslog",
            "messages",
            "daemon.log",
            "kern.log",
            "debug",
            "dmesg",
            "boot.log",
            "access.log",
            "error.log",
        ];
        for base in bases {
            if let Some(rest) = stem.strip_prefix(base) {
                if let Some(d) = rest.strip_prefix('.') {
                    return all_digits(d);
                }
                if let Some(d) = rest.strip_prefix('-') {
                    return d.len() == 8 && all_digits(d);
                }
            }
        }
        false
    }

    fn match_caddy_log(name: &str) -> bool {
        let stem = name
            .strip_suffix(".gz")
            .or_else(|| name.strip_suffix(".xz"))
            .or_else(|| name.strip_suffix(".zst"))
            .unwrap_or(name);
        for base in ["access.log", "error.log"] {
            if let Some(rest) = stem.strip_prefix(base) {
                if let Some(d) = rest.strip_prefix('.') {
                    return all_digits(d);
                }
                if let Some(d) = rest.strip_prefix('-') {
                    return d.len() == 8 && all_digits(d);
                }
            }
        }
        for prefix in ["access-", "error-", "caddy-"] {
            if let Some(rest) = stem.strip_prefix(prefix) {
                if let Some(body) = rest.strip_suffix(".log") {
                    let b = body.as_bytes();
                    if b.len() >= 12
                        && b[0..4].iter().all(u8::is_ascii_digit)
                        && b[4] == b'-'
                        && b[5..7].iter().all(u8::is_ascii_digit)
                        && b[7] == b'-'
                        && b[8..10].iter().all(u8::is_ascii_digit)
                        && b[10] == b'T'
                        && b[11..].iter().all(|&c| c.is_ascii_digit() || c == b'.' || c == b'-')
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn match_journal_archive(name: &str) -> bool {
        let stem = name.strip_suffix('~').unwrap_or(name);
        let Some(body) = stem.strip_suffix(".journal") else {
            return false;
        };
        let Some((left, hex_part)) = body.split_once('@') else {
            return false;
        };
        let left_ok = left == "system"
            || left
                .strip_prefix("user-")
                .map(all_digits)
                .unwrap_or(false);
        let hex_ok = !hex_part.is_empty()
            && hex_part
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'));
        left_ok && hex_ok
    }

    fn match_deb(name: &str) -> bool {
        name.len() > 4 && name.ends_with(".deb")
    }

    fn match_apk(name: &str) -> bool {
        name.len() > 4 && name.ends_with(".apk")
    }

    fn match_pacman(name: &str) -> bool {
        let core = name.strip_suffix(".sig").unwrap_or(name);
        core.strip_suffix(".pkg.tar.xz")
            .or_else(|| core.strip_suffix(".pkg.tar.zst"))
            .map(|prefix| !prefix.is_empty())
            .unwrap_or(false)
    }

    fn match_rpm(name: &str) -> bool {
        name.len() > 4 && name.ends_with(".rpm")
    }

    fn match_crash(name: &str) -> bool {
        name.strip_suffix(".crash")
            .or_else(|| name.strip_suffix(".upload"))
            .or_else(|| name.strip_suffix(".uploaded"))
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    fn match_coredump(name: &str) -> bool {
        let Some(rest) = name.strip_prefix("core.") else {
            return false;
        };
        rest.strip_suffix(".zst")
            .or_else(|| rest.strip_suffix(".lz4"))
            .or_else(|| rest.strip_suffix(".xz"))
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    const ALLOW_RULES: &[AllowRule] = &[
        AllowRule {
            category: CleanupCategory::PackageCache,
            rel_dir: "var/cache/apt/archives",
            default_days: 1,
            max_depth: 0,
            matcher: match_deb,
        },
        AllowRule {
            category: CleanupCategory::PackageCache,
            rel_dir: "var/cache/apk",
            default_days: 1,
            max_depth: 0,
            matcher: match_apk,
        },
        AllowRule {
            category: CleanupCategory::PackageCache,
            rel_dir: "var/cache/pacman/pkg",
            default_days: 1,
            max_depth: 0,
            matcher: match_pacman,
        },
        AllowRule {
            category: CleanupCategory::PackageCache,
            rel_dir: "var/cache/dnf",
            default_days: 1,
            max_depth: 3,
            matcher: match_rpm,
        },
        AllowRule {
            category: CleanupCategory::PackageCache,
            rel_dir: "var/cache/yum",
            default_days: 1,
            max_depth: 3,
            matcher: match_rpm,
        },
        AllowRule {
            category: CleanupCategory::ArchivedLogs,
            rel_dir: "var/log",
            default_days: 14,
            max_depth: 0,
            matcher: match_archive_log,
        },
        AllowRule {
            category: CleanupCategory::ArchivedLogs,
            rel_dir: "var/log/nginx",
            default_days: 14,
            max_depth: 0,
            matcher: match_archive_log,
        },
        AllowRule {
            category: CleanupCategory::ArchivedLogs,
            rel_dir: "var/log/apache2",
            default_days: 14,
            max_depth: 0,
            matcher: match_archive_log,
        },
        AllowRule {
            category: CleanupCategory::ArchivedLogs,
            rel_dir: "var/log/caddy",
            default_days: 14,
            max_depth: 0,
            matcher: match_caddy_log,
        },
        AllowRule {
            category: CleanupCategory::ArchivedLogs,
            rel_dir: "var/log/journal",
            default_days: 14,
            max_depth: 1,
            matcher: match_journal_archive,
        },
        AllowRule {
            category: CleanupCategory::CrashFiles,
            rel_dir: "var/crash",
            default_days: 14,
            max_depth: 0,
            matcher: match_crash,
        },
        AllowRule {
            category: CleanupCategory::CrashFiles,
            rel_dir: "var/lib/systemd/coredump",
            default_days: 14,
            max_depth: 0,
            matcher: match_coredump,
        },
    ];

    /// Check whether a relative path under a root is matched by the static allowlist rules.
    pub fn is_allowlisted_cleanup_file(rel_path: &str) -> Option<(CleanupCategory, u16)> {
        let normalized = rel_path.trim_start_matches('/').replace('\\', "/");
        if normalized.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
            return None;
        }
        let (dir_part, filename) = normalized.rsplit_once('/')?;
        for rule in ALLOW_RULES {
            if dir_part == rule.rel_dir && rule.max_depth == 0 && (rule.matcher)(filename) {
                return Some((rule.category, rule.default_days));
            }
            if rule.max_depth > 0 {
                if let Some(sub) = dir_part.strip_prefix(&format!("{}/", rule.rel_dir)) {
                    let sub_segs: Vec<&str> = sub.split('/').collect();
                    if sub_segs.len() <= rule.max_depth {
                        if rule.category == CleanupCategory::ArchivedLogs
                            && !(sub_segs.len() == 1
                                && sub_segs[0].len() == 32
                                && sub_segs[0]
                                    .bytes()
                                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                        {
                            continue;
                        }
                        if (rule.matcher)(filename) {
                            return Some((rule.category, rule.default_days));
                        }
                    }
                }
            }
        }
        None
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct CleanupSweepResult {
        pub candidate_files: usize,
        pub candidate_bytes: u64,
        pub deleted_files: usize,
        pub unlinked_bytes: u64,
        pub skipped: usize,
        pub errors: usize,
        pub bounded: bool,
        pub status: String,
    }

    fn meta_latest_epoch(meta: &fs::Metadata) -> Option<i64> {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)?;
        #[cfg(unix)]
        let ctime = {
            use std::os::unix::fs::MetadataExt;
            meta.ctime()
        };
        #[cfg(not(unix))]
        let ctime = mtime;
        let atime = meta
            .accessed()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(mtime);
        Some(mtime.max(ctime).max(atime))
    }

    fn meta_allocated_bytes(meta: &fs::Metadata) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.blocks().saturating_mul(512)
        }
        #[cfg(not(unix))]
        {
            meta.len()
        }
    }

    fn meta_nlink(meta: &fs::Metadata) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.nlink()
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            1
        }
    }

    fn open_nofollow_dir_chain(root: &Path, rel_dir: &str) -> Option<PathBuf> {
        let mut current = root.to_path_buf();
        let root_meta = fs::symlink_metadata(&current).ok()?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return None;
        }
        for comp in rel_dir.split('/') {
            if comp.is_empty() || comp == "." || comp == ".." {
                return None;
            }
            current.push(comp);
            let meta = fs::symlink_metadata(&current).ok()?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return None;
            }
        }
        Some(current)
    }

    fn walk_allowlist_dir(
        dir: &Path,
        rule: &AllowRule,
        depth: usize,
        cutoff: i64,
        execute: bool,
        byte_budget: u64,
        file_budget: usize,
        busy_inodes: &BTreeSet<(u64, u64)>,
        visited: &mut usize,
        out: &mut CleanupSweepResult,
    ) {
        let Ok(entries) = fs::read_dir(dir) else {
            out.errors += 1;
            return;
        };
        for entry in entries.flatten() {
            *visited += 1;
            if *visited > MAX_VISITED_ENTRIES {
                out.bounded = true;
                return;
            }
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                out.errors += 1;
                continue;
            };
            if meta.file_type().is_symlink() {
                out.skipped += 1;
                continue;
            }
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if depth > 0 && meta.is_dir() {
                if rule.category == CleanupCategory::ArchivedLogs
                    && !(name_str.len() == 32
                        && name_str
                            .bytes()
                            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                {
                    continue;
                }
                walk_allowlist_dir(
                    &path,
                    rule,
                    depth - 1,
                    cutoff,
                    execute,
                    byte_budget,
                    file_budget,
                    busy_inodes,
                    visited,
                    out,
                );
                if out.bounded {
                    return;
                }
                continue;
            }
            if !meta.is_file() || !(rule.matcher)(&name_str) {
                continue;
            }
            if meta_nlink(&meta) != 1 {
                out.skipped += 1;
                continue;
            }
            let Some(latest) = meta_latest_epoch(&meta) else {
                out.skipped += 1;
                continue;
            };
            if latest > cutoff {
                out.skipped += 1;
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if busy_inodes.contains(&(meta.dev(), meta.ino())) {
                    out.skipped += 1;
                    continue;
                }
            }
            #[cfg(not(unix))]
            let _ = busy_inodes;

            let allocated = meta_allocated_bytes(&meta);
            out.candidate_files += 1;
            out.candidate_bytes = out.candidate_bytes.saturating_add(allocated);
            if execute {
                if out.deleted_files >= file_budget
                    || out.unlinked_bytes.saturating_add(allocated) > byte_budget
                {
                    out.bounded = true;
                    continue;
                }
                if fs::remove_file(&path).is_ok() {
                    out.deleted_files += 1;
                    out.unlinked_bytes = out.unlinked_bytes.saturating_add(allocated);
                } else {
                    out.errors += 1;
                }
            }
        }
    }

    /// Bounded allowlist scan/cleanup under a verified root directory (never follows symlinks).
    pub fn sweep_cleanup_root(
        root: &Path,
        execute: bool,
        retention_days: u16,
        byte_budget: u64,
        file_budget: usize,
        now_epoch: i64,
        busy_inodes: &BTreeSet<(u64, u64)>,
    ) -> Result<CleanupSweepResult, String> {
        if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&retention_days) {
            return Err("invalid retention".to_string());
        }
        if byte_budget > MAX_BYTES || file_budget > MAX_FILES {
            return Err("invalid cleanup budget".to_string());
        }
        let mut out = CleanupSweepResult {
            status: if execute { "succeeded" } else { "scanned" }.to_string(),
            ..CleanupSweepResult::default()
        };
        let mut visited = 0usize;
        for rule in ALLOW_RULES {
            let rel_path = Path::new(rule.rel_dir);
            if !root.join(rel_path).exists() {
                continue;
            }
            let Some(dir_path) = open_nofollow_dir_chain(root, rule.rel_dir) else {
                out.skipped += 1;
                continue;
            };
            let days = if rule.default_days == 14 {
                retention_days
            } else {
                rule.default_days
            };
            let cutoff = now_epoch.saturating_sub((days as i64) * DAY_SECONDS);
            walk_allowlist_dir(
                &dir_path,
                rule,
                rule.max_depth,
                cutoff,
                execute,
                byte_budget,
                file_budget,
                busy_inodes,
                &mut visited,
                &mut out,
            );
            if out.bounded {
                break;
            }
        }
        if out.errors > 0 || out.bounded {
            out.status = "partial".to_string();
        }
        Ok(out)
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct DiskUsageStats {
        pub total_bytes: u64,
        pub available_bytes: u64,
        pub used_percent: f64,
    }

    impl DiskUsageStats {
        pub fn to_json(&self) -> String {
            let mut b = JsonObjBuilder::new();
            b.u64("total_bytes", self.total_bytes);
            b.u64("available_bytes", self.available_bytes);
            b.f64("used_percent", (self.used_percent * 100.0).round() / 100.0);
            b.finish()
        }
    }

    /// Best-effort POSIX `df -P -k <path>` disk usage without unsafe FFI.
    pub fn disk_usage_for_path(path: &Path) -> Option<DiskUsageStats> {
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
        #[cfg(unix)]
        {
            let out = std::process::Command::new("df")
                .args(["-P", "-k"])
                .arg(path)
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let data_line = stdout.lines().nth(1)?.trim();
            let cols: Vec<&str> = data_line.split_whitespace().collect();
            if cols.len() < 4 {
                return None;
            }
            let blocks_1k: u64 = cols[1].parse().ok()?;
            let used_1k: u64 = cols[2].parse().ok()?;
            let avail_1k: u64 = cols[3].parse().ok()?;
            let total_bytes = blocks_1k.saturating_mul(1024);
            let used_bytes = used_1k.saturating_mul(1024);
            let available_bytes = avail_1k.saturating_mul(1024);
            let denom = used_bytes.saturating_add(available_bytes);
            let used_percent = if denom > 0 {
                (100.0 * (used_bytes as f64) / (denom as f64) * 100.0).round() / 100.0
            } else {
                0.0
            };
            Some(DiskUsageStats {
                total_bytes,
                available_bytes,
                used_percent,
            })
        }
    }

    pub fn host_disk_usage_json(path: &Path) -> String {
        disk_usage_for_path(path)
            .map(|d| d.to_json())
            .unwrap_or_else(|| "{}".to_string())
    }

    /// Fail-closed enumeration of open regular file `(dev, ino)` across `/proc/*/fd`.
    pub fn collect_busy_inodes(max_fds: usize) -> Result<BTreeSet<(u64, u64)>, String> {
        #[cfg(not(unix))]
        {
            let _ = max_fds;
            Ok(BTreeSet::new())
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(proc_entries) = fs::read_dir("/proc") else {
                return Err("open-file check unavailable".to_string());
            };
            let mut busy = BTreeSet::new();
            let mut seen = 0usize;
            for entry in proc_entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.bytes().all(|b| b.is_ascii_digit()) {
                    continue;
                }
                let fd_dir = entry.path().join("fd");
                let fds = match fs::read_dir(&fd_dir) {
                    Ok(rd) => rd,
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        return Err("open-file permissions unavailable".to_string());
                    }
                    Err(_) => continue,
                };
                for fd_entry in fds.flatten() {
                    seen += 1;
                    if seen > max_fds {
                        return Err("open-file check budget exhausted".to_string());
                    }
                    if let Ok(meta) = fs::metadata(fd_entry.path()) {
                        if meta.is_file() {
                            busy.insert((meta.dev(), meta.ino()));
                        }
                    }
                }
            }
            Ok(busy)
        }
    }

    fn verify_target_root_for_cleanup(
        target: &CleanupTarget,
        host_root_override: Option<&Path>,
    ) -> Result<(PathBuf, String), String> {
        if target.runtime == "host" {
            let root = host_root_override
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/"));
            let meta = fs::symlink_metadata(&root)
                .map_err(|_| "host root unavailable".to_string())?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err("invalid host filesystem root".to_string());
            }
            return Ok((root, "host".to_string()));
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err("identity, mount, evidence or filesystem safety check unavailable".to_string())
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let pid: u32 = target
                .pid
                .trim()
                .parse()
                .ok()
                .filter(|&p| p > 1)
                .ok_or_else(|| "container is not running".to_string())?;
            let pid1_ns = fs::metadata("/proc/1/ns/pid")
                .map_err(|_| "host PID namespace unavailable".to_string())?;
            let c_ns = fs::metadata(format!("/proc/{pid}/ns/pid"))
                .map_err(|_| "container PID namespace unavailable".to_string())?;
            if (c_ns.dev(), c_ns.ino()) == (pid1_ns.dev(), pid1_ns.ino()) {
                return Err("shared host PID namespace".to_string());
            }
            if !target.pid_start_ticks.is_empty() {
                let raw_stat = fs::read_to_string(format!("/proc/{pid}/stat"))
                    .map_err(|_| "container process unavailable".to_string())?;
                let ticks = raw_stat
                    .rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().nth(19))
                    .unwrap_or("");
                if ticks != target.pid_start_ticks {
                    return Err("container restarted".to_string());
                }
            }
            let host_root_meta = fs::metadata("/")
                .map_err(|_| "host filesystem root unavailable".to_string())?;
            let guest_root = PathBuf::from(format!("/proc/{pid}/root"));
            let guest_meta = fs::metadata(&guest_root)
                .map_err(|_| "container root unavailable".to_string())?;
            if !guest_meta.is_dir()
                || (guest_meta.dev(), guest_meta.ino())
                    == (host_root_meta.dev(), host_root_meta.ino())
            {
                return Err("host filesystem root refused".to_string());
            }
            let identity = if target.runtime == "runman" {
                target.instance_id.clone()
            } else if !target.stable_id.is_empty() {
                target.stable_id.clone()
            } else {
                target.id.clone()
            };
            if identity.is_empty() {
                return Err("container identity unavailable".to_string());
            }
            Ok((guest_root, identity))
        }
    }

    /// Execute bounded scan/clean across staged targets of `run_id` and persist terminal status to `journal_path`.
    pub fn execute_and_finalize_cleanup_run(
        journal_path: &Path,
        run_id: &str,
        policy: &CleanupPolicy,
        host_root_override: Option<&Path>,
        now_epoch: i64,
    ) -> Result<CleanupRunRecord, String> {
        let state = read_cleanup_journal_readonly(journal_path)?;
        let Some(initial_run) = state.runs.iter().find(|r| r.run_id == run_id).cloned() else {
            return Err("cleanup run record not found".to_string());
        };
        if initial_run.status != "running" {
            return Ok(initial_run);
        }

        let execute = initial_run.mode == "clean";
        let busy_inodes = if host_root_override.is_some() {
            BTreeSet::new()
        } else {
            match collect_busy_inodes(50_000) {
                Ok(set) => set,
                Err(_) => {
                    let mut st = read_cleanup_journal_readonly(journal_path)?;
                    if let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) {
                        rec.status = "failed".to_string();
                        rec.finished_at = Some(now_epoch);
                        rec.error = "cleanup worker could not verify open files".to_string();
                        let snapshot = rec.clone();
                        let _ = save_cleanup_journal(journal_path, &mut st);
                        return Ok(snapshot);
                    }
                    return Err("cleanup run missing during failure update".to_string());
                }
            }
        };

        let mut remaining_bytes = MAX_BYTES;
        let mut remaining_files = MAX_FILES;
        let mut items = Vec::with_capacity(initial_run.targets.len());

        for target in &initial_run.targets {
            let mut item = CleanupRunItem {
                runtime: target.runtime.clone(),
                name: target.name.clone(),
                project: target.project.clone(),
                status: "skipped".to_string(),
                reason: String::new(),
                instance_id: String::new(),
                candidate_files: 0,
                candidate_bytes: 0,
                deleted_files: 0,
                unlinked_bytes: 0,
                freed_bytes: 0,
                skipped: 0,
                errors: 0,
                bounded: false,
                extra_fields: BTreeMap::new(),
            };
            match verify_target_root_for_cleanup(target, host_root_override) {
                Ok((root, identity)) => {
                    let before_avail = disk_usage_for_path(&root);
                    match sweep_cleanup_root(
                        &root,
                        execute,
                        policy.retention_days,
                        remaining_bytes,
                        remaining_files,
                        now_epoch,
                        &busy_inodes,
                    ) {
                        Ok(sweep) => {
                            let after_avail = if execute {
                                disk_usage_for_path(&root)
                            } else {
                                before_avail
                            };
                            let freed = match (before_avail, after_avail) {
                                (Some(b), Some(a)) if execute => {
                                    a.available_bytes.saturating_sub(b.available_bytes)
                                }
                                _ => 0,
                            };
                            item.status = sweep.status;
                            item.instance_id = identity;
                            item.candidate_files = sweep.candidate_files;
                            item.candidate_bytes = sweep.candidate_bytes;
                            item.deleted_files = sweep.deleted_files;
                            item.unlinked_bytes = sweep.unlinked_bytes;
                            item.freed_bytes = freed;
                            item.skipped = sweep.skipped;
                            item.errors = sweep.errors;
                            item.bounded = sweep.bounded;
                            remaining_bytes = remaining_bytes.saturating_sub(sweep.unlinked_bytes);
                            remaining_files = remaining_files.saturating_sub(sweep.deleted_files);
                        }
                        Err(_) => {
                            item.reason = "identity, mount, evidence or filesystem safety check unavailable"
                                .to_string();
                        }
                    }
                }
                Err(_) => {
                    item.reason =
                        "identity, mount, evidence or filesystem safety check unavailable"
                            .to_string();
                }
            }
            items.push(item);
        }

        let has_partial = items
            .iter()
            .any(|i| matches!(i.status.as_str(), "skipped" | "partial"));
        let final_status = if has_partial {
            "partial"
        } else if execute {
            "succeeded"
        } else {
            "scanned"
        };

        let mut st = read_cleanup_journal_readonly(journal_path)?;
        let fin_epoch = now_unix_secs().max(now_epoch);
        let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) else {
            return Err("cleanup run record missing during finalization".to_string());
        };
        rec.items = items;
        rec.status = final_status.to_string();
        rec.finished_at = Some(fin_epoch);
        let finalized = rec.clone();
        save_cleanup_journal(journal_path, &mut st)?;
        Ok(finalized)
    }

    pub fn mark_cleanup_run_delivered(journal_path: &Path, run_id: &str) -> Result<(), String> {
        let mut st = read_cleanup_journal_readonly(journal_path)?;
        if let Some(rec) = st.runs.iter_mut().find(|r| r.run_id == run_id) {
            rec.delivered = true;
            save_cleanup_journal(journal_path, &mut st)?;
        }
        Ok(())
    }

    /// Stage an automatic scheduled cleanup run for due targets (`now - last_attempt >= interval_hours * 3600`).
    /// Returns `Ok(Some(run_id))` when a new automatic run was staged, or `Ok(None)` when none are due.
    pub fn stage_automatic_cleanup(
        journal_path: &Path,
        policy: &CleanupPolicy,
        node_id: &str,
        containers: &[CleanupContainerCandidate],
        quarantined_identities: &BTreeSet<String>,
        now_epoch: i64,
    ) -> Result<Option<String>, String> {
        if !policy.enabled || node_id.is_empty() {
            return Ok(None);
        }
        let mut st = read_cleanup_journal_readonly(journal_path)?;
        if st.runs.iter().any(|r| r.status == "running") {
            return Ok(None);
        }
        let interval_secs = (policy.interval_hours as f64) * 3600.0;
        let now_f = now_epoch as f64;
        let due: Vec<CleanupTarget> = select_cleanup_targets(policy, containers)
            .into_iter()
            .filter(|t| !target_quarantined(t, quarantined_identities))
            .filter(|t| {
                let last = st.attempts.get(&cleanup_cooldown_key(t)).copied().unwrap_or(0.0);
                now_f - last >= interval_secs
            })
            .take(MAX_TARGETS_PER_RUN)
            .collect();
        if due.is_empty() {
            return Ok(None);
        }
        let run_id = format!("{:032x}", (now_epoch as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let rec = CleanupRunRecord {
            run_id: run_id.clone(),
            action_id: 0,
            node_id: node_id.to_string(),
            mode: "clean".to_string(),
            automatic: true,
            started_at: now_epoch,
            finished_at: None,
            status: "running".to_string(),
            targets: due.clone(),
            items: Vec::new(),
            plan_id: String::new(),
            delivered: false,
            error: String::new(),
        };
        for t in &due {
            st.attempts.insert(cleanup_cooldown_key(t), now_f);
        }
        st.runs.push(rec);
        save_cleanup_journal(journal_path, &mut st)?;
        Ok(Some(run_id))
    }
}

// ===========================================================================
// 4. Security Banner & MOTD Card (`client/security_banner.py`)
// ===========================================================================

pub mod security_banner {
    use super::util::{format_utc8_datetime, now_unix_secs, parse_utc_legacy_epoch};
    use super::*;

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
}

// ===========================================================================
// Crate-root re-exports
// ===========================================================================

pub use disk_cleanup::{
    cleanup_cooldown_key, execute_disk_cleanup_action, execute_disk_cleanup_action_json,
    is_allowlisted_cleanup_file, live_disk_cleanup_available, load_cleanup_journal,
    save_cleanup_journal, select_cleanup_targets, sweep_cleanup_root, validate_cleanup_policy,
    validate_cleanup_policy_json, CleanupActionContext, CleanupActionOutcome, CleanupCategory,
    CleanupContainerCandidate, CleanupJournalState, CleanupPolicy, CleanupRunItem,
    CleanupRunRecord, CleanupSweepResult, CleanupTarget,
};
pub use incus_health::{
    build_incus_health_and_alerts_json, build_incus_operations_health_json, build_incus_snapshot,
    build_incus_snapshot_json, evaluate_incus_stop_preflight, incus_lifecycle_action,
    parse_incus_created_epoch, IncusHealthConfig, IncusScan, IncusSnapshotReport,
    INCUS_ALERT_TYPES,
};
pub use security_banner::{
    beijing_time, cell_width, historical_detail, merge_motd_banner, merge_shell_hook,
    observed_epoch, relative_age, render_motd_banner, render_motd_banner_entries,
    safe_banner_text, safe_banner_text_default, select_motd_entries, shell_hook, wrap_cells,
    MotdCustomerDetails, MotdEntry, MotdRenderOptions,
};
pub use socks_detector::{
    gost_cli_json, gost_url, gost_url_json, is_listener_exposed, is_loopback_host,
    legacy_profiles_json, manage_panel_domains, manage_panel_domains_json, panel_domain_allowed,
    parse_endpoint, parse_inbound_protocols_json, parse_process_configs_json,
    parse_socks_config_json, password_profile, password_profile_json, socks_greeting_mode,
    standalone_panels, standalone_panels_json, strip_jsonc_comments, valid_panel_domain,
    GostEndpoint, PanelDomainAction, PanelDomainOutcome, PanelDomainStore, PasswordProfile,
    StandalonePanel,
};

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("narwhal-app-guard-{label}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    // -----------------------------------------------------------------------
    // 1. incus_health tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_incus_healthy_complete_snapshot_and_operations_health() {
        let inst_scan = r#"{
            "ok": true,
            "latency_ms": 42.5,
            "error": "",
            "items": [
                {"name": "c1", "project": "default", "status": "Running", "type": "container", "config": {"volatile.uuid": "uuid-1"}, "state": {"pid": 1001}}
            ]
        }"#;
        let ops_scan = r#"{
            "ok": true,
            "latency_ms": 18.0,
            "error": "",
            "items": [
                {"id": "op-fast", "status": "Running", "status_code": 103, "description": "Restarting instance", "created_at": "2026-11-16T00:00:00Z", "may_cancel": true, "resources": {"instances": ["/1.0/instances/c1?project=default"]}}
            ]
        }"#;
        // 120 seconds elapsed (< 300s stuck threshold)
        let now = parse_incus_created_epoch("2026-11-16T00:02:00Z").unwrap();
        let snap_json = build_incus_snapshot_json(inst_scan, ops_scan, "all", now);
        let snap = JsonVal::parse(&snap_json).expect("valid snapshot JSON");

        assert_eq!(snap.get_str("status"), Some("healthy"));
        assert_eq!(snap.get_str("scan_status"), Some("complete"));
        assert_eq!(snap.get_i64("instance_count"), Some(1));
        assert_eq!(snap.get_i64("error_instance_count"), Some(0));
        assert_eq!(snap.get_i64("active_lifecycle_operation_count"), Some(1));
        assert_eq!(snap.get_i64("stuck_lifecycle_operation_count"), Some(0));
        assert_eq!(snap.get("alerts").and_then(JsonVal::as_arr).map(|a| a.len()), Some(0));

        let ops_health_json = build_incus_operations_health_json(&snap_json);
        let ops_health = JsonVal::parse(&ops_health_json).expect("valid operations health JSON");
        assert_eq!(ops_health.get_str("source"), Some("incus_runtime"));
        assert_eq!(ops_health.get_str("status"), Some("healthy"));
        assert_eq!(
            ops_health.get("details").and_then(|d| d.get_i64("active_lifecycle_operations")),
            Some(1)
        );
    }

    #[test]
    fn test_incus_detects_error_stuck_op_and_slow_api() {
        let inst_scan = r#"{
            "ok": true,
            "latency_ms": 3100.0,
            "error": "",
            "items": [
                {"name": "err-box", "project": "buyers", "status": "Error", "config": {"volatile.uuid": "uuid-err"}, "state": {"pid": 555}},
                {"name": "hang-box", "project": "default", "status": "Running", "config": {"volatile.uuid": "uuid-hang"}, "state": {"pid": 777}}
            ]
        }"#;
        let ops_scan = r#"{
            "ok": true,
            "latency_ms": 200.0,
            "error": "",
            "items": [
                {"id": "op-stuck", "status": "Running", "description": "Stopping instance", "created_at": "2026-11-16T00:00:00Z", "may_cancel": false, "resources": {"instances": ["/1.0/instances/hang-box"]}},
                {"id": "op-bad-time", "status_code": 103, "metadata": {"action": "delete"}, "created_at": "", "resources": {"containers": ["/1.0/containers/hang-box?project=default"]}}
            ]
        }"#;
        let now = parse_incus_created_epoch("2026-11-16T00:05:00Z").unwrap(); // exact 300s
        let (ops_health_json, alerts_json) =
            build_incus_health_and_alerts_json(inst_scan, ops_scan, "all", now);

        let oh = JsonVal::parse(&ops_health_json).unwrap();
        assert_eq!(oh.get_str("status"), Some("warning"));
        let details = oh.get("details").unwrap();
        assert_eq!(details.get_i64("error_instances"), Some(1));
        assert_eq!(details.get_i64("stuck_lifecycle_operations"), Some(1));
        assert_eq!(details.get_i64("active_lifecycle_operations"), Some(2));

        let alerts = JsonVal::parse(&alerts_json).unwrap();
        let arr = alerts.as_arr().unwrap();
        let types: BTreeSet<&str> = arr.iter().filter_map(|a| a.get_str("type")).collect();
        assert!(types.contains("incus_instance_error"));
        assert!(types.contains("incus_lifecycle_operation_stuck"));
        assert!(types.contains("incus_lifecycle_operation_unverified"));
        assert!(types.contains("incus_api_slow"));

        let err_alert = arr.iter().find(|a| a.get_str("type") == Some("incus_instance_error")).unwrap();
        assert_eq!(err_alert.get_str("severity"), Some("critical"));
        assert_eq!(err_alert.get_str("instance_id"), Some("uuid-err"));
        assert!(err_alert.get_str("message").unwrap().contains("/var/log/incus/uuid-err/lxc.log"));

        let stuck_alert = arr
            .iter()
            .find(|a| a.get_str("type") == Some("incus_lifecycle_operation_stuck"))
            .unwrap();
        assert_eq!(stuck_alert.get_str("severity"), Some("critical"));
        assert_eq!(stuck_alert.get_f64("threshold"), Some(300.0));
        assert!(stuck_alert.get_str("message").unwrap().contains("不可取消"));
    }

    #[test]
    fn test_incus_unavailable_and_stop_preflight() {
        let bad_scan = r#"{"ok":false,"items":[],"latency_ms":8001.0,"error":"timeout"}"#;
        let snap_json = build_incus_snapshot_json(bad_scan, "", "default", 1_700_000_000.0);
        let snap = JsonVal::parse(&snap_json).unwrap();
        assert_eq!(snap.get_str("status"), Some("unavailable"));
        assert_eq!(snap.get_str("scan_status"), Some("unavailable"));
        let types: BTreeSet<&str> = snap
            .get("alerts")
            .unwrap()
            .as_arr()
            .unwrap()
            .iter()
            .filter_map(|a| a.get_str("type"))
            .collect();
        assert!(types.contains("incus_api_unavailable"));
        assert!(types.contains("incus_operation_inventory_unavailable"));

        let ok_inst = IncusScan::from_cli_output(
            true,
            r#"[{"name":"c1","project":"default","status":"Running","type":"container"}]"#,
            50.0,
            "",
        );
        let ok_ops = IncusScan::from_cli_output(true, "[]", 50.0, "");
        let cfg = IncusHealthConfig::default();
        assert!(evaluate_incus_stop_preflight(&ok_inst, &ok_ops, "default", "c1", &cfg).is_ok());
        assert!(evaluate_incus_stop_preflight(&ok_inst, &ok_ops, "all", "c1", &cfg).is_err());

        let busy_ops = IncusScan::from_cli_output(
            true,
            r#"[{"id":"op1","status":"Running","description":"Stopping","resources":{"instances":["/1.0/instances/c1"]}}]"#,
            50.0,
            "",
        );
        assert!(evaluate_incus_stop_preflight(&ok_inst, &busy_ops, "default", "c1", &cfg).is_err());
    }

    // -----------------------------------------------------------------------
    // 2. socks_detector & panel pairing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_password_profile_and_gost_url_and_no_secret_leak() {
        let prof_json = password_profile_json(Some("Ab112!中文"));
        let prof = JsonVal::parse(&prof_json).unwrap();
        assert_eq!(prof.get_bool("available"), Some(true));
        assert_eq!(prof.get_i64("length"), Some(8));
        assert_eq!(prof.get_i64("lowercase"), Some(1));
        assert_eq!(prof.get_i64("uppercase"), Some(1));
        assert_eq!(prof.get_i64("digits"), Some(3));
        assert_eq!(prof.get_i64("symbols"), Some(1));
        assert_eq!(prof.get_i64("other"), Some(2));
        assert_eq!(prof.get_i64("repeated_digits"), Some(1));
        assert_eq!(prof.get_i64("max_digit_frequency"), Some(2));
        assert_eq!(prof.get_i64("longest_identical_run"), Some(2));
        assert!(!prof_json.contains("Ab112!"));

        let ref_prof = JsonVal::parse(&password_profile_json(Some("${ENV_PASS}"))).unwrap();
        assert_eq!(ref_prof.get_bool("available"), Some(false));

        let g1 = JsonVal::parse(&gost_url_json("socks5://alice:super-secret-pw@0.0.0.0:1080")).unwrap();
        assert_eq!(g1.get_i64("port"), Some(1080));
        assert_eq!(g1.get_str("listen"), Some("0.0.0.0"));
        assert_eq!(g1.get_str("auth_state"), Some("unknown"));
        assert!(!gost_url_json("socks5://alice:super-secret-pw@0.0.0.0:1080").contains("super-secret-pw"));

        let g2 = JsonVal::parse(&gost_url_json("socks+tls://:1080")).unwrap();
        assert_eq!(g2.get_str("listen"), Some("*"));
        assert_eq!(g2.get_i64("port"), Some(1080));
        assert_eq!(gost_url_json("http://127.0.0.1:8080"), "null");
    }

    #[test]
    fn test_standalone_panels_and_socks_config_and_exposure() {
        let ps = "210 S sui /usr/local/s-ui/sui\n211 S x-ui /usr/local/x-ui/x-ui\n212 S sh sh -c /usr/local/s-ui/sui\n213 S vim vim /etc/x-ui/config\n214 Z sui /usr/local/s-ui/sui\n215 S sui /usr/bin/x-ui\n";
        let panels_json = standalone_panels_json(ps);
        let panels = JsonVal::parse(&panels_json).unwrap();
        let arr = panels.as_arr().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].get_i64("pid"), Some(210));
        assert_eq!(arr[0].get_str("panel"), Some("S-ui"));
        assert_eq!(arr[0].get_bool("auto_stop_eligible"), Some(false));
        assert_eq!(arr[1].get_i64("pid"), Some(211));
        assert_eq!(arr[1].get_str("panel"), Some("X-ui"));
        assert!(!panels_json.contains("/usr/local"));

        let xray_cfg = r#"{/* comment */ "inbounds": [{"protocol": "vless", "port": 443}, {"protocol": "socks", "port": 1080, "settings": {"auth": "password", "users": [{"user": "u", "pass": "password"}]}}], "outbounds": [{"protocol": "socks", "tag": "https://example.test"}]}"#;
        let parsed = JsonVal::parse(&parse_socks_config_json(xray_cfg, "xray")).unwrap();
        assert_eq!(parsed.get_bool("parsed"), Some(true));
        assert_eq!(parsed.get_bool("single_purpose"), Some(false));
        let ep = &parsed.get("endpoints").unwrap().as_arr().unwrap()[0];
        assert_eq!(ep.get_i64("port"), Some(1080));
        assert_eq!(ep.get_str("auth_state"), Some("weak_password"));

        assert_eq!(is_listener_exposed("[::1]:1080", &[]), Some(false));
        assert_eq!(is_listener_exposed("[::ffff:127.0.0.1]:1080", &[]), Some(false));
        assert_eq!(is_listener_exposed("0.0.0.0:1080", &[]), Some(true));
        assert_eq!(
            is_listener_exposed(
                "127.0.0.1:1080",
                &[("tcp:127.0.0.1:1080".to_string(), "tcp:0.0.0.0:8080".to_string())]
            ),
            Some(true)
        );
    }

    #[test]
    fn test_manage_panel_domains_updates_state_and_env_without_leaking_secrets() {
        let dir = temp_dir("panel-domains");
        let allow_file = dir.join("panel-allowlist.json");
        let auto_file = dir.join("panel-auto-remediate.json");
        let env_file = dir.join("client.env");
        fs::write(
            &auto_file,
            r#"{"domains":["panel.example.net","bad.example.net"],"updated_at":100}"#,
        )
        .unwrap();
        fs::write(
            &env_file,
            "SERVER_URL=https://watcher.local\nSHARED_SECRET=top-secret-hmac-key-never-leak\nSECURITY_ALLOWED_PANEL_DOMAINS=trusted.example.com\n",
        )
        .unwrap();

        let store = PanelDomainStore {
            allowlist_path: allow_file.clone(),
            auto_remediate_path: Some(auto_file.clone()),
            env_file_path: Some(env_file.clone()),
            env_allowed_domains: Vec::new(),
        };

        let allow_res = manage_panel_domains(
            &store,
            PanelDomainAction::Allow,
            &["Panel.Example.NET.".to_string()],
            1_700_000_000,
        )
        .expect("allow panel domains");
        assert!(allow_res.ok);
        assert_eq!(
            allow_res.allowlist,
            vec!["panel.example.net".to_string(), "trusted.example.com".to_string()]
        );
        assert_eq!(allow_res.auto_remediate, vec!["bad.example.net".to_string()]);
        assert!(!allow_res.to_json().contains("top-secret-hmac-key-never-leak"));

        let env_after_allow = fs::read_to_string(&env_file).unwrap();
        assert!(env_after_allow.contains("SHARED_SECRET=top-secret-hmac-key-never-leak"));
        assert!(env_after_allow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=panel.example.net,trusted.example.com"));

        let disallow_res = manage_panel_domains(
            &store,
            PanelDomainAction::Disallow,
            &["panel.example.net".to_string()],
            1_700_000_010,
        )
        .expect("disallow panel domains");
        assert_eq!(disallow_res.allowlist, vec!["trusted.example.com".to_string()]);
        let env_after_disallow = fs::read_to_string(&env_file).unwrap();
        assert!(env_after_disallow.contains("SHARED_SECRET=top-secret-hmac-key-never-leak"));
        assert!(env_after_disallow.contains("SECURITY_ALLOWED_PANEL_DOMAINS=trusted.example.com"));

        // Invalid domain supply on allow fails closed
        let bad = manage_panel_domains(
            &store,
            PanelDomainAction::Allow,
            &["not a domain!".to_string()],
            1_700_000_020,
        );
        assert!(bad.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // 3. disk_cleanup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_cleanup_policy_and_node_binding() {
        let ok = validate_cleanup_policy(
            r#"{"enabled":true,"include_containers":false,"retention_days":30,"interval_hours":12,"node_id":"node-1"}"#,
            Some("node-1"),
        )
        .expect("valid policy");
        assert!(ok.enabled);
        assert!(!ok.include_containers);
        assert_eq!(ok.retention_days, 30);
        assert_eq!(ok.interval_hours, 12);

        // Node mismatch must fail closed to default (enabled=false)
        let foreign = validate_cleanup_policy(
            r#"{"enabled":true,"node_id":"old-node"}"#,
            Some("new-node"),
        )
        .expect("mismatch resets to default");
        assert!(!foreign.enabled);

        // Invalid types, bounds, and arbitrary keys rejected
        for bad in [
            r#"{"enabled":"true"}"#,
            r#"{"retention_days":true}"#,
            r#"{"retention_days":13}"#,
            r#"{"retention_days":91}"#,
            r#"{"interval_hours":5}"#,
            r#"{"interval_hours":169}"#,
            r#"{"paths":["/root"],"command":"rm"}"#,
        ] {
            assert!(validate_cleanup_policy(bad, None).is_err(), "expected err for {bad}");
        }
    }

    #[test]
    fn test_cleanup_journal_load_recovery_and_action_safety_checks() {
        let dir = temp_dir("disk-cleanup");
        let journal = dir.join("disk-cleanup.json");

        // Pre-seed an interrupted 'running' run and confirm recovery marks it interrupted
        let mut initial = CleanupJournalState {
            runs: vec![CleanupRunRecord {
                run_id: "action-1".to_string(),
                action_id: 1,
                node_id: "node-a".to_string(),
                mode: "scan".to_string(),
                automatic: false,
                started_at: 1_700_000_000,
                finished_at: None,
                status: "running".to_string(),
                targets: vec![CleanupTarget::host()],
                items: vec![],
                plan_id: String::new(),
                delivered: false,
                error: String::new(),
            }],
            attempts: BTreeMap::new(),
        };
        save_cleanup_journal(&journal, &mut initial).unwrap();
        let recovered = load_cleanup_journal(&journal, 1_700_000_050).unwrap();
        assert_eq!(recovered.runs[0].status, "interrupted");
        assert_eq!(recovered.runs[0].finished_at, Some(1_700_000_050));

        // Corrupt journal fails closed
        let bad_journal = dir.join("bad-cleanup.json");
        fs::write(&bad_journal, r#"{"runs":"not-a-list","attempts":{}}"#).unwrap();
        assert!(load_cleanup_journal(&bad_journal, 1_700_000_050).is_err());

        // Action safety checks
        let ctx = CleanupActionContext {
            host_available: true,
            node_id: "node-a".to_string(),
            now_epoch: 1_700_000_100,
            journal_path: dir.join("actions.json"),
            policy: CleanupPolicy::default(),
            containers: vec![
                CleanupContainerCandidate {
                    runtime: "docker".to_string(),
                    runtime_bin: "docker".to_string(),
                    project: "".to_string(),
                    name: "docker-biz".to_string(),
                    id: "d1".to_string(),
                    stable_id: "d1".to_string(),
                    instance_id: "".to_string(),
                    pid: "100".to_string(),
                    pid_start_ticks: "1".to_string(),
                },
                CleanupContainerCandidate {
                    runtime: "podman".to_string(),
                    runtime_bin: "podman".to_string(),
                    project: "".to_string(),
                    name: "narwhal-monitor-client".to_string(),
                    id: "p0".to_string(),
                    stable_id: "p0".to_string(),
                    instance_id: "".to_string(),
                    pid: "101".to_string(),
                    pid_start_ticks: "1".to_string(),
                },
                CleanupContainerCandidate {
                    runtime: "podman".to_string(),
                    runtime_bin: "podman".to_string(),
                    project: "".to_string(),
                    name: "app1".to_string(),
                    id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    stable_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                    instance_id: "".to_string(),
                    pid: "102".to_string(),
                    pid_start_ticks: "2".to_string(),
                },
            ],
            quarantined_identities: BTreeSet::new(),
            active_run_in_progress: false,
        };

        // Node mismatch rejected
        let wrong_node = execute_disk_cleanup_action(
            r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"other"}}"#,
            &ctx,
        );
        assert!(!wrong_node.ok);

        // Scan succeeds and excludes docker & protected containers
        let scan_res = execute_disk_cleanup_action(
            r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-a"}}"#,
            &ctx,
        );
        assert!(scan_res.ok);
        assert_eq!(scan_res.targets.len(), 2);
        assert_eq!(scan_res.targets[0].name, "__host__");
        assert_eq!(scan_res.targets[1].name, "app1");

        // Duplicate action_id is idempotent
        let dup_res = execute_disk_cleanup_action(
            r#"{"id":10,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-a"}}"#,
            &ctx,
        );
        assert!(dup_res.ok);
        assert_eq!(dup_res.status, "accepted");

        // Prepare completed scan plan for execute checks
        let mut plan_state = CleanupJournalState {
            runs: vec![CleanupRunRecord {
                run_id: "action-11".to_string(),
                action_id: 11,
                node_id: "node-a".to_string(),
                mode: "scan".to_string(),
                automatic: false,
                started_at: 1_700_000_000,
                finished_at: Some(1_700_000_010),
                status: "scanned".to_string(),
                targets: vec![CleanupTarget::host()],
                items: vec![CleanupRunItem {
                    runtime: "host".to_string(),
                    name: "__host__".to_string(),
                    project: String::new(),
                    status: "scanned".to_string(),
                    reason: String::new(),
                    instance_id: "host".to_string(),
                    candidate_files: 1,
                    candidate_bytes: 1024,
                    deleted_files: 0,
                    unlinked_bytes: 0,
                    freed_bytes: 0,
                    skipped: 0,
                    errors: 0,
                    bounded: false,
                    extra_fields: BTreeMap::new(),
                }],
                plan_id: String::new(),
                delivered: false,
                error: String::new(),
            }],
            attempts: BTreeMap::new(),
        };
        save_cleanup_journal(&ctx.journal_path, &mut plan_state).unwrap();

        // Missing confirmation rejected
        let unconfirmed = execute_disk_cleanup_action(
            r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":false,"plan_id":"action-11"}}"#,
            &ctx,
        );
        assert!(!unconfirmed.ok);

        // Stale scan (> 900s) rejected
        let mut stale_ctx = ctx.clone();
        stale_ctx.now_epoch = 1_700_000_901;
        let stale_exec = execute_disk_cleanup_action(
            r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":true,"plan_id":"action-11"}}"#,
            &stale_ctx,
        );
        assert!(!stale_exec.ok);

        // Fresh confirmed execute succeeds and records attempt cooldown
        let exec_ok = execute_disk_cleanup_action(
            r#"{"id":12,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-a","confirmed":true,"plan_id":"action-11"}}"#,
            &ctx,
        );
        assert!(exec_ok.ok);
        assert_eq!(exec_ok.status, "running");
        let after_exec = load_cleanup_journal(&ctx.journal_path, ctx.now_epoch + 1).unwrap();
        assert!(after_exec.attempts.contains_key("[\"host\",\"\",\"__host__\",\"host\"]"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_allowlist_rules_and_bounded_sweep() {
        assert_eq!(
            is_allowlisted_cleanup_file("var/log/syslog.1.gz"),
            Some((CleanupCategory::ArchivedLogs, 14))
        );
        assert_eq!(
            is_allowlisted_cleanup_file("var/cache/apt/archives/curl_8.0.deb"),
            Some((CleanupCategory::PackageCache, 1))
        );
        assert_eq!(
            is_allowlisted_cleanup_file(&format!("var/log/journal/{}/system@abc-123.journal", "a".repeat(32))),
            Some((CleanupCategory::ArchivedLogs, 14))
        );
        assert!(is_allowlisted_cleanup_file("var/log/syslog").is_none());
        assert!(is_allowlisted_cleanup_file("var/log/auth.log.1.gz").is_none());
        assert!(is_allowlisted_cleanup_file(&format!("var/log/journal/{}/system.journal", "a".repeat(32))).is_none());

        let dir = temp_dir("sweep");
        let log_dir = dir.join("var/log");
        fs::create_dir_all(&log_dir).unwrap();
        let old_archive = log_dir.join("syslog.1.gz");
        let active_log = log_dir.join("syslog");
        let auth_log = log_dir.join("auth.log.1.gz");
        fs::write(&old_archive, b"archive-bytes").unwrap();
        fs::write(&active_log, b"active-syslog").unwrap();
        fs::write(&auth_log, b"auth-log").unwrap();

        let future = util::now_unix_secs() + 30 * 86_400;
        let scan = sweep_cleanup_root(
            &dir,
            false,
            14,
            disk_cleanup::MAX_BYTES,
            disk_cleanup::MAX_FILES,
            future,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(scan.candidate_files, 1);
        assert_eq!(scan.deleted_files, 0);
        assert!(old_archive.exists());

        let clean = sweep_cleanup_root(
            &dir,
            true,
            14,
            disk_cleanup::MAX_BYTES,
            disk_cleanup::MAX_FILES,
            future,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(clean.deleted_files, 1);
        assert!(!old_archive.exists());
        assert!(active_log.exists());
        assert!(auth_log.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // 4. security_banner tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_safe_banner_text_strips_ansi_control_and_redacts_secrets() {
        let raw = "\x1b]0;EvilTitle\x07\x1b[31mAlert\x1b[0m\u{200B}\n password=hunter2 Token: abc123 api-key = k999 secret:xyz";
        let sanitized = safe_banner_text(raw, 300);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\u{200B}'));
        assert!(!sanitized.contains("hunter2"));
        assert!(!sanitized.contains("abc123"));
        assert!(!sanitized.contains("k999"));
        assert!(!sanitized.contains("xyz"));
        assert!(sanitized.contains("password=[REDACTED]"));
        assert!(sanitized.contains("Token: [REDACTED]"));
        assert!(sanitized.contains("api-key = [REDACTED]"));
        assert!(sanitized.contains("secret:[REDACTED]"));
        assert!(sanitized.starts_with("Alert"));
    }

    #[test]
    fn test_beijing_time_utc_plus_8_and_legacy() {
        assert_eq!(beijing_time(Some(0.0), ""), "1970-01-01 08:00:00");
        assert_eq!(
            beijing_time(None, "2026-10-08 23:00:00 UTC"),
            "2026-10-09 07:00:00"
        );
        assert_eq!(beijing_time(Some(1_791_509_400.0), ""), "2026-10-09 09:30:00");
        assert_eq!(beijing_time(Some(f64::NAN), ""), "");
        assert_eq!(beijing_time(None, "invalid"), "");
    }

    #[test]
    fn test_render_motd_banner_closed_widths_metrics_history_and_merge() {
        // Width invariance across all supported widths and color modes
        let entries_json = r#"[{
            "type": "container_connection_count",
            "title": "连接数偏高",
            "detail": "连接数量偏高",
            "state": "active",
            "severity": "warning",
            "metrics": "value=738 / threshold=500 / duration_seconds=720",
            "time_epoch": 1791509400
        }]"#;
        for &width in &[12usize, 16, 24, 32, 40, 52, 68, 80, 100] {
            for &color in &[false, true] {
                let opts = MotdRenderOptions {
                    language: "zh".to_string(),
                    width,
                    color,
                    stale: false,
                    sampled_at: Some(1_791_509_400.0),
                    now_epoch: None,
                    dynamic_history_age: false,
                };
                let card = render_motd_banner(entries_json, &opts);
                for line in card.lines() {
                    let plain = strip_csi_sgr_for_test(line);
                    assert_eq!(cell_width(&plain), width, "width={width} line={plain:?}");
                }
            }
        }

        // Check numeric evidence & Beijing timestamp formatting
        let opts100 = MotdRenderOptions {
            width: 100,
            sampled_at: Some(1_791_509_400.0),
            ..MotdRenderOptions::default()
        };
        let card100 = render_motd_banner(entries_json, &opts100);
        assert!(card100.contains("连接 738 条（预警 500 条）；持续 12 分钟"));
        assert!(card100.contains("2026-10-09 09:30:00"));
        assert!(!card100.contains("value="));

        // Historical recovered alert tense & duration
        let hist_json = r#"[{
            "type": "connections",
            "title": "连接数过高",
            "state": "verified",
            "historical": true,
            "first_seen_epoch": 1000,
            "time_epoch": 1600,
            "recovered_at_epoch": 2800,
            "detail": "容器当前连接 738 条"
        }]"#;
        let hist_card = render_motd_banner(
            hist_json,
            &MotdRenderOptions {
                width: 100,
                sampled_at: Some(6400.0),
                ..MotdRenderOptions::default()
            },
        );
        assert!(hist_card.contains("历史告警 · 已恢复"));
        assert!(hist_card.contains("当时情况：容器当时连接 738 条"));
        assert!(hist_card.contains("恢复于：1小时0分钟前"));
        assert!(hist_card.contains("告警持续约 30 分钟"));
        assert!(hist_card.contains("目前容器无异常"));

        // Stale & merge behavior
        let stale_card = render_motd_banner(
            "[]",
            &MotdRenderOptions {
                stale: true,
                ..MotdRenderOptions::default()
            },
        );
        assert!(stale_card.contains("当前状态未知"));
        assert!(!stale_card.contains("目前容器无异常"));

        let merged = merge_motd_banner("user motd\n", &card100).unwrap();
        assert!(merged.starts_with(security_banner::START_MARKER));
        assert!(merged.ends_with("user motd\n"));
        assert!(merge_motd_banner("# >>> NARWHAL SECURITY ALERT BEGIN >>>\nbroken", &card100).is_err());
    }

    #[test]
    fn test_socks_inbound_protocols_process_configs_and_gost_cli() {
        // Xray xhttp ALPN h3 -> udp, h2 -> tcp, mixed -> ambiguous (omitted), masque -> omitted
        let xhttp_h3 = r#"{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]}}}]}"#;
        let r_h3 = JsonVal::parse(&parse_inbound_protocols_json(xhttp_h3, "xray")).unwrap();
        assert_eq!(
            r_h3.get("endpoints").unwrap().as_arr().unwrap()[0]
                .get("transports")
                .unwrap()
                .as_arr()
                .unwrap()[0]
                .as_str(),
            Some("udp")
        );

        let xhttp_mix = r#"{"inbounds":[{"protocol":"vmess","port":443,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"alpn":["h2","h3"]}}}]}"#;
        let r_mix = JsonVal::parse(&parse_inbound_protocols_json(xhttp_mix, "xray")).unwrap();
        assert!(r_mix.get("endpoints").unwrap().as_arr().unwrap()[0].get("transports").is_none());

        let sing_box = r#"{"inbounds":[{"type":"trojan","listen":"0.0.0.0","listen_port":443},{"type":"socks","listen":"127.0.0.1","listen_port":1080}]}"#;
        let r_sb = JsonVal::parse(&parse_inbound_protocols_json(sing_box, "sing-box")).unwrap();
        let sb_eps = r_sb.get("endpoints").unwrap().as_arr().unwrap();
        assert_eq!(sb_eps[0].get("transports").unwrap().as_arr().unwrap()[0].as_str(), Some("tcp"));
        assert!(sb_eps[1].get("transports").is_none());

        // process_configs exact binary + safe path checks
        let ps = "1 S supervise-daemo supervise-daemon xray --start\n12 S xray /usr/bin/xray run -config /opt/proxy/test.json -confdir /etc/xray/conf.d\n15 S sing-box /usr/bin/sing-box run -C /etc/sing-box\n18 S xray /usr/bin/xray run -c /etc/xray/../secret.json\n";
        let procs = JsonVal::parse(&parse_process_configs_json(ps)).unwrap();
        let arr = procs.as_arr().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0].get_i64("pid"), Some(12));
        assert_eq!(arr[0].get_bool("additional_configs"), Some(false));
        assert_eq!(arr[1].get_i64("pid"), Some(15));
        assert_eq!(arr[1].get("config_dirs").unwrap().as_arr().unwrap()[0].as_str(), Some("/etc/sing-box"));
        assert_eq!(arr[2].get_bool("additional_configs"), Some(true));

        // 3proxy CL password profile & gost CLI -L without -F leak
        let leg = JsonVal::parse(&legacy_profiles_json("users alice:CL:StrongPass99!\n", "3proxy")).unwrap();
        assert_eq!(leg.as_arr().unwrap()[0].get_bool("available"), Some(true));
        assert!(!legacy_profiles_json("users alice:CL:StrongPass99!\n", "3proxy").contains("StrongPass99"));

        let gost_ps = "42 S gost /usr/bin/gost -L socks5://u:pw123@:1080 -F socks5://:2080\n";
        let gcli = JsonVal::parse(&gost_cli_json(gost_ps, 42)).unwrap();
        assert_eq!(gcli.get_bool("single_purpose"), Some(true));
        assert_eq!(gcli.get("endpoints").unwrap().as_arr().unwrap().len(), 1);
        assert!(!gost_cli_json(gost_ps, 42).contains("pw123"));
        assert_eq!(socks_greeting_mode(&[0x05, 0x00]), "no_auth");
        assert_eq!(socks_greeting_mode(&[0x05, 0x02]), "auth_required");
        assert_eq!(socks_greeting_mode(&[0x05, 0xff]), "unknown");
        assert!(panel_domain_allowed("sub.trusted.example.com", &["*.trusted.example.com".to_string()]));
    }

    #[test]
    fn test_incus_timezone_offsets_partial_scan_and_project_filtering() {
        let inst_scan = r#"{"ok":true,"latency_ms":10.0,"items":[{"name":"vm1","project":"buyers","status":"Running","config":{"volatile.uuid":"u1"}}]}"#;
        let ops_scan = r#"{
            "ok": true,
            "latency_ms": 20.0,
            "items": [
                {"id":"op-other","status":"Running","description":"Stopping","created_at":"2026-11-16T00:00:00+08:00","resources":{"instances":["/1.0/instances/other?project=buyers"]}},
                {"id":"op-match","status":"Running","description":"Restarting","created_at":"2026-11-16T08:00:00+08:00","may_cancel":true,"resources":{"instances":["/1.0/instances/vm1?project=buyers"]}}
            ]
        }"#;
        // 2026-11-16T08:00:00+08:00 == 2026-11-16T00:00:00Z; check at 00:05:00Z (300s exact -> stuck)
        let now = parse_incus_created_epoch("2026-11-16T00:05:00Z").unwrap();
        let snap = JsonVal::parse(&build_incus_snapshot_json(inst_scan, ops_scan, "all", now)).unwrap();
        assert_eq!(snap.get_i64("active_lifecycle_operation_count"), Some(1));
        assert_eq!(snap.get_i64("stuck_lifecycle_operation_count"), Some(1));
        assert_eq!(snap.get_str("status"), Some("degraded"));

        // Partial scan (instances ok, operations failed)
        let partial = JsonVal::parse(&build_incus_snapshot_json(inst_scan, r#"{"ok":false,"error":"timeout"}"#, "buyers", now)).unwrap();
        assert_eq!(partial.get_str("scan_status"), Some("partial"));
        assert_eq!(partial.get_str("status"), Some("degraded"));
    }

    #[test]
    fn test_disk_cleanup_quarantine_and_podman_cooldown_truncation_and_banner_copy() {
        let pod_target = CleanupTarget {
            runtime: "podman".to_string(),
            runtime_bin: "podman".to_string(),
            project: "".to_string(),
            name: "c".to_string(),
            id: "a".repeat(12),
            stable_id: "a".repeat(64),
            instance_id: String::new(),
            pid: String::new(),
            pid_start_ticks: String::new(),
        };
        assert_eq!(
            cleanup_cooldown_key(&pod_target),
            format!("[\"podman\",\"\",\"c\",\"{}\"]", "a".repeat(12))
        );

        let dir = temp_dir("quarantine-cleanup");
        let mut quarantined = BTreeSet::new();
        quarantined.insert("uuid-quarantined".to_string());
        let ctx = CleanupActionContext {
            host_available: true,
            node_id: "n1".to_string(),
            now_epoch: 1_700_000_000,
            journal_path: dir.join("j.json"),
            policy: CleanupPolicy::default(),
            containers: vec![CleanupContainerCandidate {
                runtime: "incus".to_string(),
                runtime_bin: "incus".to_string(),
                project: "default".to_string(),
                name: "q-box".to_string(),
                id: "uuid-quarantined".to_string(),
                stable_id: "uuid-quarantined".to_string(),
                instance_id: String::new(),
                pid: "50".to_string(),
                pid_start_ticks: "10".to_string(),
            }],
            quarantined_identities: quarantined,
            active_run_in_progress: false,
        };
        let res = execute_disk_cleanup_action(
            r#"{"id":7,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"n1"}}"#,
            &ctx,
        );
        assert!(res.ok);
        assert_eq!(res.targets.len(), 1); // quarantined container excluded, only __host__ remains
        assert_eq!(res.targets[0].name, "__host__");

        // Panel pairing MOTD copy omits config paths and unrelated ports
        let panel_json = r#"[{
            "type": "unauthorized_panel_pairing",
            "state": "awaiting_report",
            "severity": "critical",
            "detail": "未授权面板域名 xb.netech.eu.org；节点程序特征 xboard-node；配置文件 /etc/xboard-node/config.yml；容器内部监听端口 22,5355,65530",
            "metrics": "value=1 / threshold=1"
        }]"#;
        let panel_card = render_motd_banner(
            panel_json,
            &MotdRenderOptions {
                width: 100,
                ..MotdRenderOptions::default()
            },
        );
        assert!(panel_card.contains("疑似第三方面板对接"));
        assert!(panel_card.contains("面板：xb.netech.eu.org"));
        assert!(panel_card.contains("已执行处理，等待复查确认"));
        assert!(!panel_card.contains("65530"));
        assert!(!panel_card.contains("config.yml"));

        // Shell hook merge preserves original
        let rc = merge_shell_hook("return\n# custom\n", shell_hook()).unwrap();
        assert!(rc.ends_with("return\n# custom\n"));
        assert_eq!(merge_shell_hook(&rc, shell_hook()).unwrap(), rc);

        // Font F-stem columns align identically across all 4 stem rows at width 68
        let font_card = render_motd_banner(
            "[]",
            &MotdRenderOptions {
                width: 68,
                color: false,
                ..MotdRenderOptions::default()
            },
        );
        let font_lines: Vec<&str> = font_card.lines().skip(2).take(5).collect();
        let pipe_positions: BTreeSet<usize> = font_lines[1..]
            .iter()
            .filter_map(|row| row.find('|'))
            .collect();
        assert_eq!(pipe_positions.len(), 1);

        // OSC-8 hyperlink with ST terminator (\x1b\\) stripped safely
        assert_eq!(
            safe_banner_text("\x1b]8;;https://evil.example\x1b\\SafeLink\x1b]8;;\x1b\\", 100),
            "SafeLink"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_json_wrappers_and_symlink_and_capacity_guards() {
        let pol_ok = JsonVal::parse(&validate_cleanup_policy_json(
            r#"{"enabled":true,"retention_days":90,"interval_hours":168}"#,
            None,
        ))
        .unwrap();
        assert_eq!(pol_ok.get_bool("ok"), Some(true));
        let pol_bad = JsonVal::parse(&validate_cleanup_policy_json(
            r#"{"retention_days":91}"#,
            None,
        ))
        .unwrap();
        assert_eq!(pol_bad.get_bool("ok"), Some(false));

        let dir = temp_dir("wrappers");
        let store = PanelDomainStore {
            allowlist_path: dir.join("allow.json"),
            auto_remediate_path: Some(dir.join("auto.json")),
            env_file_path: None,
            env_allowed_domains: Vec::new(),
        };
        let dom_res = JsonVal::parse(&manage_panel_domains_json(
            &store,
            "allow_panel_domains",
            &["192.0.2.10".to_string()],
            1_700_000_000,
        ))
        .unwrap();
        assert_eq!(dom_res.get_bool("ok"), Some(true));
        assert_eq!(
            dom_res.get("allowlist").unwrap().as_arr().unwrap()[0].as_str(),
            Some("192.0.2.10")
        );

        let ctx = CleanupActionContext {
            host_available: false,
            node_id: "n1".to_string(),
            journal_path: dir.join("j.json"),
            ..CleanupActionContext::default()
        };
        let act_res = JsonVal::parse(&execute_disk_cleanup_action_json(
            r#"{"id":1,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"n1"}}"#,
            &ctx,
        ))
        .unwrap();
        assert_eq!(act_res.get_bool("ok"), Some(false));

        // select_motd_entries enforces 1 notice + up to 2 current + 1 historical (3+1 total)
        let mut entries = vec![MotdEntry {
            entry_type: "user_notice".to_string(),
            time_epoch: Some(50.0),
            detail: "notice".to_string(),
            ..MotdEntry::default()
        }];
        for i in 1..=4 {
            entries.push(MotdEntry {
                entry_type: "cpu".to_string(),
                time_epoch: Some(i as f64),
                state: "active".to_string(),
                ..MotdEntry::default()
            });
        }
        entries.push(MotdEntry {
            entry_type: "memory".to_string(),
            state: "verified".to_string(),
            historical: true,
            recovered_at_epoch: Some(100.0),
            ..MotdEntry::default()
        });
        let selected = select_motd_entries(&entries);
        assert_eq!(selected.len(), 4);
        assert_eq!(selected[0].entry_type, "user_notice");
        assert!(selected[3].historical);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cleanup_readonly_journal_and_finalize_run() {
        use disk_cleanup::{
            execute_and_finalize_cleanup_run, execute_disk_cleanup_action,
            mark_cleanup_run_delivered, read_cleanup_journal_readonly, CleanupActionContext,
            CleanupPolicy, DAY_SECONDS,
        };
        let dir = temp_dir("cleanup_finalize");
        let root = dir.join("mock_host");
        let apt_dir = root.join("var/cache/apt/archives");
        fs::create_dir_all(&apt_dir).unwrap();
        let pkg = apt_dir.join("old.deb");
        fs::write(&pkg, b"deb-bytes").unwrap();

        let journal_path = dir.join("disk-cleanup.json");
        let now_epoch = super::util::now_unix_secs() + 10 * DAY_SECONDS;
        let ctx = CleanupActionContext {
            host_available: true,
            node_id: "node-1".to_string(),
            now_epoch,
            journal_path: journal_path.clone(),
            policy: CleanupPolicy {
                enabled: true,
                include_containers: false,
                retention_days: 14,
                interval_hours: 24,
            },
            ..CleanupActionContext::default()
        };

        let scan_action = r#"{"id":101,"action_type":"disk_cleanup_scan","params":{"expected_node_id":"node-1"}}"#;
        let scan_stage = execute_disk_cleanup_action(scan_action, &ctx);
        assert!(scan_stage.ok);
        assert_eq!(scan_stage.status, "running");

        // Readonly inspect must preserve "running" (never turn it into "interrupted")
        let ro = read_cleanup_journal_readonly(&journal_path).unwrap();
        assert_eq!(ro.runs.len(), 1);
        assert_eq!(ro.runs[0].status, "running");

        // Finalize scan against mock root
        let scanned = execute_and_finalize_cleanup_run(
            &journal_path,
            "action-101",
            &ctx.policy,
            Some(&root),
            now_epoch,
        )
        .unwrap();
        assert_eq!(scanned.status, "scanned");
        assert_eq!(scanned.items.len(), 1);
        assert_eq!(scanned.items[0].candidate_files, 1);
        assert!(pkg.exists());

        // Execute confirmed cleanup and mark delivered
        let exec_action = r#"{"id":102,"action_type":"disk_cleanup_execute","params":{"expected_node_id":"node-1","confirmed":true,"plan_id":"action-101"}}"#;
        let exec_stage = execute_disk_cleanup_action(exec_action, &ctx);
        assert!(exec_stage.ok);
        let cleaned = execute_and_finalize_cleanup_run(
            &journal_path,
            "action-102",
            &ctx.policy,
            Some(&root),
            now_epoch,
        )
        .unwrap();
        assert_eq!(cleaned.status, "succeeded");
        assert_eq!(cleaned.items[0].deleted_files, 1);
        assert!(!pkg.exists());

        mark_cleanup_run_delivered(&journal_path, "action-102").unwrap();
        let after = read_cleanup_journal_readonly(&journal_path).unwrap();
        assert!(after.runs.iter().find(|r| r.run_id == "action-102").unwrap().delivered);

        let _ = fs::remove_dir_all(&dir);
    }

    fn strip_csi_sgr_for_test(line: &str) -> String {
        let mut out = String::new();
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'm' {
                    i += 1;
                }
                i += 1;
                continue;
            }
            let ch = line[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }
}
