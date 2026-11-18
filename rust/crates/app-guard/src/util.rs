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
