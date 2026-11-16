//! Shared pure-`std` utilities for JSON formatting, IP classification,
//! POSIX path normalization, and atomic `0o600` file persistence.

use std::env;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proc_probe::json_escape;
use runtime_drivers::JsonVal;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Returns current UNIX epoch seconds (`0` if system clock precedes epoch).
pub(crate) fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Returns current UNIX epoch seconds with fractional precision.
pub(crate) fn current_unix_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Checks whether `value` is a strictly safe ASCII integer port/pid in `[min, max]`.
pub(crate) fn bounded_int_from_json(val: Option<&JsonVal>, min: i64, max: i64) -> Option<i64> {
    match val? {
        JsonVal::Num(n) if n.is_finite() && n.fract() == 0.0 => {
            if *n >= (min as f64) && *n <= (max as f64) {
                Some(*n as i64)
            } else {
                None
            }
        }
        JsonVal::Str(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let parsed = trimmed.parse::<i64>().ok()?;
            if (min..=max).contains(&parsed) {
                Some(parsed)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Matches Python `ipaddress.ip_address(...).is_global` semantics for IPv4.
pub fn is_global_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    let non_global = o[0] == 0
        || o[0] == 10
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0 && o[3] != 9 && o[3] != 10)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 224;
    !non_global
}

/// Matches Python `ipaddress.ip_address(...).is_global` semantics for IPv6.
pub fn is_global_ipv6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    // Unspecified (::) and loopback (::1)
    if v6.is_unspecified() || v6.is_loopback() {
        return false;
    }
    // IPv4-mapped ::ffff:0:0/96
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        return false;
    }
    // NAT64 local-use 64:ff9b:1::/48
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        return false;
    }
    // Discard-only 100::/64
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return false;
    }
    // 2001::/23 IETF protocol assignments (with documented global exceptions)
    if s[0] == 0x2001 && (s[1] & 0xfe00) == 0 {
        let is_global_exception = (s == [0x2001, 1, 0, 0, 0, 0, 0, 1])
            || (s == [0x2001, 1, 0, 0, 0, 0, 0, 2])
            || s[1] == 0x0003
            || (s[1] == 0x0004 && s[2] == 0x0112)
            || (s[1] & 0xfff0) == 0x0020
            || (s[1] & 0xfff0) == 0x0030;
        if !is_global_exception {
            return false;
        }
    }
    // Documentation 2001:db8::/32
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // 6to4 2002::/16
    if s[0] == 0x2002 {
        return false;
    }
    // Unique local fc00::/7
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Link-local fe80::/10
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Multicast ff00::/8
    if (s[0] & 0xff00) == 0xff00 {
        return false;
    }
    true
}

/// Checks whether `addr` is globally routable (matching Python `ipaddress.is_global`).
pub fn is_global_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => is_global_ipv6(v6),
    }
}

/// Sort key matching `(ip.version, int(ip))`.
pub fn ip_sort_key(addr: IpAddr) -> (u8, u128) {
    match addr {
        IpAddr::V4(v4) => (4, u32::from_be_bytes(v4.octets()) as u128),
        IpAddr::V6(v6) => (6, u128::from_be_bytes(v6.octets())),
    }
}

/// Validates a domain name (`_SAFE_DOMAIN` / `_valid_domain`): 2+ dot-separated labels,
/// total len <= 253, each label 1..=63 of lowercase ASCII alphanumeric with interior hyphens.
pub fn is_safe_domain(domain: &str) -> bool {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return false;
    }
    let mut count = 0usize;
    for label in trimmed.split('.') {
        count += 1;
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return false;
        }
        if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
            return false;
        }
        if !(bytes[bytes.len() - 1].is_ascii_lowercase()
            || bytes[bytes.len() - 1].is_ascii_digit())
        {
            return false;
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return false;
        }
    }
    count >= 2
}

/// Normalizes a POSIX path lexicographically without touching the filesystem.
pub(crate) fn posix_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial_slashes == 0 && comps.is_empty())
            || matches!(comps.last(), Some(&".."))
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let joined = comps.join("/");
    if initial_slashes > 0 {
        format!("{}{}", "/".repeat(initial_slashes), joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Validates a bounded absolute POSIX path (`/[A-Za-z0-9_./-]{1,240}`) with no `..` segment.
pub(crate) fn is_safe_abs_unix_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (2..=241).contains(&bytes.len())
        && bytes[0] == b'/'
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
        && !path.split('/').any(|seg| seg == "..")
}

/// Resolves a path from an environment variable or falls back to `default_path`.
pub(crate) fn resolve_env_path(env_key: &str, default_path: &str) -> PathBuf {
    if let Ok(raw) = env::var(env_key) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    PathBuf::from(default_path)
}

/// Atomically writes `content` to `path` with `0o600` permissions (Unix) and symlink rejection.
pub(crate) fn atomic_write_private(
    path: &Path,
    content: &[u8],
    temp_prefix: &str,
) -> Result<(), String> {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("cannot resolve working directory: {err}"))?
            .join(path)
    };
    let parent = abs_path
        .parent()
        .ok_or_else(|| "target path has no parent directory".to_string())?;

    if let Ok(meta) = fs::symlink_metadata(&abs_path) {
        if meta.file_type().is_symlink() {
            return Err("refusing to overwrite symlink target".to_string());
        }
    }

    create_secure_dir(parent)?;

    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!("{temp_prefix}{}-{seq}.tmp", std::process::id()));

    let write_res = (|| -> Result<(), String> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(&tmp_path)
            .map_err(|err| format!("failed to create temp file: {err}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
                .map_err(|err| format!("failed to set 0600 permissions: {err}"))?;
        }

        file.write_all(content)
            .map_err(|err| format!("failed to write temp file: {err}"))?;
        file.flush()
            .map_err(|err| format!("failed to flush temp file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync temp file: {err}"))?;
        drop(file);

        fs::rename(&tmp_path, &abs_path)
            .map_err(|err| format!("failed to replace target file atomically: {err}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&abs_path, fs::Permissions::from_mode(0o600));
            if let Ok(dir_handle) = fs::File::open(parent) {
                let _ = dir_handle.sync_all();
            }
        }
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

#[cfg(unix)]
fn create_secure_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(dir)
        .map_err(|err| format!("failed to create directory: {err}"))
}

#[cfg(not(unix))]
fn create_secure_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|err| format!("failed to create directory: {err}"))
}

/// Lightweight compact JSON object serializer matching `app-guard` conventions.
pub(crate) struct JsonBuilder {
    buf: String,
    has_fields: bool,
}

impl JsonBuilder {
    pub(crate) fn new() -> Self {
        Self {
            buf: String::from("{"),
            has_fields: false,
        }
    }

    fn key(&mut self, key: &str) {
        if self.has_fields {
            self.buf.push(',');
        }
        self.has_fields = true;
        self.buf.push('"');
        self.buf.push_str(&json_escape(key));
        self.buf.push_str("\":");
    }

    pub(crate) fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        self.buf.push('"');
        self.buf.push_str(&json_escape(value));
        self.buf.push('"');
    }

    pub(crate) fn bool(&mut self, key: &str, value: bool) {
        self.key(key);
        self.buf.push_str(if value { "true" } else { "false" });
    }

    pub(crate) fn i64(&mut self, key: &str, value: i64) {
        self.key(key);
        let _ = write!(self.buf, "{value}");
    }

    pub(crate) fn u64(&mut self, key: &str, value: u64) {
        self.key(key);
        let _ = write!(self.buf, "{value}");
    }

    pub(crate) fn usize(&mut self, key: &str, value: usize) {
        self.key(key);
        let _ = write!(self.buf, "{value}");
    }

    pub(crate) fn f64(&mut self, key: &str, value: f64) {
        self.key(key);
        if !value.is_finite() {
            self.buf.push_str("0.0");
        } else if value == 0.0 {
            self.buf.push_str("0.0");
        } else if value.fract() == 0.0 && value.abs() < 1e15 {
            let _ = write!(self.buf, "{value:.1}");
        } else {
            let _ = write!(self.buf, "{value}");
        }
    }

    pub(crate) fn raw(&mut self, key: &str, raw_json: &str) {
        self.key(key);
        self.buf.push_str(raw_json);
    }

    pub(crate) fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

pub(crate) fn json_str_list(items: &[String]) -> String {
    let mut out = String::from("[");
    for (idx, item) in items.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(item));
        out.push('"');
    }
    out.push(']');
    out
}

/// Checks boolean environment flag matching `os.getenv(..., "true").lower() not in ("0", "false", "no", "off")`.
pub(crate) fn env_bool_enabled(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(val) => {
            let lowered = val.trim().to_ascii_lowercase();
            if lowered.is_empty() {
                default
            } else {
                !matches!(lowered.as_str(), "0" | "false" | "no" | "off")
            }
        }
        Err(_) => default,
    }
}

/// Truncates a string to at most `max_chars` Unicode scalar values.
pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}
